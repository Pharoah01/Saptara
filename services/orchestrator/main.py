"""
Security Testing Orchestrator Microservice
Coordinates and manages all security testing services
"""

import asyncio
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig
from shared.utils import get_logger
from shared.auth import verify_api_key
from shared.db import init_db, AsyncSessionLocal, ScanJobRow
from shared import metrics as m

logger = get_logger(__name__)

app = FastAPI(
    title="Security Testing Orchestrator",
    description="Coordinates all security testing microservices",
    version="1.0.0",
)

SERVICES = {
    "scanner": os.getenv("SCANNER_URL", "http://scanner:8001"),
    "validator": os.getenv("VALIDATOR_URL", "http://validator:8002"),
    "simulator": os.getenv("SIMULATOR_URL", "http://simulator:8003"),
}

orchestration_cache: Dict[str, Dict[str, Any]] = {}


@app.on_event("startup")
async def startup():
    await init_db()


# ---------------------------------------------------------------------------
# Prometheus
# ---------------------------------------------------------------------------

@app.get("/metrics", include_in_schema=False)
async def metrics():
    return JSONResponse(
        content=generate_latest().decode(),
        media_type=CONTENT_TYPE_LATEST,
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class OrchestrationRequest(BaseModel):
    config: ScanConfig
    services: List[str] = ["scanner", "validator", "simulator"]
    parallel: bool = True


class OrchestrationResponse(BaseModel):
    orchestration_id: str
    status: str
    message: str
    services_started: List[str]
    started_at: datetime


# ---------------------------------------------------------------------------
# Public
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {"service": "Security Testing Orchestrator", "status": "healthy", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    service_health = {}
    async with httpx.AsyncClient() as client:
        for name, url in SERVICES.items():
            try:
                r = await client.get(f"{url}/health", timeout=5.0)
                service_health[name] = {
                    "status": "healthy" if r.status_code == 200 else "unhealthy",
                    "response_time": r.elapsed.total_seconds(),
                }
            except Exception as e:
                service_health[name] = {"status": "unreachable", "error": str(e)}

    overall = "healthy" if all(s["status"] == "healthy" for s in service_health.values()) else "degraded"
    return {
        "status": overall,
        "timestamp": datetime.utcnow().isoformat(),
        "service": "orchestrator",
        "version": "1.0.0",
        "services": service_health,
    }


# ---------------------------------------------------------------------------
# Protected
# ---------------------------------------------------------------------------

@app.post("/orchestrate", response_model=OrchestrationResponse, dependencies=[Depends(verify_api_key)])
async def start_orchestration(request: OrchestrationRequest, background_tasks: BackgroundTasks):
    orchestration_id = str(uuid.uuid4())
    now = datetime.utcnow()

    orchestration_cache[orchestration_id] = {
        "orchestration_id": orchestration_id,
        "config": request.config.dict(),
        "services": request.services,
        "parallel": request.parallel,
        "status": "running",
        "progress": 0.0,
        "service_results": {},
        "started_at": now,
        "completed_at": None,
    }

    m.scans_total.labels(service="orchestrator").inc()
    m.active_scans.labels(service="orchestrator").inc()
    background_tasks.add_task(execute_orchestration, orchestration_id, request)
    logger.info(f"Started orchestration {orchestration_id}")

    return OrchestrationResponse(
        orchestration_id=orchestration_id,
        status="running",
        message="Orchestration started successfully",
        services_started=request.services,
        started_at=now,
    )


@app.get("/orchestration/{orchestration_id}/status", dependencies=[Depends(verify_api_key)])
async def get_orchestration_status(orchestration_id: str):
    if orchestration_id not in orchestration_cache:
        raise HTTPException(status_code=404, detail="Orchestration not found")
    return orchestration_cache[orchestration_id]


@app.get("/orchestration/{orchestration_id}/results", dependencies=[Depends(verify_api_key)])
async def get_orchestration_results(orchestration_id: str):
    if orchestration_id not in orchestration_cache:
        raise HTTPException(status_code=404, detail="Orchestration not found")
    return orchestration_cache[orchestration_id]


@app.get("/services", dependencies=[Depends(verify_api_key)])
async def list_services():
    service_status = {}
    async with httpx.AsyncClient() as client:
        for name, url in SERVICES.items():
            try:
                r = await client.get(f"{url}/health", timeout=5.0)
                service_status[name] = {
                    "url": url,
                    "status": "healthy" if r.status_code == 200 else "unhealthy",
                    "response_time": r.elapsed.total_seconds(),
                }
            except Exception as e:
                service_status[name] = {"url": url, "status": "unreachable", "error": str(e)}
    return {"services": service_status}


# ---------------------------------------------------------------------------
# Background orchestration
# ---------------------------------------------------------------------------

async def execute_orchestration(orchestration_id: str, request: OrchestrationRequest):
    rec = orchestration_cache[orchestration_id]
    start = time.time()
    api_key = os.getenv("API_KEYS", "saptara-dev-key-change-me").split(",")[0].strip()
    headers = {"X-API-Key": api_key}

    try:
        if request.parallel:
            tasks = [
                _call_service(svc, request.config, headers)
                for svc in request.services if svc in SERVICES
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for svc, result in zip(request.services, results):
                rec["service_results"][svc] = (
                    {"status": "failed", "error": str(result)}
                    if isinstance(result, Exception) else result
                )
        else:
            for svc in request.services:
                if svc in SERVICES:
                    try:
                        rec["service_results"][svc] = await _call_service(svc, request.config, headers)
                    except Exception as e:
                        rec["service_results"][svc] = {"status": "failed", "error": str(e)}

        # Persist summary
        async with AsyncSessionLocal() as session:
            job = ScanJobRow(
                scan_id=orchestration_id,
                service_name="orchestrator",
                target_url=request.config.target_url,
                status="completed",
                progress=100.0,
                config=request.config.dict(),
                completed_at=datetime.utcnow(),
            )
            session.add(job)
            await session.commit()

        rec["status"] = "completed"
        rec["progress"] = 100.0
        rec["completed_at"] = datetime.utcnow()

        duration = time.time() - start
        m.scan_duration_seconds.labels(service="orchestrator").observe(duration)
        m.active_scans.labels(service="orchestrator").dec()
        logger.info(f"Orchestration {orchestration_id} completed in {duration:.1f}s")

    except Exception as e:
        logger.error(f"Orchestration {orchestration_id} failed: {e}")
        rec["status"] = "failed"
        rec["error"] = str(e)
        rec["completed_at"] = datetime.utcnow()
        m.active_scans.labels(service="orchestrator").dec()


async def _call_service(service_name: str, config: ScanConfig, headers: dict) -> dict:
    """Start a job on a downstream service and poll until done."""
    url = SERVICES[service_name]
    endpoint_map = {"scanner": "/scan", "validator": "/validate", "simulator": "/simulate"}
    endpoint = endpoint_map[service_name]
    id_key_map = {"scanner": "scan_id", "validator": "validation_id", "simulator": "simulation_id"}
    id_key = id_key_map[service_name]

    async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
        r = await client.post(f"{url}{endpoint}", json={"config": config.dict()})
        if r.status_code != 200:
            raise Exception(f"{service_name} failed to start: {r.text}")

        job_id = r.json()[id_key]
        resource = endpoint.lstrip("/")

        while True:
            sr = await client.get(f"{url}/{resource}/{job_id}/status", timeout=10.0)
            if sr.status_code != 200:
                raise Exception(f"Status check failed for {service_name}")
            data = sr.json()
            if data["status"] in ("completed", "failed", "cancelled"):
                rr = await client.get(f"{url}/{resource}/{job_id}/results", timeout=10.0)
                return {
                    "status": data["status"],
                    "service_id": job_id,
                    "results": rr.json() if rr.status_code == 200 else None,
                }
            await asyncio.sleep(2)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

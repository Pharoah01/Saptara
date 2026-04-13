"""
Security Testing Orchestrator Microservice
Fixed pipeline: Scanner → Simulator → Validator (always sequential)
Scanner finds vulnerabilities, Simulator exploits them, Validator confirms defences.
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
from sqlalchemy import select, update
from shared.db import init_db, AsyncSessionLocal, ScanJobRow
from shared import metrics as m

logger = get_logger(__name__)

app = FastAPI(
    title="Security Testing Orchestrator",
    description="Coordinates all security testing microservices",
    version="1.0.0",
)

SERVICES = {
    "scanner":   os.getenv("SCANNER_URL",   "http://scanner:8001"),
    "validator": os.getenv("VALIDATOR_URL", "http://validator:8002"),
    "simulator": os.getenv("SIMULATOR_URL", "http://simulator:8003"),
}

# Fixed pipeline order — scanner must run first, simulator uses its findings,
# validator confirms defences last.
PIPELINE = ["scanner", "simulator", "validator"]

orchestration_cache: Dict[str, Dict[str, Any]] = {}


@app.on_event("startup")
async def startup():
    await init_db()
    await _reload_cache_from_db()


async def _reload_cache_from_db():
    """Restore orchestration records from DB into memory on startup."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanJobRow).where(ScanJobRow.service_name == "orchestrator")
            )
            rows = result.scalars().all()
            for row in rows:
                status = row.status if row.status != "running" else "interrupted"
                orchestration_cache[row.scan_id] = {
                    "orchestration_id": row.scan_id,
                    "config": row.config or {},
                    "status": status,
                    "progress": row.progress or 0.0,
                    "current_stage": (row.config or {}).get("current_stage", ""),
                    "service_results": row.service_results or {},
                    "started_at": row.started_at,
                    "completed_at": row.completed_at,
                    "error": row.error,
                }
            logger.info(f"Restored {len(rows)} orchestration records from DB")
    except Exception as e:
        logger.warning(f"Could not restore cache from DB: {e}")


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


class OrchestrationResponse(BaseModel):
    orchestration_id: str
    status: str
    message: str
    pipeline: List[str]
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
        "status": "running",
        "progress": 0.0,
        "current_stage": "scanner",
        "service_results": {},
        "started_at": now,
        "completed_at": None,
        "error": None,
    }

    m.scans_total.labels(service="orchestrator").inc()
    m.active_scans.labels(service="orchestrator").inc()
    background_tasks.add_task(execute_pipeline, orchestration_id, request)
    logger.info(f"Started orchestration {orchestration_id} for {request.config.target_url}")

    return OrchestrationResponse(
        orchestration_id=orchestration_id,
        status="running",
        message="Pipeline started: Scanner → Simulator → Validator",
        pipeline=PIPELINE,
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


@app.delete("/orchestration/{orchestration_id}", dependencies=[Depends(verify_api_key)])
async def cancel_orchestration(orchestration_id: str):
    if orchestration_id not in orchestration_cache:
        raise HTTPException(status_code=404, detail="Orchestration not found")
    rec = orchestration_cache[orchestration_id]
    if rec["status"] == "running":
        rec["status"] = "cancelled"
        rec["completed_at"] = datetime.utcnow()
        m.active_scans.labels(service="orchestrator").dec()
    return {"message": f"Orchestration {orchestration_id} cancelled", "status": rec["status"]}


@app.get("/orchestration", dependencies=[Depends(verify_api_key)])
async def list_orchestrations():
    return {"orchestrations": [
        {
            "orchestration_id": oid,
            "config": rec.get("config", {}),
            "status": rec["status"],
            "progress": rec.get("progress", 0),
            "current_stage": rec.get("current_stage", ""),
            "started_at": rec.get("started_at"),
            "completed_at": rec.get("completed_at"),
        }
        for oid, rec in orchestration_cache.items()
    ]}


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
# Pipeline execution  (Scanner → Simulator → Validator)
# ---------------------------------------------------------------------------

async def execute_pipeline(orchestration_id: str, request: OrchestrationRequest):
    """
    Run the three-stage pipeline sequentially.
    - Stage 1 (Scanner):   discovers vulnerabilities
    - Stage 2 (Simulator): receives scanner findings and attempts exploitation
    - Stage 3 (Validator): confirms which defences are in place
    Results of every stage are persisted to DB before the next stage starts.
    """
    rec = orchestration_cache[orchestration_id]
    start = time.time()
    api_key = os.getenv("API_KEYS", "saptara-dev-key-change-me").split(",")[0].strip()
    headers = {"X-API-Key": api_key}

    # Persist job to DB immediately
    async with AsyncSessionLocal() as session:
        job = ScanJobRow(
            scan_id=orchestration_id,
            service_name="orchestrator",
            target_url=request.config.target_url,
            status="running",
            progress=0.0,
            config=request.config.dict(),
        )
        session.add(job)
        await session.commit()

    try:
        # ── Stage 1: Scanner ──────────────────────────────────────────────
        rec["current_stage"] = "scanner"
        rec["progress"] = 5.0
        logger.info(f"[{orchestration_id}] Stage 1/3 — Scanner")

        scanner_result = await _run_service(
            "scanner", request.config, headers,
            extra_body={},
        )
        rec["service_results"]["scanner"] = scanner_result
        rec["progress"] = 33.0
        await _persist_progress(orchestration_id, rec)

        # Extract vulnerability list from scanner to feed simulator
        scanner_findings = _extract_vulnerabilities(scanner_result)
        logger.info(
            f"[{orchestration_id}] Scanner done — "
            f"{len(scanner_findings)} vulnerabilities found"
        )

        # ── Stage 2: Simulator ────────────────────────────────────────────
        rec["current_stage"] = "simulator"
        logger.info(f"[{orchestration_id}] Stage 2/3 — Simulator")

        # Map scanner findings to attack scenarios
        scenarios = _findings_to_scenarios(scanner_findings)
        simulator_result = await _run_service(
            "simulator", request.config, headers,
            extra_body={"attack_scenarios": scenarios},
        )
        rec["service_results"]["simulator"] = simulator_result
        rec["progress"] = 66.0
        await _persist_progress(orchestration_id, rec)
        logger.info(f"[{orchestration_id}] Simulator done")

        # ── Stage 3: Validator ────────────────────────────────────────────
        rec["current_stage"] = "validator"
        logger.info(f"[{orchestration_id}] Stage 3/3 — Validator")

        validator_result = await _run_service(
            "validator", request.config, headers,
            extra_body={},
        )
        rec["service_results"]["validator"] = validator_result
        rec["progress"] = 100.0
        logger.info(f"[{orchestration_id}] Validator done")

        # ── Finalise ──────────────────────────────────────────────────────
        rec["status"] = "completed"
        rec["current_stage"] = "done"
        rec["completed_at"] = datetime.utcnow()

        async with AsyncSessionLocal() as session:
            await session.execute(
                update(ScanJobRow)
                .where(ScanJobRow.scan_id == orchestration_id)
                .values(
                    status="completed",
                    progress=100.0,
                    service_results=rec["service_results"],
                    completed_at=rec["completed_at"],
                )
            )
            await session.commit()

        duration = time.time() - start
        m.scan_duration_seconds.labels(service="orchestrator").observe(duration)
        m.active_scans.labels(service="orchestrator").dec()
        logger.info(f"[{orchestration_id}] Pipeline completed in {duration:.1f}s")

    except Exception as e:
        logger.error(f"[{orchestration_id}] Pipeline failed at {rec.get('current_stage')}: {e}")
        rec["status"] = "failed"
        rec["error"] = str(e)
        rec["completed_at"] = datetime.utcnow()
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(ScanJobRow)
                .where(ScanJobRow.scan_id == orchestration_id)
                .values(
                    status="failed",
                    error=str(e),
                    service_results=rec["service_results"],
                    completed_at=rec["completed_at"],
                )
            )
            await session.commit()
        m.active_scans.labels(service="orchestrator").dec()


async def _persist_progress(orchestration_id: str, rec: dict):
    """Checkpoint current progress + partial service_results to DB."""
    async with AsyncSessionLocal() as session:
        await session.execute(
            update(ScanJobRow)
            .where(ScanJobRow.scan_id == orchestration_id)
            .values(
                progress=rec["progress"],
                service_results=rec["service_results"],
            )
        )
        await session.commit()


async def _run_service(
    service_name: str,
    config: ScanConfig,
    headers: dict,
    extra_body: dict,
) -> dict:
    """
    POST to a downstream service, poll until done, fetch and return results.
    Results are already persisted to DB by the service itself.
    """
    url = SERVICES[service_name]
    endpoint_map = {"scanner": "/scan", "validator": "/validate", "simulator": "/simulate"}
    id_key_map  = {"scanner": "scan_id", "validator": "validation_id", "simulator": "simulation_id"}

    endpoint = endpoint_map[service_name]
    id_key    = id_key_map[service_name]
    resource  = endpoint.lstrip("/")

    body = {"config": config.dict(), **extra_body}

    async with httpx.AsyncClient(headers=headers, timeout=None) as client:
        # Start the job
        r = await client.post(f"{url}{endpoint}", json=body, timeout=30.0)
        if r.status_code != 200:
            raise RuntimeError(f"{service_name} failed to start: {r.status_code} {r.text}")

        job_id = r.json()[id_key]

        # Poll until done
        while True:
            sr = await client.get(f"{url}/{resource}/{job_id}/status", timeout=10.0)
            if sr.status_code != 200:
                raise RuntimeError(f"Status check failed for {service_name}: {sr.status_code}")

            data = sr.json()
            if data["status"] in ("completed", "failed", "cancelled"):
                # Fetch full results (already in DB; this just returns the cache)
                rr = await client.get(f"{url}/{resource}/{job_id}/results", timeout=10.0)
                return {
                    "status": data["status"],
                    "service_id": job_id,
                    "results": rr.json() if rr.status_code == 200 else {},
                }

            await asyncio.sleep(3)


def _extract_vulnerabilities(scanner_result: dict) -> list:
    """Pull the list of vulnerable/failed TestResult dicts from a scanner result."""
    try:
        all_results = scanner_result.get("results", {}).get("results", [])
        return [r for r in all_results if r.get("status") in ("vulnerable", "failed")]
    except Exception:
        return []


def _findings_to_scenarios(findings: list) -> list:
    """
    Map scanner vulnerability categories to simulator attack scenarios.
    Always include basic_attacks; add advanced/pentest based on findings.
    """
    scenarios = ["basic_attacks"]

    categories = {f.get("category", "") for f in findings}

    advanced_triggers = {
        "sql_injection", "authentication_bypass", "command_injection",
        "xxe_injection", "ssrf", "idor",
    }
    pentest_triggers = {
        "file_upload_security", "cors_misconfiguration", "path_traversal",
    }

    if categories & advanced_triggers:
        scenarios.append("advanced_attacks")
    if categories & pentest_triggers:
        scenarios.append("penetration_testing")

    return scenarios


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

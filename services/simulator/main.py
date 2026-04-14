"""
Security Attack Simulator Microservice
"""

import os
import time
import uuid
from datetime import datetime
from shared.utils.timezone import now_ist
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig
from shared.utils import get_logger
from shared.auth import verify_api_key
from shared.db import init_db, AsyncSessionLocal, ScanResultRow, ScanJobRow, sanitize
from shared import metrics as m
from .simulator_engine import SimulatorEngine

logger = get_logger(__name__)

app = FastAPI(
    title="Security Attack Simulator",
    description="Simulates real-world security attacks and penetration testing",
    version="1.0.0",
)

simulator_engine = SimulatorEngine()
simulation_cache: Dict[str, Dict[str, Any]] = {}


@app.on_event("startup")
async def startup():
    await init_db()
    await _reload_cache_from_db()


async def _reload_cache_from_db():
    """Restore simulation records from DB on startup."""
    from sqlalchemy import select
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanJobRow).where(ScanJobRow.service_name == "simulator")
            )
            rows = result.scalars().all()
            for row in rows:
                status = row.status if row.status != "running" else "interrupted"
                simulation_cache[row.scan_id] = {
                    "simulation_id": row.scan_id,
                    "config": row.config or {},
                    "status": status,
                    "progress": row.progress or 0.0,
                    "results": [],
                    "attacks_simulated": row.results_count or 0,
                    "started_at": row.started_at,
                    "completed_at": row.completed_at,
                }
            logger.info(f"Restored {len(rows)} simulation records from DB")
    except Exception as e:
        logger.warning(f"Could not restore simulation cache from DB: {e}")


@app.get("/metrics", include_in_schema=False)
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


class SimulationRequest(BaseModel):
    config: ScanConfig
    attack_scenarios: List[str] = ["basic_attacks", "advanced_attacks"]
    callback_url: Optional[str] = None


class SimulationResponse(BaseModel):
    simulation_id: str
    status: str
    message: str
    started_at: datetime


@app.get("/")
async def root():
    return {"service": "Security Attack Simulator", "status": "healthy", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": now_ist().isoformat(),
            "service": "simulator", "version": "1.0.0"}


@app.post("/simulate", response_model=SimulationResponse, dependencies=[Depends(verify_api_key)])
async def start_simulation(request: SimulationRequest, background_tasks: BackgroundTasks):
    simulation_id = str(uuid.uuid4())
    now = now_ist()

    simulation_cache[simulation_id] = {
        "simulation_id": simulation_id,
        "config": request.config.dict(),
        "attack_scenarios": request.attack_scenarios,
        "status": "running",
        "progress": 0.0,
        "results": [],
        "attacks_simulated": 0,
        "started_at": now,
        "completed_at": None,
    }

    m.scans_total.labels(service="simulator").inc()
    m.active_scans.labels(service="simulator").inc()
    background_tasks.add_task(execute_simulation, simulation_id, request)
    logger.info(f"Started simulation {simulation_id}")

    return SimulationResponse(simulation_id=simulation_id, status="running",
                               message="Simulation started successfully", started_at=now)


@app.get("/simulate/{simulation_id}/status", dependencies=[Depends(verify_api_key)])
async def get_simulation_status(simulation_id: str):
    if simulation_id not in simulation_cache:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return simulation_cache[simulation_id]


@app.get("/simulate/{simulation_id}/results", dependencies=[Depends(verify_api_key)])
async def get_simulation_results(simulation_id: str):
    if simulation_id not in simulation_cache:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return simulation_cache[simulation_id]


@app.get("/scenarios", dependencies=[Depends(verify_api_key)])
async def list_attack_scenarios():
    return {"scenarios": [
        {"id": "basic_attacks", "name": "Basic Attack Simulation", "description": "Common web application attacks"},
        {"id": "advanced_attacks", "name": "Advanced Attack Simulation", "description": "Sophisticated attack patterns"},
        {"id": "penetration_testing", "name": "Penetration Testing", "description": "Comprehensive penetration testing"},
    ]}


async def execute_simulation(simulation_id: str, request: SimulationRequest):
    rec = simulation_cache[simulation_id]
    start = time.time()
    try:
        results = await simulator_engine.execute_simulation(
            request.config, request.attack_scenarios, simulation_id
        )

        async with AsyncSessionLocal() as session:
            job = ScanJobRow(
                scan_id=simulation_id,
                service_name="simulator",
                target_url=request.config.target_url,
                status="completed",
                progress=100.0,
                results_count=len(results),
                vulnerabilities_found=sum(1 for r in results if r.is_security_issue()),
                config=request.config.dict(),
                completed_at=now_ist(),
            )
            session.add(job)
            for result in results:
                session.add(ScanResultRow(
                    id=result.id,
                    scan_id=simulation_id,
                    service_name=result.service_name,
                    category=result.category,
                    test_name=result.test_name,
                    status=result.status,
                    vulnerability_level=result.vulnerability_level,
                    target_url=result.target_url,
                    method=result.method,
                    payload=sanitize(result.payload),
                    response_code=result.response_code,
                    response_time=result.response_time,
                    details=sanitize(result.details),
                ))
                m.tests_total.labels(service="simulator", category=result.category,
                                     status=result.status.value).inc()
                if result.is_security_issue() and result.vulnerability_level:
                    m.vulnerabilities_found.labels(service="simulator",
                                                   severity=result.vulnerability_level.value).inc()
            await session.commit()

        rec["results"] = [r.dict() for r in results]
        rec["attacks_simulated"] = len(results)
        rec["status"] = "completed"
        rec["progress"] = 100.0
        rec["completed_at"] = now_ist()

        m.scan_duration_seconds.labels(service="simulator").observe(time.time() - start)
        m.active_scans.labels(service="simulator").dec()
        logger.info(f"Simulation {simulation_id} completed with {len(results)} results")

    except Exception as e:
        logger.error(f"Simulation {simulation_id} failed: {e}")
        rec["status"] = "failed"
        rec["error"] = str(e)
        rec["completed_at"] = now_ist()
        m.active_scans.labels(service="simulator").dec()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)

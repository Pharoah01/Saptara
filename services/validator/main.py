"""
Security Feature Validator Microservice
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

from shared.models import ScanConfig, TestStatus
from shared.utils import get_logger
from shared.auth import verify_api_key
from shared.db import init_db, AsyncSessionLocal, ScanResultRow, ScanJobRow, sanitize
from shared import metrics as m
from .validator_engine import ValidatorEngine

logger = get_logger(__name__)

app = FastAPI(
    title="Security Feature Validator",
    description="Validates implemented security features and configurations",
    version="1.0.0",
)

validator_engine = ValidatorEngine()
validation_cache: Dict[str, Dict[str, Any]] = {}


@app.on_event("startup")
async def startup():
    await init_db()
    await _reload_cache_from_db()


async def _reload_cache_from_db():
    """Restore validation records from DB on startup."""
    from sqlalchemy import select
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanJobRow).where(ScanJobRow.service_name == "validator")
            )
            rows = result.scalars().all()
            for row in rows:
                status = row.status if row.status != "running" else "interrupted"
                validation_cache[row.scan_id] = {
                    "validation_id": row.scan_id,
                    "config": row.config or {},
                    "status": status,
                    "progress": row.progress or 0.0,
                    "results": [],
                    "features_validated": row.results_count or 0,
                    "started_at": row.started_at,
                    "completed_at": row.completed_at,
                }
            logger.info(f"Restored {len(rows)} validation records from DB")
    except Exception as e:
        logger.warning(f"Could not restore validation cache from DB: {e}")


@app.get("/metrics", include_in_schema=False)
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


class ValidationRequest(BaseModel):
    config: ScanConfig
    callback_url: Optional[str] = None


class ValidationResponse(BaseModel):
    validation_id: str
    status: str
    message: str
    started_at: datetime


@app.get("/")
async def root():
    return {"service": "Security Feature Validator", "status": "healthy", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": now_ist().isoformat(),
            "service": "validator", "version": "1.0.0"}


@app.post("/validate", response_model=ValidationResponse, dependencies=[Depends(verify_api_key)])
async def start_validation(request: ValidationRequest, background_tasks: BackgroundTasks):
    validation_id = str(uuid.uuid4())
    now = now_ist()

    validation_cache[validation_id] = {
        "validation_id": validation_id,
        "config": request.config.dict(),
        "status": "running",
        "progress": 0.0,
        "results": [],
        "features_validated": 0,
        "started_at": now,
        "completed_at": None,
    }

    m.scans_total.labels(service="validator").inc()
    m.active_scans.labels(service="validator").inc()
    background_tasks.add_task(execute_validation, validation_id, request.config)
    logger.info(f"Started validation {validation_id}")

    return ValidationResponse(validation_id=validation_id, status="running",
                               message="Validation started successfully", started_at=now)


@app.get("/validate/{validation_id}/status", dependencies=[Depends(verify_api_key)])
async def get_validation_status(validation_id: str):
    if validation_id not in validation_cache:
        raise HTTPException(status_code=404, detail="Validation not found")
    return validation_cache[validation_id]


@app.get("/validate/{validation_id}/results", dependencies=[Depends(verify_api_key)])
async def get_validation_results(validation_id: str):
    if validation_id not in validation_cache:
        raise HTTPException(status_code=404, detail="Validation not found")
    return validation_cache[validation_id]


async def execute_validation(validation_id: str, config: ScanConfig):
    rec = validation_cache[validation_id]
    start = time.time()
    try:
        results = await validator_engine.execute_validation(config, validation_id)

        async with AsyncSessionLocal() as session:
            job = ScanJobRow(
                scan_id=validation_id,
                service_name="validator",
                target_url=config.target_url,
                status="completed",
                progress=100.0,
                results_count=len(results),
                vulnerabilities_found=sum(1 for r in results if r.status == TestStatus.FAILED),
                config=config.dict(),
                completed_at=now_ist(),
            )
            session.add(job)
            for result in results:
                session.add(ScanResultRow(
                    id=result.id,
                    scan_id=validation_id,
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
                m.tests_total.labels(service="validator", category=result.category,
                                     status=result.status.value).inc()
            await session.commit()

        rec["results"] = [r.dict() for r in results]
        rec["features_validated"] = len(results)
        rec["status"] = "completed"
        rec["progress"] = 100.0
        rec["completed_at"] = now_ist()

        m.scan_duration_seconds.labels(service="validator").observe(time.time() - start)
        m.active_scans.labels(service="validator").dec()
        logger.info(f"Validation {validation_id} completed with {len(results)} results")

    except Exception as e:
        logger.error(f"Validation {validation_id} failed: {e}")
        rec["status"] = "failed"
        rec["error"] = str(e)
        rec["completed_at"] = now_ist()
        m.active_scans.labels(service="validator").dec()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)

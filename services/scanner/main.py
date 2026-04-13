"""
Universal Security Scanner Microservice
FastAPI-based microservice for comprehensive vulnerability scanning
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Security
from fastapi.responses import JSONResponse
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
import time
from datetime import datetime

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult, TestStatus
from shared.utils import get_logger
from shared.auth import verify_api_key
from shared.db import init_db, AsyncSessionLocal, ScanResultRow, ScanJobRow, sanitize
from shared import metrics as m
from .scanner_engine import ScannerEngine

logger = get_logger(__name__)

app = FastAPI(
    title="Universal Security Scanner",
    description="Comprehensive vulnerability scanning microservice",
    version="1.0.0",
)

scanner_engine = ScannerEngine()
# In-memory cache for fast status lookups — DB is source of truth
scan_cache: Dict[str, Dict[str, Any]] = {}


@app.on_event("startup")
async def startup():
    await init_db()
    await _reload_cache_from_db()


async def _reload_cache_from_db():
    """Restore scan job records from DB so status/results survive a restart."""
    from sqlalchemy import select
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanJobRow).where(ScanJobRow.service_name == "scanner")
            )
            rows = result.scalars().all()
            for row in rows:
                status = row.status if row.status != "running" else "interrupted"
                scan_cache[row.scan_id] = {
                    "scan_id": row.scan_id,
                    "config": row.config or {},
                    "status": status,
                    "progress": row.progress or 0.0,
                    "results": [],          # full results loaded on demand from scan_results table
                    "vulnerabilities_found": row.vulnerabilities_found or 0,
                    "started_at": row.started_at,
                    "completed_at": row.completed_at,
                }
            logger.info(f"Restored {len(rows)} scan records from DB")
    except Exception as e:
        logger.warning(f"Could not restore scan cache from DB: {e}")


# ---------------------------------------------------------------------------
# Prometheus metrics endpoint
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

class ScanRequest(BaseModel):
    config: ScanConfig
    callback_url: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    started_at: datetime


# ---------------------------------------------------------------------------
# Public endpoints (no auth)
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {"service": "Universal Security Scanner", "status": "healthy", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "scanner",
        "version": "1.0.0",
    }


# ---------------------------------------------------------------------------
# Protected endpoints
# ---------------------------------------------------------------------------

@app.post("/scan", response_model=ScanResponse, dependencies=[Depends(verify_api_key)])
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    now = datetime.utcnow()

    scan_cache[scan_id] = {
        "scan_id": scan_id,
        "config": scan_request.config.dict(),
        "status": "running",
        "progress": 0.0,
        "results": [],
        "vulnerabilities_found": 0,
        "started_at": now,
        "completed_at": None,
        "callback_url": scan_request.callback_url,
    }

    m.scans_total.labels(service="scanner").inc()
    m.active_scans.labels(service="scanner").inc()

    background_tasks.add_task(execute_scan, scan_id, scan_request.config)
    logger.info(f"Started scan {scan_id} for {scan_request.config.target_url}")

    return ScanResponse(scan_id=scan_id, status="running",
                        message="Scan started successfully", started_at=now)


@app.get("/scan/{scan_id}/status", dependencies=[Depends(verify_api_key)])
async def get_scan_status(scan_id: str):
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    rec = scan_cache[scan_id]
    return {
        "scan_id": scan_id,
        "status": rec["status"],
        "progress": rec["progress"],
        "results_count": len(rec["results"]),
        "vulnerabilities_found": rec["vulnerabilities_found"],
        "started_at": rec["started_at"],
        "completed_at": rec["completed_at"],
    }


@app.get("/scan/{scan_id}/results", dependencies=[Depends(verify_api_key)])
async def get_scan_results(scan_id: str):
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_cache[scan_id]


@app.delete("/scan/{scan_id}", dependencies=[Depends(verify_api_key)])
async def cancel_scan(scan_id: str):
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    rec = scan_cache[scan_id]
    if rec["status"] == "running":
        rec["status"] = "cancelled"
        rec["completed_at"] = datetime.utcnow()
        m.active_scans.labels(service="scanner").dec()
    return {"message": f"Scan {scan_id} cancelled"}


@app.get("/scans", dependencies=[Depends(verify_api_key)])
async def list_scans():
    return {"scans": [
        {
            "scan_id": sid,
            "target_url": r["config"]["target_url"],
            "status": r["status"],
            "progress": r["progress"],
            "started_at": r["started_at"],
            "completed_at": r["completed_at"],
        }
        for sid, r in scan_cache.items()
    ]}


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------

async def execute_scan(scan_id: str, config: ScanConfig):
    rec = scan_cache[scan_id]
    start = time.time()
    try:
        results = await scanner_engine.execute_scan(config, scan_id)

        # Persist to DB
        async with AsyncSessionLocal() as session:
            job = ScanJobRow(
                scan_id=scan_id,
                service_name="scanner",
                target_url=config.target_url,
                status="completed",
                progress=100.0,
                results_count=len(results),
                vulnerabilities_found=sum(1 for r in results if r.is_security_issue()),
                config=config.dict(),
                completed_at=datetime.utcnow(),
            )
            session.add(job)

            for result in results:
                row = ScanResultRow(
                    id=result.id,
                    scan_id=scan_id,
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
                    evidence=result.evidence,
                    recommendations=sanitize(result.recommendations),
                    metadata_=result.metadata,
                )
                session.add(row)
                # Metrics per test
                m.tests_total.labels(
                    service="scanner",
                    category=result.category,
                    status=result.status.value,
                ).inc()
                if result.is_security_issue() and result.vulnerability_level:
                    m.vulnerabilities_found.labels(
                        service="scanner",
                        severity=result.vulnerability_level.value,
                    ).inc()

            await session.commit()

        # Update cache
        rec["results"] = [r.dict() for r in results]
        rec["vulnerabilities_found"] = sum(1 for r in results if r.is_security_issue())
        rec["status"] = "completed"
        rec["progress"] = 100.0
        rec["completed_at"] = datetime.utcnow()

        duration = time.time() - start
        m.scan_duration_seconds.labels(service="scanner").observe(duration)
        m.active_scans.labels(service="scanner").dec()
        logger.info(f"Scan {scan_id} completed — {len(results)} results in {duration:.1f}s")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        rec["status"] = "failed"
        rec["error"] = str(e)
        rec["completed_at"] = datetime.utcnow()
        m.active_scans.labels(service="scanner").dec()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

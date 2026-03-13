"""
Universal Security Scanner Microservice
FastAPI-based microservice for comprehensive vulnerability scanning
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult, TestStatus
from shared.utils import get_logger, SecurityHTTPClient
from .scanner_engine import ScannerEngine

# Setup logging
logger = get_logger(__name__)

# FastAPI app
app = FastAPI(
    title="Universal Security Scanner",
    description="Comprehensive vulnerability scanning microservice",
    version="1.0.0"
)

# Global scanner engine
scanner_engine = ScannerEngine()

# In-memory storage for scan results (in production, use a database)
scan_results: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    """Scan request model"""
    config: ScanConfig
    callback_url: Optional[str] = None


class ScanResponse(BaseModel):
    """Scan response model"""
    scan_id: str
    status: str
    message: str
    started_at: datetime


class ScanStatusResponse(BaseModel):
    """Scan status response model"""
    scan_id: str
    status: str
    progress: float
    results_count: int
    vulnerabilities_found: int
    started_at: datetime
    completed_at: Optional[datetime] = None


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"service": "Universal Security Scanner", "status": "healthy", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "scanner",
        "version": "1.0.0"
    }


@app.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new security scan
    
    Args:
        scan_request: Scan configuration and parameters
        background_tasks: FastAPI background tasks
        
    Returns:
        Scan response with scan ID and status
    """
    try:
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan record
        scan_record = {
            "scan_id": scan_id,
            "config": scan_request.config.dict(),
            "status": "running",
            "progress": 0.0,
            "results": [],
            "vulnerabilities_found": 0,
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "callback_url": scan_request.callback_url
        }
        
        scan_results[scan_id] = scan_record
        
        # Start scan in background
        background_tasks.add_task(
            execute_scan,
            scan_id,
            scan_request.config
        )
        
        logger.info(f"Started scan {scan_id} for target {scan_request.config.target_url}")
        
        return ScanResponse(
            scan_id=scan_id,
            status="running",
            message="Scan started successfully",
            started_at=scan_record["started_at"]
        )
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@app.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """
    Get scan status and progress
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Scan status and progress information
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_record = scan_results[scan_id]
    
    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan_record["status"],
        progress=scan_record["progress"],
        results_count=len(scan_record["results"]),
        vulnerabilities_found=scan_record["vulnerabilities_found"],
        started_at=scan_record["started_at"],
        completed_at=scan_record["completed_at"]
    )


@app.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """
    Get scan results
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Complete scan results
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]


@app.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    """
    Cancel a running scan
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Cancellation confirmation
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_record = scan_results[scan_id]
    
    if scan_record["status"] == "running":
        scan_record["status"] = "cancelled"
        scan_record["completed_at"] = datetime.utcnow()
        logger.info(f"Cancelled scan {scan_id}")
        
    return {"message": f"Scan {scan_id} cancelled successfully"}


@app.get("/scans")
async def list_scans():
    """
    List all scans
    
    Returns:
        List of all scans with basic information
    """
    scans = []
    for scan_id, scan_record in scan_results.items():
        scans.append({
            "scan_id": scan_id,
            "target_url": scan_record["config"]["target_url"],
            "status": scan_record["status"],
            "progress": scan_record["progress"],
            "started_at": scan_record["started_at"],
            "completed_at": scan_record["completed_at"]
        })
    
    return {"scans": scans}


async def execute_scan(scan_id: str, config: ScanConfig):
    """
    Execute security scan in background
    
    Args:
        scan_id: Unique scan identifier
        config: Scan configuration
    """
    try:
        logger.info(f"Executing scan {scan_id}")
        
        # Get scan record
        scan_record = scan_results[scan_id]
        
        # Execute scan using scanner engine
        results = await scanner_engine.execute_scan(config, scan_id)
        
        # Update scan record
        scan_record["results"] = [result.dict() for result in results]
        scan_record["vulnerabilities_found"] = sum(
            1 for result in results if result.is_security_issue()
        )
        scan_record["status"] = "completed"
        scan_record["progress"] = 100.0
        scan_record["completed_at"] = datetime.utcnow()
        
        logger.info(f"Completed scan {scan_id} with {len(results)} results")
        
        # TODO: Send callback notification if callback_url is provided
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_record = scan_results.get(scan_id, {})
        scan_record["status"] = "failed"
        scan_record["error"] = str(e)
        scan_record["completed_at"] = datetime.utcnow()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
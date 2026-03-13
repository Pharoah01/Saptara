"""
Security Feature Validator Microservice
FastAPI-based microservice for validating implemented security features
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult, TestStatus
from shared.utils import get_logger
from .validator_engine import ValidatorEngine

logger = get_logger(__name__)

app = FastAPI(
    title="Security Feature Validator",
    description="Validates implemented security features and configurations",
    version="1.0.0"
)

validator_engine = ValidatorEngine()
validation_results: Dict[str, Dict[str, Any]] = {}


class ValidationRequest(BaseModel):
    """Validation request model"""
    config: ScanConfig
    callback_url: Optional[str] = None


class ValidationResponse(BaseModel):
    """Validation response model"""
    validation_id: str
    status: str
    message: str
    started_at: datetime


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"service": "Security Feature Validator", "status": "healthy", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "validator",
        "version": "1.0.0"
    }


@app.post("/validate", response_model=ValidationResponse)
async def start_validation(request: ValidationRequest, background_tasks: BackgroundTasks):
    """Start security feature validation"""
    try:
        validation_id = str(uuid.uuid4())
        
        validation_record = {
            "validation_id": validation_id,
            "config": request.config.dict(),
            "status": "running",
            "progress": 0.0,
            "results": [],
            "features_validated": 0,
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "callback_url": request.callback_url
        }
        
        validation_results[validation_id] = validation_record
        
        background_tasks.add_task(execute_validation, validation_id, request.config)
        
        logger.info(f"Started validation {validation_id} for target {request.config.target_url}")
        
        return ValidationResponse(
            validation_id=validation_id,
            status="running",
            message="Validation started successfully",
            started_at=validation_record["started_at"]
        )
        
    except Exception as e:
        logger.error(f"Failed to start validation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start validation: {str(e)}")


@app.get("/validate/{validation_id}/status")
async def get_validation_status(validation_id: str):
    """Get validation status"""
    if validation_id not in validation_results:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    return validation_results[validation_id]


@app.get("/validate/{validation_id}/results")
async def get_validation_results(validation_id: str):
    """Get validation results"""
    if validation_id not in validation_results:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    return validation_results[validation_id]


async def execute_validation(validation_id: str, config: ScanConfig):
    """Execute validation in background"""
    try:
        logger.info(f"Executing validation {validation_id}")
        
        validation_record = validation_results[validation_id]
        results = await validator_engine.execute_validation(config, validation_id)
        
        validation_record["results"] = [result.dict() for result in results]
        validation_record["features_validated"] = len(results)
        validation_record["status"] = "completed"
        validation_record["progress"] = 100.0
        validation_record["completed_at"] = datetime.utcnow()
        
        logger.info(f"Completed validation {validation_id} with {len(results)} results")
        
    except Exception as e:
        logger.error(f"Validation {validation_id} failed: {e}")
        validation_record = validation_results.get(validation_id, {})
        validation_record["status"] = "failed"
        validation_record["error"] = str(e)
        validation_record["completed_at"] = datetime.utcnow()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
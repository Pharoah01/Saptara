"""
Security Testing Orchestrator Microservice
Coordinates and manages all security testing services
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
import httpx
from datetime import datetime

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult
from shared.utils import get_logger

# Setup logging
logger = get_logger(__name__)

# FastAPI app
app = FastAPI(
    title="Security Testing Orchestrator",
    description="Coordinates all security testing microservices",
    version="1.0.0"
)

# Service endpoints
SERVICES = {
    "scanner": "http://localhost:8001",
    "validator": "http://localhost:8002", 
    "simulator": "http://localhost:8003"
}

# In-memory storage for orchestration results
orchestration_results: Dict[str, Dict[str, Any]] = {}


class OrchestrationRequest(BaseModel):
    """Orchestration request model"""
    config: ScanConfig
    services: List[str] = ["scanner", "validator", "simulator"]
    parallel: bool = True


class OrchestrationResponse(BaseModel):
    """Orchestration response model"""
    orchestration_id: str
    status: str
    message: str
    services_started: List[str]
    started_at: datetime


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "Security Testing Orchestrator", 
        "status": "healthy", 
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    service_health = {}
    
    async with httpx.AsyncClient() as client:
        for service_name, service_url in SERVICES.items():
            try:
                response = await client.get(f"{service_url}/health", timeout=5.0)
                service_health[service_name] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time": response.elapsed.total_seconds()
                }
            except Exception as e:
                service_health[service_name] = {
                    "status": "unreachable",
                    "error": str(e)
                }
    
    overall_status = "healthy" if all(
        s["status"] == "healthy" for s in service_health.values()
    ) else "degraded"
    
    return {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "service": "orchestrator",
        "version": "1.0.0",
        "services": service_health
    }


@app.post("/orchestrate", response_model=OrchestrationResponse)
async def start_orchestration(
    request: OrchestrationRequest, 
    background_tasks: BackgroundTasks
):
    """
    Start orchestrated security testing across multiple services
    
    Args:
        request: Orchestration configuration
        background_tasks: FastAPI background tasks
        
    Returns:
        Orchestration response with ID and status
    """
    try:
        # Generate unique orchestration ID
        orchestration_id = str(uuid.uuid4())
        
        # Initialize orchestration record
        orchestration_record = {
            "orchestration_id": orchestration_id,
            "config": request.config.dict(),
            "services": request.services,
            "parallel": request.parallel,
            "status": "running",
            "progress": 0.0,
            "service_results": {},
            "started_at": datetime.utcnow(),
            "completed_at": None
        }
        
        orchestration_results[orchestration_id] = orchestration_record
        
        # Start orchestration in background
        background_tasks.add_task(
            execute_orchestration,
            orchestration_id,
            request
        )
        
        logger.info(f"Started orchestration {orchestration_id} with services: {request.services}")
        
        return OrchestrationResponse(
            orchestration_id=orchestration_id,
            status="running",
            message="Orchestration started successfully",
            services_started=request.services,
            started_at=orchestration_record["started_at"]
        )
        
    except Exception as e:
        logger.error(f"Failed to start orchestration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start orchestration: {str(e)}")


@app.get("/orchestration/{orchestration_id}/status")
async def get_orchestration_status(orchestration_id: str):
    """Get orchestration status and progress"""
    if orchestration_id not in orchestration_results:
        raise HTTPException(status_code=404, detail="Orchestration not found")
    
    return orchestration_results[orchestration_id]


@app.get("/orchestration/{orchestration_id}/results")
async def get_orchestration_results(orchestration_id: str):
    """Get complete orchestration results"""
    if orchestration_id not in orchestration_results:
        raise HTTPException(status_code=404, detail="Orchestration not found")
    
    return orchestration_results[orchestration_id]


@app.get("/services")
async def list_services():
    """List all available services and their status"""
    service_status = {}
    
    async with httpx.AsyncClient() as client:
        for service_name, service_url in SERVICES.items():
            try:
                response = await client.get(f"{service_url}/health", timeout=5.0)
                service_status[service_name] = {
                    "url": service_url,
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time": response.elapsed.total_seconds()
                }
            except Exception as e:
                service_status[service_name] = {
                    "url": service_url,
                    "status": "unreachable",
                    "error": str(e)
                }
    
    return {"services": service_status}


async def execute_orchestration(orchestration_id: str, request: OrchestrationRequest):
    """Execute orchestrated security testing"""
    try:
        logger.info(f"Executing orchestration {orchestration_id}")
        
        orchestration_record = orchestration_results[orchestration_id]
        
        if request.parallel:
            # Execute services in parallel
            await execute_services_parallel(orchestration_record, request)
        else:
            # Execute services sequentially
            await execute_services_sequential(orchestration_record, request)
        
        # Mark as completed
        orchestration_record["status"] = "completed"
        orchestration_record["progress"] = 100.0
        orchestration_record["completed_at"] = datetime.utcnow()
        
        logger.info(f"Completed orchestration {orchestration_id}")
        
    except Exception as e:
        logger.error(f"Orchestration {orchestration_id} failed: {e}")
        orchestration_record = orchestration_results.get(orchestration_id, {})
        orchestration_record["status"] = "failed"
        orchestration_record["error"] = str(e)
        orchestration_record["completed_at"] = datetime.utcnow()


async def execute_services_parallel(orchestration_record: Dict, request: OrchestrationRequest):
    """Execute services in parallel"""
    import asyncio
    
    tasks = []
    for service_name in request.services:
        if service_name in SERVICES:
            task = execute_service(service_name, request.config, orchestration_record)
            tasks.append(task)
    
    # Wait for all services to complete
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    for i, result in enumerate(results):
        service_name = request.services[i]
        if isinstance(result, Exception):
            orchestration_record["service_results"][service_name] = {
                "status": "failed",
                "error": str(result)
            }
        else:
            orchestration_record["service_results"][service_name] = result


async def execute_services_sequential(orchestration_record: Dict, request: OrchestrationRequest):
    """Execute services sequentially"""
    for service_name in request.services:
        if service_name in SERVICES:
            try:
                result = await execute_service(service_name, request.config, orchestration_record)
                orchestration_record["service_results"][service_name] = result
            except Exception as e:
                orchestration_record["service_results"][service_name] = {
                    "status": "failed",
                    "error": str(e)
                }


async def execute_service(service_name: str, config: ScanConfig, orchestration_record: Dict):
    """Execute individual service"""
    service_url = SERVICES[service_name]
    
    async with httpx.AsyncClient() as client:
        # Start scan/test on the service
        if service_name == "scanner":
            endpoint = "/scan"
        elif service_name == "validator":
            endpoint = "/validate"
        elif service_name == "simulator":
            endpoint = "/simulate"
        else:
            raise ValueError(f"Unknown service: {service_name}")
        
        # Start the service
        response = await client.post(
            f"{service_url}{endpoint}",
            json={"config": config.dict()},
            timeout=30.0
        )
        
        if response.status_code != 200:
            raise Exception(f"Service {service_name} failed to start: {response.text}")
        
        service_response = response.json()
        service_id = service_response.get("scan_id") or service_response.get("validation_id") or service_response.get("simulation_id")
        
        # Poll for completion
        while True:
            status_response = await client.get(
                f"{service_url}/{endpoint.split('/')[1]}/{service_id}/status",
                timeout=10.0
            )
            
            if status_response.status_code != 200:
                raise Exception(f"Failed to get status from {service_name}")
            
            status_data = status_response.json()
            
            if status_data["status"] in ["completed", "failed", "cancelled"]:
                # Get final results
                results_response = await client.get(
                    f"{service_url}/{endpoint.split('/')[1]}/{service_id}/results",
                    timeout=10.0
                )
                
                return {
                    "status": status_data["status"],
                    "service_id": service_id,
                    "results": results_response.json() if results_response.status_code == 200 else None
                }
            
            # Wait before next poll
            await asyncio.sleep(2)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
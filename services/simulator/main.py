"""
Security Attack Simulator Microservice
FastAPI-based microservice for simulating real-world attacks
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult
from shared.utils import get_logger
from .simulator_engine import SimulatorEngine

logger = get_logger(__name__)

app = FastAPI(
    title="Security Attack Simulator",
    description="Simulates real-world security attacks and penetration testing",
    version="1.0.0"
)

simulator_engine = SimulatorEngine()
simulation_results: Dict[str, Dict[str, Any]] = {}


class SimulationRequest(BaseModel):
    """Simulation request model"""
    config: ScanConfig
    attack_scenarios: List[str] = ["basic_attacks", "advanced_attacks"]
    callback_url: Optional[str] = None


class SimulationResponse(BaseModel):
    """Simulation response model"""
    simulation_id: str
    status: str
    message: str
    started_at: datetime


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"service": "Security Attack Simulator", "status": "healthy", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "simulator",
        "version": "1.0.0"
    }


@app.post("/simulate", response_model=SimulationResponse)
async def start_simulation(request: SimulationRequest, background_tasks: BackgroundTasks):
    """Start attack simulation"""
    try:
        simulation_id = str(uuid.uuid4())
        
        simulation_record = {
            "simulation_id": simulation_id,
            "config": request.config.dict(),
            "attack_scenarios": request.attack_scenarios,
            "status": "running",
            "progress": 0.0,
            "results": [],
            "attacks_simulated": 0,
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "callback_url": request.callback_url
        }
        
        simulation_results[simulation_id] = simulation_record
        
        background_tasks.add_task(execute_simulation, simulation_id, request)
        
        logger.info(f"Started simulation {simulation_id} for target {request.config.target_url}")
        
        return SimulationResponse(
            simulation_id=simulation_id,
            status="running",
            message="Simulation started successfully",
            started_at=simulation_record["started_at"]
        )
        
    except Exception as e:
        logger.error(f"Failed to start simulation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start simulation: {str(e)}")


@app.get("/simulate/{simulation_id}/status")
async def get_simulation_status(simulation_id: str):
    """Get simulation status"""
    if simulation_id not in simulation_results:
        raise HTTPException(status_code=404, detail="Simulation not found")
    
    return simulation_results[simulation_id]


@app.get("/simulate/{simulation_id}/results")
async def get_simulation_results(simulation_id: str):
    """Get simulation results"""
    if simulation_id not in simulation_results:
        raise HTTPException(status_code=404, detail="Simulation not found")
    
    return simulation_results[simulation_id]


@app.get("/scenarios")
async def list_attack_scenarios():
    """List available attack scenarios"""
    return {
        "scenarios": [
            {
                "id": "basic_attacks",
                "name": "Basic Attack Simulation",
                "description": "Common web application attacks"
            },
            {
                "id": "advanced_attacks", 
                "name": "Advanced Attack Simulation",
                "description": "Sophisticated attack patterns"
            },
            {
                "id": "penetration_testing",
                "name": "Penetration Testing",
                "description": "Comprehensive penetration testing scenarios"
            }
        ]
    }


async def execute_simulation(simulation_id: str, request: SimulationRequest):
    """Execute attack simulation in background"""
    try:
        logger.info(f"Executing simulation {simulation_id}")
        
        simulation_record = simulation_results[simulation_id]
        results = await simulator_engine.execute_simulation(request.config, request.attack_scenarios, simulation_id)
        
        simulation_record["results"] = [result.dict() for result in results]
        simulation_record["attacks_simulated"] = len(results)
        simulation_record["status"] = "completed"
        simulation_record["progress"] = 100.0
        simulation_record["completed_at"] = datetime.utcnow()
        
        logger.info(f"Completed simulation {simulation_id} with {len(results)} results")
        
    except Exception as e:
        logger.error(f"Simulation {simulation_id} failed: {e}")
        simulation_record = simulation_results.get(simulation_id, {})
        simulation_record["status"] = "failed"
        simulation_record["error"] = str(e)
        simulation_record["completed_at"] = datetime.utcnow()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
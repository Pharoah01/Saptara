"""
Tests for simulator engine
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock

from services.simulator.simulator_engine import SimulatorEngine
from shared.models import ScanConfig, TestStatus


@pytest.fixture
def simulator_engine():
    """Create simulator engine instance"""
    return SimulatorEngine()


@pytest.fixture
def sample_config():
    """Create sample scan configuration"""
    return ScanConfig(
        target_url="https://example.com",
        timeout=5,
        delay=0.1
    )


@pytest.mark.asyncio
async def test_execute_simulation(simulator_engine, sample_config):
    """Test simulation execution"""
    scenarios = ["basic_attacks", "advanced_attacks"]
    results = await simulator_engine.execute_simulation(sample_config, scenarios, "test-simulation-1")
    
    assert isinstance(results, list)
    assert len(results) >= 0


@pytest.mark.asyncio
async def test_basic_attacks_simulation(simulator_engine, sample_config):
    """Test basic attacks simulation"""
    results = await simulator_engine._simulate_basic_attacks(sample_config, "test-simulation")
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_advanced_attacks_simulation(simulator_engine, sample_config):
    """Test advanced attacks simulation"""
    results = await simulator_engine._simulate_advanced_attacks(sample_config, "test-simulation")
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_penetration_testing_simulation(simulator_engine, sample_config):
    """Test penetration testing simulation"""
    results = await simulator_engine._simulate_penetration_testing(sample_config, "test-simulation")
    assert isinstance(results, list)
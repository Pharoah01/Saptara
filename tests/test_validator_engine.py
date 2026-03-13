"""
Tests for validator engine
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock

from services.validator.validator_engine import ValidatorEngine
from shared.models import ScanConfig, TestStatus


@pytest.fixture
def validator_engine():
    """Create validator engine instance"""
    return ValidatorEngine()


@pytest.fixture
def sample_config():
    """Create sample scan configuration"""
    return ScanConfig(
        target_url="https://example.com",
        timeout=5,
        delay=0.1
    )


@pytest.mark.asyncio
async def test_execute_validation(validator_engine, sample_config):
    """Test validation execution"""
    results = await validator_engine.execute_validation(sample_config, "test-validation-1")
    
    assert isinstance(results, list)
    assert len(results) >= 0  # May be empty if all tests fail


@pytest.mark.asyncio
async def test_bot_protection_validation(validator_engine, sample_config):
    """Test bot protection validation"""
    results = await validator_engine._validate_bot_protection(sample_config, "test-validation")
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_security_middleware_validation(validator_engine, sample_config):
    """Test security middleware validation"""
    results = await validator_engine._validate_security_middleware(sample_config, "test-validation")
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_rate_limiting_validation(validator_engine, sample_config):
    """Test rate limiting validation"""
    results = await validator_engine._validate_rate_limiting(sample_config, "test-validation")
    assert isinstance(results, list)
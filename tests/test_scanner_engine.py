"""
Tests for scanner engine
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock

from services.scanner.scanner_engine import ScannerEngine
from shared.models import ScanConfig, TestCategory, IntensityLevel, TestStatus


@pytest.fixture
def scanner_engine():
    """Create scanner engine instance"""
    return ScannerEngine()


@pytest.fixture
def sample_config():
    """Create sample scan configuration"""
    return ScanConfig(
        target_url="https://example.com",
        test_categories=[TestCategory.SQL_INJECTION, TestCategory.XSS],
        intensity=IntensityLevel.LIGHT,
        timeout=5,
        delay=0.1
    )


@pytest.mark.asyncio
async def test_execute_scan(scanner_engine, sample_config):
    """Test scan execution"""
    results = await scanner_engine.execute_scan(sample_config, "test-scan-1")
    
    assert isinstance(results, list)
    assert len(results) > 0


@pytest.mark.asyncio
async def test_sql_injection_analysis(scanner_engine):
    """Test SQL injection response analysis"""
    mock_response = Mock()
    mock_response.status = 500
    mock_response.text_content = "mysql_fetch_array error"
    
    status, vuln_level, details = scanner_engine._analyze_sql_response(mock_response, "' OR 1=1", 0.1)
    
    assert status == TestStatus.VULNERABLE
    assert vuln_level is not None
    assert "error" in details.lower()


@pytest.mark.asyncio
async def test_path_traversal_analysis(scanner_engine):
    """Test path traversal response analysis"""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.text_content = "root:x:0:0:root:/root:/bin/bash"
    
    status, vuln_level, details = scanner_engine._analyze_path_traversal_response(mock_response, "../../../etc/passwd")
    
    assert status == TestStatus.VULNERABLE
    assert vuln_level is not None
    assert "Path traversal" in details


@pytest.mark.asyncio
async def test_xss_analysis(scanner_engine):
    """Test XSS response analysis"""
    mock_response = Mock()
    mock_response.status = 200
    mock_response.text_content = "<script>alert('XSS')</script>"
    
    status, vuln_level, details = scanner_engine._analyze_xss_response(mock_response, "<script>alert('XSS')</script>")
    
    assert status == TestStatus.VULNERABLE
    assert vuln_level is not None
    assert "XSS" in details


def test_intensity_config(sample_config):
    """Test intensity configuration"""
    sample_config.intensity = IntensityLevel.LIGHT
    config = sample_config.get_intensity_config()
    assert config['max_payloads'] == 5
    assert config['max_endpoints'] == 10
    
    sample_config.intensity = IntensityLevel.HEAVY
    config = sample_config.get_intensity_config()
    assert config['max_payloads'] is None
    assert config['max_endpoints'] is None


def test_category_enabled(sample_config):
    """Test category enablement check"""
    assert sample_config.is_category_enabled(TestCategory.SQL_INJECTION)
    assert sample_config.is_category_enabled(TestCategory.XSS)
    assert not sample_config.is_category_enabled(TestCategory.RATE_LIMITING)
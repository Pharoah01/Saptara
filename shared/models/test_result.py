"""
Test result data models
"""

from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class TestStatus(str, Enum):
    """Test execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    VULNERABLE = "vulnerable"
    ERROR = "error"
    SKIPPED = "skipped"


class VulnerabilityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestResult(BaseModel):
    """Individual test result model"""
    
    id: str = Field(..., description="Unique test identifier")
    category: str = Field(..., description="Test category (e.g., SQL Injection)")
    test_name: str = Field(..., description="Specific test name")
    status: TestStatus = Field(..., description="Test execution status")
    vulnerability_level: Optional[VulnerabilityLevel] = Field(None, description="Vulnerability severity if found")
    
    # Request/Response details
    target_url: str = Field(..., description="Target URL tested")
    method: str = Field(default="GET", description="HTTP method used")
    payload: Optional[str] = Field(None, description="Test payload used")
    response_code: Optional[int] = Field(None, description="HTTP response code")
    response_time: Optional[float] = Field(None, description="Response time in seconds")
    response_size: Optional[int] = Field(None, description="Response size in bytes")
    
    # Test metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Test execution timestamp")
    duration: Optional[float] = Field(None, description="Test duration in seconds")
    service_name: str = Field(..., description="Microservice that executed the test")
    
    # Additional details
    details: Optional[str] = Field(None, description="Additional test details or error messages")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Evidence of vulnerability or blocking")
    recommendations: Optional[str] = Field(None, description="Security recommendations")
    
    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        
    def is_security_issue(self) -> bool:
        """Check if this result indicates a security issue"""
        return self.status in [TestStatus.VULNERABLE, TestStatus.FAILED]
    
    def is_protected(self) -> bool:
        """Check if this result indicates proper protection"""
        return self.status in [TestStatus.BLOCKED, TestStatus.PASSED]
    
    def get_severity_score(self) -> int:
        """Get numeric severity score for sorting"""
        severity_scores = {
            VulnerabilityLevel.CRITICAL: 5,
            VulnerabilityLevel.HIGH: 4,
            VulnerabilityLevel.MEDIUM: 3,
            VulnerabilityLevel.LOW: 2,
            VulnerabilityLevel.INFO: 1
        }
        return severity_scores.get(self.vulnerability_level, 0)
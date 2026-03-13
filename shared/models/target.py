"""
Target system data models
"""

from enum import Enum
from typing import Optional, Dict, List
from pydantic import BaseModel, Field, validator
from urllib.parse import urlparse


class TargetType(str, Enum):
    """Target system types"""
    WEB_APPLICATION = "web_application"
    API = "api"
    MICROSERVICE = "microservice"
    MOBILE_BACKEND = "mobile_backend"
    UNKNOWN = "unknown"


class Target(BaseModel):
    """Target system model"""
    
    # Basic information
    url: str = Field(..., description="Target URL")
    name: Optional[str] = Field(None, description="Target name")
    description: Optional[str] = Field(None, description="Target description")
    target_type: TargetType = Field(default=TargetType.UNKNOWN, description="Target type")
    
    # Technical details
    domain: Optional[str] = Field(None, description="Target domain")
    port: Optional[int] = Field(None, description="Target port")
    protocol: Optional[str] = Field(None, description="Protocol (http/https)")
    
    # Technology stack (if known)
    technologies: Optional[List[str]] = Field(None, description="Known technologies")
    frameworks: Optional[List[str]] = Field(None, description="Known frameworks")
    server_info: Optional[str] = Field(None, description="Server information")
    
    # Security information
    has_waf: Optional[bool] = Field(None, description="Has Web Application Firewall")
    has_rate_limiting: Optional[bool] = Field(None, description="Has rate limiting")
    requires_auth: Optional[bool] = Field(None, description="Requires authentication")
    
    # Contact and authorization
    owner: Optional[str] = Field(None, description="Target owner/organization")
    contact_email: Optional[str] = Field(None, description="Contact email")
    authorization_status: str = Field(default="unknown", description="Authorization status")
    authorization_document: Optional[str] = Field(None, description="Authorization document reference")
    
    # Testing metadata
    last_tested: Optional[str] = Field(None, description="Last test date")
    test_frequency: Optional[str] = Field(None, description="Recommended test frequency")
    risk_level: Optional[str] = Field(default="medium", description="Risk level for testing")
    
    # Custom metadata
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('url')
    def validate_url(cls, v):
        """Validate and parse URL"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v
    
    def __post_init__(self):
        """Extract domain, port, and protocol from URL"""
        parsed = urlparse(self.url)
        self.domain = parsed.netloc.split(':')[0]
        self.port = parsed.port
        self.protocol = parsed.scheme
    
    def get_base_url(self) -> str:
        """Get base URL without path"""
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def is_https(self) -> bool:
        """Check if target uses HTTPS"""
        return self.url.startswith('https://')
    
    def is_authorized(self) -> bool:
        """Check if testing is authorized"""
        return self.authorization_status.lower() in ['authorized', 'approved', 'yes']
    
    def get_risk_score(self) -> int:
        """Get numeric risk score"""
        risk_scores = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return risk_scores.get(self.risk_level.lower(), 2)
"""
Scan configuration data models
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator


class TestCategory(str, Enum):
    """Available test categories — mapped to OWASP Top 10 2021"""
    # A03 Injection
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    XXE_INJECTION = "xxe_injection"
    # A01 Broken Access Control
    AUTHENTICATION_BYPASS = "authentication_bypass"
    API_ENUMERATION = "api_enumeration"
    IDOR = "idor"
    # A02 Cryptographic Failures
    SSL_TLS_SECURITY = "ssl_tls_security"
    INFORMATION_DISCLOSURE = "information_disclosure"
    # A05 Security Misconfiguration
    SECURITY_HEADERS = "security_headers"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    # A07 Auth & Session Failures
    RATE_LIMITING = "rate_limiting"
    CSRF_PROTECTION = "csrf_protection"
    # A08 Software & Data Integrity
    FILE_UPLOAD_SECURITY = "file_upload_security"
    # A10 SSRF
    SSRF = "ssrf"
    # Other
    PATH_TRAVERSAL = "path_traversal"
    BOT_DETECTION = "bot_detection"


class IntensityLevel(str, Enum):
    """Test intensity levels"""
    LIGHT = "light"
    MEDIUM = "medium"
    HEAVY = "heavy"


class ScanConfig(BaseModel):
    """Scan configuration model"""
    
    # Target configuration
    target_url: str = Field(..., description="Target URL to scan")
    target_name: Optional[str] = Field(None, description="Human-readable target name")
    
    # Test selection
    test_categories: List[TestCategory] = Field(
        default_factory=lambda: list(TestCategory),
        description="Test categories to execute"
    )
    intensity: IntensityLevel = Field(
        default=IntensityLevel.MEDIUM,
        description="Test intensity level"
    )
    
    # Execution configuration
    timeout: int = Field(default=10, description="Request timeout in seconds")
    delay: float = Field(default=0.5, description="Delay between requests in seconds")
    max_concurrent: int = Field(default=5, description="Maximum concurrent requests")
    retry_attempts: int = Field(default=3, description="Number of retry attempts for failed requests")
    
    # Output configuration
    verbose: bool = Field(default=False, description="Enable verbose output")
    save_evidence: bool = Field(default=True, description="Save evidence of vulnerabilities")
    output_format: str = Field(default="json", description="Output format (json, xml, csv)")
    
    # Authentication (if needed)
    auth_token: Optional[str] = Field(None, description="Authentication token")
    auth_headers: Optional[Dict[str, str]] = Field(None, description="Authentication headers")
    
    # Custom configuration
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    custom_payloads: Optional[Dict[str, List[str]]] = Field(None, description="Custom test payloads")
    excluded_endpoints: Optional[List[str]] = Field(None, description="Endpoints to exclude from testing")
    
    # Rate limiting
    requests_per_second: Optional[float] = Field(None, description="Rate limit for requests per second")
    
    # Metadata
    scan_id: Optional[str] = Field(None, description="Unique scan identifier")
    user_agent: str = Field(
        default="SecurityTestSuite/1.0 (Authorized Testing)",
        description="User agent string"
    )
    
    @validator('target_url')
    def validate_target_url(cls, v):
        """Validate target URL format"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Target URL must start with http:// or https://')
        return v
    
    @validator('timeout')
    def validate_timeout(cls, v):
        """Validate timeout value"""
        if v <= 0 or v > 300:
            raise ValueError('Timeout must be between 1 and 300 seconds')
        return v
    
    @validator('delay')
    def validate_delay(cls, v):
        """Validate delay value"""
        if v < 0 or v > 10:
            raise ValueError('Delay must be between 0 and 10 seconds')
        return v
    
    def get_intensity_config(self) -> Dict[str, Any]:
        """Get configuration based on intensity level"""
        intensity_configs = {
            IntensityLevel.LIGHT: {
                'max_payloads': 5,
                'max_endpoints': 10,
                'delay': max(self.delay, 1.0),
                'timeout': max(self.timeout, 15)
            },
            IntensityLevel.MEDIUM: {
                'max_payloads': 15,
                'max_endpoints': 25,
                'delay': self.delay,
                'timeout': self.timeout
            },
            IntensityLevel.HEAVY: {
                'max_payloads': None,  # No limit
                'max_endpoints': None,  # No limit
                'delay': min(self.delay, 0.2),
                'timeout': min(self.timeout, 5)
            }
        }
        return intensity_configs.get(self.intensity, intensity_configs[IntensityLevel.MEDIUM])
    
    def is_category_enabled(self, category: TestCategory) -> bool:
        """Check if a test category is enabled"""
        return category in self.test_categories
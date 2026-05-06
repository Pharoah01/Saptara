"""
Core validation engine for security feature validation
"""

import asyncio
from typing import List
from urllib.parse import urljoin

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult, TestStatus, VulnerabilityLevel
from shared.utils import get_logger, SecurityHTTPClient

logger = get_logger(__name__)


class ValidatorEngine:
    """Core security feature validation engine"""
    
    async def execute_validation(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Execute security feature validation"""
        logger.info(f"Starting validation {validation_id} for {config.target_url}")

        async def _run(fn):
            try:
                return await fn(config, validation_id)
            except Exception as e:
                logger.error(f"Validation test {fn.__name__} failed: {e}")
                return []

        batches = await asyncio.gather(*[
            _run(self._validate_bot_protection),
            _run(self._validate_security_middleware),
            _run(self._validate_rate_limiting),
            _run(self._validate_session_security),
            _run(self._validate_csrf_protection),
            _run(self._validate_input_validation),
            _run(self._validate_security_headers),
            _run(self._validate_robots_txt),
        ])
        results = [r for batch in batches for r in batch]
        logger.info(f"Validation {validation_id} completed with {len(results)} results")
        return results
    
    async def _validate_bot_protection(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate bot protection middleware"""
        results = []
        
        malicious_agents = [
            "sqlmap/1.0", "nikto/2.1.6", "Nmap Scripting Engine",
            "w3af.org", "OWASP ZAP", "Burp Suite"
        ]
        
        async with SecurityHTTPClient(config) as client:
            for agent in malicious_agents:
                test_id = f"{validation_id}-bot-{hash(agent)}"
                
                try:
                    response = await client.make_async_request(
                        'GET', '/api/challenges/',
                        headers={'User-Agent': agent}
                    )
                    
                    if "Access denied" in getattr(response, 'text_content', '') or response.status == 403:
                        status = TestStatus.PASSED
                        details = f"Bot {agent} correctly blocked"
                    else:
                        status = TestStatus.FAILED
                        details = f"Bot {agent} not blocked - Response: {response.status}"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="Bot Protection",
                        test_name=f"Block {agent}",
                        status=status,
                        target_url=urljoin(config.target_url, '/api/challenges/'),
                        method='GET',
                        service_name="validator",
                        details=details
                    ))
                    
                except Exception as e:
                    results.append(TestResult(
                        id=test_id,
                        category="Bot Protection",
                        test_name=f"Block {agent}",
                        status=TestStatus.ERROR,
                        target_url=urljoin(config.target_url, '/api/challenges/'),
                        method='GET',
                        service_name="validator",
                        details=f"Test failed: {str(e)}"
                    ))
        
        return results
    
    async def _validate_security_middleware(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate security middleware"""
        results = []
        
        # Test SQL injection detection
        sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
        
        async with SecurityHTTPClient(config) as client:
            for payload in sql_payloads:
                test_id = f"{validation_id}-sql-{hash(payload)}"
                
                try:
                    response = await client.make_async_request(
                        'GET', '/api/auth/login/',
                        payload=payload
                    )
                    
                    response_text = getattr(response, 'text_content', '').lower()
                    
                    if "security" in response_text or response.status == 403:
                        status = TestStatus.PASSED
                        details = "SQL injection correctly detected and blocked"
                    else:
                        status = TestStatus.FAILED
                        details = f"SQL injection not detected - Response: {response.status}"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="Security Middleware",
                        test_name="SQL Injection Detection",
                        status=status,
                        target_url=urljoin(config.target_url, '/api/auth/login/'),
                        method='GET',
                        payload=payload,
                        service_name="validator",
                        details=details
                    ))
                    
                except Exception as e:
                    results.append(TestResult(
                        id=test_id,
                        category="Security Middleware",
                        test_name="SQL Injection Detection",
                        status=TestStatus.ERROR,
                        target_url=urljoin(config.target_url, '/api/auth/login/'),
                        method='GET',
                        payload=payload,
                        service_name="validator",
                        details=f"Test failed: {str(e)}"
                    ))
        
        return results
    
    async def _validate_rate_limiting(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate rate limiting"""
        results = []
        test_id = f"{validation_id}-rate-limiting"
        
        async with SecurityHTTPClient(config) as client:
            blocked_count = 0
            rapid_requests = 15
            
            try:
                for i in range(rapid_requests):
                    response = await client.make_async_request(
                        'POST', '/api/auth/login/',
                        payload=f'{{"username": "test{i}", "password": "password"}}'
                    )
                    
                    if response.status == 429 or "rate limit" in getattr(response, 'text_content', '').lower():
                        blocked_count += 1
                    
                    await asyncio.sleep(0.1)
                
                if blocked_count > 0:
                    status = TestStatus.PASSED
                    details = f"Rate limiting active - {blocked_count}/{rapid_requests} requests blocked"
                else:
                    status = TestStatus.FAILED
                    details = f"No rate limiting detected - 0/{rapid_requests} requests blocked"
                
                results.append(TestResult(
                    id=test_id,
                    category="Rate Limiting",
                    test_name="Rapid Request Protection",
                    status=status,
                    target_url=urljoin(config.target_url, '/api/auth/login/'),
                    method='POST',
                    service_name="validator",
                    details=details
                ))
                
            except Exception as e:
                results.append(TestResult(
                    id=test_id,
                    category="Rate Limiting",
                    test_name="Rapid Request Protection",
                    status=TestStatus.ERROR,
                    target_url=urljoin(config.target_url, '/api/auth/login/'),
                    method='POST',
                    service_name="validator",
                    details=f"Test failed: {str(e)}"
                ))
        
        return results
    
    async def _validate_session_security(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate session security"""
        results = []
        test_id = f"{validation_id}-session-security"
        
        async with SecurityHTTPClient(config) as client:
            try:
                # Test session cookie security
                response = await client.make_async_request('POST', '/api/auth/login/',
                                                         '{"username": "testuser", "password": "testpass"}')
                
                cookies = getattr(response, 'cookies', {})
                session_cookie = None
                
                # Find session cookie
                for cookie_name in ['sessionid', 'csrftoken', 'session', 'auth_token']:
                    if cookie_name in cookies:
                        session_cookie = cookies[cookie_name]
                        break
                
                if session_cookie:
                    secure_flag = getattr(session_cookie, 'secure', False)
                    httponly_flag = getattr(session_cookie, 'httponly', False)
                    samesite = getattr(session_cookie, 'samesite', None)
                    
                    issues = []
                    if not secure_flag:
                        issues.append("Missing Secure flag")
                    if not httponly_flag:
                        issues.append("Missing HttpOnly flag")
                    if not samesite or samesite.lower() not in ['strict', 'lax']:
                        issues.append("Missing or weak SameSite attribute")
                    
                    if issues:
                        status = TestStatus.FAILED
                        details = f"Session cookie security issues: {', '.join(issues)}"
                    else:
                        status = TestStatus.PASSED
                        details = "Session cookie properly secured"
                else:
                    status = TestStatus.FAILED
                    details = "No session cookie found"
                
                results.append(TestResult(
                    id=test_id,
                    category="Session Security",
                    test_name="Session Cookie Security",
                    status=status,
                    target_url=urljoin(config.target_url, '/api/auth/login/'),
                    method='POST',
                    service_name="validator",
                    details=details
                ))
                
            except Exception as e:
                results.append(TestResult(
                    id=test_id,
                    category="Session Security",
                    test_name="Session Cookie Security",
                    status=TestStatus.ERROR,
                    target_url=urljoin(config.target_url, '/api/auth/login/'),
                    method='POST',
                    service_name="validator",
                    details=f"Session security test failed: {str(e)}"
                ))
        
        return results
    
    async def _validate_csrf_protection(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate CSRF protection"""
        results = []
        test_id = f"{validation_id}-csrf-protection"
        
        async with SecurityHTTPClient(config) as client:
            try:
                # Test CSRF protection on state-changing operations
                response = await client.make_async_request('POST', '/api/users/profile/',
                                                         '{"name": "Test User", "email": "test@example.com"}')
                
                response_text = getattr(response, 'text_content', '').lower()
                
                if response.status == 403 and ('csrf' in response_text or 'forbidden' in response_text):
                    status = TestStatus.PASSED
                    details = "CSRF protection active - request blocked"
                elif response.status == 400 and 'csrf' in response_text:
                    status = TestStatus.PASSED
                    details = "CSRF protection active - token required"
                else:
                    status = TestStatus.FAILED
                    details = f"CSRF protection may be missing - Response: {response.status}"
                
                results.append(TestResult(
                    id=test_id,
                    category="CSRF Protection",
                    test_name="CSRF Token Validation",
                    status=status,
                    target_url=urljoin(config.target_url, '/api/users/profile/'),
                    method='POST',
                    service_name="validator",
                    details=details
                ))
                
            except Exception as e:
                results.append(TestResult(
                    id=test_id,
                    category="CSRF Protection",
                    test_name="CSRF Token Validation",
                    status=TestStatus.ERROR,
                    target_url=urljoin(config.target_url, '/api/users/profile/'),
                    method='POST',
                    service_name="validator",
                    details=f"CSRF protection test failed: {str(e)}"
                ))
        
        return results
    
    async def _validate_input_validation(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate input validation"""
        results = []
        
        # Test various input validation scenarios
        test_cases = [
            {
                'name': 'SQL Injection Input',
                'endpoint': '/api/auth/login/',
                'payload': '{"username": "\' OR \'1\'=\'1", "password": "test"}',
                'expected_blocked': True
            },
            {
                'name': 'XSS Input',
                'endpoint': '/api/users/profile/',
                'payload': '{"name": "<script>alert(1)</script>", "email": "test@example.com"}',
                'expected_blocked': True
            },
            {
                'name': 'Path Traversal Input',
                'endpoint': '/api/files/',
                'payload': '{"filename": "../../../etc/passwd"}',
                'expected_blocked': True
            }
        ]
        
        async with SecurityHTTPClient(config) as client:
            for test_case in test_cases:
                test_id = f"{validation_id}-input-{hash(test_case['name'])}"
                
                try:
                    response = await client.make_async_request('POST', test_case['endpoint'], test_case['payload'])
                    response_text = getattr(response, 'text_content', '').lower()
                    
                    is_blocked = (response.status in [400, 403] or 
                                'invalid' in response_text or 
                                'blocked' in response_text or
                                'security' in response_text)
                    
                    if test_case['expected_blocked'] and is_blocked:
                        status = TestStatus.PASSED
                        details = f"Malicious input correctly blocked: {test_case['name']}"
                    elif test_case['expected_blocked'] and not is_blocked:
                        status = TestStatus.FAILED
                        details = f"Malicious input not blocked: {test_case['name']}"
                    else:
                        status = TestStatus.PASSED
                        details = f"Input validation working as expected: {test_case['name']}"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="Input Validation",
                        test_name=test_case['name'],
                        status=status,
                        target_url=urljoin(config.target_url, test_case['endpoint']),
                        method='POST',
                        payload=test_case['payload'],
                        service_name="validator",
                        details=details
                    ))
                    
                except Exception as e:
                    results.append(TestResult(
                        id=test_id,
                        category="Input Validation",
                        test_name=test_case['name'],
                        status=TestStatus.ERROR,
                        target_url=urljoin(config.target_url, test_case['endpoint']),
                        method='POST',
                        payload=test_case['payload'],
                        service_name="validator",
                        details=f"Input validation test failed: {str(e)}"
                    ))
        
        return results
    
    async def _validate_security_headers(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate security headers"""
        results = []
        test_id = f"{validation_id}-security-headers"
        
        async with SecurityHTTPClient(config) as client:
            try:
                response = await client.make_async_request('GET', '/')
                headers = getattr(response, 'headers', {})
                
                # Required security headers
                required_headers = {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                    'X-XSS-Protection': '1; mode=block',
                    'Strict-Transport-Security': 'max-age=',
                    'Content-Security-Policy': 'default-src'
                }
                
                missing_headers = []
                present_headers = []
                
                for header, expected in required_headers.items():
                    header_value = headers.get(header, '').lower()
                    
                    if not header_value:
                        missing_headers.append(header)
                    else:
                        if isinstance(expected, list):
                            if any(exp.lower() in header_value for exp in expected):
                                present_headers.append(header)
                            else:
                                missing_headers.append(f"{header} (weak value)")
                        elif expected.lower() in header_value:
                            present_headers.append(header)
                        else:
                            missing_headers.append(f"{header} (weak value)")
                
                if not missing_headers:
                    status = TestStatus.PASSED
                    details = f"All security headers present: {', '.join(present_headers)}"
                else:
                    status = TestStatus.FAILED
                    details = f"Missing/weak headers: {', '.join(missing_headers)}"
                
                results.append(TestResult(
                    id=test_id,
                    category="Security Headers",
                    test_name="Security Headers Validation",
                    status=status,
                    target_url=config.target_url,
                    method='GET',
                    service_name="validator",
                    details=details
                ))
                
            except Exception as e:
                results.append(TestResult(
                    id=test_id,
                    category="Security Headers",
                    test_name="Security Headers Validation",
                    status=TestStatus.ERROR,
                    target_url=config.target_url,
                    method='GET',
                    service_name="validator",
                    details=f"Security headers validation failed: {str(e)}"
                ))
        
        return results
    
    async def _validate_robots_txt(self, config: ScanConfig, validation_id: str) -> List[TestResult]:
        """Validate robots.txt configuration"""
        results = []
        test_id = f"{validation_id}-robots-txt"
        
        async with SecurityHTTPClient(config) as client:
            try:
                response = await client.make_async_request('GET', '/robots.txt')
                
                if response.status == 200:
                    robots_content = getattr(response, 'text_content', '').lower()
                    
                    # Check for sensitive paths that should be disallowed
                    sensitive_paths = ['/admin', '/api', '/backup', '/config', '/debug']
                    disallowed_paths = []
                    
                    for path in sensitive_paths:
                        if f'disallow: {path}' in robots_content:
                            disallowed_paths.append(path)
                    
                    if disallowed_paths:
                        status = TestStatus.PASSED
                        details = f"Robots.txt properly configured, disallows: {', '.join(disallowed_paths)}"
                    else:
                        status = TestStatus.FAILED
                        details = "Robots.txt exists but doesn't disallow sensitive paths"
                else:
                    status = TestStatus.FAILED
                    details = f"Robots.txt not found (HTTP {response.status})"
                
                results.append(TestResult(
                    id=test_id,
                    category="Robots.txt",
                    test_name="Robots.txt Configuration",
                    status=status,
                    target_url=urljoin(config.target_url, '/robots.txt'),
                    method='GET',
                    service_name="validator",
                    details=details
                ))
                
            except Exception as e:
                results.append(TestResult(
                    id=test_id,
                    category="Robots.txt",
                    test_name="Robots.txt Configuration",
                    status=TestStatus.ERROR,
                    target_url=urljoin(config.target_url, '/robots.txt'),
                    method='GET',
                    service_name="validator",
                    details=f"Robots.txt validation failed: {str(e)}"
                ))
        
        return results
"""
Core scanning engine for vulnerability detection
"""

import asyncio
import time
from typing import List, Dict, Any
from urllib.parse import urljoin

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult, TestStatus, VulnerabilityLevel, TestCategory
from shared.utils import get_logger, SecurityHTTPClient
from .payloads import PayloadDatabase

logger = get_logger(__name__)


class ScannerEngine:
    """Core vulnerability scanning engine"""
    
    def __init__(self):
        self.payload_db = PayloadDatabase()
        
    async def execute_scan(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """
        Execute comprehensive security scan
        
        Args:
            config: Scan configuration
            scan_id: Unique scan identifier
            
        Returns:
            List of test results
        """
        logger.info(f"Starting scan {scan_id} for {config.target_url}")
        
        results = []
        
        # Execute tests for each enabled category
        for category in config.test_categories:
            if config.is_category_enabled(category):
                logger.info(f"Testing category: {category}")
                category_results = await self._test_category(category, config, scan_id)
                results.extend(category_results)
                
                # Add delay between categories
                await asyncio.sleep(config.delay)
        
        logger.info(f"Scan {scan_id} completed with {len(results)} results")
        return results
    
    async def _test_category(self, category: TestCategory, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test a specific vulnerability category"""
        
        category_map = {
            TestCategory.SQL_INJECTION: self._test_sql_injection,
            TestCategory.PATH_TRAVERSAL: self._test_path_traversal,
            TestCategory.XSS: self._test_xss,
            TestCategory.AUTHENTICATION_BYPASS: self._test_auth_bypass,
            TestCategory.RATE_LIMITING: self._test_rate_limiting,
            TestCategory.BOT_DETECTION: self._test_bot_detection,
            TestCategory.API_ENUMERATION: self._test_api_enumeration,
            TestCategory.FILE_UPLOAD_SECURITY: self._test_file_upload,
            TestCategory.INFORMATION_DISCLOSURE: self._test_info_disclosure,
            TestCategory.CSRF_PROTECTION: self._test_csrf_protection,
            TestCategory.SECURITY_HEADERS: self._test_security_headers,
            TestCategory.SSL_TLS_SECURITY: self._test_ssl_tls
        }
        
        test_func = category_map.get(category)
        if test_func:
            return await test_func(config, scan_id)
        else:
            logger.warning(f"Unknown test category: {category}")
            return []
    
    async def _test_sql_injection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test SQL injection vulnerabilities"""
        results = []
        payloads = self.payload_db.get_sql_injection_payloads()
        endpoints = self.payload_db.get_common_endpoints()
        
        # Apply intensity limits
        intensity_config = config.get_intensity_config()
        if intensity_config['max_payloads']:
            payloads = payloads[:intensity_config['max_payloads']]
        if intensity_config['max_endpoints']:
            endpoints = endpoints[:intensity_config['max_endpoints']]
        
        async with SecurityHTTPClient(config) as client:
            for payload in payloads:
                for endpoint in endpoints:
                    # Test GET parameters
                    result = await self._test_sql_payload(
                        client, 'GET', endpoint, payload, config, scan_id
                    )
                    results.append(result)
                    
                    # Test POST data
                    result = await self._test_sql_payload(
                        client, 'POST', endpoint, payload, config, scan_id
                    )
                    results.append(result)
                    
                    await asyncio.sleep(config.delay)
        
        return results
    
    async def _test_sql_payload(self, client, method: str, endpoint: str, payload: str, config: ScanConfig, scan_id: str) -> TestResult:
        """Test individual SQL injection payload"""
        test_id = f"{scan_id}-sql-{method.lower()}-{hash(endpoint + payload)}"
        
        try:
            start_time = time.time()
            
            if method == 'GET':
                response = await client.make_async_request('GET', endpoint, payload)
            else:
                response = await client.make_async_request('POST', endpoint, payload)
            
            duration = time.time() - start_time
            
            # Analyze response for SQL injection indicators
            status, vulnerability_level, details = self._analyze_sql_response(response, payload)
            
            return TestResult(
                id=test_id,
                category="SQL Injection",
                test_name=f"SQL-{method} {endpoint}",
                status=status,
                vulnerability_level=vulnerability_level,
                target_url=urljoin(config.target_url, endpoint),
                method=method,
                payload=payload,
                response_code=response.status,
                response_time=duration,
                service_name="scanner",
                details=details
            )
            
        except Exception as e:
            return TestResult(
                id=test_id,
                category="SQL Injection",
                test_name=f"SQL-{method} {endpoint}",
                status=TestStatus.ERROR,
                target_url=urljoin(config.target_url, endpoint),
                method=method,
                payload=payload,
                service_name="scanner",
                details=f"Request failed: {str(e)}"
            )
    
    def _analyze_sql_response(self, response, payload: str) -> tuple:
        """Analyze response for SQL injection indicators"""
        response_text = getattr(response, 'text_content', '').lower()
        
        # Check for blocking/protection
        block_indicators = [
            'access denied', 'blocked', 'security', 'firewall', 'waf',
            'suspicious', 'malicious', 'injection', 'attack'
        ]
        
        if any(indicator in response_text for indicator in block_indicators) or response.status == 403:
            return TestStatus.BLOCKED, None, "Request blocked by security measures"
        
        # Check for SQL error indicators (vulnerability)
        sql_errors = [
            'mysql_fetch_array', 'ora-01756', 'microsoft ole db provider',
            'unclosed quotation mark', 'quoted string not properly terminated',
            'sql syntax', 'mysql_num_rows', 'pg_query', 'sqlite_query',
            'division by zero', 'table doesn\'t exist', 'column not found'
        ]
        
        if any(error in response_text for error in sql_errors):
            return TestStatus.VULNERABLE, VulnerabilityLevel.HIGH, f"SQL error detected with payload: {payload[:30]}..."
        elif response.status == 500:
            return TestStatus.VULNERABLE, VulnerabilityLevel.MEDIUM, f"Server error with payload: {payload[:30]}..."
        else:
            return TestStatus.PASSED, None, "No SQL injection vulnerability detected"
    
    # Placeholder methods for other test categories
    async def _test_path_traversal(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test path traversal vulnerabilities"""
        # Implementation similar to SQL injection
        return []
    
    async def _test_xss(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test XSS vulnerabilities"""
        return []
    
    async def _test_auth_bypass(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test authentication bypass"""
        return []
    
    async def _test_rate_limiting(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test rate limiting"""
        return []
    
    async def _test_bot_detection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test bot detection"""
        return []
    
    async def _test_api_enumeration(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test API enumeration"""
        return []
    
    async def _test_file_upload(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test file upload security"""
        return []
    
    async def _test_info_disclosure(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test information disclosure"""
        return []
    
    async def _test_csrf_protection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test CSRF protection"""
        return []
    
    async def _test_security_headers(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test security headers"""
        return []
    
    async def _test_ssl_tls(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test SSL/TLS security"""
        return []
    async def _test_path_traversal(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test path traversal vulnerabilities"""
        results = []
        payloads = self.payload_db.get_path_traversal_payloads()
        endpoints = ['/api/files/', '/api/download/', '/api/static/']
        
        intensity_config = config.get_intensity_config()
        if intensity_config['max_payloads']:
            payloads = payloads[:intensity_config['max_payloads']]
        
        async with SecurityHTTPClient(config) as client:
            for payload in payloads:
                for endpoint in endpoints:
                    test_id = f"{scan_id}-path-{hash(endpoint + payload)}"
                    
                    try:
                        start_time = time.time()
                        response = await client.make_async_request('GET', endpoint, payload)
                        duration = time.time() - start_time
                        
                        status, vulnerability_level, details = self._analyze_path_traversal_response(response, payload)
                        
                        results.append(TestResult(
                            id=test_id,
                            category="Path Traversal",
                            test_name=f"Path Traversal {endpoint}",
                            status=status,
                            vulnerability_level=vulnerability_level,
                            target_url=urljoin(config.target_url, endpoint),
                            method='GET',
                            payload=payload,
                            response_code=response.status,
                            response_time=duration,
                            service_name="scanner",
                            details=details
                        ))
                        
                        await asyncio.sleep(config.delay)
                        
                    except Exception as e:
                        results.append(TestResult(
                            id=test_id,
                            category="Path Traversal",
                            test_name=f"Path Traversal {endpoint}",
                            status=TestStatus.ERROR,
                            target_url=urljoin(config.target_url, endpoint),
                            method='GET',
                            payload=payload,
                            service_name="scanner",
                            details=f"Request failed: {str(e)}"
                        ))
        
        return results
    
    def _analyze_path_traversal_response(self, response, payload: str) -> tuple:
        """Analyze response for path traversal indicators"""
        response_text = getattr(response, 'text_content', '').lower()
        
        # Check for blocking
        if response.status == 403 or "access denied" in response_text:
            return TestStatus.BLOCKED, None, "Path traversal attempt blocked"
        
        # Check for successful traversal indicators
        traversal_indicators = [
            'root:x:', 'boot.ini', '[boot loader]', 'windows\\system32',
            '/etc/passwd', '/etc/shadow', 'administrator:', 'system volume information'
        ]
        
        if any(indicator in response_text for indicator in traversal_indicators):
            return TestStatus.VULNERABLE, VulnerabilityLevel.HIGH, f"Path traversal successful with payload: {payload[:30]}..."
        elif response.status == 200 and len(response_text) > 100:
            return TestStatus.VULNERABLE, VulnerabilityLevel.MEDIUM, f"Potential path traversal with payload: {payload[:30]}..."
        else:
            return TestStatus.PASSED, None, "No path traversal vulnerability detected"
    
    async def _test_xss(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test XSS vulnerabilities"""
        results = []
        payloads = self.payload_db.get_xss_payloads()
        endpoints = ['/api/search/', '/api/comments/', '/api/feedback/']
        
        intensity_config = config.get_intensity_config()
        if intensity_config['max_payloads']:
            payloads = payloads[:intensity_config['max_payloads']]
        
        async with SecurityHTTPClient(config) as client:
            for payload in payloads:
                for endpoint in endpoints:
                    test_id = f"{scan_id}-xss-{hash(endpoint + payload)}"
                    
                    try:
                        start_time = time.time()
                        response = await client.make_async_request('POST', endpoint, payload)
                        duration = time.time() - start_time
                        
                        status, vulnerability_level, details = self._analyze_xss_response(response, payload)
                        
                        results.append(TestResult(
                            id=test_id,
                            category="XSS",
                            test_name=f"XSS {endpoint}",
                            status=status,
                            vulnerability_level=vulnerability_level,
                            target_url=urljoin(config.target_url, endpoint),
                            method='POST',
                            payload=payload,
                            response_code=response.status,
                            response_time=duration,
                            service_name="scanner",
                            details=details
                        ))
                        
                        await asyncio.sleep(config.delay)
                        
                    except Exception as e:
                        results.append(TestResult(
                            id=test_id,
                            category="XSS",
                            test_name=f"XSS {endpoint}",
                            status=TestStatus.ERROR,
                            target_url=urljoin(config.target_url, endpoint),
                            method='POST',
                            payload=payload,
                            service_name="scanner",
                            details=f"Request failed: {str(e)}"
                        ))
        
        return results
    
    def _analyze_xss_response(self, response, payload: str) -> tuple:
        """Analyze response for XSS indicators"""
        response_text = getattr(response, 'text_content', '')
        
        # Check for blocking
        if response.status == 403 or "blocked" in response_text.lower():
            return TestStatus.BLOCKED, None, "XSS attempt blocked"
        
        # Check if payload is reflected without encoding
        if payload in response_text:
            return TestStatus.VULNERABLE, VulnerabilityLevel.HIGH, f"XSS payload reflected: {payload[:30]}..."
        
        # Check for partial reflection or encoding bypass
        payload_parts = ['<script', 'javascript:', 'onerror=', 'onload=']
        if any(part in response_text for part in payload_parts):
            return TestStatus.VULNERABLE, VulnerabilityLevel.MEDIUM, f"Potential XSS with payload: {payload[:30]}..."
        else:
            return TestStatus.PASSED, None, "No XSS vulnerability detected"
    
    async def _test_security_headers(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test security headers"""
        results = []
        test_id = f"{scan_id}-headers"
        
        async with SecurityHTTPClient(config) as client:
            try:
                response = await client.make_async_request('GET', '/')
                headers = getattr(response, 'headers', {})
                
                # Check for important security headers
                security_headers = {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                    'X-XSS-Protection': '1; mode=block',
                    'Strict-Transport-Security': 'max-age=',
                    'Content-Security-Policy': 'default-src',
                    'Referrer-Policy': ['strict-origin-when-cross-origin', 'no-referrer']
                }
                
                missing_headers = []
                weak_headers = []
                
                for header, expected in security_headers.items():
                    header_value = headers.get(header, '').lower()
                    
                    if not header_value:
                        missing_headers.append(header)
                    elif isinstance(expected, list):
                        if not any(exp.lower() in header_value for exp in expected):
                            weak_headers.append(f"{header}: {header_value}")
                    elif expected.lower() not in header_value:
                        weak_headers.append(f"{header}: {header_value}")
                
                if missing_headers or weak_headers:
                    status = TestStatus.VULNERABLE
                    vulnerability_level = VulnerabilityLevel.MEDIUM
                    details = f"Missing headers: {missing_headers}, Weak headers: {weak_headers}"
                else:
                    status = TestStatus.PASSED
                    vulnerability_level = None
                    details = "All security headers properly configured"
                
                results.append(TestResult(
                    id=test_id,
                    category="Security Headers",
                    test_name="Security Headers Check",
                    status=status,
                    vulnerability_level=vulnerability_level,
                    target_url=config.target_url,
                    method='GET',
                    service_name="scanner",
                    details=details
                ))
                
            except Exception as e:
                results.append(TestResult(
                    id=test_id,
                    category="Security Headers",
                    test_name="Security Headers Check",
                    status=TestStatus.ERROR,
                    target_url=config.target_url,
                    method='GET',
                    service_name="scanner",
                    details=f"Header check failed: {str(e)}"
                ))
        
        return results
    
    async def _test_rate_limiting(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test rate limiting"""
        results = []
        test_id = f"{scan_id}-rate-limit"
        
        async with SecurityHTTPClient(config) as client:
            try:
                blocked_requests = 0
                total_requests = 20
                
                for i in range(total_requests):
                    response = await client.make_async_request('POST', '/api/auth/login/', 
                                                             f'{{"username": "test{i}", "password": "test"}}')
                    
                    if response.status == 429 or "rate limit" in getattr(response, 'text_content', '').lower():
                        blocked_requests += 1
                    
                    await asyncio.sleep(0.1)
                
                if blocked_requests > 0:
                    status = TestStatus.PASSED
                    details = f"Rate limiting active: {blocked_requests}/{total_requests} requests blocked"
                else:
                    status = TestStatus.VULNERABLE
                    vulnerability_level = VulnerabilityLevel.MEDIUM
                    details = f"No rate limiting detected: 0/{total_requests} requests blocked"
                
                results.append(TestResult(
                    id=test_id,
                    category="Rate Limiting",
                    test_name="Rate Limit Test",
                    status=status,
                    vulnerability_level=vulnerability_level if status == TestStatus.VULNERABLE else None,
                    target_url=urljoin(config.target_url, '/api/auth/login/'),
                    method='POST',
                    service_name="scanner",
                    details=details
                ))
                
            except Exception as e:
                results.append(TestResult(
                    id=test_id,
                    category="Rate Limiting",
                    test_name="Rate Limit Test",
                    status=TestStatus.ERROR,
                    target_url=urljoin(config.target_url, '/api/auth/login/'),
                    method='POST',
                    service_name="scanner",
                    details=f"Rate limit test failed: {str(e)}"
                ))
        
        return results
    
    async def _test_bot_detection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test bot detection"""
        results = []
        malicious_agents = ["sqlmap/1.0", "nikto/2.1.6", "w3af.org", "Nmap Scripting Engine"]
        
        async with SecurityHTTPClient(config) as client:
            for agent in malicious_agents:
                test_id = f"{scan_id}-bot-{hash(agent)}"
                
                try:
                    response = await client.make_async_request('GET', '/api/challenges/',
                                                             headers={'User-Agent': agent})
                    
                    response_text = getattr(response, 'text_content', '').lower()
                    
                    if "access denied" in response_text or response.status == 403:
                        status = TestStatus.PASSED
                        details = f"Bot {agent} correctly blocked"
                    else:
                        status = TestStatus.VULNERABLE
                        vulnerability_level = VulnerabilityLevel.MEDIUM
                        details = f"Bot {agent} not blocked - Response: {response.status}"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="Bot Detection",
                        test_name=f"Block {agent}",
                        status=status,
                        vulnerability_level=vulnerability_level if status == TestStatus.VULNERABLE else None,
                        target_url=urljoin(config.target_url, '/api/challenges/'),
                        method='GET',
                        service_name="scanner",
                        details=details
                    ))
                    
                except Exception as e:
                    results.append(TestResult(
                        id=test_id,
                        category="Bot Detection",
                        test_name=f"Block {agent}",
                        status=TestStatus.ERROR,
                        target_url=urljoin(config.target_url, '/api/challenges/'),
                        method='GET',
                        service_name="scanner",
                        details=f"Bot detection test failed: {str(e)}"
                    ))
        
        return results
    
    async def _test_api_enumeration(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test API enumeration"""
        results = []
        sensitive_endpoints = ['/api/admin/', '/api/debug/', '/api/config/', '/.env', '/backup.sql', '/api/users/']
        
        async with SecurityHTTPClient(config) as client:
            for endpoint in sensitive_endpoints:
                test_id = f"{scan_id}-enum-{hash(endpoint)}"
                
                try:
                    response = await client.make_async_request('GET', endpoint)
                    response_text = getattr(response, 'text_content', '').lower()
                    
                    if response.status == 200:
                        sensitive_patterns = ['password', 'secret', 'key', 'token', 'admin', 'config']
                        if any(pattern in response_text for pattern in sensitive_patterns):
                            status = TestStatus.VULNERABLE
                            vulnerability_level = VulnerabilityLevel.HIGH
                            details = f"Sensitive information exposed at {endpoint}"
                        else:
                            status = TestStatus.VULNERABLE
                            vulnerability_level = VulnerabilityLevel.LOW
                            details = f"Endpoint {endpoint} accessible but no sensitive data found"
                    elif response.status == 404:
                        status = TestStatus.PASSED
                        details = f"Endpoint {endpoint} properly hidden"
                    else:
                        status = TestStatus.PASSED
                        details = f"Endpoint {endpoint} access restricted"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="API Enumeration",
                        test_name=f"Enumerate {endpoint}",
                        status=status,
                        vulnerability_level=vulnerability_level if status == TestStatus.VULNERABLE else None,
                        target_url=urljoin(config.target_url, endpoint),
                        method='GET',
                        service_name="scanner",
                        details=details
                    ))
                    
                except Exception as e:
                    results.append(TestResult(
                        id=test_id,
                        category="API Enumeration",
                        test_name=f"Enumerate {endpoint}",
                        status=TestStatus.ERROR,
                        target_url=urljoin(config.target_url, endpoint),
                        method='GET',
                        service_name="scanner",
                        details=f"Enumeration failed: {str(e)}"
                    ))
        
        return results
    
    # Placeholder methods for remaining categories
    async def _test_auth_bypass(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test authentication bypass"""
        # Implementation would test various auth bypass techniques
        return []
    
    async def _test_file_upload(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test file upload security"""
        # Implementation would test malicious file uploads
        return []
    
    async def _test_info_disclosure(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test information disclosure"""
        # Implementation would test for information leaks
        return []
    
    async def _test_csrf_protection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test CSRF protection"""
        # Implementation would test CSRF token validation
        return []
    
    async def _test_ssl_tls(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        """Test SSL/TLS security"""
        # Implementation would test SSL/TLS configuration
        return []
"""
Core attack simulation engine
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


class SimulatorEngine:
    """Core attack simulation engine"""
    
    async def execute_simulation(self, config: ScanConfig, scenarios: List[str], simulation_id: str) -> List[TestResult]:
        """Execute attack simulation"""
        logger.info(f"Starting simulation {simulation_id} for {config.target_url}")
        
        results = []
        
        for scenario in scenarios:
            scenario_results = await self._execute_scenario(scenario, config, simulation_id)
            results.extend(scenario_results)
            await asyncio.sleep(config.delay)
        
        logger.info(f"Simulation {simulation_id} completed with {len(results)} results")
        return results
    
    async def _execute_scenario(self, scenario: str, config: ScanConfig, simulation_id: str) -> List[TestResult]:
        """Execute specific attack scenario"""
        
        scenario_map = {
            "basic_attacks": self._simulate_basic_attacks,
            "advanced_attacks": self._simulate_advanced_attacks,
            "penetration_testing": self._simulate_penetration_testing
        }
        
        scenario_func = scenario_map.get(scenario)
        if scenario_func:
            return await scenario_func(config, simulation_id)
        else:
            logger.warning(f"Unknown scenario: {scenario}")
            return []
    
    async def _simulate_basic_attacks(self, config: ScanConfig, simulation_id: str) -> List[TestResult]:
        """Simulate basic attack patterns"""
        results = []
        
        # Simulate automated tool detection
        malicious_agents = ["sqlmap/1.0", "nikto/2.1.6", "w3af.org"]
        
        async with SecurityHTTPClient(config) as client:
            for agent in malicious_agents:
                test_id = f"{simulation_id}-basic-bot-{hash(agent)}"
                
                try:
                    response = await client.make_async_request(
                        'GET', '/api/challenges/',
                        headers={'User-Agent': agent}
                    )
                    
                    response_text = getattr(response, 'text_content', '').lower()
                    
                    if "access denied" in response_text or response.status == 403:
                        status = TestStatus.BLOCKED
                        details = f"Automated tool {agent} correctly blocked"
                    else:
                        status = TestStatus.VULNERABLE
                        vulnerability_level = VulnerabilityLevel.MEDIUM
                        details = f"Automated tool {agent} not blocked - potential security gap"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="Automated Tool Detection",
                        test_name=f"Block {agent}",
                        status=status,
                        vulnerability_level=vulnerability_level if status == TestStatus.VULNERABLE else None,
                        target_url=urljoin(config.target_url, '/api/challenges/'),
                        method='GET',
                        service_name="simulator",
                        details=details
                    ))
                    
                except Exception as e:
                    results.append(TestResult(
                        id=test_id,
                        category="Automated Tool Detection",
                        test_name=f"Block {agent}",
                        status=TestStatus.ERROR,
                        target_url=urljoin(config.target_url, '/api/challenges/'),
                        method='GET',
                        service_name="simulator",
                        details=f"Attack simulation failed: {str(e)}"
                    ))
        
        return results
    
    async def _simulate_advanced_attacks(self, config: ScanConfig, simulation_id: str) -> List[TestResult]:
        """Simulate advanced attack patterns"""
        results = []
        
        # Simulate authentication bypass attempts
        bypass_payloads = [
            {'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxfQ.invalid'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'}
        ]
        
        async with SecurityHTTPClient(config) as client:
            for headers in bypass_payloads:
                test_id = f"{simulation_id}-advanced-auth-{hash(str(headers))}"
                
                try:
                    response = await client.make_async_request(
                        'GET', '/api/users/profile/',
                        headers=headers
                    )
                    
                    if response.status in [401, 403]:
                        status = TestStatus.BLOCKED
                        details = "Authentication bypass attempt correctly blocked"
                    elif response.status == 200:
                        status = TestStatus.VULNERABLE
                        vulnerability_level = VulnerabilityLevel.HIGH
                        details = f"Authentication bypass successful with headers: {headers}"
                    else:
                        status = TestStatus.BLOCKED
                        details = f"Unexpected response: {response.status}"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="Authentication Bypass",
                        test_name="Advanced Auth Bypass",
                        status=status,
                        vulnerability_level=vulnerability_level if status == TestStatus.VULNERABLE else None,
                        target_url=urljoin(config.target_url, '/api/users/profile/'),
                        method='GET',
                        service_name="simulator",
                        details=details
                    ))
                    
                except Exception as e:
                    results.append(TestResult(
                        id=test_id,
                        category="Authentication Bypass",
                        test_name="Advanced Auth Bypass",
                        status=TestStatus.ERROR,
                        target_url=urljoin(config.target_url, '/api/users/profile/'),
                        method='GET',
                        service_name="simulator",
                        details=f"Attack simulation failed: {str(e)}"
                    ))
        
        return results
    
    async def _simulate_penetration_testing(self, config: ScanConfig, simulation_id: str) -> List[TestResult]:
        """Simulate comprehensive penetration testing"""
        results = []
        
        # Simulate API enumeration attack
        common_endpoints = [
            '/api/admin/', '/api/debug/', '/api/config/', '/.env', '/backup.sql'
        ]
        
        async with SecurityHTTPClient(config) as client:
            for endpoint in common_endpoints:
                test_id = f"{simulation_id}-pentest-enum-{hash(endpoint)}"
                
                try:
                    response = await client.make_async_request('GET', endpoint)
                    
                    if response.status == 200:
                        response_text = getattr(response, 'text_content', '').lower()
                        sensitive_patterns = ['password', 'secret', 'key', 'token', 'admin']
                        
                        if any(pattern in response_text for pattern in sensitive_patterns):
                            status = TestStatus.VULNERABLE
                            vulnerability_level = VulnerabilityLevel.HIGH
                            details = f"Sensitive information exposed at {endpoint}"
                        else:
                            status = TestStatus.BLOCKED
                            details = f"Endpoint {endpoint} accessible but no sensitive data found"
                    elif response.status == 404:
                        status = TestStatus.BLOCKED
                        details = f"Endpoint {endpoint} properly hidden"
                    else:
                        status = TestStatus.BLOCKED
                        details = f"Endpoint {endpoint} access restricted"
                    
                    results.append(TestResult(
                        id=test_id,
                        category="API Enumeration",
                        test_name=f"Enumerate {endpoint}",
                        status=status,
                        vulnerability_level=vulnerability_level if status == TestStatus.VULNERABLE else None,
                        target_url=urljoin(config.target_url, endpoint),
                        method='GET',
                        service_name="simulator",
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
                        service_name="simulator",
                        details=f"Enumeration failed: {str(e)}"
                    ))
        
        return results
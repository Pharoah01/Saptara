"""
Centralized HTTP client for security testing
"""

import asyncio
import time
from typing import Optional, Dict, Any, List
import aiohttp
import requests
from urllib.parse import urljoin
from ..models.scan_config import ScanConfig
from .logger import get_logger

logger = get_logger(__name__)


class SecurityHTTPClient:
    """HTTP client optimized for security testing"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = None
        self.async_session = None
        
    def __enter__(self):
        """Context manager entry"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent
        })
        if self.config.custom_headers:
            self.session.headers.update(self.config.custom_headers)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if self.session:
            self.session.close()
            
    async def __aenter__(self):
        """Async context manager entry"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {'User-Agent': self.config.user_agent}
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)
            
        self.async_session = aiohttp.ClientSession(
            timeout=timeout,
            headers=headers
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.async_session:
            await self.async_session.close()
    
    def make_request(
        self,
        method: str,
        endpoint: str,
        payload: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make synchronous HTTP request
        
        Args:
            method: HTTP method
            endpoint: Target endpoint
            payload: Request payload
            headers: Additional headers
            **kwargs: Additional request parameters
            
        Returns:
            Response object
        """
        url = urljoin(self.config.target_url, endpoint)
        request_headers = {}
        
        if headers:
            request_headers.update(headers)
            
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                params = {'payload': payload} if payload else None
                response = self.session.get(
                    url,
                    params=params,
                    headers=request_headers,
                    timeout=self.config.timeout,
                    **kwargs
                )
            elif method.upper() == 'POST':
                data = {'payload': payload} if payload else None
                response = self.session.post(
                    url,
                    json=data,
                    headers=request_headers,
                    timeout=self.config.timeout,
                    **kwargs
                )
            else:
                response = self.session.request(
                    method,
                    url,
                    headers=request_headers,
                    timeout=self.config.timeout,
                    **kwargs
                )
                
            response.request_time = time.time() - start_time
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise
            
    async def make_async_request(
        self,
        method: str,
        endpoint: str,
        payload: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Make asynchronous HTTP request
        
        Args:
            method: HTTP method
            endpoint: Target endpoint
            payload: Request payload
            headers: Additional headers
            **kwargs: Additional request parameters
            
        Returns:
            Response object
        """
        url = urljoin(self.config.target_url, endpoint)
        request_headers = {}
        
        if headers:
            request_headers.update(headers)
            
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                params = {'payload': payload} if payload else None
                async with self.async_session.get(
                    url,
                    params=params,
                    headers=request_headers,
                    **kwargs
                ) as response:
                    response.request_time = time.time() - start_time
                    response.text_content = await response.text()
                    return response
                    
            elif method.upper() == 'POST':
                data = {'payload': payload} if payload else None
                async with self.async_session.post(
                    url,
                    json=data,
                    headers=request_headers,
                    **kwargs
                ) as response:
                    response.request_time = time.time() - start_time
                    response.text_content = await response.text()
                    return response
                    
        except aiohttp.ClientError as e:
            logger.error(f"Async request failed: {e}")
            raise
            
    def test_connectivity(self) -> bool:
        """Test basic connectivity to target"""
        try:
            response = self.make_request('GET', '/')
            return response.status_code < 500
        except Exception as e:
            logger.error(f"Connectivity test failed: {e}")
            return False
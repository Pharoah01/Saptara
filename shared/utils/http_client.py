"""
Centralized HTTP client for security testing
Supports raw payload injection across all HTTP methods and parameter types
"""

import asyncio
import time
from typing import Optional, Dict, Any
import aiohttp
import requests
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlunparse

from ..models.scan_config import ScanConfig
from .logger import get_logger

logger = get_logger(__name__)


class MockResponse:
    """Returned when a request cannot be made (connection refused, timeout, etc.)"""
    def __init__(self, error: str):
        self.status = 0
        self.text_content = ""
        self.headers = {}
        self.cookies = {}
        self.error = error
        self.request_time = 0.0


class SecurityHTTPClient:
    """
    HTTP client for security testing.

    Supports injecting payloads as:
      - GET query parameters  (inject_as="query")
      - POST form fields      (inject_as="form")
      - POST JSON body        (inject_as="json")
      - Raw POST body         (inject_as="raw")
      - URL path segment      (inject_as="path")
      - HTTP header value     (inject_as="header", header_name=...)
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.session: Optional[requests.Session] = None
        self.async_session: Optional[aiohttp.ClientSession] = None

    # ------------------------------------------------------------------
    # Sync context manager
    # ------------------------------------------------------------------

    def __enter__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.custom_headers:
            self.session.headers.update(self.config.custom_headers)
        if self.config.auth_headers:
            self.session.headers.update(self.config.auth_headers)
        return self

    def __exit__(self, *_):
        if self.session:
            self.session.close()

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent}
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)
        if self.config.auth_headers:
            headers.update(self.config.auth_headers)
        connector = aiohttp.TCPConnector(ssl=False, limit=self.config.max_concurrent)
        self.async_session = aiohttp.ClientSession(
            timeout=timeout,
            headers=headers,
            connector=connector,
        )
        return self

    async def __aexit__(self, *_):
        if self.async_session:
            await self.async_session.close()

    # ------------------------------------------------------------------
    # Core async request
    # ------------------------------------------------------------------

    async def make_async_request(
        self,
        method: str,
        endpoint: str,
        payload: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        inject_as: str = "query",
        field_name: str = "q",
        header_name: str = "X-Custom",
        raw_body: Optional[bytes] = None,
        form_data: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        allow_redirects: bool = True,
    ):
        """
        Make an async HTTP request with flexible payload injection.

        Args:
            method:          HTTP verb (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
            endpoint:        Path relative to target_url
            payload:         String payload to inject (used with inject_as)
            headers:         Extra headers to merge
            inject_as:       How to inject payload: query|form|json|raw|path|header
            field_name:      Form/query/json field name for the payload
            header_name:     Header name when inject_as="header"
            raw_body:        Raw bytes body (overrides payload when set)
            form_data:       Full form dict (merged with payload if inject_as="form")
            json_body:       Full JSON dict (merged with payload if inject_as="json")
            allow_redirects: Follow HTTP redirects
        """
        url = urljoin(self.config.target_url, endpoint)
        method = method.upper()
        req_headers = dict(headers or {})

        params = None
        data = None
        json_data = None
        body = None

        if raw_body is not None:
            body = raw_body
        elif payload is not None:
            if inject_as == "query":
                params = {field_name: payload}
            elif inject_as == "form":
                data = dict(form_data or {})
                data[field_name] = payload
            elif inject_as == "json":
                json_data = dict(json_body or {})
                json_data[field_name] = payload
            elif inject_as == "raw":
                body = payload.encode() if isinstance(payload, str) else payload
            elif inject_as == "path":
                url = url.rstrip("/") + "/" + payload
            elif inject_as == "header":
                req_headers[header_name] = payload
        elif form_data is not None:
            data = form_data
        elif json_body is not None:
            json_data = json_body

        start = time.time()
        try:
            async with self.async_session.request(
                method,
                url,
                params=params,
                data=data,
                json=json_data,
                headers=req_headers,
                allow_redirects=allow_redirects,
            ) as resp:
                resp.request_time = time.time() - start
                resp.text_content = await resp.text(errors="replace")
                return resp
        except aiohttp.ClientConnectorError as e:
            logger.debug(f"Connection refused: {url} — {e}")
            return MockResponse(str(e))
        except asyncio.TimeoutError:
            logger.debug(f"Timeout: {url}")
            return MockResponse("timeout")
        except aiohttp.ClientError as e:
            logger.debug(f"Client error: {url} — {e}")
            return MockResponse(str(e))

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    async def get(self, endpoint: str, params: Optional[Dict] = None, headers: Optional[Dict] = None):
        """Simple GET with optional query params dict."""
        url = urljoin(self.config.target_url, endpoint)
        start = time.time()
        try:
            async with self.async_session.get(url, params=params, headers=headers or {}) as resp:
                resp.request_time = time.time() - start
                resp.text_content = await resp.text(errors="replace")
                return resp
        except Exception as e:
            return MockResponse(str(e))

    async def post_json(self, endpoint: str, body: dict, headers: Optional[Dict] = None):
        """POST with JSON body."""
        url = urljoin(self.config.target_url, endpoint)
        start = time.time()
        try:
            async with self.async_session.post(url, json=body, headers=headers or {}) as resp:
                resp.request_time = time.time() - start
                resp.text_content = await resp.text(errors="replace")
                return resp
        except Exception as e:
            return MockResponse(str(e))

    async def post_form(self, endpoint: str, data: dict, headers: Optional[Dict] = None):
        """POST with form-encoded body."""
        url = urljoin(self.config.target_url, endpoint)
        start = time.time()
        try:
            async with self.async_session.post(url, data=data, headers=headers or {}) as resp:
                resp.request_time = time.time() - start
                resp.text_content = await resp.text(errors="replace")
                return resp
        except Exception as e:
            return MockResponse(str(e))

    async def post_multipart(self, endpoint: str, fields: dict, file_field: str,
                              filename: str, file_content: bytes, content_type: str,
                              headers: Optional[Dict] = None):
        """POST multipart/form-data with a file."""
        url = urljoin(self.config.target_url, endpoint)
        form = aiohttp.FormData()
        for k, v in fields.items():
            form.add_field(k, v)
        form.add_field(
            file_field,
            file_content,
            filename=filename,
            content_type=content_type,
        )
        start = time.time()
        try:
            async with self.async_session.post(url, data=form, headers=headers or {}) as resp:
                resp.request_time = time.time() - start
                resp.text_content = await resp.text(errors="replace")
                return resp
        except Exception as e:
            return MockResponse(str(e))

    # ------------------------------------------------------------------
    # Sync request (kept for legacy use)
    # ------------------------------------------------------------------

    def make_request(
        self,
        method: str,
        endpoint: str,
        payload: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        inject_as: str = "query",
        field_name: str = "q",
    ) -> requests.Response:
        url = urljoin(self.config.target_url, endpoint)
        req_headers = dict(headers or {})
        params = None
        data = None
        json_data = None

        if payload is not None:
            if inject_as == "query":
                params = {field_name: payload}
            elif inject_as == "form":
                data = {field_name: payload}
            elif inject_as == "json":
                json_data = {field_name: payload}

        try:
            resp = self.session.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json_data,
                headers=req_headers,
                timeout=self.config.timeout,
                allow_redirects=True,
            )
            return resp
        except requests.exceptions.RequestException as e:
            logger.error(f"Sync request failed: {e}")
            raise

    def test_connectivity(self) -> bool:
        try:
            resp = self.make_request("GET", "/")
            return resp.status_code < 500
        except Exception:
            return False

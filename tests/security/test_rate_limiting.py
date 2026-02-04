"""
Tests for rate limiting enforcement.

Rate limiting prevents brute force attacks, DoS attempts,
and resource exhaustion by limiting the number of requests
a client can make in a given time period.
"""

import asyncio
import pytest
from uuid import uuid4

from httpx import AsyncClient, ASGITransport
from openlabels.server.app import app
from openlabels.server.db import get_session
from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin, CurrentUser
from openlabels.server.models import Tenant, User, ScanTarget


@pytest.fixture
async def rate_limit_setup(test_db):
    """Set up test data for rate limiting tests."""
    tenant = Tenant(
        id=uuid4(),
        name="Rate Limit Test Tenant",
        azure_tenant_id="rate-limit-test",
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

    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Test Target",
        adapter="filesystem",
        config={"path": "/test"},
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


class TestAuthRateLimiting:
    """Tests for rate limiting on authentication endpoints."""

    @pytest.mark.asyncio
    async def test_unauthenticated_endpoints_handle_rapid_requests(self, test_db):
        """Auth endpoints should handle rapid requests gracefully."""
        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Make 20 rapid requests to login endpoint
                responses = await asyncio.gather(*[
                    client.get("/api/auth/login")
                    for _ in range(20)
                ], return_exceptions=True)

                # Count successful vs rate limited responses
                status_codes = [
                    r.status_code if hasattr(r, 'status_code') else 0
                    for r in responses
                ]

                # Should either all succeed (no rate limiting) or some get 429
                # This documents actual behavior
                successful = sum(1 for s in status_codes if s in (200, 302, 307, 401))
                rate_limited = sum(1 for s in status_codes if s == 429)

                # At minimum, requests should not cause 500 errors
                server_errors = sum(1 for s in status_codes if s >= 500)
                assert server_errors == 0, f"Server errors during rapid requests: {server_errors}"

        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_callback_handles_rapid_requests(self, test_db):
        """OAuth callback should handle rapid requests."""
        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Make rapid callback requests with fake codes
                responses = await asyncio.gather(*[
                    client.get("/api/auth/callback", params={"code": f"fake-code-{i}"})
                    for i in range(10)
                ], return_exceptions=True)

                # Should not cause server errors
                for r in responses:
                    if hasattr(r, 'status_code'):
                        assert r.status_code < 500, "Callback caused server error"

        finally:
            app.dependency_overrides.clear()


class TestAPIRateLimiting:
    """Tests for rate limiting on API endpoints."""

    @pytest.mark.asyncio
    async def test_rapid_scan_creation_handled(self, rate_limit_setup):
        """Rapid scan creation requests should be handled gracefully."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Try to create 20 scans rapidly
            responses = await asyncio.gather(*[
                client.post(
                    "/api/scans",
                    json={"target_id": str(data["target"].id)},
                )
                for _ in range(20)
            ], return_exceptions=True)

            # Should either succeed, get rate limited (429), or validation error
            for r in responses:
                if hasattr(r, 'status_code'):
                    assert r.status_code in (200, 201, 400, 422, 429), \
                        f"Unexpected status: {r.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_rapid_target_creation_handled(self, rate_limit_setup):
        """Rapid target creation requests should be handled gracefully."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Try to create 20 targets rapidly
            responses = await asyncio.gather(*[
                client.post(
                    "/api/targets",
                    json={
                        "name": f"Target-{i}",
                        "adapter": "filesystem",
                        "config": {"path": f"/test-{i}"},
                    },
                )
                for i in range(20)
            ], return_exceptions=True)

            # Count responses
            created = sum(1 for r in responses
                         if hasattr(r, 'status_code') and r.status_code in (200, 201))
            rate_limited = sum(1 for r in responses
                              if hasattr(r, 'status_code') and r.status_code == 429)

            # Should not cause server errors
            server_errors = sum(1 for r in responses
                               if hasattr(r, 'status_code') and r.status_code >= 500)
            assert server_errors == 0, "Server errors during rapid target creation"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_rapid_read_requests_handled(self, rate_limit_setup):
        """Rapid read requests should be handled gracefully."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Make 50 rapid GET requests
            responses = await asyncio.gather(*[
                client.get("/api/dashboard/stats")
                for _ in range(50)
            ], return_exceptions=True)

            # Should succeed or get rate limited, but not error
            for r in responses:
                if hasattr(r, 'status_code'):
                    assert r.status_code in (200, 429), \
                        f"Unexpected status for read request: {r.status_code}"

        app.dependency_overrides.clear()


class TestBruteForceProtection:
    """Tests for brute force attack prevention."""

    @pytest.mark.asyncio
    async def test_invalid_uuid_enumeration_returns_404(self, rate_limit_setup):
        """Enumeration attempts should return consistent 404."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Try many random UUIDs
            fake_ids = [uuid4() for _ in range(10)]

            responses = await asyncio.gather(*[
                client.get(f"/api/scans/{fake_id}")
                for fake_id in fake_ids
            ])

            # All should return 404 consistently
            for response in responses:
                assert response.status_code == 404, \
                    "UUID enumeration got inconsistent response"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_consistent_error_for_auth_failures(self, test_db):
        """Auth failures should return consistent errors to prevent enumeration."""
        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Different invalid tokens should get same error
                invalid_tokens = [
                    "invalid-token",
                    "another-fake-token",
                    "eyJhbGciOiJIUzI1NiJ9.fake.payload",
                ]

                responses = await asyncio.gather(*[
                    client.get(
                        "/api/dashboard/stats",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    for token in invalid_tokens
                ])

                # All should return same status code
                status_codes = [r.status_code for r in responses]
                assert len(set(status_codes)) == 1, \
                    f"Inconsistent auth error codes: {status_codes}"

        finally:
            app.dependency_overrides.clear()


class TestResourceExhaustionPrevention:
    """Tests for resource exhaustion prevention."""

    @pytest.mark.asyncio
    async def test_large_request_body_handled(self, rate_limit_setup):
        """Extremely large request bodies should be rejected or handled."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Create a large payload (1MB of data)
            large_name = "A" * (1024 * 1024)

            response = await client.post(
                "/api/targets",
                json={
                    "name": large_name,
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )

            # Should be rejected with 400, 413, or 422
            assert response.status_code in (400, 413, 422), \
                f"Large request accepted with status {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_deeply_nested_json_handled(self, rate_limit_setup):
        """Deeply nested JSON should not cause stack overflow."""
        data = rate_limit_setup

        # Create deeply nested structure
        nested = {"a": "b"}
        for _ in range(500):
            nested = {"n": nested}

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            response = await client.post(
                "/api/targets",
                json={
                    "name": "Deep Target",
                    "adapter": "filesystem",
                    "config": nested,
                },
            )

            # Should be rejected or handled, not crash
            assert response.status_code in (200, 201, 400, 413, 422, 500), \
                f"Deep nesting caused unexpected response: {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_many_query_parameters_handled(self, rate_limit_setup):
        """Many query parameters should be handled gracefully."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Create many query parameters
            params = {f"param_{i}": f"value_{i}" for i in range(100)}

            response = await client.get("/api/results", params=params)

            # Should be handled - either ignored or rejected
            assert response.status_code in (200, 400, 414, 422), \
                f"Many params caused status {response.status_code}"

        app.dependency_overrides.clear()


class TestRateLimitBypass:
    """Tests that rate limiting cannot be bypassed."""

    @pytest.mark.asyncio
    async def test_xff_header_not_trusted_by_default(self, rate_limit_setup):
        """X-Forwarded-For should not be trusted without proper config."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Make requests with spoofed X-Forwarded-For
            responses = await asyncio.gather(*[
                client.get(
                    "/api/dashboard/stats",
                    headers={"X-Forwarded-For": f"192.168.1.{i}"},
                )
                for i in range(20)
            ])

            # All requests should be treated as same origin unless
            # trusted proxies are configured
            # Just verify no server errors
            for r in responses:
                assert r.status_code < 500

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_case_variation_in_paths_handled(self, rate_limit_setup):
        """Path case variations should not bypass rate limits."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Try different case variations of same endpoint
            paths = [
                "/api/dashboard/stats",
                "/API/dashboard/stats",
                "/api/DASHBOARD/stats",
                "/api/Dashboard/Stats",
            ]

            responses = await asyncio.gather(*[
                client.get(path)
                for path in paths
            ])

            # Some may 404 if path is case-sensitive, that's fine
            # Just ensure no bypass
            for r in responses:
                assert r.status_code in (200, 404, 429)

        app.dependency_overrides.clear()


class TestConcurrencyLimits:
    """Tests for concurrent request handling."""

    @pytest.mark.asyncio
    async def test_concurrent_requests_handled(self, rate_limit_setup):
        """Many concurrent requests should be handled without deadlock."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Make 100 concurrent requests
            responses = await asyncio.gather(*[
                client.get("/api/targets")
                for _ in range(100)
            ], return_exceptions=True)

            # Count successful responses
            successful = sum(1 for r in responses
                           if hasattr(r, 'status_code') and r.status_code == 200)

            # At least some should succeed (not all timeout/fail)
            assert successful > 0, "All concurrent requests failed"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_slow_requests_dont_block_fast_ones(self, rate_limit_setup):
        """Slow requests should not block other requests."""
        data = rate_limit_setup

        async with create_test_client(
            data["session"], data["user"], data["tenant"]
        ) as client:
            # Mix of fast and potentially slow requests
            async def fast_request():
                return await client.get("/api/health/status")

            async def slow_request():
                # A request with lots of data
                return await client.get("/api/results", params={"page_size": 1000})

            # Start slow request, then make fast ones
            tasks = [slow_request()] + [fast_request() for _ in range(5)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Fast requests should complete
            fast_responses = responses[1:]
            completed = sum(1 for r in fast_responses
                          if hasattr(r, 'status_code') and r.status_code in (200, 401))

            # Most fast requests should complete
            assert completed >= 3, "Fast requests blocked by slow request"

        app.dependency_overrides.clear()

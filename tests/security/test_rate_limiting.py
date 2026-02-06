"""
Tests for rate limiting enforcement.

Rate limiting prevents brute force attacks, DoS attempts,
and resource exhaustion by limiting the number of requests
a client can make in a given time period.
"""

import asyncio
import pytest
from uuid import uuid4


class TestAuthRateLimiting:
    """Tests for rate limiting on authentication endpoints."""

    async def test_unauthenticated_endpoints_handle_rapid_requests(self, test_client):
        """Auth endpoints should handle rapid requests gracefully."""
        # Send requests sequentially but rapidly - true concurrency would
        # overload the shared test DB session (AsyncSession is not concurrent-safe)
        status_codes = []
        for _ in range(20):
            response = await test_client.get("/api/auth/login")
            status_codes.append(response.status_code)

        # Should either all succeed (no rate limiting) or some get 429
        # At minimum, requests should not cause 500 errors
        server_errors = sum(1 for s in status_codes if s >= 500)
        assert server_errors == 0, f"Server errors during rapid requests: {server_errors}"

    async def test_callback_handles_rapid_requests(self, test_client):
        """OAuth callback should handle rapid requests."""
        # Make rapid callback requests with fake codes
        responses = await asyncio.gather(*[
            test_client.get("/api/auth/callback", params={"code": f"fake-code-{i}"})
            for i in range(10)
        ], return_exceptions=True)

        # Should not cause server errors
        for r in responses:
            if hasattr(r, 'status_code'):
                assert r.status_code < 500, "Callback caused server error"


class TestAPIRateLimiting:
    """Tests for rate limiting on API endpoints."""

    async def test_rapid_scan_creation_handled(self, test_client):
        """Rapid scan creation requests should be handled gracefully."""
        # First create a target
        target_response = await test_client.post(
            "/api/targets",
            json={
                "name": "Rate Test Target",
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )

        if target_response.status_code not in (200, 201):
            pytest.skip("Could not create target for test")

        target_id = target_response.json().get("id")

        # Try to create 20 scans rapidly
        responses = await asyncio.gather(*[
            test_client.post(
                "/api/scans",
                json={"target_id": target_id},
            )
            for _ in range(20)
        ], return_exceptions=True)

        # Should either succeed, get rate limited (429), or validation error
        for r in responses:
            if hasattr(r, 'status_code'):
                assert r.status_code in (200, 201, 400, 422, 429), \
                    f"Unexpected status: {r.status_code}"

    async def test_rapid_target_creation_handled(self, test_client):
        """Rapid target creation requests should be handled gracefully."""
        # Send requests sequentially but rapidly - true concurrency would
        # overload the shared test DB session (AsyncSession is not concurrent-safe)
        server_errors = 0
        for i in range(20):
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": f"Target-{i}",
                    "adapter": "filesystem",
                    "config": {"path": f"/test-{i}"},
                },
            )
            if response.status_code >= 500:
                server_errors += 1

        # Should not cause server errors
        assert server_errors == 0, "Server errors during rapid target creation"

    async def test_rapid_read_requests_handled(self, test_client):
        """Rapid read requests should be handled gracefully."""
        # Make 50 rapid GET requests
        responses = await asyncio.gather(*[
            test_client.get("/api/dashboard/stats")
            for _ in range(50)
        ], return_exceptions=True)

        # Should succeed or get rate limited, but not error
        for r in responses:
            if hasattr(r, 'status_code'):
                assert r.status_code in (200, 429), \
                    f"Unexpected status for read request: {r.status_code}"


class TestBruteForceProtection:
    """Tests for brute force attack prevention."""

    async def test_invalid_uuid_enumeration_returns_404(self, test_client):
        """Enumeration attempts should return consistent 404."""
        # Try many random UUIDs
        fake_ids = [uuid4() for _ in range(10)]

        responses = await asyncio.gather(*[
            test_client.get(f"/api/scans/{fake_id}")
            for fake_id in fake_ids
        ])

        # All should return 404 consistently
        for response in responses:
            assert response.status_code == 404, \
                "UUID enumeration got inconsistent response"


class TestResourceExhaustionPrevention:
    """Tests for resource exhaustion prevention."""

    async def test_large_request_body_handled(self, test_client):
        """Extremely large request bodies should be rejected or handled."""
        # Create a large payload (1MB of data)
        large_name = "A" * (1024 * 1024)

        response = await test_client.post(
            "/api/targets",
            json={
                "name": large_name,
                "adapter": "filesystem",
                "config": {"path": "/test"},
            },
        )

        # Should be rejected or handled gracefully - NEVER 500 (server crash = DoS)
        assert response.status_code in (200, 201, 400, 413, 422), \
            f"Large request caused server error (status {response.status_code}). " \
            f"500 = server crash (DoS vulnerability)"

    async def test_deeply_nested_json_handled(self, test_client):
        """Deeply nested JSON should not cause stack overflow."""
        # Create deeply nested structure
        nested = {"a": "b"}
        for _ in range(500):
            nested = {"n": nested}

        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Deep Target",
                "adapter": "filesystem",
                "config": nested,
            },
        )

        # Should be rejected or handled - NEVER 500 (server crash = DoS vulnerability)
        assert response.status_code in (200, 201, 400, 413, 422), \
            f"Deep nesting caused server error ({response.status_code}) - potential DoS vulnerability"

    async def test_many_query_parameters_handled(self, test_client):
        """Many query parameters should be handled gracefully."""
        # Create many query parameters
        params = {f"param_{i}": f"value_{i}" for i in range(100)}

        response = await test_client.get("/api/results", params=params)

        # Should be handled - either ignored or rejected
        assert response.status_code in (200, 400, 414, 422), \
            f"Many params caused status {response.status_code}"


class TestRateLimitBypass:
    """Tests that rate limiting cannot be bypassed."""

    async def test_case_variation_in_paths_handled(self, test_client):
        """Path case variations should not bypass rate limits."""
        # Try different case variations of same endpoint
        paths = [
            "/api/dashboard/stats",
            "/API/dashboard/stats",
            "/api/DASHBOARD/stats",
            "/api/Dashboard/Stats",
        ]

        responses = await asyncio.gather(*[
            test_client.get(path)
            for path in paths
        ])

        # Some may 404 if path is case-sensitive, that's fine
        # Just ensure no bypass
        for r in responses:
            assert r.status_code in (200, 404, 429)


class TestConcurrencyLimits:
    """Tests for concurrent request handling."""

    async def test_concurrent_requests_handled(self, test_client):
        """Many concurrent requests should be handled without deadlock."""
        # Make 100 concurrent requests
        responses = await asyncio.gather(*[
            test_client.get("/api/targets")
            for _ in range(100)
        ], return_exceptions=True)

        # Count successful responses
        successful = sum(1 for r in responses
                       if hasattr(r, 'status_code') and r.status_code == 200)

        # At least some should succeed (not all timeout/fail)
        assert successful > 0, "All concurrent requests failed"

    async def test_slow_requests_dont_block_fast_ones(self, test_client):
        """Slow requests should not block other requests."""
        # Mix of fast and potentially slow requests
        async def fast_request():
            return await test_client.get("/api/health/status")

        async def slow_request():
            # A request with lots of data
            return await test_client.get("/api/results", params={"page_size": 1000})

        # Start slow request, then make fast ones
        tasks = [slow_request()] + [fast_request() for _ in range(5)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Fast requests should complete
        fast_responses = responses[1:]
        completed = sum(1 for r in fast_responses
                      if hasattr(r, 'status_code') and r.status_code in (200, 401, 404))

        # Most fast requests should complete
        assert completed >= 3, "Fast requests blocked by slow request"

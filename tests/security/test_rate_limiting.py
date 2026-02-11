"""
Tests for rate limiting enforcement.

Rate limiting prevents brute force attacks, DoS attempts,
and resource exhaustion by limiting the number of requests
a client can make in a given time period.

NOTE: The test_client fixture disables rate limiting to avoid interference
with functional tests. These tests focus on verifying that the application
handles rapid requests gracefully (no crashes, no data corruption) and
that resource exhaustion attempts are properly bounded.
"""

import asyncio
import pytest
from uuid import uuid4


class TestAuthRateLimiting:
    """Tests for rate limiting on authentication endpoints."""

    async def test_unauthenticated_endpoints_handle_rapid_requests(self, test_client):
        """Auth endpoints should handle rapid requests without server errors."""
        status_codes = []
        for _ in range(20):
            response = await test_client.get("/api/auth/login")
            status_codes.append(response.status_code)

        # No server errors should occur
        server_errors = [s for s in status_codes if s >= 500]
        assert len(server_errors) == 0, \
            f"Server errors during rapid auth requests: {server_errors}"

        # All responses should be valid HTTP status codes (redirects, success, or rate limit)
        for code in status_codes:
            assert code in (200, 302, 307, 400, 429, 501), \
                f"Unexpected status code from auth endpoint: {code}"

    async def test_callback_handles_rapid_requests(self, test_client):
        """OAuth callback should handle rapid requests without server errors."""
        responses = await asyncio.gather(*[
            test_client.get("/api/auth/callback", params={"code": f"fake-code-{i}"})
            for i in range(10)
        ], return_exceptions=True)

        for i, r in enumerate(responses):
            if isinstance(r, Exception):
                pytest.fail(f"Callback request {i} raised exception: {r}")
            assert r.status_code < 500, \
                f"Callback request {i} caused server error: status {r.status_code}"


class TestAPIRateLimiting:
    """Tests for rate limiting on API endpoints."""

    async def test_rapid_scan_creation_handled(self, test_client):
        """Rapid scan creation requests should be handled without server errors."""
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
        assert target_id is not None, "Target response missing 'id'"

        # Try to create 20 scans rapidly
        responses = await asyncio.gather(*[
            test_client.post(
                "/api/scans",
                json={"target_id": target_id},
            )
            for _ in range(20)
        ], return_exceptions=True)

        server_errors = []
        for i, r in enumerate(responses):
            if isinstance(r, Exception):
                pytest.fail(f"Scan creation request {i} raised exception: {r}")
            if r.status_code >= 500:
                server_errors.append((i, r.status_code))

        assert len(server_errors) == 0, \
            f"Server errors during rapid scan creation: {server_errors}"

    async def test_rapid_target_creation_handled(self, test_client):
        """Rapid target creation requests should be handled without server errors."""
        results = []
        for i in range(20):
            response = await test_client.post(
                "/api/targets",
                json={
                    "name": f"Rate-Target-{i}",
                    "adapter": "filesystem",
                    "config": {"path": f"/test-rate-{i}"},
                },
            )
            results.append((i, response.status_code))

        server_errors = [(i, code) for i, code in results if code >= 500]
        assert len(server_errors) == 0, \
            f"Server errors during rapid target creation: {server_errors}"

        # Verify at least some targets were successfully created
        successes = [code for _, code in results if code in (200, 201)]
        assert len(successes) > 0, \
            "No targets were successfully created during rapid creation test"

    async def test_rapid_read_requests_handled(self, test_client):
        """Rapid read requests should be handled without server errors."""
        responses = await asyncio.gather(*[
            test_client.get("/api/dashboard/stats")
            for _ in range(50)
        ], return_exceptions=True)

        server_errors = []
        successes = 0
        for i, r in enumerate(responses):
            if isinstance(r, Exception):
                pytest.fail(f"Read request {i} raised exception: {r}")
            if r.status_code >= 500:
                server_errors.append((i, r.status_code))
            elif r.status_code == 200:
                successes += 1

        assert len(server_errors) == 0, \
            f"Server errors during rapid read requests: {server_errors}"
        assert successes > 0, "No successful read requests"


class TestBruteForceProtection:
    """Tests for brute force attack prevention."""

    async def test_invalid_uuid_enumeration_returns_404(self, test_client):
        """Enumeration attempts with random UUIDs should consistently return 404."""
        fake_ids = [uuid4() for _ in range(10)]

        responses = await asyncio.gather(*[
            test_client.get(f"/api/scans/{fake_id}")
            for fake_id in fake_ids
        ])

        # All should return 404 consistently (not mixed 403/404 which would leak info)
        for i, response in enumerate(responses):
            assert response.status_code == 404, \
                f"UUID enumeration request {i} returned {response.status_code}, expected 404"

    async def test_invalid_uuid_enumeration_consistent_across_endpoints(self, test_client):
        """All resource endpoints should return 404 for non-existent UUIDs."""
        fake_id = uuid4()

        endpoints = [
            f"/api/scans/{fake_id}",
            f"/api/targets/{fake_id}",
            f"/api/results/{fake_id}",
            f"/api/schedules/{fake_id}",
        ]

        for endpoint in endpoints:
            response = await test_client.get(endpoint)
            assert response.status_code == 404, \
                f"Endpoint {endpoint} returned {response.status_code}, expected 404"


class TestResourceExhaustionPrevention:
    """Tests for resource exhaustion prevention."""

    async def test_large_request_body_handled(self, test_client):
        """Extremely large request bodies should be rejected or handled gracefully."""
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

        # MUST NOT cause server crash (500). Should be rejected by:
        # - TargetCreate.name has max_length=255, so 422 is expected
        # - Or limit_request_size middleware rejects with 413
        assert response.status_code != 500, \
            "Large request body caused server error (500) - potential DoS vulnerability"
        assert response.status_code in (400, 413, 422), \
            f"Expected 400/413/422 for oversized name, got {response.status_code}"

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

        # MUST NOT cause server crash (500 = DoS vulnerability)
        assert response.status_code != 500, \
            "Deep nesting caused server error (500) - potential DoS vulnerability"

    async def test_many_query_parameters_handled(self, test_client):
        """Many query parameters should be handled gracefully."""
        # Create many query parameters
        params = {f"param_{i}": f"value_{i}" for i in range(100)}

        response = await test_client.get("/api/results", params=params)

        # Extra parameters should be ignored by the endpoint or rejected.
        # Must not crash the server.
        assert response.status_code != 500, \
            "Many query parameters caused server error (500)"
        assert response.status_code in (200, 400, 414, 422), \
            f"Unexpected status {response.status_code} for many query params"


class TestConcurrencyLimits:
    """Tests for concurrent request handling."""

    async def test_concurrent_requests_handled(self, test_client):
        """Many concurrent requests should be handled without deadlock or crash."""
        responses = await asyncio.gather(*[
            test_client.get("/api/targets")
            for _ in range(100)
        ], return_exceptions=True)

        # Count results
        successful = 0
        server_errors = 0
        exceptions = 0
        for r in responses:
            if isinstance(r, Exception):
                exceptions += 1
            elif r.status_code == 200:
                successful += 1
            elif r.status_code >= 500:
                server_errors += 1

        # No server errors (crash/deadlock)
        assert server_errors == 0, \
            f"Server errors during concurrent requests: {server_errors}"

        # At least some should succeed
        assert successful > 0, \
            f"No successful concurrent requests (exceptions={exceptions})"

"""
Comprehensive tests for FastAPI application setup and middleware.

Tests focus on:
- Health check endpoint
- API info endpoint
- Request ID middleware
- Request size limit middleware
- Client IP detection
- Global exception handling
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from uuid import uuid4


class TestHealthCheckEndpoint:
    """Tests for GET /health endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client):
        """Health check should return 200 OK."""
        response = await test_client.get("/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_healthy_status(self, test_client):
        """Health check should return healthy status."""
        response = await test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_includes_version(self, test_client):
        """Health check should include version."""
        response = await test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert data["version"] is not None


class TestApiInfoEndpoint:
    """Tests for GET /api endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client):
        """API info should return 200 OK."""
        response = await test_client.get("/api")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_api_info(self, test_client):
        """API info should return name, version, and docs URL."""
        response = await test_client.get("/api")
        assert response.status_code == 200
        data = response.json()

        assert "name" in data
        assert data["name"] == "OpenLabels API"
        assert "version" in data
        assert "docs" in data
        assert data["docs"] == "/api/docs"

    @pytest.mark.asyncio
    async def test_returns_versioning_info(self, test_client):
        """API info should include versioning information."""
        response = await test_client.get("/api")
        assert response.status_code == 200
        data = response.json()

        assert "current_api_version" in data
        assert data["current_api_version"] == "v1"
        assert "supported_versions" in data
        assert "v1" in data["supported_versions"]
        assert "versions_endpoint" in data
        assert data["versions_endpoint"] == "/api/versions"


class TestApiVersionsEndpoint:
    """Tests for GET /api/versions endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client):
        """API versions endpoint should return 200 OK."""
        response = await test_client.get("/api/versions")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_version_info(self, test_client):
        """API versions should return version information."""
        response = await test_client.get("/api/versions")
        assert response.status_code == 200
        data = response.json()

        assert "current_version" in data
        assert data["current_version"] == "v1"
        assert "supported_versions" in data
        assert "v1" in data["supported_versions"]
        assert "versions" in data
        assert len(data["versions"]) > 0

    @pytest.mark.asyncio
    async def test_version_details(self, test_client):
        """API versions should include detailed version info."""
        response = await test_client.get("/api/versions")
        assert response.status_code == 200
        data = response.json()

        v1_info = data["versions"][0]
        assert v1_info["version"] == "v1"
        assert v1_info["status"] == "current"
        assert v1_info["base_url"] == "/api/v1"


class TestRequestIdMiddleware:
    """Tests for request ID correlation middleware."""

    @pytest.mark.asyncio
    async def test_generates_request_id_when_not_provided(self, test_client):
        """Should generate request ID if not provided."""
        response = await test_client.get("/health")
        assert response.status_code == 200
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0

    @pytest.mark.asyncio
    async def test_uses_provided_request_id(self, test_client):
        """Should use provided X-Request-ID header."""
        custom_id = "custom-req-123"
        response = await test_client.get(
            "/health",
            headers={"X-Request-ID": custom_id},
        )
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == custom_id


class TestGetClientIp:
    """Tests for client IP detection function."""

    def test_returns_x_forwarded_for_first_ip(self):
        """Should return first IP from X-Forwarded-For header."""
        from openlabels.server.app import get_client_ip

        request = MagicMock()
        request.headers = {
            "X-Forwarded-For": "10.0.0.1, 192.168.1.1, 172.16.0.1",
        }
        request.client = None

        ip = get_client_ip(request)
        assert ip == "10.0.0.1"

    def test_strips_whitespace_from_forwarded_for(self):
        """Should strip whitespace from X-Forwarded-For values."""
        from openlabels.server.app import get_client_ip

        request = MagicMock()
        request.headers = {
            "X-Forwarded-For": "  10.0.0.1  ,  192.168.1.1  ",
        }
        request.client = None

        ip = get_client_ip(request)
        assert ip == "10.0.0.1"

    def test_returns_x_real_ip_when_no_forwarded_for(self):
        """Should use X-Real-IP when X-Forwarded-For is not present."""
        from openlabels.server.app import get_client_ip

        request = MagicMock()
        request.headers = {
            "X-Real-IP": "10.0.0.2",
        }
        request.client = None

        ip = get_client_ip(request)
        assert ip == "10.0.0.2"

    def test_strips_whitespace_from_real_ip(self):
        """Should strip whitespace from X-Real-IP value."""
        from openlabels.server.app import get_client_ip

        request = MagicMock()
        request.headers = {
            "X-Real-IP": "  10.0.0.2  ",
        }
        request.client = None

        ip = get_client_ip(request)
        assert ip == "10.0.0.2"

    def test_returns_client_host_when_no_proxy_headers(self):
        """Should use client.host when no proxy headers."""
        from openlabels.server.app import get_client_ip

        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "192.168.1.100"

        ip = get_client_ip(request)
        assert ip == "192.168.1.100"

    def test_returns_localhost_when_no_client(self):
        """Should return 127.0.0.1 when client is None."""
        from openlabels.server.app import get_client_ip

        request = MagicMock()
        request.headers = {}
        request.client = None

        ip = get_client_ip(request)
        assert ip == "127.0.0.1"

    def test_x_forwarded_for_takes_priority(self):
        """X-Forwarded-For should take priority over X-Real-IP."""
        from openlabels.server.app import get_client_ip

        request = MagicMock()
        request.headers = {
            "X-Forwarded-For": "10.0.0.1",
            "X-Real-IP": "10.0.0.2",
        }
        request.client = MagicMock()
        request.client.host = "192.168.1.100"

        ip = get_client_ip(request)
        assert ip == "10.0.0.1"


class TestContentType:
    """Tests for response content types."""

    @pytest.mark.asyncio
    async def test_health_returns_json(self, test_client):
        """Health endpoint should return JSON."""
        response = await test_client.get("/health")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_api_returns_json(self, test_client):
        """API info endpoint should return JSON."""
        response = await test_client.get("/api")
        assert "application/json" in response.headers.get("content-type", "")


class TestRouteRegistration:
    """Tests for API route registration."""

    @pytest.mark.asyncio
    async def test_audit_routes_registered(self, test_client):
        """Audit routes should be registered."""
        response = await test_client.get("/api/audit")
        # Accept 200, 401, 403 (authenticated), not 404
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_jobs_routes_registered(self, test_client):
        """Jobs routes should be registered."""
        response = await test_client.get("/api/jobs")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_scans_routes_registered(self, test_client):
        """Scans routes should be registered."""
        response = await test_client.get("/api/scans")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_results_routes_registered(self, test_client):
        """Results routes should be registered."""
        response = await test_client.get("/api/results")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_targets_routes_registered(self, test_client):
        """Targets routes should be registered."""
        response = await test_client.get("/api/targets")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_schedules_routes_registered(self, test_client):
        """Schedules routes should be registered."""
        response = await test_client.get("/api/schedules")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_labels_routes_registered(self, test_client):
        """Labels routes should be registered."""
        response = await test_client.get("/api/labels")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_users_routes_registered(self, test_client):
        """Users routes should be registered."""
        response = await test_client.get("/api/users")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_dashboard_routes_registered(self, test_client):
        """Dashboard routes should be registered."""
        response = await test_client.get("/api/dashboard/stats")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_remediation_routes_registered(self, test_client):
        """Remediation routes should be registered."""
        response = await test_client.get("/api/remediation")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_monitoring_routes_registered(self, test_client):
        """Monitoring routes should be registered."""
        response = await test_client.get("/api/monitoring/files")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_health_status_routes_registered(self, test_client):
        """Health status routes should be registered."""
        response = await test_client.get("/api/health/status")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_settings_routes_registered(self, test_client):
        """Settings routes should be registered."""
        response = await test_client.post("/api/settings/reset")
        assert response.status_code != 404


class TestVersionedRouteRegistration:
    """Tests for versioned API route registration at /api/v1/*."""

    @pytest.mark.asyncio
    async def test_v1_jobs_routes_registered(self, test_client):
        """V1 Jobs routes should be registered."""
        response = await test_client.get("/api/v1/jobs")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_v1_scans_routes_registered(self, test_client):
        """V1 Scans routes should be registered."""
        response = await test_client.get("/api/v1/scans")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_v1_targets_routes_registered(self, test_client):
        """V1 Targets routes should be registered."""
        response = await test_client.get("/api/v1/targets")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_v1_labels_routes_registered(self, test_client):
        """V1 Labels routes should be registered."""
        response = await test_client.get("/api/v1/labels")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_v1_users_routes_registered(self, test_client):
        """V1 Users routes should be registered."""
        response = await test_client.get("/api/v1/users")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_v1_dashboard_routes_registered(self, test_client):
        """V1 Dashboard routes should be registered."""
        response = await test_client.get("/api/v1/dashboard/stats")
        assert response.status_code != 404

    @pytest.mark.asyncio
    async def test_v1_auth_routes_registered(self, test_client):
        """V1 Auth routes should be registered."""
        response = await test_client.get("/api/v1/auth/login")
        # Auth redirects, so accept redirect status codes too
        assert response.status_code != 404


class TestBackwardCompatibilityRedirect:
    """Tests for backward compatibility redirect from /api/* to /api/v1/*."""

    @pytest.mark.asyncio
    async def test_legacy_api_redirects_to_v1(self, test_client):
        """Legacy /api/* requests should redirect to /api/v1/*."""
        # Use follow_redirects=False to check the redirect response
        response = await test_client.get("/api/jobs", follow_redirects=False)
        # Should return 307 redirect
        assert response.status_code == 307
        assert "/api/v1/jobs" in response.headers.get("location", "")

    @pytest.mark.asyncio
    async def test_legacy_api_preserves_query_string(self, test_client):
        """Legacy redirect should preserve query string parameters."""
        response = await test_client.get("/api/jobs?limit=10&offset=5", follow_redirects=False)
        assert response.status_code == 307
        location = response.headers.get("location", "")
        assert "/api/v1/jobs" in location
        assert "limit=10" in location
        assert "offset=5" in location

    @pytest.mark.asyncio
    async def test_following_redirect_works(self, test_client):
        """Following the redirect should reach the v1 endpoint."""
        response = await test_client.get("/api/jobs", follow_redirects=True)
        # Should not be 404 after following redirect
        assert response.status_code != 404

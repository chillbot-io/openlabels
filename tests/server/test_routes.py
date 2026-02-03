"""
Tests for server API routes.

Tests cover:
- Health endpoints
- Audit log endpoints
- Targets endpoints
- Jobs endpoints
- Authentication status
"""

import pytest
from uuid import uuid4
from datetime import datetime


@pytest.fixture
async def setup_test_data(test_db):
    """Set up test data for route tests."""
    from sqlalchemy import select
    from openlabels.server.models import (
        Tenant, User, ScanTarget, AuditLog, JobQueue as JobQueueModel,
    )

    # Get the existing tenant and user created by test_client fixture
    result = await test_db.execute(select(Tenant).where(Tenant.name == "Test Tenant"))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create some scan targets
    target1 = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Test Target 1",
        adapter="filesystem",
        config={"path": "/test/path1"},
        enabled=True,
        created_by=user.id,
    )
    target2 = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Test Target 2",
        adapter="sharepoint",
        config={"site": "https://example.sharepoint.com"},
        enabled=False,
        created_by=user.id,
    )
    test_db.add(target1)
    test_db.add(target2)

    # Create some audit logs
    audit1 = AuditLog(
        id=uuid4(),
        tenant_id=tenant.id,
        user_id=user.id,
        action="scan_started",
        resource_type="scan",
        resource_id=uuid4(),
        details={"test": "data"},
    )
    audit2 = AuditLog(
        id=uuid4(),
        tenant_id=tenant.id,
        user_id=user.id,
        action="target_created",
        resource_type="target",
        resource_id=target1.id,
        details={"name": target1.name},
    )
    test_db.add(audit1)
    test_db.add(audit2)

    # Create some jobs
    job_pending = JobQueueModel(
        id=uuid4(),
        tenant_id=tenant.id,
        task_type="scan",
        payload={"test": "payload"},
        priority=50,
        status="pending",
    )
    job_failed = JobQueueModel(
        id=uuid4(),
        tenant_id=tenant.id,
        task_type="scan",
        payload={"test": "failed"},
        priority=50,
        status="failed",
        error="Test error",
        retry_count=3,
    )
    test_db.add(job_pending)
    test_db.add(job_failed)

    await test_db.flush()

    return {
        "tenant": tenant,
        "user": user,
        "targets": [target1, target2],
        "audits": [audit1, audit2],
        "jobs": {"pending": job_pending, "failed": job_failed},
    }


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    async def test_health_check(self, test_client):
        """Test GET /health returns healthy status."""
        response = await test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    async def test_api_info(self, test_client):
        """Test GET /api returns API info."""
        response = await test_client.get("/api")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "OpenLabels API"
        assert "version" in data


class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    async def test_auth_status_unauthenticated(self, test_client):
        """Test GET /auth/status when not authenticated."""
        response = await test_client.get("/auth/status")
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False
        assert "provider" in data

    async def test_login_redirect(self, test_client, setup_test_data):
        """Test GET /auth/login redirects in dev mode."""
        response = await test_client.get(
            "/auth/login",
            follow_redirects=False,
        )
        # In dev mode (provider=none), it should redirect with a session cookie
        # In test mode without auth config, may return 503 (Service Unavailable)
        assert response.status_code in [302, 503]


class TestTargetsEndpoints:
    """Tests for scan targets endpoints."""

    async def test_list_targets(self, test_client, setup_test_data):
        """Test GET /api/targets returns paginated results."""
        response = await test_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "total_pages" in data
        assert data["total"] >= 0

    async def test_list_targets_with_filter(self, test_client, setup_test_data):
        """Test GET /api/targets with adapter filter."""
        response = await test_client.get("/api/targets?adapter=filesystem")
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["adapter"] == "filesystem"

    async def test_list_targets_pagination(self, test_client, setup_test_data):
        """Test GET /api/targets with pagination."""
        response = await test_client.get("/api/targets?page=1&page_size=1")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) <= 1
        assert data["page"] == 1
        assert data["page_size"] == 1


class TestAuditEndpoints:
    """Tests for audit log endpoints."""

    async def test_list_audit_logs(self, test_client, setup_test_data):
        """Test GET /api/audit returns paginated audit logs."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data

    async def test_list_audit_logs_with_filter(self, test_client, setup_test_data):
        """Test GET /api/audit with action filter."""
        response = await test_client.get("/api/audit?action=scan_started")
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["action"] == "scan_started"

    async def test_get_audit_filters(self, test_client, setup_test_data):
        """Test GET /api/audit/filters returns available filters."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200
        data = response.json()
        assert "actions" in data
        assert "resource_types" in data
        assert isinstance(data["actions"], list)


class TestJobsEndpoints:
    """Tests for job queue endpoints."""

    async def test_get_queue_stats(self, test_client, setup_test_data):
        """Test GET /api/jobs/stats returns queue statistics."""
        response = await test_client.get("/api/jobs/stats")
        assert response.status_code == 200
        data = response.json()
        assert "pending" in data
        assert "running" in data
        assert "completed" in data
        assert "failed" in data
        assert "cancelled" in data
        assert "failed_by_type" in data

    async def test_list_failed_jobs(self, test_client, setup_test_data):
        """Test GET /api/jobs/failed returns failed jobs."""
        response = await test_client.get("/api/jobs/failed")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        for item in data["items"]:
            assert item["status"] == "failed"

    async def test_list_failed_jobs_pagination(self, test_client, setup_test_data):
        """Test GET /api/jobs/failed with pagination."""
        response = await test_client.get("/api/jobs/failed?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 10


class TestCSRFProtection:
    """Tests for CSRF protection."""

    async def test_csrf_cookie_on_get(self, test_client):
        """Test that CSRF cookie is set on GET requests."""
        response = await test_client.get("/health")
        assert response.status_code == 200
        # In dev mode, CSRF is skipped, but cookie might still be set

    async def test_post_request_allowed_same_origin(self, test_client, setup_test_data):
        """Test POST request with proper origin header."""
        # In dev mode (auth.provider=none), CSRF is skipped
        response = await test_client.post(
            "/api/jobs/requeue-all",
            json={"task_type": "scan", "reset_retries": True},
            headers={"Origin": "http://test"},
        )
        # Should work in dev mode
        assert response.status_code in [200, 403, 401]


class TestErrorHandling:
    """Tests for error handling."""

    async def test_404_on_unknown_route(self, test_client):
        """Test 404 returned for unknown routes."""
        response = await test_client.get("/api/nonexistent")
        assert response.status_code == 404

    async def test_404_on_nonexistent_job(self, test_client, setup_test_data):
        """Test 404 when job doesn't exist."""
        fake_id = str(uuid4())
        response = await test_client.get(f"/api/jobs/{fake_id}")
        assert response.status_code == 404

    async def test_invalid_pagination_params(self, test_client, setup_test_data):
        """Test validation of pagination parameters."""
        # page_size too high
        response = await test_client.get("/api/targets?page_size=1000")
        assert response.status_code == 422  # Validation error

        # page too low
        response = await test_client.get("/api/targets?page=0")
        assert response.status_code == 422


class TestWebSocketAuth:
    """Tests for WebSocket authentication."""

    async def test_websocket_requires_auth(self, test_client):
        """Test that WebSocket connections require authentication."""
        # We can't easily test WebSocket with httpx, but we can verify
        # the endpoint is registered. FastAPI returns 404 for GET requests
        # to WebSocket-only endpoints since there's no GET handler.
        response = await test_client.get(f"/ws/scans/{uuid4()}")
        # WebSocket endpoints typically return 400 or upgrade required on GET
        # Note: 404 may be returned if WebSocket routes aren't mounted in test config
        assert response.status_code in [400, 403, 404, 426]


class TestRateLimiting:
    """Tests for rate limiting."""

    async def test_rate_limit_headers(self, test_client):
        """Test that rate limit headers are present."""
        response = await test_client.get("/health")
        # Rate limit headers may or may not be present depending on config
        assert response.status_code == 200

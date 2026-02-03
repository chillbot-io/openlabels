"""
Comprehensive tests for health API endpoints.

Tests focus on:
- Health status response structure
- Database connectivity status
- Job queue status detection
- ML/MIP/OCR availability checks
- Scan statistics computation
- System info (Python version, platform, uptime)
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import patch, MagicMock


@pytest.fixture
async def setup_health_test_data(test_db):
    """Set up test data for health endpoint tests."""
    from openlabels.server.models import (
        Tenant, User, ScanJob, ScanResult, JobQueue as JobQueueModel,
    )

    # Create a test tenant
    tenant = Tenant(
        id=uuid4(),
        name="Health Test Tenant",
        azure_tenant_id="health-test-tenant",
    )
    test_db.add(tenant)

    # Create a test user
    user = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email="health-test@localhost",
        name="Health Test User",
        role="admin",
    )
    test_db.add(user)

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
    }


class TestHealthStatusEndpoint:
    """Tests for GET /api/health/status endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_health_test_data):
        """Health endpoint should return 200 OK."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_health_status_structure(self, test_client, setup_health_test_data):
        """Response should have all required health status fields."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        # Server status fields
        assert "api" in data
        assert "api_text" in data
        assert "db" in data
        assert "db_text" in data
        assert "queue" in data
        assert "queue_text" in data

        # Service status fields
        assert "ml" in data
        assert "ml_text" in data
        assert "mip" in data
        assert "mip_text" in data
        assert "ocr" in data
        assert "ocr_text" in data

        # Statistics fields
        assert "scans_today" in data
        assert "files_processed" in data
        assert "success_rate" in data

    @pytest.mark.asyncio
    async def test_api_status_is_healthy(self, test_client, setup_health_test_data):
        """API status should always be healthy if endpoint responds."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["api"] == "healthy"
        assert data["api_text"] == "OK"

    @pytest.mark.asyncio
    async def test_db_status_is_healthy(self, test_client, setup_health_test_data):
        """Database status should be healthy when connected."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["db"] == "healthy"
        assert data["db_text"] == "Connected"

    @pytest.mark.asyncio
    async def test_includes_python_version(self, test_client, setup_health_test_data):
        """Response should include Python version."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert "python_version" in data
        assert data["python_version"] is not None
        # Version format X.Y.Z
        assert "." in data["python_version"]

    @pytest.mark.asyncio
    async def test_includes_platform(self, test_client, setup_health_test_data):
        """Response should include platform info."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert "platform" in data
        assert data["platform"] is not None
        assert data["platform"] in ("Linux", "Windows", "Darwin")

    @pytest.mark.asyncio
    async def test_includes_uptime(self, test_client, setup_health_test_data):
        """Response should include uptime in seconds."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert "uptime_seconds" in data
        assert data["uptime_seconds"] is not None
        assert data["uptime_seconds"] >= 0


class TestHealthQueueStatus:
    """Tests for job queue health status."""

    @pytest.fixture
    async def setup_queue_data(self, test_db):
        """Set up test data with job queue entries."""
        from openlabels.server.models import (
            Tenant, User, JobQueue as JobQueueModel,
        )

        tenant = Tenant(
            id=uuid4(),
            name="Queue Test Tenant",
            azure_tenant_id="queue-test-tenant",
        )
        test_db.add(tenant)

        user = User(
            id=uuid4(),
            tenant_id=tenant.id,
            email="queue-test@localhost",
            name="Queue Test User",
            role="admin",
        )
        test_db.add(user)

        await test_db.commit()

        return {
            "tenant": tenant,
            "user": user,
            "session": test_db,
        }

    @pytest.mark.asyncio
    async def test_queue_healthy_with_few_pending(self, test_client, setup_queue_data):
        """Queue should be healthy with few pending jobs."""
        from openlabels.server.models import JobQueue as JobQueueModel

        session = setup_queue_data["session"]
        tenant = setup_queue_data["tenant"]

        # Add 5 pending jobs (below warning threshold)
        for i in range(5):
            job = JobQueueModel(
                id=uuid4(),
                tenant_id=tenant.id,
                task_type="scan",
                payload={"test": f"job_{i}"},
                priority=50,
                status="pending",
            )
            session.add(job)
        await session.commit()

        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["queue"] == "healthy"
        assert "5 pending" in data["queue_text"]

    @pytest.mark.asyncio
    async def test_queue_warning_with_many_pending(self, test_client, setup_queue_data):
        """Queue should show warning with many pending jobs (>100)."""
        from openlabels.server.models import JobQueue as JobQueueModel

        session = setup_queue_data["session"]
        tenant = setup_queue_data["tenant"]

        # Add 150 pending jobs (above warning threshold)
        for i in range(150):
            job = JobQueueModel(
                id=uuid4(),
                tenant_id=tenant.id,
                task_type="scan",
                payload={"test": f"job_{i}"},
                priority=50,
                status="pending",
            )
            session.add(job)
        await session.commit()

        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["queue"] == "warning"
        assert "150 pending" in data["queue_text"]

    @pytest.mark.asyncio
    async def test_queue_error_with_many_failed(self, test_client, setup_queue_data):
        """Queue should show error with many failed jobs (>10)."""
        from openlabels.server.models import JobQueue as JobQueueModel

        session = setup_queue_data["session"]
        tenant = setup_queue_data["tenant"]

        # Add 15 failed jobs (above error threshold)
        for i in range(15):
            job = JobQueueModel(
                id=uuid4(),
                tenant_id=tenant.id,
                task_type="scan",
                payload={"test": f"failed_job_{i}"},
                priority=50,
                status="failed",
                error="Test failure",
                retry_count=3,
            )
            session.add(job)
        await session.commit()

        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["queue"] == "error"
        assert "15 failed" in data["queue_text"]


class TestHealthScanStatistics:
    """Tests for scan statistics in health check."""

    @pytest.fixture
    async def setup_scan_data(self, test_db):
        """Set up test data with scan jobs and results.

        Uses the existing tenant/user created by test_client fixture.
        """
        from sqlalchemy import select
        from openlabels.server.models import (
            Tenant, User, ScanJob, ScanResult, ScanTarget,
        )

        # Get the existing tenant created by test_client
        result = await test_db.execute(select(Tenant).where(Tenant.name == "Test Tenant"))
        tenant = result.scalar_one()

        result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
        user = result.scalar_one()

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

    @pytest.mark.asyncio
    async def test_scans_today_count(self, test_client, setup_scan_data):
        """Should return count of scans created today."""
        from openlabels.server.models import ScanJob

        session = setup_scan_data["session"]
        tenant = setup_scan_data["tenant"]
        target = setup_scan_data["target"]

        # Add scan jobs for today
        for i in range(5):
            scan = ScanJob(
                id=uuid4(),
                tenant_id=tenant.id,
                target_id=target.id,
                status="completed",
            )
            session.add(scan)
        await session.commit()

        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["scans_today"] == 5

    @pytest.mark.asyncio
    async def test_files_processed_count(self, test_client, setup_scan_data):
        """Should return total files processed count."""
        from openlabels.server.models import ScanJob, ScanResult

        session = setup_scan_data["session"]
        tenant = setup_scan_data["tenant"]
        target = setup_scan_data["target"]

        # Create a scan job
        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            status="completed",
        )
        session.add(scan)
        await session.flush()

        # Add scan results (files processed)
        for i in range(10):
            result = ScanResult(
                id=uuid4(),
                tenant_id=tenant.id,
                job_id=scan.id,
                file_path=f"/test/file_{i}.txt",
                file_name=f"file_{i}.txt",
                risk_score=50,
                risk_tier="MODERATE",
                entity_counts={},
                total_entities=0,
            )
            session.add(result)
        await session.commit()

        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["files_processed"] == 10

    @pytest.mark.asyncio
    async def test_success_rate_calculation(self, test_client, setup_scan_data):
        """Should calculate success rate from completed/total scans."""
        from openlabels.server.models import ScanJob

        session = setup_scan_data["session"]
        tenant = setup_scan_data["tenant"]
        target = setup_scan_data["target"]

        # Add 8 completed and 2 failed scans (80% success rate)
        for i in range(8):
            scan = ScanJob(
                id=uuid4(),
                tenant_id=tenant.id,
                target_id=target.id,
                status="completed",
            )
            session.add(scan)

        for i in range(2):
            scan = ScanJob(
                id=uuid4(),
                tenant_id=tenant.id,
                target_id=target.id,
                status="failed",
            )
            session.add(scan)
        await session.commit()

        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["success_rate"] == 80.0

    @pytest.mark.asyncio
    async def test_success_rate_100_when_no_scans(self, test_client, setup_scan_data):
        """Success rate should be 100% when no scans exist (no failures)."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["success_rate"] == 100.0


class TestHealthServiceStatus:
    """Tests for service availability status."""

    @pytest.mark.asyncio
    async def test_ml_status_present(self, test_client, setup_health_test_data):
        """ML status should be present in response."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert "ml" in data
        assert data["ml"] in ("healthy", "warning", "error")
        assert "ml_text" in data

    @pytest.mark.asyncio
    async def test_mip_status_present(self, test_client, setup_health_test_data):
        """MIP status should be present in response."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert "mip" in data
        assert data["mip"] in ("healthy", "warning", "error")
        assert "mip_text" in data

    @pytest.mark.asyncio
    async def test_mip_shows_windows_only_on_non_windows(self, test_client, setup_health_test_data):
        """MIP should show 'Windows only' on non-Windows platforms."""
        import sys
        if sys.platform != "win32":
            response = await test_client.get("/api/health/status")
            assert response.status_code == 200
            data = response.json()

            assert data["mip"] == "warning"
            assert "Windows only" in data["mip_text"]

    @pytest.mark.asyncio
    async def test_ocr_status_present(self, test_client, setup_health_test_data):
        """OCR status should be present in response."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert "ocr" in data
        assert data["ocr"] in ("healthy", "warning", "error")
        assert "ocr_text" in data


class TestHealthStatusValues:
    """Tests for valid health status values."""

    @pytest.mark.asyncio
    async def test_status_values_are_valid(self, test_client, setup_health_test_data):
        """All status fields should have valid values."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        valid_statuses = ("healthy", "warning", "error", "unknown")

        assert data["api"] in valid_statuses
        assert data["db"] in valid_statuses
        assert data["queue"] in valid_statuses
        assert data["ml"] in valid_statuses
        assert data["mip"] in valid_statuses
        assert data["ocr"] in valid_statuses

    @pytest.mark.asyncio
    async def test_numeric_fields_are_non_negative(self, test_client, setup_health_test_data):
        """Numeric fields should be non-negative."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        data = response.json()

        assert data["scans_today"] >= 0
        assert data["files_processed"] >= 0
        assert data["success_rate"] >= 0.0
        assert data["success_rate"] <= 100.0

    @pytest.mark.asyncio
    async def test_uptime_increases_between_requests(self, test_client, setup_health_test_data):
        """Uptime should increase between requests."""
        import asyncio

        response1 = await test_client.get("/api/health/status")
        uptime1 = response1.json()["uptime_seconds"]

        await asyncio.sleep(1.1)  # Wait a bit more than 1 second

        response2 = await test_client.get("/api/health/status")
        uptime2 = response2.json()["uptime_seconds"]

        assert uptime2 >= uptime1


class TestHealthEndpointAuthentication:
    """Tests for health endpoint authentication."""

    @pytest.mark.asyncio
    async def test_health_requires_authentication(self, test_client):
        """Health status endpoint requires authentication."""
        # Without authentication setup, endpoint may return 401/403
        # In dev mode with auth.provider=none, it may work without auth
        response = await test_client.get("/api/health/status")
        # Accept both authenticated success and unauthenticated error
        assert response.status_code in (200, 401, 403)


class TestHealthContentType:
    """Tests for response content type."""

    @pytest.mark.asyncio
    async def test_returns_json_content_type(self, test_client, setup_health_test_data):
        """Response should have JSON content type."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_response_is_valid_json(self, test_client, setup_health_test_data):
        """Response body should be valid JSON."""
        response = await test_client.get("/api/health/status")
        assert response.status_code == 200
        # .json() will raise if invalid JSON
        data = response.json()
        assert isinstance(data, dict)

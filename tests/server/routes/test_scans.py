"""
Comprehensive tests for scan management API endpoints.

Tests focus on:
- Create scan endpoint
- List scans with filtering and pagination
- Get scan details
- Cancel scan
"""

import pytest
from datetime import datetime, timezone
from uuid import uuid4


@pytest.fixture
async def setup_scans_data(test_db):
    """Set up test data for scans endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanJob, ScanTarget

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name == "Test Tenant"))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create scan targets
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Test Scan Target",
        adapter="filesystem",
        config={"path": "/test/path"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.flush()  # Flush to ensure target exists before creating scans

    # Create scan jobs with various statuses
    scans = []

    # Pending scans
    for i in range(2):
        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            name=f"Pending Scan {i}",
            status="pending",
            created_by=user.id,
        )
        test_db.add(scan)
        scans.append(scan)

    # Running scan
    running_scan = ScanJob(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        name="Running Scan",
        status="running",
        started_at=datetime.now(timezone.utc),
        created_by=user.id,
    )
    test_db.add(running_scan)
    scans.append(running_scan)

    # Completed scans
    for i in range(3):
        scan = ScanJob(
            id=uuid4(),
            tenant_id=tenant.id,
            target_id=target.id,
            name=f"Completed Scan {i}",
            status="completed",
            files_scanned=100 + i * 10,
            files_with_pii=i,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            created_by=user.id,
        )
        test_db.add(scan)
        scans.append(scan)

    # Failed scan
    failed_scan = ScanJob(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        name="Failed Scan",
        status="failed",
        error="Test error message",
        created_by=user.id,
    )
    test_db.add(failed_scan)
    scans.append(failed_scan)

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "scans": scans,
        "running_scan": running_scan,
        "session": test_db,
    }


class TestCreateScan:
    """Tests for POST /api/scans endpoint."""

    @pytest.mark.asyncio
    async def test_creates_scan_job(self, test_client, setup_scans_data):
        """Should create a new scan job."""
        target = setup_scans_data["target"]
        response = await test_client.post(
            "/api/scans",
            json={"target_id": str(target.id), "name": "New Test Scan"},
        )
        assert response.status_code == 201
        data = response.json()

        assert data["target_id"] == str(target.id)
        assert data["status"] == "pending"

    @pytest.mark.asyncio
    async def test_returns_404_for_invalid_target(self, test_client, setup_scans_data):
        """Should return 404 for non-existent target."""
        fake_id = uuid4()
        response = await test_client.post(
            "/api/scans",
            json={"target_id": str(fake_id)},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_generates_default_name(self, test_client, setup_scans_data):
        """Should generate default name from target."""
        target = setup_scans_data["target"]
        response = await test_client.post(
            "/api/scans",
            json={"target_id": str(target.id)},
        )
        assert response.status_code == 201
        data = response.json()

        assert "name" in data
        assert data["name"] is not None


class TestListScans:
    """Tests for GET /api/scans endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_scans_data):
        """List scans should return 200 OK."""
        response = await test_client.get("/api/scans")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_paginated_response(self, test_client, setup_scans_data):
        """Response should have pagination structure."""
        response = await test_client.get("/api/scans")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "pages" in data

    @pytest.mark.asyncio
    async def test_returns_scan_list(self, test_client, setup_scans_data):
        """Should return list of scans with expected structure."""
        response = await test_client.get("/api/scans")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] >= 7, "Should return at least 7 scans from fixture"
        assert len(data["items"]) >= 1, "Should return at least one scan item"
        # Verify scan structure
        first_scan = data["items"][0]
        assert "id" in first_scan and first_scan["id"], "Scan should have non-empty id"
        assert "status" in first_scan, "Scan should have status field"

    @pytest.mark.asyncio
    async def test_filter_by_status(self, test_client, setup_scans_data):
        """Should filter scans by status."""
        response = await test_client.get("/api/scans?status=completed")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["status"] == "completed"

    @pytest.mark.asyncio
    async def test_pagination_works(self, test_client, setup_scans_data):
        """Should respect pagination parameters."""
        response = await test_client.get("/api/scans?page=1&limit=3")
        assert response.status_code == 200
        data = response.json()

        assert data["page"] == 1
        assert len(data["items"]) <= 3

    @pytest.mark.asyncio
    async def test_scan_response_structure(self, test_client, setup_scans_data):
        """Scan items should have expected fields."""
        response = await test_client.get("/api/scans")
        assert response.status_code == 200
        data = response.json()

        if data["items"]:
            item = data["items"][0]
            assert "id" in item
            assert "target_id" in item
            assert "status" in item
            assert "created_at" in item


class TestGetScan:
    """Tests for GET /api/scans/{scan_id} endpoint."""

    @pytest.mark.asyncio
    async def test_returns_scan_details(self, test_client, setup_scans_data):
        """Should return scan details."""
        scan = setup_scans_data["scans"][0]
        response = await test_client.get(f"/api/scans/{scan.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(scan.id)
        assert data["name"] == scan.name

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent(self, test_client, setup_scans_data):
        """Should return 404 for non-existent scan."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/scans/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_full_structure(self, test_client, setup_scans_data):
        """Should return all scan fields."""
        scan = setup_scans_data["scans"][0]
        response = await test_client.get(f"/api/scans/{scan.id}")
        assert response.status_code == 200
        data = response.json()

        assert "id" in data
        assert "target_id" in data
        assert "name" in data
        assert "status" in data
        assert "files_scanned" in data
        assert "files_with_pii" in data


class TestCancelScan:
    """Tests for DELETE /api/scans/{scan_id} endpoint."""

    @pytest.mark.asyncio
    async def test_cancels_pending_scan(self, test_client, setup_scans_data):
        """Should cancel a pending scan."""
        # Find a pending scan
        pending_scans = [s for s in setup_scans_data["scans"] if s.status == "pending"]
        if pending_scans:
            scan = pending_scans[0]
            response = await test_client.delete(f"/api/scans/{scan.id}")
            assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_cancels_running_scan(self, test_client, setup_scans_data):
        """Should cancel a running scan."""
        running_scan = setup_scans_data["running_scan"]
        response = await test_client.delete(f"/api/scans/{running_scan.id}")
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_returns_400_for_completed_scan(self, test_client, setup_scans_data):
        """Should return 400 for completed scan."""
        completed_scans = [s for s in setup_scans_data["scans"] if s.status == "completed"]
        if completed_scans:
            scan = completed_scans[0]
            response = await test_client.delete(f"/api/scans/{scan.id}")
            assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent(self, test_client, setup_scans_data):
        """Should return 404 for non-existent scan."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/scans/{fake_id}")
        assert response.status_code == 404


class TestScansContentType:
    """Tests for response content type."""

    @pytest.mark.asyncio
    async def test_list_returns_json(self, test_client, setup_scans_data):
        """List scans should return JSON."""
        response = await test_client.get("/api/scans")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_get_returns_json(self, test_client, setup_scans_data):
        """Get scan should return JSON."""
        scan = setup_scans_data["scans"][0]
        response = await test_client.get(f"/api/scans/{scan.id}")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

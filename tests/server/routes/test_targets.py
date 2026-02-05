"""
Comprehensive tests for scan target management API endpoints.

Tests focus on:
- List targets with filtering and pagination
- Create target
- Get target details
- Update target
- Delete target
"""

import pytest
from uuid import uuid4


@pytest.fixture
async def setup_targets_data(test_db):
    """Set up test data for targets endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanTarget

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create various scan targets
    targets = []

    # Filesystem targets
    for i in range(3):
        target = ScanTarget(
            id=uuid4(),
            tenant_id=tenant.id,
            name=f"Filesystem Target {i}",
            adapter="filesystem",
            config={"path": f"/data/path{i}"},
            enabled=True,
            created_by=user.id,
        )
        test_db.add(target)
        targets.append(target)

    # SharePoint targets
    for i in range(2):
        target = ScanTarget(
            id=uuid4(),
            tenant_id=tenant.id,
            name=f"SharePoint Target {i}",
            adapter="sharepoint",
            config={"site": f"https://example.sharepoint.com/sites/site{i}"},
            enabled=True if i == 0 else False,
            created_by=user.id,
        )
        test_db.add(target)
        targets.append(target)

    # OneDrive target
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="OneDrive Target",
        adapter="onedrive",
        config={"user_id": "user@example.com"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    targets.append(target)

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "targets": targets,
        "session": test_db,
    }


class TestListTargets:
    """Tests for GET /api/targets endpoint."""

    async def test_returns_200_status(self, test_client, setup_targets_data):
        """List targets should return 200 OK."""
        response = await test_client.get("/api/targets")
        assert response.status_code == 200

    async def test_returns_paginated_response(self, test_client, setup_targets_data):
        """Response should have pagination structure."""
        response = await test_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "total_pages" in data

    async def test_returns_targets(self, test_client, setup_targets_data):
        """Should return list of targets with expected structure."""
        response = await test_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] >= 6, "Should return at least 6 targets from fixture"
        assert len(data["items"]) >= 1, "Should return at least one target item"
        # Verify target structure
        first_target = data["items"][0]
        assert "id" in first_target and first_target["id"], "Target should have non-empty id"
        assert "adapter" in first_target, "Target should have adapter field"

    async def test_filter_by_adapter(self, test_client, setup_targets_data):
        """Should filter targets by adapter type."""
        response = await test_client.get("/api/targets?adapter=filesystem")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["adapter"] == "filesystem"

    async def test_pagination_works(self, test_client, setup_targets_data):
        """Should respect pagination parameters."""
        response = await test_client.get("/api/targets?page=1&page_size=2")
        assert response.status_code == 200
        data = response.json()

        assert data["page"] == 1
        assert data["page_size"] == 2
        assert len(data["items"]) <= 2

    async def test_target_response_structure(self, test_client, setup_targets_data):
        """Target items should have expected fields."""
        response = await test_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()

        if data["items"]:
            item = data["items"][0]
            assert "id" in item
            assert "name" in item
            assert "adapter" in item
            assert "config" in item
            assert "enabled" in item

    async def test_invalid_page_size_rejected(self, test_client, setup_targets_data):
        """Page size above 100 should be rejected."""
        response = await test_client.get("/api/targets?page_size=200")
        assert response.status_code == 422


class TestCreateTarget:
    """Tests for POST /api/targets endpoint."""

    async def test_creates_filesystem_target(self, test_client, setup_targets_data):
        """Should create a filesystem target."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "New Filesystem Target",
                "adapter": "filesystem",
                "config": {"path": "/new/path"},
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["name"] == "New Filesystem Target"
        assert data["adapter"] == "filesystem"

    async def test_creates_sharepoint_target(self, test_client, setup_targets_data):
        """Should create a SharePoint target."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "New SharePoint Target",
                "adapter": "sharepoint",
                # SharePoint config requires 'site_url' not 'site'
                "config": {"site_url": "https://example.sharepoint.com/sites/new"},
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["adapter"] == "sharepoint"

    async def test_rejects_invalid_adapter(self, test_client, setup_targets_data):
        """Should reject invalid adapter type."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Invalid Target",
                "adapter": "invalid",
                "config": {},
            },
        )
        # 422 is the correct FastAPI/Pydantic response for validation errors
        assert response.status_code == 422


class TestGetTarget:
    """Tests for GET /api/targets/{target_id} endpoint."""

    async def test_returns_target_details(self, test_client, setup_targets_data):
        """Should return target details."""
        target = setup_targets_data["targets"][0]
        response = await test_client.get(f"/api/targets/{target.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(target.id)
        assert data["name"] == target.name

    async def test_returns_404_for_nonexistent(self, test_client, setup_targets_data):
        """Should return 404 for non-existent target."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/targets/{fake_id}")
        assert response.status_code == 404

    async def test_returns_full_structure(self, test_client, setup_targets_data):
        """Should return all target fields."""
        target = setup_targets_data["targets"][0]
        response = await test_client.get(f"/api/targets/{target.id}")
        assert response.status_code == 200
        data = response.json()

        assert "id" in data
        assert "name" in data
        assert "adapter" in data
        assert "config" in data
        assert "enabled" in data


class TestUpdateTarget:
    """Tests for PUT /api/targets/{target_id} endpoint."""

    async def test_updates_target_name(self, test_client, setup_targets_data):
        """Should update target name."""
        target = setup_targets_data["targets"][0]
        response = await test_client.put(
            f"/api/targets/{target.id}",
            json={"name": "Updated Name"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "Updated Name"

    async def test_updates_target_config(self, test_client, setup_targets_data):
        """Should update target config."""
        target = setup_targets_data["targets"][0]
        new_config = {"path": "/updated/path"}
        response = await test_client.put(
            f"/api/targets/{target.id}",
            json={"config": new_config},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["config"] == new_config

    async def test_updates_target_enabled(self, test_client, setup_targets_data):
        """Should update target enabled status."""
        target = setup_targets_data["targets"][0]
        response = await test_client.put(
            f"/api/targets/{target.id}",
            json={"enabled": False},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["enabled"] is False

    async def test_returns_404_for_nonexistent(self, test_client, setup_targets_data):
        """Should return 404 for non-existent target."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/targets/{fake_id}",
            json={"name": "Updated"},
        )
        assert response.status_code == 404


class TestDeleteTarget:
    """Tests for DELETE /api/targets/{target_id} endpoint."""

    async def test_deletes_target(self, test_client, setup_targets_data):
        """Should delete a target."""
        target = setup_targets_data["targets"][-1]  # Delete last one
        response = await test_client.delete(f"/api/targets/{target.id}")
        assert response.status_code == 204

    async def test_returns_404_for_nonexistent(self, test_client, setup_targets_data):
        """Should return 404 for non-existent target."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/targets/{fake_id}")
        assert response.status_code == 404


class TestTargetsContentType:
    """Tests for response content type."""

    async def test_list_returns_json(self, test_client, setup_targets_data):
        """List targets should return JSON."""
        response = await test_client.get("/api/targets")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    async def test_get_returns_json(self, test_client, setup_targets_data):
        """Get target should return JSON."""
        target = setup_targets_data["targets"][0]
        response = await test_client.get(f"/api/targets/{target.id}")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

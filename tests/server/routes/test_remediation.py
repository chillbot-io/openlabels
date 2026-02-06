"""
Comprehensive tests for remediation API endpoints.

Tests focus on:
- Listing remediation actions with pagination
- Quarantine file action
- Lockdown file action
- Rollback action
- Remediation statistics
- Dry-run mode
- Admin authorization requirements
- Tenant isolation
- Error handling
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock


# Rate limiting is disabled globally in the test_client fixture in conftest.py


@pytest.fixture
async def setup_remediation_data(test_db):
    """Set up test data for remediation endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanTarget, ScanJob, ScanResult

    # Get the existing tenant created by test_client (name includes random suffix)
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    # Create scan target and job so we can add scan results for remediation file paths
    target = ScanTarget(
        tenant_id=tenant.id,
        name="Remediation Test Target",
        adapter="filesystem",
        config={"path": "/test"},
        enabled=True,
        created_by=admin_user.id,
    )
    test_db.add(target)
    await test_db.flush()

    job = ScanJob(
        tenant_id=tenant.id,
        target_id=target.id,
        status="completed",
    )
    test_db.add(job)
    await test_db.flush()

    # Create scan results for all file paths used in remediation tests
    test_paths = [
        "/test/sensitive.txt", "/test/record.txt", "/test/dry_run.txt",
        "/test/custom_dir.txt", "/test/default_dir.txt",
        "/test/lockdown.txt", "/test/lockdown_record.txt",
        "/test/dry_run_lockdown.txt", "/test/no_principals.txt",
        "/test/content_type.txt",
    ]
    for path in test_paths:
        scan_result = ScanResult(
            tenant_id=tenant.id,
            job_id=job.id,
            file_path=path,
            file_name=path.split("/")[-1],
            risk_score=80,
            risk_tier="HIGH",
            entity_counts={},
            total_entities=0,
        )
        test_db.add(scan_result)
        await test_db.flush()
    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "session": test_db,
    }


class TestListRemediationActions:
    """Tests for GET /api/v1/remediation endpoint."""

    async def test_returns_200_status(self, test_client, setup_remediation_data):
        """List remediation actions should return 200 OK."""
        response = await test_client.get("/api/v1/remediation")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert isinstance(data, dict), "Response should be a dictionary"
        assert "items" in data, "Response should contain 'items' field"
        assert "total" in data, "Response should contain 'total' field"
        assert isinstance(data["items"], list), "Items should be a list"

    async def test_returns_paginated_structure(self, test_client, setup_remediation_data):
        """List should return paginated structure."""
        response = await test_client.get("/api/v1/remediation")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data
        assert isinstance(data["items"], list)

    async def test_returns_empty_list_when_no_actions(self, test_client, setup_remediation_data):
        """List should return empty items when no actions exist."""
        response = await test_client.get("/api/v1/remediation")
        assert response.status_code == 200
        data = response.json()

        assert data["items"] == []
        assert data["total"] == 0

    async def test_returns_actions(self, test_client, setup_remediation_data):
        """List should return created actions."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        action = RemediationAction(
            tenant_id=tenant.id,
            action_type="quarantine",
            status="completed",
            source_path="/test/file.txt",
            dest_path="/.quarantine/file.txt",
            performed_by=admin_user.email,
        )
        session.add(action)
        await session.commit()

        response = await test_client.get("/api/v1/remediation")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 1
        assert data["items"][0]["action_type"] == "quarantine"

    async def test_action_response_structure(self, test_client, setup_remediation_data):
        """Action response should have all required fields."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        action = RemediationAction(
            tenant_id=tenant.id,
            action_type="lockdown",
            status="pending",
            source_path="/test/sensitive.xlsx",
            performed_by=admin_user.email,
        )
        session.add(action)
        await session.commit()

        response = await test_client.get("/api/v1/remediation")
        assert response.status_code == 200
        data = response.json()

        item = data["items"][0]
        assert "id" in item
        assert "action_type" in item
        assert "status" in item
        assert "source_path" in item
        assert "dest_path" in item
        assert "dry_run" in item
        assert "error" in item
        assert "created_at" in item

    async def test_filter_by_action_type(self, test_client, setup_remediation_data):
        """List should filter by action_type."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        # Add different action types (flush after each to avoid asyncpg sentinel issues)
        for action_type in ["quarantine", "lockdown", "quarantine"]:
            action = RemediationAction(
                tenant_id=tenant.id,
                action_type=action_type,
                status="completed",
                source_path=f"/test/{action_type}_file.txt",
                performed_by=admin_user.email,
            )
            session.add(action)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/remediation?action_type=quarantine")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2
        for item in data["items"]:
            assert item["action_type"] == "quarantine"

    async def test_filter_by_status(self, test_client, setup_remediation_data):
        """List should filter by status."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        # Add actions with different statuses (flush after each to avoid asyncpg sentinel issues)
        for status in ["pending", "completed", "failed", "completed"]:
            action = RemediationAction(
                tenant_id=tenant.id,
                action_type="quarantine",
                status=status,
                source_path=f"/test/{status}_file.txt",
                performed_by=admin_user.email,
            )
            session.add(action)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/remediation?status=completed")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2
        for item in data["items"]:
            assert item["status"] == "completed"

    async def test_pagination_default_limit(self, test_client, setup_remediation_data):
        """List should use default page_size of 50."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        # Add many actions (flush after each to avoid asyncpg sentinel issues)
        for i in range(60):
            action = RemediationAction(
                tenant_id=tenant.id,
                action_type="quarantine",
                status="completed",
                source_path=f"/test/file_{i}.txt",
                performed_by=admin_user.email,
            )
            session.add(action)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/remediation")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 50
        assert data["total"] == 60

    async def test_pagination_custom_limit(self, test_client, setup_remediation_data):
        """List should respect custom page_size."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        for i in range(20):
            action = RemediationAction(
                tenant_id=tenant.id,
                action_type="quarantine",
                status="completed",
                source_path=f"/test/paginated_{i}.txt",
                performed_by=admin_user.email,
            )
            session.add(action)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/remediation?page_size=5")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 5

    async def test_pagination_page_parameter(self, test_client, setup_remediation_data):
        """List should respect page parameter."""
        response = await test_client.get("/api/remediation?page=1&page_size=10")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "items" in data, "Response should contain 'items' field"
        assert "page" in data, "Response should contain 'page' field"
        assert "total_pages" in data, "Response should contain 'total_pages' field"
        assert data["page"] == 1, "Page should be 1"
        assert isinstance(data["items"], list), "Items should be a list"
        assert len(data["items"]) <= 10, "Items should respect page_size parameter"


class TestGetRemediationAction:
    """Tests for GET /api/v1/remediation/{action_id} endpoint."""

    async def test_returns_200_status(self, test_client, setup_remediation_data):
        """Get action should return 200 OK."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        action = RemediationAction(
            tenant_id=tenant.id,
            action_type="quarantine",
            status="completed",
            source_path="/test/get_file.txt",
            performed_by=admin_user.email,
        )
        session.add(action)
        await session.commit()

        response = await test_client.get(f"/api/v1/remediation/{action.id}")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "id" in data, "Response should contain 'id' field"
        assert data["id"] == str(action.id), "Response ID should match requested action"
        assert data["action_type"] == "quarantine", "Action type should be quarantine"
        assert data["status"] == "completed", "Status should be completed"
        assert data["source_path"] == "/test/get_file.txt", "Source path should match"

    async def test_returns_action_details(self, test_client, setup_remediation_data):
        """Get action should return action details."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        action = RemediationAction(
            tenant_id=tenant.id,
            action_type="lockdown",
            status="pending",
            source_path="/test/details.xlsx",
            performed_by=admin_user.email,
        )
        session.add(action)
        await session.commit()

        response = await test_client.get(f"/api/v1/remediation/{action.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(action.id)
        assert data["action_type"] == "lockdown"
        assert data["source_path"] == "/test/details.xlsx"

    async def test_returns_404_for_nonexistent_action(self, test_client, setup_remediation_data):
        """Get nonexistent action should return 404."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/remediation/{fake_id}")
        assert response.status_code == 404


class TestQuarantineFile:
    """Tests for POST /api/v1/remediation/quarantine endpoint."""

    async def test_returns_200_status(self, test_client, setup_remediation_data):
        """Quarantine action should return 200 OK."""
        response = await test_client.post(
            "/api/v1/remediation/quarantine",
            json={
                "file_path": "/test/sensitive.txt",
                "dry_run": True,
            },
        )
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "id" in data, "Response should contain 'id' field"
        assert data["action_type"] == "quarantine", "Action type should be quarantine"
        assert data["source_path"] == "/test/sensitive.txt", "Source path should match request"
        assert data["dry_run"] is True, "Dry run should be True"
        assert data["status"] in ("pending", "completed"), "Status should be valid"

    async def test_creates_action_record(self, test_client, setup_remediation_data):
        """Quarantine should create an action record."""
        response = await test_client.post(
            "/api/v1/remediation/quarantine",
            json={
                "file_path": "/test/record.txt",
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert "id" in data
        assert data["action_type"] == "quarantine"
        assert data["source_path"] == "/test/record.txt"
        assert data["dry_run"] is True

    async def test_dry_run_does_not_move_file(self, test_client, setup_remediation_data):
        """Dry run should not actually move the file."""
        response = await test_client.post(
            "/api/v1/remediation/quarantine",
            json={
                "file_path": "/test/dry_run.txt",
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()

        # Status should still be pending for dry run
        assert data["status"] == "pending"
        assert data["dry_run"] is True

    async def test_custom_quarantine_dir(self, test_client, setup_remediation_data):
        """Quarantine should respect custom quarantine directory."""
        response = await test_client.post(
            "/api/v1/remediation/quarantine",
            json={
                "file_path": "/test/custom_dir.txt",
                "quarantine_dir": "/secure/vault",
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert "/secure/vault" in data["dest_path"]

    async def test_default_quarantine_dir(self, test_client, setup_remediation_data):
        """Quarantine should use .quarantine as default directory."""
        response = await test_client.post(
            "/api/v1/remediation/quarantine",
            json={
                "file_path": "/test/default_dir.txt",
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert ".quarantine" in data["dest_path"]

    async def test_missing_file_path_returns_422(self, test_client, setup_remediation_data):
        """Quarantine without file_path should return 422."""
        response = await test_client.post(
            "/api/v1/remediation/quarantine",
            json={
                "dry_run": True,
            },
        )
        assert response.status_code == 422


class TestLockdownFile:
    """Tests for POST /api/v1/remediation/lockdown endpoint."""

    async def test_returns_200_status(self, test_client, setup_remediation_data):
        """Lockdown action should return 200 OK."""
        response = await test_client.post(
            "/api/v1/remediation/lockdown",
            json={
                "file_path": "/test/lockdown.txt",
                "allowed_principals": ["DOMAIN\\Admin"],
                "dry_run": True,
            },
        )
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "id" in data, "Response should contain 'id' field"
        assert data["action_type"] == "lockdown", "Action type should be lockdown"
        assert data["source_path"] == "/test/lockdown.txt", "Source path should match request"
        assert data["dry_run"] is True, "Dry run should be True"
        assert data["status"] in ("pending", "completed"), "Status should be valid"

    async def test_creates_action_record(self, test_client, setup_remediation_data):
        """Lockdown should create an action record."""
        response = await test_client.post(
            "/api/v1/remediation/lockdown",
            json={
                "file_path": "/test/lockdown_record.txt",
                "allowed_principals": ["DOMAIN\\SecurityGroup"],
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert "id" in data
        assert data["action_type"] == "lockdown"
        assert data["source_path"] == "/test/lockdown_record.txt"

    async def test_dry_run_does_not_change_permissions(self, test_client, setup_remediation_data):
        """Dry run should not actually change permissions."""
        response = await test_client.post(
            "/api/v1/remediation/lockdown",
            json={
                "file_path": "/test/dry_run_lockdown.txt",
                "allowed_principals": ["DOMAIN\\Admin"],
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "pending"
        assert data["dry_run"] is True

    async def test_missing_file_path_returns_422(self, test_client, setup_remediation_data):
        """Lockdown without file_path should return 422."""
        response = await test_client.post(
            "/api/v1/remediation/lockdown",
            json={
                "allowed_principals": ["DOMAIN\\Admin"],
                "dry_run": True,
            },
        )
        assert response.status_code == 422

    async def test_missing_allowed_principals_returns_422(self, test_client, setup_remediation_data):
        """Lockdown without allowed_principals should return 422."""
        response = await test_client.post(
            "/api/v1/remediation/lockdown",
            json={
                "file_path": "/test/no_principals.txt",
                "dry_run": True,
            },
        )
        assert response.status_code == 422


class TestRollbackAction:
    """Tests for POST /api/v1/remediation/rollback endpoint."""

    async def test_returns_200_status_for_dry_run(self, test_client, setup_remediation_data):
        """Rollback dry run should return 200 OK."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        # Create a completed quarantine action to rollback
        original = RemediationAction(
            tenant_id=tenant.id,
            action_type="quarantine",
            status="completed",
            source_path="/test/original.txt",
            dest_path="/.quarantine/original.txt",
            performed_by=admin_user.email,
            dry_run=False,
        )
        session.add(original)
        await session.commit()

        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": str(original.id),
                "dry_run": True,
            },
        )
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "id" in data, "Response should contain 'id' field"
        assert data["action_type"] == "rollback", "Action type should be rollback"
        assert data["dry_run"] is True, "Dry run should be True"
        assert data["status"] in ("pending", "completed"), "Status should be valid"
        assert "source_path" in data, "Response should contain 'source_path' field"

    async def test_creates_rollback_action_record(self, test_client, setup_remediation_data):
        """Rollback should create an action record."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        original = RemediationAction(
            tenant_id=tenant.id,
            action_type="quarantine",
            status="completed",
            source_path="/test/rollback_record.txt",
            dest_path="/.quarantine/rollback_record.txt",
            performed_by=admin_user.email,
            dry_run=False,
        )
        session.add(original)
        await session.commit()

        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": str(original.id),
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["action_type"] == "rollback"

    async def test_returns_404_for_nonexistent_action(self, test_client, setup_remediation_data):
        """Rollback nonexistent action should return 404."""
        fake_id = uuid4()
        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": str(fake_id),
                "dry_run": True,
            },
        )
        assert response.status_code == 404

    async def test_cannot_rollback_already_rolled_back_action(
        self, test_client, setup_remediation_data
    ):
        """Cannot rollback an action that was already rolled back."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        original = RemediationAction(
            tenant_id=tenant.id,
            action_type="quarantine",
            status="rolled_back",  # Already rolled back
            source_path="/test/already_rolled.txt",
            dest_path="/.quarantine/already_rolled.txt",
            performed_by=admin_user.email,
            dry_run=False,
        )
        session.add(original)
        await session.commit()

        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": str(original.id),
                "dry_run": True,
            },
        )
        assert response.status_code == 400

    async def test_cannot_rollback_a_rollback_action(self, test_client, setup_remediation_data):
        """Cannot rollback a rollback action."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        rollback_action = RemediationAction(
            tenant_id=tenant.id,
            action_type="rollback",  # This is a rollback action
            status="completed",
            source_path="/test/rollback_action.txt",
            performed_by=admin_user.email,
            dry_run=False,
        )
        session.add(rollback_action)
        await session.commit()

        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": str(rollback_action.id),
                "dry_run": True,
            },
        )
        assert response.status_code == 400

    async def test_cannot_rollback_dry_run_action(self, test_client, setup_remediation_data):
        """Cannot rollback a dry-run action (nothing was executed)."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        dry_run_action = RemediationAction(
            tenant_id=tenant.id,
            action_type="quarantine",
            status="pending",
            source_path="/test/dry_run_only.txt",
            dest_path="/.quarantine/dry_run_only.txt",
            performed_by=admin_user.email,
            dry_run=True,  # This was a dry run
        )
        session.add(dry_run_action)
        await session.commit()

        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": str(dry_run_action.id),
                "dry_run": False,
            },
        )
        assert response.status_code == 400


class TestRemediationStats:
    """Tests for GET /api/v1/remediation/stats/summary endpoint."""

    async def test_returns_200_status(self, test_client, setup_remediation_data):
        """Stats endpoint should return 200 OK."""
        response = await test_client.get("/api/v1/remediation/stats/summary")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "total_actions" in data, "Response should contain 'total_actions' field"
        assert "by_type" in data, "Response should contain 'by_type' field"
        assert "by_status" in data, "Response should contain 'by_status' field"
        assert isinstance(data["total_actions"], int), "total_actions should be an integer"
        assert isinstance(data["by_type"], dict), "by_type should be a dictionary"
        assert isinstance(data["by_status"], dict), "by_status should be a dictionary"

    async def test_returns_stats_structure(self, test_client, setup_remediation_data):
        """Stats should return required structure."""
        response = await test_client.get("/api/v1/remediation/stats/summary")
        assert response.status_code == 200
        data = response.json()

        assert "total_actions" in data
        assert "by_type" in data
        assert "by_status" in data

    async def test_returns_zero_values_when_empty(self, test_client, setup_remediation_data):
        """Stats should return zeros when no actions exist."""
        response = await test_client.get("/api/v1/remediation/stats/summary")
        assert response.status_code == 200
        data = response.json()

        assert data["total_actions"] == 0
        assert data["by_type"]["quarantine"] == 0
        assert data["by_type"]["lockdown"] == 0
        assert data["by_type"]["rollback"] == 0

    async def test_counts_by_type(self, test_client, setup_remediation_data):
        """Stats should count actions by type."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        # Add actions of different types (flush after each to avoid asyncpg sentinel issues)
        for action_type, count in [("quarantine", 3), ("lockdown", 2), ("rollback", 1)]:
            for i in range(count):
                action = RemediationAction(
                    tenant_id=tenant.id,
                    action_type=action_type,
                    status="completed",
                    source_path=f"/test/{action_type}_{i}.txt",
                    performed_by=admin_user.email,
                )
                session.add(action)
                await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/remediation/stats/summary")
        assert response.status_code == 200
        data = response.json()

        assert data["total_actions"] == 6
        assert data["by_type"]["quarantine"] == 3
        assert data["by_type"]["lockdown"] == 2
        assert data["by_type"]["rollback"] == 1

    async def test_counts_by_status(self, test_client, setup_remediation_data):
        """Stats should count actions by status."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        # Add actions with different statuses (flush after each to avoid asyncpg sentinel issues)
        for status, count in [("completed", 4), ("failed", 2), ("pending", 1)]:
            for i in range(count):
                action = RemediationAction(
                    tenant_id=tenant.id,
                    action_type="quarantine",
                    status=status,
                    source_path=f"/test/{status}_{i}.txt",
                    performed_by=admin_user.email,
                )
                session.add(action)
                await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/remediation/stats/summary")
        assert response.status_code == 200
        data = response.json()

        assert data["by_status"]["completed"] == 4
        assert data["by_status"]["failed"] == 2
        assert data["by_status"]["pending"] == 1


class TestRemediationTenantIsolation:
    """Tests for tenant isolation in remediation endpoints."""

    async def test_cannot_access_other_tenant_action(self, test_client, setup_remediation_data):
        """Should not be able to access actions from other tenants."""
        from openlabels.server.models import Tenant, User, RemediationAction

        session = setup_remediation_data["session"]

        # Create another tenant and action
        other_tenant = Tenant(
            name="Other Remediation Tenant",
            azure_tenant_id="other-remediation-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="other-remediation@other.com",
            name="Other User",
            role="admin",
        )
        session.add(other_user)
        await session.flush()

        other_action = RemediationAction(
            tenant_id=other_tenant.id,
            action_type="quarantine",
            status="completed",
            source_path="/other/file.txt",
            performed_by=other_user.email,
        )
        session.add(other_action)
        await session.commit()

        # Try to access the other tenant's action
        response = await test_client.get(f"/api/v1/remediation/{other_action.id}")
        assert response.status_code == 404

    async def test_cannot_rollback_other_tenant_action(self, test_client, setup_remediation_data):
        """Should not be able to rollback actions from other tenants."""
        from openlabels.server.models import Tenant, User, RemediationAction

        session = setup_remediation_data["session"]

        other_tenant = Tenant(
            name="Other Rollback Tenant",
            azure_tenant_id="other-rollback-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="other-rollback@other.com",
            name="Other User",
            role="admin",
        )
        session.add(other_user)
        await session.flush()

        other_action = RemediationAction(
            tenant_id=other_tenant.id,
            action_type="quarantine",
            status="completed",
            source_path="/other/rollback.txt",
            dest_path="/.quarantine/rollback.txt",
            performed_by=other_user.email,
            dry_run=False,
        )
        session.add(other_action)
        await session.commit()

        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": str(other_action.id),
                "dry_run": True,
            },
        )
        assert response.status_code == 404


class TestRemediationContentType:
    """Tests for response content type."""

    async def test_list_returns_json(self, test_client, setup_remediation_data):
        """List remediation should return JSON."""
        response = await test_client.get("/api/v1/remediation")
        assert "application/json" in response.headers.get("content-type", "")

    async def test_quarantine_returns_json(self, test_client, setup_remediation_data):
        """Quarantine should return JSON."""
        response = await test_client.post(
            "/api/v1/remediation/quarantine",
            json={
                "file_path": "/test/content_type.txt",
                "dry_run": True,
            },
        )
        assert "application/json" in response.headers.get("content-type", "")

    async def test_stats_returns_json(self, test_client, setup_remediation_data):
        """Stats should return JSON."""
        response = await test_client.get("/api/v1/remediation/stats/summary")
        assert "application/json" in response.headers.get("content-type", "")

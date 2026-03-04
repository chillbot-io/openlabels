"""
Comprehensive tests for remediation API endpoints.

Tests focus on:
- Listing remediation actions with pagination and search
- Quarantine file action
- Lockdown file action
- Label apply action
- Rollback action (including label rollback)
- Bulk remediation
- Remediation statistics (PostgreSQL fallback)
- Dry-run mode
- Admin authorization requirements
- Tenant isolation
- Error handling
"""

from uuid import uuid4

import pytest

# Rate limiting is disabled globally in the test_client fixture in conftest.py


@pytest.fixture
async def setup_remediation_data(test_db):
    """Set up test data for remediation endpoint tests."""
    from sqlalchemy import select

    from openlabels.server.models import (
        ScanJob,
        ScanResult,
        ScanTarget,
        SensitivityLabel,
        Tenant,
        User,
    )

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
        # Additional paths for label and bulk tests
        "/test/label_target.txt", "/test/label_dry_run.txt",
        "/test/bulk_file_1.txt", "/test/bulk_file_2.txt", "/test/bulk_file_3.txt",
        "/data/finance/report.xlsx", "/data/hr/employees.csv",
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

    # Create sensitivity labels for label-apply tests
    label = SensitivityLabel(
        id="label-confidential-001",
        tenant_id=tenant.id,
        name="Confidential",
        description="Confidential data",
        priority=1,
    )
    test_db.add(label)
    await test_db.flush()

    label2 = SensitivityLabel(
        id="label-internal-002",
        tenant_id=tenant.id,
        name="Internal",
        description="Internal data",
        priority=2,
    )
    test_db.add(label2)
    await test_db.flush()

    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "session": test_db,
        "label": label,
        "label2": label2,
    }


class TestListRemediationActions:
    """Tests for GET /api/v1/remediation endpoint."""

    async def test_returns_paginated_structure(self, test_client, setup_remediation_data):
        """List should return paginated structure with correct defaults."""
        response = await test_client.get("/api/v1/remediation")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data
        assert data["page"] == 1
        assert data["total"] >= 0

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
        """Action response should have all required fields including new ones."""
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
        assert "performed_by" in item
        assert "dry_run" in item
        assert "error" in item
        assert "created_at" in item
        assert "completed_at" in item
        assert "rollback_of_id" in item
        assert "label_id" in item
        assert "label_name" in item

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

    async def test_search_by_file_path(self, test_client, setup_remediation_data):
        """List should filter by file path search."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        for path in ["/data/finance/report.xlsx", "/data/hr/employees.csv", "/test/random.txt"]:
            action = RemediationAction(
                tenant_id=tenant.id,
                action_type="quarantine",
                status="completed",
                source_path=path,
                performed_by=admin_user.email,
            )
            session.add(action)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/remediation?search=finance")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 1
        assert "finance" in data["items"][0]["source_path"]

    async def test_search_is_case_insensitive(self, test_client, setup_remediation_data):
        """Search should be case-insensitive."""
        from openlabels.server.models import RemediationAction

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        admin_user = setup_remediation_data["admin_user"]

        action = RemediationAction(
            tenant_id=tenant.id,
            action_type="quarantine",
            status="completed",
            source_path="/data/Finance/Report.xlsx",
            performed_by=admin_user.email,
        )
        session.add(action)
        await session.commit()

        response = await test_client.get("/api/v1/remediation?search=FINANCE")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 1

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

        response = await test_client.get("/api/v1/remediation?page_size=5")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 5

    async def test_pagination_page_parameter(self, test_client, setup_remediation_data):
        """List should respect page parameter."""
        response = await test_client.get("/api/v1/remediation?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert "total_pages" in data
        assert len(data["items"]) <= 10


class TestGetRemediationAction:
    """Tests for GET /api/v1/remediation/{action_id} endpoint."""

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


class TestLabelApply:
    """Tests for POST /api/v1/remediation/label-apply endpoint."""

    async def test_dry_run_returns_200(self, test_client, setup_remediation_data):
        """Label apply dry run should return 200."""
        label = setup_remediation_data["label"]
        response = await test_client.post(
            "/api/v1/remediation/label-apply",
            json={
                "file_path": "/test/label_target.txt",
                "label_id": label.id,
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["action_type"] == "label_apply"
        assert data["status"] == "pending"
        assert data["dry_run"] is True
        assert data["label_id"] == label.id
        assert data["label_name"] == "Confidential"

    async def test_applies_label_to_scan_result(self, test_client, setup_remediation_data):
        """Label apply should update scan result with label info."""
        from sqlalchemy import select

        from openlabels.server.models import ScanResult

        label = setup_remediation_data["label"]
        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]

        response = await test_client.post(
            "/api/v1/remediation/label-apply",
            json={
                "file_path": "/test/label_target.txt",
                "label_id": label.id,
                "dry_run": False,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["completed_at"] is not None

        # Verify the scan result was updated
        result = await session.execute(
            select(ScanResult).where(
                ScanResult.file_path == "/test/label_target.txt",
                ScanResult.tenant_id == tenant.id,
            ).limit(1)
        )
        scan_result = result.scalar_one()
        assert scan_result.current_label_id == label.id
        assert scan_result.current_label_name == "Confidential"
        assert scan_result.label_applied is True

    async def test_dry_run_does_not_update_scan_result(self, test_client, setup_remediation_data):
        """Dry run should not update the scan result."""
        from sqlalchemy import select

        from openlabels.server.models import ScanResult

        label = setup_remediation_data["label"]
        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]

        response = await test_client.post(
            "/api/v1/remediation/label-apply",
            json={
                "file_path": "/test/label_dry_run.txt",
                "label_id": label.id,
                "dry_run": True,
            },
        )
        assert response.status_code == 200

        # Verify the scan result was NOT updated
        result = await session.execute(
            select(ScanResult).where(
                ScanResult.file_path == "/test/label_dry_run.txt",
                ScanResult.tenant_id == tenant.id,
            ).limit(1)
        )
        scan_result = result.scalar_one()
        assert scan_result.label_applied is False

    async def test_returns_404_for_nonexistent_file(self, test_client, setup_remediation_data):
        """Label apply on nonexistent file should return 404."""
        label = setup_remediation_data["label"]
        response = await test_client.post(
            "/api/v1/remediation/label-apply",
            json={
                "file_path": "/nonexistent/file.txt",
                "label_id": label.id,
                "dry_run": True,
            },
        )
        assert response.status_code == 404

    async def test_returns_404_for_nonexistent_label(self, test_client, setup_remediation_data):
        """Label apply with nonexistent label should return 404."""
        response = await test_client.post(
            "/api/v1/remediation/label-apply",
            json={
                "file_path": "/test/label_target.txt",
                "label_id": "nonexistent-label-id",
                "dry_run": True,
            },
        )
        assert response.status_code == 404

    async def test_missing_label_id_returns_422(self, test_client, setup_remediation_data):
        """Label apply without label_id should return 422."""
        response = await test_client.post(
            "/api/v1/remediation/label-apply",
            json={
                "file_path": "/test/label_target.txt",
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

    async def test_rollback_label_apply_clears_label(self, test_client, setup_remediation_data):
        """Rolling back a label_apply should clear the label from the scan result."""
        from sqlalchemy import select

        from openlabels.server.models import ScanResult

        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]
        setup_remediation_data["admin_user"]
        label = setup_remediation_data["label"]

        # First apply a label
        response = await test_client.post(
            "/api/v1/remediation/label-apply",
            json={
                "file_path": "/test/label_target.txt",
                "label_id": label.id,
                "dry_run": False,
            },
        )
        assert response.status_code == 200
        action_id = response.json()["id"]

        # Now rollback the label application
        response = await test_client.post(
            "/api/v1/remediation/rollback",
            json={
                "action_id": action_id,
                "dry_run": False,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"

        # Verify the scan result label was cleared
        result = await session.execute(
            select(ScanResult).where(
                ScanResult.file_path == "/test/label_target.txt",
                ScanResult.tenant_id == tenant.id,
            ).limit(1)
        )
        scan_result = result.scalar_one()
        assert scan_result.label_applied is False
        assert scan_result.current_label_id is None

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


class TestBulkRemediation:
    """Tests for POST /api/v1/remediation/bulk endpoint."""

    async def test_bulk_quarantine_dry_run(self, test_client, setup_remediation_data):
        """Bulk quarantine dry run should process all files."""
        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "quarantine",
                "items": [
                    {"file_path": "/test/bulk_file_1.txt"},
                    {"file_path": "/test/bulk_file_2.txt"},
                    {"file_path": "/test/bulk_file_3.txt"},
                ],
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert data["success"] == 3
        assert data["failed"] == 0
        assert len(data["actions"]) == 3
        for action in data["actions"]:
            assert action["action_type"] == "quarantine"
            assert action["dry_run"] is True

    async def test_bulk_label_apply_dry_run(self, test_client, setup_remediation_data):
        """Bulk label apply dry run should process all files."""
        label = setup_remediation_data["label"]
        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "label_apply",
                "items": [
                    {"file_path": "/test/bulk_file_1.txt"},
                    {"file_path": "/test/bulk_file_2.txt"},
                ],
                "label_id": label.id,
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert data["success"] == 2
        assert data["failed"] == 0
        for action in data["actions"]:
            assert action["label_id"] == label.id
            assert action["label_name"] == "Confidential"

    async def test_bulk_label_apply_updates_scan_results(self, test_client, setup_remediation_data):
        """Bulk label apply should update scan results when not dry run."""
        from sqlalchemy import select

        from openlabels.server.models import ScanResult

        label = setup_remediation_data["label"]
        session = setup_remediation_data["session"]
        tenant = setup_remediation_data["tenant"]

        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "label_apply",
                "items": [
                    {"file_path": "/test/bulk_file_1.txt"},
                    {"file_path": "/test/bulk_file_2.txt"},
                ],
                "label_id": label.id,
                "dry_run": False,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] == 2

        # Verify scan results were updated
        for path in ["/test/bulk_file_1.txt", "/test/bulk_file_2.txt"]:
            result = await session.execute(
                select(ScanResult).where(
                    ScanResult.file_path == path,
                    ScanResult.tenant_id == tenant.id,
                ).limit(1)
            )
            sr = result.scalar_one()
            assert sr.label_applied is True
            assert sr.current_label_id == label.id

    async def test_bulk_lockdown_requires_principals(self, test_client, setup_remediation_data):
        """Bulk lockdown without principals should return 400."""
        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "lockdown",
                "items": [{"file_path": "/test/bulk_file_1.txt"}],
                "dry_run": True,
            },
        )
        assert response.status_code == 400

    async def test_bulk_label_apply_requires_label_id(self, test_client, setup_remediation_data):
        """Bulk label_apply without label_id should return 400."""
        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "label_apply",
                "items": [{"file_path": "/test/bulk_file_1.txt"}],
                "dry_run": True,
            },
        )
        assert response.status_code == 400

    async def test_bulk_invalid_action_type_returns_400(self, test_client, setup_remediation_data):
        """Bulk with invalid action_type should return 400."""
        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "invalid",
                "items": [{"file_path": "/test/bulk_file_1.txt"}],
                "dry_run": True,
            },
        )
        assert response.status_code == 400

    async def test_bulk_handles_missing_files(self, test_client, setup_remediation_data):
        """Bulk should count missing files as failures."""
        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "quarantine",
                "items": [
                    {"file_path": "/test/bulk_file_1.txt"},
                    {"file_path": "/nonexistent/file.txt"},
                ],
                "dry_run": True,
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert data["success"] == 1
        assert data["failed"] == 1

    async def test_bulk_empty_items_returns_422(self, test_client, setup_remediation_data):
        """Bulk with empty items list should return 422."""
        response = await test_client.post(
            "/api/v1/remediation/bulk",
            json={
                "action_type": "quarantine",
                "items": [],
                "dry_run": True,
            },
        )
        assert response.status_code == 422


class TestRemediationStats:
    """Tests for GET /api/v1/remediation/stats/summary endpoint."""

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

    async def test_includes_label_apply_type(self, test_client, setup_remediation_data):
        """Stats should include label_apply type in by_type."""
        response = await test_client.get("/api/v1/remediation/stats/summary")
        assert response.status_code == 200
        data = response.json()

        assert "label_apply" in data["by_type"]


class TestRemediationTenantIsolation:
    """Tests for tenant isolation in remediation endpoints."""

    async def test_cannot_access_other_tenant_action(self, test_client, setup_remediation_data):
        """Should not be able to access actions from other tenants."""
        from openlabels.server.models import RemediationAction, Tenant, User

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
        from openlabels.server.models import RemediationAction, Tenant, User

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

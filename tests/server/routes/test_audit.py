"""
Comprehensive tests for audit API endpoints.

Tests focus on:
- Audit log listing with pagination
- Filtering by action, resource type, user, dates
- Available filter options endpoint
- Single audit log retrieval
- Resource history endpoint
- Admin access requirements
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4


@pytest.fixture
async def setup_audit_data(test_db):
    """Set up test data for audit endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, AuditLog

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create various audit logs using valid enum values:
    # scan_started, scan_completed, scan_failed, scan_cancelled
    # label_applied, label_removed, label_sync
    # target_created, target_updated, target_deleted
    # user_created, user_updated, user_deleted
    # schedule_created, schedule_updated, schedule_deleted
    # quarantine_executed, lockdown_executed, rollback_executed
    # monitoring_enabled, monitoring_disabled

    audit_logs = []

    # Scan-related logs
    scan_resource_id = uuid4()
    for action in ["scan_started", "scan_completed", "scan_failed"]:
        log = AuditLog(
            id=uuid4(),
            tenant_id=tenant.id,
            user_id=user.id,
            action=action,
            resource_type="scan",
            resource_id=scan_resource_id,
            details={"scan_name": "Test Scan"},
        )
        test_db.add(log)
        audit_logs.append(log)

    # Target-related logs
    target_resource_id = uuid4()
    for action in ["target_created", "target_updated", "target_deleted"]:
        log = AuditLog(
            id=uuid4(),
            tenant_id=tenant.id,
            user_id=user.id,
            action=action,
            resource_type="target",
            resource_id=target_resource_id,
            details={"target_name": "Test Target"},
        )
        test_db.add(log)
        audit_logs.append(log)

    # User-related logs
    log = AuditLog(
        id=uuid4(),
        tenant_id=tenant.id,
        user_id=user.id,
        action="user_created",
        resource_type="user",
        resource_id=user.id,
        details={"email": "test@example.com"},
    )
    test_db.add(log)
    audit_logs.append(log)

    # Label-related log
    log = AuditLog(
        id=uuid4(),
        tenant_id=tenant.id,
        user_id=user.id,
        action="label_applied",
        resource_type="file",
        resource_id=uuid4(),
        details={"label": "Confidential"},
    )
    test_db.add(log)
    audit_logs.append(log)

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "audit_logs": audit_logs,
        "scan_resource_id": scan_resource_id,
        "target_resource_id": target_resource_id,
        "session": test_db,
    }


class TestListAuditLogs:
    """Tests for GET /api/audit endpoint."""

    async def test_returns_200_status(self, test_client, setup_audit_data):
        """Audit listing should return 200 OK."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200

    async def test_returns_paginated_response(self, test_client, setup_audit_data):
        """Response should have pagination structure."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "total_pages" in data

    async def test_returns_audit_logs(self, test_client, setup_audit_data):
        """Should return audit log items with expected fields."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] >= 8, "Should return at least 8 logs from fixture"
        assert len(data["items"]) >= 1, "Should return at least one audit item"
        # Verify item structure
        first_item = data["items"][0]
        assert "id" in first_item and first_item["id"], "Item should have non-empty id"
        assert "action" in first_item, "Item should have action field"

    async def test_audit_log_structure(self, test_client, setup_audit_data):
        """Audit log items should have expected structure."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()

        item = data["items"][0]
        assert "id" in item
        assert "action" in item
        assert "created_at" in item

    async def test_filter_by_action(self, test_client, setup_audit_data):
        """Should filter by action type."""
        response = await test_client.get("/api/audit?action=scan_started")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["action"] == "scan_started"

    async def test_filter_by_resource_type(self, test_client, setup_audit_data):
        """Should filter by resource type."""
        response = await test_client.get("/api/audit?resource_type=scan")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["resource_type"] == "scan"

    async def test_filter_by_resource_id(self, test_client, setup_audit_data):
        """Should filter by resource ID."""
        resource_id = setup_audit_data["scan_resource_id"]
        response = await test_client.get(f"/api/audit?resource_id={resource_id}")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["resource_id"] == str(resource_id)

    async def test_filter_by_user_id(self, test_client, setup_audit_data):
        """Should filter by user ID."""
        user_id = setup_audit_data["user"].id
        response = await test_client.get(f"/api/audit?user_id={user_id}")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            if item["user_id"]:
                assert item["user_id"] == str(user_id)

    async def test_pagination_works(self, test_client, setup_audit_data):
        """Should return correct page of results."""
        response = await test_client.get("/api/audit?page=1&page_size=2")
        assert response.status_code == 200
        data = response.json()

        assert data["page"] == 1
        assert data["page_size"] == 2
        assert len(data["items"]) <= 2

    async def test_pagination_second_page(self, test_client, setup_audit_data):
        """Should return different results on second page."""
        response1 = await test_client.get("/api/audit?page=1&page_size=3")
        response2 = await test_client.get("/api/audit?page=2&page_size=3")

        data1 = response1.json()
        data2 = response2.json()

        # If there are enough items, pages should be different
        if data1["total"] > 3:
            ids1 = {item["id"] for item in data1["items"]}
            ids2 = {item["id"] for item in data2["items"]}
            assert ids1 != ids2

    async def test_results_ordered_newest_first(self, test_client, setup_audit_data):
        """Results should be ordered by created_at descending."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()

        items = data["items"]
        if len(items) >= 2:
            dates = [datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
                     for item in items]
            # Check dates are in descending order
            for i in range(len(dates) - 1):
                assert dates[i] >= dates[i + 1]

    async def test_invalid_page_size_rejected(self, test_client, setup_audit_data):
        """Page size above 100 should be rejected."""
        response = await test_client.get("/api/audit?page_size=200")
        assert response.status_code == 422

    async def test_invalid_page_rejected(self, test_client, setup_audit_data):
        """Page 0 or negative should be rejected."""
        response = await test_client.get("/api/audit?page=0")
        assert response.status_code == 422


class TestGetAuditFilters:
    """Tests for GET /api/audit/filters endpoint."""

    async def test_returns_200_status(self, test_client, setup_audit_data):
        """Filters endpoint should return 200 OK."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200

    async def test_returns_filter_structure(self, test_client, setup_audit_data):
        """Response should have actions and resource_types."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200
        data = response.json()

        assert "actions" in data
        assert "resource_types" in data
        assert isinstance(data["actions"], list)
        assert isinstance(data["resource_types"], list)

    async def test_returns_available_actions(self, test_client, setup_audit_data):
        """Should return distinct actions from audit logs."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200
        data = response.json()

        # Should contain at least some of the actions from fixtures
        assert "scan_started" in data["actions"]
        assert "target_created" in data["actions"]

    async def test_returns_available_resource_types(self, test_client, setup_audit_data):
        """Should return distinct resource types from audit logs."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200
        data = response.json()

        # Should contain at least some resource types from fixtures
        assert "scan" in data["resource_types"]
        assert "target" in data["resource_types"]

    async def test_actions_are_sorted(self, test_client, setup_audit_data):
        """Actions should be sorted alphabetically."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200
        data = response.json()

        actions = data["actions"]
        assert actions == sorted(actions)

    async def test_resource_types_are_sorted(self, test_client, setup_audit_data):
        """Resource types should be sorted alphabetically."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200
        data = response.json()

        types = data["resource_types"]
        assert types == sorted(types)


class TestGetAuditLog:
    """Tests for GET /api/audit/{log_id} endpoint."""

    async def test_returns_audit_log(self, test_client, setup_audit_data):
        """Should return specific audit log."""
        log = setup_audit_data["audit_logs"][0]
        response = await test_client.get(f"/api/audit/{log.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(log.id)
        assert data["action"] == log.action

    async def test_returns_404_for_nonexistent(self, test_client, setup_audit_data):
        """Should return 404 for non-existent log."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/audit/{fake_id}")
        assert response.status_code == 404

    async def test_returns_full_details(self, test_client, setup_audit_data):
        """Should return all audit log fields."""
        log = setup_audit_data["audit_logs"][0]
        response = await test_client.get(f"/api/audit/{log.id}")
        assert response.status_code == 200
        data = response.json()

        assert "id" in data
        assert "user_id" in data
        assert "action" in data
        assert "resource_type" in data
        assert "resource_id" in data
        assert "details" in data
        assert "created_at" in data


class TestGetResourceHistory:
    """Tests for GET /api/audit/resource/{resource_type}/{resource_id} endpoint."""

    async def test_returns_resource_history(self, test_client, setup_audit_data):
        """Should return history for specific resource."""
        resource_id = setup_audit_data["scan_resource_id"]
        response = await test_client.get(f"/api/audit/resource/scan/{resource_id}")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert len(data["items"]) >= 3  # scan_started, scan_completed, scan_failed

    async def test_all_entries_match_resource(self, test_client, setup_audit_data):
        """All returned entries should match the resource."""
        resource_id = setup_audit_data["scan_resource_id"]
        response = await test_client.get(f"/api/audit/resource/scan/{resource_id}")
        assert response.status_code == 200
        data = response.json()

        for item in data["items"]:
            assert item["resource_type"] == "scan"
            assert item["resource_id"] == str(resource_id)

    async def test_returns_empty_for_unknown_resource(self, test_client, setup_audit_data):
        """Should return empty list for unknown resource."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/audit/resource/scan/{fake_id}")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert len(data["items"]) == 0

    @pytest.mark.asyncio
    async def test_respects_page_size_parameter(self, test_client, setup_audit_data):
        """Should respect the page_size parameter."""
        resource_id = setup_audit_data["scan_resource_id"]
        response = await test_client.get(
            f"/api/audit/resource/scan/{resource_id}?page_size=1"
        )
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) <= 1

    async def test_results_ordered_newest_first(self, test_client, setup_audit_data):
        """Results should be ordered by created_at descending."""
        resource_id = setup_audit_data["scan_resource_id"]
        response = await test_client.get(f"/api/audit/resource/scan/{resource_id}")
        assert response.status_code == 200
        data = response.json()
        items = data["items"]

        if len(items) >= 2:
            dates = [datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
                     for item in items]
            for i in range(len(dates) - 1):
                assert dates[i] >= dates[i + 1]


class TestAuditContentType:
    """Tests for response content type."""

    async def test_returns_json_content_type(self, test_client, setup_audit_data):
        """Response should have JSON content type."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    async def test_filters_returns_json(self, test_client, setup_audit_data):
        """Filters endpoint should return JSON."""
        response = await test_client.get("/api/audit/filters")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")


class TestAuditDateFilters:
    """Tests for date range filtering."""

    @pytest.fixture
    async def setup_dated_audit_data(self, test_db):
        """Set up audit logs with specific dates."""
        from sqlalchemy import select
        from openlabels.server.models import Tenant, User, AuditLog

        result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
        tenant = result.scalar_one()

        result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
        user = result.scalar_one()

        # Create logs using valid enum values
        old_log = AuditLog(
            id=uuid4(),
            tenant_id=tenant.id,
            user_id=user.id,
            action="monitoring_enabled",
            resource_type="file",
            resource_id=uuid4(),
            details={},
        )
        test_db.add(old_log)
        await test_db.flush()

        recent_log = AuditLog(
            id=uuid4(),
            tenant_id=tenant.id,
            user_id=user.id,
            action="monitoring_disabled",
            resource_type="file",
            resource_id=uuid4(),
            details={},
        )
        test_db.add(recent_log)
        await test_db.commit()

        return {
            "tenant": tenant,
            "user": user,
            "old_log": old_log,
            "recent_log": recent_log,
        }

    async def test_returns_all_by_default(self, test_client, setup_dated_audit_data):
        """Without date filter, should return all logs."""
        response = await test_client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()

        # Should have logs from both dated and non-dated fixtures
        assert data["total"] >= 2

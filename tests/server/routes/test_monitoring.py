"""
Comprehensive tests for monitoring API endpoints.

Tests focus on:
- Monitored files listing
- Enable/disable file monitoring
- Access events listing
- Access statistics
- Anomaly detection
- Tenant isolation
"""

import pytest
from uuid import uuid4
from datetime import datetime, timedelta, timezone


@pytest.fixture
async def setup_monitoring_data(test_db):
    """Set up test data for monitoring endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "session": test_db,
    }


class TestListMonitoredFiles:
    """Tests for GET /api/v1/monitoring/files endpoint."""

    async def test_returns_200_status(self, test_client, setup_monitoring_data):
        """List monitored files should return 200 OK."""
        response = await test_client.get("/api/v1/monitoring/files")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert isinstance(data, dict), "Response should be a dictionary"
        assert "items" in data, "Response should contain 'items' field"
        assert "total" in data, "Response should contain 'total' field"
        assert "page" in data, "Response should contain 'page' field"
        assert "total_pages" in data, "Response should contain 'total_pages' field"
        assert isinstance(data["items"], list), "Items should be a list"

    async def test_returns_paginated_structure(self, test_client, setup_monitoring_data):
        """List should return paginated structure."""
        response = await test_client.get("/api/v1/monitoring/files")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data

    async def test_returns_empty_when_no_files(self, test_client, setup_monitoring_data):
        """List should return empty when no monitored files."""
        response = await test_client.get("/api/v1/monitoring/files")
        assert response.status_code == 200
        data = response.json()

        assert data["items"] == []
        assert data["total"] == 0

    async def test_returns_monitored_files(self, test_client, setup_monitoring_data):
        """List should return monitored files."""
        from openlabels.server.models import MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        monitored = MonitoredFile(
            tenant_id=tenant.id,
            file_path="/sensitive/data.xlsx",
            risk_tier="HIGH",
            audit_read=True,
            audit_write=True,
            enabled_by=admin_user.email,
        )
        session.add(monitored)
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/files")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 1
        assert data["items"][0]["file_path"] == "/sensitive/data.xlsx"

    async def test_file_response_structure(self, test_client, setup_monitoring_data):
        """Monitored file response should have required fields."""
        from openlabels.server.models import MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        monitored = MonitoredFile(
            tenant_id=tenant.id,
            file_path="/test/structure.txt",
            risk_tier="CRITICAL",
            audit_read=True,
            audit_write=False,
            enabled_by=admin_user.email,
        )
        session.add(monitored)
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/files")
        assert response.status_code == 200
        data = response.json()

        item = data["items"][0]
        assert "id" in item
        assert "file_path" in item
        assert "risk_tier" in item
        assert "sacl_enabled" in item
        assert "audit_rule_enabled" in item
        assert "audit_read" in item
        assert "audit_write" in item
        assert "added_at" in item
        assert "last_event_at" in item
        assert "access_count" in item

    async def test_filter_by_risk_tier(self, test_client, setup_monitoring_data):
        """List should filter by risk_tier."""
        from openlabels.server.models import MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        # Add files with different risk tiers (flush after each to avoid asyncpg sentinel issues)
        for tier, path in [("CRITICAL", "/critical.txt"), ("HIGH", "/high.txt"), ("CRITICAL", "/critical2.txt")]:
            monitored = MonitoredFile(
                tenant_id=tenant.id,
                file_path=path,
                risk_tier=tier,
                enabled_by=admin_user.email,
            )
            session.add(monitored)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/files?risk_tier=CRITICAL")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2
        for item in data["items"]:
            assert item["risk_tier"] == "CRITICAL"

    async def test_pagination(self, test_client, setup_monitoring_data):
        """List should respect pagination parameters."""
        from openlabels.server.models import MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        # Add multiple files (flush after each to avoid asyncpg sentinel issues)
        for i in range(15):
            monitored = MonitoredFile(
                tenant_id=tenant.id,
                file_path=f"/paginated/file_{i}.txt",
                risk_tier="MEDIUM",
                enabled_by=admin_user.email,
            )
            session.add(monitored)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/monitoring/files?page_size=5")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 5
        assert data["total"] == 15


class TestEnableFileMonitoring:
    """Tests for POST /api/v1/monitoring/files endpoint."""

    async def test_returns_200_status(self, test_client, setup_monitoring_data):
        """Enable monitoring should return 200 OK."""
        response = await test_client.post(
            "/api/v1/monitoring/files",
            json={
                "file_path": "/new/file.txt",
                "audit_read": True,
                "audit_write": True,
            },
        )
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "id" in data, "Response should contain 'id' field"
        assert data["file_path"] == "/new/file.txt", "File path should match request"
        assert data["audit_read"] is True, "audit_read should match request"
        assert data["audit_write"] is True, "audit_write should match request"
        assert "added_at" in data, "Response should contain 'added_at' field"

    async def test_returns_created_record(self, test_client, setup_monitoring_data):
        """Enable should return the created record."""
        response = await test_client.post(
            "/api/v1/monitoring/files",
            json={
                "file_path": "/created/file.txt",
                "audit_read": True,
                "audit_write": False,
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["file_path"] == "/created/file.txt"
        assert data["audit_read"] is True
        assert data["audit_write"] is False
        assert "id" in data

    async def test_rejects_duplicate(self, test_client, setup_monitoring_data):
        """Enable should reject duplicate file_path."""
        # First creation
        await test_client.post(
            "/api/v1/monitoring/files",
            json={
                "file_path": "/duplicate/file.txt",
            },
        )

        # Duplicate
        response = await test_client.post(
            "/api/v1/monitoring/files",
            json={
                "file_path": "/duplicate/file.txt",
            },
        )
        assert response.status_code == 409


class TestDisableFileMonitoring:
    """Tests for DELETE /api/v1/monitoring/files/{file_id} endpoint."""

    async def test_returns_204_status(self, test_client, setup_monitoring_data):
        """Disable monitoring should return 204 No Content."""
        from openlabels.server.models import MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        monitored = MonitoredFile(
            tenant_id=tenant.id,
            file_path="/to/disable.txt",
            risk_tier="LOW",
            enabled_by=admin_user.email,
        )
        session.add(monitored)
        await session.commit()

        response = await test_client.delete(f"/api/v1/monitoring/files/{monitored.id}")
        assert response.status_code == 204

    async def test_file_is_removed(self, test_client, setup_monitoring_data):
        """Disabled file should no longer be in list."""
        from openlabels.server.models import MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        monitored = MonitoredFile(
            tenant_id=tenant.id,
            file_path="/remove/me.txt",
            risk_tier="MEDIUM",
            enabled_by=admin_user.email,
        )
        session.add(monitored)
        await session.commit()
        file_id = monitored.id

        await test_client.delete(f"/api/v1/monitoring/files/{file_id}")

        response = await test_client.get("/api/v1/monitoring/files")
        data = response.json()
        paths = [f["file_path"] for f in data["items"]]
        assert "/remove/me.txt" not in paths

    async def test_returns_404_for_nonexistent(self, test_client, setup_monitoring_data):
        """Disable nonexistent file should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/v1/monitoring/files/{fake_id}")
        assert response.status_code == 404


class TestListAccessEvents:
    """Tests for GET /api/v1/monitoring/events endpoint."""

    async def test_returns_200_status(self, test_client, setup_monitoring_data):
        """List events should return 200 OK."""
        response = await test_client.get("/api/v1/monitoring/events")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert isinstance(data, dict), "Response should be a dictionary"
        assert "items" in data, "Response should contain 'items' field"
        assert "total" in data, "Response should contain 'total' field"
        assert "page" in data, "Response should contain 'page' field"
        assert "total_pages" in data, "Response should contain 'total_pages' field"
        assert isinstance(data["items"], list), "Items should be a list"

    async def test_returns_paginated_structure(self, test_client, setup_monitoring_data):
        """List should return paginated structure."""
        response = await test_client.get("/api/v1/monitoring/events")
        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data

    async def test_returns_empty_when_no_events(self, test_client, setup_monitoring_data):
        """List should return empty when no events."""
        response = await test_client.get("/api/v1/monitoring/events")
        assert response.status_code == 200
        data = response.json()

        assert data["items"] == []
        assert data["total"] == 0

    async def test_returns_events(self, test_client, setup_monitoring_data):
        """List should return access events."""
        from openlabels.server.models import FileAccessEvent, MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        # Create monitored file first (required foreign key)
        monitored = MonitoredFile(
            tenant_id=tenant.id,
            file_path="/accessed/file.txt",
            risk_tier="HIGH",
            enabled_by=admin_user.email,
        )
        session.add(monitored)
        await session.flush()

        event = FileAccessEvent(
            tenant_id=tenant.id,
            monitored_file_id=monitored.id,
            file_path="/accessed/file.txt",
            action="read",
            success=True,
            user_name="testuser",
            user_domain="DOMAIN",
            event_time=datetime.now(timezone.utc),
        )
        session.add(event)
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/events")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 1
        assert data["items"][0]["file_path"] == "/accessed/file.txt"

    async def test_filter_by_file_path(self, test_client, setup_monitoring_data):
        """List should filter by file_path."""
        from openlabels.server.models import FileAccessEvent, MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        # Create monitored files for each path
        monitored_a = MonitoredFile(
            tenant_id=tenant.id, file_path="/filter/a.txt",
            risk_tier="HIGH", enabled_by=admin_user.email,
        )
        monitored_b = MonitoredFile(
            tenant_id=tenant.id, file_path="/filter/b.txt",
            risk_tier="HIGH", enabled_by=admin_user.email,
        )
        session.add(monitored_a)
        await session.flush()
        session.add(monitored_b)
        await session.flush()

        for path, monitored_id in [("/filter/a.txt", monitored_a.id), ("/filter/b.txt", monitored_b.id), ("/filter/a.txt", monitored_a.id)]:
            event = FileAccessEvent(
                tenant_id=tenant.id,
                monitored_file_id=monitored_id,
                file_path=path,
                action="read",
                success=True,
                event_time=datetime.now(timezone.utc),
            )
            session.add(event)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/events?file_path=/filter/a.txt")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2

    async def test_filter_by_user_name(self, test_client, setup_monitoring_data):
        """List should filter by user_name."""
        from openlabels.server.models import FileAccessEvent, MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        # Create monitored file first
        monitored = MonitoredFile(
            tenant_id=tenant.id, file_path="/user/filter.txt",
            risk_tier="HIGH", enabled_by=admin_user.email,
        )
        session.add(monitored)
        await session.flush()

        for user in ["alice", "bob", "alice"]:
            event = FileAccessEvent(
                tenant_id=tenant.id,
                monitored_file_id=monitored.id,
                file_path="/user/filter.txt",
                action="write",
                success=True,
                user_name=user,
                event_time=datetime.now(timezone.utc),
            )
            session.add(event)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/events?user_name=alice")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2

    async def test_filter_by_action(self, test_client, setup_monitoring_data):
        """List should filter by action type."""
        from openlabels.server.models import FileAccessEvent, MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        # Create monitored file first
        monitored = MonitoredFile(
            tenant_id=tenant.id, file_path="/action/filter.txt",
            risk_tier="HIGH", enabled_by=admin_user.email,
        )
        session.add(monitored)
        await session.flush()

        for action in ["read", "write", "read", "delete"]:
            event = FileAccessEvent(
                tenant_id=tenant.id,
                monitored_file_id=monitored.id,
                file_path="/action/filter.txt",
                action=action,
                success=True,
                event_time=datetime.now(timezone.utc),
            )
            session.add(event)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/events?action=read")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 2


class TestGetAccessStats:
    """Tests for GET /api/v1/monitoring/stats endpoint."""

    async def test_returns_200_status(self, test_client, setup_monitoring_data):
        """Stats should return 200 OK."""
        response = await test_client.get("/api/v1/monitoring/stats")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "total_events" in data, "Response should contain 'total_events' field"
        assert "events_last_24h" in data, "Response should contain 'events_last_24h' field"
        assert "events_last_7d" in data, "Response should contain 'events_last_7d' field"
        assert "by_action" in data, "Response should contain 'by_action' field"
        assert "by_user" in data, "Response should contain 'by_user' field"
        assert "monitored_files_count" in data, "Response should contain 'monitored_files_count' field"
        assert isinstance(data["total_events"], int), "total_events should be an integer"

    async def test_returns_stats_structure(self, test_client, setup_monitoring_data):
        """Stats should return required fields."""
        response = await test_client.get("/api/v1/monitoring/stats")
        assert response.status_code == 200
        data = response.json()

        assert "total_events" in data
        assert "events_last_24h" in data
        assert "events_last_7d" in data
        assert "by_action" in data
        assert "by_user" in data
        assert "monitored_files_count" in data

    async def test_returns_zero_values_when_empty(self, test_client, setup_monitoring_data):
        """Stats should return zeros when no events."""
        response = await test_client.get("/api/v1/monitoring/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_events"] == 0
        assert data["events_last_24h"] == 0
        assert data["events_last_7d"] == 0

    async def test_counts_events_correctly(self, test_client, setup_monitoring_data):
        """Stats should count events correctly."""
        from openlabels.server.models import FileAccessEvent, MonitoredFile

        session = setup_monitoring_data["session"]
        tenant = setup_monitoring_data["tenant"]
        admin_user = setup_monitoring_data["admin_user"]

        now = datetime.now(timezone.utc)

        # Create monitored files first (flush after each to avoid asyncpg sentinel issues)
        monitored_files = []
        for i in range(5):
            monitored = MonitoredFile(
                tenant_id=tenant.id, file_path=f"/stats/file_{i}.txt",
                risk_tier="HIGH", enabled_by=admin_user.email,
            )
            session.add(monitored)
            await session.flush()
            monitored_files.append(monitored)

        # Add events at different times
        for i, monitored in enumerate(monitored_files):
            event = FileAccessEvent(
                tenant_id=tenant.id,
                monitored_file_id=monitored.id,
                file_path=f"/stats/file_{i}.txt",
                action="read",
                success=True,
                event_time=now - timedelta(hours=i),
            )
            session.add(event)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/stats")
        assert response.status_code == 200
        data = response.json()

        assert data["total_events"] == 5
        assert data["events_last_24h"] == 5


class TestDetectAccessAnomalies:
    """Tests for GET /api/v1/monitoring/stats/anomalies endpoint."""

    async def test_returns_200_status(self, test_client, setup_monitoring_data):
        """Anomaly detection should return 200 OK."""
        response = await test_client.get("/api/v1/monitoring/stats/anomalies")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "analysis_period_hours" in data, "Response should contain 'analysis_period_hours' field"
        assert "analyzed_since" in data, "Response should contain 'analyzed_since' field"
        assert "anomaly_count" in data, "Response should contain 'anomaly_count' field"
        assert "anomalies" in data, "Response should contain 'anomalies' field"
        assert isinstance(data["anomalies"], list), "anomalies should be a list"
        assert isinstance(data["anomaly_count"], int), "anomaly_count should be an integer"

    async def test_returns_anomalies_structure(self, test_client, setup_monitoring_data):
        """Anomalies should return required fields."""
        response = await test_client.get("/api/v1/monitoring/stats/anomalies")
        assert response.status_code == 200
        data = response.json()

        assert "analysis_period_hours" in data
        assert "analyzed_since" in data
        assert "anomaly_count" in data
        assert "anomalies" in data

    async def test_default_24_hours(self, test_client, setup_monitoring_data):
        """Anomaly detection should default to 24 hours."""
        response = await test_client.get("/api/v1/monitoring/stats/anomalies")
        assert response.status_code == 200
        data = response.json()

        assert data["analysis_period_hours"] == 24

    async def test_custom_hours_parameter(self, test_client, setup_monitoring_data):
        """Anomaly detection should respect hours parameter."""
        response = await test_client.get("/api/v1/monitoring/stats/anomalies?hours=48")
        assert response.status_code == 200
        data = response.json()

        assert data["analysis_period_hours"] == 48

    async def test_returns_empty_anomalies_when_no_events(self, test_client, setup_monitoring_data):
        """Anomalies should be empty when no events."""
        response = await test_client.get("/api/v1/monitoring/stats/anomalies")
        assert response.status_code == 200
        data = response.json()

        assert data["anomaly_count"] == 0
        assert data["anomalies"] == []


class TestMonitoringTenantIsolation:
    """Tests for tenant isolation in monitoring endpoints."""

    async def test_cannot_access_other_tenant_files(self, test_client, setup_monitoring_data):
        """Should not be able to see files from other tenants."""
        from openlabels.server.models import Tenant, MonitoredFile

        session = setup_monitoring_data["session"]

        # Create another tenant with monitored file
        other_tenant = Tenant(
            name="Other Monitoring Tenant",
            azure_tenant_id="other-monitoring-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_file = MonitoredFile(
            tenant_id=other_tenant.id,
            file_path="/other/tenant/file.txt",
            risk_tier="HIGH",
            enabled_by="other@user.com",
        )
        session.add(other_file)
        await session.commit()

        response = await test_client.get("/api/v1/monitoring/files")
        assert response.status_code == 200
        data = response.json()

        paths = [f["file_path"] for f in data["items"]]
        assert "/other/tenant/file.txt" not in paths

    async def test_cannot_delete_other_tenant_file(self, test_client, setup_monitoring_data):
        """Should not be able to delete files from other tenants."""
        from openlabels.server.models import Tenant, MonitoredFile

        session = setup_monitoring_data["session"]

        other_tenant = Tenant(
            name="Delete Other Tenant",
            azure_tenant_id="delete-other-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_file = MonitoredFile(
            tenant_id=other_tenant.id,
            file_path="/delete/other/file.txt",
            risk_tier="MEDIUM",
            enabled_by="delete@other.com",
        )
        session.add(other_file)
        await session.commit()

        response = await test_client.delete(f"/api/v1/monitoring/files/{other_file.id}")
        assert response.status_code == 404


class TestMonitoringContentType:
    """Tests for response content type."""

    async def test_files_returns_json(self, test_client, setup_monitoring_data):
        """List files should return JSON."""
        response = await test_client.get("/api/v1/monitoring/files")
        assert "application/json" in response.headers.get("content-type", "")

    async def test_events_returns_json(self, test_client, setup_monitoring_data):
        """List events should return JSON."""
        response = await test_client.get("/api/v1/monitoring/events")
        assert "application/json" in response.headers.get("content-type", "")

    async def test_stats_returns_json(self, test_client, setup_monitoring_data):
        """Stats should return JSON."""
        response = await test_client.get("/api/v1/monitoring/stats")
        assert "application/json" in response.headers.get("content-type", "")

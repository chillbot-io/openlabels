"""
Comprehensive tests for schedules API endpoints.

Tests focus on:
- Schedule listing
- Schedule creation with validation
- Schedule retrieval by ID
- Schedule updates
- Schedule deletion
- Manual trigger execution
- Admin authorization requirements
- Tenant isolation
- HTMX response handling
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone


@pytest.fixture
async def setup_schedules_data(test_db):
    """Set up test data for schedule endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanTarget

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    # Create a scan target
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Schedule Test Target",
        adapter="filesystem",
        config={"path": "/test"},
        enabled=True,
        created_by=admin_user.id,
    )
    test_db.add(target)
    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "target": target,
        "session": test_db,
    }


class TestListSchedules:
    """Tests for GET /api/schedules endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_schedules_data):
        """List schedules endpoint should return 200 OK."""
        response = await test_client.get("/api/schedules")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_list(self, test_client, setup_schedules_data):
        """List schedules should return a list."""
        response = await test_client.get("/api/schedules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_schedules(self, test_client, setup_schedules_data):
        """List should return empty list when no schedules exist."""
        response = await test_client.get("/api/schedules")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    @pytest.mark.asyncio
    async def test_returns_schedules(self, test_client, setup_schedules_data):
        """List should return created schedules."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Test Schedule",
            target_id=target.id,
            cron="0 0 * * *",
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.get("/api/schedules")
        assert response.status_code == 200
        data = response.json()

        assert len(data) == 1
        assert data[0]["name"] == "Test Schedule"

    @pytest.mark.asyncio
    async def test_schedule_response_structure(self, test_client, setup_schedules_data):
        """Schedule response should have all required fields."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Structure Test",
            target_id=target.id,
            cron="0 0 * * *",
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.get("/api/schedules")
        assert response.status_code == 200
        data = response.json()

        sched = data[0]
        assert "id" in sched
        assert "name" in sched
        assert "target_id" in sched
        assert "cron" in sched
        assert "enabled" in sched
        assert "last_run_at" in sched
        assert "next_run_at" in sched


class TestCreateSchedule:
    """Tests for POST /api/schedules endpoint."""

    @pytest.mark.asyncio
    async def test_returns_201_status(self, test_client, setup_schedules_data):
        """Create schedule should return 201 Created."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "New Schedule",
                "target_id": str(target.id),
            },
        )
        assert response.status_code == 201

    @pytest.mark.asyncio
    async def test_returns_created_schedule(self, test_client, setup_schedules_data):
        """Create schedule should return the created schedule."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "Created Schedule",
                "target_id": str(target.id),
                "cron": "0 0 * * *",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["name"] == "Created Schedule"
        assert data["target_id"] == str(target.id)
        assert data["cron"] == "0 0 * * *"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_schedule_without_cron(self, test_client, setup_schedules_data):
        """Schedule can be created without cron (on-demand only)."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "On-Demand Schedule",
                "target_id": str(target.id),
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["cron"] is None

    @pytest.mark.asyncio
    async def test_schedule_is_enabled_by_default(self, test_client, setup_schedules_data):
        """New schedule should be enabled by default."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "Enabled Schedule",
                "target_id": str(target.id),
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["enabled"] is True

    @pytest.mark.asyncio
    async def test_returns_404_for_invalid_target(self, test_client, setup_schedules_data):
        """Create schedule with invalid target should return 404."""
        fake_target_id = uuid4()

        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "Invalid Target Schedule",
                "target_id": str(fake_target_id),
            },
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_missing_name_returns_422(self, test_client, setup_schedules_data):
        """Create schedule without name should return 422."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/schedules",
            json={
                "target_id": str(target.id),
            },
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_target_id_returns_422(self, test_client, setup_schedules_data):
        """Create schedule without target_id should return 422."""
        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "Missing Target Schedule",
            },
        )
        assert response.status_code == 422


class TestGetSchedule:
    """Tests for GET /api/schedules/{schedule_id} endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_schedules_data):
        """Get schedule should return 200 OK."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Get Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.get(f"/api/schedules/{schedule.id}")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_schedule_details(self, test_client, setup_schedules_data):
        """Get schedule should return schedule details."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Details Test",
            target_id=target.id,
            cron="30 2 * * *",
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.get(f"/api/schedules/{schedule.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(schedule.id)
        assert data["name"] == "Details Test"
        assert data["cron"] == "30 2 * * *"

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Get nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/schedules/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_422_for_invalid_uuid(self, test_client, setup_schedules_data):
        """Get schedule with invalid UUID should return 422."""
        response = await test_client.get("/api/schedules/not-a-uuid")
        assert response.status_code == 422


class TestUpdateSchedule:
    """Tests for PUT /api/schedules/{schedule_id} endpoint."""

    @pytest.mark.asyncio
    async def test_returns_200_status(self, test_client, setup_schedules_data):
        """Update schedule should return 200 OK."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Update Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.put(
            f"/api/schedules/{schedule.id}",
            json={"name": "Updated Name"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_updates_name(self, test_client, setup_schedules_data):
        """Update should change schedule name."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Original Name",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.put(
            f"/api/schedules/{schedule.id}",
            json={"name": "New Name"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "New Name"

    @pytest.mark.asyncio
    async def test_updates_cron(self, test_client, setup_schedules_data):
        """Update should change cron expression."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Cron Update Test",
            target_id=target.id,
            cron="0 0 * * *",
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.put(
            f"/api/schedules/{schedule.id}",
            json={"cron": "0 6 * * *"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["cron"] == "0 6 * * *"

    @pytest.mark.asyncio
    async def test_updates_enabled_status(self, test_client, setup_schedules_data):
        """Update should change enabled status."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Enable Test",
            target_id=target.id,
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.put(
            f"/api/schedules/{schedule.id}",
            json={"enabled": False},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["enabled"] is False

    @pytest.mark.asyncio
    async def test_partial_update(self, test_client, setup_schedules_data):
        """Update should only change provided fields."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Partial Update",
            target_id=target.id,
            cron="0 0 * * *",
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.put(
            f"/api/schedules/{schedule.id}",
            json={"name": "New Name Only"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "New Name Only"
        assert data["cron"] == "0 0 * * *"  # Unchanged
        assert data["enabled"] is True  # Unchanged

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Update nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/schedules/{fake_id}",
            json={"name": "Test"},
        )
        assert response.status_code == 404


class TestDeleteSchedule:
    """Tests for DELETE /api/schedules/{schedule_id} endpoint."""

    @pytest.mark.asyncio
    async def test_returns_204_status(self, test_client, setup_schedules_data):
        """Delete schedule should return 204 No Content."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Delete Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.delete(f"/api/schedules/{schedule.id}")
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_schedule_is_removed(self, test_client, setup_schedules_data):
        """Deleted schedule should no longer exist."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Remove Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()
        schedule_id = schedule.id

        # Delete
        await test_client.delete(f"/api/schedules/{schedule_id}")

        # Try to get - should be 404
        response = await test_client.get(f"/api/schedules/{schedule_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Delete nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/schedules/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_htmx_request_returns_200_with_trigger(self, test_client, setup_schedules_data):
        """HTMX delete request should return 200 with HX-Trigger."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="HTMX Delete Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.delete(
            f"/api/schedules/{schedule.id}",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "deleted" in response.headers["HX-Trigger"]


class TestTriggerSchedule:
    """Tests for POST /api/schedules/{schedule_id}/run endpoint."""

    @pytest.mark.asyncio
    async def test_returns_202_status(self, test_client, setup_schedules_data):
        """Trigger schedule should return 202 Accepted."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Trigger Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.post(f"/api/schedules/{schedule.id}/run")
        assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_returns_job_info(self, test_client, setup_schedules_data):
        """Trigger should return job info."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Trigger Info Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.post(f"/api/schedules/{schedule.id}/run")
        assert response.status_code == 202
        data = response.json()

        assert "message" in data
        assert "schedule_id" in data
        assert "job_id" in data
        assert data["schedule_id"] == str(schedule.id)

    @pytest.mark.asyncio
    async def test_creates_scan_job(self, test_client, setup_schedules_data):
        """Trigger should create a scan job."""
        from openlabels.server.models import ScanSchedule, ScanJob
        from sqlalchemy import select

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Create Job Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.post(f"/api/schedules/{schedule.id}/run")
        assert response.status_code == 202
        data = response.json()

        # Verify job was created
        job_id = data["job_id"]
        result = await session.execute(
            select(ScanJob).where(ScanJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        assert job is not None
        assert job.status == "pending"

    @pytest.mark.asyncio
    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Trigger nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.post(f"/api/schedules/{fake_id}/run")
        assert response.status_code == 404


class TestScheduleTenantIsolation:
    """Tests for tenant isolation in schedule endpoints."""

    @pytest.mark.asyncio
    async def test_cannot_access_other_tenant_schedule(self, test_client, setup_schedules_data):
        """Should not be able to access schedules from other tenants."""
        from openlabels.server.models import Tenant, User, ScanTarget, ScanSchedule

        session = setup_schedules_data["session"]

        # Create another tenant with target and schedule
        other_tenant = Tenant(
            name="Other Schedule Tenant",
            azure_tenant_id="other-schedule-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="other-schedule@other.com",
            name="Other User",
            role="admin",
        )
        session.add(other_user)
        await session.flush()

        other_target = ScanTarget(
            tenant_id=other_tenant.id,
            name="Other Target",
            adapter="filesystem",
            config={"path": "/other"},
            enabled=True,
            created_by=other_user.id,
        )
        session.add(other_target)
        await session.flush()

        other_schedule = ScanSchedule(
            tenant_id=other_tenant.id,
            name="Other Schedule",
            target_id=other_target.id,
            created_by=other_user.id,
        )
        session.add(other_schedule)
        await session.commit()

        # Try to access the other tenant's schedule
        response = await test_client.get(f"/api/schedules/{other_schedule.id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_cannot_create_schedule_for_other_tenant_target(
        self, test_client, setup_schedules_data
    ):
        """Should not be able to create schedule for another tenant's target."""
        from openlabels.server.models import Tenant, User, ScanTarget

        session = setup_schedules_data["session"]

        # Create another tenant with target
        other_tenant = Tenant(
            name="Other Target Tenant",
            azure_tenant_id="other-target-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="other-target@other.com",
            name="Other User",
            role="admin",
        )
        session.add(other_user)
        await session.flush()

        other_target = ScanTarget(
            tenant_id=other_tenant.id,
            name="Other Tenant Target",
            adapter="filesystem",
            config={"path": "/other"},
            enabled=True,
            created_by=other_user.id,
        )
        session.add(other_target)
        await session.commit()

        # Try to create schedule for other tenant's target
        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "Cross-Tenant Schedule",
                "target_id": str(other_target.id),
            },
        )
        assert response.status_code == 404


class TestScheduleContentType:
    """Tests for response content type."""

    @pytest.mark.asyncio
    async def test_list_returns_json(self, test_client, setup_schedules_data):
        """List schedules should return JSON."""
        response = await test_client.get("/api/schedules")
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_create_returns_json(self, test_client, setup_schedules_data):
        """Create schedule should return JSON."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/schedules",
            json={
                "name": "Content Type Test",
                "target_id": str(target.id),
            },
        )
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_trigger_returns_json(self, test_client, setup_schedules_data):
        """Trigger schedule should return JSON."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Content Type Trigger Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.post(f"/api/schedules/{schedule.id}/run")
        assert "application/json" in response.headers.get("content-type", "")

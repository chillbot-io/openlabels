"""
Comprehensive tests for schedules API endpoints (Story 9).

Tests focus on:
- Schedule listing with enriched response (target_name, cron_description)
- Schedule creation with cron validation
- Schedule retrieval by ID
- Schedule updates (including target_id change)
- Schedule deletion with HTMX support
- Toggle enable/disable
- Cron validation endpoint
- Bulk scheduling
- Manual trigger execution
- Schedule execution history
- Admin authorization requirements
- Tenant isolation
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest


@pytest.fixture
async def setup_schedules_data(test_db):
    """Set up test data for schedule endpoint tests."""
    from sqlalchemy import select

    from openlabels.server.models import ScanTarget, Tenant, User

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    # Create scan targets
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

    target2 = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Second Test Target",
        adapter="filesystem",
        config={"path": "/test2"},
        enabled=True,
        created_by=admin_user.id,
    )
    test_db.add(target2)
    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "target": target,
        "target2": target2,
        "session": test_db,
    }


class TestListSchedules:
    """Tests for GET /api/v1/schedules endpoint."""

    async def test_returns_empty_list_when_no_schedules(self, test_client, setup_schedules_data):
        """List should return empty when no schedules exist."""
        response = await test_client.get("/api/v1/schedules")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []

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

        response = await test_client.get("/api/v1/schedules")
        assert response.status_code == 200
        data = response.json()
        items = data["items"]

        assert len(items) == 1
        assert items[0]["name"] == "Test Schedule"

    async def test_enriched_response_fields(self, test_client, setup_schedules_data):
        """Schedule response should include target_name and cron_description."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Enriched Schedule",
            target_id=target.id,
            cron="0 2 * * *",
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.get("/api/v1/schedules")
        assert response.status_code == 200
        item = response.json()["items"][0]

        assert item["target_name"] == "Schedule Test Target"
        assert item["cron_description"] is not None
        assert "02:00" in item["cron_description"]
        assert "created_at" in item


class TestCreateSchedule:
    """Tests for POST /api/v1/schedules endpoint."""

    async def test_returns_created_schedule(self, test_client, setup_schedules_data):
        """Create schedule should return 201 with the created schedule details."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/v1/schedules",
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
        assert data["target_name"] == "Schedule Test Target"
        assert data["cron_description"] is not None
        assert "id" in data

    async def test_create_schedule_without_cron(self, test_client, setup_schedules_data):
        """Schedule can be created without cron (on-demand only)."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/v1/schedules",
            json={
                "name": "On-Demand Schedule",
                "target_id": str(target.id),
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["cron"] is None
        assert data["cron_description"] is None

    async def test_schedule_is_enabled_by_default(self, test_client, setup_schedules_data):
        """New schedule should be enabled by default."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/v1/schedules",
            json={
                "name": "Enabled Schedule",
                "target_id": str(target.id),
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["enabled"] is True

    async def test_returns_404_for_invalid_target(self, test_client, setup_schedules_data):
        """Create schedule with invalid target should return 404."""
        fake_target_id = uuid4()

        response = await test_client.post(
            "/api/v1/schedules",
            json={
                "name": "Invalid Target Schedule",
                "target_id": str(fake_target_id),
            },
        )
        assert response.status_code == 404

    async def test_invalid_cron_returns_400(self, test_client, setup_schedules_data):
        """Create schedule with invalid cron should return 400."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/v1/schedules",
            json={
                "name": "Bad Cron Schedule",
                "target_id": str(target.id),
                "cron": "not-a-cron",
            },
        )
        assert response.status_code == 400

    async def test_missing_name_returns_422(self, test_client, setup_schedules_data):
        """Create schedule without name should return 422."""
        target = setup_schedules_data["target"]

        response = await test_client.post(
            "/api/v1/schedules",
            json={
                "target_id": str(target.id),
            },
        )
        assert response.status_code == 422

    async def test_missing_target_id_returns_422(self, test_client, setup_schedules_data):
        """Create schedule without target_id should return 422."""
        response = await test_client.post(
            "/api/v1/schedules",
            json={
                "name": "Missing Target Schedule",
            },
        )
        assert response.status_code == 422


class TestGetSchedule:
    """Tests for GET /api/v1/schedules/{schedule_id} endpoint."""

    async def test_returns_schedule_details(self, test_client, setup_schedules_data):
        """Get schedule should return 200 with all schedule details."""
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

        response = await test_client.get(f"/api/v1/schedules/{schedule.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(schedule.id)
        assert data["name"] == "Details Test"
        assert data["cron"] == "30 2 * * *"
        assert data["target_name"] == "Schedule Test Target"
        assert data["cron_description"] is not None

    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Get nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/schedules/{fake_id}")
        assert response.status_code == 404

    async def test_returns_422_for_invalid_uuid(self, test_client, setup_schedules_data):
        """Get schedule with invalid UUID should return 422."""
        response = await test_client.get("/api/v1/schedules/not-a-uuid")
        assert response.status_code == 422


class TestUpdateSchedule:
    """Tests for PUT /api/v1/schedules/{schedule_id} endpoint."""

    async def test_updates_name(self, test_client, setup_schedules_data):
        """Update should return 200 and change schedule name."""
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
            f"/api/v1/schedules/{schedule.id}",
            json={"name": "New Name"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "New Name"

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
            f"/api/v1/schedules/{schedule.id}",
            json={"cron": "0 6 * * *"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["cron"] == "0 6 * * *"

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
            f"/api/v1/schedules/{schedule.id}",
            json={"enabled": False},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["enabled"] is False

    async def test_updates_target_id(self, test_client, setup_schedules_data):
        """Update should allow changing target_id."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        target2 = setup_schedules_data["target2"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Target Change Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.put(
            f"/api/v1/schedules/{schedule.id}",
            json={"target_id": str(target2.id)},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["target_id"] == str(target2.id)
        assert data["target_name"] == "Second Test Target"

    async def test_invalid_cron_returns_400(self, test_client, setup_schedules_data):
        """Update with invalid cron should return 400."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Bad Cron Update",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.put(
            f"/api/v1/schedules/{schedule.id}",
            json={"cron": "invalid-cron"},
        )
        assert response.status_code == 400

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
            f"/api/v1/schedules/{schedule.id}",
            json={"name": "New Name Only"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "New Name Only"
        assert data["cron"] == "0 0 * * *"  # Unchanged
        assert data["enabled"] is True  # Unchanged

    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Update nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/v1/schedules/{fake_id}",
            json={"name": "Test"},
        )
        assert response.status_code == 404


class TestDeleteSchedule:
    """Tests for DELETE /api/v1/schedules/{schedule_id} endpoint."""

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

        response = await test_client.delete(f"/api/v1/schedules/{schedule.id}")
        assert response.status_code == 204

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
        await test_client.delete(f"/api/v1/schedules/{schedule_id}")

        # Try to get - should be 404
        response = await test_client.get(f"/api/v1/schedules/{schedule_id}")
        assert response.status_code == 404

    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Delete nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/v1/schedules/{fake_id}")
        assert response.status_code == 404

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
            f"/api/v1/schedules/{schedule.id}",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        assert "HX-Trigger" in response.headers
        assert "deleted" in response.headers["HX-Trigger"]


class TestToggleSchedule:
    """Tests for PATCH /api/v1/schedules/{schedule_id}/toggle endpoint."""

    async def test_disable_schedule(self, test_client, setup_schedules_data):
        """Toggle should disable an enabled schedule."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Toggle Disable Test",
            target_id=target.id,
            cron="0 3 * * *",
            enabled=True,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.patch(
            f"/api/v1/schedules/{schedule.id}/toggle",
            json={"enabled": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False
        assert data["next_run_at"] is None

    async def test_enable_schedule(self, test_client, setup_schedules_data):
        """Toggle should enable a disabled schedule and set next_run_at."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Toggle Enable Test",
            target_id=target.id,
            cron="0 4 * * *",
            enabled=False,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.patch(
            f"/api/v1/schedules/{schedule.id}/toggle",
            json={"enabled": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["next_run_at"] is not None

    async def test_toggle_404_for_nonexistent(self, test_client, setup_schedules_data):
        """Toggle nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.patch(
            f"/api/v1/schedules/{fake_id}/toggle",
            json={"enabled": True},
        )
        assert response.status_code == 404


class TestCronValidation:
    """Tests for POST /api/v1/schedules/validate-cron endpoint."""

    async def test_valid_cron(self, test_client, setup_schedules_data):
        """Should validate a correct cron expression."""
        response = await test_client.post(
            "/api/v1/schedules/validate-cron",
            json={"cron": "0 2 * * *"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["valid"] is True
        assert data["cron"] == "0 2 * * *"
        assert data["description"] is not None
        assert len(data["next_runs"]) == 5
        assert data["error"] is None

    async def test_invalid_cron(self, test_client, setup_schedules_data):
        """Should reject an invalid cron expression."""
        response = await test_client.post(
            "/api/v1/schedules/validate-cron",
            json={"cron": "not-a-cron"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["valid"] is False
        assert data["error"] is not None
        assert data["next_runs"] == []

    async def test_cron_with_weekday(self, test_client, setup_schedules_data):
        """Should describe cron with weekday."""
        response = await test_client.post(
            "/api/v1/schedules/validate-cron",
            json={"cron": "0 9 * * 1"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["valid"] is True
        assert "Monday" in data["description"]

    async def test_every_minute_cron(self, test_client, setup_schedules_data):
        """Should describe every-minute cron."""
        response = await test_client.post(
            "/api/v1/schedules/validate-cron",
            json={"cron": "* * * * *"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["valid"] is True
        assert data["description"] is not None


class TestBulkSchedule:
    """Tests for POST /api/v1/schedules/bulk endpoint."""

    async def test_creates_schedules_for_all_targets(self, test_client, setup_schedules_data):
        """Should create schedules for all enabled targets."""
        response = await test_client.post(
            "/api/v1/schedules/bulk",
            json={"cron": "0 1 * * *"},
        )
        assert response.status_code == 201
        data = response.json()

        assert len(data) == 2  # Two enabled targets
        for item in data:
            assert item["cron"] == "0 1 * * *"
            assert item["target_name"] is not None

    async def test_skips_duplicates(self, test_client, setup_schedules_data):
        """Should skip targets that already have schedules with same cron."""
        # First bulk create
        response1 = await test_client.post(
            "/api/v1/schedules/bulk",
            json={"cron": "0 2 * * *"},
        )
        assert response1.status_code == 201
        assert len(response1.json()) == 2

        # Second bulk create with same cron - should skip all
        response2 = await test_client.post(
            "/api/v1/schedules/bulk",
            json={"cron": "0 2 * * *"},
        )
        assert response2.status_code == 201
        assert len(response2.json()) == 0

    async def test_invalid_cron_returns_400(self, test_client, setup_schedules_data):
        """Should reject invalid cron in bulk create."""
        response = await test_client.post(
            "/api/v1/schedules/bulk",
            json={"cron": "bad-cron"},
        )
        assert response.status_code == 400


class TestTriggerSchedule:
    """Tests for POST /api/v1/schedules/{schedule_id}/run endpoint."""

    async def test_returns_job_info(self, test_client, setup_schedules_data):
        """Trigger should return 202 with job info including schedule_id and job_id."""
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

        response = await test_client.post(f"/api/v1/schedules/{schedule.id}/run")
        assert response.status_code == 202
        data = response.json()

        assert "message" in data
        assert "schedule_id" in data
        assert "job_id" in data
        assert data["schedule_id"] == str(schedule.id)

    async def test_creates_scan_job(self, test_client, setup_schedules_data):
        """Trigger should create a scan job."""
        from sqlalchemy import select

        from openlabels.server.models import ScanJob, ScanSchedule

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

        response = await test_client.post(f"/api/v1/schedules/{schedule.id}/run")
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

    async def test_returns_404_for_nonexistent_schedule(self, test_client, setup_schedules_data):
        """Trigger nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.post(f"/api/v1/schedules/{fake_id}/run")
        assert response.status_code == 404


class TestScheduleHistory:
    """Tests for GET /api/v1/schedules/{schedule_id}/history endpoint."""

    async def test_returns_empty_history(self, test_client, setup_schedules_data):
        """History should return empty list when no jobs have run."""
        from openlabels.server.models import ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Empty History Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.commit()

        response = await test_client.get(f"/api/v1/schedules/{schedule.id}/history")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    async def test_returns_job_history(self, test_client, setup_schedules_data):
        """History should return past jobs linked to this schedule."""
        from openlabels.server.models import ScanJob, ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="History Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.flush()

        # Create some jobs linked to this schedule
        now = datetime.now(timezone.utc)
        for i, status in enumerate(["completed", "failed", "completed"]):
            job = ScanJob(
                tenant_id=tenant.id,
                schedule_id=schedule.id,
                target_id=target.id,
                name=f"History Job {i}",
                status=status,
                files_scanned=10 * (i + 1),
                files_with_pii=i,
                started_at=now,
                completed_at=now,
                created_by=admin_user.id,
            )
            session.add(job)
        await session.commit()

        response = await test_client.get(f"/api/v1/schedules/{schedule.id}/history")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 3
        assert len(data["items"]) == 3

        # Verify job fields
        item = data["items"][0]
        assert "id" in item
        assert "name" in item
        assert "status" in item
        assert "files_scanned" in item
        assert "files_with_pii" in item
        assert "duration_seconds" in item

    async def test_history_excludes_unrelated_jobs(self, test_client, setup_schedules_data):
        """History should only include jobs for this schedule."""
        from openlabels.server.models import ScanJob, ScanSchedule

        session = setup_schedules_data["session"]
        tenant = setup_schedules_data["tenant"]
        target = setup_schedules_data["target"]
        admin_user = setup_schedules_data["admin_user"]

        schedule = ScanSchedule(
            tenant_id=tenant.id,
            name="Isolation Test",
            target_id=target.id,
            created_by=admin_user.id,
        )
        session.add(schedule)
        await session.flush()

        # Job linked to this schedule
        job1 = ScanJob(
            tenant_id=tenant.id,
            schedule_id=schedule.id,
            target_id=target.id,
            name="Linked Job",
            status="completed",
            created_by=admin_user.id,
        )
        # Job NOT linked to any schedule
        job2 = ScanJob(
            tenant_id=tenant.id,
            target_id=target.id,
            name="Unlinked Job",
            status="completed",
            created_by=admin_user.id,
        )
        session.add_all([job1, job2])
        await session.commit()

        response = await test_client.get(f"/api/v1/schedules/{schedule.id}/history")
        assert response.status_code == 200
        data = response.json()

        assert data["total"] == 1
        assert data["items"][0]["name"] == "Linked Job"

    async def test_history_404_for_nonexistent(self, test_client, setup_schedules_data):
        """History for nonexistent schedule should return 404."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/v1/schedules/{fake_id}/history")
        assert response.status_code == 404


class TestScheduleTenantIsolation:
    """Tests for tenant isolation in schedule endpoints."""

    async def test_cannot_access_other_tenant_schedule(self, test_client, setup_schedules_data):
        """Should not be able to access schedules from other tenants."""
        from openlabels.server.models import ScanSchedule, ScanTarget, Tenant, User

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
        response = await test_client.get(f"/api/v1/schedules/{other_schedule.id}")
        assert response.status_code == 404

    async def test_cannot_create_schedule_for_other_tenant_target(
        self, test_client, setup_schedules_data
    ):
        """Should not be able to create schedule for another tenant's target."""
        from openlabels.server.models import ScanTarget, Tenant, User

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
            "/api/v1/schedules",
            json={
                "name": "Cross-Tenant Schedule",
                "target_id": str(other_target.id),
            },
        )
        assert response.status_code == 404

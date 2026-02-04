"""
Tests for multi-tenant data isolation.

These tests verify that users from one tenant cannot access,
modify, or enumerate resources belonging to another tenant.
"""

import asyncio
import contextlib
import pytest
from uuid import uuid4

from httpx import AsyncClient, ASGITransport
from openlabels.server.app import app
from openlabels.server.db import get_session
from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin, CurrentUser
from openlabels.server.models import (
    Tenant, User, ScanJob, ScanResult, ScanTarget,
    ScanSchedule, AuditLog,
)


# Rate limiting is disabled in create_client_for_user and test_client fixture


@pytest.fixture
async def two_tenant_setup(test_db):
    """Set up two separate tenants with their own users and data."""
    import random
    import string

    # Use unique suffix to avoid any conflicts
    suffix = ''.join(random.choices(string.ascii_lowercase, k=6))

    # Tenant A - create and flush immediately
    tenant_a = Tenant(
        id=uuid4(),
        name=f"Tenant A {suffix}",
        azure_tenant_id=f"tenant-a-azure-{suffix}",
    )
    test_db.add(tenant_a)
    await test_db.flush()

    # User A - flush before creating objects that reference it
    user_a = User(
        id=uuid4(),
        tenant_id=tenant_a.id,
        email=f"admin-{suffix}@tenant-a.com",
        name="Tenant A Admin",
        role="admin",
    )
    test_db.add(user_a)
    await test_db.flush()

    # Create target for tenant A
    target_a = ScanTarget(
        id=uuid4(),
        tenant_id=tenant_a.id,
        name=f"Tenant A Target {suffix}",
        adapter="filesystem",
        config={"path": "/tenant-a-data"},
        enabled=True,
        created_by=user_a.id,
    )
    test_db.add(target_a)
    await test_db.flush()

    # Create scan for tenant A
    scan_a = ScanJob(
        id=uuid4(),
        tenant_id=tenant_a.id,
        target_id=target_a.id,
        status="completed",
    )
    test_db.add(scan_a)
    await test_db.flush()

    # Create result for tenant A
    result_a = ScanResult(
        id=uuid4(),
        tenant_id=tenant_a.id,
        job_id=scan_a.id,
        file_path="/tenant-a-data/secret.txt",
        file_name="secret.txt",
        risk_score=90,
        risk_tier="CRITICAL",
        entity_counts={"SSN": 5},
        total_entities=5,
    )
    test_db.add(result_a)
    await test_db.flush()

    # Create schedule for tenant A
    schedule_a = ScanSchedule(
        id=uuid4(),
        tenant_id=tenant_a.id,
        target_id=target_a.id,
        name=f"Tenant A Schedule {suffix}",
        cron="0 0 * * *",
        enabled=True,
        created_by=user_a.id,
    )
    test_db.add(schedule_a)
    await test_db.flush()

    # Create audit log for tenant A
    audit_a = AuditLog(
        id=uuid4(),
        tenant_id=tenant_a.id,
        user_id=user_a.id,
        action="scan_started",
        resource_type="scan",
        resource_id=scan_a.id,
        details={"scan_name": "Test Scan A"},
    )
    test_db.add(audit_a)
    await test_db.flush()

    # Tenant B - create and flush
    tenant_b = Tenant(
        id=uuid4(),
        name=f"Tenant B {suffix}",
        azure_tenant_id=f"tenant-b-azure-{suffix}",
    )
    test_db.add(tenant_b)
    await test_db.flush()

    user_b = User(
        id=uuid4(),
        tenant_id=tenant_b.id,
        email=f"admin-{suffix}@tenant-b.com",
        name="Tenant B Admin",
        role="admin",
    )
    test_db.add(user_b)
    await test_db.flush()

    # Commit all changes
    await test_db.commit()

    # Refresh to ensure all relationships are loaded
    await test_db.refresh(tenant_a)
    await test_db.refresh(user_a)
    await test_db.refresh(target_a)
    await test_db.refresh(scan_a)
    await test_db.refresh(result_a)
    await test_db.refresh(schedule_a)
    await test_db.refresh(audit_a)
    await test_db.refresh(tenant_b)
    await test_db.refresh(user_b)

    return {
        "tenant_a": tenant_a,
        "user_a": user_a,
        "target_a": target_a,
        "scan_a": scan_a,
        "result_a": result_a,
        "schedule_a": schedule_a,
        "audit_a": audit_a,
        "tenant_b": tenant_b,
        "user_b": user_b,
        "session": test_db,
    }


@contextlib.asynccontextmanager
async def create_client_for_user(test_db, user, tenant):
    """
    Create a test client authenticated as a specific user.

    This is an async context manager that properly handles cleanup of:
    - App dependency overrides
    - Rate limiter states

    Usage:
        async with create_client_for_user(db, user, tenant) as client:
            response = await client.get("/api/...")
    """
    from openlabels.server.app import limiter as app_limiter
    from openlabels.server.routes.remediation import limiter as remediation_limiter
    from openlabels.server.routes.scans import limiter as scans_limiter
    from openlabels.server.routes.auth import limiter as auth_limiter

    async def override_get_session():
        yield test_db

    def _create_current_user():
        return CurrentUser(
            id=user.id,
            tenant_id=tenant.id,
            email=user.email,
            name=user.name,
            role=str(user.role),
        )

    async def override_get_current_user():
        return _create_current_user()

    async def override_get_optional_user():
        return _create_current_user()

    async def override_require_admin():
        return _create_current_user()

    # Save original states for cleanup
    limiters = [app_limiter, remediation_limiter, scans_limiter, auth_limiter]
    original_limiter_states = [l.enabled for l in limiters]

    # Set up overrides
    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_optional_user] = override_get_optional_user
    app.dependency_overrides[require_admin] = override_require_admin

    # Disable rate limiting for tests
    for limiter in limiters:
        limiter.enabled = False

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        # Always clean up, even if test fails
        app.dependency_overrides.clear()
        # Restore rate limiter states
        for limiter, original_state in zip(limiters, original_limiter_states):
            limiter.enabled = original_state


class TestScanTenantIsolation:
    """Tests for tenant isolation in scan operations."""

    @pytest.mark.asyncio
    async def test_cannot_view_other_tenant_scans(self, two_tenant_setup):
        """User from tenant B should not see tenant A's scans."""
        data = two_tenant_setup
        scan_a = data["scan_a"]

        # Authenticate as tenant B user
        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            # Try to access tenant A's scan
            response = await client.get(f"/api/scans/{scan_a.id}")

            # Should return 404 (not 403, to prevent enumeration)
            assert response.status_code == 404, \
                f"Expected 404 for cross-tenant access, got {response.status_code}"


    @pytest.mark.asyncio
    async def test_cannot_cancel_other_tenant_scans(self, two_tenant_setup):
        """User from tenant B should not cancel tenant A's scans."""
        from sqlalchemy import select

        data = two_tenant_setup
        scan_a = data["scan_a"]
        scan_a_id = scan_a.id
        original_status = scan_a.status

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.post(f"/api/scans/{scan_a.id}/cancel")

            # Should return 404 (not 403)
            assert response.status_code == 404, \
                f"Expected 404 for cross-tenant cancel, got {response.status_code}"

        # CRITICAL: Verify scan status was NOT changed in database
        scan_after = (await data["session"].execute(
            select(ScanJob).where(ScanJob.id == scan_a_id)
        )).scalar_one()
        assert scan_after.status == original_status, \
            f"TENANT ISOLATION BREACH: Scan status changed from '{original_status}' to '{scan_after.status}'!"


    @pytest.mark.asyncio
    async def test_list_scans_only_shows_own_tenant(self, two_tenant_setup):
        """Listing scans should only return current tenant's scans."""
        data = two_tenant_setup

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/scans")
            assert response.status_code == 200

            scans = response.json()
            items = scans.get("items", scans) if isinstance(scans, dict) else scans

            # Tenant B should not see tenant A's scans
            scan_a_id = str(data["scan_a"].id)
            for scan in items:
                assert scan.get("id") != scan_a_id, \
                    "Tenant B can see Tenant A's scan - isolation failure!"



class TestTargetTenantIsolation:
    """Tests for tenant isolation in target configuration."""

    @pytest.mark.asyncio
    async def test_cannot_view_other_tenant_targets(self, two_tenant_setup):
        """User from tenant B should not see tenant A's targets."""
        data = two_tenant_setup
        target_a = data["target_a"]

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/targets/{target_a.id}")
            assert response.status_code == 404


    @pytest.mark.asyncio
    async def test_cannot_modify_other_tenant_targets(self, two_tenant_setup):
        """User from tenant B should not modify tenant A's targets."""
        from sqlalchemy import select

        data = two_tenant_setup
        target_a = data["target_a"]
        target_a_id = target_a.id
        original_name = target_a.name

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            # Use PUT (the supported method) instead of PATCH
            response = await client.put(
                f"/api/targets/{target_a.id}",
                json={"name": "Hacked Target"},
            )
            assert response.status_code == 404

        # CRITICAL: Verify target was NOT modified in database
        target_after = (await data["session"].execute(
            select(ScanTarget).where(ScanTarget.id == target_a_id)
        )).scalar_one()
        assert target_after.name == original_name, \
            f"TENANT ISOLATION BREACH: Target name changed from '{original_name}' to '{target_after.name}'!"


    @pytest.mark.asyncio
    async def test_cannot_delete_other_tenant_targets(self, two_tenant_setup):
        """User from tenant B should not delete tenant A's targets."""
        from sqlalchemy import select

        data = two_tenant_setup
        target_a = data["target_a"]
        target_a_id = target_a.id

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.delete(f"/api/targets/{target_a.id}")
            assert response.status_code == 404

        # CRITICAL: Verify target was NOT deleted from database
        target_after = (await data["session"].execute(
            select(ScanTarget).where(ScanTarget.id == target_a_id)
        )).scalar_one_or_none()
        assert target_after is not None, \
            "TENANT ISOLATION BREACH: Target deleted by user from different tenant!"


    @pytest.mark.asyncio
    async def test_cannot_scan_using_other_tenant_target(self, two_tenant_setup):
        """User from tenant B should not create scan using tenant A's target."""
        from sqlalchemy import select, func

        data = two_tenant_setup
        target_a = data["target_a"]
        target_a_id = target_a.id

        # Count scans using tenant A's target before attempt
        count_before = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.target_id == target_a_id)
        )).scalar()

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                "/api/scans",
                json={"target_id": str(target_a.id)},
            )
            # Should fail - either 404 (target not found) or 400/422 (validation)
            assert response.status_code in (400, 404, 422), \
                f"Expected error for cross-tenant scan, got {response.status_code}"

        # CRITICAL: Verify no scan was created using tenant A's target
        count_after = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.target_id == target_a_id)
        )).scalar()
        assert count_after == count_before, \
            f"TENANT ISOLATION BREACH: Scan created using other tenant's target! Before: {count_before}, After: {count_after}"



class TestResultTenantIsolation:
    """Tests for tenant isolation in scan results."""

    @pytest.mark.asyncio
    async def test_cannot_view_other_tenant_results(self, two_tenant_setup):
        """User from tenant B should not see tenant A's results."""
        data = two_tenant_setup
        result_a = data["result_a"]

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/results/{result_a.id}")
            assert response.status_code == 404


    @pytest.mark.asyncio
    async def test_cannot_apply_label_to_other_tenant_result(self, two_tenant_setup):
        """User from tenant B should not apply labels to tenant A's results."""
        data = two_tenant_setup
        result_a = data["result_a"]

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                f"/api/results/{result_a.id}/label",
                json={"label_id": "some-label-id"},
            )
            assert response.status_code == 404



class TestRemediationTenantIsolation:
    """Tests for tenant isolation in remediation actions."""

    @pytest.mark.asyncio
    async def test_cannot_quarantine_other_tenant_files(self, two_tenant_setup):
        """User from tenant B should not quarantine tenant A's files."""
        data = two_tenant_setup
        result_a = data["result_a"]

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                "/api/remediation/quarantine",
                json={"result_id": str(result_a.id)},
            )
            # Should fail - 404 or 400/422
            assert response.status_code in (400, 404, 422)


    @pytest.mark.asyncio
    async def test_cannot_lockdown_other_tenant_files(self, two_tenant_setup):
        """User from tenant B should not lockdown tenant A's files."""
        data = two_tenant_setup
        result_a = data["result_a"]

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                "/api/remediation/lockdown",
                json={"result_id": str(result_a.id)},
            )
            assert response.status_code in (400, 404, 422)



class TestScheduleTenantIsolation:
    """Tests for tenant isolation in schedules."""

    @pytest.mark.asyncio
    async def test_cannot_view_other_tenant_schedules(self, two_tenant_setup):
        """User from tenant B should not see tenant A's schedules."""
        data = two_tenant_setup
        schedule_a = data["schedule_a"]

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/schedules/{schedule_a.id}")
            assert response.status_code == 404


    @pytest.mark.asyncio
    async def test_cannot_trigger_other_tenant_schedules(self, two_tenant_setup):
        """User from tenant B should not trigger tenant A's schedules."""
        from sqlalchemy import select, func

        data = two_tenant_setup
        schedule_a = data["schedule_a"]
        schedule_a_id = schedule_a.id
        tenant_a_id = data["tenant_a"].id

        # Count scans for tenant A before trigger attempt
        count_before = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.tenant_id == tenant_a_id)
        )).scalar()

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.post(f"/api/schedules/{schedule_a.id}/trigger")
            assert response.status_code == 404

        # CRITICAL: Verify no scan was triggered for tenant A
        count_after = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.tenant_id == tenant_a_id)
        )).scalar()
        assert count_after == count_before, \
            f"TENANT ISOLATION BREACH: Schedule triggered by user from different tenant! Created {count_after - count_before} scans"


    @pytest.mark.asyncio
    async def test_list_schedules_only_shows_own_tenant(self, two_tenant_setup):
        """Listing schedules should only return current tenant's schedules."""
        data = two_tenant_setup

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/schedules")
            assert response.status_code == 200

            schedules = response.json()
            items = schedules.get("items", schedules) if isinstance(schedules, dict) else schedules

            schedule_a_id = str(data["schedule_a"].id)
            for schedule in items:
                assert schedule.get("id") != schedule_a_id, \
                    "Tenant B can see Tenant A's schedule - isolation failure!"



class TestAuditLogTenantIsolation:
    """Tests for tenant isolation in audit logs."""

    @pytest.mark.asyncio
    async def test_cannot_view_other_tenant_audit_logs(self, two_tenant_setup):
        """User from tenant B should not see tenant A's audit logs."""
        data = two_tenant_setup
        audit_a = data["audit_a"]

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/audit/{audit_a.id}")
            assert response.status_code == 404


    @pytest.mark.asyncio
    async def test_list_audit_logs_only_shows_own_tenant(self, two_tenant_setup):
        """Listing audit logs should only return current tenant's logs."""
        data = two_tenant_setup

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/audit")
            assert response.status_code == 200

            result = response.json()
            items = result.get("items", [])

            audit_a_id = str(data["audit_a"].id)
            for log in items:
                assert log.get("id") != audit_a_id, \
                    "Tenant B can see Tenant A's audit log - isolation failure!"



class TestIDORPrevention:
    """Tests for Insecure Direct Object Reference prevention."""

    @pytest.mark.asyncio
    async def test_uuid_enumeration_returns_404(self, two_tenant_setup):
        """Attempting to access non-existent UUIDs should return 404."""
        data = two_tenant_setup

        async with create_client_for_user(
            data["session"], data["user_a"], data["tenant_a"]
        ) as client:
            fake_id = uuid4()

            # All these should return 404, not different error codes
            # that could leak information
            responses = await asyncio.gather(
                client.get(f"/api/scans/{fake_id}"),
                client.get(f"/api/targets/{fake_id}"),
                client.get(f"/api/results/{fake_id}"),
                client.get(f"/api/schedules/{fake_id}"),
            )

            for response in responses:
                assert response.status_code == 404


    @pytest.mark.asyncio
    async def test_cross_tenant_returns_same_as_nonexistent(self, two_tenant_setup):
        """Cross-tenant access should return same error as non-existent resource."""
        data = two_tenant_setup
        scan_a = data["scan_a"]
        fake_id = uuid4()

        async with create_client_for_user(
            data["session"], data["user_b"], data["tenant_b"]
        ) as client:
            # Cross-tenant access
            cross_tenant_response = await client.get(f"/api/scans/{scan_a.id}")

            # Non-existent resource
            nonexistent_response = await client.get(f"/api/scans/{fake_id}")

            # Both should return 404 - same response to prevent enumeration
            assert cross_tenant_response.status_code == nonexistent_response.status_code == 404


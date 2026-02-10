"""
Comprehensive IDOR (Insecure Direct Object Reference) and Cross-Tenant Security Tests.

These tests systematically verify that:
1. Users cannot access resources belonging to other tenants
2. Users cannot access resources belonging to other users in same tenant
3. Role-based access control is properly enforced
4. Resource enumeration attacks are prevented (consistent 404 responses)

Critical security principle: Cross-tenant and unauthorized access should return 404
(not 403) to prevent resource enumeration attacks.
"""

import asyncio
import contextlib
import pytest
import random
import string
from uuid import uuid4
from datetime import datetime, timezone

from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient, ASGITransport
from openlabels.server.app import app
from openlabels.server.db import get_session
from openlabels.server.dependencies import get_db_session
from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin, CurrentUser
from openlabels.server.models import (
    Tenant, User, ScanJob, ScanResult, ScanTarget,
    ScanSchedule, AuditLog, JobQueue as JobQueueModel,
)


# =============================================================================
# FIXTURES
# =============================================================================


def _generate_suffix():
    """Generate unique suffix to prevent test data collisions."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


@pytest.fixture
async def multi_tenant_idor_setup(test_db):
    """
    Set up a comprehensive multi-tenant environment for IDOR testing.

    Creates:
    - Tenant A with admin user A and viewer user A
    - Tenant B with admin user B
    - Resources (targets, scans, results, schedules, audit logs, jobs) for each tenant
    """
    suffix = _generate_suffix()

    # ========== Tenant A Setup ==========
    tenant_a = Tenant(
        id=uuid4(),
        name=f"IDOR Tenant A {suffix}",
        azure_tenant_id=f"idor-tenant-a-{suffix}",
    )
    test_db.add(tenant_a)
    await test_db.flush()

    # Admin user for Tenant A
    admin_a = User(
        id=uuid4(),
        tenant_id=tenant_a.id,
        email=f"admin-a-{suffix}@tenant-a.com",
        name="Admin User A",
        role="admin",
    )
    test_db.add(admin_a)
    await test_db.flush()

    # Viewer user for Tenant A (for horizontal escalation tests)
    viewer_a = User(
        id=uuid4(),
        tenant_id=tenant_a.id,
        email=f"viewer-a-{suffix}@tenant-a.com",
        name="Viewer User A",
        role="viewer",
    )
    test_db.add(viewer_a)
    await test_db.flush()

    # Target for Tenant A
    target_a = ScanTarget(
        id=uuid4(),
        tenant_id=tenant_a.id,
        name=f"IDOR Target A {suffix}",
        adapter="filesystem",
        config={"path": "/tenant-a/sensitive-data"},
        enabled=True,
        created_by=admin_a.id,
    )
    test_db.add(target_a)
    await test_db.flush()

    # Scan job for Tenant A
    scan_a = ScanJob(
        id=uuid4(),
        tenant_id=tenant_a.id,
        target_id=target_a.id,
        name=f"IDOR Scan A {suffix}",
        status="completed",
        files_scanned=100,
        files_with_pii=10,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        created_by=admin_a.id,
    )
    test_db.add(scan_a)
    await test_db.flush()

    # Result for Tenant A
    result_a = ScanResult(
        id=uuid4(),
        tenant_id=tenant_a.id,
        job_id=scan_a.id,
        file_path="/tenant-a/sensitive-data/secret.txt",
        file_name="secret.txt",
        risk_score=95,
        risk_tier="CRITICAL",
        entity_counts={"SSN": 10, "CREDIT_CARD": 5},
        total_entities=15,
    )
    test_db.add(result_a)
    await test_db.flush()

    # Schedule for Tenant A
    schedule_a = ScanSchedule(
        id=uuid4(),
        tenant_id=tenant_a.id,
        target_id=target_a.id,
        name=f"IDOR Schedule A {suffix}",
        cron="0 2 * * *",
        enabled=True,
        created_by=admin_a.id,
    )
    test_db.add(schedule_a)
    await test_db.flush()

    # Audit log for Tenant A
    audit_a = AuditLog(
        id=uuid4(),
        tenant_id=tenant_a.id,
        user_id=admin_a.id,
        action="scan_completed",
        resource_type="scan",
        resource_id=scan_a.id,
        details={"files_scanned": 100, "pii_found": 15},
    )
    test_db.add(audit_a)
    await test_db.flush()

    # Job queue entry for Tenant A
    job_a = JobQueueModel(
        id=uuid4(),
        tenant_id=tenant_a.id,
        task_type="scan",
        payload={"target_id": str(target_a.id)},
        priority=50,
        status="failed",
        error="Test error for IDOR testing",
        retry_count=3,
    )
    test_db.add(job_a)
    await test_db.flush()

    # ========== Tenant B Setup ==========
    tenant_b = Tenant(
        id=uuid4(),
        name=f"IDOR Tenant B {suffix}",
        azure_tenant_id=f"idor-tenant-b-{suffix}",
    )
    test_db.add(tenant_b)
    await test_db.flush()

    # Admin user for Tenant B
    admin_b = User(
        id=uuid4(),
        tenant_id=tenant_b.id,
        email=f"admin-b-{suffix}@tenant-b.com",
        name="Admin User B",
        role="admin",
    )
    test_db.add(admin_b)
    await test_db.flush()

    # Target for Tenant B
    target_b = ScanTarget(
        id=uuid4(),
        tenant_id=tenant_b.id,
        name=f"IDOR Target B {suffix}",
        adapter="filesystem",
        config={"path": "/tenant-b/data"},
        enabled=True,
        created_by=admin_b.id,
    )
    test_db.add(target_b)
    await test_db.flush()

    # Scan job for Tenant B
    scan_b = ScanJob(
        id=uuid4(),
        tenant_id=tenant_b.id,
        target_id=target_b.id,
        name=f"IDOR Scan B {suffix}",
        status="completed",
        created_by=admin_b.id,
    )
    test_db.add(scan_b)
    await test_db.flush()

    # Result for Tenant B
    result_b = ScanResult(
        id=uuid4(),
        tenant_id=tenant_b.id,
        job_id=scan_b.id,
        file_path="/tenant-b/data/file.txt",
        file_name="file.txt",
        risk_score=50,
        risk_tier="MEDIUM",
        entity_counts={"EMAIL": 2},
        total_entities=2,
    )
    test_db.add(result_b)
    await test_db.flush()

    # Schedule for Tenant B
    schedule_b = ScanSchedule(
        id=uuid4(),
        tenant_id=tenant_b.id,
        target_id=target_b.id,
        name=f"IDOR Schedule B {suffix}",
        cron="0 3 * * *",
        enabled=True,
        created_by=admin_b.id,
    )
    test_db.add(schedule_b)
    await test_db.flush()

    # Audit log for Tenant B
    audit_b = AuditLog(
        id=uuid4(),
        tenant_id=tenant_b.id,
        user_id=admin_b.id,
        action="target_created",
        resource_type="target",
        resource_id=target_b.id,
        details={"name": "IDOR Target B"},
    )
    test_db.add(audit_b)
    await test_db.flush()

    # Job queue entry for Tenant B
    job_b = JobQueueModel(
        id=uuid4(),
        tenant_id=tenant_b.id,
        task_type="label",
        payload={"file_id": str(uuid4())},
        priority=50,
        status="pending",
    )
    test_db.add(job_b)
    await test_db.flush()

    await test_db.commit()

    # Refresh all objects
    for obj in [tenant_a, admin_a, viewer_a, target_a, scan_a, result_a, schedule_a,
                audit_a, job_a, tenant_b, admin_b, target_b, scan_b, result_b,
                schedule_b, audit_b, job_b]:
        await test_db.refresh(obj)

    return {
        # Tenant A
        "tenant_a": tenant_a,
        "admin_a": admin_a,
        "viewer_a": viewer_a,
        "target_a": target_a,
        "scan_a": scan_a,
        "result_a": result_a,
        "schedule_a": schedule_a,
        "audit_a": audit_a,
        "job_a": job_a,
        # Tenant B
        "tenant_b": tenant_b,
        "admin_b": admin_b,
        "target_b": target_b,
        "scan_b": scan_b,
        "result_b": result_b,
        "schedule_b": schedule_b,
        "audit_b": audit_b,
        "job_b": job_b,
        # Session
        "session": test_db,
    }


@contextlib.asynccontextmanager
async def create_client_for_user(test_db, user, tenant, role_override=None):
    """
    Create a test client authenticated as a specific user.

    Args:
        test_db: Database session
        user: User object to authenticate as
        tenant: Tenant object
        role_override: Override role for testing (e.g., 'viewer' for admin user)
    """
    from openlabels.server.app import limiter as app_limiter
    from openlabels.server.routes.remediation import limiter as remediation_limiter
    from openlabels.server.routes.scans import limiter as scans_limiter
    from openlabels.server.routes.auth import limiter as auth_limiter
    from fastapi import HTTPException

    role = role_override or str(user.role)

    async def override_get_session():
        yield test_db

    def _create_current_user():
        return CurrentUser(
            id=user.id,
            tenant_id=tenant.id,
            email=user.email,
            name=user.name,
            role=role,
        )

    async def override_get_current_user():
        return _create_current_user()

    async def override_get_optional_user():
        return _create_current_user()

    async def override_require_admin():
        if role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        return _create_current_user()

    # Save original limiter states
    limiters = [app_limiter, remediation_limiter, scans_limiter, auth_limiter]
    original_states = [l.enabled for l in limiters]

    # Set up overrides
    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_db_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_optional_user] = override_get_optional_user
    app.dependency_overrides[require_admin] = override_require_admin

    # Disable rate limiting
    for limiter in limiters:
        limiter.enabled = False

    mock_cache = MagicMock()
    mock_cache.is_redis_connected = False
    try:
        with patch("openlabels.server.lifespan.init_db", new_callable=AsyncMock), \
             patch("openlabels.server.lifespan.close_db", new_callable=AsyncMock), \
             patch("openlabels.server.lifespan.get_cache_manager", new_callable=AsyncMock, return_value=mock_cache), \
             patch("openlabels.server.lifespan.close_cache", new_callable=AsyncMock):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://localhost"
            ) as client:
                yield client
    finally:
        app.dependency_overrides.clear()
        for limiter, state in zip(limiters, original_states):
            limiter.enabled = state


# =============================================================================
# IDOR TESTS - TARGETS
# =============================================================================


class TestTargetIDOR:
    """IDOR tests for scan target endpoints."""

    async def test_cannot_get_other_tenant_target(self, multi_tenant_idor_setup):
        """User B cannot GET target belonging to tenant A."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/targets/{data['target_a'].id}")
            assert response.status_code == 404, \
                f"Cross-tenant target access should return 404, got {response.status_code}"

    async def test_cannot_update_other_tenant_target(self, multi_tenant_idor_setup):
        """User B cannot PUT (update) target belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        original_name = data["target_a"].name
        target_id = data["target_a"].id

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.put(
                f"/api/targets/{data['target_a'].id}",
                json={"name": "HACKED BY TENANT B", "config": {"path": "/evil"}},
            )
            assert response.status_code == 404

        # Verify target was NOT modified
        target = (await data["session"].execute(
            select(ScanTarget).where(ScanTarget.id == target_id)
        )).scalar_one()
        assert target.name == original_name, \
            "CRITICAL: Target modified despite 404 response!"

    async def test_cannot_delete_other_tenant_target(self, multi_tenant_idor_setup):
        """User B cannot DELETE target belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        target_id = data["target_a"].id

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.delete(f"/api/targets/{data['target_a'].id}")
            assert response.status_code == 404

        # Verify target still exists
        target = (await data["session"].execute(
            select(ScanTarget).where(ScanTarget.id == target_id)
        )).scalar_one_or_none()
        assert target is not None, \
            "CRITICAL: Target deleted by cross-tenant user!"

    async def test_target_list_excludes_other_tenant(self, multi_tenant_idor_setup):
        """Target list should only show current tenant's targets."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/targets")
            assert response.status_code == 200

            targets = response.json()
            items = targets.get("items", targets) if isinstance(targets, dict) else targets

            target_a_id = str(data["target_a"].id)
            for target in items:
                assert target.get("id") != target_a_id, \
                    "CRITICAL: Tenant B can see Tenant A's target in list!"


# =============================================================================
# IDOR TESTS - SCANS
# =============================================================================


class TestScanIDOR:
    """IDOR tests for scan job endpoints."""

    async def test_cannot_get_other_tenant_scan(self, multi_tenant_idor_setup):
        """User B cannot GET scan belonging to tenant A."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/scans/{data['scan_a'].id}")
            assert response.status_code == 404

    async def test_cannot_cancel_other_tenant_scan(self, multi_tenant_idor_setup):
        """User B cannot DELETE (cancel) scan belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        scan_id = data["scan_a"].id
        original_status = data["scan_a"].status

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.delete(f"/api/scans/{data['scan_a'].id}")
            assert response.status_code == 404

        # Verify scan status unchanged
        scan = (await data["session"].execute(
            select(ScanJob).where(ScanJob.id == scan_id)
        )).scalar_one()
        assert scan.status == original_status, \
            "CRITICAL: Scan cancelled by cross-tenant user!"

    async def test_cannot_create_scan_with_other_tenant_target(self, multi_tenant_idor_setup):
        """User B cannot create scan using tenant A's target."""
        from sqlalchemy import select, func

        data = multi_tenant_idor_setup
        target_a_id = data["target_a"].id

        # Count scans before attempt
        count_before = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.target_id == target_a_id)
        )).scalar()

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                "/api/scans",
                json={"target_id": str(target_a_id)},
            )
            assert response.status_code in (400, 404, 422)

        # Verify no scan was created
        count_after = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.target_id == target_a_id)
        )).scalar()
        assert count_after == count_before, \
            "CRITICAL: Scan created using cross-tenant target!"

    async def test_scan_list_excludes_other_tenant(self, multi_tenant_idor_setup):
        """Scan list should only show current tenant's scans."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/scans")
            assert response.status_code == 200

            scans = response.json()
            items = scans.get("items", scans) if isinstance(scans, dict) else scans

            scan_a_id = str(data["scan_a"].id)
            for scan in items:
                assert scan.get("id") != scan_a_id, \
                    "CRITICAL: Tenant B can see Tenant A's scan in list!"


# =============================================================================
# IDOR TESTS - RESULTS
# =============================================================================


class TestResultIDOR:
    """IDOR tests for scan result endpoints."""

    async def test_cannot_get_other_tenant_result(self, multi_tenant_idor_setup):
        """User B cannot GET result belonging to tenant A."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/results/{data['result_a'].id}")
            assert response.status_code == 404

    async def test_cannot_delete_other_tenant_result(self, multi_tenant_idor_setup):
        """User B cannot DELETE result belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        result_id = data["result_a"].id

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.delete(f"/api/results/{data['result_a'].id}")
            assert response.status_code == 404

        # Verify result still exists
        result = (await data["session"].execute(
            select(ScanResult).where(ScanResult.id == result_id)
        )).scalar_one_or_none()
        assert result is not None, \
            "CRITICAL: Result deleted by cross-tenant user!"

    async def test_cannot_apply_label_to_other_tenant_result(self, multi_tenant_idor_setup):
        """User B cannot apply labels to tenant A's results."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                f"/api/results/{data['result_a'].id}/apply-label",
            )
            assert response.status_code == 404

    async def test_cannot_rescan_other_tenant_result(self, multi_tenant_idor_setup):
        """User B cannot trigger rescan of tenant A's result."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                f"/api/results/{data['result_a'].id}/rescan",
            )
            assert response.status_code == 404

    async def test_result_list_excludes_other_tenant(self, multi_tenant_idor_setup):
        """Result list should only show current tenant's results."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/results")
            assert response.status_code == 200

            results = response.json()
            items = results.get("items", [])

            result_a_id = str(data["result_a"].id)
            for result in items:
                assert result.get("id") != result_a_id, \
                    "CRITICAL: Tenant B can see Tenant A's result in list!"


# =============================================================================
# IDOR TESTS - SCHEDULES
# =============================================================================


class TestScheduleIDOR:
    """IDOR tests for scan schedule endpoints."""

    async def test_cannot_get_other_tenant_schedule(self, multi_tenant_idor_setup):
        """User B cannot GET schedule belonging to tenant A."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/schedules/{data['schedule_a'].id}")
            assert response.status_code == 404

    async def test_cannot_update_other_tenant_schedule(self, multi_tenant_idor_setup):
        """User B cannot PUT (update) schedule belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        schedule_id = data["schedule_a"].id
        original_name = data["schedule_a"].name

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.put(
                f"/api/schedules/{data['schedule_a'].id}",
                json={"name": "HACKED SCHEDULE", "cron": "* * * * *"},
            )
            assert response.status_code == 404

        # Verify schedule unchanged
        schedule = (await data["session"].execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )).scalar_one()
        assert schedule.name == original_name, \
            "CRITICAL: Schedule modified by cross-tenant user!"

    async def test_cannot_delete_other_tenant_schedule(self, multi_tenant_idor_setup):
        """User B cannot DELETE schedule belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        schedule_id = data["schedule_a"].id

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.delete(f"/api/schedules/{data['schedule_a'].id}")
            assert response.status_code == 404

        # Verify schedule still exists
        schedule = (await data["session"].execute(
            select(ScanSchedule).where(ScanSchedule.id == schedule_id)
        )).scalar_one_or_none()
        assert schedule is not None, \
            "CRITICAL: Schedule deleted by cross-tenant user!"

    async def test_cannot_trigger_other_tenant_schedule(self, multi_tenant_idor_setup):
        """User B cannot trigger tenant A's schedule."""
        from sqlalchemy import select, func

        data = multi_tenant_idor_setup
        tenant_a_id = data["tenant_a"].id

        # Count scans before trigger attempt
        count_before = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.tenant_id == tenant_a_id)
        )).scalar()

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(f"/api/schedules/{data['schedule_a'].id}/run")
            assert response.status_code == 404

        # Verify no scan was created
        count_after = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(ScanJob.tenant_id == tenant_a_id)
        )).scalar()
        assert count_after == count_before, \
            "CRITICAL: Schedule triggered by cross-tenant user!"

    async def test_cannot_create_schedule_with_other_tenant_target(self, multi_tenant_idor_setup):
        """User B cannot create schedule for tenant A's target."""
        from sqlalchemy import select, func

        data = multi_tenant_idor_setup

        count_before = (await data["session"].execute(
            select(func.count(ScanSchedule.id))
        )).scalar()

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                "/api/schedules",
                json={
                    "name": "Evil Schedule",
                    "target_id": str(data["target_a"].id),
                    "cron": "0 0 * * *",
                },
            )
            assert response.status_code == 404

        # Verify no schedule created
        count_after = (await data["session"].execute(
            select(func.count(ScanSchedule.id))
        )).scalar()
        assert count_after == count_before, \
            "CRITICAL: Schedule created for cross-tenant target!"


# =============================================================================
# IDOR TESTS - AUDIT LOGS
# =============================================================================


class TestAuditLogIDOR:
    """IDOR tests for audit log endpoints."""

    async def test_cannot_get_other_tenant_audit_log(self, multi_tenant_idor_setup):
        """User B cannot GET audit log belonging to tenant A."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/audit/{data['audit_a'].id}")
            assert response.status_code == 404

    async def test_audit_list_excludes_other_tenant(self, multi_tenant_idor_setup):
        """Audit log list should only show current tenant's logs."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/audit")
            assert response.status_code == 200

            result = response.json()
            items = result.get("items", [])

            audit_a_id = str(data["audit_a"].id)
            for log in items:
                assert log.get("id") != audit_a_id, \
                    "CRITICAL: Tenant B can see Tenant A's audit log in list!"

    async def test_resource_history_excludes_other_tenant(self, multi_tenant_idor_setup):
        """Resource history should not reveal cross-tenant resources."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            # Try to get history for tenant A's scan
            response = await client.get(
                f"/api/audit/resource/scan/{data['scan_a'].id}"
            )
            assert response.status_code == 200

            # Should return empty items (not 404, as resource type is valid)
            history = response.json()
            items = history.get("items", []) if isinstance(history, dict) else history
            assert items == [], \
                "CRITICAL: Cross-tenant resource history was returned!"


# =============================================================================
# IDOR TESTS - JOBS (JOB QUEUE)
# =============================================================================


class TestJobQueueIDOR:
    """IDOR tests for job queue endpoints."""

    async def test_cannot_get_other_tenant_job(self, multi_tenant_idor_setup):
        """User B cannot GET job belonging to tenant A."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/jobs/{data['job_a'].id}")
            assert response.status_code == 404

    async def test_cannot_requeue_other_tenant_job(self, multi_tenant_idor_setup):
        """User B cannot requeue job belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        job_id = data["job_a"].id

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                f"/api/jobs/{job_id}/requeue",
                json={"reset_retries": True},
            )
            assert response.status_code == 404

        # Verify job status unchanged
        job = (await data["session"].execute(
            select(JobQueueModel).where(JobQueueModel.id == job_id)
        )).scalar_one()
        assert job.status == "failed", \
            "CRITICAL: Job requeued by cross-tenant user!"

    async def test_cannot_cancel_other_tenant_job(self, multi_tenant_idor_setup):
        """User B cannot cancel job belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        job_id = data["job_a"].id
        original_status = data["job_a"].status

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(f"/api/jobs/{job_id}/cancel")
            assert response.status_code == 404

        # Verify job status unchanged
        job = (await data["session"].execute(
            select(JobQueueModel).where(JobQueueModel.id == job_id)
        )).scalar_one()
        assert job.status == original_status, \
            "CRITICAL: Job cancelled by cross-tenant user!"



# =============================================================================
# IDOR TESTS - USERS
# =============================================================================


class TestUserIDOR:
    """IDOR tests for user management endpoints."""

    async def test_cannot_get_other_tenant_user(self, multi_tenant_idor_setup):
        """User B cannot GET user belonging to tenant A."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get(f"/api/users/{data['admin_a'].id}")
            assert response.status_code == 404

    async def test_cannot_update_other_tenant_user(self, multi_tenant_idor_setup):
        """User B cannot update user belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        user_id = data["viewer_a"].id
        original_name = data["viewer_a"].name

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.put(
                f"/api/users/{user_id}",
                json={"name": "HACKED BY TENANT B", "role": "admin"},
            )
            assert response.status_code == 404

        # Verify user unchanged
        user = (await data["session"].execute(
            select(User).where(User.id == user_id)
        )).scalar_one()
        assert user.name == original_name, \
            "CRITICAL: User modified by cross-tenant admin!"
        assert user.role == "viewer", \
            "CRITICAL: User role escalated by cross-tenant admin!"

    async def test_cannot_delete_other_tenant_user(self, multi_tenant_idor_setup):
        """User B cannot delete user belonging to tenant A."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        user_id = data["viewer_a"].id

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.delete(f"/api/users/{user_id}")
            assert response.status_code == 404

        # Verify user still exists
        user = (await data["session"].execute(
            select(User).where(User.id == user_id)
        )).scalar_one_or_none()
        assert user is not None, \
            "CRITICAL: User deleted by cross-tenant admin!"

    async def test_user_list_excludes_other_tenant(self, multi_tenant_idor_setup):
        """User list should only show current tenant's users."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.get("/api/users")
            assert response.status_code == 200

            users_response = response.json()
            user_items = users_response.get("items", users_response) if isinstance(users_response, dict) else users_response

            tenant_a_user_ids = [
                str(data["admin_a"].id),
                str(data["viewer_a"].id),
            ]
            for user in user_items:
                assert user.get("id") not in tenant_a_user_ids, \
                    "CRITICAL: Tenant B can see Tenant A's users!"


# =============================================================================
# HORIZONTAL PRIVILEGE ESCALATION TESTS
# =============================================================================


class TestHorizontalPrivilegeEscalation:
    """Tests for horizontal privilege escalation within same tenant."""

    async def test_viewer_cannot_modify_other_users_resources(self, multi_tenant_idor_setup):
        """Viewer user cannot modify resources created by admin in same tenant."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        target_id = data["target_a"].id
        original_name = data["target_a"].name

        # Viewer A tries to modify Admin A's target
        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            response = await client.put(
                f"/api/targets/{target_id}",
                json={"name": "Modified by viewer"},
            )
            # Should be 403 (forbidden) since viewer cannot write
            assert response.status_code == 403, \
                f"Expected 403 for viewer modifying target, got {response.status_code}"

        # Verify target unchanged
        target = (await data["session"].execute(
            select(ScanTarget).where(ScanTarget.id == target_id)
        )).scalar_one()
        assert target.name == original_name, \
            "CRITICAL: Target modified by viewer user!"

    async def test_viewer_cannot_delete_other_users_resources(self, multi_tenant_idor_setup):
        """Viewer user cannot delete resources created by admin in same tenant."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        target_id = data["target_a"].id

        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            response = await client.delete(f"/api/targets/{target_id}")
            assert response.status_code == 403

        # Verify target still exists
        target = (await data["session"].execute(
            select(ScanTarget).where(ScanTarget.id == target_id)
        )).scalar_one_or_none()
        assert target is not None, \
            "CRITICAL: Target deleted by viewer user!"

    async def test_user_cannot_modify_own_role(self, multi_tenant_idor_setup):
        """User cannot elevate their own role."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup
        viewer_id = data["viewer_a"].id

        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            response = await client.put(
                f"/api/users/{viewer_id}",
                json={"role": "admin"},
            )
            # Should be denied (403 for viewers, or 400 for validation)
            assert response.status_code in (400, 403, 422), \
                f"Self-role modification should be denied, got {response.status_code}"

        # Verify role unchanged
        user = (await data["session"].execute(
            select(User).where(User.id == viewer_id)
        )).scalar_one()
        assert user.role == "viewer", \
            "CRITICAL: User self-elevated to admin!"


# =============================================================================
# VERTICAL PRIVILEGE ESCALATION TESTS
# =============================================================================


class TestVerticalPrivilegeEscalation:
    """Tests for vertical privilege escalation (viewer -> admin actions)."""

    async def test_viewer_cannot_create_targets(self, multi_tenant_idor_setup):
        """Viewer cannot create scan targets (admin-only operation)."""
        from sqlalchemy import select, func

        data = multi_tenant_idor_setup

        count_before = (await data["session"].execute(
            select(func.count(ScanTarget.id)).where(
                ScanTarget.tenant_id == data["tenant_a"].id
            )
        )).scalar()

        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            response = await client.post(
                "/api/targets",
                json={
                    "name": "Unauthorized Target",
                    "adapter": "filesystem",
                    "config": {"path": "/unauthorized"},
                },
            )
            assert response.status_code == 403

        # Verify no target created
        count_after = (await data["session"].execute(
            select(func.count(ScanTarget.id)).where(
                ScanTarget.tenant_id == data["tenant_a"].id
            )
        )).scalar()
        assert count_after == count_before, \
            "CRITICAL: Target created by viewer!"

    async def test_viewer_cannot_create_schedules(self, multi_tenant_idor_setup):
        """Viewer cannot create scan schedules (admin-only operation)."""
        from sqlalchemy import select, func

        data = multi_tenant_idor_setup

        count_before = (await data["session"].execute(
            select(func.count(ScanSchedule.id)).where(
                ScanSchedule.tenant_id == data["tenant_a"].id
            )
        )).scalar()

        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            response = await client.post(
                "/api/schedules",
                json={
                    "name": "Unauthorized Schedule",
                    "target_id": str(data["target_a"].id),
                },
            )
            assert response.status_code == 403

        # Verify no schedule created
        count_after = (await data["session"].execute(
            select(func.count(ScanSchedule.id)).where(
                ScanSchedule.tenant_id == data["tenant_a"].id
            )
        )).scalar()
        assert count_after == count_before, \
            "CRITICAL: Schedule created by viewer!"

    async def test_viewer_cannot_start_scans(self, multi_tenant_idor_setup):
        """Viewer cannot start scans (admin-only operation)."""
        from sqlalchemy import select, func

        data = multi_tenant_idor_setup

        count_before = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(
                ScanJob.tenant_id == data["tenant_a"].id
            )
        )).scalar()

        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            response = await client.post(
                "/api/scans",
                json={"target_id": str(data["target_a"].id)},
            )
            assert response.status_code == 403

        # Verify no scan created
        count_after = (await data["session"].execute(
            select(func.count(ScanJob.id)).where(
                ScanJob.tenant_id == data["tenant_a"].id
            )
        )).scalar()
        assert count_after == count_before, \
            "CRITICAL: Scan started by viewer!"

    async def test_viewer_cannot_create_users(self, multi_tenant_idor_setup):
        """Viewer cannot create users (admin-only operation)."""
        from sqlalchemy import select

        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            response = await client.post(
                "/api/users",
                json={
                    "email": "hacker@evil.com",
                    "name": "Hacker",
                    "role": "admin",
                },
            )
            assert response.status_code == 403

        # Verify no user created
        user = (await data["session"].execute(
            select(User).where(User.email == "hacker@evil.com")
        )).scalar_one_or_none()
        assert user is None, \
            "CRITICAL: Admin user created by viewer!"

    async def test_viewer_can_read_resources(self, multi_tenant_idor_setup):
        """Viewer CAN read resources (read is allowed for viewers)."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["viewer_a"], data["tenant_a"]
        ) as client:
            # These should all succeed for viewer
            endpoints = [
                "/api/targets",
                "/api/scans",
                "/api/results",
                "/api/schedules",
                "/api/dashboard/stats",
            ]

            for endpoint in endpoints:
                response = await client.get(endpoint)
                assert response.status_code == 200, \
                    f"Viewer should be able to read {endpoint}, got {response.status_code}"


# =============================================================================
# ENUMERATION PREVENTION TESTS
# =============================================================================


class TestEnumerationPrevention:
    """Tests to verify enumeration attacks are prevented."""

    async def test_cross_tenant_returns_same_as_nonexistent(self, multi_tenant_idor_setup):
        """
        Cross-tenant access should return the same response as non-existent resource.

        This prevents attackers from determining if a resource exists in another tenant.
        """
        data = multi_tenant_idor_setup
        fake_uuid = uuid4()

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            # Test various resource types
            endpoints = [
                f"/api/targets/{data['target_a'].id}",  # Cross-tenant
                f"/api/targets/{fake_uuid}",  # Non-existent
                f"/api/scans/{data['scan_a'].id}",  # Cross-tenant
                f"/api/scans/{fake_uuid}",  # Non-existent
                f"/api/results/{data['result_a'].id}",  # Cross-tenant
                f"/api/results/{fake_uuid}",  # Non-existent
                f"/api/schedules/{data['schedule_a'].id}",  # Cross-tenant
                f"/api/schedules/{fake_uuid}",  # Non-existent
            ]

            responses = await asyncio.gather(*[client.get(ep) for ep in endpoints])

            # All should return 404
            for i, response in enumerate(responses):
                assert response.status_code == 404, \
                    f"Endpoint {endpoints[i]} returned {response.status_code}, expected 404"

    async def test_bulk_uuid_enumeration_blocked(self, multi_tenant_idor_setup):
        """
        Attempting to enumerate UUIDs should return 404 for all.

        Tests that an attacker cannot determine valid UUIDs through bulk requests.
        """
        data = multi_tenant_idor_setup

        # Mix of real cross-tenant IDs and fake IDs
        test_ids = [
            data["target_a"].id,  # Real cross-tenant
            uuid4(),  # Fake
            data["scan_a"].id,  # Real cross-tenant
            uuid4(),  # Fake
            uuid4(),  # Fake
            data["result_a"].id,  # Real cross-tenant
        ]

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            for resource_id in test_ids:
                # Try different endpoints
                for endpoint_template in [
                    "/api/targets/{}",
                    "/api/scans/{}",
                    "/api/results/{}",
                    "/api/schedules/{}",
                ]:
                    response = await client.get(endpoint_template.format(resource_id))
                    assert response.status_code == 404, \
                        f"Enumeration possible: {endpoint_template.format(resource_id)} returned {response.status_code}"


# =============================================================================
# REMEDIATION IDOR TESTS
# =============================================================================


class TestRemediationIDOR:
    """IDOR tests for remediation endpoints."""

    async def test_cannot_quarantine_other_tenant_file(self, multi_tenant_idor_setup):
        """User B cannot quarantine files from tenant A's results."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                "/api/remediation/quarantine",
                json={"file_path": data["result_a"].file_path},
            )
            # Should fail with 400, 404, or 422
            assert response.status_code in (400, 403, 404, 422), \
                f"Cross-tenant quarantine should fail, got {response.status_code}"

    async def test_cannot_lockdown_other_tenant_file(self, multi_tenant_idor_setup):
        """User B cannot lockdown files from tenant A's results."""
        data = multi_tenant_idor_setup

        async with create_client_for_user(
            data["session"], data["admin_b"], data["tenant_b"]
        ) as client:
            response = await client.post(
                "/api/remediation/lockdown",
                json={
                    "file_path": data["result_a"].file_path,
                    "allowed_principals": ["SYSTEM"],
                },
            )
            assert response.status_code in (400, 403, 404, 422)

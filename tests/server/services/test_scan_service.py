"""Tests for ScanService."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from openlabels.server.services.base import TenantContext
from openlabels.server.services.scan_service import ScanService


def _make_service(session, tenant_id=None, user_id=None):
    tenant = TenantContext(
        tenant_id=tenant_id or uuid4(),
        user_id=user_id or uuid4(),
    )
    settings = MagicMock()
    return ScanService(session, tenant, settings)


@pytest.fixture
async def scan_fixtures(test_db):
    """Create a tenant, user, and scan target for testing."""
    from openlabels.server.models import Tenant, User, ScanTarget

    tenant = Tenant(name="Test Tenant Scan", azure_tenant_id="scan-test-tid")
    test_db.add(tenant)
    await test_db.flush()

    user = User(tenant_id=tenant.id, email="scan@test.com", name="Scanner", role="admin")
    test_db.add(user)
    await test_db.flush()

    target = ScanTarget(
        tenant_id=tenant.id,
        name="Test Target",
        adapter="filesystem",
        config={"path": "/tmp/test"},
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.commit()

    return {"tenant": tenant, "user": user, "target": target, "session": test_db}


class TestCreateScan:
    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_create_scan_happy_path(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        mock_queue = AsyncMock()
        MockJobQueue.return_value = mock_queue

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)

        assert job.status == "pending"
        assert job.tenant_id == f["tenant"].id
        assert job.target_id == f["target"].id
        assert job.target_name == "Test Target"
        mock_queue.enqueue.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_scan_missing_target(self, scan_fixtures):
        from openlabels.exceptions import NotFoundError

        f = scan_fixtures
        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)

        with pytest.raises(NotFoundError):
            await svc.create_scan(uuid4())


class TestGetScan:
    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_get_own_tenant(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)

        retrieved = await svc.get_scan(job.id)
        assert retrieved.id == job.id

    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_get_wrong_tenant_raises(self, MockJobQueue, scan_fixtures):
        from openlabels.exceptions import NotFoundError

        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)

        other_svc = _make_service(f["session"], uuid4(), uuid4())
        with pytest.raises(NotFoundError):
            await other_svc.get_scan(job.id)


class TestListScans:
    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_list_all(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        await svc.create_scan(f["target"].id)
        await svc.create_scan(f["target"].id)

        jobs, total = await svc.list_scans()
        assert total == 2
        assert len(jobs) == 2

    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_list_by_status(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        await svc.create_scan(f["target"].id)

        jobs, total = await svc.list_scans(status="pending")
        assert total == 1

        jobs, total = await svc.list_scans(status="running")
        assert total == 0

    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_invalid_status_returns_empty(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        await svc.create_scan(f["target"].id)

        jobs, total = await svc.list_scans(status="invalid_status")
        assert total == 0
        assert jobs == []


class TestCancelScan:
    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_cancel_pending(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)
        cancelled = await svc.cancel_scan(job.id)

        assert cancelled.status == "cancelled"
        assert cancelled.completed_at is not None

    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_cancel_completed_raises(self, MockJobQueue, scan_fixtures):
        from openlabels.exceptions import BadRequestError

        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)
        job.status = "completed"
        await f["session"].flush()

        with pytest.raises(BadRequestError):
            await svc.cancel_scan(job.id)


class TestRetryScan:
    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_retry_failed_scan(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        mock_queue = AsyncMock()
        MockJobQueue.return_value = mock_queue

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)
        job.status = "failed"
        await f["session"].flush()

        new_job = await svc.retry_scan(job.id)
        assert new_job.id != job.id
        assert new_job.status == "pending"
        assert "(retry)" in new_job.name

        # Should have been called with priority 60
        enqueue_calls = mock_queue.enqueue.call_args_list
        assert enqueue_calls[-1].kwargs.get("priority") == 60

    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_retry_running_raises(self, MockJobQueue, scan_fixtures):
        from openlabels.exceptions import BadRequestError

        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)

        with pytest.raises(BadRequestError):
            await svc.retry_scan(job.id)


class TestDeleteScan:
    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_delete_completed(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)
        job.status = "completed"
        await f["session"].flush()

        result = await svc.delete_scan(job.id)
        assert result is True

    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_delete_running_raises(self, MockJobQueue, scan_fixtures):
        from openlabels.exceptions import BadRequestError

        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        job = await svc.create_scan(f["target"].id)
        job.status = "running"
        await f["session"].flush()

        with pytest.raises(BadRequestError):
            await svc.delete_scan(job.id)


class TestScanStats:
    @pytest.mark.asyncio
    @patch("openlabels.server.services.scan_service.JobQueue")
    async def test_get_scan_stats(self, MockJobQueue, scan_fixtures):
        f = scan_fixtures
        MockJobQueue.return_value = AsyncMock()

        svc = _make_service(f["session"], f["tenant"].id, f["user"].id)
        j1 = await svc.create_scan(f["target"].id)
        j2 = await svc.create_scan(f["target"].id)
        j2.status = "completed"
        await f["session"].flush()

        stats = await svc.get_scan_stats()
        assert stats["pending"] == 1
        assert stats["completed"] == 1
        assert stats["total"] == 2

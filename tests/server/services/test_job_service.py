"""Tests for JobService (job orchestration)."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from openlabels.core.types import JobStatus
from openlabels.exceptions import BadRequestError, NotFoundError
from openlabels.server.services.base import TenantContext
from openlabels.server.services.job_service import JobService


def _make_service(session=None, tenant_id=None, user_id=None):
    """Create a JobService with mocked dependencies."""
    session = session or AsyncMock()
    tenant = TenantContext(
        tenant_id=tenant_id or uuid4(),
        user_id=user_id or uuid4(),
    )
    settings = MagicMock()
    return JobService(session, tenant, settings)


# ---------------------------------------------------------------------------
# Enqueue
# ---------------------------------------------------------------------------


class TestEnqueue:
    @pytest.mark.asyncio
    async def test_enqueue_valid_task_type(self):
        svc = _make_service()
        job_id = uuid4()
        svc._queue = AsyncMock()
        svc._queue.enqueue.return_value = job_id

        result = await svc.enqueue("scan", {"target_id": str(uuid4())})

        assert result == job_id
        svc._queue.enqueue.assert_awaited_once_with(
            task_type="scan",
            payload={"target_id": svc._queue.enqueue.call_args.kwargs["payload"]["target_id"]},
            priority=50,
        )

    @pytest.mark.asyncio
    async def test_enqueue_all_valid_types(self):
        for task_type in ("scan", "label", "export", "label_sync"):
            svc = _make_service()
            svc._queue = AsyncMock()
            svc._queue.enqueue.return_value = uuid4()

            result = await svc.enqueue(task_type, {"key": "value"})
            assert result is not None

    @pytest.mark.asyncio
    async def test_enqueue_invalid_task_type_raises(self):
        svc = _make_service()
        svc._queue = AsyncMock()

        with pytest.raises(BadRequestError, match="Invalid task type"):
            await svc.enqueue("invalid_type", {})

        svc._queue.enqueue.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_enqueue_custom_priority(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.enqueue.return_value = uuid4()

        await svc.enqueue("scan", {}, priority=90)

        svc._queue.enqueue.assert_awaited_once()
        assert svc._queue.enqueue.call_args.kwargs["priority"] == 90


# ---------------------------------------------------------------------------
# Get Job
# ---------------------------------------------------------------------------


class TestGetJob:
    @pytest.mark.asyncio
    async def test_get_job_returns_entity(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.id = job_id

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        result = await svc.get_job(job_id)
        assert result is mock_job

    @pytest.mark.asyncio
    async def test_get_job_not_found_raises(self):
        session = AsyncMock()
        session.get.return_value = None

        svc = _make_service(session=session)
        with pytest.raises(NotFoundError):
            await svc.get_job(uuid4())


# ---------------------------------------------------------------------------
# Cancel Job
# ---------------------------------------------------------------------------


class TestCancelJob:
    @pytest.mark.asyncio
    async def test_cancel_pending_job(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.id = job_id
        mock_job.status = JobStatus.PENDING

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        svc._queue = AsyncMock()
        svc._queue.cancel.return_value = True

        result = await svc.cancel_job(job_id)
        assert result is True
        svc._queue.cancel.assert_awaited_once_with(job_id)

    @pytest.mark.asyncio
    async def test_cancel_running_job(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.id = job_id
        mock_job.status = JobStatus.RUNNING

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        svc._queue = AsyncMock()
        svc._queue.cancel.return_value = True

        result = await svc.cancel_job(job_id)
        assert result is True

    @pytest.mark.asyncio
    async def test_cancel_completed_job_raises(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.id = job_id
        mock_job.status = JobStatus.COMPLETED

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        svc._queue = AsyncMock()

        with pytest.raises(BadRequestError, match="Cannot cancel"):
            await svc.cancel_job(job_id)

    @pytest.mark.asyncio
    async def test_cancel_failed_job_raises(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.id = job_id
        mock_job.status = JobStatus.FAILED

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        svc._queue = AsyncMock()

        with pytest.raises(BadRequestError, match="Cannot cancel"):
            await svc.cancel_job(job_id)


# ---------------------------------------------------------------------------
# Queue Stats
# ---------------------------------------------------------------------------


class TestGetQueueStats:
    @pytest.mark.asyncio
    async def test_get_queue_stats(self):
        svc = _make_service()
        expected_stats = {
            "pending": 5,
            "running": 2,
            "completed": 100,
            "failed": 3,
            "cancelled": 1,
            "failed_by_type": {"scan": 2, "label": 1},
        }
        svc._queue = AsyncMock()
        svc._queue.get_queue_stats.return_value = expected_stats

        result = await svc.get_queue_stats()
        assert result == expected_stats
        svc._queue.get_queue_stats.assert_awaited_once()


# ---------------------------------------------------------------------------
# List Jobs
# ---------------------------------------------------------------------------


class TestListJobs:
    @pytest.mark.asyncio
    async def test_list_jobs_delegates_to_paginate(self):
        """list_jobs builds a query with conditions and calls paginate."""
        tid = uuid4()
        svc = _make_service(tenant_id=tid)

        mock_jobs = [MagicMock(), MagicMock()]
        with patch.object(svc, "paginate", new_callable=AsyncMock) as mock_paginate:
            mock_paginate.return_value = (mock_jobs, 2)

            jobs, total = await svc.list_jobs(status="pending", task_type="scan")
            assert total == 2
            assert len(jobs) == 2
            mock_paginate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_list_jobs_no_filters(self):
        tid = uuid4()
        svc = _make_service(tenant_id=tid)

        with patch.object(svc, "paginate", new_callable=AsyncMock) as mock_paginate:
            mock_paginate.return_value = ([], 0)

            jobs, total = await svc.list_jobs()
            assert total == 0
            assert jobs == []


# ---------------------------------------------------------------------------
# Failed Jobs
# ---------------------------------------------------------------------------


class TestGetFailedJobs:
    @pytest.mark.asyncio
    async def test_get_failed_jobs(self):
        svc = _make_service()
        mock_jobs = [MagicMock()]
        svc._queue = AsyncMock()
        svc._queue.get_failed_count.return_value = 1
        svc._queue.get_failed_jobs.return_value = mock_jobs

        jobs, total = await svc.get_failed_jobs(task_type="scan")
        assert total == 1
        assert len(jobs) == 1
        svc._queue.get_failed_count.assert_awaited_once_with("scan")

    @pytest.mark.asyncio
    async def test_get_failed_jobs_pagination(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.get_failed_count.return_value = 10
        svc._queue.get_failed_jobs.return_value = [MagicMock()] * 5

        jobs, total = await svc.get_failed_jobs(limit=5, offset=5)
        assert total == 10
        assert len(jobs) == 5
        svc._queue.get_failed_jobs.assert_awaited_once_with(
            task_type=None, limit=5, offset=5,
        )


# ---------------------------------------------------------------------------
# Requeue Failed
# ---------------------------------------------------------------------------


class TestRequeueFailed:
    @pytest.mark.asyncio
    async def test_requeue_failed_job(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.id = job_id
        mock_job.status = JobStatus.FAILED

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        svc._queue = AsyncMock()
        svc._queue.requeue_failed.return_value = True

        result = await svc.requeue_failed(job_id)
        assert result is True
        svc._queue.requeue_failed.assert_awaited_once_with(
            job_id=job_id, reset_retries=True,
        )

    @pytest.mark.asyncio
    async def test_requeue_non_failed_raises(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.id = job_id
        mock_job.status = JobStatus.PENDING

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        svc._queue = AsyncMock()

        with pytest.raises(BadRequestError, match="Only failed jobs"):
            await svc.requeue_failed(job_id)

    @pytest.mark.asyncio
    async def test_requeue_without_reset_retries(self):
        tid = uuid4()
        job_id = uuid4()

        mock_job = MagicMock()
        mock_job.tenant_id = tid
        mock_job.status = JobStatus.FAILED

        session = AsyncMock()
        session.get.return_value = mock_job

        svc = _make_service(session=session, tenant_id=tid)
        svc._queue = AsyncMock()
        svc._queue.requeue_failed.return_value = True

        await svc.requeue_failed(job_id, reset_retries=False)
        svc._queue.requeue_failed.assert_awaited_once_with(
            job_id=job_id, reset_retries=False,
        )


# ---------------------------------------------------------------------------
# Requeue All Failed
# ---------------------------------------------------------------------------


class TestRequeueAllFailed:
    @pytest.mark.asyncio
    async def test_requeue_all_failed(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.requeue_all_failed.return_value = 5

        count = await svc.requeue_all_failed(task_type="scan")
        assert count == 5
        svc._queue.requeue_all_failed.assert_awaited_once_with(
            task_type="scan", reset_retries=True,
        )

    @pytest.mark.asyncio
    async def test_requeue_all_no_filter(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.requeue_all_failed.return_value = 0

        count = await svc.requeue_all_failed()
        assert count == 0


# ---------------------------------------------------------------------------
# Purge Failed
# ---------------------------------------------------------------------------


class TestPurgeFailed:
    @pytest.mark.asyncio
    async def test_purge_failed(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.purge_failed.return_value = 3

        count = await svc.purge_failed(task_type="scan", older_than_days=7)
        assert count == 3
        svc._queue.purge_failed.assert_awaited_once_with(
            task_type="scan", older_than_days=7,
        )

    @pytest.mark.asyncio
    async def test_purge_failed_no_filter(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.purge_failed.return_value = 10

        count = await svc.purge_failed()
        assert count == 10


# ---------------------------------------------------------------------------
# Cleanup Expired
# ---------------------------------------------------------------------------


class TestCleanupExpired:
    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.cleanup_expired_jobs.return_value = {"completed": 5, "failed": 2}

        result = await svc.cleanup_expired(
            completed_ttl_days=30, failed_ttl_days=90,
        )
        assert result == {"completed": 5, "failed": 2}
        svc._queue.cleanup_expired_jobs.assert_awaited_once_with(
            completed_ttl_days=30, failed_ttl_days=90,
        )

    @pytest.mark.asyncio
    async def test_cleanup_expired_no_ttl(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.cleanup_expired_jobs.return_value = {}

        result = await svc.cleanup_expired()
        assert result == {}


# ---------------------------------------------------------------------------
# Reclaim Stuck
# ---------------------------------------------------------------------------


class TestReclaimStuck:
    @pytest.mark.asyncio
    async def test_reclaim_stuck_jobs(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.reclaim_stuck_jobs.return_value = 2

        count = await svc.reclaim_stuck(timeout_seconds=1800)
        assert count == 2
        svc._queue.reclaim_stuck_jobs.assert_awaited_once_with(
            timeout_seconds=1800,
        )

    @pytest.mark.asyncio
    async def test_reclaim_stuck_default_timeout(self):
        svc = _make_service()
        svc._queue = AsyncMock()
        svc._queue.reclaim_stuck_jobs.return_value = 0

        count = await svc.reclaim_stuck()
        assert count == 0
        svc._queue.reclaim_stuck_jobs.assert_awaited_once_with(
            timeout_seconds=3600,
        )


# ---------------------------------------------------------------------------
# Age Stats
# ---------------------------------------------------------------------------


class TestGetAgeStats:
    @pytest.mark.asyncio
    async def test_get_age_stats(self):
        svc = _make_service()
        expected = {
            "pending": {"count": 3, "oldest_hours": 2.5, "avg_hours": 1.0},
            "running": {"count": 1, "oldest_hours": 0.5, "avg_hours": 0.5},
        }
        svc._queue = AsyncMock()
        svc._queue.get_job_age_stats.return_value = expected

        result = await svc.get_age_stats()
        assert result == expected
        svc._queue.get_job_age_stats.assert_awaited_once()

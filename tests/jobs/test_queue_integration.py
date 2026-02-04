"""
PostgreSQL integration tests for the job queue.

These tests verify actual database behavior, not mocked interactions.
Requires a PostgreSQL database - set TEST_DATABASE_URL env var.

Run with:
    export TEST_DATABASE_URL="postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"
    pytest tests/jobs/test_queue_integration.py -v
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from openlabels.jobs.queue import JobQueue, calculate_retry_delay


@pytest.fixture
async def tenant_id(test_db):
    """Create a test tenant and return its ID."""
    from openlabels.server.models import Tenant

    tenant = Tenant(name="Queue Test Tenant")
    test_db.add(tenant)
    await test_db.flush()
    return tenant.id


@pytest.fixture
async def queue(test_db, tenant_id):
    """Create a JobQueue instance with a real database session."""
    return JobQueue(test_db, tenant_id)


@pytest.mark.integration
class TestEnqueueIntegration:
    """Integration tests for job enqueueing."""

    @pytest.mark.asyncio
    async def test_enqueue_creates_job_in_database(self, queue, test_db):
        """Verify enqueue actually creates a job in the database."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {"path": "/data"})

        # Verify job exists in database
        job = await test_db.get(JobQueueModel, job_id)
        assert job is not None
        assert job.task_type == "scan"
        assert job.payload == {"path": "/data"}
        assert job.status == "pending"

    @pytest.mark.asyncio
    async def test_enqueue_respects_priority(self, queue, test_db):
        """Verify priority is stored correctly."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {}, priority=90)

        job = await test_db.get(JobQueueModel, job_id)
        assert job.priority == 90

    @pytest.mark.asyncio
    async def test_enqueue_with_scheduled_time(self, queue, test_db):
        """Verify scheduled_for is stored correctly."""
        from openlabels.server.models import JobQueue as JobQueueModel

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        job_id = await queue.enqueue("scan", {}, scheduled_for=future)

        job = await test_db.get(JobQueueModel, job_id)
        assert job.scheduled_for is not None
        # Compare with some tolerance for DB roundtrip
        assert abs((job.scheduled_for - future).total_seconds()) < 1


@pytest.mark.integration
class TestDequeueIntegration:
    """Integration tests for job dequeueing with real SELECT FOR UPDATE."""

    @pytest.mark.asyncio
    async def test_dequeue_returns_highest_priority_first(self, queue, test_db):
        """Verify dequeue returns jobs in priority order."""
        # Enqueue jobs with different priorities
        low_id = await queue.enqueue("scan", {"type": "low"}, priority=10)
        high_id = await queue.enqueue("scan", {"type": "high"}, priority=90)
        medium_id = await queue.enqueue("scan", {"type": "medium"}, priority=50)

        # Should get high priority first
        job1 = await queue.dequeue("worker-1")
        assert job1.id == high_id
        assert job1.status == "running"
        assert job1.worker_id == "worker-1"

        # Then medium
        job2 = await queue.dequeue("worker-1")
        assert job2.id == medium_id

        # Then low
        job3 = await queue.dequeue("worker-1")
        assert job3.id == low_id

    @pytest.mark.asyncio
    async def test_dequeue_returns_none_when_empty(self, queue):
        """Verify dequeue returns None when no jobs available."""
        job = await queue.dequeue("worker-1")
        assert job is None

    @pytest.mark.asyncio
    async def test_dequeue_skips_scheduled_future_jobs(self, queue):
        """Jobs scheduled for the future should not be dequeued."""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        await queue.enqueue("scan", {}, scheduled_for=future)

        job = await queue.dequeue("worker-1")
        assert job is None  # Should not get the future-scheduled job

    @pytest.mark.asyncio
    async def test_dequeue_gets_past_scheduled_jobs(self, queue):
        """Jobs scheduled in the past should be dequeued."""
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        job_id = await queue.enqueue("scan", {}, scheduled_for=past)

        job = await queue.dequeue("worker-1")
        assert job is not None
        assert job.id == job_id

    @pytest.mark.asyncio
    async def test_dequeue_sets_started_at(self, queue):
        """Dequeue should set started_at timestamp."""
        await queue.enqueue("scan", {})

        before = datetime.now(timezone.utc)
        job = await queue.dequeue("worker-1")
        after = datetime.now(timezone.utc)

        assert job.started_at is not None
        assert before <= job.started_at <= after


@pytest.mark.integration
class TestCompleteIntegration:
    """Integration tests for job completion."""

    @pytest.mark.asyncio
    async def test_complete_sets_status_and_time(self, queue, test_db):
        """Verify complete updates status and completed_at."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})
        await queue.dequeue("worker-1")

        await queue.complete(job_id, result={"processed": 100})

        # Refresh to get updated state
        await test_db.refresh(await test_db.get(JobQueueModel, job_id))
        job = await test_db.get(JobQueueModel, job_id)

        assert job.status == "completed"
        assert job.completed_at is not None
        assert job.result == {"processed": 100}


@pytest.mark.integration
class TestFailAndRetryIntegration:
    """Integration tests for failure handling and retry logic."""

    @pytest.mark.asyncio
    async def test_fail_reschedules_with_exponential_backoff(self, queue, test_db):
        """Verify fail reschedules job with proper delay."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})
        await queue.dequeue("worker-1")

        before = datetime.now(timezone.utc)
        await queue.fail(job_id, "Temporary error", retry=True)

        job = await test_db.get(JobQueueModel, job_id)

        # Should be back to pending
        assert job.status == "pending"
        assert job.retry_count == 1
        assert job.worker_id is None
        assert job.started_at is None

        # Should be scheduled for future (2 seconds for first retry)
        expected_delay = calculate_retry_delay(0)  # 2 seconds
        assert job.scheduled_for is not None
        assert job.scheduled_for >= before + expected_delay

    @pytest.mark.asyncio
    async def test_fail_moves_to_dead_letter_after_max_retries(self, queue, test_db):
        """Verify job moves to failed status after max retries."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})
        job = await test_db.get(JobQueueModel, job_id)

        # Simulate max retries reached
        job.retry_count = job.max_retries  # 3 by default
        await test_db.flush()

        await queue.dequeue("worker-1")
        await queue.fail(job_id, "Permanent error", retry=True)

        await test_db.refresh(job)
        assert job.status == "failed"
        assert job.completed_at is not None
        assert job.error == "Permanent error"

    @pytest.mark.asyncio
    async def test_fail_without_retry_goes_to_dead_letter_immediately(self, queue, test_db):
        """Verify retry=False moves job to dead letter immediately."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})
        await queue.dequeue("worker-1")

        await queue.fail(job_id, "Non-retriable error", retry=False)

        job = await test_db.get(JobQueueModel, job_id)
        assert job.status == "failed"
        assert job.retry_count == 0  # Not incremented

    @pytest.mark.asyncio
    async def test_exponential_backoff_sequence(self, queue, test_db):
        """Verify exponential backoff increases correctly over retries."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})

        expected_delays = [2, 4, 8]  # Seconds for retries 0, 1, 2

        for i, expected_seconds in enumerate(expected_delays):
            # Get and fail the job
            job = await queue.dequeue("worker-1")
            if not job:
                # Need to wait for scheduled time or manually reset
                j = await test_db.get(JobQueueModel, job_id)
                j.scheduled_for = None  # Make it immediately available
                await test_db.flush()
                job = await queue.dequeue("worker-1")

            before = datetime.now(timezone.utc)
            await queue.fail(job_id, f"Error {i}", retry=True)

            j = await test_db.get(JobQueueModel, job_id)
            assert j.retry_count == i + 1

            # Check scheduled time is approximately correct
            if j.scheduled_for:
                delay = (j.scheduled_for - before).total_seconds()
                assert delay >= expected_seconds - 1
                assert delay <= expected_seconds + 1


@pytest.mark.integration
class TestCancelIntegration:
    """Integration tests for job cancellation."""

    @pytest.mark.asyncio
    async def test_cancel_pending_job(self, queue, test_db):
        """Verify pending jobs can be cancelled."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})

        result = await queue.cancel(job_id)

        assert result is True
        job = await test_db.get(JobQueueModel, job_id)
        assert job.status == "cancelled"
        assert job.completed_at is not None

    @pytest.mark.asyncio
    async def test_cancel_completed_job_fails(self, queue, test_db):
        """Verify completed jobs cannot be cancelled."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})
        await queue.dequeue("worker-1")
        await queue.complete(job_id)

        result = await queue.cancel(job_id)

        assert result is False
        job = await test_db.get(JobQueueModel, job_id)
        assert job.status == "completed"  # Unchanged


@pytest.mark.integration
class TestDeadLetterQueueIntegration:
    """Integration tests for dead letter queue operations."""

    @pytest.mark.asyncio
    async def test_get_failed_jobs(self, queue, test_db):
        """Verify get_failed_jobs returns failed jobs."""
        # Create and fail some jobs
        for i in range(3):
            job_id = await queue.enqueue("scan", {"index": i})
            await queue.dequeue("worker-1")
            await queue.fail(job_id, f"Error {i}", retry=False)

        failed = await queue.get_failed_jobs()

        assert len(failed) == 3
        for job in failed:
            assert job.status == "failed"

    @pytest.mark.asyncio
    async def test_get_failed_jobs_filter_by_type(self, queue, test_db):
        """Verify get_failed_jobs can filter by task type."""
        # Create failed jobs of different types
        for task_type in ["scan", "scan", "label"]:
            job_id = await queue.enqueue(task_type, {})
            await queue.dequeue("worker-1")
            await queue.fail(job_id, "Error", retry=False)

        scan_failed = await queue.get_failed_jobs(task_type="scan")
        label_failed = await queue.get_failed_jobs(task_type="label")

        assert len(scan_failed) == 2
        assert len(label_failed) == 1

    @pytest.mark.asyncio
    async def test_requeue_failed_job(self, queue, test_db):
        """Verify failed jobs can be requeued."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})
        await queue.dequeue("worker-1")
        await queue.fail(job_id, "Error", retry=False)

        result = await queue.requeue_failed(job_id)

        assert result is True
        job = await test_db.get(JobQueueModel, job_id)
        assert job.status == "pending"
        assert job.retry_count == 0  # Reset
        assert job.error is None

    @pytest.mark.asyncio
    async def test_requeue_failed_preserves_retries_when_requested(self, queue, test_db):
        """Verify requeue can preserve retry count."""
        from openlabels.server.models import JobQueue as JobQueueModel

        job_id = await queue.enqueue("scan", {})
        job = await test_db.get(JobQueueModel, job_id)
        job.retry_count = 2
        await test_db.flush()

        await queue.dequeue("worker-1")
        await queue.fail(job_id, "Error", retry=False)

        await queue.requeue_failed(job_id, reset_retries=False)

        job = await test_db.get(JobQueueModel, job_id)
        assert job.retry_count == 2  # Preserved

    @pytest.mark.asyncio
    async def test_get_failed_count(self, queue, test_db):
        """Verify get_failed_count returns correct count."""
        # Create and fail jobs
        for i in range(5):
            job_id = await queue.enqueue("scan", {})
            await queue.dequeue("worker-1")
            await queue.fail(job_id, "Error", retry=False)

        count = await queue.get_failed_count()
        assert count == 5


@pytest.mark.integration
class TestQueueStatsIntegration:
    """Integration tests for queue statistics."""

    @pytest.mark.asyncio
    async def test_get_queue_stats(self, queue, test_db):
        """Verify get_queue_stats returns comprehensive statistics."""
        # Create jobs in various states
        pending_id = await queue.enqueue("scan", {})

        running_id = await queue.enqueue("scan", {})
        await queue.dequeue("worker-1")

        completed_id = await queue.enqueue("label", {})
        await queue.dequeue("worker-2")
        await queue.complete(completed_id)

        failed_id = await queue.enqueue("scan", {})
        await queue.dequeue("worker-3")
        await queue.fail(failed_id, "Error", retry=False)

        stats = await queue.get_queue_stats()

        assert stats["pending"] == 1
        assert stats["running"] == 1
        assert stats["completed"] == 1
        assert stats["failed"] == 1
        assert stats["failed_by_type"]["scan"] == 1


@pytest.mark.integration
class TestTenantIsolation:
    """Tests verifying tenant isolation in the queue."""

    @pytest.mark.asyncio
    async def test_dequeue_only_returns_tenant_jobs(self, test_db):
        """Verify queue only returns jobs for its own tenant."""
        from openlabels.server.models import Tenant

        # Create two tenants
        tenant1 = Tenant(name="Tenant 1")
        tenant2 = Tenant(name="Tenant 2")
        test_db.add(tenant1)
        test_db.add(tenant2)
        await test_db.flush()

        queue1 = JobQueue(test_db, tenant1.id)
        queue2 = JobQueue(test_db, tenant2.id)

        # Enqueue job for tenant 1
        job_id = await queue1.enqueue("scan", {"tenant": "1"})

        # Tenant 2's queue should not see it
        job = await queue2.dequeue("worker-1")
        assert job is None

        # Tenant 1's queue should see it
        job = await queue1.dequeue("worker-1")
        assert job is not None
        assert job.id == job_id

    @pytest.mark.asyncio
    async def test_requeue_failed_respects_tenant(self, test_db):
        """Verify requeue_failed only works for same tenant's jobs."""
        from openlabels.server.models import Tenant

        tenant1 = Tenant(name="Tenant 1")
        tenant2 = Tenant(name="Tenant 2")
        test_db.add(tenant1)
        test_db.add(tenant2)
        await test_db.flush()

        queue1 = JobQueue(test_db, tenant1.id)
        queue2 = JobQueue(test_db, tenant2.id)

        # Create failed job for tenant 1
        job_id = await queue1.enqueue("scan", {})
        await queue1.dequeue("worker-1")
        await queue1.fail(job_id, "Error", retry=False)

        # Tenant 2 should not be able to requeue it
        result = await queue2.requeue_failed(job_id)
        assert result is False

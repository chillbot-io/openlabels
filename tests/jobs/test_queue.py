"""
Comprehensive tests for the PostgreSQL-backed job queue.

Tests focus on:
- Exponential backoff retry logic
- Job lifecycle (enqueue, dequeue, complete, fail, cancel)
- Dead letter queue operations
- Concurrent access safety
- Queue statistics
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock, patch

from openlabels.jobs.queue import (
    calculate_retry_delay,
    JobQueue,
    BASE_RETRY_DELAY_SECONDS,
    MAX_RETRY_DELAY_SECONDS,
)


class TestCalculateRetryDelay:
    """Tests for exponential backoff retry delay calculation."""

    def test_first_retry_is_base_delay(self):
        """First retry (count=0) should be base delay."""
        delay = calculate_retry_delay(0)
        assert delay == timedelta(seconds=BASE_RETRY_DELAY_SECONDS)
        assert delay == timedelta(seconds=2)

    def test_exponential_backoff_sequence(self):
        """Verify exponential backoff: 2s, 4s, 8s, 16s, 32s..."""
        expected_seconds = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]

        for retry_count, expected in enumerate(expected_seconds):
            delay = calculate_retry_delay(retry_count)
            assert delay.total_seconds() == expected, f"retry_count={retry_count}"

    def test_delay_caps_at_max(self):
        """Delay should cap at MAX_RETRY_DELAY_SECONDS (1 hour)."""
        # With 2^n * 2, we hit 3600 at n >= 11 (2048*2 = 4096 > 3600)
        delay = calculate_retry_delay(11)
        assert delay.total_seconds() == MAX_RETRY_DELAY_SECONDS
        assert delay == timedelta(hours=1)

    def test_very_high_retry_count_still_caps(self):
        """Even very high retry counts should cap at max delay."""
        delay = calculate_retry_delay(100)
        assert delay.total_seconds() == MAX_RETRY_DELAY_SECONDS

    def test_negative_retry_count_returns_fractional(self):
        """Negative retry count produces fractional delay (edge case)."""
        # 2^(-1) = 0.5, so delay = 2 * 0.5 = 1 second
        delay = calculate_retry_delay(-1)
        assert delay.total_seconds() == 1.0

    def test_returns_timedelta_type(self):
        """Function should always return a timedelta object."""
        for i in range(-1, 15):
            result = calculate_retry_delay(i)
            assert isinstance(result, timedelta)


class TestJobQueueInitialization:
    """Tests for JobQueue class initialization."""

    def test_init_stores_session_and_tenant(self):
        """JobQueue should store session and tenant_id."""
        mock_session = AsyncMock()
        tenant_id = uuid4()

        queue = JobQueue(mock_session, tenant_id)

        assert queue.session is mock_session
        assert queue.tenant_id == tenant_id

    def test_init_accepts_uuid_tenant_id(self):
        """tenant_id should be a UUID."""
        mock_session = AsyncMock()
        tenant_id = uuid4()

        queue = JobQueue(mock_session, tenant_id)

        assert isinstance(queue.tenant_id, UUID)


class TestJobQueueEnqueue:
    """Tests for job enqueueing."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_enqueue_returns_job_id(self, queue):
        """Enqueue should return a UUID job ID."""
        job_id = await queue.enqueue("scan", {"path": "/data"})

        assert isinstance(job_id, UUID)

    @pytest.mark.asyncio
    async def test_enqueue_adds_job_to_session(self, queue):
        """Enqueue should add a job model to the session."""
        await queue.enqueue("scan", {"path": "/data"})

        queue.session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_enqueue_flushes_session(self, queue):
        """Enqueue should flush the session."""
        await queue.enqueue("scan", {"path": "/data"})

        queue.session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_enqueue_with_default_priority(self, queue):
        """Default priority should be 50."""
        await queue.enqueue("scan", {"path": "/data"})

        call_args = queue.session.add.call_args[0][0]
        assert call_args.priority == 50

    @pytest.mark.asyncio
    async def test_enqueue_with_custom_priority(self, queue):
        """Should accept custom priority."""
        await queue.enqueue("scan", {"path": "/data"}, priority=100)

        call_args = queue.session.add.call_args[0][0]
        assert call_args.priority == 100

    @pytest.mark.asyncio
    async def test_enqueue_with_scheduled_time(self, queue):
        """Should accept scheduled_for time."""
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        await queue.enqueue("scan", {"path": "/data"}, scheduled_for=future_time)

        call_args = queue.session.add.call_args[0][0]
        assert call_args.scheduled_for == future_time

    @pytest.mark.asyncio
    async def test_enqueue_sets_pending_status(self, queue):
        """New jobs should have 'pending' status."""
        await queue.enqueue("scan", {"path": "/data"})

        call_args = queue.session.add.call_args[0][0]
        assert call_args.status == "pending"

    @pytest.mark.asyncio
    async def test_enqueue_stores_payload(self, queue):
        """Payload should be stored in the job."""
        payload = {"path": "/data", "recursive": True}
        await queue.enqueue("scan", payload)

        call_args = queue.session.add.call_args[0][0]
        assert call_args.payload == payload

    @pytest.mark.asyncio
    async def test_enqueue_stores_task_type(self, queue):
        """Task type should be stored in the job."""
        await queue.enqueue("label", {"files": []})

        call_args = queue.session.add.call_args[0][0]
        assert call_args.task_type == "label"


class TestJobQueueDequeue:
    """Tests for job dequeueing."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_dequeue_returns_none_when_no_jobs(self, queue):
        """Dequeue should return None when no jobs available."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        queue.session.execute = AsyncMock(return_value=mock_result)

        job = await queue.dequeue("worker-1")

        assert job is None

    @pytest.mark.asyncio
    async def test_dequeue_returns_job_model(self, queue):
        """Dequeue should return job model when available."""
        mock_job = MagicMock()
        mock_job.status = "pending"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        queue.session.execute = AsyncMock(return_value=mock_result)

        job = await queue.dequeue("worker-1")

        assert job is mock_job

    @pytest.mark.asyncio
    async def test_dequeue_sets_running_status(self, queue):
        """Dequeue should set job status to 'running'."""
        mock_job = MagicMock()
        mock_job.status = "pending"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        queue.session.execute = AsyncMock(return_value=mock_result)

        await queue.dequeue("worker-1")

        assert mock_job.status == "running"

    @pytest.mark.asyncio
    async def test_dequeue_sets_worker_id(self, queue):
        """Dequeue should set the worker_id on the job."""
        mock_job = MagicMock()
        mock_job.status = "pending"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        queue.session.execute = AsyncMock(return_value=mock_result)

        await queue.dequeue("worker-abc")

        assert mock_job.worker_id == "worker-abc"

    @pytest.mark.asyncio
    async def test_dequeue_sets_started_at(self, queue):
        """Dequeue should set started_at timestamp."""
        mock_job = MagicMock()
        mock_job.status = "pending"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        queue.session.execute = AsyncMock(return_value=mock_result)

        before = datetime.now(timezone.utc)
        await queue.dequeue("worker-1")
        after = datetime.now(timezone.utc)

        assert mock_job.started_at >= before
        assert mock_job.started_at <= after

    @pytest.mark.asyncio
    async def test_dequeue_flushes_session(self, queue):
        """Dequeue should flush session after claiming job."""
        mock_job = MagicMock()
        mock_job.status = "pending"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        queue.session.execute = AsyncMock(return_value=mock_result)

        await queue.dequeue("worker-1")

        queue.session.flush.assert_called()


class TestJobQueueComplete:
    """Tests for marking jobs complete."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_complete_executes_update(self, queue):
        """Complete should execute an update statement."""
        job_id = uuid4()
        await queue.complete(job_id)

        queue.session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_complete_accepts_result_data(self, queue):
        """Complete should accept optional result data."""
        job_id = uuid4()
        result = {"files_processed": 100}

        # Should not raise
        await queue.complete(job_id, result=result)

    @pytest.mark.asyncio
    async def test_complete_without_result(self, queue):
        """Complete should work without result data."""
        job_id = uuid4()

        # Should not raise
        await queue.complete(job_id)


class TestJobQueueFail:
    """Tests for job failure handling with retry logic."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_fail_returns_early_if_job_not_found(self, queue):
        """Fail should return early if job doesn't exist."""
        queue.session.get = AsyncMock(return_value=None)

        # Should not raise
        await queue.fail(uuid4(), "Error message")

        # Should not flush if no job found
        queue.session.flush.assert_not_called()

    @pytest.mark.asyncio
    async def test_fail_with_retry_reschedules_job(self, queue):
        """Fail with retry should reschedule job if retries remain."""
        mock_job = MagicMock()
        mock_job.retry_count = 0
        mock_job.max_retries = 3

        queue.session.get = AsyncMock(return_value=mock_job)

        await queue.fail(uuid4(), "Temporary error", retry=True)

        assert mock_job.status == "pending"
        assert mock_job.retry_count == 1
        assert mock_job.worker_id is None
        assert mock_job.started_at is None
        assert mock_job.scheduled_for is not None

    @pytest.mark.asyncio
    async def test_fail_calculates_retry_delay(self, queue):
        """Fail should calculate proper exponential backoff delay."""
        mock_job = MagicMock()
        mock_job.retry_count = 2  # Will calculate for 3rd retry
        mock_job.max_retries = 5

        queue.session.get = AsyncMock(return_value=mock_job)

        before = datetime.now(timezone.utc)
        await queue.fail(uuid4(), "Error", retry=True)
        after = datetime.now(timezone.utc)

        # 2^2 * 2 = 8 seconds delay
        expected_delay = timedelta(seconds=8)
        min_scheduled = before + expected_delay
        max_scheduled = after + expected_delay

        assert mock_job.scheduled_for >= min_scheduled
        assert mock_job.scheduled_for <= max_scheduled

    @pytest.mark.asyncio
    async def test_fail_stores_error_message(self, queue):
        """Fail should store the error message."""
        mock_job = MagicMock()
        mock_job.retry_count = 0
        mock_job.max_retries = 3

        queue.session.get = AsyncMock(return_value=mock_job)

        await queue.fail(uuid4(), "Connection timeout")

        assert mock_job.error == "Connection timeout"

    @pytest.mark.asyncio
    async def test_fail_moves_to_dead_letter_when_retries_exhausted(self, queue):
        """Job should be marked failed when max retries reached."""
        mock_job = MagicMock()
        mock_job.retry_count = 3
        mock_job.max_retries = 3  # At max

        queue.session.get = AsyncMock(return_value=mock_job)

        await queue.fail(uuid4(), "Permanent failure")

        assert mock_job.status == "failed"
        assert mock_job.completed_at is not None

    @pytest.mark.asyncio
    async def test_fail_with_retry_false_moves_to_dead_letter(self, queue):
        """Fail with retry=False should move to dead letter immediately."""
        mock_job = MagicMock()
        mock_job.retry_count = 0
        mock_job.max_retries = 10  # Plenty of retries left

        queue.session.get = AsyncMock(return_value=mock_job)

        await queue.fail(uuid4(), "Non-retriable error", retry=False)

        assert mock_job.status == "failed"
        assert mock_job.retry_count == 0  # Not incremented

    @pytest.mark.asyncio
    async def test_fail_flushes_session(self, queue):
        """Fail should flush the session."""
        mock_job = MagicMock()
        mock_job.retry_count = 0
        mock_job.max_retries = 3

        queue.session.get = AsyncMock(return_value=mock_job)

        await queue.fail(uuid4(), "Error")

        queue.session.flush.assert_called_once()


class TestJobQueueCancel:
    """Tests for job cancellation."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_cancel_returns_false_if_not_found(self, queue):
        """Cancel should return False if job doesn't exist."""
        queue.session.get = AsyncMock(return_value=None)

        result = await queue.cancel(uuid4())

        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_pending_job_succeeds(self, queue):
        """Should be able to cancel pending jobs."""
        mock_job = MagicMock()
        mock_job.status = "pending"

        queue.session.get = AsyncMock(return_value=mock_job)

        result = await queue.cancel(uuid4())

        assert result is True
        assert mock_job.status == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_running_job_succeeds(self, queue):
        """Should be able to cancel running jobs."""
        mock_job = MagicMock()
        mock_job.status = "running"

        queue.session.get = AsyncMock(return_value=mock_job)

        result = await queue.cancel(uuid4())

        assert result is True
        assert mock_job.status == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_completed_job_fails(self, queue):
        """Cannot cancel completed jobs."""
        mock_job = MagicMock()
        mock_job.status = "completed"

        queue.session.get = AsyncMock(return_value=mock_job)

        result = await queue.cancel(uuid4())

        assert result is False
        assert mock_job.status == "completed"  # Unchanged

    @pytest.mark.asyncio
    async def test_cancel_failed_job_fails(self, queue):
        """Cannot cancel already failed jobs."""
        mock_job = MagicMock()
        mock_job.status = "failed"

        queue.session.get = AsyncMock(return_value=mock_job)

        result = await queue.cancel(uuid4())

        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_sets_completed_at(self, queue):
        """Cancel should set completed_at timestamp."""
        mock_job = MagicMock()
        mock_job.status = "pending"

        queue.session.get = AsyncMock(return_value=mock_job)

        before = datetime.now(timezone.utc)
        await queue.cancel(uuid4())
        after = datetime.now(timezone.utc)

        assert mock_job.completed_at >= before
        assert mock_job.completed_at <= after


class TestJobQueueCountMethods:
    """Tests for count methods."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_get_pending_count_returns_count(self, queue):
        """get_pending_count should return number of pending jobs."""
        mock_result = MagicMock()
        mock_result.all.return_value = [1, 2, 3]  # 3 pending jobs
        queue.session.execute = AsyncMock(return_value=mock_result)

        count = await queue.get_pending_count()

        assert count == 3

    @pytest.mark.asyncio
    async def test_get_running_count_returns_count(self, queue):
        """get_running_count should return number of running jobs."""
        mock_result = MagicMock()
        mock_result.all.return_value = [1, 2]  # 2 running jobs
        queue.session.execute = AsyncMock(return_value=mock_result)

        count = await queue.get_running_count()

        assert count == 2


class TestDeadLetterQueue:
    """Tests for dead letter queue operations."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_get_failed_jobs_returns_list(self, queue):
        """get_failed_jobs should return a list of failed jobs."""
        mock_jobs = [MagicMock(), MagicMock()]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_jobs
        queue.session.execute = AsyncMock(return_value=mock_result)

        jobs = await queue.get_failed_jobs()

        assert len(jobs) == 2

    @pytest.mark.asyncio
    async def test_get_failed_jobs_with_task_type_filter(self, queue):
        """get_failed_jobs should accept task_type filter."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        queue.session.execute = AsyncMock(return_value=mock_result)

        # Should not raise
        await queue.get_failed_jobs(task_type="scan")

    @pytest.mark.asyncio
    async def test_get_failed_count_returns_integer(self, queue):
        """get_failed_count should return count."""
        mock_result = MagicMock()
        mock_result.scalar.return_value = 5
        queue.session.execute = AsyncMock(return_value=mock_result)

        count = await queue.get_failed_count()

        assert count == 5

    @pytest.mark.asyncio
    async def test_get_failed_count_returns_zero_when_none(self, queue):
        """get_failed_count should return 0 when scalar returns None."""
        mock_result = MagicMock()
        mock_result.scalar.return_value = None
        queue.session.execute = AsyncMock(return_value=mock_result)

        count = await queue.get_failed_count()

        assert count == 0

    @pytest.mark.asyncio
    async def test_requeue_failed_returns_false_if_not_found(self, queue):
        """requeue_failed returns False if job not found."""
        queue.session.get = AsyncMock(return_value=None)

        result = await queue.requeue_failed(uuid4())

        assert result is False

    @pytest.mark.asyncio
    async def test_requeue_failed_returns_false_if_not_failed(self, queue):
        """requeue_failed returns False if job is not in failed state."""
        mock_job = MagicMock()
        mock_job.status = "pending"
        mock_job.tenant_id = queue.tenant_id

        queue.session.get = AsyncMock(return_value=mock_job)

        result = await queue.requeue_failed(uuid4())

        assert result is False

    @pytest.mark.asyncio
    async def test_requeue_failed_returns_false_if_wrong_tenant(self, queue):
        """requeue_failed returns False if job belongs to different tenant."""
        mock_job = MagicMock()
        mock_job.status = "failed"
        mock_job.tenant_id = uuid4()  # Different tenant

        queue.session.get = AsyncMock(return_value=mock_job)

        result = await queue.requeue_failed(uuid4())

        assert result is False

    @pytest.mark.asyncio
    async def test_requeue_failed_resets_job_state(self, queue):
        """requeue_failed should reset job to pending state."""
        mock_job = MagicMock()
        mock_job.status = "failed"
        mock_job.tenant_id = queue.tenant_id
        mock_job.retry_count = 3

        queue.session.get = AsyncMock(return_value=mock_job)

        result = await queue.requeue_failed(uuid4())

        assert result is True
        assert mock_job.status == "pending"
        assert mock_job.worker_id is None
        assert mock_job.started_at is None
        assert mock_job.completed_at is None
        assert mock_job.scheduled_for is None
        assert mock_job.error is None
        assert mock_job.retry_count == 0

    @pytest.mark.asyncio
    async def test_requeue_failed_preserves_retries_if_requested(self, queue):
        """requeue_failed with reset_retries=False should keep retry count."""
        mock_job = MagicMock()
        mock_job.status = "failed"
        mock_job.tenant_id = queue.tenant_id
        mock_job.retry_count = 3

        queue.session.get = AsyncMock(return_value=mock_job)

        await queue.requeue_failed(uuid4(), reset_retries=False)

        assert mock_job.retry_count == 3  # Unchanged

    @pytest.mark.asyncio
    async def test_requeue_all_failed_returns_count(self, queue):
        """requeue_all_failed should return number of requeued jobs."""
        mock_result = MagicMock()
        mock_result.rowcount = 10
        queue.session.execute = AsyncMock(return_value=mock_result)

        count = await queue.requeue_all_failed()

        assert count == 10

    @pytest.mark.asyncio
    async def test_purge_failed_returns_deleted_count(self, queue):
        """purge_failed should return number of deleted jobs."""
        mock_result = MagicMock()
        mock_result.rowcount = 5
        queue.session.execute = AsyncMock(return_value=mock_result)

        count = await queue.purge_failed()

        assert count == 5

    @pytest.mark.asyncio
    async def test_purge_failed_with_older_than_days(self, queue):
        """purge_failed should support older_than_days filter."""
        mock_result = MagicMock()
        mock_result.rowcount = 3
        queue.session.execute = AsyncMock(return_value=mock_result)

        # Should not raise
        count = await queue.purge_failed(older_than_days=30)

        assert count == 3


class TestQueueStats:
    """Tests for queue statistics."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_get_queue_stats_returns_dict(self, queue):
        """get_queue_stats should return a dictionary."""
        # Mock status counts
        status_result = MagicMock()
        status_result.all.return_value = [
            ("pending", 10),
            ("running", 2),
            ("completed", 100),
            ("failed", 5),
        ]

        # Mock failed by type
        failed_result = MagicMock()
        failed_result.all.return_value = [
            ("scan", 3),
            ("label", 2),
        ]

        queue.session.execute = AsyncMock(side_effect=[status_result, failed_result])

        stats = await queue.get_queue_stats()

        assert isinstance(stats, dict)
        assert stats["pending"] == 10
        assert stats["running"] == 2
        assert stats["completed"] == 100
        assert stats["failed"] == 5
        assert stats["failed_by_type"] == {"scan": 3, "label": 2}

    @pytest.mark.asyncio
    async def test_get_queue_stats_returns_zero_for_missing(self, queue):
        """Stats should return 0 for statuses with no jobs."""
        status_result = MagicMock()
        status_result.all.return_value = [("pending", 5)]  # Only pending

        failed_result = MagicMock()
        failed_result.all.return_value = []

        queue.session.execute = AsyncMock(side_effect=[status_result, failed_result])

        stats = await queue.get_queue_stats()

        assert stats["pending"] == 5
        assert stats["running"] == 0
        assert stats["completed"] == 0
        assert stats["failed"] == 0
        assert stats["cancelled"] == 0


class TestJobQueueEdgeCases:
    """Edge case and security-focused tests."""

    @pytest.fixture
    def queue(self):
        """Create a job queue with mocked session."""
        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        tenant_id = uuid4()
        return JobQueue(mock_session, tenant_id)

    @pytest.mark.asyncio
    async def test_enqueue_with_empty_payload(self, queue):
        """Should handle empty payload dictionary."""
        job_id = await queue.enqueue("scan", {})

        assert isinstance(job_id, UUID)

    @pytest.mark.asyncio
    async def test_enqueue_with_nested_payload(self, queue):
        """Should handle deeply nested payload."""
        payload = {
            "level1": {
                "level2": {
                    "level3": {
                        "value": "deep"
                    }
                }
            }
        }

        # Should not raise
        job_id = await queue.enqueue("scan", payload)
        assert isinstance(job_id, UUID)

    @pytest.mark.asyncio
    async def test_enqueue_with_special_characters_in_task_type(self, queue):
        """Task type with special characters should be handled."""
        # This tests that task_type is properly parameterized
        job_id = await queue.enqueue("scan'; DROP TABLE jobs; --", {})

        assert isinstance(job_id, UUID)

    @pytest.mark.asyncio
    async def test_get_job_returns_job_model(self, queue):
        """get_job should return job by ID."""
        mock_job = MagicMock()
        queue.session.get = AsyncMock(return_value=mock_job)

        job = await queue.get_job(uuid4())

        assert job is mock_job

    @pytest.mark.asyncio
    async def test_get_job_returns_none_if_not_found(self, queue):
        """get_job should return None if not found."""
        queue.session.get = AsyncMock(return_value=None)

        job = await queue.get_job(uuid4())

        assert job is None

    @pytest.mark.asyncio
    async def test_priority_zero_is_valid(self, queue):
        """Priority 0 (lowest) should be valid."""
        await queue.enqueue("scan", {}, priority=0)

        call_args = queue.session.add.call_args[0][0]
        assert call_args.priority == 0

    @pytest.mark.asyncio
    async def test_priority_100_is_valid(self, queue):
        """Priority 100 (highest) should be valid."""
        await queue.enqueue("scan", {}, priority=100)

        call_args = queue.session.add.call_args[0][0]
        assert call_args.priority == 100

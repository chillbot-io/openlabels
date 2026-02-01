"""
Comprehensive tests for the OCR Priority Queue.

Tests priority calculation, queue operations, threading safety,
worker functionality, and edge cases.
"""

import pytest
import threading
import time
from unittest.mock import MagicMock, patch

from openlabels.adapters.scanner.queue import (
    OCRJob,
    OCRPriorityQueue,
    OCRQueueWorker,
    QueueStatus,
    calculate_priority,
    calculate_priority_from_context,
)
from openlabels.core.triggers import ScanTrigger


class TestOCRJob:
    """Tests for OCRJob dataclass."""

    def test_create_job_basic(self):
        """Test basic job creation."""
        job = OCRJob(path="/path/to/file.pdf")

        assert job.path == "/path/to/file.pdf"
        assert job.job_id != ""  # Auto-generated
        assert job.created_at != ""  # Auto-generated
        assert job.exposure == "PRIVATE"  # Default
        assert job.attempts == 0

    def test_job_auto_generates_id(self):
        """Test job ID is auto-generated."""
        job1 = OCRJob(path="/file1.pdf")
        job2 = OCRJob(path="/file2.pdf")

        assert job1.job_id != job2.job_id

    def test_job_calculates_priority(self):
        """Test priority is calculated from inputs."""
        job = OCRJob(
            path="/file.pdf",
            exposure="PUBLIC",
            triggers=["NO_ENCRYPTION"],
        )

        # PUBLIC (50) + NO_ENCRYPTION (20) = 70
        assert job.priority == 70

    def test_job_preserves_custom_priority(self):
        """Test custom priority is preserved."""
        job = OCRJob(path="/file.pdf", priority=42)

        assert job.priority == 42

    def test_job_to_dict(self):
        """Test conversion to dictionary."""
        job = OCRJob(path="/file.pdf", exposure="INTERNAL")
        d = job.to_dict()

        assert d["path"] == "/file.pdf"
        assert d["exposure"] == "INTERNAL"
        assert "job_id" in d
        assert "created_at" in d

    def test_job_ordering(self):
        """Test jobs are ordered by priority (negated)."""
        job_low = OCRJob(path="/low.pdf", priority=10)
        job_high = OCRJob(path="/high.pdf", priority=90)

        # Higher priority should sort first (lower _sort_key)
        assert job_high < job_low

    def test_job_metadata(self):
        """Test job metadata storage."""
        job = OCRJob(
            path="/file.pdf",
            metadata={"source": "upload", "user_id": 123},
        )

        assert job.metadata["source"] == "upload"
        assert job.metadata["user_id"] == 123


class TestCalculatePriority:
    """Tests for priority calculation."""

    def test_private_exposure_base(self):
        """Test PRIVATE exposure gives 0 base."""
        priority = calculate_priority("PRIVATE", [])
        assert priority == 0

    def test_internal_exposure(self):
        """Test INTERNAL exposure gives 10."""
        priority = calculate_priority("INTERNAL", [])
        assert priority == 10

    def test_org_wide_exposure(self):
        """Test ORG_WIDE exposure gives 30."""
        priority = calculate_priority("ORG_WIDE", [])
        assert priority == 30

    def test_public_exposure(self):
        """Test PUBLIC exposure gives 50."""
        priority = calculate_priority("PUBLIC", [])
        assert priority == 50

    def test_case_insensitive_exposure(self):
        """Test exposure is case insensitive."""
        assert calculate_priority("public", []) == 50
        assert calculate_priority("Public", []) == 50
        assert calculate_priority("PUBLIC", []) == 50

    def test_no_encryption_trigger(self):
        """Test NO_ENCRYPTION trigger adds 20."""
        priority = calculate_priority("PRIVATE", ["NO_ENCRYPTION"])
        assert priority == 20

    def test_low_confidence_high_risk_trigger(self):
        """Test LOW_CONFIDENCE_HIGH_RISK trigger adds 25."""
        priority = calculate_priority("PRIVATE", ["LOW_CONFIDENCE_HIGH_RISK"])
        assert priority == 25

    def test_stale_data_trigger(self):
        """Test STALE_DATA trigger adds 5."""
        priority = calculate_priority("PRIVATE", ["STALE_DATA"])
        assert priority == 5

    def test_no_labels_trigger(self):
        """Test NO_LABELS trigger adds 15."""
        priority = calculate_priority("PRIVATE", ["NO_LABELS"])
        assert priority == 15

    def test_multiple_triggers(self):
        """Test multiple triggers stack."""
        priority = calculate_priority(
            "PRIVATE",
            ["NO_ENCRYPTION", "NO_LABELS", "STALE_DATA"],
        )
        # 0 + 20 + 15 + 5 = 40
        assert priority == 40

    def test_small_file_boost(self):
        """Test small files get +5 priority."""
        priority = calculate_priority("PRIVATE", [], size_bytes=500_000)  # 500KB
        assert priority == 5

    def test_large_file_penalty(self):
        """Test large files get -10 priority."""
        priority = calculate_priority(
            "PUBLIC", [],
            size_bytes=200_000_000,  # 200MB
        )
        # 50 - 10 = 40
        assert priority == 40

    def test_priority_capped_at_100(self):
        """Test priority is capped at 100."""
        priority = calculate_priority(
            "PUBLIC",
            ["NO_ENCRYPTION", "LOW_CONFIDENCE_HIGH_RISK", "NO_LABELS", "STALE_DATA"],
            size_bytes=100,
        )
        # Would be 50 + 20 + 25 + 15 + 5 + 5 = 120, but capped
        assert priority == 100

    def test_priority_minimum_zero(self):
        """Test priority doesn't go below 0."""
        priority = calculate_priority("PRIVATE", [], size_bytes=200_000_000)
        # 0 - 10 = -10, but floored at 0
        assert priority == 0

    def test_scan_trigger_enum(self):
        """Test ScanTrigger enum values work."""
        priority = calculate_priority("PRIVATE", [ScanTrigger.NO_ENCRYPTION])
        assert priority == 20


class TestCalculatePriorityFromContext:
    """Tests for calculate_priority_from_context."""

    def test_from_context_basic(self):
        """Test basic context priority calculation."""
        context = MagicMock()
        context.exposure = "PUBLIC"
        context.encryption = "platform"
        context.has_classification = True
        context.size_bytes = 1000

        priority = calculate_priority_from_context(context)
        assert priority >= 50  # At least PUBLIC base

    def test_from_context_adds_no_encryption(self):
        """Test NO_ENCRYPTION trigger added when encryption=none."""
        context = MagicMock()
        context.exposure = "PRIVATE"
        context.encryption = "none"
        context.has_classification = True
        context.size_bytes = 0

        priority = calculate_priority_from_context(context)
        assert priority >= 20  # NO_ENCRYPTION boost

    def test_from_context_adds_no_labels(self):
        """Test NO_LABELS trigger added when no classification."""
        context = MagicMock()
        context.exposure = "PRIVATE"
        context.encryption = "platform"
        context.has_classification = False
        context.size_bytes = 0

        priority = calculate_priority_from_context(context)
        assert priority >= 15  # NO_LABELS boost

    def test_from_context_with_triggers(self):
        """Test explicit triggers are included."""
        context = MagicMock()
        context.exposure = "PRIVATE"
        context.encryption = "platform"
        context.has_classification = True
        context.size_bytes = 0

        priority = calculate_priority_from_context(
            context,
            triggers=[ScanTrigger.STALE_DATA],
        )
        assert priority >= 5


class TestOCRPriorityQueue:
    """Tests for OCRPriorityQueue."""

    @pytest.fixture
    def queue(self):
        return OCRPriorityQueue(max_size=10, max_retries=3)

    def test_enqueue_dequeue_basic(self, queue):
        """Test basic enqueue and dequeue."""
        job = OCRJob(path="/file.pdf")
        queue.enqueue(job)

        result = queue.dequeue(block=False)
        assert result.path == "/file.pdf"

    def test_priority_ordering(self, queue):
        """Test higher priority jobs dequeue first."""
        low_job = OCRJob(path="/low.pdf", priority=10)
        high_job = OCRJob(path="/high.pdf", priority=90)

        queue.enqueue(low_job)
        queue.enqueue(high_job)

        # High priority should come out first
        first = queue.dequeue(block=False)
        assert first.priority == 90

        second = queue.dequeue(block=False)
        assert second.priority == 10

    def test_dequeue_empty_nonblocking(self, queue):
        """Test non-blocking dequeue on empty queue."""
        result = queue.dequeue(block=False)
        assert result is None

    def test_dequeue_timeout(self, queue):
        """Test dequeue with timeout."""
        start = time.time()
        result = queue.dequeue(block=True, timeout=0.1)
        elapsed = time.time() - start

        assert result is None
        assert elapsed >= 0.1

    def test_duplicate_job_rejected(self, queue):
        """Test duplicate jobs are rejected."""
        job = OCRJob(path="/file.pdf", job_id="unique_id")

        assert queue.enqueue(job) is True
        assert queue.enqueue(job) is False  # Duplicate

        assert queue.size == 1

    def test_queue_full_nonblocking(self):
        """Test full queue rejects non-blocking enqueue."""
        queue = OCRPriorityQueue(max_size=2)

        queue.enqueue(OCRJob(path="/1.pdf"))
        queue.enqueue(OCRJob(path="/2.pdf"))

        result = queue.enqueue(OCRJob(path="/3.pdf"), block=False)
        assert result is False
        assert queue.stats["dropped"] == 1

    def test_peek(self, queue):
        """Test peek doesn't remove job."""
        job = OCRJob(path="/file.pdf")
        queue.enqueue(job)

        peeked = queue.peek()
        assert peeked.path == "/file.pdf"

        # Job still in queue
        assert queue.size == 1

    def test_peek_empty(self, queue):
        """Test peek on empty queue."""
        assert queue.peek() is None

    def test_clear(self, queue):
        """Test clear removes all jobs."""
        queue.enqueue(OCRJob(path="/1.pdf"))
        queue.enqueue(OCRJob(path="/2.pdf"))

        count = queue.clear()

        assert count == 2
        assert queue.size == 0
        assert queue.is_empty

    def test_requeue_increments_attempts(self, queue):
        """Test requeue increments attempt counter."""
        job = OCRJob(path="/file.pdf")
        queue.enqueue(job)

        dequeued = queue.dequeue(block=False)
        assert dequeued.attempts == 0

        queue.requeue(dequeued, error="Test error")

        requeued = queue.dequeue(block=False)
        assert requeued.attempts == 1
        assert requeued.last_error == "Test error"

    def test_requeue_reduces_priority(self, queue):
        """Test requeue reduces priority."""
        job = OCRJob(path="/file.pdf", priority=50)
        queue.enqueue(job)

        dequeued = queue.dequeue(block=False)
        queue.requeue(dequeued)

        requeued = queue.dequeue(block=False)
        assert requeued.priority == 45  # Reduced by 5

    def test_requeue_max_retries(self, queue):
        """Test requeue fails after max retries."""
        job = OCRJob(path="/file.pdf")
        job.attempts = 2  # Already at max_retries - 1

        result = queue.requeue(job)

        assert result is False
        assert queue.stats["failed"] == 1

    def test_size_property(self, queue):
        """Test size property."""
        assert queue.size == 0

        queue.enqueue(OCRJob(path="/1.pdf"))
        assert queue.size == 1

        queue.enqueue(OCRJob(path="/2.pdf"))
        assert queue.size == 2

    def test_is_empty_property(self, queue):
        """Test is_empty property."""
        assert queue.is_empty is True

        queue.enqueue(OCRJob(path="/file.pdf"))
        assert queue.is_empty is False

    def test_is_full_property(self):
        """Test is_full property."""
        queue = OCRPriorityQueue(max_size=2)

        assert queue.is_full is False

        queue.enqueue(OCRJob(path="/1.pdf"))
        queue.enqueue(OCRJob(path="/2.pdf"))

        assert queue.is_full is True

    def test_stats(self, queue):
        """Test stats property."""
        job = OCRJob(path="/file.pdf")
        queue.enqueue(job)
        queue.dequeue(block=False)

        stats = queue.stats
        assert stats["enqueued"] == 1
        assert stats["dequeued"] == 1
        assert stats["current_size"] == 0

    def test_pause_resume(self, queue):
        """Test pause and resume."""
        queue.pause()
        assert queue.status == QueueStatus.PAUSED

        queue.resume()
        assert queue.status == QueueStatus.RUNNING

    def test_stop(self, queue):
        """Test stop."""
        queue.stop()
        assert queue.status == QueueStatus.STOPPED


class TestOCRPriorityQueueThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_enqueue(self):
        """Test concurrent enqueue operations."""
        queue = OCRPriorityQueue(max_size=100)
        errors = []

        def enqueue_jobs(start_id):
            try:
                for i in range(10):
                    queue.enqueue(OCRJob(
                        path=f"/file_{start_id}_{i}.pdf",
                        job_id=f"job_{start_id}_{i}",
                    ))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=enqueue_jobs, args=(i,))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert queue.size == 50  # 5 threads * 10 jobs each

    def test_concurrent_enqueue_dequeue(self):
        """Test concurrent enqueue and dequeue."""
        queue = OCRPriorityQueue(max_size=100)
        enqueued = []
        dequeued = []
        errors = []

        def enqueue_jobs():
            try:
                for i in range(20):
                    job = OCRJob(path=f"/file_{i}.pdf")
                    if queue.enqueue(job, timeout=1.0):
                        enqueued.append(job.job_id)
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)

        def dequeue_jobs():
            try:
                for _ in range(20):
                    job = queue.dequeue(timeout=0.5)
                    if job:
                        dequeued.append(job.job_id)
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)

        enqueue_thread = threading.Thread(target=enqueue_jobs)
        dequeue_thread = threading.Thread(target=dequeue_jobs)

        enqueue_thread.start()
        dequeue_thread.start()

        enqueue_thread.join()
        dequeue_thread.join()

        assert len(errors) == 0


class TestOCRQueueWorker:
    """Tests for OCRQueueWorker."""

    def test_worker_processes_jobs(self):
        """Test worker processes jobs from queue."""
        queue = OCRPriorityQueue()
        processed = []

        def process_fn(job):
            processed.append(job.job_id)
            return "success"

        worker = OCRQueueWorker(queue, process_fn)
        worker.start()

        try:
            # Enqueue some jobs
            queue.enqueue(OCRJob(path="/file1.pdf"))
            queue.enqueue(OCRJob(path="/file2.pdf"))

            # Wait for processing
            time.sleep(0.5)

            assert len(processed) == 2
        finally:
            worker.stop()

    def test_worker_calls_on_complete(self):
        """Test worker calls on_complete callback."""
        queue = OCRPriorityQueue()
        completed = []

        def process_fn(job):
            return f"result_{job.job_id}"

        def on_complete(job, result):
            completed.append((job.job_id, result))

        worker = OCRQueueWorker(queue, process_fn, on_complete=on_complete)
        worker.start()

        try:
            queue.enqueue(OCRJob(path="/file.pdf", job_id="test_job"))
            time.sleep(0.3)

            assert len(completed) == 1
            assert completed[0][1] == "result_test_job"
        finally:
            worker.stop()

    def test_worker_calls_on_error(self):
        """Test worker calls on_error callback."""
        queue = OCRPriorityQueue(max_retries=1)  # Fail immediately
        errors = []

        def process_fn(job):
            raise ValueError("Test error")

        def on_error(job, exc):
            errors.append((job.job_id, str(exc)))

        worker = OCRQueueWorker(queue, process_fn, on_error=on_error)
        worker.start()

        try:
            queue.enqueue(OCRJob(path="/file.pdf", job_id="error_job"))
            time.sleep(0.3)

            assert len(errors) >= 1
            assert "Test error" in errors[0][1]
        finally:
            worker.stop()

    def test_worker_stop(self):
        """Test worker stops cleanly."""
        queue = OCRPriorityQueue()
        worker = OCRQueueWorker(queue, lambda j: None)

        worker.start()
        assert worker.is_running is True

        worker.stop()
        assert worker.is_running is False

    def test_worker_multiple_threads(self):
        """Test worker with multiple threads."""
        queue = OCRPriorityQueue()
        processed = []
        lock = threading.Lock()

        def process_fn(job):
            with lock:
                processed.append(job.job_id)
            time.sleep(0.05)  # Simulate work

        worker = OCRQueueWorker(queue, process_fn, num_workers=3)
        worker.start()

        try:
            # Enqueue many jobs
            for i in range(10):
                queue.enqueue(OCRJob(path=f"/file{i}.pdf"))

            # Wait for processing
            time.sleep(1.0)

            assert len(processed) == 10
        finally:
            worker.stop()


class TestQueueStatus:
    """Tests for QueueStatus enum."""

    def test_status_values(self):
        """Test status enum values."""
        assert QueueStatus.RUNNING.value == "running"
        assert QueueStatus.PAUSED.value == "paused"
        assert QueueStatus.STOPPED.value == "stopped"

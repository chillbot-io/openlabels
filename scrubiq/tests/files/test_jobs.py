"""Tests for file processing job management.

Tests for FileJob dataclass and JobManager class.
"""

import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from scrubiq.files.jobs import FileJob, JobManager, JobStatus


# =============================================================================
# JOBSTATUS ENUM TESTS
# =============================================================================

class TestJobStatus:
    """Tests for JobStatus enum."""

    def test_all_statuses_exist(self):
        """All expected statuses are defined."""
        assert JobStatus.UPLOADING.value == "uploading"
        assert JobStatus.QUEUED.value == "queued"
        assert JobStatus.LOADING_MODELS.value == "loading_models"
        assert JobStatus.PROCESSING.value == "processing"
        assert JobStatus.EXTRACTING.value == "extracting"
        assert JobStatus.OCR.value == "ocr"
        assert JobStatus.DETECTING.value == "detecting"
        assert JobStatus.COMPLETE.value == "complete"
        assert JobStatus.FAILED.value == "failed"

    def test_status_is_string_enum(self):
        """JobStatus values are strings."""
        assert isinstance(JobStatus.COMPLETE.value, str)
        assert str(JobStatus.COMPLETE) == "JobStatus.COMPLETE"


# =============================================================================
# FILEJOB CREATION TESTS
# =============================================================================

class TestFileJobCreation:
    """Tests for FileJob creation."""

    def test_create_job_with_required_fields(self):
        """Job created with required fields."""
        job = FileJob(
            id="test-123",
            filename="document.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert job.id == "test-123"
        assert job.filename == "document.pdf"
        assert job.content_type == "application/pdf"
        assert job.size_bytes == 1024

    def test_default_status_is_queued(self):
        """Default status is QUEUED."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert job.status == JobStatus.QUEUED

    def test_default_progress_is_zero(self):
        """Default progress is 0.0."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert job.progress == 0.0

    def test_optional_fields_default_to_none(self):
        """Optional fields default to None."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert job.status_message is None
        assert job.pages_total is None
        assert job.pages_processed is None
        assert job.error is None
        assert job.extracted_text is None
        assert job.redacted_text is None
        assert job.spans is None
        assert job.phi_count is None
        assert job.conversation_id is None
        assert job.processing_time_ms is None
        assert job.ocr_confidence is None

    def test_has_redacted_image_defaults_false(self):
        """has_redacted_image defaults to False."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert job.has_redacted_image is False

    def test_timestamps_auto_set(self):
        """Timestamps are automatically set."""
        before = datetime.now(timezone.utc)
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        after = datetime.now(timezone.utc)

        assert before <= job.created_at <= after
        assert before <= job.updated_at <= after

    def test_metadata_defaults_to_empty_dict(self):
        """metadata defaults to empty dict."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert job.metadata == {}


# =============================================================================
# FILEJOB UPDATE_STATUS TESTS
# =============================================================================

class TestFileJobUpdateStatus:
    """Tests for FileJob.update_status()."""

    def test_update_status_changes_status(self):
        """update_status() changes status."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        job.update_status(JobStatus.PROCESSING)

        assert job.status == JobStatus.PROCESSING

    def test_update_status_with_progress(self):
        """update_status() updates progress when provided."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        job.update_status(JobStatus.EXTRACTING, progress=0.5)

        assert job.status == JobStatus.EXTRACTING
        assert job.progress == 0.5

    def test_update_status_updates_timestamp(self):
        """update_status() updates updated_at timestamp."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        original_updated_at = job.updated_at

        time.sleep(0.01)
        job.update_status(JobStatus.OCR)

        assert job.updated_at > original_updated_at

    def test_update_status_preserves_progress_when_not_provided(self):
        """update_status() preserves progress when not provided."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        job.progress = 0.75

        job.update_status(JobStatus.DETECTING)

        assert job.progress == 0.75


# =============================================================================
# FILEJOB SET_ERROR TESTS
# =============================================================================

class TestFileJobSetError:
    """Tests for FileJob.set_error()."""

    def test_set_error_sets_status_to_failed(self):
        """set_error() sets status to FAILED."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        job.set_error("Something went wrong")

        assert job.status == JobStatus.FAILED

    def test_set_error_stores_error_message(self):
        """set_error() stores error message."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        job.set_error("Connection timeout")

        assert job.error == "Connection timeout"

    def test_set_error_updates_timestamp(self):
        """set_error() updates updated_at timestamp."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        original_updated_at = job.updated_at

        time.sleep(0.01)
        job.set_error("Error")

        assert job.updated_at > original_updated_at


# =============================================================================
# FILEJOB SET_COMPLETE TESTS
# =============================================================================

class TestFileJobSetComplete:
    """Tests for FileJob.set_complete()."""

    def test_set_complete_sets_status(self):
        """set_complete() sets status to COMPLETE."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        job.set_complete(
            extracted_text="Hello John",
            redacted_text="Hello [NAME]",
            spans=[],
            processing_time_ms=100.0,
        )

        assert job.status == JobStatus.COMPLETE

    def test_set_complete_sets_progress_to_one(self):
        """set_complete() sets progress to 1.0."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        job.set_complete(
            extracted_text="Text",
            redacted_text="Text",
            spans=[],
            processing_time_ms=50.0,
        )

        assert job.progress == 1.0

    def test_set_complete_stores_results(self):
        """set_complete() stores all result data."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        mock_span = MagicMock()
        mock_span.start = 6
        mock_span.end = 10
        mock_span.text = "John"

        job.set_complete(
            extracted_text="Hello John Doe",
            redacted_text="Hello [NAME] [NAME]",
            spans=[mock_span],
            processing_time_ms=123.45,
            ocr_confidence=0.95,
            has_redacted_image=True,
        )

        assert job.extracted_text == "Hello John Doe"
        assert job.redacted_text == "Hello [NAME] [NAME]"
        assert len(job.spans) == 1
        assert job.phi_count == 1
        assert job.processing_time_ms == 123.45
        assert job.ocr_confidence == 0.95
        assert job.has_redacted_image is True


# =============================================================================
# FILEJOB TO_DICT TESTS
# =============================================================================

class TestFileJobToDict:
    """Tests for FileJob.to_dict()."""

    def test_to_dict_includes_required_fields(self):
        """to_dict() includes all required fields."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=2048,
        )

        result = job.to_dict()

        assert result["job_id"] == "test-123"
        assert result["filename"] == "doc.pdf"
        assert result["content_type"] == "application/pdf"
        assert result["size_bytes"] == 2048
        assert result["status"] == "queued"

    def test_to_dict_includes_timestamps_as_iso(self):
        """to_dict() includes timestamps as ISO strings."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        result = job.to_dict()

        assert "created_at" in result
        assert "updated_at" in result
        # Should be parseable ISO format
        datetime.fromisoformat(result["created_at"].replace("Z", "+00:00"))

    def test_to_dict_includes_progress(self):
        """to_dict() includes progress."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        job.progress = 0.75

        result = job.to_dict()

        assert result["progress"] == 0.75

    def test_to_dict_includes_optional_fields(self):
        """to_dict() includes optional fields."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
            conversation_id="conv-456",
            pages_total=5,
            pages_processed=3,
        )
        job.phi_count = 10
        job.has_redacted_image = True
        job.processing_time_ms = 500.0

        result = job.to_dict()

        assert result["conversation_id"] == "conv-456"
        assert result["pages_total"] == 5
        assert result["pages_processed"] == 3
        assert result["phi_count"] == 10
        assert result["has_redacted_image"] is True
        assert result["processing_time_ms"] == 500.0


# =============================================================================
# FILEJOB TO_RESULT_DICT TESTS
# =============================================================================

class TestFileJobToResultDict:
    """Tests for FileJob.to_result_dict()."""

    def test_returns_none_if_not_complete(self):
        """to_result_dict() returns None if not complete."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert job.to_result_dict() is None

    def test_returns_none_for_failed_job(self):
        """to_result_dict() returns None for failed job."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        job.set_error("Failed")

        assert job.to_result_dict() is None

    def test_returns_dict_for_complete_job(self):
        """to_result_dict() returns dict for complete job."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        mock_span = MagicMock()
        mock_span.start = 0
        mock_span.end = 4
        mock_span.text = "John"
        mock_span.entity_type = "PERSON"
        mock_span.confidence = 0.99
        mock_span.detector = "ner"
        mock_span.token = "[NAME]"

        job.set_complete(
            extracted_text="John Doe",
            redacted_text="[NAME] [NAME]",
            spans=[mock_span],
            processing_time_ms=100.0,
            ocr_confidence=0.95,
            has_redacted_image=True,
        )

        result = job.to_result_dict()

        assert result["job_id"] == "test-123"
        assert result["filename"] == "doc.pdf"
        assert result["extracted_text"] == "John Doe"
        assert result["redacted_text"] == "[NAME] [NAME]"
        assert len(result["spans"]) == 1
        assert result["spans"][0]["text"] == "John"
        assert result["processing_time_ms"] == 100.0
        assert result["ocr_confidence"] == 0.95
        assert result["has_redacted_image"] is True

    def test_result_dict_span_format(self):
        """to_result_dict() formats spans correctly."""
        job = FileJob(
            id="test-123",
            filename="doc.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        mock_span = MagicMock()
        mock_span.start = 10
        mock_span.end = 20
        mock_span.text = "555-1234"
        mock_span.entity_type = "PHONE"
        mock_span.confidence = 0.85
        mock_span.detector = "regex"
        mock_span.token = "[PHONE]"

        job.set_complete(
            extracted_text="Call me at 555-1234",
            redacted_text="Call me at [PHONE]",
            spans=[mock_span],
            processing_time_ms=50.0,
        )

        result = job.to_result_dict()
        span = result["spans"][0]

        assert span["start"] == 10
        assert span["end"] == 20
        assert span["text"] == "555-1234"
        assert span["entity_type"] == "PHONE"
        assert span["confidence"] == 0.85
        assert span["detector"] == "regex"
        assert span["token"] == "[PHONE]"


# =============================================================================
# JOBMANAGER CREATION TESTS
# =============================================================================

class TestJobManagerCreation:
    """Tests for JobManager creation."""

    def test_create_manager_default_max_jobs(self):
        """JobManager has default max_jobs."""
        manager = JobManager()

        assert manager._max_jobs == 100

    def test_create_manager_custom_max_jobs(self):
        """JobManager accepts custom max_jobs."""
        manager = JobManager(max_jobs=50)

        assert manager._max_jobs == 50

    def test_manager_starts_empty(self):
        """JobManager starts with no jobs."""
        manager = JobManager()

        assert len(manager._jobs) == 0


# =============================================================================
# JOBMANAGER CREATE_JOB TESTS
# =============================================================================

class TestJobManagerCreateJob:
    """Tests for JobManager.create_job()."""

    def test_create_job_returns_job(self):
        """create_job() returns a FileJob."""
        manager = JobManager()

        job = manager.create_job(
            filename="test.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )

        assert isinstance(job, FileJob)

    def test_create_job_generates_uuid(self):
        """create_job() generates unique UUID."""
        manager = JobManager()

        job1 = manager.create_job("a.pdf", "application/pdf", 100)
        job2 = manager.create_job("b.pdf", "application/pdf", 200)

        assert job1.id != job2.id
        assert len(job1.id) == 36  # UUID format

    def test_create_job_stores_job(self):
        """create_job() stores job in manager."""
        manager = JobManager()

        job = manager.create_job("test.pdf", "application/pdf", 1024)

        assert job.id in manager._jobs
        assert manager._jobs[job.id] is job

    def test_create_job_with_conversation_id(self):
        """create_job() accepts conversation_id."""
        manager = JobManager()

        job = manager.create_job(
            filename="test.pdf",
            content_type="application/pdf",
            size_bytes=1024,
            conversation_id="conv-123",
        )

        assert job.conversation_id == "conv-123"


# =============================================================================
# JOBMANAGER GET_JOB TESTS
# =============================================================================

class TestJobManagerGetJob:
    """Tests for JobManager.get_job()."""

    def test_get_existing_job(self):
        """get_job() returns existing job."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        result = manager.get_job(job.id)

        assert result is job

    def test_get_nonexistent_job(self):
        """get_job() returns None for nonexistent job."""
        manager = JobManager()

        result = manager.get_job("nonexistent-id")

        assert result is None


# =============================================================================
# JOBMANAGER GET_JOBS_BATCH TESTS
# =============================================================================

class TestJobManagerGetJobsBatch:
    """Tests for JobManager.get_jobs_batch()."""

    def test_get_batch_returns_dict(self):
        """get_jobs_batch() returns dict of jobs."""
        manager = JobManager()
        job1 = manager.create_job("a.pdf", "application/pdf", 100)
        job2 = manager.create_job("b.pdf", "application/pdf", 200)

        result = manager.get_jobs_batch([job1.id, job2.id])

        assert job1.id in result
        assert job2.id in result
        assert result[job1.id] is job1
        assert result[job2.id] is job2

    def test_get_batch_excludes_missing(self):
        """get_jobs_batch() excludes nonexistent jobs."""
        manager = JobManager()
        job = manager.create_job("a.pdf", "application/pdf", 100)

        result = manager.get_jobs_batch([job.id, "nonexistent"])

        assert len(result) == 1
        assert job.id in result

    def test_get_batch_empty_list(self):
        """get_jobs_batch() returns empty dict for empty list."""
        manager = JobManager()
        manager.create_job("a.pdf", "application/pdf", 100)

        result = manager.get_jobs_batch([])

        assert result == {}


# =============================================================================
# JOBMANAGER UPDATE_JOB TESTS
# =============================================================================

class TestJobManagerUpdateJob:
    """Tests for JobManager.update_job()."""

    def test_update_job_status(self):
        """update_job() updates status."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        result = manager.update_job(job.id, status=JobStatus.PROCESSING)

        assert result is job
        assert job.status == JobStatus.PROCESSING

    def test_update_job_progress(self):
        """update_job() updates progress."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        manager.update_job(job.id, progress=0.5)

        assert job.progress == 0.5

    def test_update_job_pages(self):
        """update_job() updates page counts."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        manager.update_job(job.id, pages_total=10, pages_processed=5)

        assert job.pages_total == 10
        assert job.pages_processed == 5

    def test_update_job_status_message(self):
        """update_job() updates status message."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        manager.update_job(job.id, status_message="Processing page 3 of 5")

        assert job.status_message == "Processing page 3 of 5"

    def test_update_nonexistent_job(self):
        """update_job() returns None for nonexistent job."""
        manager = JobManager()

        result = manager.update_job("nonexistent", status=JobStatus.PROCESSING)

        assert result is None


# =============================================================================
# JOBMANAGER COMPLETE_JOB TESTS
# =============================================================================

class TestJobManagerCompleteJob:
    """Tests for JobManager.complete_job()."""

    def test_complete_job_marks_complete(self):
        """complete_job() marks job as complete."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        result = manager.complete_job(
            job.id,
            extracted_text="Hello",
            redacted_text="Hello",
            spans=[],
            processing_time_ms=100.0,
        )

        assert result is job
        assert job.status == JobStatus.COMPLETE

    def test_complete_job_with_all_options(self):
        """complete_job() accepts all optional parameters."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        manager.complete_job(
            job.id,
            extracted_text="John Doe",
            redacted_text="[NAME]",
            spans=[],
            processing_time_ms=150.0,
            ocr_confidence=0.92,
            has_redacted_image=True,
        )

        assert job.ocr_confidence == 0.92
        assert job.has_redacted_image is True

    def test_complete_nonexistent_job(self):
        """complete_job() returns None for nonexistent job."""
        manager = JobManager()

        result = manager.complete_job(
            "nonexistent",
            extracted_text="",
            redacted_text="",
            spans=[],
            processing_time_ms=0.0,
        )

        assert result is None


# =============================================================================
# JOBMANAGER FAIL_JOB TESTS
# =============================================================================

class TestJobManagerFailJob:
    """Tests for JobManager.fail_job()."""

    def test_fail_job_marks_failed(self):
        """fail_job() marks job as failed."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        result = manager.fail_job(job.id, "OCR failed")

        assert result is job
        assert job.status == JobStatus.FAILED
        assert job.error == "OCR failed"

    def test_fail_nonexistent_job(self):
        """fail_job() returns None for nonexistent job."""
        manager = JobManager()

        result = manager.fail_job("nonexistent", "Error")

        assert result is None


# =============================================================================
# JOBMANAGER LIST_JOBS TESTS
# =============================================================================

class TestJobManagerListJobs:
    """Tests for JobManager.list_jobs()."""

    def test_list_all_jobs(self):
        """list_jobs() returns all jobs."""
        manager = JobManager()
        manager.create_job("a.pdf", "application/pdf", 100)
        manager.create_job("b.pdf", "application/pdf", 200)
        manager.create_job("c.pdf", "application/pdf", 300)

        jobs = manager.list_jobs()

        assert len(jobs) == 3

    def test_list_jobs_newest_first(self):
        """list_jobs() returns jobs newest first."""
        manager = JobManager()
        job1 = manager.create_job("first.pdf", "application/pdf", 100)
        time.sleep(0.01)
        job2 = manager.create_job("second.pdf", "application/pdf", 200)
        time.sleep(0.01)
        job3 = manager.create_job("third.pdf", "application/pdf", 300)

        jobs = manager.list_jobs()

        assert jobs[0].id == job3.id
        assert jobs[1].id == job2.id
        assert jobs[2].id == job1.id

    def test_list_jobs_filter_by_conversation(self):
        """list_jobs() filters by conversation_id."""
        manager = JobManager()
        manager.create_job("a.pdf", "application/pdf", 100, conversation_id="conv-1")
        manager.create_job("b.pdf", "application/pdf", 200, conversation_id="conv-2")
        manager.create_job("c.pdf", "application/pdf", 300, conversation_id="conv-1")

        jobs = manager.list_jobs(conversation_id="conv-1")

        assert len(jobs) == 2
        assert all(j.conversation_id == "conv-1" for j in jobs)

    def test_list_jobs_filter_by_status(self):
        """list_jobs() filters by status."""
        manager = JobManager()
        job1 = manager.create_job("a.pdf", "application/pdf", 100)
        job2 = manager.create_job("b.pdf", "application/pdf", 200)
        manager.fail_job(job2.id, "Error")

        jobs = manager.list_jobs(status=JobStatus.FAILED)

        assert len(jobs) == 1
        assert jobs[0].id == job2.id

    def test_list_jobs_with_limit(self):
        """list_jobs() respects limit."""
        manager = JobManager()
        for i in range(10):
            manager.create_job(f"{i}.pdf", "application/pdf", 100)

        jobs = manager.list_jobs(limit=5)

        assert len(jobs) == 5


# =============================================================================
# JOBMANAGER DELETE_JOB TESTS
# =============================================================================

class TestJobManagerDeleteJob:
    """Tests for JobManager.delete_job()."""

    def test_delete_existing_job(self):
        """delete_job() removes job."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 1024)

        result = manager.delete_job(job.id)

        assert result is True
        assert manager.get_job(job.id) is None

    def test_delete_nonexistent_job(self):
        """delete_job() returns False for nonexistent job."""
        manager = JobManager()

        result = manager.delete_job("nonexistent")

        assert result is False


# =============================================================================
# JOBMANAGER EVICTION TESTS
# =============================================================================

class TestJobManagerEviction:
    """Tests for JobManager eviction logic."""

    def test_evicts_completed_jobs_at_capacity(self):
        """Manager evicts old completed jobs at capacity."""
        manager = JobManager(max_jobs=10)

        # Create and complete jobs
        for i in range(10):
            job = manager.create_job(f"{i}.pdf", "application/pdf", 100)
            manager.complete_job(
                job.id,
                extracted_text="",
                redacted_text="",
                spans=[],
                processing_time_ms=10.0,
            )
            time.sleep(0.01)  # Ensure different timestamps

        # Create one more - should trigger eviction
        new_job = manager.create_job("new.pdf", "application/pdf", 100)

        # Should have evicted some old jobs
        assert len(manager._jobs) <= 10
        assert manager.get_job(new_job.id) is not None

    def test_evicts_failed_jobs_too(self):
        """Manager evicts failed jobs too."""
        manager = JobManager(max_jobs=5)

        # Create and fail jobs
        for i in range(5):
            job = manager.create_job(f"{i}.pdf", "application/pdf", 100)
            manager.fail_job(job.id, "Error")
            time.sleep(0.01)

        # Create new job
        new_job = manager.create_job("new.pdf", "application/pdf", 100)

        assert manager.get_job(new_job.id) is not None


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

class TestJobManagerThreadSafety:
    """Tests for JobManager thread safety."""

    def test_concurrent_create_jobs(self):
        """Concurrent job creation is thread-safe."""
        manager = JobManager()
        errors = []
        jobs = []

        def create():
            try:
                job = manager.create_job("test.pdf", "application/pdf", 100)
                jobs.append(job)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(jobs) == 50
        assert len(set(j.id for j in jobs)) == 50  # All unique IDs

    def test_concurrent_update_and_read(self):
        """Concurrent updates and reads are thread-safe."""
        manager = JobManager()
        job = manager.create_job("test.pdf", "application/pdf", 100)
        errors = []

        def update():
            try:
                for _ in range(20):
                    manager.update_job(job.id, progress=0.5)
            except Exception as e:
                errors.append(e)

        def read():
            try:
                for _ in range(20):
                    manager.get_job(job.id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=update) for _ in range(5)]
        threads += [threading.Thread(target=read) for _ in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

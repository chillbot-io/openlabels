"""Tests for file processing mixin.

Tests for FileMixin class.
"""

import sys
from enum import Enum
from unittest.mock import MagicMock, patch

import pytest

from scrubiq.mixins.file import FileMixin


# =============================================================================
# TEST CLASS SETUP
# =============================================================================

class MockFileMixin(FileMixin):
    """Mock class using FileMixin for testing."""

    def __init__(self):
        self._unlocked = True
        self._file_processor = None
        self._models_loading = False

    def _require_unlock(self):
        if not self._unlocked:
            raise RuntimeError("Session locked")


# =============================================================================
# PROCESS_FILE TESTS
# =============================================================================

class TestProcessFile:
    """Tests for process_file method."""

    def test_returns_result_dict(self):
        """Returns job result dict on success."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.to_result_dict.return_value = {
            "redacted_text": "[NAME_1] said hello",
            "spans": [],
        }
        mock_processor.process_file.return_value = mock_job
        mixin._file_processor = mock_processor

        result = mixin.process_file(
            content=b"test content",
            filename="test.txt",
        )

        assert result["redacted_text"] == "[NAME_1] said hello"

    def test_passes_all_parameters(self):
        """Passes all parameters to processor."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.to_result_dict.return_value = {}
        mock_processor.process_file.return_value = mock_job
        mixin._file_processor = mock_processor

        mixin.process_file(
            content=b"content",
            filename="doc.pdf",
            content_type="application/pdf",
            conversation_id="conv-123",
        )

        mock_processor.process_file.assert_called_once_with(
            content=b"content",
            filename="doc.pdf",
            content_type="application/pdf",
            conversation_id="conv-123",
        )

    def test_falls_back_to_to_dict(self):
        """Falls back to to_dict if to_result_dict returns None."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.to_result_dict.return_value = None
        mock_job.to_dict.return_value = {"status": "complete"}
        mock_processor.process_file.return_value = mock_job
        mixin._file_processor = mock_processor

        result = mixin.process_file(b"content", "file.txt")

        assert result == {"status": "complete"}

    def test_raises_when_processor_none(self):
        """Raises RuntimeError when file processor is None."""
        mixin = MockFileMixin()
        mixin._file_processor = None

        with pytest.raises(RuntimeError, match="File processor not initialized"):
            mixin.process_file(b"content", "file.txt")

    def test_raises_models_loading(self):
        """Raises RuntimeError when models still loading."""
        mixin = MockFileMixin()
        mixin._file_processor = None
        mixin._models_loading = True

        with pytest.raises(RuntimeError, match="MODELS_LOADING"):
            mixin.process_file(b"content", "file.txt")

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockFileMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.process_file(b"content", "file.txt")


# =============================================================================
# PROCESS_FILE_ASYNC TESTS
# =============================================================================

class TestProcessFileAsync:
    """Tests for process_file_async method."""

    def test_returns_job_id(self):
        """Returns job ID on success."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.id = "job-abc-123"
        mock_processor.process_file_async.return_value = mock_job
        mixin._file_processor = mock_processor

        result = mixin.process_file_async(b"content", "test.txt")

        assert result == "job-abc-123"

    def test_passes_all_parameters(self):
        """Passes all parameters to processor."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.id = "job-id"
        mock_processor.process_file_async.return_value = mock_job
        mixin._file_processor = mock_processor

        mixin.process_file_async(
            content=b"data",
            filename="image.png",
            content_type="image/png",
            conversation_id="conv-456",
        )

        mock_processor.process_file_async.assert_called_once_with(
            content=b"data",
            filename="image.png",
            content_type="image/png",
            conversation_id="conv-456",
        )

    def test_raises_when_processor_none(self):
        """Raises RuntimeError when processor is None."""
        mixin = MockFileMixin()
        mixin._file_processor = None

        with pytest.raises(RuntimeError, match="File processor not initialized"):
            mixin.process_file_async(b"content", "file.txt")

    def test_raises_models_loading(self):
        """Raises RuntimeError when models loading."""
        mixin = MockFileMixin()
        mixin._file_processor = None
        mixin._models_loading = True

        with pytest.raises(RuntimeError, match="MODELS_LOADING"):
            mixin.process_file_async(b"content", "file.txt")

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockFileMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.process_file_async(b"content", "file.txt")


# =============================================================================
# GET_UPLOAD_JOB TESTS
# =============================================================================

class TestGetUploadJob:
    """Tests for get_upload_job method."""

    def test_returns_job_dict(self):
        """Returns job dict when found."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_job = MagicMock()
        mock_job.to_dict.return_value = {
            "id": "job-123",
            "status": "processing",
        }
        mock_processor.get_job.return_value = mock_job
        mixin._file_processor = mock_processor

        result = mixin.get_upload_job("job-123")

        assert result["id"] == "job-123"
        assert result["status"] == "processing"

    def test_returns_none_when_not_found(self):
        """Returns None when job not found."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.get_job.return_value = None
        mixin._file_processor = mock_processor

        result = mixin.get_upload_job("nonexistent")

        assert result is None

    def test_returns_none_when_no_processor(self):
        """Returns None when no file processor."""
        mixin = MockFileMixin()
        mixin._file_processor = None

        result = mixin.get_upload_job("job-123")

        assert result is None

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockFileMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_upload_job("job-123")


# =============================================================================
# GET_UPLOAD_RESULT TESTS
# =============================================================================

class TestGetUploadResult:
    """Tests for get_upload_result method."""

    def test_returns_result(self):
        """Returns result when job complete."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.get_job_result.return_value = {
            "redacted_text": "text",
            "spans": [],
        }
        mixin._file_processor = mock_processor

        result = mixin.get_upload_result("job-123")

        assert result["redacted_text"] == "text"

    def test_returns_none_when_incomplete(self):
        """Returns None when job not complete."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.get_job_result.return_value = None
        mixin._file_processor = mock_processor

        result = mixin.get_upload_result("job-123")

        assert result is None

    def test_returns_none_when_no_processor(self):
        """Returns None when no file processor."""
        mixin = MockFileMixin()
        mixin._file_processor = None

        result = mixin.get_upload_result("job-123")

        assert result is None

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockFileMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_upload_result("job-123")


# =============================================================================
# GET_UPLOAD_RESULTS_BATCH TESTS
# =============================================================================

class TestGetUploadResultsBatch:
    """Tests for get_upload_results_batch method."""

    def test_returns_batch_results(self):
        """Returns dict of results for batch."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.get_job_results_batch.return_value = {
            "job-1": {"text": "result1"},
            "job-2": {"text": "result2"},
        }
        mixin._file_processor = mock_processor

        result = mixin.get_upload_results_batch(["job-1", "job-2", "job-3"])

        assert len(result) == 2
        assert "job-1" in result
        assert "job-2" in result

    def test_returns_empty_when_no_processor(self):
        """Returns empty dict when no file processor."""
        mixin = MockFileMixin()
        mixin._file_processor = None

        result = mixin.get_upload_results_batch(["job-1"])

        assert result == {}

    def test_passes_job_ids_to_processor(self):
        """Passes job IDs to processor."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.get_job_results_batch.return_value = {}
        mixin._file_processor = mock_processor

        mixin.get_upload_results_batch(["id-1", "id-2"])

        mock_processor.get_job_results_batch.assert_called_once_with(["id-1", "id-2"])

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockFileMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_upload_results_batch(["job-1"])


# =============================================================================
# GET_REDACTED_IMAGE TESTS
# =============================================================================

class TestGetRedactedImage:
    """Tests for get_redacted_image method."""

    @pytest.fixture(autouse=True)
    def mock_storage_import(self):
        """Mock the storage import to avoid SQLCipher requirement."""
        import sys
        from enum import Enum

        class MockImageFileType(Enum):
            REDACTED = "redacted"
            REDACTED_PDF = "redacted_pdf"

        # Create a mock storage module
        mock_storage = MagicMock()
        mock_storage.ImageFileType = MockImageFileType

        # Save original and patch
        original = sys.modules.get("scrubiq.storage")
        sys.modules["scrubiq.storage"] = mock_storage

        yield MockImageFileType

        # Restore original
        if original is not None:
            sys.modules["scrubiq.storage"] = original
        else:
            del sys.modules["scrubiq.storage"]

    def test_returns_image_tuple(self, mock_storage_import):
        """Returns tuple of (bytes, filename, content_type)."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_image_store = MagicMock()

        mock_info = MagicMock()
        mock_info.original_filename = "document.pdf"
        mock_info.content_type = "application/pdf"

        mock_image_store.retrieve.return_value = (b"image_bytes", mock_info)
        mock_processor.image_store = mock_image_store
        mixin._file_processor = mock_processor

        result = mixin.get_redacted_image("job-123")

        assert result[0] == b"image_bytes"
        assert result[1] == "document.pdf"
        assert result[2] == "application/pdf"

    def test_returns_none_when_not_found(self, mock_storage_import):
        """Returns None when image not found."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_image_store = MagicMock()
        mock_image_store.retrieve.return_value = None
        mock_processor.image_store = mock_image_store
        mixin._file_processor = mock_processor

        result = mixin.get_redacted_image("job-123")

        assert result is None

    def test_returns_none_when_no_processor(self):
        """Returns None when no file processor."""
        mixin = MockFileMixin()
        mixin._file_processor = None

        result = mixin.get_redacted_image("job-123")

        assert result is None

    def test_returns_none_when_no_image_store(self):
        """Returns None when no image store."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.image_store = None
        mixin._file_processor = mock_processor

        result = mixin.get_redacted_image("job-123")

        assert result is None

    def test_tries_multiple_file_types(self, mock_storage_import):
        """Tries REDACTED then REDACTED_PDF file types."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_image_store = MagicMock()

        # First call returns None, second returns result
        mock_info = MagicMock()
        mock_info.original_filename = "doc.pdf"
        mock_info.content_type = "application/pdf"
        mock_image_store.retrieve.side_effect = [None, (b"pdf_bytes", mock_info)]
        mock_processor.image_store = mock_image_store
        mixin._file_processor = mock_processor

        result = mixin.get_redacted_image("job-123")

        assert result[0] == b"pdf_bytes"

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockFileMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.get_redacted_image("job-123")


# =============================================================================
# LIST_UPLOAD_JOBS TESTS
# =============================================================================

class TestListUploadJobs:
    """Tests for list_upload_jobs method."""

    def test_returns_job_list(self):
        """Returns list of job dicts."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()

        mock_job1 = MagicMock()
        mock_job1.to_dict.return_value = {"id": "job-1", "status": "complete"}
        mock_job2 = MagicMock()
        mock_job2.to_dict.return_value = {"id": "job-2", "status": "processing"}

        mock_processor.list_jobs.return_value = [mock_job1, mock_job2]
        mixin._file_processor = mock_processor

        result = mixin.list_upload_jobs()

        assert len(result) == 2
        assert result[0]["id"] == "job-1"
        assert result[1]["id"] == "job-2"

    def test_passes_parameters(self):
        """Passes conversation_id and limit to processor."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.list_jobs.return_value = []
        mixin._file_processor = mock_processor

        mixin.list_upload_jobs(conversation_id="conv-123", limit=25)

        mock_processor.list_jobs.assert_called_once_with(
            conversation_id="conv-123",
            limit=25,
        )

    def test_default_limit(self):
        """Uses default limit of 50."""
        mixin = MockFileMixin()
        mock_processor = MagicMock()
        mock_processor.list_jobs.return_value = []
        mixin._file_processor = mock_processor

        mixin.list_upload_jobs()

        mock_processor.list_jobs.assert_called_once_with(
            conversation_id=None,
            limit=50,
        )

    def test_returns_empty_when_no_processor(self):
        """Returns empty list when no file processor."""
        mixin = MockFileMixin()
        mixin._file_processor = None

        result = mixin.list_upload_jobs()

        assert result == []

    def test_requires_unlock(self):
        """Raises when session is locked."""
        mixin = MockFileMixin()
        mixin._unlocked = False

        with pytest.raises(RuntimeError, match="locked"):
            mixin.list_upload_jobs()

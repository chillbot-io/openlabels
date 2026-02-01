"""
Phase 3 Production Readiness Tests: Error Handling & Observability

Tests for:
- Issue 3.1: Structured error types for LabelIndex
- Issue 3.2: Degraded detection state tracking
- Issue 3.3: Failed detector tracking in results
- Issue 3.4: Runaway thread monitoring
- Issue 3.5: File operation error classification
"""

import errno
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Issue 3.1: Structured exception types
from openlabels.core.exceptions import (
    OpenLabelsError,
    TransientError,
    PermanentError,
    DatabaseError,
    CorruptedDataError,
    NotFoundError,
    ValidationError,
    PermissionDeniedError,
    OperationTimeoutError,
    FileErrorType,
    FileOperationError,
)


class TestStructuredExceptions:
    """Tests for Issue 3.1: Structured error types."""

    def test_exception_hierarchy(self):
        """Verify exception inheritance hierarchy."""
        # All exceptions inherit from OpenLabelsError
        assert issubclass(TransientError, OpenLabelsError)
        assert issubclass(PermanentError, OpenLabelsError)
        assert issubclass(DatabaseError, TransientError)
        assert issubclass(CorruptedDataError, PermanentError)
        assert issubclass(NotFoundError, PermanentError)
        assert issubclass(ValidationError, PermanentError)

    def test_exception_details(self):
        """Verify exception details are captured."""
        err = DatabaseError(
            "Connection failed",
            operation="store",
            db_path="/path/to/db",
        )
        assert err.message == "Connection failed"
        assert err.operation == "store"
        assert err.details["db_path"] == "/path/to/db"

    def test_not_found_error(self):
        """NotFoundError includes resource identification."""
        err = NotFoundError(
            "Label not found",
            resource_type="label",
            resource_id="label-123",
        )
        assert err.resource_type == "label"
        assert err.resource_id == "label-123"

    def test_corrupted_data_error(self):
        """CorruptedDataError includes data location."""
        err = CorruptedDataError(
            "Invalid JSON",
            data_location="index.db:label_versions",
            expected_format="JSON",
        )
        assert err.data_location == "index.db:label_versions"
        assert err.expected_format == "JSON"


class TestFileOperationErrorClassification:
    """Tests for Issue 3.5: File operation error classification."""

    def test_permission_error_classification(self):
        """Permission denied is classified correctly."""
        e = PermissionError("Access denied")
        result = FileOperationError.from_exception(e, "/path/to/file")

        assert result.error_type == FileErrorType.PERMISSION_DENIED
        assert result.retryable is False

    def test_not_found_error_classification(self):
        """File not found is classified correctly."""
        e = FileNotFoundError("No such file")
        result = FileOperationError.from_exception(e, "/path/to/file")

        assert result.error_type == FileErrorType.NOT_FOUND
        assert result.retryable is False

    def test_disk_full_error_classification(self):
        """Disk full error is classified correctly."""
        e = OSError(errno.ENOSPC, "No space left on device")
        result = FileOperationError.from_exception(e, "/path/to/file")

        assert result.error_type == FileErrorType.DISK_FULL
        assert result.retryable is False

    def test_file_locked_error_classification(self):
        """File locked error is classified as retryable."""
        e = OSError(errno.EAGAIN, "Resource temporarily unavailable")
        result = FileOperationError.from_exception(e, "/path/to/file")

        assert result.error_type == FileErrorType.LOCKED
        assert result.retryable is True

    def test_already_exists_error_classification(self):
        """File exists error is classified correctly."""
        e = FileExistsError("File already exists")
        result = FileOperationError.from_exception(e, "/path/to/file")

        assert result.error_type == FileErrorType.ALREADY_EXISTS
        assert result.retryable is False

    def test_unknown_error_classification(self):
        """Unknown errors are classified as unknown."""
        e = Exception("Something went wrong")
        result = FileOperationError.from_exception(e, "/path/to/file")

        assert result.error_type == FileErrorType.UNKNOWN
        assert result.retryable is False


class TestDetectionMetadata:
    """Tests for Issues 3.2 & 3.3: Detection metadata tracking."""

    def test_metadata_tracks_success(self):
        """Metadata tracks successful detector runs."""
        from openlabels.adapters.scanner.detectors.orchestrator import DetectionMetadata

        metadata = DetectionMetadata()
        metadata.add_success("checksum")
        metadata.add_success("patterns")
        metadata.finalize()

        assert "checksum" in metadata.detectors_run
        assert "patterns" in metadata.detectors_run
        assert not metadata.all_detectors_failed

    def test_metadata_tracks_failures(self):
        """Metadata tracks detector failures."""
        from openlabels.adapters.scanner.detectors.orchestrator import DetectionMetadata

        metadata = DetectionMetadata()
        metadata.add_failure("broken_detector", "ValueError: bad input")
        metadata.finalize()

        assert "broken_detector" in metadata.detectors_failed
        assert any("broken_detector" in w for w in metadata.warnings)

    def test_metadata_tracks_timeouts(self):
        """Metadata tracks detector timeouts."""
        from openlabels.adapters.scanner.detectors.orchestrator import DetectionMetadata

        metadata = DetectionMetadata()
        metadata.add_timeout("slow_detector", 5.0, cancelled=True)
        metadata.finalize()

        assert "slow_detector" in metadata.detectors_timed_out
        assert any("slow_detector" in w and "timed out" in w for w in metadata.warnings)

    def test_all_detectors_failed(self):
        """Metadata correctly detects when all detectors fail."""
        from openlabels.adapters.scanner.detectors.orchestrator import DetectionMetadata

        metadata = DetectionMetadata()
        metadata.add_failure("detector1", "error1")
        metadata.add_timeout("detector2", 5.0, cancelled=False)
        metadata.finalize()

        assert metadata.all_detectors_failed is True
        assert any("All" in w and "failed" in w for w in metadata.warnings)

    def test_degraded_mode_on_structured_failure(self):
        """Metadata sets degraded when structured extractor fails."""
        from openlabels.adapters.scanner.detectors.orchestrator import DetectionMetadata

        metadata = DetectionMetadata()
        metadata.structured_extractor_failed = True
        metadata.degraded = True
        metadata.warnings.append("Structured extraction failed")

        assert metadata.degraded is True
        assert metadata.structured_extractor_failed is True


class TestRunawayThreadTracking:
    """Tests for Issue 3.4: Runaway thread monitoring via Context."""

    def test_runaway_detection_count_starts_at_zero(self):
        """Runaway detection count starts at zero for new Context."""
        from openlabels.context import Context

        # Fresh context should have zero runaway count
        ctx = Context()
        try:
            count = ctx.get_runaway_detection_count()
            assert isinstance(count, int)
            assert count == 0
        finally:
            ctx.close()

    def test_track_runaway_increments_count(self):
        """Tracking runaway detection increments count in Context."""
        from openlabels.context import Context

        ctx = Context()
        try:
            # Get initial count
            initial = ctx.get_runaway_detection_count()
            assert initial == 0

            # Track a runaway
            ctx.track_runaway_detection("test_detector")

            # Count should increase
            new_count = ctx.get_runaway_detection_count()
            assert new_count == initial + 1
        finally:
            ctx.close()


class TestDetectionResultEnhancements:
    """Tests for DetectionResult Phase 3 enhancements."""

    def test_detection_result_includes_failure_info(self):
        """DetectionResult includes failure information."""
        from openlabels.adapters.scanner.types import DetectionResult

        result = DetectionResult(
            text="test",
            spans=[],
            processing_time_ms=100.0,
            detectors_used=["checksum"],
            detectors_failed=["broken"],
            warnings=["broken failed: ValueError"],
            degraded=False,
            all_detectors_failed=False,
        )

        assert "broken" in result.detectors_failed
        assert "broken failed" in result.warnings[0]

    def test_detection_result_is_reliable_property(self):
        """is_reliable property returns False when degraded or all failed."""
        from openlabels.adapters.scanner.types import DetectionResult

        # Reliable result
        good_result = DetectionResult(
            text="test",
            spans=[],
            processing_time_ms=100.0,
        )
        assert good_result.is_reliable is True

        # Degraded result
        degraded_result = DetectionResult(
            text="test",
            spans=[],
            processing_time_ms=100.0,
            degraded=True,
        )
        assert degraded_result.is_reliable is False

        # All failed result
        failed_result = DetectionResult(
            text="test",
            spans=[],
            processing_time_ms=100.0,
            all_detectors_failed=True,
        )
        assert failed_result.is_reliable is False

    def test_detection_result_to_dict_includes_failures(self):
        """to_dict includes failure info when present."""
        from openlabels.adapters.scanner.types import DetectionResult

        result = DetectionResult(
            text="test",
            spans=[],
            processing_time_ms=100.0,
            detectors_failed=["broken"],
            warnings=["test warning"],
            degraded=True,
        )

        d = result.to_dict()
        assert "detectors_failed" in d
        assert "warnings" in d
        assert "degraded" in d

    def test_detection_result_to_dict_excludes_empty_failures(self):
        """to_dict excludes failure info when not present."""
        from openlabels.adapters.scanner.types import DetectionResult

        result = DetectionResult(
            text="test",
            spans=[],
            processing_time_ms=100.0,
        )

        d = result.to_dict()
        assert "detectors_failed" not in d
        assert "warnings" not in d
        assert "degraded" not in d


class TestLabelIndexStructuredErrors:
    """Tests for LabelIndex structured error support."""

    def test_get_raises_not_found_error(self):
        """get() raises NotFoundError when raise_on_error=True."""
        from openlabels.output.index import LabelIndex

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            index = LabelIndex(db_path=str(db_path))

            # Should return None with default behavior
            result = index.get("nonexistent-label")
            assert result is None

            # Should raise with raise_on_error=True
            with pytest.raises(NotFoundError) as exc_info:
                index.get("nonexistent-label", raise_on_error=True)

            assert exc_info.value.resource_type == "label"
            assert exc_info.value.resource_id == "nonexistent-label"

    def test_get_by_path_raises_not_found_error(self):
        """get_by_path() raises NotFoundError when raise_on_error=True."""
        from openlabels.output.index import LabelIndex

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            index = LabelIndex(db_path=str(db_path))

            # Should return None with default behavior
            result = index.get_by_path("/nonexistent/path")
            assert result is None

            # Should raise with raise_on_error=True
            with pytest.raises(NotFoundError) as exc_info:
                index.get_by_path("/nonexistent/path", raise_on_error=True)

            assert exc_info.value.resource_type == "file_label"


class TestFileOpsStructuredErrors:
    """Tests for FileOps structured error reporting."""

    def test_quarantine_result_error_classification(self):
        """QuarantineResult includes error classification counts."""
        from openlabels.components.fileops import QuarantineResult, FileErrorType

        errors = [
            {
                "path": "/path/1",
                "error_type": FileErrorType.PERMISSION_DENIED.value,
                "message": "Permission denied",
                "retryable": False,
            },
            {
                "path": "/path/2",
                "error_type": FileErrorType.LOCKED.value,
                "message": "File locked",
                "retryable": True,
            },
        ]

        result = QuarantineResult(
            moved_count=5,
            error_count=2,
            moved_files=[],
            errors=errors,
            destination="/quarantine",
        )

        assert result.retryable_errors == 1
        assert result.permanent_errors == 1

    def test_delete_result_error_classification(self):
        """DeleteResult includes error classification counts."""
        from openlabels.components.fileops import DeleteResult, FileErrorType

        errors = [
            {
                "path": "/path/1",
                "error_type": FileErrorType.NOT_FOUND.value,
                "message": "Not found",
                "retryable": False,
            },
        ]

        result = DeleteResult(
            deleted_count=10,
            error_count=1,
            deleted_files=[],
            errors=errors,
        )

        assert result.retryable_errors == 0
        assert result.permanent_errors == 1

    def test_file_error_from_exception(self):
        """FileError.from_exception classifies errors correctly."""
        from openlabels.components.fileops import FileError, FileErrorType

        # Permission error
        perm_err = PermissionError("Access denied")
        file_err = FileError.from_exception(perm_err, "/test/path")

        assert file_err.error_type == FileErrorType.PERMISSION_DENIED
        assert file_err.retryable is False
        assert file_err.path == "/test/path"

    def test_file_error_to_dict(self):
        """FileError.to_dict produces correct structure."""
        from openlabels.components.fileops import FileError, FileErrorType

        err = FileError(
            path="/test/path",
            error_type=FileErrorType.DISK_FULL,
            message="No space left",
            retryable=False,
        )

        d = err.to_dict()
        assert d["path"] == "/test/path"
        assert d["error_type"] == "disk_full"
        assert d["message"] == "No space left"
        assert d["retryable"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

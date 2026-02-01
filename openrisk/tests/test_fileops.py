"""
Tests for FileOps component.

Tests critical file operation functionality:
- Quarantine operations with idempotency
- Delete operations with proper safeguards
- Symlink detection and rejection (TOCTOU protection)
- Atomic operation handling
- Error classification and retryability
"""

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from openlabels.components.fileops import (
    FileError,
    FileOps,
    QuarantineResult,
    DeleteResult,
    QUARANTINE_MANIFEST,
)
from openlabels.core.types import FilterCriteria, OperationResult
from openlabels.core.exceptions import FileErrorType


class TestFileError:
    """Tests for FileError dataclass."""

    def test_to_dict_serialization(self):
        """FileError should serialize to dict correctly."""
        error = FileError(
            path="/test/file.txt",
            error_type=FileErrorType.PERMISSION_DENIED,
            message="Access denied",
            retryable=False,
        )
        result = error.to_dict()

        assert result["path"] == "/test/file.txt"
        assert result["error_type"] == "permission_denied"
        assert result["message"] == "Access denied"
        assert result["retryable"] is False

    def test_from_permission_error(self):
        """Should classify PermissionError correctly."""
        exc = PermissionError("Access denied")
        error = FileError.from_exception(exc, "/test/file.txt")

        assert error.error_type == FileErrorType.PERMISSION_DENIED
        assert error.retryable is False

    def test_from_file_not_found_error(self):
        """Should classify FileNotFoundError correctly."""
        exc = FileNotFoundError("No such file")
        error = FileError.from_exception(exc, "/test/file.txt")

        assert error.error_type == FileErrorType.NOT_FOUND
        assert error.retryable is False

    def test_from_file_exists_error(self):
        """Should classify FileExistsError correctly."""
        exc = FileExistsError("File already exists")
        error = FileError.from_exception(exc, "/test/file.txt")

        assert error.error_type == FileErrorType.ALREADY_EXISTS
        assert error.retryable is False

    def test_from_disk_full_error(self):
        """Should classify disk full error correctly."""
        import errno
        exc = OSError(errno.ENOSPC, "No space left on device")
        error = FileError.from_exception(exc, "/test/file.txt")

        assert error.error_type == FileErrorType.DISK_FULL
        assert error.retryable is False

    def test_from_lock_error(self):
        """Should classify lock errors as retryable."""
        import errno
        exc = OSError(errno.EAGAIN, "Resource temporarily unavailable")
        error = FileError.from_exception(exc, "/test/file.txt")

        assert error.error_type == FileErrorType.LOCKED
        assert error.retryable is True

    def test_from_unknown_error(self):
        """Should handle unknown errors."""
        exc = RuntimeError("Unknown error")
        error = FileError.from_exception(exc, "/test/file.txt")

        assert error.error_type == FileErrorType.UNKNOWN
        assert error.retryable is False


class TestQuarantineResult:
    """Tests for QuarantineResult dataclass."""

    def test_error_classification_counts(self):
        """Should calculate retryable vs permanent error counts."""
        result = QuarantineResult(
            moved_count=5,
            error_count=3,
            moved_files=[],
            errors=[
                {"retryable": True, "path": "/a"},
                {"retryable": False, "path": "/b"},
                {"retryable": True, "path": "/c"},
            ],
            destination="/quarantine",
        )

        assert result.retryable_errors == 2
        assert result.permanent_errors == 1


class TestDeleteResult:
    """Tests for DeleteResult dataclass."""

    def test_error_classification_counts(self):
        """Should calculate retryable vs permanent error counts."""
        result = DeleteResult(
            deleted_count=10,
            error_count=4,
            deleted_files=[],
            errors=[
                {"retryable": False, "path": "/a"},
                {"retryable": False, "path": "/b"},
                {"retryable": True, "path": "/c"},
                {"retryable": False, "path": "/d"},
            ],
        )

        assert result.retryable_errors == 1
        assert result.permanent_errors == 3


class TestFileOpsMove:
    """Tests for FileOps.move() method."""

    @pytest.fixture
    def fileops(self):
        """Create FileOps instance with mocked dependencies."""
        mock_ctx = MagicMock()
        mock_scanner = MagicMock()
        return FileOps(mock_ctx, mock_scanner)

    def test_move_regular_file(self, fileops, tmp_path):
        """Should successfully move a regular file."""
        source = tmp_path / "source.txt"
        source.write_text("content")
        dest = tmp_path / "dest" / "moved.txt"

        result = fileops.move(source, dest)

        assert result.success is True
        assert result.operation == "move"
        assert not source.exists()
        assert dest.exists()
        assert dest.read_text() == "content"

    def test_move_rejects_symlink(self, fileops, tmp_path):
        """Should reject symlink source (TOCTOU protection)."""
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        dest = tmp_path / "dest.txt"

        result = fileops.move(link, dest)

        assert result.success is False
        assert "Symlinks not allowed" in result.error
        assert result.metadata["error_type"] == FileErrorType.PERMISSION_DENIED.value
        assert result.metadata["retryable"] is False
        # Original files should be unchanged
        assert link.exists()
        assert target.exists()

    def test_move_rejects_directory(self, fileops, tmp_path):
        """Should reject directory source (only regular files)."""
        source_dir = tmp_path / "source_dir"
        source_dir.mkdir()
        dest = tmp_path / "dest_dir"

        result = fileops.move(source_dir, dest)

        assert result.success is False
        assert "Not a regular file" in result.error

    def test_move_nonexistent_source(self, fileops, tmp_path):
        """Should handle non-existent source file."""
        source = tmp_path / "nonexistent.txt"
        dest = tmp_path / "dest.txt"

        result = fileops.move(source, dest)

        assert result.success is False
        assert result.metadata["error_type"] == FileErrorType.NOT_FOUND.value

    def test_move_creates_parent_directories(self, fileops, tmp_path):
        """Should create parent directories for destination."""
        source = tmp_path / "source.txt"
        source.write_text("content")
        dest = tmp_path / "nested" / "deep" / "dest.txt"

        result = fileops.move(source, dest)

        assert result.success is True
        assert dest.exists()
        assert dest.parent.exists()

    def test_move_returns_structured_error_on_oserror(self, fileops, tmp_path):
        """Should return structured error info on OSError."""
        source = tmp_path / "source.txt"
        source.write_text("content")
        # Make source read-only directory to cause permission error
        # on some systems when moving
        dest = tmp_path / "dest.txt"

        # Mock to simulate permission error
        with patch('shutil.move', side_effect=PermissionError("Access denied")):
            result = fileops.move(source, dest)

        assert result.success is False
        assert result.metadata["error_type"] == FileErrorType.PERMISSION_DENIED.value


class TestFileOpsQuarantine:
    """Tests for FileOps.quarantine() method."""

    @pytest.fixture
    def fileops(self):
        """Create FileOps instance with mocked scanner."""
        mock_ctx = MagicMock()
        mock_scanner = MagicMock()
        return FileOps(mock_ctx, mock_scanner), mock_scanner

    def test_quarantine_dry_run(self, fileops, tmp_path):
        """Dry run should not move files."""
        ops, scanner = fileops
        source = tmp_path / "source"
        source.mkdir()
        test_file = source / "test.txt"
        test_file.write_text("content")

        # Mock scanner to return the test file
        scanner.scan.return_value = [
            MagicMock(path=str(test_file), score=90, tier="CRITICAL", error=None)
        ]

        quarantine_dir = tmp_path / "quarantine"
        result = ops.quarantine(source, quarantine_dir, dry_run=True)

        assert result.moved_count == 1
        assert result.moved_files[0]["dry_run"] is True
        assert test_file.exists()  # File should still exist

    def test_quarantine_moves_files(self, fileops, tmp_path):
        """Should move matching files to quarantine."""
        ops, scanner = fileops
        source = tmp_path / "source"
        source.mkdir()
        test_file = source / "test.txt"
        test_file.write_text("content")

        scanner.scan.return_value = [
            MagicMock(path=str(test_file), score=90, tier="CRITICAL", error=None)
        ]

        quarantine_dir = tmp_path / "quarantine"
        result = ops.quarantine(source, quarantine_dir, dry_run=False)

        assert result.moved_count == 1
        assert not test_file.exists()
        assert (quarantine_dir / "test.txt").exists()

    def test_quarantine_creates_manifest(self, fileops, tmp_path):
        """Should create quarantine manifest for idempotency."""
        ops, scanner = fileops
        source = tmp_path / "source"
        source.mkdir()
        test_file = source / "test.txt"
        test_file.write_text("content")

        scanner.scan.return_value = [
            MagicMock(path=str(test_file), score=90, tier="CRITICAL", error=None)
        ]

        quarantine_dir = tmp_path / "quarantine"
        ops.quarantine(source, quarantine_dir, dry_run=False)

        manifest_path = quarantine_dir / QUARANTINE_MANIFEST
        assert manifest_path.exists()

        manifest = json.loads(manifest_path.read_text())
        assert "processed" in manifest
        assert str(test_file) in manifest["processed"]

    def test_quarantine_rejects_symlink(self, fileops, tmp_path):
        """Should reject symlinks in quarantine operation."""
        ops, scanner = fileops
        source = tmp_path / "source"
        source.mkdir()
        target = source / "target.txt"
        target.write_text("content")
        link = source / "link.txt"
        link.symlink_to(target)

        # Scanner returns the symlink
        scanner.scan.return_value = [
            MagicMock(path=str(link), score=90, tier="CRITICAL", error=None)
        ]

        quarantine_dir = tmp_path / "quarantine"
        result = ops.quarantine(source, quarantine_dir, dry_run=False)

        assert result.error_count == 1
        assert result.moved_count == 0
        assert "Symlinks not allowed" in result.errors[0]["message"]

    def test_quarantine_handles_scan_errors(self, fileops, tmp_path):
        """Should handle scanner errors gracefully."""
        ops, scanner = fileops
        source = tmp_path / "source"
        source.mkdir()

        # Scanner returns an error result
        scanner.scan.return_value = [
            MagicMock(path="/some/file.txt", score=None, tier=None, error="Scan failed")
        ]

        quarantine_dir = tmp_path / "quarantine"
        result = ops.quarantine(source, quarantine_dir, dry_run=False)

        assert result.error_count == 1
        assert result.moved_count == 0


class TestFileOpsIdempotentMove:
    """Tests for idempotent move operation."""

    @pytest.fixture
    def fileops(self):
        """Create FileOps instance."""
        mock_ctx = MagicMock()
        mock_scanner = MagicMock()
        return FileOps(mock_ctx, mock_scanner)

    def test_idempotent_move_same_content_skips(self, fileops, tmp_path):
        """Should skip if dest exists with same content."""
        source = tmp_path / "source.txt"
        source.write_text("content")
        dest = tmp_path / "dest.txt"
        dest.write_text("content")  # Same content
        manifest_path = tmp_path / QUARANTINE_MANIFEST

        success, error = fileops._idempotent_move(source, dest, manifest_path)

        assert success is True
        assert error is None
        assert source.exists()  # Source unchanged (idempotent skip)

    def test_idempotent_move_different_content_errors(self, fileops, tmp_path):
        """Should error if dest exists with different content."""
        source = tmp_path / "source.txt"
        source.write_text("content1")
        dest = tmp_path / "dest.txt"
        dest.write_text("content2")  # Different content
        manifest_path = tmp_path / QUARANTINE_MANIFEST

        success, error = fileops._idempotent_move(source, dest, manifest_path)

        assert success is False
        assert error is not None
        assert error.error_type == FileErrorType.ALREADY_EXISTS

    def test_idempotent_move_source_missing_dest_exists_in_manifest(self, fileops, tmp_path):
        """Should succeed if source is in manifest (already processed)."""
        source = tmp_path / "source.txt"  # Does not exist
        dest = tmp_path / "dest.txt"
        dest.write_text("content")
        manifest_path = tmp_path / QUARANTINE_MANIFEST

        # Create manifest with source marked as processed
        manifest = {"processed": {str(source): {"dest": str(dest), "hash": "abc"}}}
        manifest_path.write_text(json.dumps(manifest))

        success, error = fileops._idempotent_move(source, dest, manifest_path)

        assert success is True
        assert error is None

    def test_idempotent_move_rejects_symlink_source(self, fileops, tmp_path):
        """Should reject symlink source."""
        target = tmp_path / "target.txt"
        target.write_text("content")
        source = tmp_path / "link.txt"
        source.symlink_to(target)
        dest = tmp_path / "dest.txt"
        manifest_path = tmp_path / QUARANTINE_MANIFEST

        success, error = fileops._idempotent_move(source, dest, manifest_path)

        assert success is False
        assert error is not None
        assert "Symlinks not allowed" in error.message

    def test_idempotent_move_rejects_directory(self, fileops, tmp_path):
        """Should reject directory source."""
        source = tmp_path / "source_dir"
        source.mkdir()
        dest = tmp_path / "dest_dir"
        manifest_path = tmp_path / QUARANTINE_MANIFEST

        success, error = fileops._idempotent_move(source, dest, manifest_path)

        assert success is False
        assert "Not a regular file" in error.message


class TestFileOpsDelete:
    """Tests for FileOps.delete() method."""

    @pytest.fixture
    def fileops(self):
        """Create FileOps instance."""
        mock_ctx = MagicMock()
        mock_scanner = MagicMock()
        return FileOps(mock_ctx, mock_scanner), mock_scanner

    def test_delete_single_file(self, fileops, tmp_path):
        """Should delete a single file."""
        ops, scanner = fileops
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = ops.delete(test_file, dry_run=False)

        assert result.deleted_count == 1
        assert not test_file.exists()

    def test_delete_single_file_dry_run(self, fileops, tmp_path):
        """Dry run should not delete file."""
        ops, scanner = fileops
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = ops.delete(test_file, dry_run=True)

        assert result.deleted_count == 1
        assert test_file.exists()  # Should still exist

    def test_delete_rejects_symlink(self, fileops, tmp_path):
        """Should reject symlink deletion."""
        ops, scanner = fileops
        target = tmp_path / "target.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        result = ops.delete(link, dry_run=False)

        assert result.error_count == 1
        assert result.deleted_count == 0
        assert "Symlinks not allowed" in result.errors[0]["message"]
        # Both should still exist
        assert link.exists()
        assert target.exists()

    def test_delete_nonexistent_file(self, fileops, tmp_path):
        """Should handle non-existent file."""
        ops, scanner = fileops
        nonexistent = tmp_path / "nonexistent.txt"

        result = ops.delete(nonexistent, dry_run=False)

        assert result.error_count == 1
        assert result.errors[0]["error_type"] == FileErrorType.NOT_FOUND.value

    def test_delete_directory_with_filter(self, fileops, tmp_path):
        """Should delete matching files in directory."""
        ops, scanner = fileops
        source = tmp_path / "source"
        source.mkdir()
        file1 = source / "file1.txt"
        file1.write_text("content1")
        file2 = source / "file2.txt"
        file2.write_text("content2")

        # Scanner returns both files
        scanner.scan.return_value = [
            MagicMock(path=str(file1), score=90, tier="CRITICAL", error=None),
            MagicMock(path=str(file2), score=85, tier="HIGH", error=None),
        ]

        result = ops.delete(source, dry_run=False)

        assert result.deleted_count == 2
        assert not file1.exists()
        assert not file2.exists()

    def test_delete_handles_permission_error(self, fileops, tmp_path):
        """Should handle permission errors gracefully."""
        ops, scanner = fileops
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Mock unlink to raise permission error
        with patch.object(Path, 'unlink', side_effect=PermissionError("Access denied")):
            result = ops.delete(test_file, dry_run=False)

        assert result.error_count == 1
        assert result.errors[0]["error_type"] == FileErrorType.PERMISSION_DENIED.value


class TestFileOpsFilterCriteria:
    """Tests for filter criteria building."""

    @pytest.fixture
    def fileops(self):
        """Create FileOps instance."""
        mock_ctx = MagicMock()
        mock_scanner = MagicMock()
        return FileOps(mock_ctx, mock_scanner)

    def test_build_filter_with_min_score_only(self, fileops):
        """Should create FilterCriteria from min_score."""
        result = fileops._build_filter_criteria(None, min_score=75)

        assert result is not None
        assert result.min_score == 75

    def test_build_filter_merges_min_score(self, fileops):
        """Should merge min_score into existing criteria."""
        existing = FilterCriteria(min_score=50)
        result = fileops._build_filter_criteria(existing, min_score=75)

        assert result.min_score == 75

    def test_build_filter_passes_through_none(self, fileops):
        """Should return None if no criteria provided."""
        result = fileops._build_filter_criteria(None, None)

        assert result is None


class TestManifestHandling:
    """Tests for quarantine manifest file handling."""

    @pytest.fixture
    def fileops(self):
        """Create FileOps instance."""
        mock_ctx = MagicMock()
        mock_scanner = MagicMock()
        return FileOps(mock_ctx, mock_scanner)

    def test_load_manifest_creates_empty_if_missing(self, fileops, tmp_path):
        """Should return empty manifest if file doesn't exist."""
        manifest_path = tmp_path / QUARANTINE_MANIFEST

        manifest = fileops._load_manifest(manifest_path)

        assert manifest == {"processed": {}}

    def test_load_manifest_reads_existing(self, fileops, tmp_path):
        """Should read existing manifest file."""
        manifest_path = tmp_path / QUARANTINE_MANIFEST
        manifest_path.write_text('{"processed": {"file1": {}}}')

        manifest = fileops._load_manifest(manifest_path)

        assert "file1" in manifest["processed"]

    def test_load_manifest_handles_corrupt_json(self, fileops, tmp_path):
        """Should handle corrupted manifest gracefully."""
        manifest_path = tmp_path / QUARANTINE_MANIFEST
        manifest_path.write_text('invalid json{{{')

        manifest = fileops._load_manifest(manifest_path)

        assert manifest == {"processed": {}}

    def test_save_manifest_atomic(self, fileops, tmp_path):
        """Manifest save should be atomic (write to temp, then rename)."""
        manifest_path = tmp_path / QUARANTINE_MANIFEST
        manifest = {"processed": {"file1": {"dest": "/dest/file1", "hash": "abc"}}}

        fileops._save_manifest(manifest_path, manifest)

        # Should exist and be readable
        assert manifest_path.exists()
        loaded = json.loads(manifest_path.read_text())
        assert loaded == manifest


class TestTOCTOUProtection:
    """Tests for Time-of-Check to Time-of-Use protection.

    Note: Symlink rejection is tested in the main test classes above.
    These tests verify regular file operations work correctly.
    """

    @pytest.fixture
    def fileops(self):
        """Create FileOps instance."""
        mock_ctx = MagicMock()
        mock_scanner = MagicMock()
        return FileOps(mock_ctx, mock_scanner)

    def test_move_regular_file_succeeds(self, fileops, tmp_path):
        """Move should succeed for regular files (symlinks rejected elsewhere)."""
        source = tmp_path / "source.txt"
        source.write_text("content")
        dest = tmp_path / "dest.txt"

        result = fileops.move(source, dest)

        assert result.success is True
        assert not source.exists()
        assert dest.exists()

    def test_idempotent_move_regular_file_succeeds(self, fileops, tmp_path):
        """Idempotent move should succeed for regular files."""
        source = tmp_path / "source.txt"
        source.write_text("content")
        dest = tmp_path / "dest.txt"
        manifest_path = tmp_path / QUARANTINE_MANIFEST

        success, error = fileops._idempotent_move(source, dest, manifest_path)

        assert success is True
        assert error is None
        assert dest.exists()

    def test_delete_regular_file_succeeds(self, fileops, tmp_path):
        """Delete should succeed for regular files (symlinks rejected elsewhere)."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = fileops.delete(test_file, dry_run=False)

        assert result.deleted_count == 1
        assert result.error_count == 0
        assert not test_file.exists()

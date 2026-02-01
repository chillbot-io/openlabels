"""
Tests for openlabels.output.reader module.

Tests the unified label reader that handles embedded and virtual labels.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock


class TestLabelReadResult:
    """Tests for LabelReadResult dataclass."""

    def test_label_read_result_creation(self):
        """Should create result with required fields."""
        from openlabels.output.reader import LabelReadResult

        result = LabelReadResult(
            label_set=None,
            transport="none",
            verified=False,
        )

        assert result.label_set is None
        assert result.transport == "none"
        assert result.verified is False
        assert result.pointer is None

    def test_label_read_result_with_pointer(self):
        """Should accept optional pointer."""
        from openlabels.output.reader import LabelReadResult
        from openlabels.core.labels import VirtualLabelPointer

        pointer = VirtualLabelPointer(
            label_id="test-id",
            content_hash="abc123",
        )

        result = LabelReadResult(
            label_set=None,
            transport="virtual",
            verified=True,
            pointer=pointer,
        )

        assert result.pointer is pointer

    def test_transport_values(self):
        """Should accept valid transport values."""
        from openlabels.output.reader import LabelReadResult

        for transport in ["embedded", "virtual", "cloud", "none"]:
            result = LabelReadResult(
                label_set=None,
                transport=transport,
                verified=False,
            )
            assert result.transport == transport


class TestReadLabel:
    """Tests for read_label function."""

    def test_read_label_nonexistent_file(self):
        """Should return none transport for nonexistent file."""
        from openlabels.output.reader import read_label

        result = read_label("/nonexistent/path/file.txt")

        assert result.label_set is None
        assert result.transport == "none"
        assert result.verified is False

    def test_read_label_unlabeled_file(self):
        """Should return none transport for unlabeled file."""
        from openlabels.output.reader import read_label

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"Hello World")
            temp_path = f.name

        try:
            result = read_label(temp_path)
            assert result.transport == "none"
            assert result.label_set is None
        finally:
            os.unlink(temp_path)

    def test_read_label_accepts_path_object(self):
        """Should accept Path object."""
        from openlabels.output.reader import read_label

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            result = read_label(temp_path)
            assert result is not None
        finally:
            os.unlink(temp_path)

    def test_read_label_accepts_string_path(self):
        """Should accept string path."""
        from openlabels.output.reader import read_label

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            result = read_label(temp_path)
            assert result is not None
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.read_embedded_label')
    def test_read_label_checks_embedded_first(self, mock_read, mock_supports):
        """Should check embedded labels first for supported types."""
        from openlabels.output.reader import read_label
        from openlabels.core.labels import LabelSet, Label

        mock_supports.return_value = True
        mock_label_set = Mock(spec=LabelSet)
        mock_label_set.content_hash = "abc123"
        mock_read.return_value = mock_label_set

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            with patch('openlabels.output.reader.compute_content_hash_file') as mock_hash:
                mock_hash.return_value = "abc123"
                result = read_label(temp_path)

            assert result.transport == "embedded"
            assert result.label_set is mock_label_set
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.read_virtual_label')
    def test_read_label_falls_back_to_virtual(self, mock_read_virtual, mock_supports):
        """Should fall back to virtual if no embedded."""
        from openlabels.output.reader import read_label
        from openlabels.core.labels import VirtualLabelPointer

        mock_supports.return_value = False
        mock_pointer = Mock(spec=VirtualLabelPointer)
        mock_pointer.content_hash = "abc123"
        mock_read_virtual.return_value = mock_pointer

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            with patch('openlabels.output.reader.get_default_index') as mock_idx:
                mock_index = Mock()
                mock_label_set = Mock()
                mock_index.resolve.return_value = mock_label_set
                mock_idx.return_value = mock_index

                with patch('openlabels.output.reader.compute_content_hash_file') as mock_hash:
                    mock_hash.return_value = "abc123"
                    result = read_label(temp_path)

            assert result.transport == "virtual"
            assert result.pointer is mock_pointer
        finally:
            os.unlink(temp_path)


class TestHasLabel:
    """Tests for has_label function."""

    def test_has_label_unlabeled_file(self):
        """Should return False for unlabeled file."""
        from openlabels.output.reader import has_label

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"Hello World")
            temp_path = f.name

        try:
            assert has_label(temp_path) is False
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.read_embedded_label')
    def test_has_label_with_embedded(self, mock_read, mock_supports):
        """Should return True if embedded label exists."""
        from openlabels.output.reader import has_label

        mock_supports.return_value = True
        mock_read.return_value = Mock()  # Non-None = has label

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            assert has_label(temp_path) is True
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.read_virtual_label')
    def test_has_label_with_virtual(self, mock_read_virtual, mock_supports):
        """Should return True if virtual label exists."""
        from openlabels.output.reader import has_label

        mock_supports.return_value = False
        mock_read_virtual.return_value = Mock()  # Non-None

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            assert has_label(temp_path) is True
        finally:
            os.unlink(temp_path)


class TestGetLabelTransport:
    """Tests for get_label_transport function."""

    def test_get_transport_unlabeled(self):
        """Should return 'none' for unlabeled file."""
        from openlabels.output.reader import get_label_transport

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            assert get_label_transport(temp_path) == "none"
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.read_embedded_label')
    def test_get_transport_embedded(self, mock_read, mock_supports):
        """Should return 'embedded' for embedded labels."""
        from openlabels.output.reader import get_label_transport

        mock_supports.return_value = True
        mock_read.return_value = Mock()

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            assert get_label_transport(temp_path) == "embedded"
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.read_virtual_label')
    def test_get_transport_virtual(self, mock_read_virtual, mock_supports):
        """Should return 'virtual' for virtual labels."""
        from openlabels.output.reader import get_label_transport

        mock_supports.return_value = False
        mock_read_virtual.return_value = Mock()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            assert get_label_transport(temp_path) == "virtual"
        finally:
            os.unlink(temp_path)


class TestVerifyLabel:
    """Tests for verify_label function."""

    def test_verify_label_no_label(self):
        """Should return False, 'no_label' for unlabeled file."""
        from openlabels.output.reader import verify_label

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            is_valid, reason = verify_label(temp_path)
            assert is_valid is False
            assert reason == "no_label"
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.read_label')
    def test_verify_label_valid(self, mock_read):
        """Should return True, 'valid' for verified label."""
        from openlabels.output.reader import verify_label, LabelReadResult

        mock_read.return_value = LabelReadResult(
            label_set=Mock(),
            transport="embedded",
            verified=True,
        )

        is_valid, reason = verify_label("/test/path")
        assert is_valid is True
        assert reason == "valid"

    @patch('openlabels.output.reader.read_label')
    def test_verify_label_hash_mismatch(self, mock_read):
        """Should return False, 'hash_mismatch' for stale label."""
        from openlabels.output.reader import verify_label, LabelReadResult

        mock_read.return_value = LabelReadResult(
            label_set=Mock(),
            transport="embedded",
            verified=False,  # Hash doesn't match
        )

        is_valid, reason = verify_label("/test/path")
        assert is_valid is False
        assert reason == "hash_mismatch"


class TestWriteLabel:
    """Tests for write_label function."""

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.write_embedded_label')
    @patch('openlabels.output.reader.get_default_index')
    def test_write_label_embedded(self, mock_idx, mock_write, mock_supports):
        """Should write embedded label for supported types."""
        from openlabels.output.reader import write_label
        from openlabels.core.labels import LabelSet

        mock_supports.return_value = True
        mock_write.return_value = True
        mock_index = Mock()
        mock_idx.return_value = mock_index

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            label_set = Mock(spec=LabelSet)
            success, transport = write_label(temp_path, label_set)

            assert success is True
            assert transport == "embedded"
            mock_write.assert_called_once()
            mock_index.store.assert_called_once()
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.write_virtual_label')
    @patch('openlabels.output.reader.get_default_index')
    def test_write_label_virtual(self, mock_idx, mock_write, mock_supports):
        """Should write virtual label for unsupported types."""
        from openlabels.output.reader import write_label
        from openlabels.core.labels import LabelSet

        mock_supports.return_value = False
        mock_write.return_value = True
        mock_index = Mock()
        mock_idx.return_value = mock_index

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            label_set = Mock(spec=LabelSet)
            success, transport = write_label(temp_path, label_set)

            assert success is True
            assert transport == "virtual"
            mock_index.store.assert_called_once()
        finally:
            os.unlink(temp_path)

    @patch('openlabels.output.reader.supports_embedded_labels')
    @patch('openlabels.output.reader.write_embedded_label')
    @patch('openlabels.output.reader.write_virtual_label')
    def test_write_label_failure(self, mock_virtual, mock_embedded, mock_supports):
        """Should return False, 'none' on write failure."""
        from openlabels.output.reader import write_label

        mock_supports.return_value = False
        mock_virtual.return_value = False

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            success, transport = write_label(temp_path, Mock())
            assert success is False
            assert transport == "none"
        finally:
            os.unlink(temp_path)


class TestRescanIfStale:
    """Tests for rescan_if_stale function."""

    @patch('openlabels.output.reader.read_label')
    def test_rescan_if_stale_valid_label(self, mock_read):
        """Should return existing label if valid."""
        from openlabels.output.reader import rescan_if_stale, LabelReadResult

        mock_label_set = Mock()
        mock_read.return_value = LabelReadResult(
            label_set=mock_label_set,
            transport="embedded",
            verified=True,
        )

        result = rescan_if_stale("/test/path")
        assert result is mock_label_set

    @patch('openlabels.output.reader.read_label')
    def test_rescan_if_stale_no_scanner(self, mock_read):
        """Should return None if stale and no scanner."""
        from openlabels.output.reader import rescan_if_stale, LabelReadResult

        mock_read.return_value = LabelReadResult(
            label_set=Mock(),
            transport="embedded",
            verified=False,  # Stale
        )

        result = rescan_if_stale("/test/path", scanner_func=None)
        assert result is None

    @patch('openlabels.output.reader.read_label')
    def test_rescan_if_stale_with_scanner(self, mock_read):
        """Should call scanner if stale."""
        from openlabels.output.reader import rescan_if_stale, LabelReadResult

        mock_read.return_value = LabelReadResult(
            label_set=Mock(),
            transport="embedded",
            verified=False,  # Stale
        )

        new_label_set = Mock()
        scanner_func = Mock(return_value=new_label_set)

        result = rescan_if_stale("/test/path", scanner_func=scanner_func)

        scanner_func.assert_called_once_with("/test/path")
        assert result is new_label_set

    @patch('openlabels.output.reader.read_label')
    def test_rescan_if_stale_no_label(self, mock_read):
        """Should call scanner if no label exists."""
        from openlabels.output.reader import rescan_if_stale, LabelReadResult

        mock_read.return_value = LabelReadResult(
            label_set=None,  # No label
            transport="none",
            verified=False,
        )

        new_label_set = Mock()
        scanner_func = Mock(return_value=new_label_set)

        result = rescan_if_stale("/test/path", scanner_func=scanner_func)

        scanner_func.assert_called_once()
        assert result is new_label_set


class TestReadLabelsBatch:
    """Tests for read_labels_batch function."""

    def test_read_labels_batch_empty(self):
        """Should return empty dict for empty input."""
        from openlabels.output.reader import read_labels_batch

        result = read_labels_batch([])
        assert result == {}

    def test_read_labels_batch_multiple_files(self):
        """Should read labels from multiple files."""
        from openlabels.output.reader import read_labels_batch

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = []
            for i in range(3):
                path = os.path.join(tmpdir, f"file{i}.txt")
                with open(path, "w") as f:
                    f.write(f"content {i}")
                paths.append(path)

            results = read_labels_batch(paths)

            assert len(results) == 3
            for path in paths:
                assert path in results


class TestFindUnlabeled:
    """Tests for find_unlabeled function."""

    def test_find_unlabeled_empty_dir(self):
        """Should return empty list for empty directory."""
        from openlabels.output.reader import find_unlabeled

        with tempfile.TemporaryDirectory() as tmpdir:
            result = find_unlabeled(tmpdir)
            assert result == []

    def test_find_unlabeled_all_unlabeled(self):
        """Should find all unlabeled files."""
        from openlabels.output.reader import find_unlabeled

        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                path = os.path.join(tmpdir, f"file{i}.txt")
                with open(path, "w") as f:
                    f.write(f"content {i}")

            result = find_unlabeled(tmpdir)

            assert len(result) == 3

    def test_find_unlabeled_non_recursive(self):
        """Should not recurse when recursive=False."""
        from openlabels.output.reader import find_unlabeled

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file in root
            with open(os.path.join(tmpdir, "root.txt"), "w") as f:
                f.write("root")

            # Create file in subdir
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir)
            with open(os.path.join(subdir, "nested.txt"), "w") as f:
                f.write("nested")

            result = find_unlabeled(tmpdir, recursive=False)

            assert len(result) == 1
            assert "root.txt" in str(result[0])

    def test_find_unlabeled_recursive(self):
        """Should recurse when recursive=True."""
        from openlabels.output.reader import find_unlabeled

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file in root
            with open(os.path.join(tmpdir, "root.txt"), "w") as f:
                f.write("root")

            # Create file in subdir
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir)
            with open(os.path.join(subdir, "nested.txt"), "w") as f:
                f.write("nested")

            result = find_unlabeled(tmpdir, recursive=True)

            assert len(result) == 2


class TestFindStaleLabels:
    """Tests for find_stale_labels function."""

    def test_find_stale_empty_dir(self):
        """Should return empty list for empty directory."""
        from openlabels.output.reader import find_stale_labels

        with tempfile.TemporaryDirectory() as tmpdir:
            result = find_stale_labels(tmpdir)
            assert result == []

    def test_find_stale_no_labels(self):
        """Should return empty list when no labels exist."""
        from openlabels.output.reader import find_stale_labels

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "test.txt"), "w") as f:
                f.write("test")

            result = find_stale_labels(tmpdir)
            # No labels = no stale labels
            assert result == []


class TestReadCloudLabelFull:
    """Tests for read_cloud_label_full function."""

    @patch('openlabels.output.reader.read_cloud_label')
    @patch('openlabels.output.reader.get_default_index')
    def test_read_cloud_label_success(self, mock_idx, mock_read):
        """Should read cloud label and resolve."""
        from openlabels.output.reader import read_cloud_label_full

        mock_pointer = Mock()
        mock_read.return_value = mock_pointer

        mock_label_set = Mock()
        mock_index = Mock()
        mock_index.resolve.return_value = mock_label_set
        mock_idx.return_value = mock_index

        result = read_cloud_label_full("s3://bucket/key")

        assert result.transport == "cloud"
        assert result.label_set is mock_label_set
        assert result.pointer is mock_pointer

    @patch('openlabels.output.reader.read_cloud_label')
    def test_read_cloud_label_no_pointer(self, mock_read):
        """Should return none transport if no pointer."""
        from openlabels.output.reader import read_cloud_label_full

        mock_read.return_value = None

        result = read_cloud_label_full("s3://bucket/key")

        assert result.transport == "none"
        assert result.label_set is None

    @patch('openlabels.output.reader.read_cloud_label')
    @patch('openlabels.output.reader.get_default_index')
    def test_read_cloud_label_not_in_index(self, mock_idx, mock_read):
        """Should return none if not in index."""
        from openlabels.output.reader import read_cloud_label_full

        mock_read.return_value = Mock()  # Has pointer
        mock_index = Mock()
        mock_index.resolve.return_value = None  # Not in index
        mock_idx.return_value = mock_index

        result = read_cloud_label_full("s3://bucket/key")

        assert result.transport == "none"
        assert result.label_set is None

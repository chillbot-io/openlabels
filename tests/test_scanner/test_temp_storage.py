"""
Comprehensive tests for secure temporary storage.

Tests SecureTempDir creation, cleanup, file operations,
context manager usage, and security properties.
"""

import pytest
import tempfile
import os
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.adapters.scanner.temp_storage import (
    SecureTempDir,
    _cleanup_on_exit,
    _active_temp_dirs,
    _active_temp_dirs_lock,
)


class TestSecureTempDirCreation:
    """Tests for SecureTempDir creation."""

    def test_create_temp_dir(self):
        """Test basic temp directory creation."""
        temp = SecureTempDir("test_job")
        try:
            path = temp.create()

            assert path.exists()
            assert path.is_dir()
            assert "openlabels_scan_test_job" in str(path)
        finally:
            temp.cleanup()

    def test_create_with_custom_base(self):
        """Test creation with custom base directory."""
        with tempfile.TemporaryDirectory() as base:
            base_path = Path(base)
            temp = SecureTempDir("test_job", base_dir=base_path)
            try:
                path = temp.create()

                assert path.parent == base_path
            finally:
                temp.cleanup()

    def test_create_idempotent(self):
        """Test multiple create calls return same path."""
        temp = SecureTempDir("test_job")
        try:
            path1 = temp.create()
            path2 = temp.create()

            assert path1 == path2
        finally:
            temp.cleanup()

    def test_path_property_before_create(self):
        """Test path property is None before create."""
        temp = SecureTempDir("test_job")
        assert temp.path is None

    def test_path_property_after_create(self):
        """Test path property returns path after create."""
        temp = SecureTempDir("test_job")
        try:
            created_path = temp.create()
            assert temp.path == created_path
        finally:
            temp.cleanup()

    @pytest.mark.skipif(os.name == 'nt', reason="Permission test not reliable on Windows")
    def test_restricted_permissions(self):
        """Test temp dir has restricted permissions (700)."""
        temp = SecureTempDir("test_job")
        try:
            path = temp.create()
            mode = path.stat().st_mode & 0o777

            # Should be 700 (owner read/write/execute only)
            assert mode == 0o700
        finally:
            temp.cleanup()


class TestSecureTempDirCleanup:
    """Tests for SecureTempDir cleanup."""

    def test_cleanup_removes_directory(self):
        """Test cleanup removes the directory."""
        temp = SecureTempDir("test_job")
        path = temp.create()

        assert path.exists()
        temp.cleanup()
        assert not path.exists()

    def test_cleanup_removes_contents(self):
        """Test cleanup removes directory contents."""
        temp = SecureTempDir("test_job")
        path = temp.create()

        # Create some files
        (path / "file1.txt").write_text("test")
        (path / "file2.txt").write_text("test")
        subdir = path / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("nested")

        temp.cleanup()
        assert not path.exists()

    def test_cleanup_idempotent(self):
        """Test cleanup can be called multiple times safely."""
        temp = SecureTempDir("test_job")
        temp.create()

        temp.cleanup()
        temp.cleanup()  # Should not raise
        temp.cleanup()

    def test_cleanup_sets_path_to_none(self):
        """Test cleanup sets path property to None."""
        temp = SecureTempDir("test_job")
        temp.create()
        temp.cleanup()

        assert temp.path is None

    def test_cleanup_removes_from_tracking(self):
        """Test cleanup removes from global tracking list."""
        temp = SecureTempDir("test_job")
        path = temp.create()

        with _active_temp_dirs_lock:
            assert path in _active_temp_dirs

        temp.cleanup()

        with _active_temp_dirs_lock:
            assert path not in _active_temp_dirs


class TestSecureTempDirContextManager:
    """Tests for context manager usage."""

    def test_context_manager_creates(self):
        """Test context manager creates directory."""
        temp = SecureTempDir("test_job")
        with temp as path:
            assert path.exists()
            assert path.is_dir()

    def test_context_manager_cleans_up(self):
        """Test context manager cleans up on exit."""
        temp = SecureTempDir("test_job")
        with temp as path:
            created_path = path

        assert not created_path.exists()

    def test_context_manager_cleans_up_on_exception(self):
        """Test context manager cleans up even on exception."""
        temp = SecureTempDir("test_job")
        created_path = None

        try:
            with temp as path:
                created_path = path
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert not created_path.exists()

    def test_context_manager_returns_path(self):
        """Test context manager returns Path object."""
        with SecureTempDir("test_job") as path:
            assert isinstance(path, Path)


class TestSecureTempDirFileOperations:
    """Tests for file operation helpers."""

    def test_write_page(self):
        """Test writing a page."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            page_path = temp.write_page(0, b"test data")

            assert page_path.exists()
            assert page_path.name == "page_0000.png"
            assert page_path.read_bytes() == b"test data"

    def test_write_page_custom_extension(self):
        """Test writing a page with custom extension."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            page_path = temp.write_page(5, b"jpeg data", ext=".jpg")

            assert page_path.name == "page_0005.jpg"

    def test_read_page(self):
        """Test reading a page."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            # Write first
            temp.write_page(0, b"page content")

            # Read back
            data = temp.read_page(0)
            assert data == b"page content"

    def test_read_page_raises_without_create(self):
        """Test read_page raises if directory not created."""
        temp = SecureTempDir("test_job")

        with pytest.raises(RuntimeError, match="not created"):
            temp.read_page(0)

    def test_write_page_raises_without_create(self):
        """Test write_page raises if directory not created."""
        temp = SecureTempDir("test_job")

        with pytest.raises(RuntimeError, match="not created"):
            temp.write_page(0, b"data")

    def test_page_path(self):
        """Test getting page path."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            path = temp.page_path(3)

            assert path.name == "page_0003.png"
            assert path.parent == temp_dir

    def test_page_path_custom_extension(self):
        """Test page_path with custom extension."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            path = temp.page_path(10, ext=".tiff")

            assert path.name == "page_0010.tiff"

    def test_page_path_raises_without_create(self):
        """Test page_path raises if directory not created."""
        temp = SecureTempDir("test_job")

        with pytest.raises(RuntimeError, match="not created"):
            temp.page_path(0)

    def test_list_pages_empty(self):
        """Test listing pages when empty."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            pages = temp.list_pages()
            assert pages == []

    def test_list_pages_sorted(self):
        """Test pages are listed in order."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            # Write pages out of order
            temp.write_page(2, b"page 2")
            temp.write_page(0, b"page 0")
            temp.write_page(1, b"page 1")

            pages = temp.list_pages()

            assert len(pages) == 3
            assert pages[0].name == "page_0000.png"
            assert pages[1].name == "page_0001.png"
            assert pages[2].name == "page_0002.png"

    def test_list_pages_filters_extension(self):
        """Test list_pages filters by extension."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            temp.write_page(0, b"png", ext=".png")
            temp.write_page(1, b"jpg", ext=".jpg")

            png_pages = temp.list_pages(ext=".png")
            jpg_pages = temp.list_pages(ext=".jpg")

            assert len(png_pages) == 1
            assert len(jpg_pages) == 1

    def test_list_pages_not_created(self):
        """Test list_pages returns empty if not created."""
        temp = SecureTempDir("test_job")
        pages = temp.list_pages()
        assert pages == []

    def test_iter_pages(self):
        """Test iterating over pages."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir("test_job")
            temp._path = temp_dir

            temp.write_page(0, b"page 0 data")
            temp.write_page(1, b"page 1 data")
            temp.write_page(2, b"page 2 data")

            pages_data = list(temp.iter_pages())

            assert len(pages_data) == 3
            assert pages_data[0] == b"page 0 data"
            assert pages_data[1] == b"page 1 data"
            assert pages_data[2] == b"page 2 data"


class TestCleanupOnExit:
    """Tests for cleanup on exit functionality."""

    def test_cleanup_on_exit_clears_dirs(self):
        """Test _cleanup_on_exit removes directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a temp dir and add to tracking
            test_path = Path(tmpdir) / "test_temp"
            test_path.mkdir()

            with _active_temp_dirs_lock:
                _active_temp_dirs.append(test_path)

            assert test_path.exists()

            _cleanup_on_exit()

            assert not test_path.exists()

    def test_cleanup_on_exit_handles_missing_dir(self):
        """Test _cleanup_on_exit handles already-deleted dirs."""
        with _active_temp_dirs_lock:
            # Add non-existent path
            _active_temp_dirs.append(Path("/nonexistent/path"))

        # Should not raise
        _cleanup_on_exit()


class TestSecureTempDirTracking:
    """Tests for global tracking of temp directories."""

    def test_create_adds_to_tracking(self):
        """Test create adds to global tracking."""
        temp = SecureTempDir("test_job")
        try:
            path = temp.create()

            with _active_temp_dirs_lock:
                assert path in _active_temp_dirs
        finally:
            temp.cleanup()

    def test_tracking_thread_safe(self):
        """Test tracking operations are thread-safe."""
        import threading

        temps = []
        errors = []

        def create_and_cleanup():
            try:
                temp = SecureTempDir(f"job_{threading.current_thread().name}")
                temp.create()
                temps.append(temp)
                temp.cleanup()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_and_cleanup) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestSecureTempDirJobId:
    """Tests for job ID handling."""

    def test_job_id_in_path(self):
        """Test job ID appears in directory name."""
        temp = SecureTempDir("my_unique_job_123")
        try:
            path = temp.create()
            assert "my_unique_job_123" in path.name
        finally:
            temp.cleanup()

    def test_unique_paths_for_same_job_id(self):
        """Test same job ID creates unique paths (UUID suffix)."""
        temp1 = SecureTempDir("same_job")
        temp2 = SecureTempDir("same_job")
        try:
            path1 = temp1.create()
            path2 = temp2.create()

            # Should be different due to UUID
            assert path1 != path2
        finally:
            temp1.cleanup()
            temp2.cleanup()

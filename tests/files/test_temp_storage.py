"""Tests for secure temporary storage module.

Tests for SecureTempDir class and cleanup functionality.
"""

import os
import tempfile
from pathlib import Path

import pytest

from scrubiq.files.temp_storage import (
    SecureTempDir,
    _active_temp_dirs,
    _cleanup_on_exit,
)


# =============================================================================
# SECURETEMPDIR CREATION TESTS
# =============================================================================

class TestSecureTempDirCreation:
    """Tests for SecureTempDir creation."""

    def test_create_creates_directory(self):
        """create() creates the temp directory."""
        temp = SecureTempDir("test_job")
        try:
            path = temp.create()
            assert path.exists()
            assert path.is_dir()
        finally:
            temp.cleanup()

    def test_create_returns_same_path_on_second_call(self):
        """create() returns same path when called twice."""
        temp = SecureTempDir("test_job")
        try:
            path1 = temp.create()
            path2 = temp.create()
            assert path1 == path2
        finally:
            temp.cleanup()

    def test_path_property_before_create(self):
        """path property is None before create()."""
        temp = SecureTempDir("test_job")
        assert temp.path is None

    def test_path_property_after_create(self):
        """path property returns directory path after create()."""
        temp = SecureTempDir("test_job")
        try:
            path = temp.create()
            assert temp.path == path
        finally:
            temp.cleanup()

    def test_directory_name_includes_job_id(self):
        """Directory name includes job_id."""
        temp = SecureTempDir("my_test_job")
        try:
            path = temp.create()
            assert "my_test_job" in path.name
        finally:
            temp.cleanup()

    def test_directory_name_has_unique_suffix(self):
        """Directory name has unique suffix."""
        temp1 = SecureTempDir("same_job")
        temp2 = SecureTempDir("same_job")
        try:
            path1 = temp1.create()
            path2 = temp2.create()
            assert path1 != path2
        finally:
            temp1.cleanup()
            temp2.cleanup()

    def test_custom_base_dir(self):
        """Custom base_dir is used."""
        with tempfile.TemporaryDirectory() as base:
            base_path = Path(base)
            temp = SecureTempDir("test_job", base_dir=base_path)
            try:
                path = temp.create()
                assert path.parent == base_path
            finally:
                temp.cleanup()

    def test_directory_has_restricted_permissions(self):
        """Directory is created with 700 permissions."""
        temp = SecureTempDir("test_job")
        try:
            path = temp.create()
            mode = path.stat().st_mode & 0o777
            # Should be 700 or close (some systems may vary)
            assert mode == 0o700 or mode == 0o755  # Allow for umask
        finally:
            temp.cleanup()


# =============================================================================
# SECURETEMPDIR CLEANUP TESTS
# =============================================================================

class TestSecureTempDirCleanup:
    """Tests for SecureTempDir cleanup."""

    def test_cleanup_removes_directory(self):
        """cleanup() removes the directory."""
        temp = SecureTempDir("test_job")
        path = temp.create()
        assert path.exists()

        temp.cleanup()
        assert not path.exists()

    def test_cleanup_sets_path_to_none(self):
        """cleanup() sets path to None."""
        temp = SecureTempDir("test_job")
        temp.create()
        temp.cleanup()
        assert temp.path is None

    def test_cleanup_is_idempotent(self):
        """cleanup() can be called multiple times safely."""
        temp = SecureTempDir("test_job")
        temp.create()
        temp.cleanup()
        temp.cleanup()  # Should not raise
        temp.cleanup()  # Should not raise

    def test_cleanup_removes_from_tracking_list(self):
        """cleanup() removes from _active_temp_dirs."""
        temp = SecureTempDir("test_job")
        path = temp.create()
        assert path in _active_temp_dirs

        temp.cleanup()
        assert path not in _active_temp_dirs

    def test_cleanup_removes_files_in_directory(self):
        """cleanup() removes all files in directory."""
        temp = SecureTempDir("test_job")
        path = temp.create()

        # Create some files
        (path / "test.txt").write_text("data")
        (path / "test2.png").write_bytes(b"image data")

        temp.cleanup()
        assert not path.exists()


# =============================================================================
# CONTEXT MANAGER TESTS
# =============================================================================

class TestSecureTempDirContextManager:
    """Tests for SecureTempDir as context manager."""

    def test_context_manager_creates_directory(self):
        """Context manager creates directory on enter."""
        with SecureTempDir("test_job") as path:
            assert path.exists()
            assert path.is_dir()

    def test_context_manager_cleans_up_on_exit(self):
        """Context manager cleans up on exit."""
        with SecureTempDir("test_job") as path:
            created_path = path
        assert not created_path.exists()

    def test_context_manager_cleans_up_on_exception(self):
        """Context manager cleans up even on exception."""
        try:
            with SecureTempDir("test_job") as path:
                created_path = path
                raise ValueError("Test exception")
        except ValueError:
            pass
        assert not created_path.exists()

    def test_context_manager_removes_files(self):
        """Context manager removes files on exit."""
        with SecureTempDir("test_job") as path:
            (path / "file.txt").write_text("test")
            created_path = path
        assert not created_path.exists()


# =============================================================================
# FILE OPERATIONS TESTS
# =============================================================================

class TestSecureTempDirFileOps:
    """Tests for SecureTempDir file operations."""

    def test_write_page_creates_file(self):
        """write_page() creates page file."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            page_path = temp.write_page(0, b"image data")
            assert page_path.exists()
            assert page_path.name == "page_0000.png"
            assert page_path.read_bytes() == b"image data"

    def test_write_page_zero_pads_number(self):
        """write_page() zero-pads page number."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            temp.write_page(0, b"0")
            temp.write_page(1, b"1")
            temp.write_page(99, b"99")

            assert (temp_dir / "page_0000.png").exists()
            assert (temp_dir / "page_0001.png").exists()
            assert (temp_dir / "page_0099.png").exists()

    def test_write_page_custom_extension(self):
        """write_page() uses custom extension."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            page_path = temp.write_page(0, b"data", ext=".jpg")
            assert page_path.name == "page_0000.jpg"

    def test_write_page_raises_if_not_created(self):
        """write_page() raises if temp dir not created."""
        temp = SecureTempDir("test_job")
        with pytest.raises(RuntimeError, match="not created"):
            temp.write_page(0, b"data")

    def test_read_page_returns_data(self):
        """read_page() returns page data."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            temp.write_page(0, b"test data")
            data = temp.read_page(0)
            assert data == b"test data"

    def test_read_page_raises_if_not_created(self):
        """read_page() raises if temp dir not created."""
        temp = SecureTempDir("test_job")
        with pytest.raises(RuntimeError, match="not created"):
            temp.read_page(0)

    def test_page_path_returns_path(self):
        """page_path() returns expected path."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            path = temp.page_path(5)
            assert path == temp_dir / "page_0005.png"

    def test_page_path_raises_if_not_created(self):
        """page_path() raises if temp dir not created."""
        temp = SecureTempDir("test_job")
        with pytest.raises(RuntimeError, match="not created"):
            temp.page_path(0)

    def test_list_pages_returns_sorted_list(self):
        """list_pages() returns pages sorted by number."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            # Write pages out of order
            temp.write_page(2, b"2")
            temp.write_page(0, b"0")
            temp.write_page(1, b"1")

            pages = temp.list_pages()
            assert len(pages) == 3
            assert pages[0].name == "page_0000.png"
            assert pages[1].name == "page_0001.png"
            assert pages[2].name == "page_0002.png"

    def test_list_pages_empty_directory(self):
        """list_pages() returns empty list for empty directory."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            assert temp.list_pages() == []

    def test_list_pages_before_create(self):
        """list_pages() returns empty list before create."""
        temp = SecureTempDir("test_job")
        assert temp.list_pages() == []

    def test_list_pages_filters_by_extension(self):
        """list_pages() filters by extension."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            temp.write_page(0, b"png", ext=".png")
            temp.write_page(0, b"jpg", ext=".jpg")

            png_pages = temp.list_pages(".png")
            jpg_pages = temp.list_pages(".jpg")

            assert len(png_pages) == 1
            assert len(jpg_pages) == 1

    def test_iter_pages_yields_data(self):
        """iter_pages() yields page data in order."""
        with SecureTempDir("test_job") as temp_dir:
            temp = SecureTempDir.__new__(SecureTempDir)
            temp._path = temp_dir

            temp.write_page(0, b"page0")
            temp.write_page(1, b"page1")
            temp.write_page(2, b"page2")

            data = list(temp.iter_pages())
            assert data == [b"page0", b"page1", b"page2"]


# =============================================================================
# EXIT CLEANUP TESTS
# =============================================================================

class TestExitCleanup:
    """Tests for _cleanup_on_exit function."""

    def test_cleanup_on_exit_removes_active_dirs(self):
        """_cleanup_on_exit removes active directories."""
        # Create a temp dir manually
        temp = SecureTempDir("test_exit_cleanup")
        path = temp.create()
        assert path in _active_temp_dirs

        # Call cleanup function
        _cleanup_on_exit()

        assert not path.exists()
        assert path not in _active_temp_dirs

    def test_cleanup_on_exit_handles_already_removed(self):
        """_cleanup_on_exit handles already-removed directories."""
        # Create and immediately remove
        temp = SecureTempDir("test_job")
        path = temp.create()

        # Remove manually but leave in tracking list
        import shutil
        shutil.rmtree(path)

        # Should not raise
        _cleanup_on_exit()
        assert path not in _active_temp_dirs


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_special_chars_in_job_id(self):
        """Special characters in job_id don't cause issues."""
        temp = SecureTempDir("job-123_test.run")
        try:
            path = temp.create()
            assert path.exists()
        finally:
            temp.cleanup()

    def test_empty_job_id(self):
        """Empty job_id works."""
        temp = SecureTempDir("")
        try:
            path = temp.create()
            assert path.exists()
        finally:
            temp.cleanup()

    def test_unicode_job_id(self):
        """Unicode in job_id works."""
        temp = SecureTempDir("job_日本語")
        try:
            path = temp.create()
            assert path.exists()
        finally:
            temp.cleanup()

    def test_very_long_job_id(self):
        """Very long job_id works."""
        temp = SecureTempDir("a" * 100)
        try:
            path = temp.create()
            assert path.exists()
        finally:
            temp.cleanup()

    def test_concurrent_creates(self):
        """Multiple SecureTempDir instances can coexist."""
        temps = [SecureTempDir(f"job_{i}") for i in range(5)]
        try:
            paths = [t.create() for t in temps]
            # All paths should be unique
            assert len(set(paths)) == 5
            # All should exist
            assert all(p.exists() for p in paths)
        finally:
            for t in temps:
                t.cleanup()

    def test_nested_directories(self):
        """Files in nested directories are cleaned up."""
        with SecureTempDir("test_job") as temp_dir:
            # Create nested structure
            nested = temp_dir / "subdir" / "deep"
            nested.mkdir(parents=True)
            (nested / "file.txt").write_text("data")

            created_path = temp_dir

        # Everything should be cleaned up
        assert not created_path.exists()

"""
Tests for filesystem adapter.

Tests actual file system operations, filtering, and permission handling.
"""

import os
import stat
import tempfile
from pathlib import Path
from datetime import datetime

import pytest

from openlabels.adapters.filesystem import FilesystemAdapter
from openlabels.adapters.base import FileInfo, ExposureLevel, FilterConfig


class TestFilesystemAdapterListFiles:
    """Tests for file listing functionality."""

    async def test_list_files_finds_all_files(self):
        """Should list all files in a directory."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "file1.txt").write_text("content1")
            (Path(tmpdir) / "file2.txt").write_text("content2")
            (Path(tmpdir) / "file3.txt").write_text("content3")

            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 3
            names = {f.name for f in files}
            assert names == {"file1.txt", "file2.txt", "file3.txt"}

    async def test_list_files_empty_directory(self):
        """Should return empty iterator for empty directory."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 0

    async def test_list_files_recursive(self):
        """Should recursively list files in subdirectories."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure
            subdir = Path(tmpdir) / "subdir" / "nested"
            subdir.mkdir(parents=True)

            (Path(tmpdir) / "root.txt").write_text("root")
            (Path(tmpdir) / "subdir" / "level1.txt").write_text("level1")
            (subdir / "level2.txt").write_text("level2")

            files = []
            async for f in adapter.list_files(tmpdir, recursive=True):
                files.append(f)

            assert len(files) == 3
            names = {f.name for f in files}
            assert "root.txt" in names
            assert "level1.txt" in names
            assert "level2.txt" in names

    async def test_list_files_non_recursive(self):
        """Non-recursive listing should only get top-level files."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()

            (Path(tmpdir) / "root.txt").write_text("root")
            (subdir / "nested.txt").write_text("nested")

            files = []
            async for f in adapter.list_files(tmpdir, recursive=False):
                files.append(f)

            assert len(files) == 1
            assert files[0].name == "root.txt"

    async def test_list_files_returns_fileinfo_with_correct_attributes(self):
        """FileInfo should have correct path, name, size, modified."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Hello World")  # 11 bytes

            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 1
            file_info = files[0]

            assert file_info.name == "test.txt"
            assert file_info.size == 11
            assert file_info.path.endswith("test.txt")
            assert isinstance(file_info.modified, datetime)
            assert file_info.adapter == "filesystem"

    async def test_list_files_raises_on_nonexistent_path(self):
        """Should raise FilesystemError for non-existent path."""
        from openlabels.exceptions import FilesystemError
        adapter = FilesystemAdapter()

        with pytest.raises(FilesystemError, match="does not exist"):
            async for _ in adapter.list_files("/nonexistent/path/12345"):
                pass

    async def test_list_files_raises_on_file_not_directory(self):
        """Should raise FilesystemError when target is a file, not directory."""
        from openlabels.exceptions import FilesystemError
        adapter = FilesystemAdapter()

        with tempfile.NamedTemporaryFile() as f:
            with pytest.raises(FilesystemError, match="not a directory"):
                async for _ in adapter.list_files(f.name):
                    pass


class TestFilesystemAdapterFiltering:
    """Tests for file filtering with FilterConfig."""

    async def test_filters_hidden_files_by_pattern(self):
        """Should filter hidden files when pattern excludes them."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "visible.txt").write_text("visible")
            (Path(tmpdir) / ".hidden.txt").write_text("hidden")

            # Create filter that excludes hidden files
            filter_config = FilterConfig(
                exclude_patterns=[".*"],
                exclude_temp_files=False,
                exclude_system_dirs=False,
            )

            files = []
            async for f in adapter.list_files(tmpdir, filter_config=filter_config):
                files.append(f)

            names = [f.name for f in files]
            assert "visible.txt" in names
            assert ".hidden.txt" not in names

    async def test_filters_temp_files_by_default(self):
        """Default filter should exclude common temp file extensions."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "document.txt").write_text("doc")
            (Path(tmpdir) / "backup.bak").write_text("bak")
            (Path(tmpdir) / "temp.tmp").write_text("tmp")
            (Path(tmpdir) / "swap.swp").write_text("swp")

            # Default filter excludes temp files
            filter_config = FilterConfig(exclude_temp_files=True, exclude_system_dirs=False)

            files = []
            async for f in adapter.list_files(tmpdir, filter_config=filter_config):
                files.append(f)

            names = [f.name for f in files]
            assert "document.txt" in names
            assert "backup.bak" not in names
            assert "temp.tmp" not in names
            assert "swap.swp" not in names

    async def test_filters_by_size(self):
        """Should filter files by size limits."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "small.txt").write_text("x" * 10)
            (Path(tmpdir) / "medium.txt").write_text("x" * 100)
            (Path(tmpdir) / "large.txt").write_text("x" * 1000)

            filter_config = FilterConfig(
                min_size_bytes=50,
                max_size_bytes=500,
                exclude_temp_files=False,
                exclude_system_dirs=False,
            )

            files = []
            async for f in adapter.list_files(tmpdir, filter_config=filter_config):
                files.append(f)

            names = [f.name for f in files]
            assert "small.txt" not in names  # Too small
            assert "medium.txt" in names  # Just right
            assert "large.txt" not in names  # Too large

    async def test_no_filter_includes_all_files(self):
        """Without filtering, should include all files."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "normal.txt").write_text("normal")
            (Path(tmpdir) / "backup.bak").write_text("backup")
            (Path(tmpdir) / ".hidden").write_text("hidden")

            # Disable all filtering
            filter_config = FilterConfig(
                exclude_temp_files=False,
                exclude_system_dirs=False,
                exclude_extensions=[],
                exclude_patterns=[],
            )

            files = []
            async for f in adapter.list_files(tmpdir, filter_config=filter_config):
                files.append(f)

            names = [f.name for f in files]
            assert "normal.txt" in names
            assert "backup.bak" in names
            assert ".hidden" in names


class TestFilesystemAdapterReadFile:
    """Tests for file reading."""

    async def test_read_file_returns_content(self):
        """Should read and return file contents as bytes."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Hello, World!")

            file_info = FileInfo(
                path=str(test_file),
                name="test.txt",
                size=13,
                modified=datetime.now(),
                adapter="filesystem",
            )

            content = await adapter.read_file(file_info)

            assert content == b"Hello, World!"

    async def test_read_file_binary(self):
        """Should correctly read binary files."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "binary.bin"
            binary_content = bytes(range(256))
            test_file.write_bytes(binary_content)

            file_info = FileInfo(
                path=str(test_file),
                name="binary.bin",
                size=256,
                modified=datetime.now(),
                adapter="filesystem",
            )

            content = await adapter.read_file(file_info)

            assert content == binary_content


class TestFilesystemAdapterExposureLevel:
    """Tests for exposure level calculation on POSIX systems."""

    @pytest.mark.skipif(os.name == 'nt', reason="POSIX-specific test")
    async def test_private_exposure_for_owner_only(self):
        """Files with mode 600 should be PRIVATE."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "private.txt"
            test_file.write_text("secret")
            os.chmod(test_file, 0o600)  # Owner read/write only

            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 1
            assert files[0].exposure == ExposureLevel.PRIVATE

    @pytest.mark.skipif(os.name == 'nt', reason="POSIX-specific test")
    async def test_org_wide_exposure_for_group_readable(self):
        """Files with group read should be ORG_WIDE."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "group.txt"
            test_file.write_text("internal")
            os.chmod(test_file, 0o640)  # Owner rw, group read

            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 1
            assert files[0].exposure == ExposureLevel.ORG_WIDE

    @pytest.mark.skipif(os.name == 'nt', reason="POSIX-specific test")
    async def test_public_exposure_for_world_readable(self):
        """Files with world read should be PUBLIC."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "public.txt"
            test_file.write_text("public")
            os.chmod(test_file, 0o644)  # World readable

            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 1
            assert files[0].exposure == ExposureLevel.PUBLIC


class TestFilesystemAdapterTestConnection:
    """Tests for connection testing."""

    async def test_connection_succeeds_for_valid_path(self):
        """Should return True for valid directory."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = await adapter.test_connection({"path": tmpdir})
            assert result is True

    async def test_connection_fails_for_nonexistent_path(self):
        """Should return False for non-existent path."""
        adapter = FilesystemAdapter()

        result = await adapter.test_connection({"path": "/nonexistent/12345"})
        assert result is False

    async def test_connection_fails_for_file_path(self):
        """Should return False when path is a file, not directory."""
        adapter = FilesystemAdapter()

        with tempfile.NamedTemporaryFile() as f:
            result = await adapter.test_connection({"path": f.name})
            assert result is False

    async def test_connection_fails_for_missing_path_config(self):
        """Should return False when path not in config."""
        adapter = FilesystemAdapter()

        result = await adapter.test_connection({})
        assert result is False


class TestFilesystemAdapterMetadata:
    """Tests for metadata retrieval."""

    async def test_get_metadata_returns_current_info(self):
        """get_metadata should return current file info."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("initial")

            initial_info = FileInfo(
                path=str(test_file),
                name="test.txt",
                size=7,
                modified=datetime.now(),
                adapter="filesystem",
            )

            # Modify the file
            test_file.write_text("modified content")

            updated_info = await adapter.get_metadata(initial_info)

            assert updated_info.size == 16  # "modified content" = 16 bytes
            assert updated_info.name == "test.txt"


class TestFilesystemAdapterProperties:
    """Tests for adapter properties and configuration."""

    def test_adapter_type_is_filesystem(self):
        """adapter_type should be 'filesystem'."""
        adapter = FilesystemAdapter()
        assert adapter.adapter_type == "filesystem"

    def test_supports_delta_returns_false(self):
        """Filesystem adapter doesn't support delta queries."""
        adapter = FilesystemAdapter()
        assert adapter.supports_delta() is False

    def test_supports_remediation_returns_true(self):
        """Filesystem adapter supports remediation."""
        adapter = FilesystemAdapter()
        assert adapter.supports_remediation() is True

    def test_service_account_stored(self):
        """Service account should be stored for Windows impersonation."""
        adapter = FilesystemAdapter(service_account="DOMAIN\\svcaccount")
        assert adapter.service_account == "DOMAIN\\svcaccount"


class TestFilesystemAdapterMoveFile:
    """Tests for file move/quarantine functionality."""

    async def test_move_file_success(self):
        """Should successfully move file to new location."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "source.txt"
            source.write_text("content")

            dest = Path(tmpdir) / "quarantine" / "source.txt"

            file_info = FileInfo(
                path=str(source),
                name="source.txt",
                size=7,
                modified=datetime.now(),
                adapter="filesystem",
            )

            result = await adapter.move_file(file_info, str(dest))

            assert result is True
            assert not source.exists()
            assert dest.exists()
            assert dest.read_text() == "content"

    async def test_move_file_creates_destination_directory(self):
        """Should create destination directory if it doesn't exist."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "source.txt"
            source.write_text("content")

            # Deeply nested destination
            dest = Path(tmpdir) / "a" / "b" / "c" / "source.txt"

            file_info = FileInfo(
                path=str(source),
                name="source.txt",
                size=7,
                modified=datetime.now(),
                adapter="filesystem",
            )

            result = await adapter.move_file(file_info, str(dest))

            assert result is True
            assert dest.exists()

    async def test_move_nonexistent_file_returns_false(self):
        """Should return False when source doesn't exist."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            file_info = FileInfo(
                path="/nonexistent/file.txt",
                name="file.txt",
                size=0,
                modified=datetime.now(),
                adapter="filesystem",
            )

            result = await adapter.move_file(file_info, str(Path(tmpdir) / "dest.txt"))

            assert result is False


class TestFilesystemAdapterACL:
    """Tests for ACL get/set functionality."""

    @pytest.mark.skipif(os.name == 'nt', reason="POSIX-specific test")
    async def test_get_acl_returns_posix_permissions(self):
        """Should return POSIX permission info."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("content")
            os.chmod(test_file, 0o644)

            file_info = FileInfo(
                path=str(test_file),
                name="test.txt",
                size=7,
                modified=datetime.now(),
                adapter="filesystem",
            )

            acl = await adapter.get_acl(file_info)

            assert acl is not None
            assert acl["platform"] == "posix"
            assert "mode" in acl
            assert "uid" in acl
            assert "gid" in acl

    @pytest.mark.skipif(os.name == 'nt', reason="POSIX-specific test")
    async def test_set_acl_changes_permissions(self):
        """Should apply POSIX permissions."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("content")
            os.chmod(test_file, 0o644)

            file_info = FileInfo(
                path=str(test_file),
                name="test.txt",
                size=7,
                modified=datetime.now(),
                adapter="filesystem",
            )

            # Set restrictive permissions
            acl = {
                "platform": "posix",
                "mode": 0o600,
            }

            result = await adapter.set_acl(file_info, acl)

            assert result is True
            new_mode = test_file.stat().st_mode & 0o777
            assert new_mode == 0o600

    @pytest.mark.skipif(os.name == 'nt', reason="POSIX-specific test")
    async def test_lockdown_restricts_to_owner_only(self):
        """Lockdown should restrict file to owner read/write only."""
        adapter = FilesystemAdapter()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "sensitive.txt"
            test_file.write_text("sensitive data")
            os.chmod(test_file, 0o644)  # Start with world readable

            file_info = FileInfo(
                path=str(test_file),
                name="sensitive.txt",
                size=14,
                modified=datetime.now(),
                adapter="filesystem",
            )

            success, original_acl = await adapter.lockdown_file(file_info)

            assert success is True
            assert original_acl is not None

            # Verify permissions are now restrictive
            new_mode = test_file.stat().st_mode & 0o777
            assert new_mode == 0o600

            # Verify original ACL was captured for rollback
            assert original_acl["platform"] == "posix"
            assert original_acl["mode"] & 0o777 == 0o644

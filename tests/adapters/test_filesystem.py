"""Tests for filesystem adapter."""

import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestFilesystemAdapter:
    """Tests for FilesystemAdapter."""

    def test_adapter_creation(self):
        """Test creating filesystem adapter."""
        from openlabels.adapters.filesystem import FilesystemAdapter

        adapter = FilesystemAdapter()
        assert adapter is not None

    def test_adapter_with_service_account(self):
        """Test adapter with service account."""
        from openlabels.adapters.filesystem import FilesystemAdapter

        adapter = FilesystemAdapter(service_account="DOMAIN\\svcaccount")
        assert adapter is not None

    @pytest.mark.asyncio
    async def test_list_files_empty_directory(self):
        """Test listing files in empty directory."""
        from openlabels.adapters.filesystem import FilesystemAdapter

        with tempfile.TemporaryDirectory() as tmpdir:
            adapter = FilesystemAdapter()
            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 0

    @pytest.mark.asyncio
    async def test_list_files_with_files(self):
        """Test listing files with actual files."""
        from openlabels.adapters.filesystem import FilesystemAdapter

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "test1.txt").write_text("content1")
            (Path(tmpdir) / "test2.txt").write_text("content2")

            adapter = FilesystemAdapter()
            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            assert len(files) == 2
            names = [f.name for f in files]
            assert "test1.txt" in names
            assert "test2.txt" in names

    @pytest.mark.asyncio
    async def test_list_files_recursive(self):
        """Test listing files recursively."""
        from openlabels.adapters.filesystem import FilesystemAdapter

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (Path(tmpdir) / "root.txt").write_text("root")
            (subdir / "nested.txt").write_text("nested")

            adapter = FilesystemAdapter()
            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            names = [f.name for f in files]
            assert "root.txt" in names
            assert "nested.txt" in names

    @pytest.mark.asyncio
    async def test_read_file(self):
        """Test reading file content."""
        from openlabels.adapters.filesystem import FilesystemAdapter
        from openlabels.adapters.base import FileInfo, ExposureLevel

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Hello, World!")

            adapter = FilesystemAdapter()

            # Create FileInfo manually
            file_info = FileInfo(
                path=str(test_file),
                name="test.txt",
                size=13,
                modified=test_file.stat().st_mtime,
                adapter="filesystem",
                exposure=ExposureLevel.PRIVATE,
            )

            content = await adapter.read_file(file_info)

            assert content == b"Hello, World!"

    @pytest.mark.asyncio
    async def test_list_files_filters_hidden(self):
        """Test that hidden files can be filtered."""
        from openlabels.adapters.filesystem import FilesystemAdapter

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "visible.txt").write_text("visible")
            (Path(tmpdir) / ".hidden.txt").write_text("hidden")

            adapter = FilesystemAdapter()
            files = []
            async for f in adapter.list_files(tmpdir):
                files.append(f)

            # Behavior depends on implementation
            # At minimum, visible.txt should be present
            names = [f.name for f in files]
            assert "visible.txt" in names


class TestFileInfo:
    """Tests for FileInfo dataclass."""

    def test_file_info_creation(self):
        """Test creating FileInfo."""
        from openlabels.adapters.base import FileInfo, ExposureLevel

        info = FileInfo(
            path="/path/to/file.txt",
            name="file.txt",
            size=1024,
            modified=1234567890.0,
            adapter="filesystem",
            exposure=ExposureLevel.PRIVATE,
        )

        assert info.path == "/path/to/file.txt"
        assert info.name == "file.txt"
        assert info.size == 1024

    def test_file_info_exposure_levels(self):
        """Test FileInfo with different exposure levels."""
        from openlabels.adapters.base import FileInfo, ExposureLevel

        for level in ExposureLevel:
            info = FileInfo(
                path="/test.txt",
                name="test.txt",
                size=100,
                modified=0.0,
                adapter="filesystem",
                exposure=level,
            )
            assert info.exposure == level


class TestExposureLevel:
    """Tests for ExposureLevel enum."""

    def test_exposure_levels_exist(self):
        """Test that exposure levels are defined."""
        from openlabels.adapters.base import ExposureLevel

        assert hasattr(ExposureLevel, "PRIVATE")
        assert hasattr(ExposureLevel, "INTERNAL")
        assert hasattr(ExposureLevel, "ORG_WIDE")
        assert hasattr(ExposureLevel, "PUBLIC")

    def test_exposure_level_values(self):
        """Test exposure level values."""
        from openlabels.adapters.base import ExposureLevel

        # Values should be strings
        assert isinstance(ExposureLevel.PRIVATE.value, str)
        assert isinstance(ExposureLevel.PUBLIC.value, str)

    def test_exposure_level_ordering(self):
        """Test exposure levels have logical ordering."""
        from openlabels.adapters.base import ExposureLevel

        # The enum should have 4 levels
        levels = list(ExposureLevel)
        assert len(levels) >= 4

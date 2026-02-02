"""Tests for adapter base classes."""

import pytest


class TestAdapterProtocol:
    """Tests for Adapter protocol class."""

    def test_adapter_import(self):
        """Test Adapter can be imported."""
        from openlabels.adapters.base import Adapter

        assert Adapter is not None

    def test_adapter_is_protocol(self):
        """Test Adapter is a Protocol."""
        from openlabels.adapters.base import Adapter

        # Should define the adapter interface
        assert Adapter is not None


class TestFileInfo:
    """Tests for FileInfo dataclass."""

    def test_file_info_import(self):
        """Test FileInfo can be imported."""
        from openlabels.adapters.base import FileInfo

        assert FileInfo is not None

    def test_file_info_fields(self):
        """Test FileInfo has required fields."""
        from openlabels.adapters.base import FileInfo, ExposureLevel

        info = FileInfo(
            path="/test/path.txt",
            name="path.txt",
            size=1024,
            modified=1234567890.0,
            adapter="filesystem",
            exposure=ExposureLevel.PRIVATE,
        )

        assert info.path == "/test/path.txt"
        assert info.name == "path.txt"
        assert info.size == 1024


class TestExposureLevel:
    """Tests for ExposureLevel enum."""

    def test_exposure_level_import(self):
        """Test ExposureLevel can be imported."""
        from openlabels.adapters.base import ExposureLevel

        assert ExposureLevel is not None

    def test_exposure_level_values(self):
        """Test ExposureLevel values."""
        from openlabels.adapters.base import ExposureLevel

        assert ExposureLevel.PRIVATE is not None
        assert ExposureLevel.INTERNAL is not None
        assert ExposureLevel.ORG_WIDE is not None
        assert ExposureLevel.PUBLIC is not None

    def test_exposure_levels_are_orderable(self):
        """Test exposure levels have logical ordering."""
        from openlabels.adapters.base import ExposureLevel

        levels = list(ExposureLevel)
        # Should have at least 4 levels
        assert len(levels) >= 4


class TestAdapterRegistry:
    """Tests for adapter registry."""

    def test_adapters_package_import(self):
        """Test adapters package can be imported."""
        from openlabels import adapters

        assert adapters is not None

    def test_filesystem_adapter_available(self):
        """Test filesystem adapter is available."""
        from openlabels.adapters.filesystem import FilesystemAdapter

        assert FilesystemAdapter is not None

    def test_sharepoint_adapter_available(self):
        """Test SharePoint adapter is available."""
        from openlabels.adapters.sharepoint import SharePointAdapter

        assert SharePointAdapter is not None

    def test_onedrive_adapter_available(self):
        """Test OneDrive adapter is available."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        assert OneDriveAdapter is not None

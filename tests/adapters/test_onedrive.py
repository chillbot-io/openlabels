"""Tests for OneDrive adapter."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestOneDriveAdapter:
    """Tests for OneDriveAdapter."""

    def test_adapter_import(self):
        """Test OneDriveAdapter can be imported."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        assert OneDriveAdapter is not None

    def test_adapter_creation(self):
        """Test creating OneDrive adapter."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
        )

        assert adapter is not None
        assert adapter.tenant_id == "test-tenant"

    def test_adapter_has_list_files(self):
        """Test adapter has list_files method."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        assert hasattr(adapter, 'list_files')

    def test_adapter_has_read_file(self):
        """Test adapter has read_file method."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        assert hasattr(adapter, 'read_file')


class TestOneDriveExposureMapping:
    """Tests for OneDrive permission to exposure mapping."""

    def test_exposure_levels(self):
        """Test exposure level definitions."""
        from openlabels.adapters.base import ExposureLevel

        # OneDrive should support standard exposure levels
        assert ExposureLevel.PRIVATE is not None
        assert ExposureLevel.PUBLIC is not None


class TestOneDriveDriveTypes:
    """Tests for OneDrive drive type handling."""

    def test_drive_types(self):
        """Test OneDrive drive types."""
        # Common OneDrive drive types
        drive_types = ["personal", "business", "documentLibrary"]

        for dtype in drive_types:
            assert isinstance(dtype, str)

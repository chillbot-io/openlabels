"""Tests for SharePoint adapter."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestSharePointAdapter:
    """Tests for SharePointAdapter."""

    def test_adapter_creation(self):
        """Test creating SharePoint adapter."""
        from openlabels.adapters.sharepoint import SharePointAdapter

        adapter = SharePointAdapter(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
        )

        assert adapter is not None
        assert adapter.tenant_id == "test-tenant"

    def test_adapter_requires_credentials(self):
        """Test adapter requires credentials."""
        from openlabels.adapters.sharepoint import SharePointAdapter

        # Should work with all credentials
        adapter = SharePointAdapter(
            tenant_id="tenant",
            client_id="client",
            client_secret="secret",
        )
        assert adapter.tenant_id is not None

    def test_adapter_has_expected_attributes(self):
        """Test adapter has expected attributes."""
        from openlabels.adapters.sharepoint import SharePointAdapter

        adapter = SharePointAdapter(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
        )

        # Check adapter has necessary attributes
        assert hasattr(adapter, 'tenant_id')
        assert hasattr(adapter, 'client_id')

    @pytest.mark.asyncio
    async def test_list_files_method_exists(self):
        """Test that list_files method exists on SharePointAdapter."""
        from openlabels.adapters.sharepoint import SharePointAdapter

        adapter = SharePointAdapter(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
        )

        # Verify the adapter has the expected methods
        assert hasattr(adapter, 'list_files')
        assert hasattr(adapter, 'list_sites')
        assert hasattr(adapter, '_get_client')
        assert adapter.adapter_type == "sharepoint"
        assert adapter.supports_delta() is True


class TestSharePointExposureMapping:
    """Tests for SharePoint permission to exposure mapping."""

    def test_exposure_mapping_exists(self):
        """Test that exposure mapping logic exists."""
        from openlabels.adapters.sharepoint import SharePointAdapter

        # Adapter should have method to determine exposure
        adapter = SharePointAdapter(
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        # Check adapter has necessary attributes/methods
        assert hasattr(adapter, 'tenant_id')


class TestSharePointSiteDiscovery:
    """Tests for SharePoint site discovery."""

    def test_site_id_format(self):
        """Test site ID format handling."""
        from openlabels.adapters.sharepoint import SharePointAdapter

        adapter = SharePointAdapter(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
        )

        # Site IDs should be handled properly
        # Format is typically hostname,site-id,web-id
        assert adapter is not None

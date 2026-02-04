"""
Tests for OneDrive adapter.

Tests cover adapter configuration, exposure level mapping, and file info conversion.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestOneDriveAdapterConfiguration:
    """Tests for OneDrive adapter configuration."""

    def test_stores_tenant_id(self):
        """Adapter should store tenant ID."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="my-tenant-123",
            client_id="client",
            client_secret="secret",
        )

        assert adapter.tenant_id == "my-tenant-123"

    def test_stores_client_id(self):
        """Adapter should store client ID."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="tenant",
            client_id="my-client-456",
            client_secret="secret",
        )

        assert adapter.client_id == "my-client-456"

    def test_stores_client_secret(self):
        """Adapter should store client secret."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="tenant",
            client_id="client",
            client_secret="my-secret-789",
        )

        assert adapter.client_secret == "my-secret-789"

    def test_adapter_type_is_onedrive(self):
        """Adapter type should be 'onedrive'."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert adapter.adapter_type == "onedrive"

    def test_supports_delta_queries(self):
        """OneDrive adapter should support delta queries."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert adapter.supports_delta() is True

    def test_client_initially_none(self):
        """Graph client should not be created until needed."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert adapter._client is None


class TestOneDriveExposureMapping:
    """Tests for exposure level determination from sharing info."""

    def test_anonymous_link_is_public(self):
        """Anonymous sharing link should map to PUBLIC exposure."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        from openlabels.adapters.base import ExposureLevel

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "permissions": [
                {"link": {"scope": "anonymous"}}
            ]
        }

        assert adapter._determine_exposure(item) == ExposureLevel.PUBLIC

    def test_organization_link_is_org_wide(self):
        """Organization sharing link should map to ORG_WIDE exposure."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        from openlabels.adapters.base import ExposureLevel

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "permissions": [
                {"link": {"scope": "organization"}}
            ]
        }

        assert adapter._determine_exposure(item) == ExposureLevel.ORG_WIDE

    def test_shared_item_is_internal(self):
        """Item with shared flag should map to INTERNAL exposure."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        from openlabels.adapters.base import ExposureLevel

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {"shared": True}

        assert adapter._determine_exposure(item) == ExposureLevel.INTERNAL

    def test_no_sharing_is_private(self):
        """Item without sharing info should default to PRIVATE."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        from openlabels.adapters.base import ExposureLevel

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {}

        assert adapter._determine_exposure(item) == ExposureLevel.PRIVATE

    def test_empty_permissions_is_private(self):
        """Empty permissions list should default to PRIVATE."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        from openlabels.adapters.base import ExposureLevel

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {"permissions": []}

        assert adapter._determine_exposure(item) == ExposureLevel.PRIVATE


class TestOneDriveFileInfoConversion:
    """Tests for converting Graph API items to FileInfo."""

    def test_converts_basic_file_info(self):
        """Should convert basic file properties."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "id": "item-123",
            "name": "document.docx",
            "size": 1024,
            "lastModifiedDateTime": "2024-01-15T10:30:00Z",
            "parentReference": {"path": "/drive/root:/Documents"},
            "file": {},  # Indicates it's a file
        }

        file_info = adapter._item_to_file_info(item, "user@example.com")

        assert file_info.name == "document.docx"
        assert file_info.size == 1024
        assert file_info.item_id == "item-123"
        assert file_info.user_id == "user@example.com"
        assert file_info.adapter == "onedrive"

    def test_parses_path_from_parent_reference(self):
        """Should construct path from parent reference."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "id": "item-123",
            "name": "report.xlsx",
            "size": 500,
            "lastModifiedDateTime": "2024-01-15T10:30:00Z",
            "parentReference": {"path": "/drive/root:/Finance/Reports"},
            "file": {},
        }

        file_info = adapter._item_to_file_info(item, "user@example.com")

        assert file_info.path == "/Finance/Reports/report.xlsx"

    def test_parses_datetime(self):
        """Should parse ISO datetime correctly."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "id": "item-123",
            "name": "test.txt",
            "size": 100,
            "lastModifiedDateTime": "2024-06-20T14:45:30Z",
            "parentReference": {"path": "/drive/root:"},
            "file": {},
        }

        file_info = adapter._item_to_file_info(item, "user")

        assert file_info.modified.year == 2024
        assert file_info.modified.month == 6
        assert file_info.modified.day == 20
        assert file_info.modified.hour == 14
        assert file_info.modified.minute == 45

    def test_extracts_owner_from_created_by_user(self):
        """Should extract owner from createdBy.user."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "id": "item-123",
            "name": "test.txt",
            "size": 100,
            "lastModifiedDateTime": "2024-01-15T10:30:00Z",
            "parentReference": {"path": "/drive/root:"},
            "file": {},
            "createdBy": {
                "user": {"email": "owner@example.com"}
            }
        }

        file_info = adapter._item_to_file_info(item, "user")

        assert file_info.owner == "owner@example.com"

    def test_extracts_owner_from_display_name_fallback(self):
        """Should use displayName if email not available."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "id": "item-123",
            "name": "test.txt",
            "size": 100,
            "lastModifiedDateTime": "2024-01-15T10:30:00Z",
            "parentReference": {"path": "/drive/root:"},
            "file": {},
            "createdBy": {
                "user": {"displayName": "John Doe"}
            }
        }

        file_info = adapter._item_to_file_info(item, "user")

        assert file_info.owner == "John Doe"

    def test_handles_missing_parent_reference(self):
        """Should handle missing parent reference gracefully."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "id": "item-123",
            "name": "orphan.txt",
            "size": 100,
            "lastModifiedDateTime": "2024-01-15T10:30:00Z",
            "file": {},
        }

        file_info = adapter._item_to_file_info(item, "user")

        assert file_info.path == "/orphan.txt"

    def test_handles_missing_size(self):
        """Should default to 0 for missing size."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        item = {
            "id": "item-123",
            "name": "test.txt",
            "lastModifiedDateTime": "2024-01-15T10:30:00Z",
            "parentReference": {"path": "/drive/root:"},
            "file": {},
        }

        file_info = adapter._item_to_file_info(item, "user")

        assert file_info.size == 0


class TestOneDriveAdapterStats:
    """Tests for adapter statistics."""

    def test_stats_include_adapter_type(self):
        """Stats should include adapter type."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        stats = adapter.get_stats()

        assert stats["adapter"] == "onedrive"

    def test_stats_without_client(self):
        """Stats should work even without client initialized."""
        from openlabels.adapters.onedrive import OneDriveAdapter

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        # Should not raise
        stats = adapter.get_stats()

        assert isinstance(stats, dict)


class TestOneDriveAdapterProtocol:
    """Tests verifying adapter follows the protocol."""

    def test_has_list_files_method(self):
        """Adapter should have async list_files method."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        import inspect

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(adapter, 'list_files')
        assert inspect.iscoroutinefunction(adapter.list_files)

    def test_has_read_file_method(self):
        """Adapter should have async read_file method."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        import inspect

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(adapter, 'read_file')
        assert inspect.iscoroutinefunction(adapter.read_file)

    def test_has_test_connection_method(self):
        """Adapter should have async test_connection method."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        import inspect

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(adapter, 'test_connection')
        assert inspect.iscoroutinefunction(adapter.test_connection)

    def test_has_get_metadata_method(self):
        """Adapter should have async get_metadata method."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        import inspect

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(adapter, 'get_metadata')
        assert inspect.iscoroutinefunction(adapter.get_metadata)

    def test_has_close_method(self):
        """Adapter should have async close method."""
        from openlabels.adapters.onedrive import OneDriveAdapter
        import inspect

        adapter = OneDriveAdapter(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(adapter, 'close')
        assert inspect.iscoroutinefunction(adapter.close)

"""
Comprehensive tests for the label synchronization task.

Tests focus on:
- LabelSyncResult data class
- Label sync task execution
- Graph API token acquisition
- Label fetching from Graph API
- Stale label removal
- Error handling and retries
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch

from openlabels.jobs.tasks.label_sync import (
    LabelSyncResult,
    execute_label_sync_task,
    sync_labels_from_graph,
    HTTPX_AVAILABLE,
)


class TestLabelSyncResult:
    """Tests for LabelSyncResult data class."""

    def test_init_defaults_to_zero(self):
        """Should initialize with zero counts."""
        result = LabelSyncResult()

        assert result.labels_synced == 0
        assert result.labels_added == 0
        assert result.labels_updated == 0
        assert result.labels_removed == 0

    def test_init_creates_empty_errors_list(self):
        """Should initialize with empty errors list."""
        result = LabelSyncResult()

        assert result.errors == []

    def test_to_dict_returns_all_fields(self):
        """to_dict should return all fields."""
        result = LabelSyncResult()
        result.labels_synced = 10
        result.labels_added = 5
        result.labels_updated = 3
        result.labels_removed = 2
        result.errors = ["Error 1"]

        d = result.to_dict()

        assert d["labels_synced"] == 10
        assert d["labels_added"] == 5
        assert d["labels_updated"] == 3
        assert d["labels_removed"] == 2
        assert d["errors"] == ["Error 1"]


class TestExecuteLabelSyncTask:
    """Tests for execute_label_sync_task function."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        return AsyncMock()

    async def test_returns_error_when_no_credentials(self, mock_session):
        """Should return error when credentials are missing."""
        with patch('openlabels.server.config.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    provider="local",
                    tenant_id=None,
                    client_id=None,
                    client_secret=None,
                )
            )

            result = await execute_label_sync_task(
                mock_session,
                {"tenant_id": str(uuid4())}
            )

            assert result["success"] is False
            assert "not configured" in result["error"].lower() or "missing" in result["error"].lower()

    async def test_uses_payload_credentials(self, mock_session):
        """Should use credentials from settings (credentials never from payload for security)."""
        tenant_id = uuid4()

        with patch('openlabels.server.config.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    provider="azure_ad",
                    tenant_id="azure-tenant",
                    client_id="client-id",
                    client_secret="client-secret",
                )
            )
            with patch('openlabels.jobs.tasks.label_sync.sync_labels_from_graph') as mock_sync:
                mock_result = LabelSyncResult()
                mock_result.labels_synced = 5
                mock_sync.return_value = mock_result

                result = await execute_label_sync_task(
                    mock_session,
                    {"tenant_id": str(tenant_id)}
                )

                mock_sync.assert_called_once()
                call_kwargs = mock_sync.call_args.kwargs
                assert call_kwargs["azure_tenant_id"] == "azure-tenant"
                assert call_kwargs["client_id"] == "client-id"

    async def test_falls_back_to_settings_credentials(self, mock_session):
        """Should fall back to settings when payload missing credentials."""
        tenant_id = uuid4()

        with patch('openlabels.server.config.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    provider="azure_ad",
                    tenant_id="settings-tenant",
                    client_id="settings-client",
                    client_secret="settings-secret",
                )
            )
            with patch('openlabels.jobs.tasks.label_sync.sync_labels_from_graph') as mock_sync:
                mock_result = LabelSyncResult()
                mock_sync.return_value = mock_result

                await execute_label_sync_task(
                    mock_session,
                    {"tenant_id": str(tenant_id)}
                )

                call_kwargs = mock_sync.call_args.kwargs
                assert call_kwargs["azure_tenant_id"] == "settings-tenant"
                assert call_kwargs["client_id"] == "settings-client"

    async def test_returns_success_when_no_errors(self, mock_session):
        """Should return success=True when no errors."""
        with patch('openlabels.server.config.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    provider="azure_ad",
                    tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )
            )
            with patch('openlabels.jobs.tasks.label_sync.sync_labels_from_graph') as mock_sync:
                mock_result = LabelSyncResult()
                mock_result.labels_synced = 10
                mock_sync.return_value = mock_result

                result = await execute_label_sync_task(
                    mock_session,
                    {"tenant_id": str(uuid4())}
                )

                assert result["success"] is True
                assert result["labels_synced"] == 10

    async def test_returns_failure_when_errors(self, mock_session):
        """Should return success=False when there are errors."""
        with patch('openlabels.server.config.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    provider="azure_ad",
                    tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )
            )
            with patch('openlabels.jobs.tasks.label_sync.sync_labels_from_graph') as mock_sync:
                mock_result = LabelSyncResult()
                mock_result.errors = ["Error 1", "Error 2"]
                mock_sync.return_value = mock_result

                result = await execute_label_sync_task(
                    mock_session,
                    {"tenant_id": str(uuid4())}
                )

                assert result["success"] is False
                assert "Error 1" in result["error"]

    async def test_passes_remove_stale_option(self, mock_session):
        """Should pass remove_stale option to sync function."""
        with patch('openlabels.server.config.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                auth=MagicMock(
                    provider="azure_ad",
                    tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )
            )
            with patch('openlabels.jobs.tasks.label_sync.sync_labels_from_graph') as mock_sync:
                mock_result = LabelSyncResult()
                mock_sync.return_value = mock_result

                await execute_label_sync_task(
                    mock_session,
                    {
                        "tenant_id": str(uuid4()),
                        "remove_stale": True,
                    }
                )

                call_kwargs = mock_sync.call_args.kwargs
                assert call_kwargs["remove_stale"] is True


class TestSyncLabelsFromGraph:
    """Tests for sync_labels_from_graph function."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session with batch query support."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.add = MagicMock()
        # Mock for batch query - returns empty result by default (no existing labels)
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=mock_result)
        return session

    async def test_returns_error_when_httpx_unavailable(self, mock_session):
        """Should return error when httpx is not available."""
        import openlabels.jobs.tasks.label_sync as module
        original = module.HTTPX_AVAILABLE

        try:
            module.HTTPX_AVAILABLE = False

            result = await sync_labels_from_graph(
                mock_session,
                tenant_id=uuid4(),
                azure_tenant_id="tenant",
                client_id="client",
                client_secret="secret",
            )

            assert "httpx" in result.errors[0].lower()
        finally:
            module.HTTPX_AVAILABLE = original

    async def test_returns_error_when_token_fails(self, mock_session):
        """Should return error when token acquisition fails."""
        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = None

            result = await sync_labels_from_graph(
                mock_session,
                tenant_id=uuid4(),
                azure_tenant_id="tenant",
                client_id="client",
                client_secret="secret",
            )

            assert len(result.errors) > 0
            assert "token" in result.errors[0].lower()

    async def test_returns_error_when_fetch_fails(self, mock_session):
        """Should return error when label fetch fails."""
        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "valid-token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = None

                result = await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert len(result.errors) > 0
                assert "fetch" in result.errors[0].lower()

    async def test_adds_new_labels(self, mock_session):
        """Should add labels that don't exist in database."""
        # Mock batch query to return no existing labels
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "valid-token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"id": str(uuid4()), "name": "Label 1"},
                    {"id": str(uuid4()), "name": "Label 2"},
                ]

                result = await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert result.labels_added == 2
                assert result.labels_synced == 2
                assert mock_session.add.call_count == 2

    async def test_updates_existing_labels(self, mock_session):
        """Should update labels that exist in database."""
        label_id = str(uuid4())
        existing_label = MagicMock()
        existing_label.id = label_id
        existing_label.name = "Old Name"

        # Mock batch query to return the existing label
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing_label]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "valid-token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"id": label_id, "name": "New Name"},
                ]

                result = await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert result.labels_updated == 1
                assert existing_label.name == "New Name"

    async def test_skips_labels_without_id(self, mock_session):
        """Should skip labels that don't have an ID."""
        # Mock batch query to return no existing labels
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "valid-token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"name": "No ID Label"},  # Missing id
                    {"id": str(uuid4()), "name": "Has ID"},
                ]

                result = await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert result.labels_synced == 1

    async def test_removes_stale_labels_when_enabled(self, mock_session):
        """Should remove stale labels when remove_stale=True."""
        # Mock batch query to return no existing labels
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "valid-token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [{"id": str(uuid4()), "name": "Label"}]
                with patch('openlabels.jobs.tasks.label_sync._remove_stale_labels') as mock_remove:
                    mock_remove.return_value = 3

                    result = await sync_labels_from_graph(
                        mock_session,
                        tenant_id=uuid4(),
                        azure_tenant_id="tenant",
                        client_id="client",
                        client_secret="secret",
                        remove_stale=True,
                    )

                    mock_remove.assert_called_once()
                    assert result.labels_removed == 3

    async def test_does_not_remove_stale_when_disabled(self, mock_session):
        """Should not remove stale labels when remove_stale=False."""
        mock_session.get = AsyncMock(return_value=None)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "valid-token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [{"id": str(uuid4()), "name": "Label"}]
                with patch('openlabels.jobs.tasks.label_sync._remove_stale_labels') as mock_remove:

                    await sync_labels_from_graph(
                        mock_session,
                        tenant_id=uuid4(),
                        azure_tenant_id="tenant",
                        client_id="client",
                        client_secret="secret",
                        remove_stale=False,
                    )

                    mock_remove.assert_not_called()



class TestLabelFieldExtraction:
    """Tests for extracting label fields from Graph API response."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session with batch query support."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_extracts_label_description(self, mock_session):
        """Should extract description from label data."""
        label_id = str(uuid4())
        existing = MagicMock()
        existing.id = label_id
        existing.description = None

        # Mock batch query to return existing label
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"id": label_id, "name": "Label", "description": "Test desc"}
                ]

                await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert existing.description == "Test desc"

    async def test_extracts_label_color(self, mock_session):
        """Should extract color from label data."""
        label_id = str(uuid4())
        existing = MagicMock()
        existing.id = label_id
        existing.color = None

        # Mock batch query to return existing label
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"id": label_id, "name": "Label", "color": "#FF0000"}
                ]

                await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert existing.color == "#FF0000"

    async def test_extracts_label_priority(self, mock_session):
        """Should extract priority from label data."""
        label_id = str(uuid4())
        existing = MagicMock()
        existing.id = label_id
        existing.priority = 0

        # Mock batch query to return existing label
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"id": label_id, "name": "Label", "priority": 100}
                ]

                await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert existing.priority == 100

    async def test_extracts_parent_id(self, mock_session):
        """Should extract parent_id from nested parent object."""
        label_id = str(uuid4())
        existing = MagicMock()
        existing.id = label_id
        existing.parent_id = None

        parent_id = str(uuid4())

        # Mock batch query to return existing label
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"id": label_id, "name": "Label", "parent": {"id": parent_id}}
                ]

                await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                assert existing.parent_id == parent_id

    async def test_updates_synced_at_timestamp(self, mock_session):
        """Should update synced_at to current time."""
        label_id = str(uuid4())
        existing = MagicMock()
        existing.id = label_id
        existing.synced_at = None

        # Mock batch query to return existing label
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                mock_fetch.return_value = [
                    {"id": label_id, "name": "Label"}
                ]

                before = datetime.now(timezone.utc)
                await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )
                after = datetime.now(timezone.utc)

                assert before <= existing.synced_at <= after


class TestLabelSyncErrorHandling:
    """Tests for error handling in label sync."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.flush = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_catches_individual_label_errors(self, mock_session):
        """Should catch and record errors for individual labels."""
        # Mock batch query to raise exception
        mock_session.execute = AsyncMock(side_effect=Exception("Database error"))

        with patch('openlabels.jobs.tasks.label_sync._get_graph_token') as mock_token:
            mock_token.return_value = "token"
            with patch('openlabels.jobs.tasks.label_sync._fetch_labels_from_graph') as mock_fetch:
                label_id = str(uuid4())
                mock_fetch.return_value = [
                    {"id": label_id, "name": "Label"}
                ]

                result = await sync_labels_from_graph(
                    mock_session,
                    tenant_id=uuid4(),
                    azure_tenant_id="tenant",
                    client_id="client",
                    client_secret="secret",
                )

                # Should have an error since execute failed
                assert len(result.errors) > 0

    async def test_handles_settings_exception(self, mock_session):
        """Should handle exception when getting settings."""
        with patch('openlabels.server.config.get_settings') as mock_settings:
            mock_settings.side_effect = Exception("Settings error")

            result = await execute_label_sync_task(
                mock_session,
                {"tenant_id": str(uuid4())}
            )

            assert result["success"] is False
            assert "settings" in result["error"].lower()

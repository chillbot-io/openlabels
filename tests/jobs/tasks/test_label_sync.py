"""
Tests for the label synchronization task.

The task delegates Graph API communication to LabelingEngine; these tests
verify DB upsert logic, stale-label removal, and error handling.
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
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_engine(labels: list[dict] | None = None):
    """Return a patch context that mocks create_labeling_engine."""
    engine = MagicMock()
    engine.get_available_labels = AsyncMock(return_value=labels or [])
    return patch(
        "openlabels.jobs.tasks.label_sync.create_labeling_engine",
        return_value=engine,
    )


def _mock_settings(provider="azure_ad", tenant_id="t", client_id="c", client_secret="s"):
    """Return a patch context that mocks get_settings inside the task."""
    settings = MagicMock()
    settings.auth.provider = provider
    settings.auth.tenant_id = tenant_id
    settings.auth.client_id = client_id
    settings.auth.client_secret = client_secret
    return patch(
        "openlabels.server.config.get_settings",
        return_value=settings,
    )


# ---------------------------------------------------------------------------
# LabelSyncResult
# ---------------------------------------------------------------------------

class TestLabelSyncResult:
    def test_init_defaults_to_zero(self):
        result = LabelSyncResult()
        assert result.labels_synced == 0
        assert result.labels_added == 0
        assert result.labels_updated == 0
        assert result.labels_removed == 0

    def test_init_creates_empty_errors_list(self):
        assert LabelSyncResult().errors == []

    def test_to_dict_returns_all_fields(self):
        result = LabelSyncResult()
        result.labels_synced = 10
        result.labels_added = 5
        result.labels_updated = 3
        result.labels_removed = 2
        result.errors = ["Error 1"]

        d = result.to_dict()
        assert d == {
            "labels_synced": 10,
            "labels_added": 5,
            "labels_updated": 3,
            "labels_removed": 2,
            "errors": ["Error 1"],
        }


# ---------------------------------------------------------------------------
# execute_label_sync_task
# ---------------------------------------------------------------------------

class TestExecuteLabelSyncTask:
    @pytest.fixture
    def mock_session(self):
        return AsyncMock()

    async def test_returns_error_when_provider_not_azure(self, mock_session):
        with _mock_settings(provider="local"):
            result = await execute_label_sync_task(
                mock_session, {"tenant_id": str(uuid4())}
            )
        assert result["success"] is False
        assert "not configured" in result["error"].lower()

    async def test_returns_error_when_credentials_missing(self, mock_session):
        with _mock_settings(client_secret=""):
            result = await execute_label_sync_task(
                mock_session, {"tenant_id": str(uuid4())}
            )
        assert result["success"] is False
        assert "not configured" in result["error"].lower()

    async def test_returns_success_when_no_errors(self, mock_session):
        with _mock_settings():
            with patch(
                "openlabels.jobs.tasks.label_sync.sync_labels_from_graph"
            ) as mock_sync:
                r = LabelSyncResult()
                r.labels_synced = 10
                mock_sync.return_value = r

                result = await execute_label_sync_task(
                    mock_session, {"tenant_id": str(uuid4())}
                )

        assert result["success"] is True
        assert result["labels_synced"] == 10

    async def test_returns_failure_when_errors(self, mock_session):
        with _mock_settings():
            with patch(
                "openlabels.jobs.tasks.label_sync.sync_labels_from_graph"
            ) as mock_sync:
                r = LabelSyncResult()
                r.errors = ["E1", "E2"]
                mock_sync.return_value = r

                result = await execute_label_sync_task(
                    mock_session, {"tenant_id": str(uuid4())}
                )

        assert result["success"] is False
        assert "E1" in result["error"]

    async def test_passes_remove_stale_option(self, mock_session):
        with _mock_settings():
            with patch(
                "openlabels.jobs.tasks.label_sync.sync_labels_from_graph"
            ) as mock_sync:
                mock_sync.return_value = LabelSyncResult()

                await execute_label_sync_task(
                    mock_session,
                    {"tenant_id": str(uuid4()), "remove_stale": True},
                )

                assert mock_sync.call_args.kwargs["remove_stale"] is True

    async def test_handles_settings_exception(self, mock_session):
        with patch(
            "openlabels.server.config.get_settings",
            side_effect=RuntimeError("boom"),
        ):
            result = await execute_label_sync_task(
                mock_session, {"tenant_id": str(uuid4())}
            )
        assert result["success"] is False
        assert "settings" in result["error"].lower()


# ---------------------------------------------------------------------------
# sync_labels_from_graph
# ---------------------------------------------------------------------------

class TestSyncLabelsFromGraph:
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.flush = AsyncMock()
        session.add = MagicMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=mock_result)
        return session

    async def test_returns_error_when_no_labels(self, mock_session):
        with _mock_engine(labels=[]):
            result = await sync_labels_from_graph(mock_session, tenant_id=uuid4())
        assert len(result.errors) == 1
        assert "no labels" in result.errors[0].lower()

    async def test_adds_new_labels(self, mock_session):
        labels = [
            {"id": str(uuid4()), "name": "Label 1"},
            {"id": str(uuid4()), "name": "Label 2"},
        ]
        with _mock_engine(labels=labels):
            result = await sync_labels_from_graph(mock_session, tenant_id=uuid4())

        assert result.labels_added == 2
        assert result.labels_synced == 2
        assert mock_session.add.call_count == 2

    async def test_updates_existing_labels(self, mock_session):
        label_id = str(uuid4())
        existing = MagicMock()
        existing.id = label_id
        existing.name = "Old Name"

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with _mock_engine(labels=[{"id": label_id, "name": "New Name"}]):
            result = await sync_labels_from_graph(mock_session, tenant_id=uuid4())

        assert result.labels_updated == 1
        assert existing.name == "New Name"

    async def test_skips_labels_without_id(self, mock_session):
        labels = [
            {"name": "No ID"},
            {"id": str(uuid4()), "name": "Has ID"},
        ]
        with _mock_engine(labels=labels):
            result = await sync_labels_from_graph(mock_session, tenant_id=uuid4())
        assert result.labels_synced == 1

    async def test_removes_stale_labels_when_enabled(self, mock_session):
        labels = [{"id": str(uuid4()), "name": "Label"}]
        with _mock_engine(labels=labels):
            with patch(
                "openlabels.jobs.tasks.label_sync._remove_stale_labels"
            ) as mock_remove:
                mock_remove.return_value = 3
                result = await sync_labels_from_graph(
                    mock_session, tenant_id=uuid4(), remove_stale=True
                )
        assert result.labels_removed == 3

    async def test_does_not_remove_stale_when_disabled(self, mock_session):
        labels = [{"id": str(uuid4()), "name": "Label"}]
        with _mock_engine(labels=labels):
            with patch(
                "openlabels.jobs.tasks.label_sync._remove_stale_labels"
            ) as mock_remove:
                await sync_labels_from_graph(
                    mock_session, tenant_id=uuid4(), remove_stale=False
                )
        mock_remove.assert_not_called()


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------

class TestLabelFieldExtraction:
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.flush = AsyncMock()
        session.add = MagicMock()
        return session

    def _session_with_existing(self, session, existing_label):
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [existing_label]
        session.execute = AsyncMock(return_value=mock_result)

    async def test_extracts_description(self, mock_session):
        label_id = str(uuid4())
        existing = MagicMock(id=label_id, description=None)
        self._session_with_existing(mock_session, existing)

        with _mock_engine([{"id": label_id, "name": "L", "description": "Test desc"}]):
            await sync_labels_from_graph(mock_session, tenant_id=uuid4())
        assert existing.description == "Test desc"

    async def test_extracts_color(self, mock_session):
        label_id = str(uuid4())
        existing = MagicMock(id=label_id, color=None)
        self._session_with_existing(mock_session, existing)

        with _mock_engine([{"id": label_id, "name": "L", "color": "#FF0000"}]):
            await sync_labels_from_graph(mock_session, tenant_id=uuid4())
        assert existing.color == "#FF0000"

    async def test_extracts_priority(self, mock_session):
        label_id = str(uuid4())
        existing = MagicMock(id=label_id, priority=0)
        self._session_with_existing(mock_session, existing)

        with _mock_engine([{"id": label_id, "name": "L", "priority": 100}]):
            await sync_labels_from_graph(mock_session, tenant_id=uuid4())
        assert existing.priority == 100

    async def test_extracts_parent_id(self, mock_session):
        label_id = str(uuid4())
        parent_id = str(uuid4())
        existing = MagicMock(id=label_id, parent_id=None)
        self._session_with_existing(mock_session, existing)

        with _mock_engine([{"id": label_id, "name": "L", "parent_id": parent_id}]):
            await sync_labels_from_graph(mock_session, tenant_id=uuid4())
        assert existing.parent_id == parent_id

    async def test_updates_synced_at(self, mock_session):
        label_id = str(uuid4())
        existing = MagicMock(id=label_id, synced_at=None)
        self._session_with_existing(mock_session, existing)

        with _mock_engine([{"id": label_id, "name": "L"}]):
            before = datetime.now(timezone.utc)
            await sync_labels_from_graph(mock_session, tenant_id=uuid4())
            after = datetime.now(timezone.utc)
        assert before <= existing.synced_at <= after


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestLabelSyncErrorHandling:
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.flush = AsyncMock()
        session.add = MagicMock()
        return session

    async def test_catches_engine_exception(self, mock_session):
        mock_session.execute = AsyncMock(side_effect=RuntimeError("DB error"))

        with _mock_engine([{"id": str(uuid4()), "name": "L"}]):
            result = await sync_labels_from_graph(mock_session, tenant_id=uuid4())
        assert len(result.errors) >= 1

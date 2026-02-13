"""
Tests for the label application task.

The task is a thin wrapper around LabelingEngine; these tests verify
DB orchestration (result lookup, field updates) and adapter inference.
Actual labeling logic is covered by tests/labeling/.
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch

from openlabels.jobs.tasks.label import execute_label_task, _infer_adapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_engine(success=True, method="test", error=None):
    """Return a patch context that mocks create_labeling_engine."""
    engine = MagicMock()
    engine.apply_label = AsyncMock(return_value=MagicMock(
        success=success, method=method, error=error,
    ))
    return patch(
        "openlabels.jobs.tasks.label.create_labeling_engine",
        return_value=engine,
    )


# ---------------------------------------------------------------------------
# _infer_adapter
# ---------------------------------------------------------------------------

class TestInferAdapter:
    def test_sharepoint_url(self):
        assert _infer_adapter("https://contoso.sharepoint.com/sites/docs/file.docx") == "sharepoint"

    def test_onedrive_url(self):
        assert _infer_adapter("https://contoso-my.sharepoint.com/personal/user_onedrive/file.xlsx") == "sharepoint"

    def test_onedrive_keyword_url(self):
        assert _infer_adapter("https://onedrive.live.com/file.docx") == "onedrive"

    def test_local_path(self):
        assert _infer_adapter("/home/user/document.docx") == "filesystem"

    def test_non_microsoft_https(self):
        assert _infer_adapter("https://example.com/file.pdf") == "filesystem"

    def test_http_url(self):
        assert _infer_adapter("http://example.com/file.txt") == "filesystem"


# ---------------------------------------------------------------------------
# execute_label_task
# ---------------------------------------------------------------------------

def _make_result(**overrides):
    defaults = dict(
        id=uuid4(),
        file_path="/test/document.docx",
        file_name="document.docx",
        file_size=1024,
        file_modified=datetime.now(timezone.utc),
        adapter_item_id=None,
        label_applied=False,
        label_applied_at=None,
        current_label_id=None,
        current_label_name=None,
        label_error=None,
    )
    defaults.update(overrides)
    return MagicMock(**defaults)


def _make_label(label_name="Confidential", **overrides):
    label = MagicMock()
    label.id = overrides.pop("id", str(uuid4()))
    label.name = label_name
    for k, v in overrides.items():
        setattr(label, k, v)
    return label


class TestExecuteLabelTask:
    @pytest.fixture
    def mock_session(self):
        return AsyncMock()

    async def test_raises_when_result_not_found(self, mock_session):
        mock_session.get = AsyncMock(return_value=None)
        with pytest.raises(ValueError, match="Result not found"):
            await execute_label_task(
                mock_session,
                {"result_id": str(uuid4()), "label_id": str(uuid4())},
            )

    async def test_raises_when_label_not_found(self, mock_session):
        result = _make_result()
        mock_session.get = AsyncMock(side_effect=[result, None])
        with pytest.raises(ValueError, match="Label not found"):
            await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": str(uuid4())},
            )

    async def test_rejects_non_microsoft_http_urls(self, mock_session):
        result = _make_result(file_path="https://example.com/files/document.pdf")
        label = _make_label()
        mock_session.get = AsyncMock(side_effect=[result, label])

        out = await execute_label_task(
            mock_session,
            {"result_id": str(result.id), "label_id": label.id},
        )
        assert out["success"] is False
        assert out["method"] == "unsupported"

    async def test_returns_success_on_successful_labeling(self, mock_session):
        result = _make_result()
        label = _make_label()
        mock_session.get = AsyncMock(side_effect=[result, label])

        with _mock_engine(success=True, method="mip_sdk"):
            out = await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": label.id},
            )

        assert out["success"] is True
        assert out["label_name"] == "Confidential"
        assert out["method"] == "mip_sdk"

    async def test_returns_failure_on_labeling_error(self, mock_session):
        result = _make_result()
        label = _make_label()
        mock_session.get = AsyncMock(side_effect=[result, label])

        with _mock_engine(success=False, method="mip", error="MIP SDK not available"):
            out = await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": label.id},
            )

        assert out["success"] is False
        assert out["error"] == "MIP SDK not available"


# ---------------------------------------------------------------------------
# DB field updates
# ---------------------------------------------------------------------------

class TestLabelResultUpdate:
    @pytest.fixture
    def mock_session(self):
        return AsyncMock()

    async def test_updates_label_applied_on_success(self, mock_session):
        result = _make_result()
        label = _make_label(label_name="Secret")
        mock_session.get = AsyncMock(side_effect=[result, label])

        with _mock_engine(success=True):
            await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": label.id},
            )
        assert result.label_applied is True

    async def test_updates_label_applied_at_on_success(self, mock_session):
        result = _make_result()
        label = _make_label(label_name="Secret")
        mock_session.get = AsyncMock(side_effect=[result, label])

        with _mock_engine(success=True):
            before = datetime.now(timezone.utc)
            await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": label.id},
            )
            after = datetime.now(timezone.utc)
        assert before <= result.label_applied_at <= after

    async def test_updates_current_label_on_success(self, mock_session):
        result = _make_result()
        label = _make_label(label_name="Secret")
        mock_session.get = AsyncMock(side_effect=[result, label])

        with _mock_engine(success=True):
            await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": label.id},
            )
        assert result.current_label_id == label.id
        assert result.current_label_name == "Secret"

    async def test_clears_label_error_on_success(self, mock_session):
        result = _make_result(label_error="Previous error")
        label = _make_label(label_name="Secret")
        mock_session.get = AsyncMock(side_effect=[result, label])

        with _mock_engine(success=True):
            await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": label.id},
            )
        assert result.label_error is None

    async def test_sets_label_error_on_failure(self, mock_session):
        result = _make_result()
        label = _make_label(label_name="Secret")
        mock_session.get = AsyncMock(side_effect=[result, label])

        with _mock_engine(success=False, error="Labeling failed"):
            await execute_label_task(
                mock_session,
                {"result_id": str(result.id), "label_id": label.id},
            )
        assert result.label_error == "Labeling failed"

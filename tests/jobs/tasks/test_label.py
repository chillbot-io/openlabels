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


class TestInferAdapter:
    """Tests for _infer_adapter helper."""

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


class TestExecuteLabelTask:
    """Tests for execute_label_task function."""

    @pytest.fixture
    def mock_session(self):
        return AsyncMock()

    @pytest.fixture
    def mock_result(self):
        result = MagicMock()
        result.id = uuid4()
        result.file_path = "/test/document.docx"
        result.file_name = "document.docx"
        result.file_size = 1024
        result.file_modified = datetime.now(timezone.utc)
        result.adapter_item_id = None
        result.label_applied = False
        result.label_applied_at = None
        result.current_label_id = None
        result.current_label_name = None
        result.label_error = None
        return result

    @pytest.fixture
    def mock_label(self):
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Confidential"
        return label

    async def test_raises_when_result_not_found(self, mock_session):
        mock_session.get = AsyncMock(return_value=None)

        with pytest.raises(ValueError, match="Result not found"):
            await execute_label_task(
                mock_session,
                {"result_id": str(uuid4()), "label_id": str(uuid4())},
            )

    async def test_raises_when_label_not_found(self, mock_session, mock_result):
        mock_session.get = AsyncMock(side_effect=[mock_result, None])

        with pytest.raises(ValueError, match="Label not found"):
            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": str(uuid4())},
            )

    async def test_rejects_non_microsoft_http_urls(self, mock_session, mock_result, mock_label):
        mock_result.file_path = "https://example.com/files/document.pdf"
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        result = await execute_label_task(
            mock_session,
            {"result_id": str(mock_result.id), "label_id": mock_label.id},
        )

        assert result["success"] is False
        assert result["method"] == "unsupported"

    @patch("openlabels.jobs.tasks.label.get_settings")
    @patch("openlabels.jobs.tasks.label.LabelingEngine")
    async def test_returns_success_on_successful_labeling(
        self, MockEngine, mock_settings, mock_session, mock_result, mock_label,
    ):
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        engine_inst = MockEngine.return_value
        engine_inst.apply_label = AsyncMock(return_value=MagicMock(
            success=True, method="mip_sdk", error=None,
        ))

        settings = MagicMock()
        settings.auth.tenant_id = "t"
        settings.auth.client_id = "c"
        settings.auth.client_secret = "s"
        mock_settings.return_value = settings

        result = await execute_label_task(
            mock_session,
            {"result_id": str(mock_result.id), "label_id": mock_label.id},
        )

        assert result["success"] is True
        assert result["label_name"] == "Confidential"
        assert result["method"] == "mip_sdk"

    @patch("openlabels.jobs.tasks.label.get_settings")
    @patch("openlabels.jobs.tasks.label.LabelingEngine")
    async def test_returns_failure_on_labeling_error(
        self, MockEngine, mock_settings, mock_session, mock_result, mock_label,
    ):
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        engine_inst = MockEngine.return_value
        engine_inst.apply_label = AsyncMock(return_value=MagicMock(
            success=False, method="mip", error="MIP SDK not available",
        ))

        settings = MagicMock()
        settings.auth.tenant_id = "t"
        settings.auth.client_id = "c"
        settings.auth.client_secret = "s"
        mock_settings.return_value = settings

        result = await execute_label_task(
            mock_session,
            {"result_id": str(mock_result.id), "label_id": mock_label.id},
        )

        assert result["success"] is False
        assert result["error"] == "MIP SDK not available"


class TestLabelResultUpdate:
    """Tests for scan result field updates after labeling."""

    @pytest.fixture
    def mock_session(self):
        return AsyncMock()

    @pytest.fixture
    def mock_result(self):
        result = MagicMock()
        result.id = uuid4()
        result.file_path = "/test/file.docx"
        result.file_name = "file.docx"
        result.file_size = 512
        result.file_modified = datetime.now(timezone.utc)
        result.adapter_item_id = None
        result.label_applied = False
        result.label_applied_at = None
        result.current_label_id = None
        result.current_label_name = None
        result.label_error = None
        return result

    @pytest.fixture
    def mock_label(self):
        label = MagicMock()
        label.id = str(uuid4())
        label.name = "Secret"
        return label

    def _patch_engine(self, success, method="test", error=None):
        """Return context managers that patch LabelingEngine and get_settings."""
        engine_patch = patch("openlabels.jobs.tasks.label.LabelingEngine")
        settings_patch = patch("openlabels.jobs.tasks.label.get_settings")
        return engine_patch, settings_patch, MagicMock(
            success=success, method=method, error=error,
        )

    async def test_updates_label_applied_on_success(self, mock_session, mock_result, mock_label):
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch("openlabels.jobs.tasks.label.LabelingEngine") as MockEngine, \
             patch("openlabels.jobs.tasks.label.get_settings") as mock_settings:
            settings = MagicMock()
            settings.auth.tenant_id = "t"
            settings.auth.client_id = "c"
            settings.auth.client_secret = "s"
            mock_settings.return_value = settings
            MockEngine.return_value.apply_label = AsyncMock(
                return_value=MagicMock(success=True, method="test", error=None)
            )

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id},
            )

            assert mock_result.label_applied is True

    async def test_updates_label_applied_at_on_success(self, mock_session, mock_result, mock_label):
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch("openlabels.jobs.tasks.label.LabelingEngine") as MockEngine, \
             patch("openlabels.jobs.tasks.label.get_settings") as mock_settings:
            settings = MagicMock()
            settings.auth.tenant_id = "t"
            settings.auth.client_id = "c"
            settings.auth.client_secret = "s"
            mock_settings.return_value = settings
            MockEngine.return_value.apply_label = AsyncMock(
                return_value=MagicMock(success=True, method="test", error=None)
            )

            before = datetime.now(timezone.utc)
            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id},
            )
            after = datetime.now(timezone.utc)

            assert before <= mock_result.label_applied_at <= after

    async def test_updates_current_label_on_success(self, mock_session, mock_result, mock_label):
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch("openlabels.jobs.tasks.label.LabelingEngine") as MockEngine, \
             patch("openlabels.jobs.tasks.label.get_settings") as mock_settings:
            settings = MagicMock()
            settings.auth.tenant_id = "t"
            settings.auth.client_id = "c"
            settings.auth.client_secret = "s"
            mock_settings.return_value = settings
            MockEngine.return_value.apply_label = AsyncMock(
                return_value=MagicMock(success=True, method="test", error=None)
            )

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id},
            )

            assert mock_result.current_label_id == mock_label.id
            assert mock_result.current_label_name == "Secret"

    async def test_clears_label_error_on_success(self, mock_session, mock_result, mock_label):
        mock_result.label_error = "Previous error"
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch("openlabels.jobs.tasks.label.LabelingEngine") as MockEngine, \
             patch("openlabels.jobs.tasks.label.get_settings") as mock_settings:
            settings = MagicMock()
            settings.auth.tenant_id = "t"
            settings.auth.client_id = "c"
            settings.auth.client_secret = "s"
            mock_settings.return_value = settings
            MockEngine.return_value.apply_label = AsyncMock(
                return_value=MagicMock(success=True, method="test", error=None)
            )

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id},
            )

            assert mock_result.label_error is None

    async def test_sets_label_error_on_failure(self, mock_session, mock_result, mock_label):
        mock_session.get = AsyncMock(side_effect=[mock_result, mock_label])

        with patch("openlabels.jobs.tasks.label.LabelingEngine") as MockEngine, \
             patch("openlabels.jobs.tasks.label.get_settings") as mock_settings:
            settings = MagicMock()
            settings.auth.tenant_id = "t"
            settings.auth.client_id = "c"
            settings.auth.client_secret = "s"
            mock_settings.return_value = settings
            MockEngine.return_value.apply_label = AsyncMock(
                return_value=MagicMock(success=False, method="test", error="Labeling failed")
            )

            await execute_label_task(
                mock_session,
                {"result_id": str(mock_result.id), "label_id": mock_label.id},
            )

            assert mock_result.label_error == "Labeling failed"

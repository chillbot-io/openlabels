"""Tests for Azure Sentinel SIEM adapter."""

import base64
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.export.adapters.base import ExportRecord
from openlabels.export.adapters.sentinel import SentinelAdapter


def _make_record(**overrides) -> ExportRecord:
    defaults = dict(
        record_type="scan_result",
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        tenant_id="tenant-1",
        file_path="/data/secret.txt",
        risk_score=85,
        risk_tier="HIGH",
        entity_types=["SSN"],
        entity_counts={"SSN": 3},
        policy_violations=[],
        action_taken=None,
        user="alice@example.com",
        source_adapter="filesystem",
        metadata={},
    )
    defaults.update(overrides)
    return ExportRecord(**defaults)


# Use a valid base64-encoded key for HMAC
_FAKE_KEY = base64.b64encode(b"0" * 64).decode()


class TestSentinelAdapterInit:
    def test_url_construction(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        assert "ws-123" in adapter._url
        assert "opinsights.azure.com" in adapter._url

    def test_format_name(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        assert adapter.format_name() == "sentinel"


class TestBuildSignature:
    def test_produces_shared_key_header(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        sig = adapter._build_signature("Mon, 01 Jan 2025 00:00:00 GMT", 100)
        assert sig.startswith("SharedKey ws-123:")


class TestExportBatch:
    @pytest.mark.asyncio
    async def test_export_success(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        records = [_make_record()]

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("openlabels.export.adapters.sentinel.httpx.AsyncClient", return_value=mock_client):
            sent = await adapter.export_batch(records)

        assert sent == 1

    @pytest.mark.asyncio
    async def test_export_empty(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        sent = await adapter.export_batch([])
        assert sent == 0

    @pytest.mark.asyncio
    async def test_export_http_error(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        records = [_make_record()]

        mock_response = MagicMock()
        mock_response.status_code = 403

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("openlabels.export.adapters.sentinel.httpx.AsyncClient", return_value=mock_client):
            sent = await adapter.export_batch(records)

        assert sent == 0


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_connection_delegates_to_export(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("openlabels.export.adapters.sentinel.httpx.AsyncClient", return_value=mock_client):
            result = await adapter.test_connection()

        assert result is True

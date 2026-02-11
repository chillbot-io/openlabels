"""Tests for Splunk HEC SIEM adapter."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.export.adapters.base import ExportRecord
from openlabels.export.adapters.splunk import SplunkAdapter


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


class TestSplunkAdapterInit:
    def test_strips_trailing_slash(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088/", hec_token="tok")
        assert not adapter._url.endswith("/")

    def test_batch_size_capped(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok", batch_size=9999)
        assert adapter._batch_size <= 500

    def test_format_name(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        assert adapter.format_name() == "splunk"


class TestExportBatch:
    @pytest.mark.asyncio
    async def test_export_success(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        records = [_make_record() for _ in range(3)]

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("openlabels.export.adapters.splunk.httpx.AsyncClient", return_value=mock_client):
            sent = await adapter.export_batch(records)

        assert sent == 3

    @pytest.mark.asyncio
    async def test_export_empty(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        sent = await adapter.export_batch([])
        assert sent == 0

    @pytest.mark.asyncio
    async def test_export_http_error_stops(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok", batch_size=2)
        records = [_make_record() for _ in range(5)]

        mock_response = MagicMock()
        mock_response.status_code = 503

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch("openlabels.export.adapters.splunk.httpx.AsyncClient", return_value=mock_client):
            sent = await adapter.export_batch(records)

        # Should stop after first failed batch
        assert sent == 0


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_connection_success(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("openlabels.export.adapters.splunk.httpx.AsyncClient", return_value=mock_client):
            result = await adapter.test_connection()

        assert result is True

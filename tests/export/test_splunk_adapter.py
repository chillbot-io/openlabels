"""Tests for Splunk HEC SIEM adapter."""

import json
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
        assert adapter._url == "https://splunk:8088"

    def test_batch_size_capped(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok", batch_size=9999)
        assert adapter._batch_size == 500

    def test_batch_size_respected_when_small(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok", batch_size=100)
        assert adapter._batch_size == 100

    def test_format_name(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        assert adapter.format_name() == "splunk"

    def test_default_index_and_sourcetype(self):
        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        assert adapter._index == "main"
        assert adapter._sourcetype == "openlabels"

    def test_custom_index_and_sourcetype(self):
        adapter = SplunkAdapter(
            hec_url="https://splunk:8088", hec_token="tok",
            index="security", sourcetype="custom_type",
        )
        assert adapter._index == "security"
        assert adapter._sourcetype == "custom_type"


class TestFormatEvent:
    def test_event_structure(self):
        adapter = SplunkAdapter(
            hec_url="https://splunk:8088", hec_token="tok",
            index="security", sourcetype="openlabels",
        )
        record = _make_record()
        event_json = adapter._format_event(record)
        event = json.loads(event_json)
        assert event["sourcetype"] == "openlabels"
        assert event["index"] == "security"
        assert event["source"] == "openlabels:scan_result"
        assert event["time"] == datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        assert event["event"]["file_path"] == "/data/secret.txt"
        assert event["event"]["risk_score"] == 85
        assert event["event"]["risk_tier"] == "HIGH"
        assert event["event"]["entity_types"] == ["SSN"]
        assert event["event"]["user"] == "alice@example.com"


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
        # Verify the POST was made to the correct HEC endpoint with correct auth
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "https://splunk:8088/services/collector/event"
        assert call_args[1]["headers"]["Authorization"] == "Splunk tok"
        assert call_args[1]["headers"]["Content-Type"] == "application/json"
        # Verify body is newline-delimited JSON with 3 events
        body = call_args[1]["content"]
        events = [json.loads(line) for line in body.strip().split("\n")]
        assert len(events) == 3
        assert all(e["sourcetype"] == "openlabels" for e in events)

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
        # Verify the health check endpoint was called with correct auth
        call_args = mock_client.get.call_args
        assert call_args[0][0] == "https://splunk:8088/services/collector/health/1.0"
        assert call_args[1]["headers"]["Authorization"] == "Splunk tok"

    @pytest.mark.asyncio
    async def test_connection_failure_on_error(self):
        import httpx

        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with patch("openlabels.export.adapters.splunk.httpx.AsyncClient", return_value=mock_client):
            result = await adapter.test_connection()

        assert result is False

"""Tests for ElasticSearch SIEM adapter."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.export.adapters.base import ExportRecord
from openlabels.export.adapters.elastic import ElasticAdapter


def _make_record(**overrides) -> ExportRecord:
    defaults = dict(
        record_type="scan_result",
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        tenant_id="tenant-1",
        file_path="/data/secret.txt",
        risk_score=85,
        risk_tier="HIGH",
        entity_types=["SSN", "EMAIL"],
        entity_counts={"SSN": 3, "EMAIL": 1},
        policy_violations=[],
        action_taken=None,
        user="alice@example.com",
        source_adapter="filesystem",
        metadata={},
    )
    defaults.update(overrides)
    return ExportRecord(**defaults)


class TestElasticAdapterInit:
    def test_basic_init(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"])
        assert adapter.format_name() == "elastic"

    def test_api_key_auth(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"], api_key="my-key")
        client = adapter._make_client()
        assert client is not None


class TestBuildBulkBody:
    def test_ndjson_format(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"])
        records = [_make_record(), _make_record(risk_tier="CRITICAL")]
        body = adapter._build_bulk_body(records)

        lines = body.strip().split("\n")
        # Each record produces 2 lines: index action + document
        assert len(lines) == 4

    def test_index_name_contains_prefix(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"], index_prefix="myindex")
        record = _make_record()
        idx = adapter._index_name(record)
        assert idx.startswith("myindex-")


class TestExportBatch:
    @pytest.mark.asyncio
    async def test_export_batch_success(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"])
        records = [_make_record() for _ in range(3)]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": [{}] * 3}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch.object(adapter, "_make_client", return_value=mock_client):
            sent = await adapter.export_batch(records)

        assert sent == 3

    @pytest.mark.asyncio
    async def test_export_batch_empty(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"])
        sent = await adapter.export_batch([])
        assert sent == 0

    @pytest.mark.asyncio
    async def test_batch_splitting(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"])
        # Create more records than _MAX_BATCH_SIZE (500)
        records = [_make_record() for _ in range(600)]

        post_call_count = 0

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": [{}] * 500}
        mock_response.raise_for_status = MagicMock()

        async def track_post(*args, **kwargs):
            nonlocal post_call_count
            post_call_count += 1
            # Return correct item count for the batch
            return mock_response

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = track_post

        with patch.object(adapter, "_make_client", return_value=mock_client):
            sent = await adapter.export_batch(records)

        # Should have made 2 POST calls (500 + 100)
        assert post_call_count == 2


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_connection_success(self):
        adapter = ElasticAdapter(hosts=["https://es:9200"])

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(adapter, "_make_client", return_value=mock_client):
            result = await adapter.test_connection()

        assert result is True

    @pytest.mark.asyncio
    async def test_connection_failure(self):
        import httpx

        adapter = ElasticAdapter(hosts=["https://es:9200"])

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with patch.object(adapter, "_make_client", return_value=mock_client):
            result = await adapter.test_connection()

        assert result is False

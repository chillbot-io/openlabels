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
        assert adapter._url == "https://ws-123.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    def test_format_name(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        assert adapter.format_name() == "sentinel"

    def test_custom_log_type(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY, log_type="CustomLog")
        assert adapter._log_type == "CustomLog"


class TestBuildSignature:
    def test_produces_shared_key_header(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        date_str = "Mon, 01 Jan 2025 00:00:00 GMT"
        sig = adapter._build_signature(date_str, 100)
        assert sig.startswith("SharedKey ws-123:")
        # Verify the HMAC value matches an independently computed signature
        import hashlib
        import hmac as hmac_mod
        string_to_sign = f"POST\n100\napplication/json\nx-ms-date:{date_str}\n/api/logs"
        decoded_key = base64.b64decode(_FAKE_KEY)
        expected_hash = base64.b64encode(
            hmac_mod.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")
        assert sig == f"SharedKey ws-123:{expected_hash}"

    def test_signature_changes_with_content_length(self):
        adapter = SentinelAdapter(workspace_id="ws-123", shared_key=_FAKE_KEY)
        date_str = "Mon, 01 Jan 2025 00:00:00 GMT"
        sig_100 = adapter._build_signature(date_str, 100)
        sig_200 = adapter._build_signature(date_str, 200)
        assert sig_100 != sig_200
        # Both still have the same prefix
        assert sig_100.startswith("SharedKey ws-123:")
        assert sig_200.startswith("SharedKey ws-123:")


class TestToSentinelRecord:
    def test_field_mapping(self):
        record = _make_record(
            policy_violations=["PCI-DSS"],
            action_taken="quarantine",
        )
        sentinel_rec = SentinelAdapter._to_sentinel_record(record)
        assert sentinel_rec["RecordType_s"] == "scan_result"
        assert sentinel_rec["TenantId_s"] == "tenant-1"
        assert sentinel_rec["FilePath_s"] == "/data/secret.txt"
        assert sentinel_rec["RiskScore_d"] == 85
        assert sentinel_rec["RiskTier_s"] == "HIGH"
        assert sentinel_rec["EntityTypes_s"] == "SSN"
        assert sentinel_rec["EntityCounts_s"] == '{"SSN": 3}'
        assert sentinel_rec["PolicyViolations_s"] == "PCI-DSS"
        assert sentinel_rec["ActionTaken_s"] == "quarantine"
        assert sentinel_rec["User_s"] == "alice@example.com"
        assert sentinel_rec["SourceAdapter_s"] == "filesystem"
        assert sentinel_rec["TimeGenerated"] == "2025-06-15T12:00:00+00:00"

    def test_null_optional_fields(self):
        record = _make_record(action_taken=None, user=None)
        sentinel_rec = SentinelAdapter._to_sentinel_record(record)
        assert sentinel_rec["ActionTaken_s"] == ""
        assert sentinel_rec["User_s"] == ""


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
        # Verify the POST was made with correct headers
        call_kwargs = mock_client.post.call_args[1]
        assert call_kwargs["headers"]["Content-Type"] == "application/json"
        assert call_kwargs["headers"]["Log-Type"] == "OpenLabels"
        assert call_kwargs["headers"]["Authorization"].startswith("SharedKey ws-123:")
        assert "x-ms-date" in call_kwargs["headers"]

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

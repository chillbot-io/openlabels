"""Tests for SIEM adapter serialization formats (CEF, LEEF, JSON, ECS).

All tests use mocked HTTP/syslog — no real SIEM connections.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from openlabels.export.adapters.base import ExportRecord


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def sample_record() -> ExportRecord:
    return ExportRecord(
        record_type="scan_result",
        timestamp=datetime(2026, 2, 8, 12, 0, 0, tzinfo=timezone.utc),
        tenant_id=UUID("12345678-1234-1234-1234-123456789abc"),
        file_path="/data/reports/q4-financials.xlsx",
        risk_score=85,
        risk_tier="CRITICAL",
        entity_types=["SSN", "CREDIT_CARD"],
        entity_counts={"SSN": 3, "CREDIT_CARD": 1},
        policy_violations=["HIPAA PHI", "PCI-DSS"],
        action_taken="quarantine",
        user="jdoe",
        source_adapter="sharepoint",
    )


@pytest.fixture
def sample_batch(sample_record: ExportRecord) -> list[ExportRecord]:
    records = []
    for i in range(5):
        r = ExportRecord(
            record_type="scan_result",
            timestamp=datetime(2026, 2, 8, 12, i, 0, tzinfo=timezone.utc),
            tenant_id=sample_record.tenant_id,
            file_path=f"/data/file_{i}.txt",
            risk_score=50 + i * 10,
            risk_tier="HIGH",
            entity_types=["EMAIL"],
            entity_counts={"EMAIL": i + 1},
        )
        records.append(r)
    return records


# ── ExportRecord ─────────────────────────────────────────────────────

class TestExportRecord:
    def test_to_dict(self, sample_record: ExportRecord):
        d = sample_record.to_dict()
        assert d["record_type"] == "scan_result"
        assert d["file_path"] == "/data/reports/q4-financials.xlsx"
        assert d["risk_score"] == 85
        assert d["risk_tier"] == "CRITICAL"
        assert d["entity_types"] == ["SSN", "CREDIT_CARD"]
        assert d["policy_violations"] == ["HIPAA PHI", "PCI-DSS"]
        assert d["tenant_id"] == "12345678-1234-1234-1234-123456789abc"
        assert d["user"] == "jdoe"

    def test_to_dict_serializable(self, sample_record: ExportRecord):
        """to_dict() output must be JSON-serializable and round-trip correctly."""
        d = sample_record.to_dict()
        serialized = json.dumps(d)
        deserialized = json.loads(serialized)
        assert deserialized["record_type"] == "scan_result"
        assert deserialized["file_path"] == "/data/reports/q4-financials.xlsx"
        assert deserialized["risk_score"] == 85
        assert deserialized["entity_types"] == ["SSN", "CREDIT_CARD"]
        assert deserialized["tenant_id"] == "12345678-1234-1234-1234-123456789abc"
        assert deserialized["timestamp"] == "2026-02-08T12:00:00+00:00"

    def test_defaults(self):
        r = ExportRecord(
            record_type="test",
            timestamp=datetime.now(tz=timezone.utc),
            tenant_id=uuid4(),
            file_path="/tmp/test.txt",
        )
        assert r.entity_types == []
        assert r.entity_counts == {}
        assert r.policy_violations == []
        assert r.source_adapter == "filesystem"


# ── Splunk Adapter ───────────────────────────────────────────────────

class TestSplunkAdapter:
    def test_format_name(self):
        from openlabels.export.adapters.splunk import SplunkAdapter

        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        assert adapter.format_name() == "splunk"

    def test_format_event(self, sample_record: ExportRecord):
        from openlabels.export.adapters.splunk import SplunkAdapter

        adapter = SplunkAdapter(
            hec_url="https://splunk:8088",
            hec_token="tok",
            index="security",
            sourcetype="openlabels",
        )
        event_json = adapter._format_event(sample_record)
        event = json.loads(event_json)
        assert event["sourcetype"] == "openlabels"
        assert event["index"] == "security"
        assert event["source"] == "openlabels:scan_result"
        assert event["event"]["file_path"] == "/data/reports/q4-financials.xlsx"
        assert event["event"]["risk_score"] == 85
        # 2026-02-08T12:00:00 UTC as Unix epoch
        assert event["time"] == datetime(2026, 2, 8, 12, 0, 0, tzinfo=timezone.utc).timestamp()

    @pytest.mark.asyncio
    async def test_export_batch_success(self, sample_batch: list[ExportRecord]):
        from openlabels.export.adapters.splunk import SplunkAdapter

        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("openlabels.export.adapters.splunk.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            count = await adapter.export_batch(sample_batch)
            assert count == 5

    @pytest.mark.asyncio
    async def test_export_empty_batch(self):
        from openlabels.export.adapters.splunk import SplunkAdapter

        adapter = SplunkAdapter(hec_url="https://splunk:8088", hec_token="tok")
        count = await adapter.export_batch([])
        assert count == 0


# ── Sentinel Adapter ─────────────────────────────────────────────────

class TestSentinelAdapter:
    def test_format_name(self):
        from openlabels.export.adapters.sentinel import SentinelAdapter

        adapter = SentinelAdapter(workspace_id="ws123", shared_key="a2V5")
        assert adapter.format_name() == "sentinel"

    def test_to_sentinel_record(self, sample_record: ExportRecord):
        from openlabels.export.adapters.sentinel import SentinelAdapter

        rec = SentinelAdapter._to_sentinel_record(sample_record)
        assert rec["RecordType_s"] == "scan_result"
        assert rec["FilePath_s"] == "/data/reports/q4-financials.xlsx"
        assert rec["RiskScore_d"] == 85
        assert rec["RiskTier_s"] == "CRITICAL"
        assert "SSN" in rec["EntityTypes_s"]
        assert "HIPAA PHI" in rec["PolicyViolations_s"]
        assert rec["User_s"] == "jdoe"

    def test_build_signature(self):
        from openlabels.export.adapters.sentinel import SentinelAdapter
        import base64
        import hashlib
        import hmac

        # Use a known key
        raw_key = b"test-key-1234567890123456"
        key = base64.b64encode(raw_key).decode()
        adapter = SentinelAdapter(workspace_id="ws-test", shared_key=key)
        date_str = "Mon, 08 Feb 2026 12:00:00 GMT"
        sig = adapter._build_signature(date_str, 100)
        assert sig.startswith("SharedKey ws-test:")

        # Verify the HMAC value matches what we compute independently
        string_to_sign = f"POST\n100\napplication/json\nx-ms-date:{date_str}\n/api/logs"
        expected_hash = base64.b64encode(
            hmac.new(raw_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")
        assert sig == f"SharedKey ws-test:{expected_hash}"


# ── QRadar Adapter ───────────────────────────────────────────────────

class TestQRadarAdapter:
    def test_format_name(self):
        from openlabels.export.adapters.qradar import QRadarAdapter

        adapter = QRadarAdapter(syslog_host="qradar.local")
        assert adapter.format_name() == "qradar"

    def test_to_leef(self, sample_record: ExportRecord):
        from openlabels.export.adapters.qradar import QRadarAdapter

        adapter = QRadarAdapter(syslog_host="qradar.local", fmt="leef")
        msg = adapter._to_leef(sample_record)
        assert msg.startswith("LEEF:2.0|OpenLabels|OpenLabels|2.0|scanresult|")
        assert "filePath=/data/reports/q4-financials.xlsx" in msg
        assert "riskScore=85" in msg
        assert "riskTier=CRITICAL" in msg

    def test_to_cef(self, sample_record: ExportRecord):
        from openlabels.export.adapters.qradar import QRadarAdapter

        adapter = QRadarAdapter(syslog_host="qradar.local", fmt="cef")
        msg = adapter._to_cef(sample_record)
        assert msg.startswith("CEF:0|OpenLabels|OpenLabels|2.0|scanresult|")
        assert "|10|" in msg  # CRITICAL severity
        assert "filePath=/data/reports/q4-financials.xlsx" in msg

    def test_cef_escape(self):
        from openlabels.export.adapters.base import cef_escape

        assert cef_escape("a=b|c\\d") == "a\\=b\\|c\\\\d"


# ── Elastic Adapter ──────────────────────────────────────────────────

class TestElasticAdapter:
    def test_format_name(self):
        from openlabels.export.adapters.elastic import ElasticAdapter

        adapter = ElasticAdapter(hosts=["https://es:9200"])
        assert adapter.format_name() == "elastic"

    def test_to_ecs(self, sample_record: ExportRecord):
        from openlabels.export.adapters.elastic import ElasticAdapter

        doc = ElasticAdapter._to_ecs(sample_record)
        assert doc["@timestamp"] == "2026-02-08T12:00:00+00:00"
        assert doc["event"]["risk_score"] == 85
        assert doc["event"]["severity_name"] == "CRITICAL"
        assert doc["event"]["kind"] == "alert"  # has policy_violations
        assert doc["file"]["path"] == "/data/reports/q4-financials.xlsx"
        assert doc["user"]["name"] == "jdoe"
        assert doc["rule"]["name"] == ["HIPAA PHI", "PCI-DSS"]

    def test_to_ecs_no_violations(self):
        from openlabels.export.adapters.elastic import ElasticAdapter

        r = ExportRecord(
            record_type="scan_result",
            timestamp=datetime(2026, 2, 8, tzinfo=timezone.utc),
            tenant_id=uuid4(),
            file_path="/tmp/test.txt",
        )
        doc = ElasticAdapter._to_ecs(r)
        assert doc["event"]["kind"] == "event"  # no violations

    def test_index_name(self, sample_record: ExportRecord):
        from openlabels.export.adapters.elastic import ElasticAdapter

        adapter = ElasticAdapter(hosts=["https://es:9200"], index_prefix="ol")
        name = adapter._index_name(sample_record)
        assert name == "ol-scan_result-2026.02.08"

    def test_build_bulk_body(self, sample_batch: list[ExportRecord]):
        from openlabels.export.adapters.elastic import ElasticAdapter

        adapter = ElasticAdapter(hosts=["https://es:9200"])
        body = adapter._build_bulk_body(sample_batch)
        lines = body.strip().split("\n")
        # 5 records × 2 lines each (action + document)
        assert len(lines) == 10


# ── Syslog CEF Adapter ──────────────────────────────────────────────

class TestSyslogCEFAdapter:
    def test_format_name(self):
        from openlabels.export.adapters.syslog_cef import SyslogCEFAdapter

        adapter = SyslogCEFAdapter(host="syslog.local")
        assert adapter.format_name() == "syslog_cef"

    def test_to_cef(self, sample_record: ExportRecord):
        from openlabels.export.adapters.syslog_cef import SyslogCEFAdapter

        adapter = SyslogCEFAdapter(host="syslog.local")
        msg = adapter._to_cef(sample_record)
        assert msg.startswith("CEF:0|OpenLabels|Scanner|2.0|scanresult|")
        assert "|10|" in msg
        assert "filePath=/data/reports/q4-financials.xlsx" in msg
        assert "riskScore=85" in msg

    @pytest.mark.asyncio
    async def test_export_empty(self):
        from openlabels.export.adapters.syslog_cef import SyslogCEFAdapter

        adapter = SyslogCEFAdapter(host="syslog.local")
        assert await adapter.export_batch([]) == 0

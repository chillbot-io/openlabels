"""Tests for QRadar and SyslogCEF SIEM adapters."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.export.adapters.base import ExportRecord
from openlabels.export.adapters.qradar import QRadarAdapter
from openlabels.export.adapters.syslog_cef import SyslogCEFAdapter


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


# ---------------------------------------------------------------------------
# QRadar
# ---------------------------------------------------------------------------


class TestQRadarInit:
    def test_default_port(self):
        adapter = QRadarAdapter(syslog_host="qradar.local")
        assert adapter._port == 514

    def test_format_name(self):
        adapter = QRadarAdapter(syslog_host="qradar.local")
        assert adapter.format_name() == "qradar"


class TestQRadarFormatting:
    def test_leef_format(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", fmt="leef")
        record = _make_record()
        leef = adapter._to_leef(record)
        assert leef.startswith("LEEF:2.0|OpenLabels|OpenLabels|2.0|scanresult|")
        assert "filePath=/data/secret.txt" in leef
        assert "riskScore=85" in leef
        assert "riskTier=HIGH" in leef
        assert "entityTypes=SSN" in leef
        assert "userName=alice@example.com" in leef
        assert "sourceAdapter=filesystem" in leef

    def test_cef_format(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", fmt="cef")
        record = _make_record()
        cef = adapter._to_cef(record)
        assert cef.startswith("CEF:0|OpenLabels|OpenLabels|2.0|scanresult|")
        assert "|7|" in cef  # HIGH severity maps to 7
        assert "filePath=/data/secret.txt" in cef
        assert "riskScore=85" in cef
        assert "riskTier=HIGH" in cef
        assert "suser=alice@example.com" in cef

    def test_cef_severity_mapping(self):
        for tier, expected_sev in [("CRITICAL", 10), ("HIGH", 7), ("MEDIUM", 5), ("LOW", 3), ("MINIMAL", 1)]:
            record = _make_record(risk_tier=tier)
            adapter = QRadarAdapter(syslog_host="qradar.local", fmt="cef")
            cef = adapter._to_cef(record)
            assert f"|{expected_sev}|" in cef, f"Expected severity {expected_sev} for tier {tier}"

    def test_cef_escape_special_chars(self):
        assert QRadarAdapter._cef_escape("a=b|c\\d") == "a\\=b\\|c\\\\d"


class TestQRadarExportBatch:
    @pytest.mark.asyncio
    async def test_export_tcp(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", protocol="tcp", fmt="leef")
        records = [_make_record()]

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch.object(adapter, "_open_tcp_connection",
                          return_value=(AsyncMock(), mock_writer)):
            sent = await adapter.export_batch(records)

        assert sent == 1
        # Verify writer.write was called with a LEEF-formatted syslog message
        mock_writer.write.assert_called_once()
        written = mock_writer.write.call_args[0][0].decode("utf-8")
        assert written.startswith("<14>LEEF:2.0|OpenLabels|")
        assert written.endswith("\n")
        assert "filePath=/data/secret.txt" in written

    @pytest.mark.asyncio
    async def test_export_tcp_cef_format(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", protocol="tcp", fmt="cef")
        records = [_make_record()]

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch.object(adapter, "_open_tcp_connection",
                          return_value=(AsyncMock(), mock_writer)):
            sent = await adapter.export_batch(records)

        assert sent == 1
        written = mock_writer.write.call_args[0][0].decode("utf-8")
        assert written.startswith("<14>CEF:0|OpenLabels|")

    @pytest.mark.asyncio
    async def test_export_udp(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", protocol="udp")
        records = [_make_record()]

        mock_sock = MagicMock()
        mock_sock.sendto = MagicMock(return_value=100)
        mock_sock.close = MagicMock()

        with patch("socket.socket", return_value=mock_sock), \
             patch("asyncio.get_running_loop") as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=100)
            sent = await adapter.export_batch(records)

        assert sent == 1

    @pytest.mark.asyncio
    async def test_export_empty(self):
        adapter = QRadarAdapter(syslog_host="qradar.local")
        sent = await adapter.export_batch([])
        assert sent == 0


class TestQRadarTestConnection:
    @pytest.mark.asyncio
    async def test_tcp_connection_success(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", protocol="tcp")

        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(AsyncMock(), mock_writer)):
            result = await adapter.test_connection()

        assert result is True

    @pytest.mark.asyncio
    async def test_tcp_connection_failure(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", protocol="tcp")

        with patch("asyncio.open_connection", side_effect=OSError("refused")):
            result = await adapter.test_connection()

        assert result is False


# ---------------------------------------------------------------------------
# SyslogCEF
# ---------------------------------------------------------------------------


class TestSyslogCEFInit:
    def test_default_port(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        assert adapter._port == 514

    def test_custom_port(self):
        adapter = SyslogCEFAdapter(host="syslog.local", port=1514)
        assert adapter._port == 1514

    def test_format_name(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        assert adapter.format_name() == "syslog_cef"

    def test_default_protocol(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        assert adapter._protocol == "tcp"


class TestSyslogCEFFormatting:
    def test_cef_format_content(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        record = _make_record()
        cef = adapter._to_cef(record)
        # SyslogCEF uses "Scanner" as product (vs QRadar which uses "OpenLabels")
        assert cef.startswith("CEF:0|OpenLabels|Scanner|2.0|scanresult|")
        assert "|7|" in cef  # HIGH severity maps to 7
        assert "filePath=/data/secret.txt" in cef
        assert "riskScore=85" in cef
        assert "riskTier=HIGH" in cef
        assert "suser=alice@example.com" in cef
        assert "src=filesystem" in cef

    def test_cef_with_policy_violations(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        record = _make_record(policy_violations=["HIPAA PHI", "PCI-DSS"])
        cef = adapter._to_cef(record)
        assert "policyViolations=HIPAA PHI,PCI-DSS" in cef


class TestSyslogCEFExportBatch:
    @pytest.mark.asyncio
    async def test_export_tcp(self):
        adapter = SyslogCEFAdapter(host="syslog.local", protocol="tcp")
        records = [_make_record(), _make_record()]

        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch.object(adapter, "_open_tcp_connection",
                          return_value=(AsyncMock(), mock_writer)):
            sent = await adapter.export_batch(records)

        assert sent == 2
        # Verify writer.write was called with CEF-formatted syslog messages
        assert mock_writer.write.call_count == 2
        first_msg = mock_writer.write.call_args_list[0][0][0].decode("utf-8")
        assert first_msg.startswith("<14>CEF:0|OpenLabels|Scanner|")
        assert first_msg.endswith("\n")

    @pytest.mark.asyncio
    async def test_export_empty(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        sent = await adapter.export_batch([])
        assert sent == 0

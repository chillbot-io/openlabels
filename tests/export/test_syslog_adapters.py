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
        assert "LEEF:" in leef
        assert "OpenLabels" in leef

    def test_cef_format(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", fmt="cef")
        record = _make_record()
        cef = adapter._to_cef(record)
        assert "CEF:" in cef
        assert "OpenLabels" in cef


class TestQRadarExportBatch:
    @pytest.mark.asyncio
    async def test_export_tcp(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", protocol="tcp")
        records = [_make_record()]

        mock_writer = AsyncMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch.object(adapter, "_open_tcp_connection",
                          return_value=(AsyncMock(), mock_writer)):
            sent = await adapter.export_batch(records)

        assert sent == 1

    @pytest.mark.asyncio
    async def test_export_udp(self):
        adapter = QRadarAdapter(syslog_host="qradar.local", protocol="udp")
        records = [_make_record()]

        mock_sock = MagicMock()
        mock_sock.sendto = MagicMock(return_value=100)
        mock_sock.close = MagicMock()

        with patch("socket.socket", return_value=mock_sock), \
             patch("asyncio.get_event_loop") as mock_loop:
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

        mock_writer = AsyncMock()
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

    def test_format_name(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        name = adapter.format_name()
        assert name in ("syslog_cef", "syslog-cef", "cef")


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

    @pytest.mark.asyncio
    async def test_export_empty(self):
        adapter = SyslogCEFAdapter(host="syslog.local")
        sent = await adapter.export_batch([])
        assert sent == 0

"""IBM QRadar adapter — syslog transport with LEEF/CEF encoding.

Exports OpenLabels findings to IBM QRadar via syslog using LEEF (preferred)
or CEF format.  QRadar auto-parses structured fields into event properties.

Transport: Syslog over TCP/UDP/TLS (RFC 5424)
Format: LEEF:2.0|OpenLabels|Scanner|2.0|{EventID}|...
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket

from openlabels.export.adapters.base import (
    ExportRecord,
    SyslogTransportMixin,
    cef_escape,
    format_cef,
)

logger = logging.getLogger(__name__)

_PRODUCT = "OpenLabels"
_PRODUCT_VERSION = "2.0"
_VENDOR = "OpenLabels"
_LEEF_VERSION = "2.0"


class QRadarAdapter(SyslogTransportMixin):
    """Export to IBM QRadar via syslog using LEEF or CEF format."""

    def __init__(
        self,
        syslog_host: str,
        syslog_port: int = 514,
        *,
        protocol: str = "tcp",
        use_tls: bool = False,
        fmt: str = "leef",
    ) -> None:
        self._host = syslog_host
        self._port = syslog_port
        self._protocol = protocol.lower()
        self._use_tls = use_tls
        self._fmt = fmt.lower()  # "leef" or "cef"


    async def export_batch(self, records: list[ExportRecord]) -> int:
        if not records:
            return 0

        messages = []
        for r in records:
            msg = self._to_leef(r) if self._fmt == "leef" else self._to_cef(r)
            messages.append(msg)

        return await self._send_syslog(messages)

    async def test_connection(self) -> bool:
        try:
            if self._protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(5)
                    sock.sendto(b"<14>OpenLabels connection test\n", (self._host, self._port))
            else:
                reader, writer = await asyncio.wait_for(
                    self._open_tcp_connection(), timeout=10,
                )
                writer.write(b"<14>OpenLabels connection test\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError) as exc:
            logger.warning("QRadar connection test failed: %s", exc)
            return False

    def format_name(self) -> str:
        return "qradar"


    def _to_leef(self, record: ExportRecord) -> str:
        """Convert ExportRecord to LEEF 2.0 syslog message."""
        event_id = record.record_type.replace("_", "")
        kv_sep = "\t"
        fields = {
            "devTime": record.timestamp.strftime("%b %d %Y %H:%M:%S"),
            "filePath": record.file_path,
            "riskScore": str(record.risk_score or 0),
            "riskTier": record.risk_tier or "",
            "entityTypes": ",".join(record.entity_types),
            "entityCounts": json.dumps(record.entity_counts),
            "policyViolations": ",".join(record.policy_violations),
            "actionTaken": record.action_taken or "",
            "userName": record.user or "",
            "sourceAdapter": record.source_adapter,
            "tenantId": str(record.tenant_id),
        }
        # Escape tab and equals in LEEF field values to prevent parsing issues
        def _leef_esc(val: str) -> str:
            return val.replace("\\", "\\\\").replace("\t", "\\t").replace("=", "\\=")
        extensions = kv_sep.join(f"{k}={_leef_esc(str(v))}" for k, v in fields.items())
        header = (
            f"LEEF:{_LEEF_VERSION}|{_VENDOR}|{_PRODUCT}|"
            f"{_PRODUCT_VERSION}|{event_id}|"
        )
        return header + extensions

    def _to_cef(self, record: ExportRecord) -> str:
        """Convert ExportRecord to CEF format string."""
        return format_cef(record, _VENDOR, _PRODUCT, _PRODUCT_VERSION)

"""Generic syslog adapter — CEF (Common Event Format).

CEF is supported by most SIEMs and log management platforms.  Use this
adapter as a fallback when no native adapter exists for the target SIEM.

Transport: UDP, TCP, or TLS syslog (RFC 5424)
Format: CEF:0|OpenLabels|Scanner|2.0|{event_id}|{name}|{severity}|{extensions}
"""

from __future__ import annotations

import asyncio
import logging
import socket

from openlabels.export.adapters.base import (
    ExportRecord,
    SyslogTransportMixin,
    format_cef,
)

logger = logging.getLogger(__name__)

_VENDOR = "OpenLabels"
_PRODUCT = "Scanner"
_PRODUCT_VERSION = "2.0"


class SyslogCEFAdapter(SyslogTransportMixin):
    """Generic syslog export using CEF (Common Event Format)."""

    def __init__(
        self,
        host: str,
        port: int = 514,
        *,
        protocol: str = "tcp",
        use_tls: bool = False,
    ) -> None:
        self._host = host
        self._port = port
        self._protocol = protocol.lower()
        self._use_tls = use_tls

    # ── SIEMAdapter protocol ─────────────────────────────────────────

    async def export_batch(self, records: list[ExportRecord]) -> int:
        if not records:
            return 0

        messages = [self._to_cef(r) for r in records]
        return await self._send_syslog(messages)

    async def test_connection(self) -> bool:
        try:
            if self._protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(5)
                    sock.sendto(
                        b"<14>CEF:0|OpenLabels|Scanner|2.0|test|Connection Test|1|\n",
                        (self._host, self._port),
                    )
            else:
                reader, writer = await asyncio.wait_for(
                    self._open_tcp_connection(), timeout=10,
                )
                writer.write(
                    b"<14>CEF:0|OpenLabels|Scanner|2.0|test|Connection Test|1|\n"
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError) as exc:
            logger.warning("Syslog CEF connection test failed: %s", exc)
            return False

    def format_name(self) -> str:
        return "syslog_cef"

    # ── CEF formatter ────────────────────────────────────────────────

    def _to_cef(self, record: ExportRecord) -> str:
        return format_cef(
            record, _VENDOR, _PRODUCT, _PRODUCT_VERSION, include_source=True
        )

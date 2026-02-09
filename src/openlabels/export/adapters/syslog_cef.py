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
import ssl

from openlabels.export.adapters.base import ExportRecord

logger = logging.getLogger(__name__)

_VENDOR = "OpenLabels"
_PRODUCT = "Scanner"
_PRODUCT_VERSION = "2.0"


class SyslogCEFAdapter:
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
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                sock.sendto(
                    b"<14>CEF:0|OpenLabels|Scanner|2.0|test|Connection Test|1|\n",
                    (self._host, self._port),
                )
                sock.close()
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
        severity = _risk_tier_to_cef_severity(record.risk_tier)
        event_id = record.record_type.replace("_", "")
        name = f"OpenLabels {record.record_type}"
        extensions = (
            f"filePath={_cef_escape(record.file_path)} "
            f"riskScore={record.risk_score or 0} "
            f"riskTier={record.risk_tier or 'MINIMAL'} "
            f"entityTypes={','.join(record.entity_types)} "
            f"policyViolations={','.join(record.policy_violations)} "
            f"suser={_cef_escape(record.user or '')} "
            f"act={_cef_escape(record.action_taken or '')} "
            f"rt={record.timestamp.strftime('%b %d %Y %H:%M:%S')} "
            f"src={_cef_escape(record.source_adapter)}"
        )
        return (
            f"CEF:0|{_VENDOR}|{_PRODUCT}|{_PRODUCT_VERSION}|"
            f"{event_id}|{name}|{severity}|{extensions}"
        )

    # ── transport ────────────────────────────────────────────────────

    async def _send_syslog(self, messages: list[str]) -> int:
        sent = 0
        try:
            if self._protocol == "udp":
                sent = await self._send_udp(messages)
            else:
                sent = await self._send_tcp(messages)
        except (OSError, asyncio.TimeoutError) as exc:
            logger.error("Syslog CEF send failed: %s", exc)
        return sent

    async def _send_udp(self, messages: list[str]) -> int:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for msg in messages:
                payload = f"<14>{msg}\n"
                await loop.run_in_executor(
                    None, sock.sendto, payload.encode("utf-8"),
                    (self._host, self._port),
                )
        finally:
            sock.close()
        return len(messages)

    async def _send_tcp(self, messages: list[str]) -> int:
        reader, writer = await asyncio.wait_for(
            self._open_tcp_connection(), timeout=30,
        )
        try:
            for msg in messages:
                payload = f"<14>{msg}\n"
                writer.write(payload.encode("utf-8"))
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
        return len(messages)

    async def _open_tcp_connection(self):
        if self._use_tls:
            ctx = ssl.create_default_context()
            return await asyncio.open_connection(
                self._host, self._port, ssl=ctx,
            )
        return await asyncio.open_connection(self._host, self._port)


# ── shared helpers ───────────────────────────────────────────────────

def _risk_tier_to_cef_severity(tier: str | None) -> int:
    return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "MINIMAL": 1}.get(
        (tier or "").upper(), 1
    )


def _cef_escape(value: str) -> str:
    """Escape CEF special characters: backslash, equals, pipe."""
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")

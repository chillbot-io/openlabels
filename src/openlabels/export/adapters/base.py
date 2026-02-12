"""Base protocol and data types for SIEM export adapters."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

logger = logging.getLogger(__name__)


@dataclass
class ExportRecord:
    """Normalized record for SIEM export.

    Each record represents a single finding (scan result, access event,
    policy violation, or audit log entry) in a SIEM-agnostic format.
    Adapters convert these into their platform-native schema.
    """

    record_type: str  # scan_result, access_event, policy_violation, audit_log
    timestamp: datetime
    tenant_id: UUID
    file_path: str
    risk_score: int | None = None
    risk_tier: str | None = None
    entity_types: list[str] = field(default_factory=list)
    entity_counts: dict[str, int] = field(default_factory=dict)
    policy_violations: list[str] = field(default_factory=list)
    action_taken: str | None = None
    user: str | None = None
    source_adapter: str = "filesystem"
    metadata: dict = field(default_factory=dict)

    _STANDARD_KEYS = frozenset({
        "record_type", "timestamp", "tenant_id", "file_path", "risk_score",
        "risk_tier", "entity_types", "entity_counts", "policy_violations",
        "action_taken", "user", "source_adapter",
    })

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON-based adapters."""
        base = {
            "record_type": self.record_type,
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": str(self.tenant_id),
            "file_path": self.file_path,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier,
            "entity_types": self.entity_types,
            "entity_counts": self.entity_counts,
            "policy_violations": self.policy_violations,
            "action_taken": self.action_taken,
            "user": self.user,
            "source_adapter": self.source_adapter,
        }
        # Only merge metadata keys that don't collide with standard fields
        for k, v in self.metadata.items():
            if k not in self._STANDARD_KEYS:
                base[k] = v
        return base


@runtime_checkable
class SIEMAdapter(Protocol):
    """Protocol for SIEM-specific export adapters."""

    async def export_batch(self, records: list[ExportRecord]) -> int:
        """Export a batch of records to the SIEM.

        Returns number of records successfully ingested.
        """
        ...

    async def test_connection(self) -> bool:
        """Verify connectivity to the SIEM endpoint."""
        ...

    def format_name(self) -> str:
        """Return adapter name: 'splunk', 'sentinel', 'qradar', etc."""
        ...


# ---------------------------------------------------------------------------
# Shared syslog transport mixin
# ---------------------------------------------------------------------------


def risk_tier_to_cef_severity(tier: str | None) -> int:
    """Map risk tier to CEF numeric severity."""
    return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "MINIMAL": 1}.get(
        (tier or "").upper(), 1
    )


def cef_escape(value: str) -> str:
    """Escape CEF special characters: backslash, equals, pipe."""
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")


class SyslogTransportMixin:
    """Shared syslog transport (UDP/TCP/TLS) for CEF and LEEF adapters.

    Subclasses must set ``_host``, ``_port``, ``_protocol``, and
    ``_use_tls`` attributes before calling these methods.
    """

    _host: str
    _port: int
    _protocol: str
    _use_tls: bool

    async def _send_syslog(
        self, messages: list[str], *, max_retries: int = 3,
    ) -> int:
        """Send syslog messages over the configured transport with retry."""
        for attempt in range(max_retries + 1):
            try:
                if self._protocol == "udp":
                    return await self._send_udp(messages)
                else:
                    return await self._send_tcp(messages)
            except (OSError, asyncio.TimeoutError) as exc:
                if attempt < max_retries:
                    wait = 2 ** attempt
                    logger.warning(
                        "%s syslog send attempt %d/%d failed, retrying in %ds: %s",
                        type(self).__name__, attempt + 1, max_retries + 1,
                        wait, exc,
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        "%s syslog send failed after %d attempts: %s",
                        type(self).__name__, max_retries + 1, exc,
                    )
        return 0

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

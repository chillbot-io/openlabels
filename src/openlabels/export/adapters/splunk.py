"""Splunk adapter — HTTP Event Collector (HEC).

Exports OpenLabels findings to Splunk via the HTTP Event Collector API.
Each :class:`ExportRecord` becomes a Splunk event with sourcetype ``openlabels``.

HEC endpoint: ``https://{host}:8088/services/collector/event``
Authentication: Bearer token (HEC token)
Format: Newline-delimited JSON events
"""

from __future__ import annotations

import json
import logging
from datetime import timezone

import httpx

from openlabels.export.adapters.base import ExportRecord

logger = logging.getLogger(__name__)

# HEC recommends batches of ~1 MB; we cap at 500 events per request.
_MAX_BATCH_SIZE = 500


class SplunkAdapter:
    """Export to Splunk via HTTP Event Collector (HEC)."""

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        *,
        index: str = "main",
        sourcetype: str = "openlabels",
        verify_ssl: bool = True,
        batch_size: int = _MAX_BATCH_SIZE,
    ) -> None:
        self._url = hec_url.rstrip("/")
        self._token = hec_token
        self._index = index
        self._sourcetype = sourcetype
        self._verify_ssl = verify_ssl
        self._batch_size = min(batch_size, _MAX_BATCH_SIZE)

    # ── SIEMAdapter protocol ─────────────────────────────────────────

    async def export_batch(self, records: list[ExportRecord]) -> int:
        """POST newline-delimited JSON events to HEC."""
        if not records:
            return 0

        total_sent = 0
        for offset in range(0, len(records), self._batch_size):
            chunk = records[offset : offset + self._batch_size]
            payload = "\n".join(self._format_event(r) for r in chunk)

            async with httpx.AsyncClient(verify=self._verify_ssl) as client:
                resp = await client.post(
                    f"{self._url}/services/collector/event",
                    content=payload,
                    headers={
                        "Authorization": f"Splunk {self._token}",
                        "Content-Type": "application/json",
                    },
                    timeout=30.0,
                )

            if resp.status_code == 200:
                total_sent += len(chunk)
            else:
                logger.error(
                    "Splunk HEC returned %d: %s", resp.status_code, resp.text[:200],
                )
                break

        return total_sent

    async def test_connection(self) -> bool:
        """Send a health-check request to the HEC endpoint."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl) as client:
                resp = await client.get(
                    f"{self._url}/services/collector/health/1.0",
                    headers={"Authorization": f"Splunk {self._token}"},
                    timeout=10.0,
                )
            return resp.status_code == 200
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("Splunk connection test failed: %s", exc)
            return False

    def format_name(self) -> str:
        return "splunk"

    # ── internals ────────────────────────────────────────────────────

    def _format_event(self, record: ExportRecord) -> str:
        """Convert an ExportRecord to a Splunk HEC JSON event."""
        epoch = record.timestamp.replace(tzinfo=timezone.utc).timestamp()
        event = {
            "event": record.to_dict(),
            "time": epoch,
            "sourcetype": self._sourcetype,
            "source": f"openlabels:{record.record_type}",
            "index": self._index,
        }
        return json.dumps(event, default=str)

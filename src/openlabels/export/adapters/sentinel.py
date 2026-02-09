"""Microsoft Sentinel adapter — Log Analytics Data Collector API.

Exports OpenLabels findings to Microsoft Sentinel via the Azure Log Analytics
Data Collector API.  Records appear as custom log table ``OpenLabels_CL``.

Endpoint: ``https://{workspace_id}.ods.opinsights.azure.com/api/logs``
Authentication: HMAC-SHA256 shared key
Format: JSON array
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import httpx

from openlabels.export.adapters.base import ExportRecord

logger = logging.getLogger(__name__)

_API_VERSION = "2016-04-01"
_MAX_PAYLOAD_MB = 30  # Azure limit per request


class SentinelAdapter:
    """Export to Microsoft Sentinel via Log Analytics Data Collector API."""

    def __init__(
        self,
        workspace_id: str,
        shared_key: str,
        *,
        log_type: str = "OpenLabels",
    ) -> None:
        self._workspace_id = workspace_id
        self._shared_key = shared_key
        self._log_type = log_type
        self._url = (
            f"https://{workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version={_API_VERSION}"
        )

    # ── SIEMAdapter protocol ─────────────────────────────────────────

    async def export_batch(self, records: list[ExportRecord]) -> int:
        if not records:
            return 0

        body = json.dumps(
            [self._to_sentinel_record(r) for r in records],
            default=str,
        )
        rfc1123_date = datetime.now(tz=timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        signature = self._build_signature(rfc1123_date, len(body))

        headers = {
            "Content-Type": "application/json",
            "Log-Type": self._log_type,
            "Authorization": signature,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "TimeGenerated",
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._url, content=body, headers=headers, timeout=30.0,
            )

        if resp.status_code in (200, 202):
            return len(records)

        logger.error(
            "Sentinel returned %d: %s", resp.status_code, resp.text[:200],
        )
        return 0

    async def test_connection(self) -> bool:
        """Send a minimal payload to verify auth."""
        try:
            test_record = ExportRecord(
                record_type="test",
                timestamp=datetime.now(tz=timezone.utc),
                tenant_id=__import__("uuid").UUID(int=0),
                file_path="__connection_test__",
            )
            count = await self.export_batch([test_record])
            return count == 1
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("Sentinel connection test failed: %s", exc)
            return False

    def format_name(self) -> str:
        return "sentinel"

    # ── internals ────────────────────────────────────────────────────

    def _build_signature(self, date: str, content_length: int) -> str:
        """Build the HMAC-SHA256 Authorization header value.

        Signature format per Microsoft docs:
        ``POST\\n{content_length}\\napplication/json\\nx-ms-date:{date}\\n/api/logs``
        """
        string_to_sign = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        decoded_key = base64.b64decode(self._shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self._workspace_id}:{encoded_hash}"

    @staticmethod
    def _to_sentinel_record(record: ExportRecord) -> dict:
        """Map ExportRecord fields to Sentinel custom log columns.

        Sentinel auto-suffixes: ``_s`` (string), ``_d`` (double),
        ``_t`` (datetime), ``_b`` (bool).
        """
        return {
            "TimeGenerated": record.timestamp.isoformat(),
            "RecordType_s": record.record_type,
            "TenantId_s": str(record.tenant_id),
            "FilePath_s": record.file_path,
            "RiskScore_d": record.risk_score,
            "RiskTier_s": record.risk_tier,
            "EntityTypes_s": ",".join(record.entity_types),
            "EntityCounts_s": json.dumps(record.entity_counts),
            "PolicyViolations_s": ",".join(record.policy_violations),
            "ActionTaken_s": record.action_taken or "",
            "User_s": record.user or "",
            "SourceAdapter_s": record.source_adapter,
        }

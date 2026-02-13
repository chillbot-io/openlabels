"""Elasticsearch adapter — Bulk API with ECS field mapping.

Exports OpenLabels findings to Elasticsearch / Elastic SIEM via the Bulk API.
Records are indexed as ECS-compatible documents in date-based indices.

Endpoint: ``https://{host}:9200/_bulk``
Authentication: API key or basic auth
Format: NDJSON (action + document pairs)
Index pattern: ``openlabels-{record_type}-YYYY.MM.DD``
"""

from __future__ import annotations

import json
import logging

import httpx

from openlabels.export.adapters.base import ExportRecord

logger = logging.getLogger(__name__)

_MAX_BATCH_SIZE = 500


class ElasticAdapter:
    """Export to Elasticsearch / Elastic SIEM via Bulk API."""

    def __init__(
        self,
        hosts: list[str],
        *,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        index_prefix: str = "openlabels",
        verify_ssl: bool = True,
    ) -> None:
        self._hosts = hosts
        self._api_key = api_key
        self._username = username
        self._password = password
        self._index_prefix = index_prefix
        self._verify_ssl = verify_ssl


    async def export_batch(self, records: list[ExportRecord]) -> int:
        if not records:
            return 0

        total_sent = 0
        for offset in range(0, len(records), _MAX_BATCH_SIZE):
            chunk = records[offset : offset + _MAX_BATCH_SIZE]
            body = self._build_bulk_body(chunk)
            result = await self._post_bulk(body)
            if result >= 0:
                total_sent += result
            else:
                break
        return total_sent

    async def test_connection(self) -> bool:
        try:
            async with self._make_client() as client:
                resp = await client.get(
                    f"{self._hosts[0]}/", timeout=10.0,
                )
            return resp.status_code == 200
        except (httpx.HTTPError, OSError, IndexError) as exc:
            logger.warning("Elastic connection test failed: %s", exc)
            return False

    def format_name(self) -> str:
        return "elastic"


    def _build_bulk_body(self, records: list[ExportRecord]) -> str:
        """Build NDJSON body for the _bulk API."""
        lines: list[str] = []
        for r in records:
            index_name = self._index_name(r)
            action = json.dumps({"index": {"_index": index_name}})
            document = json.dumps(self._to_ecs(r), default=str)
            lines.append(action)
            lines.append(document)
        return "\n".join(lines) + "\n"

    async def _post_bulk(self, body: str) -> int:
        """POST bulk body; returns count of successful items or -1 on error."""
        async with self._make_client() as client:
            resp = await client.post(
                f"{self._hosts[0]}/_bulk",
                content=body,
                headers={"Content-Type": "application/x-ndjson"},
                timeout=30.0,
            )

        if resp.status_code not in (200, 201):
            logger.error(
                "Elastic Bulk API returned %d: %s",
                resp.status_code, resp.text[:200],
            )
            return -1

        result = resp.json()
        if result.get("errors"):
            failed = sum(
                1 for item in result.get("items", [])
                if item.get("index", {}).get("error")
            )
            succeeded = len(result.get("items", [])) - failed
            logger.warning(
                "Elastic Bulk API: %d succeeded, %d failed", succeeded, failed,
            )
            return succeeded

        return len(result.get("items", []))

    def _make_client(self) -> httpx.AsyncClient:
        auth = None
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"ApiKey {self._api_key}"
        elif self._username and self._password:
            auth = httpx.BasicAuth(self._username, self._password)
        return httpx.AsyncClient(
            verify=self._verify_ssl, auth=auth, headers=headers,
        )

    def _index_name(self, record: ExportRecord) -> str:
        date_suffix = record.timestamp.strftime("%Y.%m.%d")
        return f"{self._index_prefix}-{record.record_type}-{date_suffix}"

    @staticmethod
    def _to_ecs(record: ExportRecord) -> dict:
        """Map ExportRecord to ECS-compatible document fields."""
        doc: dict = {
            "@timestamp": record.timestamp.isoformat(),
            "event": {
                "kind": "alert" if record.policy_violations else "event",
                "category": ["file"],
                "type": [record.record_type],
                "risk_score": record.risk_score,
                "severity_name": record.risk_tier,
                "action": record.action_taken,
            },
            "file": {
                "path": record.file_path,
            },
            "labels": {
                "tenant_id": str(record.tenant_id),
                "source_adapter": record.source_adapter,
                "entity_types": record.entity_types,
            },
            "rule": {
                "name": record.policy_violations or [],
            },
        }
        if record.user:
            doc["user"] = {"name": record.user}
        if record.entity_counts:
            doc["labels"]["entity_counts"] = record.entity_counts
        return doc

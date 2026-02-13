"""SIEM export engine — adapter lifecycle, cursor tracking, batch scheduling.

The :class:`ExportEngine` manages multiple :class:`SIEMAdapter` instances,
tracks per-adapter export cursors (last exported timestamp), and provides
three export modes:

* ``export_scan`` — export all results from a specific scan job
* ``export_since_last`` — incremental export since each adapter's cursor
* ``export_full`` — full or filtered tenant export
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from openlabels.export.adapters.base import ExportRecord, SIEMAdapter

logger = logging.getLogger(__name__)

# Default batch size for fetching records from the data source.
_FETCH_BATCH = 1000


class ExportEngine:
    """Manages SIEM export across configured adapters.

    Supports scheduled export (post-scan, periodic), on-demand export
    (API trigger, CLI), and delivery tracking via per-adapter cursors.
    """

    def __init__(self, adapters: list[SIEMAdapter]) -> None:
        self._adapters = adapters
        # adapter_name → last_exported_at
        self._cursors: dict[str, datetime] = {}

    @property
    def adapter_names(self) -> list[str]:
        return [a.format_name() for a in self._adapters]

    @property
    def cursors(self) -> dict[str, str]:
        """Return cursors as ISO strings for API serialization."""
        return {k: v.isoformat() for k, v in self._cursors.items()}


    async def export_scan(
        self,
        job_id: UUID,
        tenant_id: UUID,
        records: list[ExportRecord],
    ) -> dict[str, int]:
        """Export all results from a specific scan job to all adapters."""
        return await self._dispatch(records)

    async def export_since_last(
        self,
        tenant_id: UUID,
        records: list[ExportRecord],
    ) -> dict[str, int]:
        """Export new records to all adapters since their last cursor.

        Returns ``{adapter_name: records_exported}``.
        """
        results: dict[str, int] = {}
        for adapter in self._adapters:
            name = adapter.format_name()
            cursor = self._cursors.get(name)
            # Filter records newer than this adapter's cursor
            if cursor:
                filtered = [r for r in records if r.timestamp > cursor]
            else:
                filtered = list(records)

            if not filtered:
                results[name] = 0
                continue

            try:
                count = await adapter.export_batch(filtered)
                results[name] = count
                if filtered:
                    self._cursors[name] = max(
                        r.timestamp for r in filtered
                    )
            except (ConnectionError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
                logger.error(
                    "Export to %s failed: %s", name, exc,
                )
                results[name] = 0

        return results

    async def export_full(
        self,
        tenant_id: UUID,
        records: list[ExportRecord],
        *,
        since: datetime | None = None,
        record_types: list[str] | None = None,
    ) -> dict[str, int]:
        """Full or filtered export to all adapters."""
        filtered = records
        if since:
            filtered = [r for r in filtered if r.timestamp >= since]
        if record_types:
            filtered = [r for r in filtered if r.record_type in record_types]
        return await self._dispatch(filtered)

    async def test_connections(self) -> dict[str, bool]:
        """Test connectivity for all configured adapters."""
        results: dict[str, bool] = {}
        for adapter in self._adapters:
            name = adapter.format_name()
            try:
                results[name] = await adapter.test_connection()
            except (ConnectionError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
                logger.error("Connection test for %s failed: %s", name, exc)
                results[name] = False
        return results

    def get_status(self) -> dict[str, Any]:
        """Return engine status for API consumption."""
        return {
            "adapters": self.adapter_names,
            "cursors": self.cursors,
            "adapter_count": len(self._adapters),
        }


    async def _dispatch(self, records: list[ExportRecord]) -> dict[str, int]:
        """Send records to all adapters."""
        results: dict[str, int] = {}
        for adapter in self._adapters:
            name = adapter.format_name()
            try:
                count = await adapter.export_batch(records)
                results[name] = count
                if records:
                    self._cursors[name] = max(
                        r.timestamp for r in records
                    )
            except (ConnectionError, TimeoutError, OSError, RuntimeError, ValueError) as exc:
                logger.error("Export to %s failed: %s", name, exc)
                results[name] = 0
        return results



def scan_result_to_export_records(
    rows: list[dict[str, Any]],
    tenant_id: UUID,
) -> list[ExportRecord]:
    """Convert scan result dicts into ExportRecords."""
    records: list[ExportRecord] = []
    for row in rows:
        entity_counts = row.get("entity_counts") or {}
        violations = row.get("policy_violations") or []
        violation_names = [v.get("policy_name", "") for v in violations] if violations else []

        records.append(ExportRecord(
            record_type="scan_result",
            timestamp=row.get("scanned_at") or datetime.now(tz=timezone.utc),
            tenant_id=tenant_id,
            file_path=row.get("file_path", ""),
            risk_score=row.get("risk_score"),
            risk_tier=row.get("risk_tier"),
            entity_types=list(entity_counts.keys()),
            entity_counts=entity_counts,
            policy_violations=violation_names,
            action_taken=row.get("action_taken"),
            user=row.get("owner"),
            source_adapter=row.get("source_adapter", "filesystem"),
        ))
    return records


def scan_results_to_dicts(results: Sequence) -> list[dict[str, Any]]:
    """Convert ScanResult ORM objects to export-ready dicts.

    This avoids repeating the same field-extraction dict comprehension
    in every job task that feeds ``scan_result_to_export_records``.
    """
    return [
        {
            "file_path": r.file_path,
            "risk_score": r.risk_score,
            "risk_tier": r.risk_tier,
            "entity_counts": r.entity_counts,
            "policy_violations": r.policy_violations,
            "owner": r.owner,
            "scanned_at": r.scanned_at,
        }
        for r in results
    ]

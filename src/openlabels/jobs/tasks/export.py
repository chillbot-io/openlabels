"""SIEM export task — periodic and on-demand export of findings.

Provides:
- ``periodic_siem_export`` — background coroutine for periodic mode
- ``execute_export_task`` — job queue handler for on-demand export
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)


async def periodic_siem_export(
    interval_seconds: int,
    shutdown_event: asyncio.Event,
) -> None:
    """Background coroutine that exports new records on a periodic interval.

    Runs until *shutdown_event* is set.  Each cycle fetches new scan results
    since the last export cursor and pushes them to all configured SIEMs.
    """
    from openlabels.server.config import get_settings
    from openlabels.export.engine import ExportEngine, scan_result_to_export_records
    from openlabels.export.setup import build_adapters_from_settings

    settings = get_settings()
    adapters = build_adapters_from_settings(settings.siem_export)
    if not adapters:
        logger.info("No SIEM adapters configured; periodic export disabled")
        return

    engine = ExportEngine(adapters)
    logger.info(
        "Periodic SIEM export started (interval=%ds, adapters=%s)",
        interval_seconds,
        engine.adapter_names,
    )

    from openlabels.server.advisory_lock import try_advisory_lock, AdvisoryLockID

    while not shutdown_event.is_set():
        try:
            from openlabels.server.db import get_session_context
            from openlabels.server.models import ScanResult
            from sqlalchemy import select

            async with get_session_context() as session:
                if not await try_advisory_lock(session, AdvisoryLockID.SIEM_EXPORT):
                    logger.debug("Periodic SIEM export: another instance is running, skipping")
                else:
                    from openlabels.server.models import Tenant

                    # Iterate tenants to maintain proper isolation
                    tenants = (await session.execute(
                        select(Tenant)
                    )).scalars().all()

                    for tenant in tenants:
                        rows = (await session.execute(
                            select(ScanResult)
                            .where(ScanResult.tenant_id == tenant.id)
                            .order_by(ScanResult.scanned_at.desc())
                            .limit(5000)
                        )).scalars().all()

                        if not rows:
                            continue

                        result_dicts = [
                            {
                                "file_path": r.file_path,
                                "risk_score": r.risk_score,
                                "risk_tier": r.risk_tier,
                                "entity_counts": r.entity_counts,
                                "policy_violations": r.policy_violations,
                                "owner": r.owner,
                                "scanned_at": r.scanned_at,
                            }
                            for r in rows
                        ]
                        export_records = scan_result_to_export_records(
                            result_dicts, tenant.id,
                        )
                        # Apply record type filter from config
                        allowed_types = settings.siem_export.export_record_types
                        if allowed_types:
                            export_records = [
                                r for r in export_records
                                if r.record_type in allowed_types
                            ]
                        results = await engine.export_since_last(
                            tenant.id, export_records,
                        )
                        total = sum(results.values())
                        if total > 0:
                            logger.info(
                                "Periodic SIEM export for tenant %s: %s",
                                tenant.id, results,
                            )

        except Exception as exc:
            logger.error("Periodic SIEM export cycle failed: %s", exc)

        # Wait for next cycle or shutdown
        try:
            await asyncio.wait_for(
                shutdown_event.wait(), timeout=interval_seconds,
            )
        except asyncio.TimeoutError:
            pass  # Normal: interval elapsed, loop again


async def execute_export_task(
    session: Any,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Job queue handler for on-demand SIEM export.

    Payload keys:
        tenant_id: UUID string
        since: ISO datetime string (optional)
        record_types: list of record type strings (optional)
        adapter: specific adapter name (optional, exports to all if omitted)
    """
    from openlabels.server.config import get_settings
    from openlabels.server.models import ScanResult
    from openlabels.export.engine import ExportEngine, scan_result_to_export_records
    from openlabels.export.setup import build_adapters_from_settings
    from sqlalchemy import select

    settings = get_settings()
    adapters = build_adapters_from_settings(settings.siem_export)
    if not adapters:
        return {"error": "No SIEM adapters configured", "exported": {}}

    # Filter to specific adapter if requested
    adapter_name = payload.get("adapter")
    if adapter_name:
        adapters = [a for a in adapters if a.format_name() == adapter_name]
        if not adapters:
            return {"error": f"Adapter '{adapter_name}' not configured", "exported": {}}

    engine = ExportEngine(adapters)
    tenant_id = UUID(payload["tenant_id"])

    # Fetch results
    query = select(ScanResult).where(ScanResult.tenant_id == tenant_id)
    since_str = payload.get("since")
    if since_str:
        since = datetime.fromisoformat(since_str)
        query = query.where(ScanResult.scanned_at >= since)
    query = query.order_by(ScanResult.scanned_at.desc()).limit(10_000)

    rows = (await session.execute(query)).scalars().all()
    result_dicts = [
        {
            "file_path": r.file_path,
            "risk_score": r.risk_score,
            "risk_tier": r.risk_tier,
            "entity_counts": r.entity_counts,
            "policy_violations": r.policy_violations,
            "owner": r.owner,
            "scanned_at": r.scanned_at,
        }
        for r in rows
    ]
    export_records = scan_result_to_export_records(result_dicts, tenant_id)

    record_types = payload.get("record_types")
    since_dt = datetime.fromisoformat(since_str) if since_str else None
    results = await engine.export_full(
        tenant_id, export_records,
        since=since_dt,
        record_types=record_types,
    )

    return {
        "exported": results,
        "total_records": len(export_records),
        "adapters": engine.adapter_names,
    }

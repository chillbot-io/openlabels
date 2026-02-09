"""SIEM export API endpoints (Phase K).

Provides endpoints to trigger SIEM export, test connections, and view status.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from openlabels.server.auth import get_current_tenant_id
from openlabels.server.config import get_settings

router = APIRouter(prefix="/export", tags=["export"])


# ── Request / Response schemas ───────────────────────────────────────

class SIEMExportRequest(BaseModel):
    since: Optional[datetime] = None
    record_types: Optional[list[str]] = None
    adapter: Optional[str] = None


class SIEMExportResponse(BaseModel):
    exported: dict[str, int]
    total_records: int
    adapters: list[str]


class SIEMTestResponse(BaseModel):
    results: dict[str, bool]


class SIEMStatusResponse(BaseModel):
    enabled: bool
    mode: str
    adapters: list[str]
    cursors: dict[str, str]


# ── Endpoints ────────────────────────────────────────────────────────

@router.post("/siem", response_model=SIEMExportResponse)
async def trigger_siem_export(
    body: SIEMExportRequest,
    tenant_id: UUID = Depends(get_current_tenant_id),
):
    """Trigger an immediate SIEM export for the current tenant."""
    settings = get_settings()
    if not settings.siem_export.enabled:
        raise HTTPException(status_code=400, detail="SIEM export is not enabled")

    from openlabels.export.engine import ExportEngine, scan_result_to_export_records
    from openlabels.export.setup import build_adapters_from_settings
    from openlabels.server.db import get_session_context
    from openlabels.server.models import ScanResult
    from sqlalchemy import select

    adapters = build_adapters_from_settings(settings.siem_export)
    if body.adapter:
        adapters = [a for a in adapters if a.format_name() == body.adapter]
        if not adapters:
            raise HTTPException(
                status_code=404,
                detail=f"Adapter '{body.adapter}' not configured",
            )

    engine = ExportEngine(adapters)

    async with get_session_context() as session:
        query = (
            select(ScanResult)
            .where(ScanResult.tenant_id == tenant_id)
            .order_by(ScanResult.scanned_at.desc())
            .limit(10_000)
        )
        if body.since:
            query = query.where(ScanResult.scanned_at >= body.since)

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
    results = await engine.export_full(
        tenant_id, export_records,
        since=body.since,
        record_types=body.record_types,
    )
    return SIEMExportResponse(
        exported=results,
        total_records=len(export_records),
        adapters=engine.adapter_names,
    )


@router.post("/siem/test", response_model=SIEMTestResponse)
async def test_siem_connections(
    tenant_id: UUID = Depends(get_current_tenant_id),
):
    """Test connectivity to all configured SIEM endpoints."""
    settings = get_settings()
    if not settings.siem_export.enabled:
        raise HTTPException(status_code=400, detail="SIEM export is not enabled")

    from openlabels.export.engine import ExportEngine
    from openlabels.export.setup import build_adapters_from_settings

    adapters = build_adapters_from_settings(settings.siem_export)
    if not adapters:
        raise HTTPException(status_code=400, detail="No SIEM adapters configured")

    engine = ExportEngine(adapters)
    results = await engine.test_connections()
    return SIEMTestResponse(results=results)


@router.get("/siem/status", response_model=SIEMStatusResponse)
async def siem_export_status(
    tenant_id: UUID = Depends(get_current_tenant_id),
):
    """View SIEM export configuration and cursor status."""
    settings = get_settings()

    from openlabels.export.setup import build_adapters_from_settings

    adapter_names = [
        a.format_name()
        for a in build_adapters_from_settings(settings.siem_export)
    ]
    return SIEMStatusResponse(
        enabled=settings.siem_export.enabled,
        mode=settings.siem_export.mode,
        adapters=adapter_names,
        cursors={},  # Cursors are per-engine-instance; status shows config
    )

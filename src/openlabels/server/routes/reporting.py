"""
Reporting API endpoints (Phase M).

Provides:
- POST /generate  — trigger report generation
- GET  /           — list generated reports
- GET  /{id}       — get report details
- GET  /{id}/download — download generated report
- POST /{id}/distribute — distribute report via email
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.models import Report, ScanResult, ScanJob, generate_uuid
from openlabels.server.dependencies import TenantContextDep
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Valid report types
VALID_TYPES = {"executive_summary", "compliance_report", "scan_detail", "access_audit", "sensitive_files"}
VALID_FORMATS = {"html", "pdf", "csv"}


# ── Request / Response schemas ──────────────────────────────────────


class ReportGenerateRequest(BaseModel):
    report_type: str = Field(..., description="Report type (executive_summary, compliance_report, scan_detail, access_audit, sensitive_files)")
    format: str = Field(default="html", description="Output format: html, pdf, csv")
    name: Optional[str] = Field(default=None, max_length=255, description="Optional friendly name")
    job_id: Optional[UUID] = Field(default=None, description="Scope to a specific scan job")
    filters: Optional[dict] = Field(default=None, description="Additional query filters")


class ReportDistributeRequest(BaseModel):
    to: list[str] = Field(..., min_length=1, description="List of email addresses")
    subject: Optional[str] = Field(default=None, description="Custom email subject")


class ReportResponse(BaseModel):
    id: UUID
    name: str
    report_type: str
    format: str
    status: str
    result_path: Optional[str] = None
    result_size_bytes: Optional[int] = None
    error: Optional[str] = None
    created_at: datetime
    generated_at: Optional[datetime] = None
    distributed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Helpers ─────────────────────────────────────────────────────────


async def _build_report_data(
    session: AsyncSession,
    tenant_id: UUID,
    report_type: str,
    job_id: UUID | None,
) -> dict:
    """Query the database and assemble data context for report templates."""

    base_query = select(ScanResult).where(ScanResult.tenant_id == tenant_id)
    if job_id:
        base_query = base_query.where(ScanResult.job_id == job_id)

    result = await session.execute(base_query)
    rows = result.scalars().all()

    findings = []
    by_tier: dict[str, int] = {}
    by_entity: dict[str, int] = {}
    total_score = 0
    by_exposure: dict[str, int] = {}
    unlabeled = 0
    publicly_exposed = 0

    for r in rows:
        entry = {
            "file_path": r.file_path,
            "file_name": r.file_name,
            "risk_score": r.risk_score,
            "risk_tier": r.risk_tier or "MINIMAL",
            "entity_counts": r.entity_counts or {},
            "total_entities": r.total_entities or 0,
            "exposure_level": getattr(r, "exposure_level", None),
            "label_name": getattr(r, "current_label_name", None),
        }
        findings.append(entry)
        tier = entry["risk_tier"]
        by_tier[tier] = by_tier.get(tier, 0) + 1
        total_score += r.risk_score or 0

        for etype, ecount in (r.entity_counts or {}).items():
            by_entity[etype] = by_entity.get(etype, 0) + ecount

        exp = entry["exposure_level"]
        if exp:
            by_exposure[exp] = by_exposure.get(exp, 0) + 1
        if exp == "PUBLIC":
            publicly_exposed += 1
        if not entry["label_name"]:
            unlabeled += 1

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    total_files = len(findings)
    files_with_findings = sum(1 for f in findings if f["total_entities"] > 0)
    avg_risk = round(total_score / total_files) if total_files else 0

    # Job metadata
    job_name = None
    target_name = None
    files_scanned = total_files
    files_with_pii = files_with_findings
    scan_duration = "-"
    if job_id:
        job_result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
        job = job_result.scalar_one_or_none()
        if job:
            job_name = job.name or str(job.id)
            target_name = getattr(job, "target_name", None) or "-"
            files_scanned = job.files_scanned or total_files
            files_with_pii = job.files_with_pii or files_with_findings
            if job.started_at and job.completed_at:
                delta = job.completed_at - job.started_at
                scan_duration = f"{int(delta.total_seconds())}s"

    # Sensitive files specific
    sensitive_findings = [f for f in findings if f["total_entities"] > 0]

    # Entity type summary for sensitive_files report
    entity_file_counts: dict[str, set] = {}
    entity_total_counts: dict[str, int] = {}
    for f in findings:
        for etype, ecount in (f.get("entity_counts") or {}).items():
            entity_file_counts.setdefault(etype, set()).add(f["file_path"])
            entity_total_counts[etype] = entity_total_counts.get(etype, 0) + ecount

    by_entity_type = sorted(
        [
            {"entity_type": k, "file_count": len(v), "total_count": entity_total_counts[k]}
            for k, v in entity_file_counts.items()
        ],
        key=lambda x: x["total_count"],
        reverse=True,
    )

    return {
        # Shared
        "findings": findings if report_type != "sensitive_files" else sensitive_findings,
        "total_files": total_files,
        "files_with_findings": files_with_findings,
        "total_entities": sum(by_entity.values()),
        "avg_risk_score": avg_risk,
        "by_tier": by_tier,
        "by_entity": by_entity,
        "top_risk_files": findings[:10],
        # scan_detail
        "job_name": job_name,
        "target_name": target_name or "-",
        "files_scanned": files_scanned,
        "files_with_pii": files_with_pii,
        "scan_duration": scan_duration,
        # compliance_report
        "total_policies": 0,
        "total_violations": 0,
        "compliance_rate": 100.0,
        "violations_by_policy": [],
        "violations_by_framework": {},
        "top_violating_files": [],
        # access_audit (placeholder — populated when access events are available)
        "total_events": 0,
        "unique_users": 0,
        "sensitive_accesses": 0,
        "top_users": [],
        "top_files": [],
        "events": [],
        # sensitive_files
        "total_sensitive": len(sensitive_findings),
        "publicly_exposed": publicly_exposed,
        "unlabeled": unlabeled,
        "critical_count": by_tier.get("CRITICAL", 0),
        "by_entity_type": by_entity_type,
        "by_exposure": by_exposure,
    }


# ── Endpoints ───────────────────────────────────────────────────────


@router.post("/generate", response_model=ReportResponse, status_code=201)
async def generate_report(
    request: ReportGenerateRequest,
    tenant: TenantContextDep,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    """Generate a new report."""
    if request.report_type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid report_type. Must be one of: {', '.join(sorted(VALID_TYPES))}")
    if request.format not in VALID_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format. Must be one of: {', '.join(sorted(VALID_FORMATS))}")

    settings = get_settings()
    tenant_id = tenant.tenant_id

    name = request.name or f"{request.report_type} ({request.format})"
    report = Report(
        id=generate_uuid(),
        tenant_id=tenant_id,
        name=name,
        report_type=request.report_type,
        format=request.format,
        status="pending",
        filters=request.filters,
    )
    session.add(report)
    await session.flush()

    try:
        from openlabels.reporting.engine import ReportEngine

        data = await _build_report_data(session, tenant_id, request.report_type, request.job_id)
        data["tenant_name"] = getattr(tenant, "tenant_name", None) or ""

        engine = ReportEngine(storage_dir=Path(settings.reporting.storage_path))
        path = await engine.generate(request.report_type, data, request.format)

        report.status = "generated"
        report.result_path = str(path)
        report.result_size_bytes = path.stat().st_size
        report.generated_at = datetime.now(timezone.utc)
    except Exception as exc:
        logger.error("Report generation failed: %s", exc, exc_info=True)
        report.status = "failed"
        report.error = str(exc)

    await session.commit()
    await session.refresh(report)
    return ReportResponse.model_validate(report)


@router.get("", response_model=PaginatedResponse[ReportResponse])
async def list_reports(
    tenant: TenantContextDep,
    session: AsyncSession = Depends(get_session),
    report_type: Optional[str] = Query(None),
    pagination: PaginationParams = Depends(),
) -> PaginatedResponse[ReportResponse]:
    """List generated reports for the current tenant."""
    tenant_id = tenant.tenant_id

    query = select(Report).where(Report.tenant_id == tenant_id)
    count_query = select(func.count(Report.id)).where(Report.tenant_id == tenant_id)

    if report_type:
        query = query.where(Report.report_type == report_type)
        count_query = count_query.where(Report.report_type == report_type)

    query = query.order_by(desc(Report.created_at))
    query = query.offset(pagination.offset).limit(pagination.page_size)

    result = await session.execute(query)
    reports = result.scalars().all()

    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    return PaginatedResponse[ReportResponse](
        **create_paginated_response(
            items=[ReportResponse.model_validate(r) for r in reports],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID,
    tenant: TenantContextDep,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    """Get report details by ID."""
    result = await session.execute(
        select(Report).where(Report.id == report_id, Report.tenant_id == tenant.tenant_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return ReportResponse.model_validate(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    tenant: TenantContextDep,
    session: AsyncSession = Depends(get_session),
):
    """Download a generated report file."""
    from fastapi.responses import FileResponse

    result = await session.execute(
        select(Report).where(Report.id == report_id, Report.tenant_id == tenant.tenant_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "generated":
        raise HTTPException(status_code=400, detail=f"Report is not ready (status={report.status})")
    if not report.result_path or not Path(report.result_path).exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    media_type = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "html": "text/html",
    }.get(report.format, "application/octet-stream")

    return FileResponse(
        report.result_path,
        media_type=media_type,
        filename=Path(report.result_path).name,
    )


@router.post("/{report_id}/distribute", response_model=ReportResponse)
async def distribute_report(
    report_id: UUID,
    request: ReportDistributeRequest,
    tenant: TenantContextDep,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    """Distribute a generated report via email."""
    result = await session.execute(
        select(Report).where(Report.id == report_id, Report.tenant_id == tenant.tenant_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "generated":
        raise HTTPException(status_code=400, detail=f"Report is not ready (status={report.status})")

    settings = get_settings().reporting
    if not settings.smtp_host:
        raise HTTPException(status_code=400, detail="SMTP is not configured. Set OPENLABELS_REPORTING__SMTP_HOST.")

    try:
        from openlabels.reporting.engine import ReportEngine

        engine = ReportEngine()
        await engine.distribute_email(
            Path(report.result_path),
            smtp_host=settings.smtp_host,
            smtp_port=settings.smtp_port,
            smtp_user=settings.smtp_user,
            smtp_password=settings.smtp_password,
            smtp_use_tls=settings.smtp_use_tls,
            from_addr=settings.smtp_from_addr,
            to_addrs=request.to,
            subject=request.subject or f"OpenLabels Report: {report.name}",
        )
        report.status = "distributed"
        report.distributed_to = [{"type": "email", "to": request.to}]
        report.distributed_at = datetime.now(timezone.utc)
    except Exception as exc:
        logger.error("Report distribution failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Distribution failed: {exc}")

    await session.commit()
    await session.refresh(report)
    return ReportResponse.model_validate(report)

"""
Reporting API endpoints (Phase M).

Provides:
- POST /generate      — trigger report generation
- POST /schedule      — schedule recurring report generation
- GET  /              — list generated reports
- GET  /{id}          — get report details
- GET  /{id}/download — download generated report
- POST /{id}/distribute — distribute report via email
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.dependencies import TenantContextDep
from openlabels.server.models import (
    FileAccessEvent,
    Policy,
    Report,
    ScanJob,
    ScanResult,
    generate_uuid,
)
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
    name: str | None = Field(default=None, max_length=255, description="Optional friendly name")
    job_id: UUID | None = Field(default=None, description="Scope to a specific scan job")
    filters: dict | None = Field(default=None, description="Additional query filters")


class ReportScheduleRequest(BaseModel):
    report_type: str = Field(..., description="Report type to schedule")
    format: str = Field(default="html", description="Output format: html, pdf, csv")
    cron: str = Field(..., description="Cron expression (e.g., '0 9 * * MON')")
    name: str | None = Field(default=None, max_length=255, description="Schedule name")
    distribute_to: list[str] | None = Field(default=None, description="Email addresses for distribution")


class ReportDistributeRequest(BaseModel):
    to: list[str] = Field(..., min_length=1, description="List of email addresses")
    subject: str | None = Field(default=None, description="Custom email subject")


class ReportResponse(BaseModel):
    id: UUID
    name: str
    report_type: str
    format: str
    status: str
    result_path: str | None = None
    result_size_bytes: int | None = None
    error: str | None = None
    created_at: datetime
    generated_at: datetime | None = None
    distributed_at: datetime | None = None

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

    # ── Compliance data from Policy model + ScanResult.policy_violations ──
    total_policies = 0
    total_violations = 0
    violations_by_policy: list[dict] = []
    violations_by_framework: dict[str, int] = {}
    top_violating_files: list[dict] = []

    try:
        policy_result = await session.execute(
            select(Policy).where(Policy.tenant_id == tenant_id, Policy.enabled == True)  # noqa: E712
        )
        policies = policy_result.scalars().all()
        total_policies = len(policies)

        # Build policy lookup by name
        policy_lookup: dict[str, Policy] = {p.name: p for p in policies}

        # Aggregate violations from scan results
        violation_counts_by_policy: dict[str, int] = {}
        file_violation_counts: dict[str, dict] = {}
        for r in rows:
            violations = r.policy_violations or []
            for v in violations:
                pname = v.get("policy") or v.get("policy_name", "Unknown")
                violation_counts_by_policy[pname] = violation_counts_by_policy.get(pname, 0) + 1
                total_violations += 1

                # Map to framework
                pol = policy_lookup.get(pname)
                if pol:
                    fw = pol.framework
                    violations_by_framework[fw] = violations_by_framework.get(fw, 0) + 1

                # Track per-file
                fpath = r.file_path
                if fpath not in file_violation_counts:
                    file_violation_counts[fpath] = {"file_path": fpath, "violation_count": 0, "policies": set()}
                file_violation_counts[fpath]["violation_count"] += 1
                file_violation_counts[fpath]["policies"].add(pname)

        violations_by_policy = sorted(
            [
                {"name": k, "count": v, "severity": getattr(policy_lookup.get(k), "risk_level", "medium")}
                for k, v in violation_counts_by_policy.items()
            ],
            key=lambda x: x["count"],
            reverse=True,
        )
        top_violating_files = sorted(
            [
                {**fv, "policies": sorted(fv["policies"])}
                for fv in file_violation_counts.values()
            ],
            key=lambda x: x["violation_count"],
            reverse=True,
        )[:20]
    except Exception:
        logger.debug("Could not load compliance data", exc_info=True)

    compliance_rate = round(
        ((total_files - total_violations) / total_files * 100) if total_files else 100.0,
        1,
    )

    # ── Access audit data from FileAccessEvent ──
    access_total_events = 0
    access_unique_users = 0
    access_sensitive_accesses = 0
    access_top_users: list[dict] = []
    access_top_files: list[dict] = []
    access_events: list[dict] = []

    try:
        # Total events
        count_result = await session.execute(
            select(func.count(FileAccessEvent.id)).where(
                FileAccessEvent.tenant_id == tenant_id,
            )
        )
        access_total_events = count_result.scalar() or 0

        # Unique users
        users_result = await session.execute(
            select(func.count(func.distinct(FileAccessEvent.user_name))).where(
                FileAccessEvent.tenant_id == tenant_id,
            )
        )
        access_unique_users = users_result.scalar() or 0

        # Sensitive accesses (files that have scan results with entities)
        sensitive_paths = {f["file_path"] for f in findings if f["total_entities"] > 0}
        if sensitive_paths:
            sens_result = await session.execute(
                select(func.count(FileAccessEvent.id)).where(
                    FileAccessEvent.tenant_id == tenant_id,
                    FileAccessEvent.file_path.in_(sensitive_paths),
                )
            )
            access_sensitive_accesses = sens_result.scalar() or 0

        # Top users by event count
        top_users_q = await session.execute(
            select(
                FileAccessEvent.user_name,
                func.count(FileAccessEvent.id).label("event_count"),
            )
            .where(FileAccessEvent.tenant_id == tenant_id)
            .group_by(FileAccessEvent.user_name)
            .order_by(desc(func.count(FileAccessEvent.id)))
            .limit(20)
        )
        access_top_users = [
            {"user": row.user_name or "unknown", "event_count": row.event_count, "sensitive_count": 0}
            for row in top_users_q
        ]

        # Top accessed files
        top_files_q = await session.execute(
            select(
                FileAccessEvent.file_path,
                func.count(FileAccessEvent.id).label("access_count"),
                func.count(func.distinct(FileAccessEvent.user_name)).label("unique_users"),
            )
            .where(FileAccessEvent.tenant_id == tenant_id)
            .group_by(FileAccessEvent.file_path)
            .order_by(desc(func.count(FileAccessEvent.id)))
            .limit(20)
        )
        access_top_files = [
            {
                "file_path": row.file_path,
                "access_count": row.access_count,
                "unique_users": row.unique_users,
                "risk_tier": next(
                    (f["risk_tier"] for f in findings if f["file_path"] == row.file_path),
                    "MINIMAL",
                ),
            }
            for row in top_files_q
        ]

        # Recent events (limit 200)
        recent_q = await session.execute(
            select(FileAccessEvent)
            .where(FileAccessEvent.tenant_id == tenant_id)
            .order_by(desc(FileAccessEvent.event_time))
            .limit(200)
        )
        access_events = [
            {
                "timestamp": e.event_time.strftime("%Y-%m-%d %H:%M:%S") if e.event_time else "-",
                "user": e.user_name or "unknown",
                "action": e.action,
                "file_path": e.file_path,
            }
            for e in recent_q.scalars()
        ]
    except Exception:
        logger.debug("Could not load access audit data", exc_info=True)

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
        "total_policies": total_policies,
        "total_violations": total_violations,
        "compliance_rate": compliance_rate,
        "violations_by_policy": violations_by_policy,
        "violations_by_framework": violations_by_framework,
        "top_violating_files": top_violating_files,
        # access_audit
        "total_events": access_total_events,
        "unique_users": access_unique_users,
        "sensitive_accesses": access_sensitive_accesses,
        "top_users": access_top_users,
        "top_files": access_top_files,
        "events": access_events,
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
        created_by=getattr(tenant, "user_id", None),
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
    report_type: str | None = Query(None),
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

    # Validate the stored path is within the configured storage directory
    settings = get_settings()
    storage_root = Path(settings.reporting.storage_path).resolve()
    report_file = Path(report.result_path).resolve()
    if not str(report_file).startswith(str(storage_root)):
        logger.warning(
            "Report %s has result_path outside storage directory: %s",
            report_id, report.result_path,
        )
        raise HTTPException(status_code=403, detail="Report file path is outside storage directory")

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
        raise HTTPException(status_code=500, detail=f"Distribution failed: {exc}") from exc

    await session.commit()
    await session.refresh(report)
    return ReportResponse.model_validate(report)


class ReportScheduleResponse(BaseModel):
    status: str
    message: str
    report_type: str
    format: str
    cron: str
    distribute_to: list[str] | None = None


@router.post("/schedule", response_model=ReportScheduleResponse, status_code=201)
async def schedule_report(
    request: ReportScheduleRequest,
    tenant: TenantContextDep,
    session: AsyncSession = Depends(get_session),
) -> ReportScheduleResponse:
    """Schedule recurring report generation via the job queue.

    Creates a job queue entry of type ``report`` that the scheduler
    will trigger at the requested cron cadence.
    """
    from openlabels.server.models import JobQueue

    if request.report_type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid report_type. Must be one of: {', '.join(sorted(VALID_TYPES))}")
    if request.format not in VALID_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format. Must be one of: {', '.join(sorted(VALID_FORMATS))}")

    tenant_id = tenant.tenant_id
    name = request.name or f"scheduled_{request.report_type}"

    job = JobQueue(
        id=generate_uuid(),
        tenant_id=tenant_id,
        task_type="report",
        payload={
            "report_type": request.report_type,
            "format": request.format,
            "cron": request.cron,
            "name": name,
            "distribute_to": request.distribute_to,
        },
        status="pending",
    )
    session.add(job)
    await session.commit()

    logger.info("Scheduled report %s (%s) with cron '%s'", name, request.report_type, request.cron)

    return ReportScheduleResponse(
        status="scheduled",
        message=f"Report '{name}' scheduled with cron '{request.cron}'",
        report_type=request.report_type,
        format=request.format,
        cron=request.cron,
        distribute_to=request.distribute_to,
    )

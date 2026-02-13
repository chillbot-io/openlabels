"""
Web UI routes for OpenLabels.

Serves Jinja2 templates with HTMX support for dynamic updates.
"""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin
from openlabels.core.constants import DEFAULT_QUERY_LIMIT
from openlabels.core.types import JobStatus
from openlabels.server.db import get_session
from openlabels.server.models import AuditLog, ScanJob, ScanResult, ScanSchedule, ScanTarget

logger = logging.getLogger(__name__)

# Matches valid CSS hex colors: #RGB, #RRGGBB, #RRGGBBAA
_HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_DEFAULT_LABEL_COLOR = "#6B7280"


def _sanitize_color(color: str | None) -> str:
    """Validate hex color to prevent CSS injection via style attributes."""
    if color and _HEX_COLOR_RE.match(color):
        return color
    return _DEFAULT_LABEL_COLOR


router = APIRouter()


def _login_redirect(request: Request) -> RedirectResponse:
    """Build a redirect response to the login page, preserving the intended destination."""
    return RedirectResponse(url=f"/ui/login?next={request.url.path}", status_code=302)


# Set up templates directory
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


def format_relative_time(dt: datetime | None) -> str:
    """Format datetime as relative time string."""
    if not dt:
        return "Never"

    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    diff = now - dt
    seconds = diff.total_seconds()

    if seconds < 0:
        # Future date
        abs_seconds = abs(seconds)
        if abs_seconds < 60:
            return "In a moment"
        elif abs_seconds < 3600:
            minutes = int(abs_seconds / 60)
            return f"In {minutes}m"
        elif abs_seconds < 86400:
            hours = int(abs_seconds / 3600)
            return f"In {hours}h"
        elif abs_seconds < 604800:
            days = int(abs_seconds / 86400)
            return f"In {days}d"
        else:
            return dt.strftime("%Y-%m-%d")

    if seconds < 60:
        return "Just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes}m ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours}h ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days}d ago"
    else:
        return dt.strftime("%Y-%m-%d")


def truncate_string(s: str, length: int = 50, suffix: str = "...") -> str:
    """Truncate string to specified length."""
    if not s:
        return ""
    if len(s) <= length:
        return s
    return s[:length - len(suffix)] + suffix


# Register template filters
templates.env.filters["relative_time"] = format_relative_time
templates.env.filters["truncate_path"] = truncate_string


# Default empty values for dashboard partials (HTMX will load actual data)
_DEFAULT_STATS = {
    "total_files": 0,
    "total_findings": 0,
    "critical_findings": 0,
    "active_scans": 0,
}


# Page routes
@router.get("/")
async def home(request: Request):
    return RedirectResponse(url="/ui/dashboard", status_code=302)


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_page": "dashboard",
            "stats": _DEFAULT_STATS,
            "recent_scans": [],
            "findings": [],
            "risk_distribution": [],
            "activity": [],
        },
    )


@router.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "targets.html",
        {"request": request, "active_page": "targets"},
    )


@router.get("/targets/new", response_class=HTMLResponse)
async def new_target_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "targets_form.html",
        {"request": request, "active_page": "targets", "target": None, "mode": "create"},
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "scans.html",
        {"request": request, "active_page": "scans"},
    )


@router.get("/scans/new", response_class=HTMLResponse)
async def new_scan_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "scans_form.html",
        {"request": request, "active_page": "scans"},
    )


@router.get("/results", response_class=HTMLResponse)
async def results_page(
    request: Request,
    scan_id: str | None = None,
    user=Depends(get_optional_user),
):
    """Results page with optional scan_id filter."""
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "results.html",
        {"request": request, "active_page": "results", "scan_id": scan_id},
    )


@router.get("/labels", response_class=HTMLResponse)
async def labels_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "labels.html",
        {"request": request, "active_page": "labels"},
    )


@router.get("/labels/sync", response_class=HTMLResponse)
async def labels_sync_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "labels_sync.html",
        {"request": request, "active_page": "labels"},
    )


@router.get("/monitoring", response_class=HTMLResponse)
async def monitoring_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "monitoring.html",
        {
            "request": request,
            "active_page": "monitoring",
            "stats": {"pending": 0, "running": 0, "completed": 0, "failed": 0, "cancelled": 0},
            "activity_logs": [],
            "jobs": [],
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Settings page with current configuration values.

    Reads persisted tenant settings from the database, falling back to
    system defaults from config when no tenant overrides exist.
    """
    from openlabels.server.config import get_settings
    from openlabels.server.models import TenantSettings

    config = get_settings()

    # Load tenant-specific overrides from DB
    tenant_settings = None
    if hasattr(user, "tenant_id"):
        result = await session.execute(
            select(TenantSettings).where(TenantSettings.tenant_id == user.tenant_id)
        )
        tenant_settings = result.scalar_one_or_none()

    # Entity categories for the detection tab — canonical types only (aliases
    # are resolved automatically by the detection pipeline).
    entity_categories = [
        ("Names", [
            ("NAME", "Name (General)"), ("NAME_PATIENT", "Patient Name"),
            ("NAME_PROVIDER", "Provider Name"), ("NAME_RELATIVE", "Relative Name"),
            ("FIRSTNAME", "First Name"), ("LASTNAME", "Last Name"),
            ("MIDDLENAME", "Middle Name"), ("FULLNAME", "Full Name"),
            ("NURSE", "Nurse"), ("STAFF", "Staff"),
        ]),
        ("Dates & Time", [
            ("DATE", "Date (General)"), ("DATE_DOB", "Date of Birth"),
            ("DATE_TIME", "Date & Time"), ("TIME", "Time"),
            ("BIRTH_YEAR", "Birth Year"), ("DATE_RANGE", "Date Range"),
        ]),
        ("Age", [("AGE", "Age")]),
        ("Locations", [
            ("ADDRESS", "Address"), ("ZIP", "ZIP / Postal Code"),
            ("CITY", "City"), ("STATE", "State / Province"),
            ("COUNTRY", "Country"), ("COUNTY", "County"),
            ("GPS_COORDINATE", "GPS Coordinate"), ("LOC", "Location (General)"),
            ("GPE", "Geo-Political Entity"), ("ROOM", "Room Number"),
        ]),
        ("Government IDs", [
            ("SSN", "Social Security Number"), ("SSN_PARTIAL", "Partial SSN"),
            ("UKNINUMBER", "UK National Insurance"), ("SIN", "Canadian SIN"),
            ("DRIVER_LICENSE", "Driver's License"), ("STATE_ID", "State ID"),
            ("PASSPORT", "Passport"), ("MILITARY_ID", "Military ID"),
            ("TAX_ID", "Tax ID"), ("TIN", "Taxpayer ID Number"),
            ("EIN", "Employer ID Number"), ("ITIN", "Individual Tax ID"),
        ]),
        ("Medical IDs", [
            ("MRN", "Medical Record Number"), ("NPI", "NPI Number"),
            ("DEA", "DEA Number"), ("MEDICAL_LICENSE", "Medical License"),
            ("ENCOUNTER_ID", "Encounter ID"), ("HEALTH_PLAN_ID", "Health Plan ID"),
            ("MEMBER_ID", "Member ID"), ("MEDICARE_ID", "Medicare ID"),
            ("PHARMACY_ID", "Pharmacy ID"), ("NDC", "National Drug Code"),
        ]),
        ("Vehicle IDs", [
            ("VIN", "Vehicle Identification Number"),
            ("LICENSE_PLATE", "License Plate"),
        ]),
        ("Contact Info", [
            ("PHONE", "Phone Number"), ("EMAIL", "Email Address"),
            ("FAX", "Fax Number"), ("PAGER", "Pager Number"),
            ("URL", "URL"), ("USERNAME", "Username"),
        ]),
        ("Network & Device", [
            ("IP_ADDRESS", "IP Address"), ("MAC_ADDRESS", "MAC Address"),
            ("DEVICE_ID", "Device ID"), ("IMEI", "IMEI Number"),
            ("BIOMETRIC_ID", "Biometric ID"), ("DICOM_UID", "DICOM UID"),
            ("CERTIFICATE_NUMBER", "Certificate Number"),
            ("CLAIM_NUMBER", "Claim Number"),
        ]),
        ("Financial", [
            ("CREDIT_CARD", "Credit Card"),
            ("CREDIT_CARD_PARTIAL", "Partial Credit Card"),
            ("BANK_ACCOUNT", "Bank Account"),
            ("ACCOUNT_NUMBER", "Account Number"),
            ("IBAN", "IBAN"), ("ABA_ROUTING", "ABA Routing Number"),
            ("SWIFT", "SWIFT / BIC Code"),
        ]),
        ("Securities", [
            ("CUSIP", "CUSIP"), ("ISIN", "ISIN"), ("SEDOL", "SEDOL"),
            ("FIGI", "FIGI"), ("LEI", "LEI"),
        ]),
        ("Cryptocurrency", [
            ("BITCOIN_ADDRESS", "Bitcoin Address"),
            ("ETHEREUM_ADDRESS", "Ethereum Address"),
            ("CRYPTO_SEED_PHRASE", "Crypto Seed Phrase"),
            ("SOLANA_ADDRESS", "Solana Address"),
            ("CARDANO_ADDRESS", "Cardano Address"),
            ("LITECOIN_ADDRESS", "Litecoin Address"),
            ("DOGECOIN_ADDRESS", "Dogecoin Address"),
            ("XRP_ADDRESS", "XRP Address"),
        ]),
        ("Secrets - Cloud Providers", [
            ("AWS_ACCESS_KEY", "AWS Access Key"),
            ("AWS_SECRET_KEY", "AWS Secret Key"),
            ("AWS_SESSION_TOKEN", "AWS Session Token"),
            ("AZURE_STORAGE_KEY", "Azure Storage Key"),
            ("AZURE_CONNECTION_STRING", "Azure Connection String"),
            ("AZURE_SAS_TOKEN", "Azure SAS Token"),
            ("GOOGLE_API_KEY", "Google API Key"), ("FIREBASE_KEY", "Firebase Key"),
        ]),
        ("Secrets - Code & CI", [
            ("GITHUB_TOKEN", "GitHub Token"), ("GITLAB_TOKEN", "GitLab Token"),
            ("NPM_TOKEN", "NPM Token"), ("PYPI_TOKEN", "PyPI Token"),
            ("NUGET_KEY", "NuGet Key"),
        ]),
        ("Secrets - Communication", [
            ("SLACK_TOKEN", "Slack Token"), ("SLACK_WEBHOOK", "Slack Webhook"),
            ("DISCORD_TOKEN", "Discord Token"),
            ("TWILIO_ACCOUNT_SID", "Twilio Account SID"),
            ("SENDGRID_KEY", "SendGrid Key"), ("MAILCHIMP_KEY", "Mailchimp Key"),
        ]),
        ("Secrets - Payment", [
            ("STRIPE_KEY", "Stripe Key"), ("SQUARE_TOKEN", "Square Token"),
            ("SHOPIFY_TOKEN", "Shopify Token"),
        ]),
        ("Secrets - Infrastructure", [
            ("HEROKU_KEY", "Heroku Key"), ("DATADOG_KEY", "Datadog Key"),
            ("NEWRELIC_KEY", "New Relic Key"), ("DATABASE_URL", "Database URL"),
        ]),
        ("Secrets - Authentication", [
            ("PRIVATE_KEY", "Private Key"), ("JWT", "JWT Token"),
            ("BASIC_AUTH", "Basic Auth Credentials"),
            ("BEARER_TOKEN", "Bearer Token"), ("PASSWORD", "Password"),
            ("API_KEY", "API Key"), ("SECRET", "Secret (General)"),
        ]),
        ("Government - Classification", [
            ("CLASSIFICATION_LEVEL", "Classification Level"),
            ("CLASSIFICATION_MARKING", "Classification Marking"),
            ("SCI_MARKING", "SCI Marking"),
            ("DISSEMINATION_CONTROL", "Dissemination Control"),
        ]),
        ("Government - Contracts", [
            ("CAGE_CODE", "CAGE Code"), ("DUNS_NUMBER", "DUNS Number"),
            ("UEI", "Unique Entity ID"), ("DOD_CONTRACT", "DoD Contract"),
            ("GSA_CONTRACT", "GSA Contract"), ("CLEARANCE_LEVEL", "Clearance Level"),
            ("ITAR_MARKING", "ITAR Marking"), ("EAR_MARKING", "EAR Marking"),
        ]),
        ("Professional", [
            ("PROFESSION", "Profession"), ("OCCUPATION", "Occupation"),
            ("JOB_TITLE", "Job Title"),
        ]),
        ("Medical Context", [
            ("DRUG", "Drug"), ("MEDICATION", "Medication"),
            ("LAB_TEST", "Lab Test"), ("DIAGNOSIS", "Diagnosis"),
            ("PROCEDURE", "Procedure"), ("RX_NUMBER", "Prescription Number"),
            ("BLOOD_TYPE", "Blood Type"),
        ]),
        ("Organization & Facility", [
            ("FACILITY", "Facility"), ("HOSPITAL", "Hospital"),
            ("ORG", "Organization"), ("COMPANY", "Company"),
            ("EMPLOYER", "Employer"), ("VENDOR", "Vendor"),
        ]),
        ("Document & Tracking", [
            ("DOCUMENT_ID", "Document ID"), ("ID_NUMBER", "ID Number"),
            ("TRACKING_NUMBER", "Tracking Number"),
            ("SHIPMENT_ID", "Shipment ID"),
        ]),
    ]

    # Flatten all entity IDs for the default "all enabled" list
    all_entity_ids = [eid for _, types in entity_categories for eid, _ in types]

    # Adapter defaults
    adapter_defs = (
        tenant_settings.adapter_defaults
        if tenant_settings and tenant_settings.adapter_defaults
        else {}
    )

    # Build settings object merging DB overrides with system defaults
    settings = {
        "azure": {
            "tenant_id": (
                tenant_settings.azure_tenant_id
                if tenant_settings and tenant_settings.azure_tenant_id
                else config.auth.tenant_id
            ) or "",
            "client_id": (
                tenant_settings.azure_client_id
                if tenant_settings and tenant_settings.azure_client_id
                else config.auth.client_id
            ) or "",
        },
        "scan": {
            "max_file_size_mb": (
                tenant_settings.max_file_size_mb
                if tenant_settings and tenant_settings.max_file_size_mb is not None
                else config.detection.max_file_size_mb
            ),
            "concurrent_files": (
                tenant_settings.concurrent_files
                if tenant_settings and tenant_settings.concurrent_files is not None
                else getattr(config.detection, "concurrent_files", 10)
            ),
            "enable_ocr": (
                tenant_settings.enable_ocr
                if tenant_settings and tenant_settings.enable_ocr is not None
                else config.detection.enable_ocr
            ),
        },
        "fanout": {
            "fanout_enabled": (
                tenant_settings.fanout_enabled
                if tenant_settings and tenant_settings.fanout_enabled is not None
                else True
            ),
            "fanout_threshold": (
                tenant_settings.fanout_threshold
                if tenant_settings and tenant_settings.fanout_threshold is not None
                else 10000
            ),
            "fanout_max_partitions": (
                tenant_settings.fanout_max_partitions
                if tenant_settings and tenant_settings.fanout_max_partitions is not None
                else 16
            ),
            "pipeline_max_concurrent_files": (
                tenant_settings.pipeline_max_concurrent_files
                if tenant_settings and tenant_settings.pipeline_max_concurrent_files is not None
                else 8
            ),
            "pipeline_memory_budget_mb": (
                tenant_settings.pipeline_memory_budget_mb
                if tenant_settings and tenant_settings.pipeline_memory_budget_mb is not None
                else 512
            ),
        },
        "entities": {
            "enabled": (
                tenant_settings.enabled_entities
                if tenant_settings and tenant_settings.enabled_entities
                else all_entity_ids
            ),
        },
        "adapters": {
            "exclude_extensions": ", ".join(adapter_defs.get("exclude_extensions", [])),
            "exclude_patterns": ", ".join(adapter_defs.get("exclude_patterns", [])),
            "exclude_accounts": ", ".join(adapter_defs.get("exclude_accounts", [])),
            "min_size_bytes": adapter_defs.get("min_size_bytes") or 0,
            "max_size_bytes": adapter_defs.get("max_size_bytes") or 0,
            "exclude_temp_files": adapter_defs.get("exclude_temp_files", True),
            "exclude_system_dirs": adapter_defs.get("exclude_system_dirs", True),
        },
    }

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "active_page": "settings",
            "settings": settings,
            "entity_categories": entity_categories,
        },
    )


@router.get("/schedules", response_class=HTMLResponse)
async def schedules_page(request: Request, user=Depends(get_optional_user)):
    if not user:
        return _login_redirect(request)
    return templates.TemplateResponse(
        "schedules.html",
        {"request": request, "active_page": "schedules"},
    )


@router.get("/schedules/new", response_class=HTMLResponse)
async def new_schedule_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """New schedule form page."""
    if not user:
        return _login_redirect(request)
    targets = []
    if user:
        query = (
            select(ScanTarget)
            .where(ScanTarget.tenant_id == user.tenant_id, ScanTarget.enabled == True)  # noqa: E712
            .order_by(ScanTarget.name)
            .limit(DEFAULT_QUERY_LIMIT)
        )
        result = await session.execute(query)
        for t in result.scalars().all():
            targets.append({"id": str(t.id), "name": t.name, "adapter": t.adapter})

    return templates.TemplateResponse(
        "schedules_form.html",
        {"request": request, "active_page": "schedules", "schedule": None, "targets": targets},
    )


@router.get("/schedules/{schedule_id}", response_class=HTMLResponse)
async def edit_schedule_page(
    request: Request,
    schedule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Edit schedule form page."""
    schedule = None
    targets = []

    if user:
        # Get schedule
        schedule_obj = await session.get(ScanSchedule, schedule_id)
        if schedule_obj and schedule_obj.tenant_id == user.tenant_id:
            schedule = {
                "id": str(schedule_obj.id),
                "name": schedule_obj.name,
                "target_id": str(schedule_obj.target_id),
                "cron": schedule_obj.cron,
                "enabled": schedule_obj.enabled,
            }

        # Get targets
        query = (
            select(ScanTarget)
            .where(ScanTarget.tenant_id == user.tenant_id)
            .order_by(ScanTarget.name)
            .limit(DEFAULT_QUERY_LIMIT)
        )
        result = await session.execute(query)
        for t in result.scalars().all():
            targets.append({"id": str(t.id), "name": t.name, "adapter": t.adapter})

    if not schedule:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 404, "error_message": "Schedule not found"},
            status_code=404,
        )

    return templates.TemplateResponse(
        "schedules_form.html",
        {"request": request, "active_page": "schedules", "schedule": schedule, "targets": targets},
    )


@router.get("/targets/{target_id}", response_class=HTMLResponse)
async def edit_target_page(
    request: Request,
    target_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Edit target form page."""
    target = None

    if user:
        target_obj = await session.get(ScanTarget, target_id)
        if target_obj and target_obj.tenant_id == user.tenant_id:
            target = {
                "id": str(target_obj.id),
                "name": target_obj.name,
                "adapter": target_obj.adapter,
                "config": target_obj.config or {},
                "enabled": target_obj.enabled,
            }

    if not target:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 404, "error_message": "Target not found"},
            status_code=404,
        )

    return templates.TemplateResponse(
        "targets_form.html",
        {"request": request, "active_page": "targets", "target": target, "mode": "edit"},
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail_page(
    request: Request,
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Scan detail page with real-time updates."""
    scan = None

    if user:
        scan_obj = await session.get(ScanJob, scan_id)
        if scan_obj and scan_obj.tenant_id == user.tenant_id:
            # Get total_files from progress JSONB column, fall back to estimate
            progress_data = scan_obj.progress or {}
            total_files = (
                progress_data.get("files_total")
                or scan_obj.total_files_estimated
                or 0
            )

            progress_pct = 0
            if total_files > 0:
                progress_pct = min(100, int((scan_obj.files_scanned or 0) / total_files * 100))
            elif scan_obj.status == JobStatus.COMPLETED:
                progress_pct = 100

            scan = {
                "id": str(scan_obj.id),
                "target_name": scan_obj.target_name or "Unknown",
                "status": scan_obj.status,
                "files_scanned": scan_obj.files_scanned or 0,
                "total_files": total_files,
                "progress": progress_pct,
                "error": scan_obj.error,
                "created_at": scan_obj.created_at,
                "started_at": scan_obj.started_at,
                "completed_at": scan_obj.completed_at,
            }

    if not scan:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 404, "error_message": "Scan not found"},
            status_code=404,
        )

    return templates.TemplateResponse(
        "scan_detail.html",
        {"request": request, "active_page": "scans", "scan": scan},
    )


@router.get("/results/{result_id}", response_class=HTMLResponse)
async def result_detail_page(
    request: Request,
    result_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Result detail page showing file findings."""
    result = None

    if user:
        result_obj = await session.get(ScanResult, result_id)
        if result_obj and result_obj.tenant_id == user.tenant_id:
            file_path = result_obj.file_path or ""
            file_name = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]

            # Extract entity list from findings if available
            entities = []
            if result_obj.findings and isinstance(result_obj.findings, dict):
                entities = result_obj.findings.get("entities", [])

            result = {
                "id": str(result_obj.id),
                "file_path": file_path,
                "file_name": file_name,
                "risk_tier": result_obj.risk_tier,
                "risk_score": result_obj.risk_score or 0,
                "entity_counts": result_obj.entity_counts or {},
                "entities": entities,
                "label_applied": result_obj.label_applied,
                "label_name": result_obj.current_label_name,
                "scanned_at": result_obj.scanned_at,
                "file_size": result_obj.file_size,
                "file_hash": result_obj.content_hash,
            }

    if not result:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 404, "error_message": "Result not found"},
            status_code=404,
        )

    return templates.TemplateResponse(
        "result_detail.html",
        {"request": request, "active_page": "results", "result": result},
    )


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    from openlabels.server.config import get_settings

    config = get_settings()
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "dev_mode": config.server.environment == "development"},
    )


# Form submission handlers for HTMX
from fastapi import Form
from fastapi.responses import RedirectResponse


@router.post("/targets", response_class=HTMLResponse)
async def create_target_form(
    request: Request,
    name: str = Form(...),
    adapter: str = Form(...),
    enabled: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Handle target creation form submission."""
    # Get form data for config fields
    form_data = await request.form()

    # Build config from form fields
    config = {}
    for key, value in form_data.items():
        if key.startswith("config[") and key.endswith("]"):
            config_key = key[7:-1]  # Extract key from config[key]
            if value:  # Only include non-empty values
                config[config_key] = value

    # Validate target config (same as API endpoint)
    from fastapi import HTTPException
    from openlabels.server.routes.targets import validate_target_config
    try:
        config = validate_target_config(adapter, config)
    except HTTPException as e:
        return templates.TemplateResponse(
            "targets.html",
            {"request": request, "active_page": "targets", "error": e.detail, "targets": []},
            status_code=400,
        )

    try:
        target = ScanTarget(
            tenant_id=user.tenant_id,
            name=name,
            adapter=adapter,
            config=config,
            enabled=enabled == "on",
            created_by=user.id,
        )
        session.add(target)
        await session.flush()
    except Exception as e:
        logger.warning("Failed to create target: %s", e)
        return templates.TemplateResponse(
            "targets_form.html",
            {"request": request, "active_page": "targets", "target": None,
             "mode": "create", "error": "Failed to create target. Name may already exist."},
            status_code=400,
        )

    # Return redirect — use HX-Redirect for HTMX, 303 as fallback for non-HTMX
    if request.headers.get("HX-Request"):
        response = HTMLResponse(status_code=200)
        response.headers["HX-Redirect"] = "/ui/targets"
    else:
        response = RedirectResponse(url="/ui/targets", status_code=303)
    return response


@router.post("/targets/{target_id}", response_class=HTMLResponse)
async def update_target_form(
    request: Request,
    target_id: UUID,
    name: str = Form(...),
    adapter: str = Form(...),
    enabled: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Handle target update form submission."""
    target = await session.get(ScanTarget, target_id)
    if not target or target.tenant_id != user.tenant_id:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 404, "error_message": "Target not found"},
            status_code=404,
        )

    # Get form data for config fields
    form_data = await request.form()

    # Build config from form fields
    config = {}
    for key, value in form_data.items():
        if key.startswith("config[") and key.endswith("]"):
            config_key = key[7:-1]
            if value:
                config[config_key] = value

    # SECURITY: Validate target config (same as API endpoint)
    from fastapi import HTTPException
    from openlabels.server.routes.targets import validate_target_config
    try:
        config = validate_target_config(adapter, config)
    except HTTPException as e:
        return templates.TemplateResponse(
            "targets_form.html",
            {"request": request, "active_page": "targets", "target": {
                "id": str(target_id), "name": name, "adapter": adapter,
                "config": config, "enabled": enabled == "on",
            }, "mode": "edit", "error": e.detail},
            status_code=400,
        )

    target.name = name
    target.adapter = adapter
    target.config = config
    target.enabled = enabled == "on"

    if request.headers.get("HX-Request"):
        response = HTMLResponse(status_code=200)
        response.headers["HX-Redirect"] = "/ui/targets"
    else:
        response = RedirectResponse(url="/ui/targets", status_code=303)
    return response


@router.post("/schedules", response_class=HTMLResponse)
async def create_schedule_form(
    request: Request,
    name: str = Form(...),
    target_id: str = Form(...),
    cron: str = Form(...),
    enabled: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Handle schedule creation form submission."""
    from openlabels.jobs import parse_cron_expression

    try:
        parsed_target_id = UUID(target_id)
    except (ValueError, AttributeError):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 400, "error_message": "Invalid target ID"},
            status_code=400,
        )

    try:
        schedule = ScanSchedule(
            tenant_id=user.tenant_id,
            name=name,
            target_id=parsed_target_id,
            cron=cron if cron else None,
            enabled=enabled == "on",
            created_by=user.id,
        )

        # Calculate next run time if cron is set
        if cron:
            schedule.next_run_at = parse_cron_expression(cron)

        session.add(schedule)
        await session.flush()
    except Exception as e:
        logger.warning("Failed to create schedule: %s", e)
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 400,
             "error_message": "Failed to create schedule. Check your cron expression."},
            status_code=400,
        )

    if request.headers.get("HX-Request"):
        response = HTMLResponse(status_code=200)
        response.headers["HX-Redirect"] = "/ui/schedules"
    else:
        response = RedirectResponse(url="/ui/schedules", status_code=303)
    return response


@router.post("/schedules/{schedule_id}", response_class=HTMLResponse)
async def update_schedule_form(
    request: Request,
    schedule_id: UUID,
    name: str = Form(...),
    target_id: str = Form(...),
    cron: str = Form(...),
    enabled: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Handle schedule update form submission."""
    from openlabels.jobs import parse_cron_expression

    schedule = await session.get(ScanSchedule, schedule_id)
    if not schedule or schedule.tenant_id != user.tenant_id:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 404, "error_message": "Schedule not found"},
            status_code=404,
        )

    try:
        parsed_target_id = UUID(target_id)
    except (ValueError, AttributeError):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 400, "error_message": "Invalid target ID"},
            status_code=400,
        )

    schedule.name = name
    schedule.target_id = parsed_target_id
    schedule.cron = cron if cron else None
    schedule.enabled = enabled == "on"

    if cron:
        try:
            schedule.next_run_at = parse_cron_expression(cron)
        except Exception as e:
            logger.warning("Invalid cron expression %r: %s", cron, e)
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error_code": 400,
                 "error_message": f"Invalid cron expression: {cron}"},
                status_code=400,
            )
    else:
        schedule.next_run_at = None

    if request.headers.get("HX-Request"):
        response = HTMLResponse(status_code=200)
        response.headers["HX-Redirect"] = "/ui/schedules"
    else:
        response = RedirectResponse(url="/ui/schedules", status_code=303)
    return response


@router.post("/scans", response_class=HTMLResponse)
async def create_scan_form(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """Handle scan creation form submission."""
    from openlabels.jobs import JobQueue

    form_data = await request.form()
    target_ids = form_data.getlist("target_ids[]")

    if not target_ids:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 400, "error_message": "No targets selected"},
            status_code=400,
        )

    # Read scan options from form
    apply_labels = form_data.get("apply_labels") == "on"
    deep_scan = form_data.get("deep_scan") == "on"
    incremental = form_data.get("incremental") == "on"
    priority_str = form_data.get("priority", "normal")
    priority_map = {"low": 25, "normal": 50, "high": 75}
    priority = priority_map.get(priority_str, 50)

    # Create scan jobs for each selected target
    job_ids = []
    queue = JobQueue(session, user.tenant_id)

    try:
        for tid in target_ids:
            try:
                parsed_tid = UUID(tid)
            except (ValueError, AttributeError):
                logger.warning("Skipping invalid target ID: %r", tid)
                continue

            target = await session.get(ScanTarget, parsed_tid)
            if target and target.tenant_id == user.tenant_id:
                job = ScanJob(
                    tenant_id=user.tenant_id,
                    target_id=target.id,
                    target_name=target.name,
                    status=JobStatus.PENDING,
                    created_by=user.id,
                )
                session.add(job)
                await session.flush()

                # Enqueue the scan job with options in payload
                await queue.enqueue(
                    task_type="scan",
                    payload={
                        "job_id": str(job.id),
                        "force_full_scan": not incremental,
                        "apply_labels": apply_labels,
                        "deep_scan": deep_scan,
                    },
                    priority=priority,
                )
                job_ids.append(str(job.id))
    except Exception as e:
        logger.error("Failed to create scan jobs: %s", e)
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error_code": 500,
             "error_message": "Failed to create scan. Please try again."},
            status_code=500,
        )

    if request.headers.get("HX-Request"):
        response = HTMLResponse(status_code=200)
        response.headers["HX-Redirect"] = "/ui/scans"
    else:
        response = RedirectResponse(url="/ui/scans", status_code=303)
    return response


# Partial routes for HTMX
@router.get("/partials/dashboard-stats", response_class=HTMLResponse)
async def dashboard_stats_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Dashboard stats partial for HTMX updates.

    Mirrors the GET /api/v1/dashboard/stats endpoint semantics:
    - total_files: total files scanned across all jobs (from ScanJob)
    - total_findings: count of sensitive files (from ScanResult)
    - critical_findings: count of CRITICAL-tier files
    - active_scans: currently running/pending scans
    """
    stats = {
        "total_files": 0,
        "total_findings": 0,
        "critical_findings": 0,
        "active_scans": 0,
    }

    if user:
        # Total files scanned and active scans from ScanJob (matches API)
        scan_stats_query = select(
            func.coalesce(func.sum(ScanJob.files_scanned), 0).label("total_files_scanned"),
            func.sum(
                case((ScanJob.status.in_(["pending", "running"]), 1), else_=0)
            ).label("active"),
        ).where(ScanJob.tenant_id == user.tenant_id)

        result = await session.execute(scan_stats_query)
        scan_row = result.one()
        stats["total_files"] = scan_row.total_files_scanned or 0
        stats["active_scans"] = scan_row.active or 0

        # Sensitive file stats from ScanResult (matches API's files_with_pii / critical_files)
        file_stats_query = select(
            func.count().label("files_with_pii"),
            func.sum(case((ScanResult.risk_tier == "CRITICAL", 1), else_=0)).label("critical_files"),
        ).where(ScanResult.tenant_id == user.tenant_id)

        result = await session.execute(file_stats_query)
        row = result.one()
        stats["total_findings"] = row.files_with_pii or 0
        stats["critical_findings"] = row.critical_files or 0

    return templates.TemplateResponse(
        "partials/dashboard_stats.html",
        {"request": request, "stats": stats},
    )


@router.get("/partials/recent-scans", response_class=HTMLResponse)
async def recent_scans_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Recent scans partial for HTMX updates."""
    recent_scans = []

    if user:
        query = (
            select(ScanJob)
            .where(ScanJob.tenant_id == user.tenant_id)
            .order_by(desc(ScanJob.created_at))
            .limit(5)
        )
        result = await session.execute(query)
        scans = result.scalars().all()

        # Batch-fetch findings counts to avoid N+1 queries
        scan_ids = [scan.id for scan in scans]
        if scan_ids:
            findings_query = (
                select(
                    ScanResult.job_id,
                    func.coalesce(func.sum(ScanResult.total_entities), 0).label("total"),
                )
                .where(ScanResult.job_id.in_(scan_ids))
                .group_by(ScanResult.job_id)
            )
            findings_result = await session.execute(findings_query)
            findings_map = {row.job_id: row.total for row in findings_result.all()}
        else:
            findings_map = {}

        for scan in scans:
            recent_scans.append({
                "id": str(scan.id),
                "target_name": scan.target_name or "Unknown",
                "status": scan.status,
                "files_scanned": scan.files_scanned or 0,
                "findings_count": findings_map.get(scan.id, 0),
                "created_at": scan.created_at,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
            })

    return templates.TemplateResponse(
        "partials/recent_scans.html",
        {"request": request, "recent_scans": recent_scans},
    )


@router.get("/partials/findings-by-type", response_class=HTMLResponse)
async def findings_by_type_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Findings by type partial for HTMX updates."""
    findings_by_type = []

    if user:
        # Push JSONB aggregation to PostgreSQL instead of loading 50k rows
        # into Python. Uses jsonb_each_text() to expand the JSONB map and
        # GROUP BY to aggregate counts server-side.
        from sqlalchemy import text as sa_text

        agg_query = sa_text("""
            SELECT kv.key AS entity_type,
                   SUM(
                       CASE WHEN kv.value ~ '^[0-9]+$'
                            THEN kv.value::int
                            ELSE 0
                       END
                   ) AS total_count,
                   MAX(CASE r.risk_tier
                       WHEN 'CRITICAL' THEN 4
                       WHEN 'HIGH' THEN 3
                       WHEN 'MEDIUM' THEN 2
                       ELSE 1
                   END) AS max_risk_ord
            FROM scan_results r,
                 LATERAL jsonb_each_text(r.entity_counts) AS kv(key, value)
            WHERE r.tenant_id = :tid
              AND r.entity_counts IS NOT NULL
            GROUP BY kv.key
            ORDER BY total_count DESC
            LIMIT 10
        """)
        result = await session.execute(agg_query, {"tid": user.tenant_id})
        rows = result.all()

        risk_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
        grand_total = sum(row.total_count for row in rows) or 1
        for row in rows:
            findings_by_type.append({
                "entity_type": row.entity_type,
                "count": row.total_count,
                "risk": risk_map.get(row.max_risk_ord, "LOW"),
                "percentage": round(row.total_count / grand_total * 100, 1),
            })

    return templates.TemplateResponse(
        "partials/findings_by_type.html",
        {"request": request, "findings_by_type": findings_by_type},
    )


@router.get("/partials/risk-distribution", response_class=HTMLResponse)
async def risk_distribution_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Risk distribution partial for HTMX updates."""
    risk_distribution = []

    if user:
        query = select(
            ScanResult.risk_tier,
            func.count().label("count"),
        ).where(
            ScanResult.tenant_id == user.tenant_id,
        ).group_by(ScanResult.risk_tier)

        result = await session.execute(query)
        rows = result.all()

        total = sum(row.count for row in rows) or 1
        risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        risk_data = {row.risk_tier: row.count for row in rows}

        for level in risk_order:
            count = risk_data.get(level, 0)
            risk_distribution.append({
                "level": level,
                "count": count,
                "percentage": round(count / total * 100, 1),
            })

    return templates.TemplateResponse(
        "partials/risk_distribution.html",
        {"request": request, "risk_distribution": risk_distribution},
    )


@router.get("/partials/recent-activity", response_class=HTMLResponse)
async def recent_activity_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Recent activity partial for HTMX updates."""
    recent_activity = []

    if user:
        query = (
            select(AuditLog)
            .where(AuditLog.tenant_id == user.tenant_id)
            .order_by(desc(AuditLog.created_at))
            .limit(10)
        )
        result = await session.execute(query)
        logs = result.scalars().all()

        for log in logs:
            activity_type = log.action
            description = log.action.replace("_", " ").title()
            details = None

            if log.details:
                if "name" in log.details:
                    details = log.details["name"]
                elif "file_path" in log.details:
                    details = log.details["file_path"]

            recent_activity.append({
                "type": activity_type,
                "description": description,
                "details": details,
                "timestamp": format_relative_time(log.created_at),
            })

    return templates.TemplateResponse(
        "partials/recent_activity.html",
        {"request": request, "recent_activity": recent_activity},
    )


@router.get("/partials/health-status", response_class=HTMLResponse)
async def health_status_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Health status partial for HTMX updates."""
    health = {"status": "healthy"}

    if not user:
        return templates.TemplateResponse(
            "partials/health_status.html",
            {"request": request, "health": health},
        )

    from openlabels.server.models import JobQueue as JobQueueModel
    from sqlalchemy import text as sa_text

    # Check database connectivity
    try:
        await session.execute(sa_text("SELECT 1"))
    except Exception as e:
        logger.warning("Health check DB query failed: %s", e)
        health["status"] = "unhealthy"
        return templates.TemplateResponse(
            "partials/health_status.html",
            {"request": request, "health": health},
        )

    # Check for excessive failed jobs (indicates systemic issues)
    try:
        failed_query = select(func.count()).select_from(
            select(JobQueueModel).where(JobQueueModel.status == JobStatus.FAILED).subquery()
        )
        result = await session.execute(failed_query)
        failed_count = result.scalar() or 0
        if failed_count > 10:
            health["status"] = "degraded"
    except Exception as e:
        logger.warning("Health check job queue query failed: %s", e)
        health["status"] = "degraded"

    return templates.TemplateResponse(
        "partials/health_status.html",
        {"request": request, "health": health},
    )


@router.get("/partials/targets-list", response_class=HTMLResponse)
async def targets_list_partial(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    adapter: str | None = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Targets list partial for HTMX updates."""
    targets = []
    total = 0

    if user:
        query = select(ScanTarget).where(ScanTarget.tenant_id == user.tenant_id)
        if adapter:
            query = query.where(ScanTarget.adapter == adapter)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        result = await session.execute(count_query)
        total = result.scalar() or 0

        # Get page
        query = query.order_by(desc(ScanTarget.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        target_rows = result.scalars().all()

        for target in target_rows:
            targets.append({
                "id": str(target.id),
                "name": target.name,
                "adapter": target.adapter,
                "enabled": target.enabled,
                "created_at": target.created_at,
            })

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    return templates.TemplateResponse(
        "partials/targets_list.html",
        {
            "request": request,
            "targets": targets,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_more": page < total_pages,
        },
    )


@router.get("/partials/scans-list", response_class=HTMLResponse)
async def scans_list_partial(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Scans list partial for HTMX updates."""
    scans = []
    total = 0

    if user:
        query = select(ScanJob).where(ScanJob.tenant_id == user.tenant_id)
        if status:
            query = query.where(ScanJob.status == status)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        result = await session.execute(count_query)
        total = result.scalar() or 0

        # Get page
        query = query.order_by(desc(ScanJob.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await session.execute(query)
        scan_rows = result.scalars().all()

        for scan in scan_rows:
            progress_data = scan.progress or {}
            total_files = (
                progress_data.get("files_total")
                or scan.total_files_estimated
                or 0
            )

            progress_pct = 0
            if total_files > 0:
                progress_pct = min(100, int((scan.files_scanned or 0) / total_files * 100))
            elif scan.status == JobStatus.COMPLETED:
                progress_pct = 100

            scans.append({
                "id": str(scan.id),
                "target_name": scan.target_name or "Unknown",
                "status": scan.status,
                "files_scanned": scan.files_scanned or 0,
                "progress": progress_pct,
                "created_at": scan.created_at,
            })

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    return templates.TemplateResponse(
        "partials/scans_list.html",
        {
            "request": request,
            "scans": scans,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_more": page < total_pages,
        },
    )


@router.get("/partials/results-list", response_class=HTMLResponse)
async def results_list_partial(
    request: Request,
    # Cursor-based pagination (preferred for large datasets)
    cursor: str | None = Query(None, description="Cursor for next page"),
    # Offset-based pagination (for backward compatibility)
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    # Filters
    risk_tier: str | None = None,
    entity_type: str | None = None,
    has_label: str | None = None,
    scan_id: str | None = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """
    Results list partial for HTMX updates.

    Supports both cursor-based and offset-based pagination.
    Cursor-based pagination is more efficient for large result sets.
    """
    from openlabels.server.pagination import (
        CursorPaginationParams,
        apply_cursor_pagination,
    )

    results = []
    total = 0
    total_pages = 1
    has_more = False
    next_cursor = None

    if user:
        # Build base query with filters
        base_conditions = [ScanResult.tenant_id == user.tenant_id]
        if risk_tier:
            base_conditions.append(ScanResult.risk_tier == risk_tier)
        if entity_type:
            # Filter results that contain this entity type in their JSONB entity_counts
            base_conditions.append(ScanResult.entity_counts.has_key(entity_type))  # noqa: W601
        if has_label == "true":
            base_conditions.append(ScanResult.label_applied == True)  # noqa: E712
        elif has_label == "false":
            base_conditions.append(ScanResult.label_applied == False)  # noqa: E712
        if scan_id:
            base_conditions.append(ScanResult.job_id == UUID(scan_id))

        # Count total
        count_query = select(func.count()).select_from(
            select(ScanResult).where(*base_conditions).subquery()
        )
        result = await session.execute(count_query)
        total = result.scalar() or 0
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        # Use cursor-based pagination if cursor is provided
        if cursor is not None:
            query = select(ScanResult).where(*base_conditions)
            pagination_params = CursorPaginationParams(
                cursor=cursor,
                limit=page_size,
            )
            paginated = await apply_cursor_pagination(
                session,
                query,
                ScanResult,
                pagination_params,
                timestamp_column=ScanResult.scanned_at,
            )
            result_rows = paginated.items
            has_more = paginated.has_more
            next_cursor = paginated.next_cursor
        else:
            # Offset-based pagination
            query = (
                select(ScanResult)
                .where(*base_conditions)
                .order_by(desc(ScanResult.scanned_at))
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
            result = await session.execute(query)
            result_rows = result.scalars().all()
            has_more = page < total_pages

        for r in result_rows:
            file_path = r.file_path or ""
            file_name = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]
            file_type = file_name.split(".")[-1].lower() if "." in file_name else ""

            results.append({
                "id": str(r.id),
                "file_path": file_path,
                "file_name": file_name,
                "file_type": file_type,
                "risk_tier": r.risk_tier,
                "risk_score": r.risk_score or 0,
                "entity_counts": r.entity_counts or {},
                "label_applied": r.label_applied,
                "label_name": r.current_label_name,
                "scanned_at": r.scanned_at,
            })

    return templates.TemplateResponse(
        "partials/results_list.html",
        {
            "request": request,
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_more": has_more,
            "cursor": next_cursor,
        },
    )


@router.get("/partials/activity-log", response_class=HTMLResponse)
async def activity_log_partial(
    request: Request,
    action: str | None = None,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Activity log partial for HTMX updates."""
    activity_logs = []

    if user:
        query = select(AuditLog).where(AuditLog.tenant_id == user.tenant_id)
        if action:
            query = query.where(AuditLog.action == action)
        query = query.order_by(desc(AuditLog.created_at)).limit(50)

        result = await session.execute(query)
        logs = result.scalars().all()

        for log in logs:
            activity_logs.append({
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id) if log.resource_id else None,
                "details": log.details,
                "user_email": None,  # Would need to join with User table
                "created_at": log.created_at,
            })

    return templates.TemplateResponse(
        "partials/activity_log.html",
        {"request": request, "activity_logs": activity_logs},
    )


@router.get("/partials/job-queue", response_class=HTMLResponse)
async def job_queue_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Job queue partial for HTMX updates."""
    from openlabels.server.models import JobQueue as JobQueueModel

    stats = {
        "pending": 0,
        "running": 0,
        "completed": 0,
        "failed": 0,
        "cancelled": 0,
    }
    failed_jobs = []

    if user:
        # Get stats
        stats_query = select(
            JobQueueModel.status,
            func.count().label("count"),
        ).where(
            JobQueueModel.tenant_id == user.tenant_id
        ).group_by(JobQueueModel.status)

        result = await session.execute(stats_query)
        for row in result.all():
            if row.status in stats:
                stats[row.status] = row.count

        # Get recent failed jobs
        failed_query = (
            select(JobQueueModel)
            .where(
                JobQueueModel.tenant_id == user.tenant_id,
                JobQueueModel.status == JobStatus.FAILED,
            )
            .order_by(desc(JobQueueModel.completed_at))
            .limit(5)
        )
        result = await session.execute(failed_query)
        for job in result.scalars().all():
            failed_jobs.append({
                "id": str(job.id),
                "task_type": job.task_type,
                "error": job.error,
                "failed_at": job.completed_at,
            })

    return templates.TemplateResponse(
        "partials/job_queue.html",
        {"request": request, "stats": stats, "failed_jobs": failed_jobs},
    )


@router.get("/partials/system-health", response_class=HTMLResponse)
async def system_health_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """System health partial for HTMX updates."""
    health = {
        "status": "healthy",
        "components": {
            "database": "ok",
            "queue": "ok",
        },
    }

    if not user:
        return templates.TemplateResponse(
            "partials/system_health.html",
            {"request": request, "health": health},
        )

    from openlabels.server.models import JobQueue as JobQueueModel
    from sqlalchemy import text as sa_text

    # Check database
    try:
        await session.execute(sa_text("SELECT 1"))
    except Exception as db_err:
        logger.error("Database health check failed: %s: %s", type(db_err).__name__, db_err)
        health["status"] = "unhealthy"
        health["components"]["database"] = "error"

    # Check job queue for failures
    try:
        failed_query = select(func.count()).select_from(
            select(JobQueueModel).where(JobQueueModel.status == JobStatus.FAILED).subquery()
        )
        result = await session.execute(failed_query)
        failed_count = result.scalar() or 0
        if failed_count > 10:
            health["components"]["queue"] = "warning"
            if health["status"] == "healthy":
                health["status"] = "degraded"
    except Exception as queue_err:
        logger.warning("Queue health check failed: %s: %s", type(queue_err).__name__, queue_err)
        health["components"]["queue"] = "warning"
        if health["status"] == "healthy":
            health["status"] = "degraded"

    return templates.TemplateResponse(
        "partials/system_health.html",
        {"request": request, "health": health},
    )


@router.get("/partials/labels-list", response_class=HTMLResponse)
async def labels_list_partial(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Labels list partial for HTMX updates."""
    labels = []
    total = 0

    if user:
        from openlabels.server.models import SensitivityLabel

        base_query = select(SensitivityLabel).where(
            SensitivityLabel.tenant_id == user.tenant_id
        )

        # Count total
        count_query = select(func.count()).select_from(base_query.subquery())
        result = await session.execute(count_query)
        total = result.scalar() or 0

        # Get page
        query = base_query.order_by(SensitivityLabel.priority).offset(
            (page - 1) * page_size
        ).limit(page_size)
        result = await session.execute(query)
        for label in result.scalars().all():
            labels.append({
                "id": str(label.id),
                "name": label.name,
                "description": label.description,
                "color": _sanitize_color(label.color),
                "priority": label.priority,
                "synced_at": label.synced_at,
            })

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    return templates.TemplateResponse(
        "partials/labels_list.html",
        {
            "request": request,
            "labels": labels,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_more": page < total_pages,
        },
    )


@router.get("/partials/label-mappings", response_class=HTMLResponse)
async def label_mappings_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Label mappings partial for HTMX updates."""
    from openlabels.server.models import LabelRule, SensitivityLabel

    labels = []
    mappings = {}

    if user:
        query = (
            select(SensitivityLabel)
            .where(SensitivityLabel.tenant_id == user.tenant_id)
            .order_by(SensitivityLabel.priority)
            .limit(DEFAULT_QUERY_LIMIT)
        )
        result = await session.execute(query)
        for label in result.scalars().all():
            labels.append({
                "id": str(label.id),
                "name": label.name,
            })

        # Load existing risk_tier label rules to populate current mappings
        rules_query = (
            select(LabelRule)
            .where(
                LabelRule.tenant_id == user.tenant_id,
                LabelRule.rule_type == "risk_tier",
            )
            .order_by(desc(LabelRule.priority))
        )
        result = await session.execute(rules_query)
        for rule in result.scalars().all():
            # Map risk tier values (CRITICAL, HIGH, MEDIUM, LOW) to label IDs
            # Only store the first (highest priority) mapping per tier
            if rule.match_value not in mappings:
                mappings[rule.match_value] = rule.label_id

    return templates.TemplateResponse(
        "partials/label_mappings.html",
        {"request": request, "labels": labels, "mappings": mappings},
    )


@router.get("/partials/target-checkboxes", response_class=HTMLResponse)
async def target_checkboxes_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Target checkboxes partial for scan form."""
    targets = []

    if user:
        query = (
            select(ScanTarget)
            .where(
                ScanTarget.tenant_id == user.tenant_id,
                ScanTarget.enabled == True,  # noqa: E712
            )
            .order_by(ScanTarget.name)
            .limit(DEFAULT_QUERY_LIMIT)
        )
        result = await session.execute(query)
        for target in result.scalars().all():
            targets.append({
                "id": str(target.id),
                "name": target.name,
                "adapter": target.adapter,
            })

    if targets:
        markup = '<div class="divide-y divide-gray-200">'
        for target in targets:
            safe_id = html.escape(target['id'])
            safe_name = html.escape(target['name'])
            safe_adapter = html.escape(target['adapter'])
            markup += f'''
            <label class="flex items-center p-3 hover:bg-gray-50 cursor-pointer">
                <input type="checkbox" name="target_ids[]" value="{safe_id}"
                    class="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded">
                <div class="ml-3">
                    <span class="text-sm font-medium text-gray-900">{safe_name}</span>
                    <span class="ml-2 text-xs text-gray-500">{safe_adapter}</span>
                </div>
            </label>'''
        markup += '</div>'
    else:
        markup = '''
        <div class="p-4 text-center text-gray-500">
            <p>No enabled targets found.</p>
            <a href="/ui/targets/new" class="text-primary-600 hover:text-primary-800">Create a target</a>
        </div>'''

    return HTMLResponse(content=markup)


@router.get("/partials/schedules-list", response_class=HTMLResponse)
async def schedules_list_partial(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_optional_user),
):
    """Schedules list partial for HTMX updates."""
    schedules = []
    total = 0

    if user:
        base_query = select(ScanSchedule).where(
            ScanSchedule.tenant_id == user.tenant_id
        )

        # Count total
        count_query = select(func.count()).select_from(base_query.subquery())
        result = await session.execute(count_query)
        total = result.scalar() or 0

        # Get page
        query = base_query.order_by(desc(ScanSchedule.created_at)).offset(
            (page - 1) * page_size
        ).limit(page_size)
        result = await session.execute(query)
        schedule_rows = result.scalars().all()

        # Batch-fetch all target names to avoid N+1 queries
        target_ids = {s.target_id for s in schedule_rows}
        target_names = {}
        if target_ids:
            targets_query = select(ScanTarget.id, ScanTarget.name).where(
                ScanTarget.id.in_(target_ids)
            )
            targets_result = await session.execute(targets_query)
            target_names = {row.id: row.name for row in targets_result.all()}

        for schedule in schedule_rows:
            schedules.append({
                "id": str(schedule.id),
                "name": schedule.name,
                "target_name": target_names.get(schedule.target_id, "Unknown"),
                "cron": schedule.cron,
                "enabled": schedule.enabled,
                "last_run_at": schedule.last_run_at,
                "next_run_at": schedule.next_run_at,
            })

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    return templates.TemplateResponse(
        "partials/schedules_list.html",
        {
            "request": request,
            "schedules": schedules,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_more": page < total_pages,
        },
    )

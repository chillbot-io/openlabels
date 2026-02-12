"""
Settings API routes (JSON).

Provides GET/POST endpoints for tenant settings management.
All responses are JSON for SPA frontend consumption.

Note: Azure client secrets are write-only (cannot be retrieved via GET).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import require_admin
from openlabels.server.db import get_session
from openlabels.server.models import TenantSettings

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Response / Request schemas ───────────────────────────────────────


class AzureSettingsResponse(BaseModel):
    """Azure AD settings (secret is write-only)."""
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret_set: bool = False


class ScanSettingsResponse(BaseModel):
    """Scan configuration settings."""
    max_file_size_mb: int = 100
    concurrent_files: int = 10
    enable_ocr: bool = False


class EntitySettingsResponse(BaseModel):
    """Entity detection settings."""
    enabled_entities: list[str] = Field(default_factory=list)


class FanoutSettingsResponse(BaseModel):
    """Horizontal scaling / fan-out settings."""
    fanout_enabled: bool = True
    fanout_threshold: int = 10000
    fanout_max_partitions: int = 16
    pipeline_max_concurrent_files: int = 8
    pipeline_memory_budget_mb: int = 512


class AllSettingsResponse(BaseModel):
    """Combined response for all tenant settings."""
    azure: AzureSettingsResponse = Field(default_factory=AzureSettingsResponse)
    scan: ScanSettingsResponse = Field(default_factory=ScanSettingsResponse)
    entities: EntitySettingsResponse = Field(default_factory=EntitySettingsResponse)
    fanout: FanoutSettingsResponse = Field(default_factory=FanoutSettingsResponse)


class AzureSettingsRequest(BaseModel):
    """Request to update Azure AD settings."""
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""


class ScanSettingsRequest(BaseModel):
    """Request to update scan settings."""
    max_file_size_mb: int = Field(default=100, ge=1, le=10000)
    concurrent_files: int = Field(default=10, ge=1, le=100)
    enable_ocr: bool = False


class EntitySettingsRequest(BaseModel):
    """Request to update entity detection settings."""
    entities: list[str] = Field(default_factory=list)


class SettingsUpdateResponse(BaseModel):
    """Generic success response for settings updates."""
    status: str = "ok"
    message: str


# ── Helpers ──────────────────────────────────────────────────────────


async def _get_or_create_settings(
    session: AsyncSession,
    tenant_id,
    user_id,
) -> TenantSettings:
    """Fetch existing TenantSettings for the tenant, or create a new row."""
    result = await session.execute(
        select(TenantSettings).where(TenantSettings.tenant_id == tenant_id)
    )
    settings = result.scalar_one_or_none()
    if settings is None:
        settings = TenantSettings(tenant_id=tenant_id, updated_by=user_id)
        session.add(settings)
        await session.flush()
    return settings


def _settings_to_response(settings: TenantSettings | None) -> AllSettingsResponse:
    """Convert a TenantSettings row (or None) to the API response."""
    if settings is None:
        return AllSettingsResponse()

    return AllSettingsResponse(
        azure=AzureSettingsResponse(
            azure_tenant_id=settings.azure_tenant_id,
            azure_client_id=settings.azure_client_id,
            azure_client_secret_set=settings.azure_client_secret_set,
        ),
        scan=ScanSettingsResponse(
            max_file_size_mb=settings.max_file_size_mb,
            concurrent_files=settings.concurrent_files,
            enable_ocr=settings.enable_ocr,
        ),
        entities=EntitySettingsResponse(
            enabled_entities=settings.enabled_entities or [],
        ),
        fanout=FanoutSettingsResponse(
            fanout_enabled=settings.fanout_enabled,
            fanout_threshold=settings.fanout_threshold,
            fanout_max_partitions=settings.fanout_max_partitions,
            pipeline_max_concurrent_files=settings.pipeline_max_concurrent_files,
            pipeline_memory_budget_mb=settings.pipeline_memory_budget_mb,
        ),
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("", response_model=AllSettingsResponse)
async def get_all_settings(
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> AllSettingsResponse:
    """
    Get all tenant settings.

    Returns current configuration or system defaults if no tenant-specific
    settings have been saved.
    """
    result = await session.execute(
        select(TenantSettings).where(TenantSettings.tenant_id == user.tenant_id)
    )
    settings = result.scalar_one_or_none()
    return _settings_to_response(settings)


@router.post("/azure", response_model=SettingsUpdateResponse)
async def update_azure_settings(
    request: AzureSettingsRequest,
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsUpdateResponse:
    """
    Update Azure AD configuration.

    The client_secret value is NOT stored in the database. If a non-empty
    secret is provided we only record that one has been configured
    (azure_client_secret_set = True). In production the real secret
    should be forwarded to a secrets manager.
    """
    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.azure_tenant_id = request.tenant_id or None
    settings.azure_client_id = request.client_id or None
    if request.client_secret:
        settings.azure_client_secret_set = True
    settings.updated_by = user.id

    logger.info(
        "Azure settings updated by user %s",
        user.email,
        extra={"tenant_id": request.tenant_id, "client_id": request.client_id},
    )

    return SettingsUpdateResponse(message="Azure settings updated")


@router.post("/scan", response_model=SettingsUpdateResponse)
async def update_scan_settings(
    request: ScanSettingsRequest,
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsUpdateResponse:
    """Update scan configuration and persist to tenant settings."""
    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.max_file_size_mb = request.max_file_size_mb
    settings.concurrent_files = request.concurrent_files
    settings.enable_ocr = request.enable_ocr
    settings.updated_by = user.id

    logger.info(
        "Scan settings updated by user %s",
        user.email,
        extra={
            "max_file_size_mb": request.max_file_size_mb,
            "concurrent_files": request.concurrent_files,
            "enable_ocr": request.enable_ocr,
        },
    )

    return SettingsUpdateResponse(message="Scan settings updated")


@router.post("/entities", response_model=SettingsUpdateResponse)
async def update_entity_settings(
    request: EntitySettingsRequest,
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsUpdateResponse:
    """
    Update entity detection configuration.

    Controls which entity types are detected during scans.
    """
    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.enabled_entities = request.entities
    settings.updated_by = user.id

    logger.info(
        "Entity settings updated by user %s",
        user.email,
        extra={"enabled_entities": request.entities},
    )

    return SettingsUpdateResponse(message="Entity detection settings updated")


@router.post("/fanout", response_class=HTMLResponse)
async def update_fanout_settings(
    fanout_enabled: str | None = Form(None),
    fanout_threshold: int = Form(10000),
    fanout_max_partitions: int = Form(16),
    pipeline_max_concurrent_files: int = Form(8),
    pipeline_memory_budget_mb: int = Form(512),
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    """Update fan-out and pipeline parallelism configuration."""
    # Validate bounds
    fanout_threshold = max(100, min(fanout_threshold, 1_000_000))
    fanout_max_partitions = max(1, min(fanout_max_partitions, 128))
    pipeline_max_concurrent_files = max(1, min(pipeline_max_concurrent_files, 64))
    pipeline_memory_budget_mb = max(64, min(pipeline_memory_budget_mb, 8192))

    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.fanout_enabled = fanout_enabled == "on"
    settings.fanout_threshold = fanout_threshold
    settings.fanout_max_partitions = fanout_max_partitions
    settings.pipeline_max_concurrent_files = pipeline_max_concurrent_files
    settings.pipeline_memory_budget_mb = pipeline_memory_budget_mb
    settings.updated_by = user.id

    logger.info(
        f"Fan-out/pipeline settings updated by user {user.email}",
        extra={
            "fanout_enabled": settings.fanout_enabled,
            "fanout_threshold": fanout_threshold,
            "fanout_max_partitions": fanout_max_partitions,
            "pipeline_max_concurrent_files": pipeline_max_concurrent_files,
            "pipeline_memory_budget_mb": pipeline_memory_budget_mb,
        },
    )

    return htmx_notify("Performance settings updated")


@router.post("/adapters", response_class=HTMLResponse)
async def update_adapter_defaults(
    exclude_extensions: str = Form(""),
    exclude_patterns: str = Form(""),
    exclude_accounts: str = Form(""),
    min_size_bytes: int = Form(0),
    max_size_bytes: int = Form(0),
    exclude_temp_files: str | None = Form(None),
    exclude_system_dirs: str | None = Form(None),
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    """Update global adapter filter defaults."""
    # Validate bounds
    min_size_bytes = max(0, min(min_size_bytes, 1_073_741_824))  # 0 – 1 GB
    max_size_bytes = max(0, min(max_size_bytes, 10_737_418_240))  # 0 – 10 GB

    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.adapter_defaults = {
        "exclude_extensions": [
            e.strip() for e in exclude_extensions.split(",") if e.strip()
        ],
        "exclude_patterns": [
            p.strip() for p in exclude_patterns.split(",") if p.strip()
        ],
        "exclude_accounts": [
            a.strip() for a in exclude_accounts.split(",") if a.strip()
        ],
        "min_size_bytes": min_size_bytes if min_size_bytes > 0 else None,
        "max_size_bytes": max_size_bytes if max_size_bytes > 0 else None,
        "exclude_temp_files": exclude_temp_files == "on",
        "exclude_system_dirs": exclude_system_dirs == "on",
    }
    settings.updated_by = user.id

    logger.info(
        f"Adapter defaults updated by user {user.email}",
        extra={"adapter_defaults": settings.adapter_defaults},
    )

    return htmx_notify("Adapter defaults updated")


@router.post("/reset", response_class=HTMLResponse)
async def reset_settings(
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsUpdateResponse:
    """
    Reset all settings to defaults.

    Deletes the tenant-specific TenantSettings row so the tenant
    reverts to system defaults.
    """
    await session.execute(
        delete(TenantSettings).where(TenantSettings.tenant_id == user.tenant_id)
    )

    logger.warning(
        "Settings reset to defaults by user %s",
        user.email,
    )

    return SettingsUpdateResponse(message="Settings reset to defaults")

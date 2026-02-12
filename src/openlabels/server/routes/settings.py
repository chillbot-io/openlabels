"""
Settings API routes.

Handles configuration updates from the web UI.
Note: For security, Azure client secrets are write-only (cannot be retrieved).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form
from fastapi.responses import HTMLResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import require_admin
from openlabels.server.db import get_session
from openlabels.server.models import TenantSettings
from openlabels.server.routes import htmx_notify

logger = logging.getLogger(__name__)

router = APIRouter()


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


@router.post("/azure", response_class=HTMLResponse)
async def update_azure_settings(
    tenant_id: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    """
    Update Azure AD configuration.

    The client_secret value is NOT stored in the database. If a non-empty
    secret is provided we only record that one has been configured
    (azure_client_secret_set = True).  In production the real secret
    should be forwarded to a secrets manager.
    """
    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.azure_tenant_id = tenant_id or None
    settings.azure_client_id = client_id or None
    if client_secret:
        settings.azure_client_secret_set = True
    settings.updated_by = user.id

    logger.info(
        f"Azure settings updated by user {user.email}",
        extra={"tenant_id": tenant_id, "client_id": client_id},
    )

    return htmx_notify("Azure settings updated")


@router.post("/scan", response_class=HTMLResponse)
async def update_scan_settings(
    max_file_size_mb: int = Form(100),
    concurrent_files: int = Form(10),
    enable_ocr: str | None = Form(None),  # Checkbox sends "on" or nothing
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    """Update scan configuration and persist to tenant settings."""
    # SECURITY: Validate bounds to prevent resource exhaustion
    max_file_size_mb = max(1, min(max_file_size_mb, 10_000))
    concurrent_files = max(1, min(concurrent_files, 100))

    ocr_enabled = enable_ocr == "on"

    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.max_file_size_mb = max_file_size_mb
    settings.concurrent_files = concurrent_files
    settings.enable_ocr = ocr_enabled
    settings.updated_by = user.id

    logger.info(
        f"Scan settings updated by user {user.email}",
        extra={
            "max_file_size_mb": max_file_size_mb,
            "concurrent_files": concurrent_files,
            "enable_ocr": ocr_enabled,
        },
    )

    return htmx_notify("Scan settings updated")


@router.post("/entities", response_class=HTMLResponse)
async def update_entity_settings(
    entities: list[str] = Form(default=[]),
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    """
    Update entity detection configuration.

    Controls which entity types are detected during scans.
    """
    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.enabled_entities = entities
    settings.updated_by = user.id

    logger.info(
        f"Entity settings updated by user {user.email}",
        extra={"enabled_entities": entities},
    )

    return htmx_notify("Entity detection settings updated")


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
):
    """
    Reset all settings to defaults.

    Deletes the tenant-specific TenantSettings row so the tenant
    reverts to system defaults.
    """
    await session.execute(
        delete(TenantSettings).where(TenantSettings.tenant_id == user.tenant_id)
    )

    logger.warning(
        f"Settings reset to defaults by user {user.email}",
    )

    return htmx_notify("Settings reset to defaults")

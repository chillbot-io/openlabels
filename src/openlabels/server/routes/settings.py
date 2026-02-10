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

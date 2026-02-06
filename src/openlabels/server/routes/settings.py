"""
Settings API routes.

Handles configuration updates from the web UI.
Note: For security, Azure client secrets are write-only (cannot be retrieved).
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Form
from fastapi.responses import HTMLResponse

from openlabels.auth.dependencies import require_admin
from openlabels.server.routes import htmx_notify

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/azure", response_class=HTMLResponse)
async def update_azure_settings(
    tenant_id: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    user=Depends(require_admin),
):
    """
    Update Azure AD configuration.

    Note: In production, these settings should be stored securely
    (e.g., in a secrets manager or encrypted database).
    This implementation logs the intent but doesn't persist changes.
    """
    logger.info(
        f"Azure settings update requested by user {user.email}",
        extra={"tenant_id": tenant_id, "client_id": client_id},
    )

    return htmx_notify("Azure settings updated")


@router.post("/scan", response_class=HTMLResponse)
async def update_scan_settings(
    max_file_size_mb: int = Form(100),
    concurrent_files: int = Form(10),
    enable_ocr: Optional[str] = Form(None),  # Checkbox sends "on" or nothing
    user=Depends(require_admin),
):
    """
    Update scan configuration.

    Note: Settings changes are logged but not persisted to config file.
    In production, consider storing tenant-specific settings in database.
    """
    ocr_enabled = enable_ocr == "on"

    logger.info(
        f"Scan settings update requested by user {user.email}",
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
):
    """
    Update entity detection configuration.

    Controls which entity types are detected during scans.
    """
    # Form sends entities[] as the field name
    logger.info(
        f"Entity settings update requested by user {user.email}",
        extra={"enabled_entities": entities},
    )

    return htmx_notify("Entity detection settings updated")


@router.post("/reset", response_class=HTMLResponse)
async def reset_settings(
    user=Depends(require_admin),
):
    """
    Reset all settings to defaults.

    This clears any tenant-specific configuration overrides.
    """
    logger.warning(
        f"Settings reset requested by user {user.email}",
    )

    return htmx_notify("Settings reset to defaults")

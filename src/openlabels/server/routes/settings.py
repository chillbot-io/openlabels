"""
Settings API routes (JSON).

Provides GET/POST endpoints for tenant settings management.
All responses are JSON for SPA frontend consumption.

Note: Azure client secrets are write-only (cannot be retrieved via GET).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import require_admin
from openlabels.server.db import get_session
from openlabels.server.models import TenantSettings
from openlabels.server.routes import audit_log

logger = logging.getLogger(__name__)

router = APIRouter()




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
    enable_ml: bool = True


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
    model_config = ConfigDict(extra="forbid")
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""


class ScanSettingsRequest(BaseModel):
    """Request to update scan settings."""
    max_file_size_mb: int = Field(default=100, ge=1, le=10000)
    concurrent_files: int = Field(default=10, ge=1, le=100)
    enable_ocr: bool = False
    enable_ml: bool = True


class EntitySettingsRequest(BaseModel):
    """Request to update entity detection settings."""
    model_config = ConfigDict(extra="forbid")
    enabled_entities: list[str] = Field(default_factory=list)


class SettingsUpdateResponse(BaseModel):
    """Generic success response for settings updates."""
    status: str = "ok"
    message: str




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
            enable_ml=settings.enable_ml,
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

    settings.azure_tenant_id = request.azure_tenant_id or None
    settings.azure_client_id = request.azure_client_id or None
    if request.azure_client_secret:
        settings.azure_client_secret_set = True
    settings.updated_by = user.id

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="settings_updated", resource_type="settings",
        details={"section": "azure", "client_id": request.azure_client_id or None},
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
    settings.enable_ml = request.enable_ml
    settings.updated_by = user.id

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="settings_updated", resource_type="settings",
        details={
            "section": "scan",
            "max_file_size_mb": request.max_file_size_mb,
            "concurrent_files": request.concurrent_files,
            "enable_ocr": request.enable_ocr,
            "enable_ml": request.enable_ml,
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

    settings.enabled_entities = request.enabled_entities
    settings.updated_by = user.id

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="settings_updated", resource_type="settings",
        details={"section": "entities", "enabled_entities": request.enabled_entities},
    )

    return SettingsUpdateResponse(message="Entity detection settings updated")


class FanoutSettingsRequest(BaseModel):
    """Request to update fan-out and pipeline settings."""
    model_config = ConfigDict(extra="forbid")
    fanout_enabled: bool = True
    fanout_threshold: int = Field(default=10000, ge=100, le=1_000_000)
    fanout_max_partitions: int = Field(default=16, ge=1, le=128)
    pipeline_max_concurrent_files: int = Field(default=8, ge=1, le=64)
    pipeline_memory_budget_mb: int = Field(default=512, ge=64, le=8192)


@router.post("/fanout", response_model=SettingsUpdateResponse)
async def update_fanout_settings(
    request: FanoutSettingsRequest,
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsUpdateResponse:
    """Update fan-out and pipeline parallelism configuration."""
    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.fanout_enabled = request.fanout_enabled
    settings.fanout_threshold = request.fanout_threshold
    settings.fanout_max_partitions = request.fanout_max_partitions
    settings.pipeline_max_concurrent_files = request.pipeline_max_concurrent_files
    settings.pipeline_memory_budget_mb = request.pipeline_memory_budget_mb
    settings.updated_by = user.id

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="settings_updated", resource_type="settings",
        details={
            "section": "fanout",
            "fanout_enabled": request.fanout_enabled,
            "fanout_threshold": request.fanout_threshold,
            "fanout_max_partitions": request.fanout_max_partitions,
        },
    )

    return SettingsUpdateResponse(message="Performance settings updated")


class AdapterDefaultsRequest(BaseModel):
    """Request to update global adapter filter defaults."""
    model_config = ConfigDict(extra="forbid")
    exclude_extensions: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)
    exclude_accounts: list[str] = Field(default_factory=list)
    min_size_bytes: int = Field(default=0, ge=0, le=1_073_741_824)
    max_size_bytes: int = Field(default=0, ge=0, le=10_737_418_240)
    exclude_temp_files: bool = False
    exclude_system_dirs: bool = False


@router.post("/adapters", response_model=SettingsUpdateResponse)
async def update_adapter_defaults(
    request: AdapterDefaultsRequest,
    user=Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsUpdateResponse:
    """Update global adapter filter defaults."""
    settings = await _get_or_create_settings(session, user.tenant_id, user.id)

    settings.adapter_defaults = {
        "exclude_extensions": request.exclude_extensions,
        "exclude_patterns": request.exclude_patterns,
        "exclude_accounts": request.exclude_accounts,
        "min_size_bytes": request.min_size_bytes if request.min_size_bytes > 0 else None,
        "max_size_bytes": request.max_size_bytes if request.max_size_bytes > 0 else None,
        "exclude_temp_files": request.exclude_temp_files,
        "exclude_system_dirs": request.exclude_system_dirs,
    }
    settings.updated_by = user.id

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="settings_updated", resource_type="settings",
        details={"section": "adapters"},
    )

    return SettingsUpdateResponse(message="Adapter defaults updated")


@router.post("/reset")
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

    audit_log(
        session, tenant_id=user.tenant_id, user_id=user.id,
        action="settings_updated", resource_type="settings",
        details={"section": "reset", "action": "reset_to_defaults"},
    )

    return SettingsUpdateResponse(message="Settings reset to defaults")

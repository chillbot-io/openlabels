"""Configuration management routes."""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from ...core import ScrubIQ
from ...services import ConfigProvider, SettingCategory
from ...constants import API_RATE_WINDOW_SECONDS
from ...rate_limiter import check_rate_limit
from ..dependencies import require_unlocked
from ..errors import not_found, bad_request, ErrorCode

logger = logging.getLogger(__name__)
router = APIRouter(tags=["config"])

# Rate limits for config operations
CONFIG_READ_RATE_LIMIT = 60  # Max reads per window
CONFIG_WRITE_RATE_LIMIT = 10  # Max writes per window


# --- SCHEMAS ---
class SettingResponse(BaseModel):
    """A configuration setting with metadata."""
    key: str
    category: str
    description: str
    type: str
    default: Any
    current: Any
    allowed_values: Optional[List[Any]] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    requires_restart: bool
    runtime_editable: bool


class SettingUpdate(BaseModel):
    """Request to update a setting."""
    value: Any = Field(..., description="New value for the setting")


class ConfigExport(BaseModel):
    """Full configuration export."""
    settings: Dict[str, Any]


class ConfigImportRequest(BaseModel):
    """Request to import configuration."""
    settings: Dict[str, Any]


class ConfigImportResponse(BaseModel):
    """Response from configuration import."""
    updated: List[str]
    failed: List[str] = []


# Global config provider instance
_config_provider: Optional[ConfigProvider] = None


def get_config_provider() -> ConfigProvider:
    """Get or create the config provider instance."""
    global _config_provider
    if _config_provider is None:
        raise RuntimeError("ConfigProvider not initialized")
    return _config_provider


def init_config_provider(config) -> ConfigProvider:
    """Initialize the global config provider."""
    global _config_provider
    _config_provider = ConfigProvider(config)
    return _config_provider


# --- ROUTES ---
@router.get("/config", response_model=Dict[str, SettingResponse])
def list_all_settings(
    request: Request,
    category: Optional[str] = Query(default=None, description="Filter by category"),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    List all configuration settings with metadata.

    Returns all settings with their current values, types, constraints,
    and descriptions. Optionally filter by category.
    """
    check_rate_limit(request, action="config_read", limit=CONFIG_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    provider = get_config_provider()

    all_settings = provider.get_all_with_metadata()

    # Filter by category if specified
    if category:
        try:
            cat = SettingCategory(category)
            all_settings = {
                k: v for k, v in all_settings.items()
                if v["category"] == category
            }
        except ValueError:
            raise bad_request(
                f"Invalid category '{category}'. Valid: {provider.get_categories()}",
                error_code=ErrorCode.VALIDATION_ERROR
            )

    # Convert to SettingResponse format
    return {
        key: SettingResponse(
            key=key,
            category=meta["category"],
            description=meta["description"],
            type=meta["type"],
            default=meta["default"],
            current=meta["current"],
            allowed_values=meta["allowed_values"],
            min_value=meta["min_value"],
            max_value=meta["max_value"],
            requires_restart=meta["requires_restart"],
            runtime_editable=meta["runtime_editable"],
        )
        for key, meta in all_settings.items()
    }


@router.get("/config/categories", response_model=List[str])
def list_categories(
    request: Request,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """List all configuration categories."""
    check_rate_limit(request, action="config_read", limit=CONFIG_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    provider = get_config_provider()
    return provider.get_categories()


@router.get("/config/{key:path}", response_model=SettingResponse)
def get_setting(
    request: Request,
    key: str,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Get a specific configuration setting.

    Use dot notation for the key (e.g., "detection.min_confidence").
    """
    check_rate_limit(request, action="config_read", limit=CONFIG_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    provider = get_config_provider()

    meta = provider.get_metadata(key)
    if meta is None:
        raise not_found(f"Setting '{key}' not found", error_code=ErrorCode.NOT_FOUND)

    return SettingResponse(
        key=meta.key,
        category=meta.category.value,
        description=meta.description,
        type=meta.value_type,
        default=meta.default,
        current=meta.current,
        allowed_values=meta.allowed_values,
        min_value=meta.min_value,
        max_value=meta.max_value,
        requires_restart=meta.requires_restart,
        runtime_editable=meta.runtime_editable,
    )


@router.put("/config/{key:path}", response_model=SettingResponse)
def update_setting(
    request: Request,
    key: str,
    body: SettingUpdate,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Update a configuration setting.

    Only settings with runtime_editable=true can be changed.
    Settings with requires_restart=true will need app restart to take effect.
    """
    check_rate_limit(request, action="config_write", limit=CONFIG_WRITE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    provider = get_config_provider()

    meta = provider.get_metadata(key)
    if meta is None:
        raise not_found(f"Setting '{key}' not found", error_code=ErrorCode.NOT_FOUND)

    try:
        provider.set(key, body.value)
    except RuntimeError as e:
        raise bad_request(str(e), error_code=ErrorCode.VALIDATION_ERROR)
    except ValueError as e:
        raise bad_request(str(e), error_code=ErrorCode.VALIDATION_ERROR)

    # Return updated metadata
    meta = provider.get_metadata(key)
    return SettingResponse(
        key=meta.key,
        category=meta.category.value,
        description=meta.description,
        type=meta.value_type,
        default=meta.default,
        current=meta.current,
        allowed_values=meta.allowed_values,
        min_value=meta.min_value,
        max_value=meta.max_value,
        requires_restart=meta.requires_restart,
        runtime_editable=meta.runtime_editable,
    )


@router.get("/config/export", response_model=ConfigExport)
def export_config(
    request: Request,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Export all configuration settings.

    Returns a dictionary that can be saved and imported later.
    """
    check_rate_limit(request, action="config_read", limit=CONFIG_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    provider = get_config_provider()
    return ConfigExport(settings=provider.export_to_dict())


@router.post("/config/import", response_model=ConfigImportResponse)
def import_config(
    request: Request,
    body: ConfigImportRequest,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Import configuration settings.

    Only runtime-editable settings will be updated. Invalid or
    non-editable settings will be skipped.
    """
    check_rate_limit(request, action="config_write", limit=CONFIG_WRITE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    provider = get_config_provider()

    updated = []
    failed = []

    for key, value in body.settings.items():
        try:
            provider.set(key, value)
            updated.append(key)
        except (KeyError, ValueError, RuntimeError) as e:
            logger.warning(f"Failed to import setting {key}: {e}")
            failed.append(key)

    return ConfigImportResponse(updated=updated, failed=failed)


@router.post("/config/reset/{key:path}", response_model=SettingResponse)
def reset_setting(
    request: Request,
    key: str,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Reset a setting to its default value.

    Only works for runtime-editable settings.
    """
    check_rate_limit(request, action="config_write", limit=CONFIG_WRITE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    provider = get_config_provider()

    meta = provider.get_metadata(key)
    if meta is None:
        raise not_found(f"Setting '{key}' not found", error_code=ErrorCode.NOT_FOUND)

    try:
        provider.set(key, meta.default)
    except (RuntimeError, ValueError) as e:
        raise bad_request(str(e), error_code=ErrorCode.VALIDATION_ERROR)

    meta = provider.get_metadata(key)
    return SettingResponse(
        key=meta.key,
        category=meta.category.value,
        description=meta.description,
        type=meta.value_type,
        default=meta.default,
        current=meta.current,
        allowed_values=meta.allowed_values,
        min_value=meta.min_value,
        max_value=meta.max_value,
        requires_restart=meta.requires_restart,
        runtime_editable=meta.runtime_editable,
    )

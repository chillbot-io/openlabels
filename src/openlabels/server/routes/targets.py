"""
Scan target management API endpoints.

Security features:
- Path validation prevents scanning of system directories
- URL validation prevents SSRF attacks via SharePoint/OneDrive targets
- Configuration sanitization removes potentially dangerous options
"""

from __future__ import annotations

import logging
import os
import re
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser, get_current_user, require_admin
from openlabels.server.db import get_session
from openlabels.server.models import ScanTarget
from openlabels.server.routes import get_or_404, htmx_notify
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# Security: Blocked path prefixes for filesystem scan targets
# These system directories should never be scanned
BLOCKED_SCAN_PATH_PREFIXES = (
    # Unix/Linux system directories
    "/etc",
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/lib",
    "/lib64",
    "/opt",
    "/run",
    "/tmp",
    # Windows system directories
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\System Volume Information",
)

# Blocked path patterns (regex)
BLOCKED_SCAN_PATH_PATTERNS = [
    re.compile(r"\.\."),  # Path traversal
    re.compile(r"^~"),  # Home directory expansion
    re.compile(r"\$\{?[A-Za-z_]"),  # Environment variable expansion
]

# Allowed SharePoint/OneDrive domains (Microsoft 365)
ALLOWED_SHAREPOINT_DOMAINS = (
    ".sharepoint.com",
    ".sharepoint-df.com",  # DoD/GCC High
    ".sharepoint.de",  # Germany
    ".sharepoint.cn",  # China
)


def validate_filesystem_target_config(config: dict) -> dict:
    """
    Validate filesystem scan target configuration.

    Security: Prevents scanning of system directories and path traversal attacks.

    Args:
        config: Target configuration dictionary

    Returns:
        Validated and sanitized config

    Raises:
        HTTPException: If configuration is invalid or contains blocked paths
    """
    if not config:
        raise HTTPException(status_code=400, detail="Configuration is required")

    path = config.get("path")
    if not path:
        raise HTTPException(status_code=400, detail="Filesystem target requires 'path' in config")

    # Normalize the path
    try:
        normalized_path = os.path.normpath(path)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"Invalid path format: {path}") from None

    # Check for path traversal patterns
    for pattern in BLOCKED_SCAN_PATH_PATTERNS:
        if pattern.search(path):
            logger.warning(f"Blocked scan target with suspicious path pattern: {path}")
            raise HTTPException(
                status_code=400,
                detail="Path contains invalid characters or traversal sequences"
            )

    # Check against blocked prefixes (case-insensitive for Windows)
    path_lower = normalized_path.lower()
    for blocked in BLOCKED_SCAN_PATH_PREFIXES:
        blocked_lower = blocked.lower()
        if path_lower == blocked_lower or path_lower.startswith(blocked_lower + os.sep):
            logger.warning(f"Blocked scan target for system directory: {path}")
            raise HTTPException(
                status_code=403,
                detail=f"Scanning system directories is not allowed: {blocked}"
            )

    # Must be an absolute path
    if not os.path.isabs(normalized_path):
        raise HTTPException(
            status_code=400,
            detail="Filesystem path must be absolute"
        )

    # Return sanitized config
    sanitized = config.copy()
    sanitized["path"] = normalized_path
    return sanitized


def validate_sharepoint_target_config(config: dict) -> dict:
    """
    Validate SharePoint scan target configuration.

    Security: Validates that URLs point to legitimate SharePoint domains
    to prevent SSRF attacks.

    Args:
        config: Target configuration dictionary

    Returns:
        Validated and sanitized config

    Raises:
        HTTPException: If configuration is invalid or contains suspicious URLs
    """
    if not config:
        raise HTTPException(status_code=400, detail="Configuration is required")

    site_url = config.get("site_url")
    if not site_url:
        raise HTTPException(status_code=400, detail="SharePoint target requires 'site_url' in config")

    # Parse and validate URL
    try:
        parsed = urlparse(site_url)
    except (ValueError, TypeError) as url_err:
        # Log invalid URLs for security monitoring - could indicate injection attempts
        logger.warning(f"Failed to parse SharePoint URL '{site_url[:100]}...': {type(url_err).__name__}")
        raise HTTPException(status_code=400, detail="Invalid site_url format") from url_err

    # Must be HTTPS
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="SharePoint URL must use HTTPS"
        )

    # Validate domain is a legitimate SharePoint domain
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid SharePoint URL: missing hostname")

    hostname_lower = hostname.lower()
    is_valid_domain = any(
        hostname_lower.endswith(domain) for domain in ALLOWED_SHAREPOINT_DOMAINS
    )

    if not is_valid_domain:
        logger.warning(f"Blocked SharePoint target with non-SharePoint domain: {hostname}")
        raise HTTPException(
            status_code=400,
            detail="site_url must be a valid SharePoint domain (*.sharepoint.com)"
        )

    # Validate document library path if provided
    doc_library = config.get("document_library")
    if doc_library:
        # Check for path traversal
        if ".." in doc_library:
            raise HTTPException(
                status_code=400,
                detail="Document library path contains invalid traversal sequences"
            )

    return config


def validate_onedrive_target_config(config: dict) -> dict:
    """
    Validate OneDrive scan target configuration.

    Security: Validates paths and prevents traversal attacks.

    Args:
        config: Target configuration dictionary

    Returns:
        Validated and sanitized config

    Raises:
        HTTPException: If configuration is invalid
    """
    if not config:
        raise HTTPException(status_code=400, detail="Configuration is required")

    # OneDrive uses user_id or path
    user_id = config.get("user_id")
    path = config.get("path", "/")

    if not user_id:
        raise HTTPException(
            status_code=400,
            detail="OneDrive target requires 'user_id' in config"
        )

    # Validate path doesn't contain traversal
    if ".." in path:
        raise HTTPException(
            status_code=400,
            detail="OneDrive path contains invalid traversal sequences"
        )

    # Normalize path
    normalized_path = "/" + path.strip("/") if path else "/"

    sanitized = config.copy()
    sanitized["path"] = normalized_path
    return sanitized


def validate_s3_target_config(config: dict) -> dict:
    """
    Validate S3 scan target configuration.

    Args:
        config: Target configuration dictionary

    Returns:
        Validated and sanitized config

    Raises:
        HTTPException: If configuration is invalid
    """
    if not config:
        raise HTTPException(status_code=400, detail="Configuration is required")

    bucket = config.get("bucket")
    if not bucket:
        raise HTTPException(
            status_code=400,
            detail="S3 target requires 'bucket' in config",
        )

    # Validate bucket name per S3 naming rules
    if not re.match(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$", bucket):
        raise HTTPException(
            status_code=400,
            detail="Invalid S3 bucket name",
        )

    prefix = config.get("prefix", "")
    if ".." in prefix:
        raise HTTPException(
            status_code=400,
            detail="S3 prefix contains invalid traversal sequences",
        )

    return config


def validate_gcs_target_config(config: dict) -> dict:
    """
    Validate GCS scan target configuration.

    Args:
        config: Target configuration dictionary

    Returns:
        Validated and sanitized config

    Raises:
        HTTPException: If configuration is invalid
    """
    if not config:
        raise HTTPException(status_code=400, detail="Configuration is required")

    bucket = config.get("bucket")
    if not bucket:
        raise HTTPException(
            status_code=400,
            detail="GCS target requires 'bucket' in config",
        )

    # Validate bucket name per GCS naming rules
    if not re.match(r"^[a-z0-9][a-z0-9_\-\.]{1,220}[a-z0-9]$", bucket):
        raise HTTPException(
            status_code=400,
            detail="Invalid GCS bucket name",
        )

    prefix = config.get("prefix", "")
    if ".." in prefix:
        raise HTTPException(
            status_code=400,
            detail="GCS prefix contains invalid traversal sequences",
        )

    return config


def validate_target_config(adapter: str, config: dict) -> dict:
    """
    Validate scan target configuration based on adapter type.

    Args:
        adapter: The adapter type ('filesystem', 'sharepoint', 'onedrive', 's3', 'gcs')
        config: Target configuration dictionary

    Returns:
        Validated and sanitized config

    Raises:
        HTTPException: If configuration is invalid
    """
    validators = {
        "filesystem": validate_filesystem_target_config,
        "sharepoint": validate_sharepoint_target_config,
        "onedrive": validate_onedrive_target_config,
        "s3": validate_s3_target_config,
        "gcs": validate_gcs_target_config,
    }

    validator = validators.get(adapter)
    if not validator:
        raise HTTPException(status_code=400, detail=f"Unknown adapter type: {adapter}")

    return validator(config)


class TargetCreate(BaseModel):
    """Request to create a scan target."""

    name: str = Field(..., min_length=1, max_length=255, description="Target name")
    adapter: str = Field(..., pattern="^(filesystem|sharepoint|onedrive|s3|gcs)$", description="Adapter type")
    config: dict = Field(..., description="Adapter-specific configuration")

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        """Strip null bytes and other dangerous control characters."""
        sanitized = v.replace("\x00", "")
        if not sanitized or not sanitized.strip():
            raise ValueError("Name must not be empty after sanitization")
        return sanitized


class TargetUpdate(BaseModel):
    """Request to update a scan target."""

    name: str | None = Field(None, min_length=1, max_length=255)
    config: dict | None = None
    enabled: bool | None = None


class TargetResponse(BaseModel):
    """Scan target response."""

    id: UUID
    name: str
    adapter: str
    config: dict
    enabled: bool

    class Config:
        from_attributes = True


@router.get("", response_model=PaginatedResponse[TargetResponse])
async def list_targets(
    adapter: str | None = Query(None, description="Filter by adapter type"),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> PaginatedResponse[TargetResponse]:
    """List configured scan targets with pagination."""
    # Base query with tenant filter
    base_query = select(ScanTarget).where(ScanTarget.tenant_id == user.tenant_id)

    if adapter:
        base_query = base_query.where(ScanTarget.adapter == adapter)

    # Get total count
    count_query = select(func.count()).select_from(base_query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    paginated_query = (
        base_query
        .order_by(ScanTarget.name)
        .offset(pagination.offset)
        .limit(pagination.limit)
    )
    result = await session.execute(paginated_query)
    targets = result.scalars().all()

    return PaginatedResponse[TargetResponse](
        **create_paginated_response(
            items=[TargetResponse.model_validate(t) for t in targets],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.post("", response_model=TargetResponse, status_code=201)
async def create_target(
    request: TargetCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> TargetResponse:
    """Create a new scan target."""
    if request.adapter not in ("filesystem", "sharepoint", "onedrive", "s3", "gcs"):
        raise HTTPException(status_code=400, detail="Invalid adapter type")

    # Security: Validate target configuration to prevent path traversal and SSRF
    validated_config = validate_target_config(request.adapter, request.config)

    try:
        target = ScanTarget(
            tenant_id=user.tenant_id,
            name=request.name,
            adapter=request.adapter,
            config=validated_config,
            enabled=True,  # Explicitly set default to ensure it's available before flush
            created_by=user.id,
        )
        session.add(target)
        await session.flush()

        # Refresh to load server-generated defaults and ensure proper types
        await session.refresh(target)

        return target
    except SQLAlchemyError as e:
        logger.error(f"Database error creating target: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred") from e


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> TargetResponse:
    """Get scan target details."""
    try:
        target = await get_or_404(session, ScanTarget, target_id, tenant_id=user.tenant_id)
        return target
    except SQLAlchemyError as e:
        logger.error(f"Database error getting target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred") from e


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: UUID,
    request: TargetUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> TargetResponse:
    """Update a scan target."""
    try:
        target = await get_or_404(session, ScanTarget, target_id, tenant_id=user.tenant_id)

        if request.name is not None:
            target.name = request.name
        if request.config is not None:
            # Security: Validate updated configuration
            validated_config = validate_target_config(target.adapter, request.config)
            target.config = validated_config
        if request.enabled is not None:
            target.enabled = request.enabled

        return target
    except SQLAlchemyError as e:
        logger.error(f"Database error updating target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred") from e


@router.delete("/{target_id}")
async def delete_target(
    target_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Delete a scan target."""
    try:
        target = await get_or_404(session, ScanTarget, target_id, tenant_id=user.tenant_id)

        target_name = target.name
        await session.delete(target)

        # Check if this is an HTMX request
        if request.headers.get("HX-Request"):
            return htmx_notify(f'Target "{target_name}" deleted', refreshTargets=True)

        # Regular REST response
        return Response(status_code=204)
    except SQLAlchemyError as e:
        logger.error(f"Database error deleting target {target_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred") from e

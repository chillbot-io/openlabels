"""
Scan target management API endpoints.

Security features:
- Path validation prevents scanning of system directories
- URL validation prevents SSRF attacks via SharePoint/OneDrive targets
- Configuration sanitization removes potentially dangerous options
"""

import logging
import os
import re
from typing import Optional
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanTarget
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser

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
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid path format: {path}")

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
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid site_url format")

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


def validate_target_config(adapter: str, config: dict) -> dict:
    """
    Validate scan target configuration based on adapter type.

    Args:
        adapter: The adapter type ('filesystem', 'sharepoint', 'onedrive')
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
    }

    validator = validators.get(adapter)
    if not validator:
        raise HTTPException(status_code=400, detail=f"Unknown adapter type: {adapter}")

    return validator(config)


class TargetCreate(BaseModel):
    """Request to create a scan target."""

    name: str
    adapter: str  # 'filesystem', 'sharepoint', 'onedrive'
    config: dict  # Adapter-specific configuration


class TargetUpdate(BaseModel):
    """Request to update a scan target."""

    name: Optional[str] = None
    config: Optional[dict] = None
    enabled: Optional[bool] = None


class TargetResponse(BaseModel):
    """Scan target response."""

    id: UUID
    name: str
    adapter: str
    config: dict
    enabled: bool

    class Config:
        from_attributes = True


class PaginatedTargetsResponse(BaseModel):
    """Paginated list of scan targets."""

    items: list[TargetResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=PaginatedTargetsResponse)
async def list_targets(
    adapter: Optional[str] = Query(None, description="Filter by adapter type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> PaginatedTargetsResponse:
    """List configured scan targets with pagination."""
    # Base query with tenant filter
    base_query = select(ScanTarget).where(ScanTarget.tenant_id == user.tenant_id)

    if adapter:
        base_query = base_query.where(ScanTarget.adapter == adapter)

    # Get total count
    count_query = select(func.count()).select_from(base_query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    offset = (page - 1) * page_size

    # Get paginated results
    paginated_query = base_query.order_by(ScanTarget.name).offset(offset).limit(page_size)
    result = await session.execute(paginated_query)
    targets = result.scalars().all()

    return PaginatedTargetsResponse(
        items=[TargetResponse.model_validate(t) for t in targets],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post("", response_model=TargetResponse, status_code=201)
async def create_target(
    request: TargetCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> TargetResponse:
    """Create a new scan target."""
    if request.adapter not in ("filesystem", "sharepoint", "onedrive"):
        raise HTTPException(status_code=400, detail="Invalid adapter type")

    # Security: Validate target configuration to prevent path traversal and SSRF
    validated_config = validate_target_config(request.adapter, request.config)

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


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(get_current_user),
) -> TargetResponse:
    """Get scan target details."""
    target = await session.get(ScanTarget, target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: UUID,
    request: TargetUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> TargetResponse:
    """Update a scan target."""
    target = await session.get(ScanTarget, target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Target not found")

    if request.name is not None:
        target.name = request.name
    if request.config is not None:
        # Security: Validate updated configuration
        validated_config = validate_target_config(target.adapter, request.config)
        target.config = validated_config
    if request.enabled is not None:
        target.enabled = request.enabled

    return target


@router.delete("/{target_id}")
async def delete_target(
    target_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
):
    """Delete a scan target."""
    target = await session.get(ScanTarget, target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Target not found")

    target_name = target.name
    await session.delete(target)

    # Check if this is an HTMX request
    if request.headers.get("HX-Request"):
        return HTMLResponse(
            content="",
            status_code=200,
            headers={
                "HX-Trigger": f'{{"notify": {{"message": "Target \\"{target_name}\\" deleted", "type": "success"}}, "refreshTargets": true}}',
            },
        )

    # Regular REST response
    return Response(status_code=204)

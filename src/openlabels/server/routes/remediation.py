"""
Remediation API endpoints for file quarantine, lockdown, and rollback.

Security features:
- All actions require admin role
- Full audit logging of all actions
- Rollback capability for reversing actions
- Dry-run mode for testing without execution
- Path traversal prevention via path validation
- Rate limiting on remediation actions
"""

import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter

from openlabels.server.db import get_session
from openlabels.server.utils import get_client_ip
from openlabels.server.models import (
    RemediationAction,
    FileInventory,
    AuditLog,
)
from openlabels.auth.dependencies import require_admin
from openlabels.adapters.base import FileInfo
from openlabels.adapters.filesystem import FilesystemAdapter

logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_client_ip)

# Security: Paths that are never allowed to be accessed
BLOCKED_PATH_PREFIXES = (
    "/etc/",
    "/var/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/root/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/boot/",
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\ProgramData\\",
)

# Security: File patterns that should never be accessed
BLOCKED_FILE_PATTERNS = (
    ".env",
    ".git/",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".htpasswd",
    "shadow",
    "passwd",
    "credentials",
)


def validate_file_path(file_path: str) -> str:
    """
    Validate file path to prevent path traversal attacks.

    Security checks:
    1. Normalize path to prevent traversal (../, ./, etc.)
    2. Block access to system directories
    3. Block access to sensitive files
    4. Ensure path is absolute
    5. Strip null bytes to prevent null byte injection

    Args:
        file_path: The file path to validate

    Returns:
        Canonicalized safe path

    Raises:
        HTTPException: If path is invalid or blocked
    """
    if not file_path:
        raise HTTPException(
            status_code=400,
            detail="File path is required"
        )

    # Security: Strip null bytes to prevent null byte injection attacks
    # Null bytes can be used to truncate paths: "/data/file.pdf\x00.txt" -> "/data/file.pdf"
    if "\x00" in file_path:
        logger.warning(f"Null byte injection attempt detected: {repr(file_path)}")
        file_path = file_path.replace("\x00", "")

    # Normalize the path to resolve .. and . components
    # This converts paths like /data/../etc/passwd to /etc/passwd
    try:
        canonical_path = os.path.normpath(os.path.abspath(file_path))
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid file path format: {file_path} - {e}")
        raise HTTPException(
            status_code=400,
            detail="Invalid file path format"
        )

    # Check if path traversal was attempted
    # If normalized path doesn't start the same way, traversal was attempted
    if ".." in file_path:
        logger.warning(f"Path traversal attempt detected: {file_path}")
        raise HTTPException(
            status_code=400,
            detail="Path traversal is not allowed"
        )

    # Block access to system directories
    # Check both canonical path (for Linux paths) and original path (for Windows paths on Linux)
    canonical_lower = canonical_path.lower()
    original_lower = file_path.lower()
    for blocked in BLOCKED_PATH_PREFIXES:
        blocked_lower = blocked.lower()
        if canonical_lower.startswith(blocked_lower) or original_lower.startswith(blocked_lower):
            logger.warning(f"Blocked access to system path: {file_path} -> {canonical_path}")
            raise HTTPException(
                status_code=403,
                detail="Access to system directories is not allowed"
            )

    # Block access to sensitive files
    path_parts = canonical_path.lower().replace("\\", "/")
    for pattern in BLOCKED_FILE_PATTERNS:
        if pattern in path_parts:
            logger.warning(f"Blocked access to sensitive file: {file_path}")
            raise HTTPException(
                status_code=403,
                detail="Access to this file type is not allowed"
            )

    return canonical_path


def validate_quarantine_dir(quarantine_dir: Optional[str], base_path: str) -> str:
    """
    Validate quarantine directory to prevent path traversal.

    Args:
        quarantine_dir: Custom quarantine directory or None for default
        base_path: Base path of the file being quarantined

    Returns:
        Safe quarantine directory path
    """
    if not quarantine_dir:
        # Default: create .quarantine in the same directory as the file
        return os.path.join(os.path.dirname(base_path), ".quarantine")

    # Validate the custom quarantine directory
    try:
        canonical_dir = os.path.normpath(os.path.abspath(quarantine_dir))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid quarantine directory format"
        )

    # Check for path traversal
    if ".." in quarantine_dir:
        logger.warning(f"Path traversal in quarantine_dir: {quarantine_dir}")
        raise HTTPException(
            status_code=400,
            detail="Path traversal is not allowed in quarantine directory"
        )

    # Block system directories for quarantine
    canonical_lower = canonical_dir.lower()
    for blocked in BLOCKED_PATH_PREFIXES:
        if canonical_lower.startswith(blocked.lower()):
            logger.warning(f"Blocked quarantine to system path: {quarantine_dir}")
            raise HTTPException(
                status_code=403,
                detail="Cannot use system directory as quarantine location"
            )

    return canonical_dir


def _get_adapter_for_path(file_path: str):
    """
    Get the appropriate adapter for a file path.

    Currently only supports filesystem. Future: detect SharePoint/OneDrive URLs.
    """
    # For now, use filesystem adapter for all paths
    # Future: check if path is a SharePoint/OneDrive URL
    return FilesystemAdapter()


def _encode_acl(acl: dict) -> str:
    """Encode ACL dict to base64 string for storage."""
    return base64.b64encode(json.dumps(acl).encode()).decode()


def _decode_acl(encoded: str) -> dict:
    """Decode base64 ACL string back to dict."""
    return json.loads(base64.b64decode(encoded).decode())


class QuarantineRequest(BaseModel):
    """Request to quarantine a file."""

    file_path: str = Field(..., description="Path to file to quarantine")
    quarantine_dir: Optional[str] = Field(
        None, description="Custom quarantine directory (default: .quarantine)"
    )
    dry_run: bool = Field(
        False, description="Preview action without executing"
    )


class LockdownRequest(BaseModel):
    """Request to lock down a file (restrict permissions)."""

    file_path: str = Field(..., description="Path to file to lock down")
    allowed_principals: list[str] = Field(
        ..., description="List of users/groups allowed access (e.g., ['DOMAIN\\\\Admin'])"
    )
    dry_run: bool = Field(
        False, description="Preview action without executing"
    )


class RollbackRequest(BaseModel):
    """Request to rollback a remediation action."""

    action_id: UUID = Field(..., description="ID of action to rollback")
    dry_run: bool = Field(
        False, description="Preview rollback without executing"
    )


class RemediationResponse(BaseModel):
    """Response for remediation actions."""

    id: UUID
    action_type: str
    status: str
    source_path: str
    dest_path: Optional[str]
    dry_run: bool
    error: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class RemediationListResponse(BaseModel):
    """Paginated list of remediation actions."""

    items: list[RemediationResponse]
    total: int
    page: int
    pages: int


@router.get("", response_model=RemediationListResponse)
async def list_remediation_actions(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    action_type: Optional[str] = Query(
        None, description="Filter by action type (quarantine, lockdown, rollback)"
    ),
    status: Optional[str] = Query(
        None, description="Filter by status (pending, completed, failed, rolled_back)"
    ),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    List remediation actions with pagination.

    Returns a paginated list of all remediation actions for the tenant.
    """
    # Build base query
    query = select(RemediationAction).where(
        RemediationAction.tenant_id == user.tenant_id
    )

    if action_type:
        query = query.where(RemediationAction.action_type == action_type)
    if status:
        query = query.where(RemediationAction.status == status)

    # Get total count
    count_query = select(func.count()).where(
        RemediationAction.tenant_id == user.tenant_id
    )
    if action_type:
        count_query = count_query.where(RemediationAction.action_type == action_type)
    if status:
        count_query = count_query.where(RemediationAction.status == status)

    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * limit
    query = query.order_by(RemediationAction.created_at.desc()).offset(offset).limit(limit)

    result = await session.execute(query)
    actions = result.scalars().all()

    pages = (total + limit - 1) // limit if total > 0 else 1

    return RemediationListResponse(
        items=actions,
        total=total,
        page=page,
        pages=pages,
    )


@router.get("/{action_id}", response_model=RemediationResponse)
async def get_remediation_action(
    action_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Get details of a specific remediation action."""
    action = await session.get(RemediationAction, action_id)
    if not action or action.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Action not found")
    return action


@router.post("/quarantine", response_model=RemediationResponse)
@limiter.limit("10/minute")
async def quarantine_file(
    http_request: Request,
    request: QuarantineRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Quarantine a sensitive file.

    Moves the file to a secure quarantine directory with restricted access.
    The original location is recorded for potential rollback.

    This action:
    1. Moves file to quarantine directory
    2. Sets restrictive permissions on quarantine folder
    3. Records the action for audit and rollback

    Use dry_run=true to preview the action without executing.

    Security:
    - Path traversal attacks are blocked
    - System directories cannot be accessed
    - Rate limited to 10 requests per minute
    """
    # Security: Validate file path to prevent path traversal
    validated_path = validate_file_path(request.file_path)

    # Security: Validate quarantine directory
    quarantine_dir = validate_quarantine_dir(request.quarantine_dir, validated_path)

    # Build destination path
    file_name = os.path.basename(validated_path)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest_path = f"{quarantine_dir}/{timestamp}_{file_name}"

    # Create remediation action record
    action = RemediationAction(
        tenant_id=user.tenant_id,
        action_type="quarantine",
        status="pending" if request.dry_run else "pending",
        source_path=validated_path,  # Use validated path
        dest_path=dest_path,
        performed_by=user.email,
        dry_run=request.dry_run,
    )
    session.add(action)
    await session.flush()

    if not request.dry_run:
        # Execute actual quarantine operation via adapter
        adapter = _get_adapter_for_path(validated_path)

        if not adapter.supports_remediation():
            action.status = "failed"
            action.error = "Adapter does not support remediation"
        else:
            # Create FileInfo for the source file
            file_info = FileInfo(
                path=validated_path,
                name=file_name,
                size=0,
                modified=datetime.now(timezone.utc),
                adapter=adapter.adapter_type,
            )

            # Execute move
            success = await adapter.move_file(file_info, dest_path)

            if success:
                action.status = "completed"
                logger.info(f"Quarantined {validated_path} to {dest_path}")
            else:
                action.status = "failed"
                action.error = "Failed to move file"
                logger.error(f"Failed to quarantine {validated_path}")

    # Log audit event
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="quarantine_executed",
        resource_type="file",
        details={
            "source_path": validated_path,
            "dest_path": dest_path,
            "dry_run": request.dry_run,
            "action_id": str(action.id),
            "status": action.status,
        },
    )
    session.add(audit)
    await session.flush()

    # Refresh to load server-generated defaults (created_at)
    await session.refresh(action)

    return action


@router.post("/lockdown", response_model=RemediationResponse)
@limiter.limit("10/minute")
async def lockdown_file(
    http_request: Request,
    request: LockdownRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Lock down a sensitive file by restricting permissions.

    Changes the file's ACL to allow access only to specified principals.
    The original ACL is preserved for potential rollback.

    This action:
    1. Saves current ACL for rollback
    2. Replaces ACL with restricted access list
    3. Records the action for audit

    Use dry_run=true to preview the action without executing.

    Security:
    - Path traversal attacks are blocked
    - System directories cannot be accessed
    - Rate limited to 10 requests per minute
    """
    # Security: Validate file path to prevent path traversal
    validated_path = validate_file_path(request.file_path)

    # Create remediation action record
    action = RemediationAction(
        tenant_id=user.tenant_id,
        action_type="lockdown",
        status="pending",
        source_path=validated_path,  # Use validated path
        performed_by=user.email,
        principals={"allowed": request.allowed_principals},
        dry_run=request.dry_run,
    )
    session.add(action)
    await session.flush()

    if not request.dry_run:
        # Execute actual lockdown operation via adapter
        adapter = _get_adapter_for_path(validated_path)

        if not adapter.supports_remediation():
            action.status = "failed"
            action.error = "Adapter does not support remediation"
        else:
            file_name = os.path.basename(validated_path)

            file_info = FileInfo(
                path=validated_path,
                name=file_name,
                size=0,
                modified=datetime.now(timezone.utc),
                adapter=adapter.adapter_type,
            )

            # Get and save current ACL for rollback
            original_acl = await adapter.get_acl(file_info)
            if original_acl:
                action.previous_acl = _encode_acl(original_acl)

            # Execute lockdown
            success, _ = await adapter.lockdown_file(
                file_info,
                allowed_sids=request.allowed_principals,
            )

            if success:
                action.status = "completed"
                logger.info(f"Locked down {validated_path}")
            else:
                action.status = "failed"
                action.error = "Failed to set permissions"
                logger.error(f"Failed to lockdown {validated_path}")

    # Log audit event
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="lockdown_executed",
        resource_type="file",
        details={
            "file_path": validated_path,
            "allowed_principals": request.allowed_principals,
            "dry_run": request.dry_run,
            "action_id": str(action.id),
            "status": action.status,
        },
    )
    session.add(audit)
    await session.flush()

    # Refresh to load server-generated defaults (created_at)
    await session.refresh(action)

    return action


@router.post("/rollback", response_model=RemediationResponse)
async def rollback_action(
    request: RollbackRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """
    Rollback a previous remediation action.

    For quarantine: moves file back to original location.
    For lockdown: restores original ACL.

    Use dry_run=true to preview the rollback without executing.
    """
    # Get the original action
    original = await session.get(RemediationAction, request.action_id)
    if not original or original.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Action not found")

    if original.status == "rolled_back":
        raise HTTPException(
            status_code=400,
            detail="Action has already been rolled back"
        )

    if original.action_type == "rollback":
        raise HTTPException(
            status_code=400,
            detail="Cannot rollback a rollback action"
        )

    if original.dry_run:
        raise HTTPException(
            status_code=400,
            detail="Cannot rollback a dry-run action (nothing was executed)"
        )

    # Create rollback action record
    rollback = RemediationAction(
        tenant_id=user.tenant_id,
        action_type="rollback",
        status="pending",
        source_path=original.dest_path or original.source_path,
        dest_path=original.source_path if original.action_type == "quarantine" else None,
        performed_by=user.email,
        rollback_of_id=original.id,
        dry_run=request.dry_run,
    )
    session.add(rollback)

    if not request.dry_run:
        # Execute actual rollback operation via adapter
        adapter = _get_adapter_for_path(original.source_path)
        rollback_success = False

        if not adapter.supports_remediation():
            rollback.status = "failed"
            rollback.error = "Adapter does not support remediation"
        elif original.action_type == "quarantine":
            # Move file back from dest_path to source_path
            if original.dest_path:
                import os
                file_name = os.path.basename(original.dest_path)
                file_info = FileInfo(
                    path=original.dest_path,
                    name=file_name,
                    size=0,
                    modified=datetime.now(timezone.utc),
                    adapter=adapter.adapter_type,
                )

                rollback_success = await adapter.move_file(file_info, original.source_path)

                if rollback_success:
                    rollback.status = "completed"
                    original.status = "rolled_back"
                    logger.info(f"Rolled back quarantine: {original.dest_path} -> {original.source_path}")
                else:
                    rollback.status = "failed"
                    rollback.error = "Failed to move file back"
            else:
                rollback.status = "failed"
                rollback.error = "No destination path recorded"

        elif original.action_type == "lockdown":
            # Restore ACL from previous_acl
            if original.previous_acl:
                import os
                file_name = os.path.basename(original.source_path)
                file_info = FileInfo(
                    path=original.source_path,
                    name=file_name,
                    size=0,
                    modified=datetime.now(timezone.utc),
                    adapter=adapter.adapter_type,
                )

                original_acl = _decode_acl(original.previous_acl)
                rollback_success = await adapter.set_acl(file_info, original_acl)

                if rollback_success:
                    rollback.status = "completed"
                    original.status = "rolled_back"
                    logger.info(f"Rolled back lockdown: restored ACL for {original.source_path}")
                else:
                    rollback.status = "failed"
                    rollback.error = "Failed to restore permissions"
            else:
                rollback.status = "failed"
                rollback.error = "No previous ACL recorded"
        else:
            rollback.status = "failed"
            rollback.error = f"Unknown action type: {original.action_type}"

    await session.flush()

    # Log audit event
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="rollback_executed",
        resource_type="file",
        details={
            "original_action_id": str(original.id),
            "original_action_type": original.action_type,
            "source_path": original.source_path,
            "dry_run": request.dry_run,
            "rollback_id": str(rollback.id),
        },
    )
    session.add(audit)
    await session.flush()

    # Refresh to load server-generated defaults (created_at)
    await session.refresh(rollback)

    return rollback


@router.get("/stats/summary")
async def get_remediation_stats(
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Get summary statistics for remediation actions."""
    stats_query = select(
        func.count().label("total"),
        func.sum(
            case((RemediationAction.action_type == "quarantine", 1), else_=0)
        ).label("quarantine_count"),
        func.sum(
            case((RemediationAction.action_type == "lockdown", 1), else_=0)
        ).label("lockdown_count"),
        func.sum(
            case((RemediationAction.action_type == "rollback", 1), else_=0)
        ).label("rollback_count"),
        func.sum(
            case((RemediationAction.status == "completed", 1), else_=0)
        ).label("completed"),
        func.sum(
            case((RemediationAction.status == "failed", 1), else_=0)
        ).label("failed"),
        func.sum(
            case((RemediationAction.status == "pending", 1), else_=0)
        ).label("pending"),
    ).where(RemediationAction.tenant_id == user.tenant_id)

    result = await session.execute(stats_query)
    row = result.one()

    return {
        "total_actions": row.total or 0,
        "by_type": {
            "quarantine": row.quarantine_count or 0,
            "lockdown": row.lockdown_count or 0,
            "rollback": row.rollback_count or 0,
        },
        "by_status": {
            "completed": row.completed or 0,
            "failed": row.failed or 0,
            "pending": row.pending or 0,
        },
    }

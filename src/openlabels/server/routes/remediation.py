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
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.adapters.base import FileInfo, supports_remediation
from openlabels.adapters.filesystem import FilesystemAdapter
from openlabels.auth.dependencies import require_admin
from openlabels.core.path_validation import (
    PathValidationError,
    validate_path,
)
from openlabels.server.db import get_session
from openlabels.server.models import (
    AuditLog,
    RemediationAction,
    ScanResult,
)
from openlabels.server.routes import get_or_404
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    create_paginated_response,
)
from openlabels.server.utils import get_client_ip

logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_client_ip)


def validate_file_path(file_path: str) -> str:
    """
    Validate file path to prevent path traversal attacks.

    Uses the centralized path_validation module and converts
    PathValidationError to HTTPException for FastAPI compatibility.

    Args:
        file_path: The file path to validate

    Returns:
        Canonicalized safe path

    Raises:
        HTTPException: If path is invalid or blocked
    """
    try:
        return validate_path(file_path)
    except PathValidationError as e:
        error_msg = str(e)
        # Map error messages to appropriate HTTP status codes
        if "system directories" in error_msg or "file type" in error_msg:
            raise HTTPException(status_code=403, detail=error_msg) from e
        raise HTTPException(status_code=400, detail=error_msg) from e


def validate_quarantine_dir(quarantine_dir: str | None, base_path: str) -> str:
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

    # Use centralized path validation
    try:
        canonical_dir = validate_path(quarantine_dir)
    except PathValidationError as e:
        error_msg = str(e)
        if "system directories" in error_msg:
            raise HTTPException(
                status_code=403,
                detail="Cannot use system directory as quarantine location"
            ) from e
        raise HTTPException(status_code=400, detail=error_msg) from e

    return canonical_dir


def _get_adapter_for_path(file_path: str) -> FilesystemAdapter:
    """Return the adapter for *file_path*.

    Currently only supports filesystem.  Future: detect SharePoint/OneDrive URLs.
    """
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
    quarantine_dir: str | None = Field(
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
    dest_path: str | None
    dry_run: bool
    error: str | None
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("", response_model=PaginatedResponse[RemediationResponse])
async def list_remediation_actions(
    action_type: str | None = Query(
        None, description="Filter by action type (quarantine, lockdown, rollback)"
    ),
    status: str | None = Query(
        None, description="Filter by status (pending, completed, failed, rolled_back)"
    ),
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> PaginatedResponse[RemediationResponse]:
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
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    query = query.order_by(RemediationAction.created_at.desc()).offset(pagination.offset).limit(pagination.limit)

    result = await session.execute(query)
    actions = result.scalars().all()

    return PaginatedResponse[RemediationResponse](
        **create_paginated_response(
            items=[RemediationResponse.model_validate(a) for a in actions],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
        )
    )


@router.get("/{action_id}", response_model=RemediationResponse)
async def get_remediation_action(
    action_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Get details of a specific remediation action."""
    action = await get_or_404(session, RemediationAction, action_id, tenant_id=user.tenant_id)
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

    # Security: Verify file belongs to the requesting tenant
    result = await session.execute(
        select(ScanResult).where(
            ScanResult.file_path == validated_path,
            ScanResult.tenant_id == user.tenant_id,
        ).limit(1)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="File not found in tenant's scan results")

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

        if not supports_remediation(adapter):
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

    # Security: Verify file belongs to the requesting tenant
    result = await session.execute(
        select(ScanResult).where(
            ScanResult.file_path == validated_path,
            ScanResult.tenant_id == user.tenant_id,
        ).limit(1)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="File not found in tenant's scan results")

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

        if not supports_remediation(adapter):
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
    original = await get_or_404(session, RemediationAction, request.action_id, tenant_id=user.tenant_id)

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

        if not supports_remediation(adapter):
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
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Get summary statistics for remediation actions.

    When backed by DuckDB, aggregations run on Parquet for faster
    full-table scans.  Otherwise falls back to PostgreSQL.
    """
    from openlabels.analytics.dashboard_pg import PostgresDashboardService

    svc = getattr(request.app.state, "dashboard_service", None)
    if svc is None:
        svc = PostgresDashboardService(session)

    stats = await svc.get_remediation_stats(user.tenant_id)

    return {
        "total_actions": stats.total_actions,
        "by_type": stats.by_type,
        "by_status": stats.by_status,
    }

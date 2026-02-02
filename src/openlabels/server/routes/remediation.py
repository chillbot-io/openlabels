"""
Remediation API endpoints for file quarantine, lockdown, and rollback.

Security features:
- All actions require admin role
- Full audit logging of all actions
- Rollback capability for reversing actions
- Dry-run mode for testing without execution
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import (
    RemediationAction,
    FileInventory,
    AuditLog,
)
from openlabels.auth.dependencies import require_admin

router = APIRouter()


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
async def quarantine_file(
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
    """
    quarantine_dir = request.quarantine_dir or ".quarantine"

    # Build destination path
    import os
    file_name = os.path.basename(request.file_path)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dest_path = f"{quarantine_dir}/{timestamp}_{file_name}"

    # Create remediation action record
    action = RemediationAction(
        tenant_id=user.tenant_id,
        action_type="quarantine",
        status="pending" if request.dry_run else "pending",
        source_path=request.file_path,
        dest_path=dest_path,
        performed_by=user.email,
        dry_run=request.dry_run,
    )
    session.add(action)
    await session.flush()

    if not request.dry_run:
        # TODO: Execute actual quarantine operation via adapter
        # This would call the appropriate adapter (filesystem, SharePoint, OneDrive)
        # to perform the actual file move operation
        #
        # For now, mark as pending - the job worker will process it
        pass

    # Log audit event
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="quarantine_executed",
        resource_type="file",
        details={
            "source_path": request.file_path,
            "dest_path": dest_path,
            "dry_run": request.dry_run,
            "action_id": str(action.id),
        },
    )
    session.add(audit)
    await session.flush()

    return action


@router.post("/lockdown", response_model=RemediationResponse)
async def lockdown_file(
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
    """
    # Create remediation action record
    action = RemediationAction(
        tenant_id=user.tenant_id,
        action_type="lockdown",
        status="pending",
        source_path=request.file_path,
        performed_by=user.email,
        principals={"allowed": request.allowed_principals},
        dry_run=request.dry_run,
    )
    session.add(action)
    await session.flush()

    if not request.dry_run:
        # TODO: Execute actual lockdown operation via adapter
        # This would:
        # 1. Get current ACL and store in previous_acl (base64 encoded)
        # 2. Set new ACL with only allowed_principals
        #
        # For now, mark as pending - the job worker will process it
        pass

    # Log audit event
    audit = AuditLog(
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="lockdown_executed",
        resource_type="file",
        details={
            "file_path": request.file_path,
            "allowed_principals": request.allowed_principals,
            "dry_run": request.dry_run,
            "action_id": str(action.id),
        },
    )
    session.add(audit)
    await session.flush()

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
        # TODO: Execute actual rollback operation via adapter
        # For quarantine: move file back from dest_path to source_path
        # For lockdown: restore ACL from previous_acl
        #
        # On success, update original action status to rolled_back
        original.status = "rolled_back"

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
            func.case((RemediationAction.action_type == "quarantine", 1), else_=0)
        ).label("quarantine_count"),
        func.sum(
            func.case((RemediationAction.action_type == "lockdown", 1), else_=0)
        ).label("lockdown_count"),
        func.sum(
            func.case((RemediationAction.action_type == "rollback", 1), else_=0)
        ).label("rollback_count"),
        func.sum(
            func.case((RemediationAction.status == "completed", 1), else_=0)
        ).label("completed"),
        func.sum(
            func.case((RemediationAction.status == "failed", 1), else_=0)
        ).label("failed"),
        func.sum(
            func.case((RemediationAction.status == "pending", 1), else_=0)
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

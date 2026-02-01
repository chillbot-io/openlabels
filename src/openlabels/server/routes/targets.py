"""
Scan target management API endpoints.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanTarget
from openlabels.auth.dependencies import get_current_user, require_admin

router = APIRouter()


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


@router.get("", response_model=list[TargetResponse])
async def list_targets(
    adapter: Optional[str] = Query(None, description="Filter by adapter type"),
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """List configured scan targets."""
    query = select(ScanTarget).where(ScanTarget.tenant_id == user.tenant_id)

    if adapter:
        query = query.where(ScanTarget.adapter == adapter)

    result = await session.execute(query)
    targets = result.scalars().all()
    return [TargetResponse.model_validate(t) for t in targets]


@router.post("", response_model=TargetResponse, status_code=201)
async def create_target(
    request: TargetCreate,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Create a new scan target."""
    if request.adapter not in ("filesystem", "sharepoint", "onedrive"):
        raise HTTPException(status_code=400, detail="Invalid adapter type")

    target = ScanTarget(
        tenant_id=user.tenant_id,
        name=request.name,
        adapter=request.adapter,
        config=request.config,
        created_by=user.id,
    )
    session.add(target)
    await session.flush()
    return target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
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
    user=Depends(require_admin),
):
    """Update a scan target."""
    target = await session.get(ScanTarget, target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Target not found")

    if request.name is not None:
        target.name = request.name
    if request.config is not None:
        target.config = request.config
    if request.enabled is not None:
        target.enabled = request.enabled

    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Delete a scan target."""
    target = await session.get(ScanTarget, target_id)
    if not target or target.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Target not found")

    await session.delete(target)

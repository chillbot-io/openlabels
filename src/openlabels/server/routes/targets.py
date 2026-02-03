"""
Scan target management API endpoints.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanTarget
from openlabels.auth.dependencies import get_current_user, require_admin, CurrentUser

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

    target = ScanTarget(
        tenant_id=user.tenant_id,
        name=request.name,
        adapter=request.adapter,
        config=request.config,
        enabled=True,  # Explicitly set default to ensure it's available before flush
        created_by=user.id,
    )
    session.add(target)
    await session.flush()

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
        target.config = request.config
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

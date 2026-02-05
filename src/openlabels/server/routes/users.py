"""
User management API endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import User, Tenant
from openlabels.server.errors import NotFoundError, ConflictError, BadRequestError
from openlabels.auth.dependencies import get_current_user, require_admin

router = APIRouter()


class UserCreate(BaseModel):
    """Request to create a new user."""

    email: EmailStr
    name: Optional[str] = None
    role: str = Field(default="viewer", pattern="^(admin|viewer)$")


class UserUpdate(BaseModel):
    """Request to update a user."""

    name: Optional[str] = None
    role: Optional[str] = Field(default=None, pattern="^(admin|viewer)$")


class UserResponse(BaseModel):
    """User response."""

    id: UUID
    email: str
    name: Optional[str]
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """
    Paginated list of users.

    Uses standardized pagination format with consistent field naming.
    """

    items: list[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_more: bool


@router.get("", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, alias="limit", description="Items per page"),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> UserListResponse:
    """
    List all users in the tenant with pagination.

    Uses standardized pagination format with consistent field naming:
    - `items`: List of users
    - `total`: Total number of users
    - `page`: Current page number
    - `page_size`: Items per page
    - `total_pages`: Total number of pages
    - `has_more`: Whether there are more pages
    """
    # Get total count
    count_query = select(func.count(User.id)).where(User.tenant_id == user.tenant_id)
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    # Get users
    offset = (page - 1) * page_size
    query = (
        select(User)
        .where(User.tenant_id == user.tenant_id)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(query)
    users = result.scalars().all()

    return UserListResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_more=page < total_pages,
    )


@router.post("", response_model=UserResponse, status_code=201)
async def create_user(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_session),
    current_user=Depends(require_admin),
):
    """Create a new user."""
    # Check if user already exists
    existing = await session.execute(
        select(User).where(
            User.tenant_id == current_user.tenant_id,
            User.email == user_data.email,
        )
    )
    if existing.scalar_one_or_none():
        raise ConflictError(
            message="User with this email already exists",
            details={"email": user_data.email}
        )

    # Create user
    new_user = User(
        tenant_id=current_user.tenant_id,
        email=user_data.email,
        name=user_data.name,
        role=user_data.role,
    )
    session.add(new_user)
    await session.flush()

    # Refresh to load server-generated defaults (created_at)
    await session.refresh(new_user)

    return new_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user=Depends(get_current_user),
):
    """Get user details."""
    user = await session.get(User, user_id)
    if not user or user.tenant_id != current_user.tenant_id:
        raise NotFoundError(
            message="User not found",
            details={"user_id": str(user_id)}
        )
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_data: UserUpdate,
    session: AsyncSession = Depends(get_session),
    current_user=Depends(require_admin),
):
    """Update user details."""
    user = await session.get(User, user_id)
    if not user or user.tenant_id != current_user.tenant_id:
        raise NotFoundError(
            message="User not found",
            details={"user_id": str(user_id)}
        )

    if user_data.name is not None:
        user.name = user_data.name
    if user_data.role is not None:
        user.role = user_data.role

    await session.flush()
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user=Depends(require_admin),
):
    """Delete a user."""
    user = await session.get(User, user_id)
    if not user or user.tenant_id != current_user.tenant_id:
        raise NotFoundError(
            message="User not found",
            details={"user_id": str(user_id)}
        )

    # Prevent self-deletion
    if user.id == current_user.id:
        raise BadRequestError(
            message="Cannot delete yourself",
            details={"user_id": str(user_id)}
        )

    await session.delete(user)
    await session.flush()

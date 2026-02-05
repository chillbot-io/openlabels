"""
User management API endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import User, Tenant
from openlabels.server.schemas.pagination import (
    PaginatedResponse,
    PaginationParams,
    paginate_query,
)
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


@router.get("", response_model=PaginatedResponse[UserResponse])
async def list_users(
    pagination: PaginationParams = Depends(),
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
) -> PaginatedResponse[UserResponse]:
    """List all users in the tenant."""
    query = (
        select(User)
        .where(User.tenant_id == user.tenant_id)
        .order_by(User.created_at.desc())
    )

    result = await paginate_query(
        session,
        query,
        pagination,
        transformer=lambda u: UserResponse.model_validate(u),
    )

    return PaginatedResponse[UserResponse](**result)


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
        raise HTTPException(status_code=409, detail="User with this email already exists")

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
        raise HTTPException(status_code=404, detail="User not found")
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
        raise HTTPException(status_code=404, detail="User not found")

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
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent self-deletion
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    await session.delete(user)
    await session.flush()

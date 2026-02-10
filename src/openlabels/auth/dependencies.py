"""
FastAPI dependencies for authentication and role-based access control.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import Any
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.oauth import TokenClaims, validate_token
from openlabels.exceptions import AuthError
from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.models import Tenant, User

logger = logging.getLogger(__name__)

# OAuth2 scheme
settings = get_settings()
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"https://login.microsoftonline.com/{settings.auth.tenant_id or 'common'}/oauth2/v2.0/authorize",
    tokenUrl=f"https://login.microsoftonline.com/{settings.auth.tenant_id or 'common'}/oauth2/v2.0/token",
    auto_error=False,  # Don't auto-error so we can handle dev mode
)


class CurrentUser(BaseModel):
    """Current authenticated user context."""

    id: UUID
    tenant_id: UUID
    email: str
    name: str | None
    role: str

    model_config = ConfigDict(from_attributes=True)


async def get_or_create_user(
    session: AsyncSession,
    claims: TokenClaims,
) -> User:
    """Get existing user or create new one from token claims."""
    # First, ensure tenant exists
    tenant_query = select(Tenant).where(
        Tenant.azure_tenant_id == claims.tenant_id
    )
    tenant_result = await session.execute(tenant_query)
    tenant = tenant_result.scalar_one_or_none()

    if not tenant:
        # Create tenant
        tenant = Tenant(
            name=f"Tenant {claims.tenant_id[:8]}",
            azure_tenant_id=claims.tenant_id,
        )
        session.add(tenant)
        await session.flush()

    # Find or create user
    user_query = select(User).where(
        User.tenant_id == tenant.id,
        User.email == claims.preferred_username,
    )
    user_result = await session.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        # Determine role - first user is admin
        count_query = select(User.id).where(User.tenant_id == tenant.id)
        count_result = await session.execute(count_query)
        is_first_user = len(count_result.all()) == 0

        user = User(
            tenant_id=tenant.id,
            email=claims.preferred_username,
            name=claims.name,
            azure_oid=claims.oid,
            role="admin" if is_first_user or "admin" in claims.roles else "viewer",
        )
        session.add(user)
        await session.flush()
    else:
        # Update name if changed
        if claims.name and user.name != claims.name:
            user.name = claims.name

    return user


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> CurrentUser:
    """Get the current authenticated user."""
    settings = get_settings()

    if settings.auth.provider == "none":
        if not settings.server.debug:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Auth provider 'none' requires server.debug=True. "
                "Set AUTH_PROVIDER=azure_ad for production or "
                "OPENLABELS_SERVER__DEBUG=true for development.",
            )
        # Development mode - create/get dev user
        claims = TokenClaims(
            oid="dev-user-oid",
            preferred_username="dev@localhost",
            name="Development User",
            tenant_id="dev-tenant",
            roles=["admin"],
        )
    else:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            claims = await validate_token(token)
        except (ValueError, AuthError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    user = await get_or_create_user(session, claims)
    return CurrentUser.model_validate(user)


async def get_optional_user(
    token: str | None = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> CurrentUser | None:
    """Get the current user if authenticated, or None if not.

    Use this for routes where authentication is optional (e.g., pages that
    show different content for authenticated vs anonymous users).
    """
    settings = get_settings()

    if settings.auth.provider == "none":
        if not settings.server.debug:
            return None
        # Development mode - create/get dev user
        claims = TokenClaims(
            oid="dev-user-oid",
            preferred_username="dev@localhost",
            name="Development User",
            tenant_id="dev-tenant",
            roles=["admin"],
        )
        user = await get_or_create_user(session, claims)
        return CurrentUser.model_validate(user)

    if not token:
        return None

    try:
        claims = await validate_token(token)
        user = await get_or_create_user(session, claims)
        return CurrentUser.model_validate(user)
    except (ValueError, AuthError):
        # Invalid or expired token — user is not authenticated
        return None
    except Exception as e:
        # Log unexpected errors in authentication (e.g. DB issues)
        logger.debug(f"Authentication check failed: {type(e).__name__}: {e}")
        return None


# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------

# Type alias for the dependency callable returned by require_role().
_RoleDep = Callable[..., Coroutine[Any, Any, CurrentUser]]


def require_role(*allowed_roles: str) -> _RoleDep:
    """FastAPI dependency factory that enforces role-based access.

    Usage::

        @router.delete("/{id}", dependencies=[Depends(require_role("admin"))])
        async def delete_item(id: UUID): ...

        @router.get("/report", dependencies=[Depends(require_role("admin", "operator"))])
        async def get_report(): ...
    """
    async def _check_role(
        user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed_roles)}. "
                f"User has: {user.role}",
            )
        return user

    return _check_role


# Pre-built dependencies for common roles.
require_admin: _RoleDep = require_role("admin")
require_operator: _RoleDep = require_role("admin", "operator")
require_viewer: _RoleDep = require_role("admin", "operator", "viewer")

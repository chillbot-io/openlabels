"""
FastAPI dependencies for authentication and role-based access control.

Supports Azure AD, generic OIDC, and dev-mode authentication.
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
from openlabels.server.logging import set_tenant_id, set_user_id
from openlabels.server.models import Tenant, User

logger = logging.getLogger(__name__)

# Claims used in development mode (auth.provider == "none" + server.debug)
_DEV_CLAIMS = TokenClaims(
    oid="dev-user-oid",
    preferred_username="dev@localhost",
    name="Development User",
    tenant_id="dev-tenant",
    roles=["admin"],
    provider="none",
)


def _build_oauth2_scheme() -> OAuth2AuthorizationCodeBearer:
    """Build OAuth2 scheme based on current auth provider config."""
    settings = get_settings()

    if settings.auth.provider == "oidc" and settings.auth.oidc.discovery_url:
        # For OIDC, we don't know the exact URLs at import time
        # (they come from discovery), so use placeholder URLs.
        # The actual auth flow is handled by the routes, not this scheme.
        return OAuth2AuthorizationCodeBearer(
            authorizationUrl="/api/v1/auth/login",
            tokenUrl="/api/v1/auth/token",
            auto_error=False,
        )

    # Azure AD or fallback
    tenant_id = settings.auth.tenant_id or "common"
    return OAuth2AuthorizationCodeBearer(
        authorizationUrl=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        tokenUrl=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        auto_error=False,
    )


# OAuth2 scheme
oauth2_scheme = _build_oauth2_scheme()


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
    """Get existing user or create new one from token claims.

    Works with any auth provider: Azure AD, generic OIDC, or dev mode.
    Uses provider-agnostic fields (idp_tenant_id, external_id) for lookups,
    with fallback to legacy fields (azure_tenant_id, azure_oid) for backward
    compatibility during migration.
    """
    provider = claims.provider

    # First, find or create tenant
    tenant = await _find_or_create_tenant(session, claims, provider)

    # Find or create user
    user = await _find_or_create_user(session, tenant, claims, provider)

    return user


async def _find_or_create_tenant(
    session: AsyncSession,
    claims: TokenClaims,
    provider: str,
) -> Tenant:
    """Find existing tenant or create new one."""
    tenant = None

    # Try provider-agnostic lookup first
    if claims.tenant_id:
        tenant_query = select(Tenant).where(
            Tenant.idp_tenant_id == claims.tenant_id
        )
        result = await session.execute(tenant_query)
        tenant = result.scalars().first()

    # Fallback: try legacy azure_tenant_id lookup
    if not tenant and claims.tenant_id:
        tenant_query = select(Tenant).where(
            Tenant.azure_tenant_id == claims.tenant_id
        )
        result = await session.execute(tenant_query)
        tenant = result.scalars().first()
        # If found via legacy field, backfill the new field
        if tenant and not tenant.idp_tenant_id:
            tenant.idp_tenant_id = claims.tenant_id

    if not tenant:
        # Create tenant
        tenant = Tenant(
            name=f"Tenant {claims.tenant_id[:8]}",
            azure_tenant_id=claims.tenant_id if provider == "azure_ad" else None,
            idp_tenant_id=claims.tenant_id,
            auth_provider=provider,
        )
        session.add(tenant)
        await session.flush()

    return tenant


async def _find_or_create_user(
    session: AsyncSession,
    tenant: Tenant,
    claims: TokenClaims,
    provider: str,
) -> User:
    """Find existing user or create new one."""
    # Look up by email within tenant (email is the canonical identity)
    user_query = select(User).where(
        User.tenant_id == tenant.id,
        User.email == claims.preferred_username,
    )
    user_result = await session.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        # Determine role - first user is admin
        # SECURITY: Lock the tenant row to serialize concurrent user creation and
        # prevent a TOCTOU race where two requests both see zero users and both
        # become admin.
        await session.execute(
            select(Tenant).where(Tenant.id == tenant.id).with_for_update()
        )
        from sqlalchemy import func as sa_func
        count_query = (
            select(sa_func.count()).select_from(User)
            .where(User.tenant_id == tenant.id)
        )
        count_result = await session.execute(count_query)
        is_first_user = (count_result.scalar() or 0) == 0

        user = User(
            tenant_id=tenant.id,
            email=claims.preferred_username,
            name=claims.name,
            azure_oid=claims.oid if provider == "azure_ad" else None,
            external_id=claims.oid,
            auth_provider=provider,
            role="admin" if is_first_user or "admin" in claims.roles else "viewer",
        )
        session.add(user)
        await session.flush()
    else:
        # Update name if changed
        if claims.name and user.name != claims.name:
            user.name = claims.name
        # Sync role from claims (e.g. admin granted via IdP)
        expected_role = "admin" if "admin" in claims.roles else user.role
        if user.role != expected_role:
            user.role = expected_role
        # Backfill external_id if missing (migration from azure_oid)
        if not user.external_id and claims.oid:
            user.external_id = claims.oid
            user.auth_provider = provider

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
                "Set AUTH_PROVIDER=azure_ad or AUTH_PROVIDER=oidc for production or "
                "OPENLABELS_SERVER__DEBUG=true for development.",
            )
        claims = _DEV_CLAIMS
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
            # SECURITY: Log specific error server-side; return generic message to client
            logger.debug("Token validation failed: %s", e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    user = await get_or_create_user(session, claims)
    cu = CurrentUser.model_validate(user)
    set_tenant_id(str(cu.tenant_id))
    set_user_id(str(cu.id))
    return cu


async def get_optional_user(
    token: str | None = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
) -> CurrentUser | None:
    """Get the current user if authenticated, or None if not."""
    settings = get_settings()

    if settings.auth.provider == "none":
        if not settings.server.debug:
            return None
        user = await get_or_create_user(session, _DEV_CLAIMS)
        return CurrentUser.model_validate(user)

    if not token:
        return None

    try:
        claims = await validate_token(token)
        user = await get_or_create_user(session, claims)
        return CurrentUser.model_validate(user)
    except (ValueError, AuthError):
        return None


# Role-based access control
_RoleDep = Callable[..., Coroutine[Any, Any, CurrentUser]]


def require_role(*allowed_roles: str) -> _RoleDep:
    """FastAPI dependency factory that enforces role-based access."""
    async def _check_role(
        user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if user.role not in allowed_roles:
            logger.debug(
                "RBAC denied: user %s (role=%s) needs one of %s",
                user.email, user.role, allowed_roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _check_role


# Pre-built dependencies for common roles.
require_admin: _RoleDep = require_role("admin")
require_operator: _RoleDep = require_role("admin")
require_viewer: _RoleDep = require_role("admin", "viewer")

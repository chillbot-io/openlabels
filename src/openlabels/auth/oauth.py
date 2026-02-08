"""
OAuth 2.0 / OIDC authentication with Azure AD.

Features:
- JWT token validation against Azure AD JWKS
- Thread-safe JWKS caching with asyncio.Lock
- Automatic JWKS refresh on key-not-found (key rotation)
- Granular token error types (expired vs invalid)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

import httpx
from jose import jwt, JWTError  # type: ignore[import-untyped]
from pydantic import BaseModel, model_validator

from openlabels.exceptions import TokenExpiredError, TokenInvalidError
from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)


class TokenClaims(BaseModel):
    """Claims extracted from a validated JWT token."""

    oid: str  # Azure AD object ID
    preferred_username: str  # Email/UPN
    name: Optional[str] = None
    tenant_id: str
    roles: list[str] = []

    @model_validator(mode="before")
    @classmethod
    def validate_required_claims(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Validate security-critical claims are not empty."""
        if isinstance(data, dict):
            oid = data.get("oid", "")
            if not oid or not str(oid).strip():
                raise ValueError("oid cannot be empty - this would allow impersonation")
            tenant_id = data.get("tenant_id", "")
            if not tenant_id or not str(tenant_id).strip():
                raise ValueError("tenant_id cannot be empty")
        return data


# ---------------------------------------------------------------------------
# JWKS cache with async-safe locking
# ---------------------------------------------------------------------------

# Maps tenant_id -> (jwks_data, fetched_at_monotonic)
_jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}
_jwks_lock = asyncio.Lock()

# JWKS cache TTL in seconds (1 hour) — ensures rotated keys are picked up
_JWKS_CACHE_TTL_SECONDS = 3600

# Timeout for JWKS HTTP fetch
_JWKS_FETCH_TIMEOUT_SECONDS = 10.0


async def get_jwks(tenant_id: str) -> dict[str, Any]:
    """Fetch JWKS (JSON Web Key Set) from Azure AD with TTL-based caching.

    Uses double-checked locking so that concurrent requests waiting for the
    same tenant don't all fetch simultaneously.
    """
    now = time.monotonic()

    # Fast path: check cache without lock
    if tenant_id in _jwks_cache:
        cached_data, fetched_at = _jwks_cache[tenant_id]
        if now - fetched_at < _JWKS_CACHE_TTL_SECONDS:
            return cached_data

    # Acquire lock for cache update
    async with _jwks_lock:
        # Re-check after acquiring lock (another coroutine may have refreshed)
        now = time.monotonic()
        if tenant_id in _jwks_cache:
            cached_data, fetched_at = _jwks_cache[tenant_id]
            if now - fetched_at < _JWKS_CACHE_TTL_SECONDS:
                return cached_data

        # Fetch fresh JWKS
        jwks_uri = (
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        )
        async with httpx.AsyncClient(timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            jwks_data: dict[str, Any] = response.json()
            _jwks_cache[tenant_id] = (jwks_data, time.monotonic())
            return jwks_data


async def _find_signing_key(kid: str, tenant_id: str) -> dict[str, Any]:
    """Find the signing key matching *kid*, refreshing the cache if needed.

    Azure AD rotates keys periodically.  If a token arrives signed with a
    key not yet in our cache, we evict the cached JWKS for *tenant_id* and
    re-fetch before giving up.
    """
    jwks = await get_jwks(tenant_id)
    keys: list[dict[str, Any]] = jwks.get("keys", [])
    for k in keys:
        if k.get("kid") == kid:
            return k

    # Key not found — force refresh (Azure AD may have rotated keys)
    _jwks_cache.pop(tenant_id, None)
    jwks = await get_jwks(tenant_id)
    keys = jwks.get("keys", [])
    for k in keys:
        if k.get("kid") == kid:
            return k

    raise TokenInvalidError("Unable to find signing key after cache refresh")


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


async def validate_token(token: str) -> TokenClaims:
    """Validate an Azure AD access token and extract claims.

    Raises:
        TokenExpiredError: If the token has expired.
        TokenInvalidError: If the token is malformed, has an invalid
            signature, or the signing key cannot be found.
        ValueError: If auth is misconfigured (provider "none" in prod).
    """
    settings = get_settings()

    if settings.auth.provider == "none":
        if not settings.server.debug:
            raise ValueError(
                "Auth provider 'none' is only allowed when server.debug is True. "
                "Refusing to bypass authentication in non-debug mode."
            )
        # Return mock claims for development
        return TokenClaims(
            oid="dev-user-oid",
            preferred_username="dev@localhost",
            name="Development User",
            tenant_id="dev-tenant",
            roles=["admin"],
        )

    tenant_id = settings.auth.tenant_id
    if not tenant_id:
        raise TokenInvalidError("auth.tenant_id is not configured")

    try:
        # Decode header to get kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        # Find signing key (with automatic cache refresh on rotation)
        key = await _find_signing_key(kid, tenant_id)

        # Validate and decode
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.auth.client_id,
            issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        )

        return TokenClaims(
            oid=claims["oid"],
            preferred_username=claims["preferred_username"],
            name=claims.get("name"),
            tenant_id=claims.get("tid", tenant_id),
            roles=claims.get("roles", []),
        )

    except (TokenExpiredError, TokenInvalidError):
        raise
    except JWTError as e:
        error_str = str(e).lower()
        if "expired" in error_str:
            raise TokenExpiredError(f"Token expired: {e}")
        elif "signature" in error_str:
            raise TokenInvalidError(f"Invalid signature: {e}")
        else:
            raise TokenInvalidError(f"Invalid token: {e}")


def clear_jwks_cache() -> None:
    """Clear the JWKS cache (useful for testing or key rotation)."""
    _jwks_cache.clear()

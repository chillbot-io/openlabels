"""
OAuth 2.0 / OIDC token validation.

Supports:
- Azure AD via direct JWKS validation (provider="azure_ad")
- Generic OIDC via discovery document (provider="oidc")
- Dev mode bypass (provider="none" + debug=True)

Features:
- JWT token validation against provider JWKS
- Thread-safe JWKS caching with asyncio.Lock
- Automatic JWKS refresh on key rotation
- Granular token error types (expired vs invalid)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, PyJWTError
from pydantic import BaseModel, model_validator

from openlabels.exceptions import TokenExpiredError, TokenInvalidError
from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)


class TokenClaims(BaseModel):
    """Claims extracted from a validated JWT token.

    Provider-agnostic: works with both Azure AD and generic OIDC providers.
    The `oid` field holds the external user identifier from any provider
    (Azure AD object ID, OIDC subject, etc.).
    """

    oid: str  # External user ID (Azure AD oid, OIDC sub, etc.)
    preferred_username: str  # Email/UPN
    name: str | None = None
    tenant_id: str
    roles: list[str] = []
    provider: str = "azure_ad"  # Which provider issued this token

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


# JWKS cache with async-safe locking (for Azure AD direct validation)
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


async def _validate_azure_ad_token(token: str) -> TokenClaims:
    """Validate an Azure AD access token and extract claims."""
    settings = get_settings()
    tenant_id = settings.auth.tenant_id
    if not tenant_id:
        raise TokenInvalidError("auth.tenant_id is not configured")

    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise TokenInvalidError("Token header missing 'kid' claim")

        key_data = await _find_signing_key(kid, tenant_id)
        signing_key = jwt.PyJWK(key_data)

        claims = jwt.decode(
            token,
            signing_key,
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
            provider="azure_ad",
        )

    except (TokenExpiredError, TokenInvalidError):
        raise
    except ExpiredSignatureError as e:
        raise TokenExpiredError(f"Token expired: {e}") from e
    except InvalidSignatureError as e:
        raise TokenInvalidError(f"Invalid signature: {e}") from e
    except PyJWTError as e:
        raise TokenInvalidError(f"Invalid token: {e}") from e


async def _validate_oidc_token(token: str) -> TokenClaims:
    """Validate a generic OIDC id_token and extract claims."""
    from openlabels.auth.oidc_provider import (
        extract_claims,
        get_discovery,
        validate_id_token,
    )

    settings = get_settings()
    oidc_config = settings.auth.oidc

    if not oidc_config.discovery_url:
        raise TokenInvalidError("auth.oidc.discovery_url is not configured")

    discovery = await get_discovery(oidc_config.discovery_url)
    raw_claims = await validate_id_token(token, discovery, oidc_config)
    normalized = extract_claims(raw_claims, oidc_config)

    return TokenClaims(
        oid=normalized.sub,
        preferred_username=normalized.email,
        name=normalized.name,
        tenant_id=normalized.tenant_id,
        roles=normalized.roles,
        provider="oidc",
    )


async def validate_token(token: str) -> TokenClaims:
    """Validate a token and extract claims.

    Dispatches to the appropriate provider based on auth settings.

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
        return TokenClaims(
            oid="dev-user-oid",
            preferred_username="dev@localhost",
            name="Development User",
            tenant_id="dev-tenant",
            roles=["admin"],
            provider="none",
        )

    if settings.auth.provider == "oidc":
        return await _validate_oidc_token(token)

    # Default: azure_ad
    return await _validate_azure_ad_token(token)


def clear_jwks_cache() -> None:
    """Clear the JWKS cache (useful for testing or key rotation)."""
    _jwks_cache.clear()

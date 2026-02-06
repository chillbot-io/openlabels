"""
OAuth 2.0 / OIDC authentication with Azure AD.
"""

from typing import Optional
import httpx
from jose import jwt, JWTError
from pydantic import BaseModel, model_validator

from openlabels.server.config import get_settings


class TokenClaims(BaseModel):
    """Claims extracted from a validated JWT token."""

    oid: str  # Azure AD object ID
    preferred_username: str  # Email/UPN
    name: Optional[str] = None
    tenant_id: str
    roles: list[str] = []

    @model_validator(mode="before")
    @classmethod
    def validate_required_claims(cls, data):
        """Validate security-critical claims are not empty."""
        if isinstance(data, dict):
            oid = data.get("oid", "")
            if not oid or not str(oid).strip():
                raise ValueError("oid cannot be empty - this would allow impersonation")
            tenant_id = data.get("tenant_id", "")
            if not tenant_id or not str(tenant_id).strip():
                raise ValueError("tenant_id cannot be empty")
        return data


# Cache for JWKS: maps tenant_id -> (jwks_data, fetched_at)
_jwks_cache: dict[str, tuple[dict, float]] = {}

# JWKS cache TTL in seconds (1 hour) — ensures rotated keys are picked up
_JWKS_CACHE_TTL_SECONDS = 3600

# Timeout for JWKS fetch to prevent hanging the server
_JWKS_FETCH_TIMEOUT_SECONDS = 10.0


async def get_jwks(tenant_id: str) -> dict:
    """Fetch JWKS (JSON Web Key Set) from Azure AD with TTL-based caching."""
    import time

    now = time.monotonic()

    if tenant_id in _jwks_cache:
        cached_data, fetched_at = _jwks_cache[tenant_id]
        if now - fetched_at < _JWKS_CACHE_TTL_SECONDS:
            return cached_data

    jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    async with httpx.AsyncClient(timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        jwks_data = response.json()
        _jwks_cache[tenant_id] = (jwks_data, now)
        return jwks_data


async def validate_token(token: str) -> TokenClaims:
    """Validate an Azure AD access token and extract claims."""
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

    try:
        # Decode header to get kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        # Get JWKS
        jwks = await get_jwks(settings.auth.tenant_id)

        # Find the key
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = k
                break

        if not key:
            raise ValueError("Unable to find signing key")

        # Validate and decode
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.auth.client_id,
            issuer=f"https://login.microsoftonline.com/{settings.auth.tenant_id}/v2.0",
        )

        return TokenClaims(
            oid=claims["oid"],
            preferred_username=claims["preferred_username"],
            name=claims.get("name"),
            tenant_id=claims.get("tid", settings.auth.tenant_id),
            roles=claims.get("roles", []),
        )

    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


def clear_jwks_cache():
    """Clear the JWKS cache (useful for testing or key rotation)."""
    _jwks_cache.clear()

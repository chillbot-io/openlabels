"""
OAuth 2.0 / OIDC authentication with Azure AD.
"""

from typing import Optional
import httpx
from jose import jwt, JWTError
from pydantic import BaseModel

from openlabels.server.config import get_settings


class TokenClaims(BaseModel):
    """Claims extracted from a validated JWT token."""

    oid: str  # Azure AD object ID
    preferred_username: str  # Email/UPN
    name: Optional[str] = None
    tenant_id: str
    roles: list[str] = []


# Cache for JWKS
_jwks_cache: dict = {}


async def get_jwks(tenant_id: str) -> dict:
    """Fetch JWKS (JSON Web Key Set) from Azure AD."""
    if tenant_id in _jwks_cache:
        return _jwks_cache[tenant_id]

    jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    async with httpx.AsyncClient() as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        _jwks_cache[tenant_id] = response.json()
        return _jwks_cache[tenant_id]


async def validate_token(token: str) -> TokenClaims:
    """Validate an Azure AD access token and extract claims."""
    settings = get_settings()

    if settings.auth.provider == "none":
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
    global _jwks_cache
    _jwks_cache = {}

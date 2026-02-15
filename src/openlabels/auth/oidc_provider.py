"""
Generic OIDC authentication provider.

Uses standard OpenID Connect Discovery and Authorization Code flow
to support any OIDC-compliant identity provider:
- Okta
- Google Workspace
- Keycloak
- Auth0
- PingFederate
- Azure AD (via standard OIDC, not MSAL)
- Any provider with a .well-known/openid-configuration endpoint

The provider fetches the OIDC discovery document on first use,
caches it, and uses it to build authorization URLs, exchange
codes for tokens, and fetch JWKS for token validation.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, PyJWTError

from openlabels.exceptions import TokenExpiredError, TokenInvalidError
from openlabels.server.config import OIDCProviderSettings

logger = logging.getLogger(__name__)

# Cache TTLs
_DISCOVERY_CACHE_TTL = 3600  # 1 hour
_JWKS_CACHE_TTL = 3600  # 1 hour
_FETCH_TIMEOUT = 10.0

# Module-level caches
_discovery_cache: dict[str, tuple[dict[str, Any], float]] = {}
_jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}
_cache_lock = asyncio.Lock()


class OIDCTokenClaims:
    """Normalized claims from a validated OIDC token.

    Different providers use different claim names. This class
    normalizes them using the configured claim mapping.
    """

    def __init__(
        self,
        sub: str,
        email: str,
        name: str | None,
        tenant_id: str,
        roles: list[str],
        raw_claims: dict[str, Any],
    ):
        self.sub = sub
        self.email = email
        self.name = name
        self.tenant_id = tenant_id
        self.roles = roles
        self.raw_claims = raw_claims


async def get_discovery(discovery_url: str) -> dict[str, Any]:
    """Fetch and cache the OIDC discovery document.

    The discovery document (RFC 8414) provides:
    - authorization_endpoint
    - token_endpoint
    - jwks_uri
    - issuer
    - supported scopes, claims, etc.
    """
    now = time.monotonic()

    # Fast path: check cache without lock
    if discovery_url in _discovery_cache:
        cached, fetched_at = _discovery_cache[discovery_url]
        if now - fetched_at < _DISCOVERY_CACHE_TTL:
            return cached

    async with _cache_lock:
        # Re-check after acquiring lock
        now = time.monotonic()
        if discovery_url in _discovery_cache:
            cached, fetched_at = _discovery_cache[discovery_url]
            if now - fetched_at < _DISCOVERY_CACHE_TTL:
                return cached

        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT) as client:
            resp = await client.get(discovery_url)
            resp.raise_for_status()
            doc = resp.json()

        # Validate required fields
        required = ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"]
        missing = [f for f in required if f not in doc]
        if missing:
            raise ValueError(
                f"OIDC discovery document at {discovery_url} is missing "
                f"required fields: {', '.join(missing)}"
            )

        _discovery_cache[discovery_url] = (doc, time.monotonic())
        logger.info("Cached OIDC discovery document from %s", discovery_url)
        return doc


async def _get_jwks(jwks_uri: str) -> dict[str, Any]:
    """Fetch and cache JWKS from the provider."""
    now = time.monotonic()

    if jwks_uri in _jwks_cache:
        cached, fetched_at = _jwks_cache[jwks_uri]
        if now - fetched_at < _JWKS_CACHE_TTL:
            return cached

    async with _cache_lock:
        now = time.monotonic()
        if jwks_uri in _jwks_cache:
            cached, fetched_at = _jwks_cache[jwks_uri]
            if now - fetched_at < _JWKS_CACHE_TTL:
                return cached

        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT) as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            jwks = resp.json()

        _jwks_cache[jwks_uri] = (jwks, time.monotonic())
        return jwks


async def _find_signing_key(kid: str | None, jwks_uri: str) -> dict[str, Any]:
    """Find signing key by kid, refreshing cache if needed.

    If kid is None (some providers omit it), use the sole key if exactly
    one signing key exists; otherwise raise an error.
    """
    jwks = await _get_jwks(jwks_uri)
    keys: list[dict[str, Any]] = jwks.get("keys", [])

    if kid is None:
        # No kid header — only safe if there's exactly one signing key
        signing_keys = [k for k in keys if k.get("use", "sig") == "sig"]
        if len(signing_keys) == 1:
            return signing_keys[0]
        raise TokenInvalidError(
            f"Token has no 'kid' header and JWKS has {len(signing_keys)} signing keys"
        )

    for k in keys:
        if k.get("kid") == kid:
            return k

    # Key not found — force refresh (provider may have rotated keys)
    _jwks_cache.pop(jwks_uri, None)
    jwks = await _get_jwks(jwks_uri)
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k

    raise TokenInvalidError("Unable to find signing key after cache refresh")


def get_authorization_url(
    discovery: dict[str, Any],
    config: OIDCProviderSettings,
    state: str,
    redirect_uri: str,
    nonce: str | None = None,
) -> str:
    """Build the authorization URL for the OIDC provider.

    Args:
        discovery: The OIDC discovery document
        config: Provider settings
        state: CSRF state parameter
        redirect_uri: Where the provider should redirect after auth
        nonce: Optional nonce for replay protection
    """
    auth_endpoint = discovery["authorization_endpoint"]
    params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": redirect_uri,
        "scope": config.scopes,
        "state": state,
    }
    if nonce:
        params["nonce"] = nonce

    url = httpx.URL(auth_endpoint, params=params)
    return str(url)


async def exchange_code(
    discovery: dict[str, Any],
    config: OIDCProviderSettings,
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange authorization code for tokens.

    Returns the full token response including:
    - access_token
    - id_token
    - refresh_token (if available)
    - expires_in
    - token_type
    """
    token_endpoint = discovery["token_endpoint"]

    async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
        )

        if resp.status_code != 200:
            try:
                error_body = resp.json()
            except Exception:
                error_body = {"error": "unknown", "error_description": resp.text[:200]}
            logger.error(
                "OIDC token exchange failed: %s - %s",
                error_body.get("error"),
                error_body.get("error_description"),
            )
            return {"error": error_body.get("error", "token_exchange_failed"),
                    "error_description": error_body.get("error_description", "")}

        return resp.json()


async def validate_id_token(
    id_token: str,
    discovery: dict[str, Any],
    config: OIDCProviderSettings,
) -> dict[str, Any]:
    """Validate an OIDC id_token and return its claims.

    Validates:
    - Signature against provider's JWKS
    - Issuer matches discovery document
    - Audience matches client_id
    - Expiration

    Returns raw decoded claims dict.
    """
    jwks_uri = discovery["jwks_uri"]
    issuer = discovery["issuer"]

    try:
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")

        key_data = await _find_signing_key(kid, jwks_uri)
        signing_key = jwt.PyJWK(key_data)

        # Some providers use RS256, others ES256 — accept common algorithms
        algorithms = unverified_header.get("alg", "RS256")
        if algorithms not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"):
            raise TokenInvalidError(f"Unsupported algorithm: {algorithms}")

        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=[algorithms],
            audience=config.client_id,
            issuer=issuer,
            options={"verify_at_hash": False},  # Not all providers include at_hash
        )
        return claims

    except ExpiredSignatureError as e:
        raise TokenExpiredError(f"ID token expired: {e}") from e
    except InvalidSignatureError as e:
        raise TokenInvalidError(f"Invalid signature: {e}") from e
    except PyJWTError as e:
        raise TokenInvalidError(f"Invalid token: {e}") from e


def extract_claims(
    raw_claims: dict[str, Any],
    config: OIDCProviderSettings,
) -> OIDCTokenClaims:
    """Extract and normalize claims using the configured claim mapping.

    Maps provider-specific claim names to standard OpenLabels fields.
    """
    sub = raw_claims.get(config.claim_sub, "")
    if not sub:
        raise TokenInvalidError(
            f"Required claim '{config.claim_sub}' (sub) is missing or empty"
        )

    email = raw_claims.get(config.claim_email, "")
    if not email:
        # Fallback: some providers put email in preferred_username or upn
        email = raw_claims.get("preferred_username", raw_claims.get("upn", ""))
    if not email:
        raise TokenInvalidError(
            f"Required claim '{config.claim_email}' (email) is missing or empty"
        )

    name = raw_claims.get(config.claim_name)

    # Tenant: if claim_tenant is configured, extract it; otherwise use a default
    tenant_id = ""
    if config.claim_tenant:
        tenant_id = raw_claims.get(config.claim_tenant, "")
    if not tenant_id:
        # Single-tenant mode: use a hash of the issuer as tenant ID
        tenant_id = f"oidc-{_stable_hash(raw_claims.get('iss', 'default'))}"

    # Roles: may be a list, a space-separated string, or a comma-separated string
    roles_raw = raw_claims.get(config.claim_roles, [])
    if isinstance(roles_raw, str):
        roles = [r.strip() for r in roles_raw.replace(",", " ").split() if r.strip()]
    elif isinstance(roles_raw, list):
        roles = [str(r) for r in roles_raw]
    else:
        roles = []

    return OIDCTokenClaims(
        sub=str(sub),
        email=str(email),
        name=str(name) if name else None,
        tenant_id=str(tenant_id),
        roles=roles,
        raw_claims=raw_claims,
    )


async def refresh_token(
    discovery: dict[str, Any],
    config: OIDCProviderSettings,
    refresh_token_value: str,
) -> dict[str, Any]:
    """Refresh an access token using a refresh token.

    Returns the full token response.
    """
    token_endpoint = discovery["token_endpoint"]

    async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "refresh_token",
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "refresh_token": refresh_token_value,
            },
            headers={"Accept": "application/json"},
        )

        if resp.status_code != 200:
            try:
                error_body = resp.json()
            except Exception:
                error_body = {"error": "unknown"}
            return {"error": error_body.get("error", "refresh_failed")}

        return resp.json()


def get_end_session_url(
    discovery: dict[str, Any],
    config: OIDCProviderSettings,
    post_logout_redirect_uri: str,
    id_token_hint: str | None = None,
) -> str | None:
    """Get the provider's logout/end-session URL if supported.

    Returns None if the provider doesn't advertise an end_session_endpoint.
    """
    end_session_endpoint = discovery.get("end_session_endpoint")
    if not end_session_endpoint:
        return None

    params: dict[str, str] = {
        "client_id": config.client_id,
        "post_logout_redirect_uri": post_logout_redirect_uri,
    }
    if id_token_hint:
        params["id_token_hint"] = id_token_hint

    url = httpx.URL(end_session_endpoint, params=params)
    return str(url)


def _stable_hash(s: str) -> str:
    """Create a short stable hash for use as a default tenant ID."""
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def clear_oidc_cache() -> None:
    """Clear all OIDC caches (discovery + JWKS). Useful for testing."""
    _discovery_cache.clear()
    _jwks_cache.clear()

"""FastAPI dependencies for ScrubIQ API.

API Key Authentication:
- All protected endpoints require a valid API key via Bearer token
- API key is used for both authentication AND encryption key derivation
- Each API key gets an isolated ScrubIQ instance from the pool

Multi-tenancy:
- Instance pool manages per-API-key ScrubIQ instances
- Complete isolation: each key has its own tokens, conversations, audit log
- Shared: ML models, database connection, configuration

Usage:
    @router.get("/protected")
    def protected_endpoint(cr: ScrubIQ = Depends(require_api_key)):
        # cr is the isolated instance for this API key
        ...
"""

import logging
from typing import Optional, Tuple
from fastapi import Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..core import ScrubIQ
from ..services import APIKeyService, APIKeyMetadata
from ..instance_pool import get_pool, InstancePool
from .errors import unauthorized, forbidden, ErrorCode

logger = logging.getLogger(__name__)

# Security scheme for OpenAPI docs
bearer_scheme = HTTPBearer(auto_error=False)

# API key service (set during app initialization)
_api_key_service: Optional[APIKeyService] = None


def set_api_key_service(service: APIKeyService) -> None:
    """Set the global API key service (called by app lifespan)."""
    global _api_key_service
    _api_key_service = service


def get_api_key_service() -> APIKeyService:
    """Get the global API key service."""
    if _api_key_service is None:
        raise RuntimeError("API key service not initialized")
    return _api_key_service


def _extract_bearer_token(request: Request) -> Optional[str]:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1]


def _validate_api_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Tuple[str, APIKeyMetadata]:
    """
    Validate API key from Authorization header.

    Returns:
        (api_key, metadata) tuple

    Raises:
        HTTPException 401 if invalid or missing
    """
    # Get token from header
    token = None
    if credentials:
        token = credentials.credentials
    else:
        # Fallback to manual extraction (for non-browser clients)
        token = _extract_bearer_token(request)

    if not token:
        raise unauthorized(
            "API key required",
            error_code=ErrorCode.NOT_AUTHENTICATED,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate token
    service = get_api_key_service()
    metadata = service.validate_key(token)

    if metadata is None:
        # SECURITY: Don't log any part of the key - prevents key prefix enumeration
        logger.warning("Invalid API key authentication attempt")
        raise unauthorized(
            "Invalid API key",
            error_code=ErrorCode.NOT_AUTHENTICATED,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Store metadata in request state for rate limiting
    request.state.api_key = metadata

    return token, metadata


def require_api_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> ScrubIQ:
    """
    Dependency that requires a valid API key and returns isolated ScrubIQ instance.

    This is the main dependency for protected endpoints. It:
    1. Validates the API key
    2. Checks rate limit for the API key
    3. Derives the encryption key from the API key
    4. Gets or creates an isolated ScrubIQ instance from the pool
    5. Returns the ready-to-use instance

    Each API key gets complete isolation:
    - Own token store (PHI mappings)
    - Own conversations and messages
    - Own audit log entries
    - Own entity graph

    Usage:
        @router.post("/redact")
        def redact(cr: ScrubIQ = Depends(require_api_key)):
            return cr.redact(text)
    """
    api_key, metadata = _validate_api_key(request, credentials)

    # Check rate limit for this API key
    from ..rate_limiter import check_api_key_rate_limit
    check_api_key_rate_limit(request, action="api")

    # Derive encryption key from API key
    service = get_api_key_service()
    encryption_key = service.derive_encryption_key(api_key)

    # Get or create isolated instance from pool
    try:
        pool = get_pool()
        instance = pool.get_or_create(
            api_key_prefix=metadata.key_prefix,
            encryption_key=encryption_key,
        )
        return instance
    except Exception as e:
        logger.error(f"Failed to get instance for {metadata.key_prefix}: {e}")
        raise unauthorized(
            "Failed to initialize session",
            error_code=ErrorCode.NOT_AUTHENTICATED,
        )


def require_permission(permission: str):
    """
    Create a dependency that requires a specific permission.

    Usage:
        @router.delete("/keys/{prefix}")
        def delete_key(
            prefix: str,
            cr: ScrubIQ = Depends(require_permission("admin"))
        ):
            ...
    """
    def dependency(
        request: Request,
        cr: ScrubIQ = Depends(require_api_key),
    ) -> ScrubIQ:
        metadata: APIKeyMetadata = request.state.api_key
        if permission not in metadata.permissions:
            raise forbidden(
                f"Permission '{permission}' required",
                error_code=ErrorCode.PERMISSION_DENIED,
            )
        return cr

    return dependency


# Backward compatibility alias
require_unlocked = require_api_key

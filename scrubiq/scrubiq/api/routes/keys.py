"""API key management routes.

Endpoints for creating, listing, and revoking API keys.
All endpoints require admin permission except initial key creation.
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ...services import APIKeyService, APIKeyMetadata
from ..dependencies import (
    get_api_key_service,
    require_api_key,
    require_permission,
)
from ..errors import bad_request, not_found, forbidden, ErrorCode

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/keys", tags=["api-keys"])


# ============================================================================
# SCHEMAS
# ============================================================================


class CreateKeyRequest(BaseModel):
    """Request to create a new API key."""

    name: str = Field(..., min_length=1, max_length=100, description="Human-readable key name")
    rate_limit: int = Field(default=1000, ge=1, le=100000, description="Max requests per minute")
    permissions: Optional[List[str]] = Field(
        default=None,
        description="Permissions for this key (default: redact, restore, chat)"
    )


class CreateKeyResponse(BaseModel):
    """Response containing the newly created API key.

    IMPORTANT: The full key is only shown once. Store it securely.
    """

    key: str = Field(..., description="The full API key (only shown once!)")
    key_prefix: str = Field(..., description="Key prefix for identification")
    name: str
    created_at: str
    rate_limit: int
    permissions: List[str]


class KeyInfo(BaseModel):
    """Public information about an API key (no secrets)."""

    id: int
    key_prefix: str
    name: str
    created_at: str
    last_used_at: Optional[str]
    rate_limit: int
    permissions: List[str]
    revoked_at: Optional[str]
    is_active: bool


class ListKeysResponse(BaseModel):
    """Response containing list of API keys."""

    keys: List[KeyInfo]
    total: int


class UpdateKeyRequest(BaseModel):
    """Request to update an API key."""

    name: Optional[str] = Field(None, min_length=1, max_length=100)
    rate_limit: Optional[int] = Field(None, ge=1, le=100000)
    permissions: Optional[List[str]] = None


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _format_timestamp(ts: Optional[float]) -> Optional[str]:
    """Format Unix timestamp to ISO string."""
    if ts is None:
        return None
    return datetime.fromtimestamp(ts).isoformat()


def _metadata_to_info(meta: APIKeyMetadata) -> KeyInfo:
    """Convert APIKeyMetadata to KeyInfo response model."""
    return KeyInfo(
        id=meta.id,
        key_prefix=meta.key_prefix,
        name=meta.name,
        created_at=_format_timestamp(meta.created_at),
        last_used_at=_format_timestamp(meta.last_used_at),
        rate_limit=meta.rate_limit,
        permissions=meta.permissions,
        revoked_at=_format_timestamp(meta.revoked_at),
        is_active=meta.is_active,
    )


# ============================================================================
# ROUTES
# ============================================================================


@router.post("", response_model=CreateKeyResponse)
def create_key(
    req: CreateKeyRequest,
    request: Request,
    service: APIKeyService = Depends(get_api_key_service),
):
    """
    Create a new API key.

    For the first key (bootstrapping), no auth is required.
    Subsequent keys require admin permission.

    **IMPORTANT**: The full key is only returned once. Store it securely!
    """
    # Validate permissions early
    valid_permissions = {"redact", "restore", "chat", "admin", "files"}
    if req.permissions:
        invalid = set(req.permissions) - valid_permissions
        if invalid:
            raise bad_request(
                f"Invalid permissions: {invalid}. Valid: {valid_permissions}",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

    # Try atomic bootstrap first (race-condition safe)
    # This will succeed only if no keys exist yet
    bootstrap_result = service.create_bootstrap_key(
        name=req.name,
        rate_limit=req.rate_limit,
        permissions=req.permissions if req.permissions else ["redact", "restore", "chat", "admin"],
    )

    if bootstrap_result is not None:
        # This was the first key - no auth was needed
        full_key, metadata = bootstrap_result
        logger.info(f"Bootstrap API key created: {metadata.key_prefix}... ({req.name})")
        return CreateKeyResponse(
            key=full_key,
            key_prefix=metadata.key_prefix,
            name=metadata.name,
            created_at=_format_timestamp(metadata.created_at),
            rate_limit=metadata.rate_limit,
            permissions=metadata.permissions,
        )

    # Keys already exist - require admin permission
    if not hasattr(request.state, "api_key"):
        # Try to validate the request
        from ..dependencies import _extract_bearer_token
        token = _extract_bearer_token(request)
        if token:
            meta = service.validate_key(token)
            if meta and "admin" in meta.permissions:
                # Authorized
                pass
            else:
                raise forbidden(
                    "Admin permission required to create API keys",
                    error_code=ErrorCode.PERMISSION_DENIED,
                )
        else:
            raise forbidden(
                "API key with admin permission required",
                error_code=ErrorCode.PERMISSION_DENIED,
            )
    else:
        meta = request.state.api_key
        if "admin" not in meta.permissions:
            raise forbidden(
                "Admin permission required to create API keys",
                error_code=ErrorCode.PERMISSION_DENIED,
            )

    # Create the key (auth verified)
    full_key, metadata = service.create_key(
        name=req.name,
        rate_limit=req.rate_limit,
        permissions=req.permissions,
    )

    logger.info(f"API key created: {metadata.key_prefix}... ({req.name})")

    return CreateKeyResponse(
        key=full_key,
        key_prefix=metadata.key_prefix,
        name=metadata.name,
        created_at=_format_timestamp(metadata.created_at),
        rate_limit=metadata.rate_limit,
        permissions=metadata.permissions,
    )


@router.get("", response_model=ListKeysResponse)
def list_keys(
    include_revoked: bool = False,
    _: None = Depends(require_permission("admin")),
    service: APIKeyService = Depends(get_api_key_service),
):
    """
    List all API keys.

    Requires admin permission. Returns key metadata only (not the actual keys).
    """
    keys = service.list_keys(include_revoked=include_revoked)
    return ListKeysResponse(
        keys=[_metadata_to_info(k) for k in keys],
        total=len(keys),
    )


@router.get("/{key_prefix}", response_model=KeyInfo)
def get_key(
    key_prefix: str,
    _: None = Depends(require_permission("admin")),
    service: APIKeyService = Depends(get_api_key_service),
):
    """
    Get details about a specific API key.

    Requires admin permission.
    """
    metadata = service.get_key_by_prefix(key_prefix)
    if metadata is None:
        raise not_found(
            f"API key not found: {key_prefix}",
            error_code=ErrorCode.NOT_FOUND,
        )
    return _metadata_to_info(metadata)


@router.patch("/{key_prefix}", response_model=KeyInfo)
def update_key(
    key_prefix: str,
    req: UpdateKeyRequest,
    _: None = Depends(require_permission("admin")),
    service: APIKeyService = Depends(get_api_key_service),
):
    """
    Update an API key's metadata.

    Requires admin permission.
    """
    # Validate permissions if provided
    if req.permissions:
        valid_permissions = {"redact", "restore", "chat", "admin", "files"}
        invalid = set(req.permissions) - valid_permissions
        if invalid:
            raise bad_request(
                f"Invalid permissions: {invalid}. Valid: {valid_permissions}",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

    success = service.update_key(
        key_prefix=key_prefix,
        name=req.name,
        rate_limit=req.rate_limit,
        permissions=req.permissions,
    )

    if not success:
        raise not_found(
            f"API key not found or revoked: {key_prefix}",
            error_code=ErrorCode.NOT_FOUND,
        )

    # Return updated key
    metadata = service.get_key_by_prefix(key_prefix)
    return _metadata_to_info(metadata)


@router.delete("/{key_prefix}")
def revoke_key(
    key_prefix: str,
    _: None = Depends(require_permission("admin")),
    service: APIKeyService = Depends(get_api_key_service),
):
    """
    Revoke an API key.

    Requires admin permission. Revoked keys cannot be used for authentication.
    """
    success = service.revoke_key(key_prefix)
    if not success:
        raise not_found(
            f"API key not found or already revoked: {key_prefix}",
            error_code=ErrorCode.NOT_FOUND,
        )

    logger.info(f"API key revoked: {key_prefix}...")
    return {"success": True, "revoked": key_prefix}

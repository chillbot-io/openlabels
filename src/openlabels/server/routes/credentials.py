"""
Session-scoped encrypted credential storage for resource enumeration.

Credentials are:
- Encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256)
- Tied to the user's login session (auto-expire with session)
- Never persisted beyond the session lifetime
- Keyed by (user_id, source_type) so each user can store one credential set per source
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser, require_admin
from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.session import SessionStore

logger = logging.getLogger(__name__)

router = APIRouter()

SESSION_COOKIE_NAME = "openlabels_session"

# Valid source types that can store credentials
VALID_SOURCE_TYPES = frozenset({"smb", "nfs", "sharepoint", "onedrive", "s3", "gcs", "azure_blob"})


def _derive_fernet_key() -> bytes:
    """Derive a Fernet key from the server's secret_key.

    Uses HKDF-like derivation: SHA-256 of (secret_key + salt) truncated to
    32 bytes, then base64-encoded for Fernet.
    """
    settings = get_settings()
    secret = settings.server.secret_key or "openlabels-dev-secret"
    raw = hashlib.sha256(f"{secret}:credential-encryption".encode()).digest()
    return base64.urlsafe_b64encode(raw)


def _encrypt(data: dict[str, Any]) -> str:
    """Encrypt credential data to a Fernet token string."""
    f = Fernet(_derive_fernet_key())
    plaintext = json.dumps(data).encode()
    return f.encrypt(plaintext).decode()


def _decrypt(token: str) -> dict[str, Any]:
    """Decrypt a Fernet token back to credential data."""
    f = Fernet(_derive_fernet_key())
    try:
        plaintext = f.decrypt(token.encode())
        return json.loads(plaintext)
    except (InvalidToken, json.JSONDecodeError) as e:
        logger.warning("Failed to decrypt credentials: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail="Stored credentials are invalid or corrupted") from e


class CredentialStore(BaseModel):
    """Request to store credentials for a source type."""
    source_type: str = Field(..., description="Source type (smb, nfs, sharepoint, onedrive, s3, gcs, azure_blob)")
    credentials: dict[str, Any] = Field(..., description="Credential fields (host, username, password, etc.)")
    save: bool = Field(False, description="Whether to persist credentials for the session duration")


class CredentialStoreResponse(BaseModel):
    """Response after storing credentials."""
    source_type: str
    saved: bool
    fields_stored: list[str]


class CredentialCheckResponse(BaseModel):
    """Response for checking if credentials exist."""
    source_type: str
    has_credentials: bool
    fields_stored: list[str]


async def _get_session_id(request: Request) -> str:
    """Extract session ID from cookie."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")
    return session_id


async def _get_session_data(
    request: Request,
    db: AsyncSession,
) -> tuple[str, dict]:
    """Get the session ID and its data."""
    session_id = await _get_session_id(request)
    store = SessionStore(db)
    data = await store.get(session_id)
    if data is None:
        raise HTTPException(status_code=401, detail="Session expired")
    return session_id, data


def _cred_key(user_id: str, source_type: str) -> str:
    """Build the key used inside the session data dict."""
    return f"cred:{user_id}:{source_type}"


@router.post("", response_model=CredentialStoreResponse)
async def store_credentials(
    request: Request,
    body: CredentialStore,
    db: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> CredentialStoreResponse:
    """Store encrypted credentials for a source type.

    Credentials are encrypted with Fernet and stored in the user's session.
    They persist until the session expires or the user logs out.
    """
    if body.source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid source type: {body.source_type}")

    # Encrypt the credentials
    encrypted = _encrypt(body.credentials)

    # Store in session data
    session_id, session_data = await _get_session_data(request, db)
    key = _cred_key(str(user.id), body.source_type)
    session_data[key] = encrypted

    store = SessionStore(db)
    await store.set(
        session_id,
        session_data,
        ttl=60 * 60 * 24 * 7,  # Match session TTL
        tenant_id=str(user.tenant_id),
        user_id=str(user.id),
    )

    return CredentialStoreResponse(
        source_type=body.source_type,
        saved=True,
        fields_stored=list(body.credentials.keys()),
    )


@router.get("/{source_type}", response_model=CredentialCheckResponse)
async def check_credentials(
    source_type: str,
    request: Request,
    db: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> CredentialCheckResponse:
    """Check if credentials exist for a source type."""
    if source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid source type: {source_type}")

    session_id, session_data = await _get_session_data(request, db)
    key = _cred_key(str(user.id), source_type)
    encrypted = session_data.get(key)

    if not encrypted:
        return CredentialCheckResponse(
            source_type=source_type,
            has_credentials=False,
            fields_stored=[],
        )

    try:
        creds = _decrypt(encrypted)
        return CredentialCheckResponse(
            source_type=source_type,
            has_credentials=True,
            fields_stored=list(creds.keys()),
        )
    except HTTPException:
        return CredentialCheckResponse(
            source_type=source_type,
            has_credentials=False,
            fields_stored=[],
        )


@router.delete("/{source_type}")
async def delete_credentials(
    source_type: str,
    request: Request,
    db: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """Delete stored credentials for a source type."""
    if source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid source type: {source_type}")

    session_id, session_data = await _get_session_data(request, db)
    key = _cred_key(str(user.id), source_type)

    if key in session_data:
        del session_data[key]
        store = SessionStore(db)
        await store.set(
            session_id,
            session_data,
            ttl=60 * 60 * 24 * 7,
            tenant_id=str(user.tenant_id),
            user_id=str(user.id),
        )

    return {"status": "ok", "source_type": source_type}


def get_decrypted_credentials(
    session_data: dict,
    user_id: str,
    source_type: str,
) -> dict[str, Any] | None:
    """Utility: decrypt credentials from session data.

    Used by the enumeration route to retrieve stored credentials.
    Returns None if no credentials stored.
    """
    key = _cred_key(user_id, source_type)
    encrypted = session_data.get(key)
    if not encrypted:
        return None
    try:
        return _decrypt(encrypted)
    except HTTPException:
        return None

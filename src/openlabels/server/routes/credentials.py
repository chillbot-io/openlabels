"""
Encrypted credential storage for resource connections.

Two storage tiers:
1. **Session credentials** — encrypted in the session JSONB, expire with the session.
   Used for temporary enumeration during setup.
2. **Saved credentials** — encrypted in the ``saved_credentials`` table, persist
   indefinitely. Used by the scan engine for scheduled scans.

Both tiers use Fernet (AES-128-CBC + HMAC-SHA256), keyed from the server's
``secret_key`` setting.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.auth.dependencies import CurrentUser, require_admin
from openlabels.server.config import get_settings
from openlabels.server.db import get_session
from openlabels.server.models import SavedCredential
from openlabels.server.routes import audit_log
from openlabels.server.session import SessionStore

logger = logging.getLogger(__name__)

router = APIRouter()

# Must match the cookie name in auth.py and ws.py
SESSION_COOKIE_NAME = "openlabels_session"

# Valid source types that can store credentials
VALID_SOURCE_TYPES = frozenset({"smb", "nfs", "sharepoint", "onedrive", "s3", "gcs", "azure_blob"})


def _derive_fernet_key() -> bytes:
    """Derive a Fernet key from the server's secret_key.

    Uses HKDF-like derivation: SHA-256 of (secret_key + salt) truncated to
    32 bytes, then base64-encoded for Fernet.

    Raises RuntimeError if secret_key is not configured — credentials must
    never be encrypted with a predictable default key.
    """
    settings = get_settings()
    secret = settings.server.secret_key
    if not secret:
        raise RuntimeError(
            "OPENLABELS_SERVER__SECRET_KEY is not configured. "
            "A secret key is required for credential encryption. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
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


# ── Request / Response models ───────────────────────────────────────

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


class SaveCredentialRequest(BaseModel):
    """Request to persist credentials to the database."""
    source_type: str = Field(..., description="Source type")
    name: str = Field(..., description="Display name (e.g. 'SMB — fileserver.contoso.com')")
    credentials: dict[str, Any] = Field(..., description="Credential fields")
    target_id: UUID | None = Field(None, description="Optional target to associate with")


class SavedCredentialResponse(BaseModel):
    """Metadata about a saved credential (never exposes secrets)."""
    id: UUID
    source_type: str
    name: str
    fields_stored: list[str]
    target_id: UUID | None
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


# ── Session helpers ─────────────────────────────────────────────────

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


# ── Session-scoped credential endpoints ─────────────────────────────

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


# ── Persistent credential endpoints ────────────────────────────────

@router.post("/saved", response_model=SavedCredentialResponse)
async def save_credential(
    body: SaveCredentialRequest,
    db: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> SavedCredentialResponse:
    """Persist encrypted credentials to the database.

    Unlike session credentials, these survive server restarts and session
    expiry. Used by the scan engine for scheduled scans.
    """
    if body.source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid source type: {body.source_type}")

    encrypted = _encrypt(body.credentials)
    fields = list(body.credentials.keys())

    # Upsert: if a saved credential for this tenant+source+name exists, update it
    existing = await db.execute(
        select(SavedCredential).where(
            SavedCredential.tenant_id == user.tenant_id,
            SavedCredential.source_type == body.source_type,
            SavedCredential.name == body.name,
        )
    )
    row = existing.scalar_one_or_none()

    is_update = False
    if row:
        is_update = True
        row.encrypted_data = encrypted
        row.fields_stored = fields
        row.target_id = body.target_id
    else:
        row = SavedCredential(
            tenant_id=user.tenant_id,
            source_type=body.source_type,
            name=body.name,
            encrypted_data=encrypted,
            fields_stored=fields,
            target_id=body.target_id,
            created_by=user.id,
        )
        db.add(row)

    await db.flush()
    await db.refresh(row)

    audit_log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="credential_updated" if is_update else "credential_created",
        resource_type="saved_credential",
        resource_id=row.id,
        details={"source_type": body.source_type, "name": body.name, "fields": fields},
    )

    return SavedCredentialResponse(
        id=row.id,
        source_type=row.source_type,
        name=row.name,
        fields_stored=row.fields_stored,
        target_id=row.target_id,
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
    )


@router.get("/saved", response_model=list[SavedCredentialResponse])
async def list_saved_credentials(
    source_type: str | None = None,
    db: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> list[SavedCredentialResponse]:
    """List saved credentials (metadata only, no secrets)."""
    query = select(SavedCredential).where(
        SavedCredential.tenant_id == user.tenant_id,
    )
    if source_type:
        query = query.where(SavedCredential.source_type == source_type)
    query = query.order_by(SavedCredential.created_at.desc())

    result = await db.execute(query)
    rows = result.scalars().all()

    return [
        SavedCredentialResponse(
            id=r.id,
            source_type=r.source_type,
            name=r.name,
            fields_stored=r.fields_stored,
            target_id=r.target_id,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )
        for r in rows
    ]


@router.delete("/saved/{credential_id}")
async def delete_saved_credential(
    credential_id: UUID,
    db: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_admin),
) -> dict:
    """Delete a saved credential."""
    result = await db.execute(
        select(SavedCredential).where(
            SavedCredential.id == credential_id,
            SavedCredential.tenant_id == user.tenant_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Capture metadata before deletion for the audit log
    deleted_source_type = row.source_type
    deleted_name = row.name

    await db.delete(row)
    await db.flush()

    audit_log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="credential_deleted",
        resource_type="saved_credential",
        resource_id=credential_id,
        details={"source_type": deleted_source_type, "name": deleted_name},
    )

    return {"status": "ok", "id": str(credential_id)}


# ── Utility functions ───────────────────────────────────────────────

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


async def get_saved_credentials_for_target(
    db: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> dict[str, Any] | None:
    """Retrieve decrypted credentials for a scan target.

    Used by the scan engine to authenticate to data sources.
    """
    result = await db.execute(
        select(SavedCredential).where(
            SavedCredential.tenant_id == tenant_id,
            SavedCredential.target_id == target_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        return None
    try:
        f = Fernet(_derive_fernet_key())
        plaintext = f.decrypt(row.encrypted_data.encode())
        return json.loads(plaintext)
    except (InvalidToken, json.JSONDecodeError):
        logger.warning("Failed to decrypt saved credentials %s", row.id)
        return None

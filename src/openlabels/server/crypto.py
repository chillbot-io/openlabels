"""
Shared cryptographic utilities for OpenLabels.

Provides Fernet-based encryption for sensitive data at rest, including:
- Full dict encryption (used by SavedCredential)
- Selective field encryption for JSONB columns (used by ScanTarget.config)

All encryption uses AES-128-CBC + HMAC-SHA256 via Fernet, keyed from the
server's ``secret_key`` setting.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)

# Prefix added to encrypted values so we can distinguish them from plaintext
# when reading back from the database.  This avoids double-encryption and
# allows a graceful migration for existing rows.
ENCRYPTED_PREFIX = "enc:fernet:"

# Field names in ScanTarget.config JSONB that contain credentials.
# These are the fields passed through to adapter constructors that hold
# secrets (passwords, keys, tokens, connection strings).
CREDENTIAL_FIELD_NAMES = frozenset({
    "access_key",
    "secret_key",
    "account_key",
    "sas_token",
    "connection_string",
    "password",
    "client_secret",
    "api_key",
    "token",
    "credentials_path",
    "service_account_key",
})


def _derive_fernet_key() -> bytes:
    """Derive a Fernet key from the server's secret_key.

    Uses SHA-256 of (secret_key + salt) truncated to 32 bytes, then
    base64url-encoded for Fernet.

    Raises ``RuntimeError`` if ``secret_key`` is not configured.
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


def encrypt_value(plaintext: str) -> str:
    """Encrypt a single string value with Fernet.

    Returns a string prefixed with ``ENCRYPTED_PREFIX`` so callers can
    detect already-encrypted values.
    """
    f = Fernet(_derive_fernet_key())
    token = f.encrypt(plaintext.encode()).decode()
    return f"{ENCRYPTED_PREFIX}{token}"


def decrypt_value(token: str) -> str:
    """Decrypt a single Fernet-encrypted value.

    Expects the ``ENCRYPTED_PREFIX``; returns the original plaintext.
    Raises ``InvalidToken`` if the token is corrupted or the key is wrong.
    """
    if not token.startswith(ENCRYPTED_PREFIX):
        # Not encrypted (legacy data or non-credential field) — return as-is
        return token
    raw_token = token[len(ENCRYPTED_PREFIX):]
    f = Fernet(_derive_fernet_key())
    return f.decrypt(raw_token.encode()).decode()


def is_encrypted(value: Any) -> bool:
    """Check whether a value carries the encryption prefix."""
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def encrypt_config_credentials(config: dict[str, Any]) -> dict[str, Any]:
    """Encrypt credential fields within a ScanTarget config JSONB dict.

    Only string values whose keys are in ``CREDENTIAL_FIELD_NAMES`` are
    encrypted.  Already-encrypted values (detected by prefix) are left
    untouched to prevent double-encryption.  Non-credential fields are
    passed through unchanged.

    Args:
        config: The raw config dict (may contain plaintext secrets).

    Returns:
        A *new* dict with credential fields replaced by Fernet tokens.
    """
    if not config:
        return config

    result = {}
    for key, value in config.items():
        if (
            key in CREDENTIAL_FIELD_NAMES
            and isinstance(value, str)
            and value  # skip empty strings
            and not is_encrypted(value)
        ):
            try:
                result[key] = encrypt_value(value)
            except RuntimeError:
                # secret_key not configured — log and store plaintext
                # so the app doesn't crash, but warn loudly
                logger.error(
                    "Cannot encrypt config field '%s': secret_key not configured",
                    key,
                )
                result[key] = value
        else:
            result[key] = value
    return result


def decrypt_config_credentials(config: dict[str, Any]) -> dict[str, Any]:
    """Decrypt credential fields within a ScanTarget config JSONB dict.

    Only values carrying the ``ENCRYPTED_PREFIX`` are decrypted.  This
    means the function is safe to call on configs that were stored before
    encryption was enabled (they will pass through unchanged).

    Args:
        config: The config dict as stored in the database.

    Returns:
        A *new* dict with credential fields decrypted to plaintext.
    """
    if not config:
        return config

    result = {}
    for key, value in config.items():
        if is_encrypted(value):
            try:
                result[key] = decrypt_value(value)
            except (InvalidToken, Exception) as exc:
                logger.warning(
                    "Failed to decrypt config field '%s': %s",
                    key,
                    type(exc).__name__,
                )
                # Return the raw token so the caller can decide how to handle it.
                # This is safer than silently dropping the value.
                result[key] = value
        else:
            result[key] = value
    return result


def mask_config_credentials(config: dict[str, Any]) -> dict[str, Any]:
    """Replace credential field values with a mask for safe API responses.

    Credential fields (both encrypted and plaintext) are replaced with
    ``"******"`` so that secrets are never leaked through the API.
    Non-credential fields pass through unchanged.
    """
    if not config:
        return config

    result = {}
    for key, value in config.items():
        if key in CREDENTIAL_FIELD_NAMES and isinstance(value, str) and value:
            result[key] = "******"
        else:
            result[key] = value
    return result


def encrypt_dict(data: dict[str, Any]) -> str:
    """Encrypt an entire dict to a Fernet token string.

    Used by SavedCredential for full-payload encryption.
    """
    f = Fernet(_derive_fernet_key())
    plaintext = json.dumps(data).encode()
    return f.encrypt(plaintext).decode()


def decrypt_dict(token: str) -> dict[str, Any]:
    """Decrypt a Fernet token back to a dict.

    Used by SavedCredential for full-payload decryption.
    Raises ``InvalidToken`` on failure.
    """
    f = Fernet(_derive_fernet_key())
    plaintext = f.decrypt(token.encode())
    return json.loads(plaintext)

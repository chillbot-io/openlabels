"""
Shared cryptographic utilities for OpenLabels.

Provides Fernet-based encryption for sensitive data at rest, including:
- Full dict encryption (used by SavedCredential)
- Selective field encryption for JSONB columns (used by ScanTarget.config)

All encryption uses AES-128-CBC + HMAC-SHA256 via Fernet, keyed from the
server's ``secret_key`` setting via HKDF key derivation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import threading
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

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


def _derive_fernet_key(secret: str | None = None) -> bytes:
    """Derive a Fernet key from the server's secret_key using HKDF.

    Uses HKDF-SHA256 for proper cryptographic key derivation instead of a
    single round of SHA-256.

    Raises ``RuntimeError`` if ``secret_key`` is not configured.
    """
    if secret is None:
        settings = get_settings()
        key_val = settings.server.secret_key
        secret = key_val.get_secret_value() if hasattr(key_val, "get_secret_value") else key_val
    if not secret:
        raise RuntimeError(
            "OPENLABELS_SERVER__SECRET_KEY is not configured. "
            "A secret key is required for credential encryption. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    # Derive a per-deployment salt by hashing the secret with a fixed domain
    # separator.  This ensures different deployments (with different secrets)
    # produce different HKDF salts, avoiding the "static salt" weakness while
    # remaining deterministic for a given secret (no external state needed).
    deployment_salt = hashlib.sha256(
        b"openlabels-credential-encryption-v1:" + secret.encode()
    ).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=deployment_salt,
        info=b"fernet-key",
    )
    raw = hkdf.derive(secret.encode())
    return base64.urlsafe_b64encode(raw)


# TTL-based cache for MultiFernet instance.  Allows runtime key rotation
# without a full process restart — the cache expires after _FERNET_TTL_SECONDS
# and the next call rebuilds from current settings.
_FERNET_TTL_SECONDS: float = 300  # 5 minutes
_fernet_cache: MultiFernet | None = None
_fernet_cache_time: float = 0.0
_fernet_lock = threading.Lock()


def _get_fernet() -> MultiFernet:
    """Return a cached MultiFernet instance supporting key rotation.

    The primary key is derived via HKDF. If ``OPENLABELS_SERVER__SECRET_KEY_PREVIOUS``
    is set, a secondary Fernet is created from the old key so that data encrypted
    with the previous key can still be decrypted (rotation support).

    The result is cached for ``_FERNET_TTL_SECONDS`` (default 5 minutes).
    Call ``invalidate_fernet_cache()`` to force an immediate refresh.
    """
    global _fernet_cache, _fernet_cache_time
    now = time.monotonic()
    if _fernet_cache is not None and (now - _fernet_cache_time) < _FERNET_TTL_SECONDS:
        return _fernet_cache

    with _fernet_lock:
        # Double-check after acquiring lock
        now = time.monotonic()
        if _fernet_cache is not None and (now - _fernet_cache_time) < _FERNET_TTL_SECONDS:
            return _fernet_cache

        settings = get_settings()
        primary = Fernet(_derive_fernet_key())
        keys = [primary]
        prev_key = getattr(settings.server, "secret_key_previous", None)
        prev_secret = prev_key.get_secret_value() if hasattr(prev_key, "get_secret_value") else (prev_key or "")
        if prev_secret:
            keys.append(Fernet(_derive_fernet_key(prev_secret)))
        _fernet_cache = MultiFernet(keys)
        _fernet_cache_time = now
        return _fernet_cache


def invalidate_fernet_cache() -> None:
    """Force the Fernet cache to refresh on next access.

    Useful after changing ``secret_key`` at runtime or in tests.
    """
    global _fernet_cache, _fernet_cache_time
    with _fernet_lock:
        _fernet_cache = None
        _fernet_cache_time = 0.0


def encrypt_value(plaintext: str) -> str:
    """Encrypt a single string value with Fernet.

    Returns a string prefixed with ``ENCRYPTED_PREFIX`` so callers can
    detect already-encrypted values.
    """
    f = _get_fernet()
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
    f = _get_fernet()
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
                # secret_key not configured — fail closed to prevent
                # storing credentials in plaintext
                raise RuntimeError(
                    "OPENLABELS_SERVER__SECRET_KEY is required to store credentials. "
                    "Cannot save plaintext credentials without encryption configured."
                )
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
            except InvalidToken:
                logger.warning(
                    "Failed to decrypt config field '%s': invalid token (corrupted or wrong key)",
                    key,
                )
                result[key] = value
            except Exception as exc:
                logger.warning(
                    "Unexpected error decrypting config field '%s': %s",
                    key,
                    type(exc).__name__,
                )
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
    f = _get_fernet()
    plaintext = json.dumps(data).encode()
    return f.encrypt(plaintext).decode()


def decrypt_dict(token: str) -> dict[str, Any]:
    """Decrypt a Fernet token back to a dict.

    Used by SavedCredential for full-payload decryption.
    Raises ``InvalidToken`` on failure.
    """
    f = _get_fernet()
    plaintext = f.decrypt(token.encode())
    return json.loads(plaintext)

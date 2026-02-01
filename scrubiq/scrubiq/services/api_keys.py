"""
API Key management service.

Handles API key generation, validation, and revocation.
Keys are used for both authentication AND encryption key derivation.

Usage:
    from scrubiq.services import APIKeyService

    service = APIKeyService(db)

    # Create a new key
    key, metadata = service.create_key(name="production-agent")
    # key = "sk-7Kx9mPqR2vNwYzA5bCdEfGhJkLmN3pQr..."

    # Validate a key
    metadata = service.validate_key(key)
    if metadata:
        # Key is valid
        ...

    # Revoke a key
    service.revoke_key(key_prefix="sk-7Kx9")
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..storage.database import Database

logger = logging.getLogger(__name__)

# Key format: sk-{32 bytes base62} = 44 chars total
KEY_PREFIX = "sk-"
KEY_BYTES = 32  # 256 bits of entropy
KEY_PREFIX_LENGTH = 8  # Display prefix: "sk-7Kx9" for identification

# Base62 alphabet (URL-safe, no confusing chars)
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _generate_key() -> str:
    """Generate a new API key with sufficient entropy."""
    # Generate random bytes
    random_bytes = secrets.token_bytes(KEY_BYTES)

    # Encode as base62 for URL-safety
    num = int.from_bytes(random_bytes, "big")
    chars = []
    while num:
        chars.append(BASE62[num % 62])
        num //= 62

    # Pad to consistent length
    encoded = "".join(reversed(chars)).zfill(43)  # 32 bytes -> ~43 base62 chars

    return f"{KEY_PREFIX}{encoded}"


def _hash_key(key: str) -> str:
    """Hash an API key for storage. Uses SHA-256."""
    return hashlib.sha256(key.encode()).hexdigest()


def _get_key_prefix(key: str) -> str:
    """Get the display prefix of a key (e.g., 'sk-7Kx9')."""
    return key[:KEY_PREFIX_LENGTH]


def _derive_encryption_key(api_key: str, salt: bytes) -> bytes:
    """
    Derive an encryption key from an API key.

    Uses HKDF-like derivation: HMAC-SHA256(salt, api_key)
    This allows the API key to serve as both auth and encryption material.

    Args:
        api_key: The full API key
        salt: Random salt (stored per-database)

    Returns:
        32-byte encryption key
    """
    return hmac.new(salt, api_key.encode(), hashlib.sha256).digest()


@dataclass
class APIKeyMetadata:
    """Metadata about an API key."""
    id: int
    key_prefix: str  # "sk-7Kx9" for display
    name: str
    created_at: float
    last_used_at: Optional[float]
    rate_limit: int  # Requests per minute
    permissions: List[str]  # ["redact", "restore", "chat", "admin"]
    revoked_at: Optional[float]

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_active(self) -> bool:
        return not self.is_revoked


class APIKeyService:
    """
    Service for managing API keys.

    Thread-safe: Uses database transactions for consistency.

    Responsibilities:
    - Generate new API keys with cryptographic randomness
    - Validate keys (constant-time comparison)
    - Track key usage (last_used_at)
    - Revoke keys
    - Derive encryption keys from API keys
    """

    def __init__(self, db: Database):
        """
        Initialize API key service.

        Args:
            db: Database connection
        """
        self._db = db
        self._ensure_table()
        self._ensure_salt()

    def _ensure_table(self) -> None:
        """Create api_keys table if it doesn't exist."""
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_used_at REAL,
                rate_limit INTEGER NOT NULL DEFAULT 1000,
                permissions TEXT NOT NULL DEFAULT '["redact","restore","chat"]',
                revoked_at REAL
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_keys_hash
            ON api_keys(key_hash)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_keys_prefix
            ON api_keys(key_prefix)
        """)

    def _ensure_salt(self) -> None:
        """Ensure encryption salt exists in database."""
        row = self._db.fetchone(
            "SELECT value FROM settings WHERE key = 'encryption_salt'"
        )
        if row is None:
            # Generate new salt
            salt = secrets.token_bytes(32)
            self._db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("encryption_salt", salt.hex())
            )
            self._db.conn.commit()

    def _get_salt(self) -> bytes:
        """Get the encryption salt."""
        row = self._db.fetchone(
            "SELECT value FROM settings WHERE key = 'encryption_salt'"
        )
        if row is None:
            raise RuntimeError("Encryption salt not found")
        return bytes.fromhex(row["value"])

    # =========================================================================
    # KEY MANAGEMENT
    # =========================================================================

    def create_key(
        self,
        name: str,
        rate_limit: int = 1000,
        permissions: Optional[List[str]] = None,
    ) -> Tuple[str, APIKeyMetadata]:
        """
        Create a new API key.

        Args:
            name: Human-readable name for the key (e.g., "production-agent")
            rate_limit: Max requests per minute (default 1000)
            permissions: List of allowed actions (default: redact, restore, chat)

        Returns:
            (full_key, metadata) - The full key is only returned once!

        SECURITY: The full key is only returned at creation time.
        Store it securely - it cannot be retrieved later.
        """
        if permissions is None:
            permissions = ["redact", "restore", "chat"]

        # Generate key
        full_key = _generate_key()
        key_hash = _hash_key(full_key)
        key_prefix = _get_key_prefix(full_key)
        created_at = time.time()

        # Store in database
        cursor = self._db.execute("""
            INSERT INTO api_keys (key_hash, key_prefix, name, created_at, rate_limit, permissions)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (key_hash, key_prefix, name, created_at, rate_limit, json.dumps(permissions)))
        self._db.conn.commit()

        key_id = cursor.lastrowid

        metadata = APIKeyMetadata(
            id=key_id,
            key_prefix=key_prefix,
            name=name,
            created_at=created_at,
            last_used_at=None,
            rate_limit=rate_limit,
            permissions=permissions,
            revoked_at=None,
        )

        logger.info(f"Created API key: {key_prefix}... ({name})")
        return full_key, metadata

    def validate_key(self, key: str) -> Optional[APIKeyMetadata]:
        """
        Validate an API key and return its metadata.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            key: The full API key to validate

        Returns:
            APIKeyMetadata if valid, None if invalid or revoked
        """
        if not key or not key.startswith(KEY_PREFIX):
            return None

        key_hash = _hash_key(key)

        row = self._db.fetchone("""
            SELECT id, key_hash, key_prefix, name, created_at, last_used_at,
                   rate_limit, permissions, revoked_at
            FROM api_keys
            WHERE key_hash = ?
        """, (key_hash,))

        if row is None:
            return None

        # Check if revoked
        if row["revoked_at"] is not None:
            logger.warning(f"Attempted use of revoked key: {row['key_prefix']}...")
            return None

        # Update last_used_at
        self._db.execute("""
            UPDATE api_keys SET last_used_at = ? WHERE id = ?
        """, (time.time(), row["id"]))
        # Don't commit here - let the request handler do it

        return APIKeyMetadata(
            id=row["id"],
            key_prefix=row["key_prefix"],
            name=row["name"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            rate_limit=row["rate_limit"],
            permissions=json.loads(row["permissions"]),
            revoked_at=row["revoked_at"],
        )

    def revoke_key(self, key_prefix: str) -> bool:
        """
        Revoke an API key by its prefix.

        Args:
            key_prefix: The key prefix (e.g., "sk-7Kx9")

        Returns:
            True if key was found and revoked, False otherwise
        """
        cursor = self._db.execute("""
            UPDATE api_keys
            SET revoked_at = ?
            WHERE key_prefix = ? AND revoked_at IS NULL
        """, (time.time(), key_prefix))
        self._db.conn.commit()

        if cursor.rowcount > 0:
            logger.info(f"Revoked API key: {key_prefix}...")
            return True
        return False

    def revoke_key_by_id(self, key_id: int) -> bool:
        """Revoke an API key by its ID."""
        cursor = self._db.execute("""
            UPDATE api_keys
            SET revoked_at = ?
            WHERE id = ? AND revoked_at IS NULL
        """, (time.time(), key_id))
        self._db.conn.commit()
        return cursor.rowcount > 0

    def list_keys(self, include_revoked: bool = False) -> List[APIKeyMetadata]:
        """
        List all API keys.

        Args:
            include_revoked: Include revoked keys in the list

        Returns:
            List of APIKeyMetadata (without the actual key values)
        """
        if include_revoked:
            rows = self._db.fetchall("""
                SELECT id, key_prefix, name, created_at, last_used_at,
                       rate_limit, permissions, revoked_at
                FROM api_keys
                ORDER BY created_at DESC
            """)
        else:
            rows = self._db.fetchall("""
                SELECT id, key_prefix, name, created_at, last_used_at,
                       rate_limit, permissions, revoked_at
                FROM api_keys
                WHERE revoked_at IS NULL
                ORDER BY created_at DESC
            """)

        return [
            APIKeyMetadata(
                id=row["id"],
                key_prefix=row["key_prefix"],
                name=row["name"],
                created_at=row["created_at"],
                last_used_at=row["last_used_at"],
                rate_limit=row["rate_limit"],
                permissions=json.loads(row["permissions"]),
                revoked_at=row["revoked_at"],
            )
            for row in rows
        ]

    def get_key_by_prefix(self, key_prefix: str) -> Optional[APIKeyMetadata]:
        """Get key metadata by prefix (without validating the full key)."""
        row = self._db.fetchone("""
            SELECT id, key_prefix, name, created_at, last_used_at,
                   rate_limit, permissions, revoked_at
            FROM api_keys
            WHERE key_prefix = ?
        """, (key_prefix,))

        if row is None:
            return None

        return APIKeyMetadata(
            id=row["id"],
            key_prefix=row["key_prefix"],
            name=row["name"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            rate_limit=row["rate_limit"],
            permissions=json.loads(row["permissions"]),
            revoked_at=row["revoked_at"],
        )

    def update_key(
        self,
        key_prefix: str,
        name: Optional[str] = None,
        rate_limit: Optional[int] = None,
        permissions: Optional[List[str]] = None,
    ) -> bool:
        """
        Update an API key's metadata.

        Args:
            key_prefix: The key prefix to update
            name: New name (optional)
            rate_limit: New rate limit (optional)
            permissions: New permissions (optional)

        Returns:
            True if key was found and updated
        """
        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)

        if rate_limit is not None:
            updates.append("rate_limit = ?")
            params.append(rate_limit)

        if permissions is not None:
            updates.append("permissions = ?")
            params.append(json.dumps(permissions))

        if not updates:
            return False

        params.append(key_prefix)
        cursor = self._db.execute(f"""
            UPDATE api_keys
            SET {", ".join(updates)}
            WHERE key_prefix = ? AND revoked_at IS NULL
        """, tuple(params))
        self._db.conn.commit()

        return cursor.rowcount > 0

    # =========================================================================
    # ENCRYPTION KEY DERIVATION
    # =========================================================================

    def derive_encryption_key(self, api_key: str) -> bytes:
        """
        Derive a 32-byte encryption key from an API key.

        This allows the API key to serve as both authentication
        and encryption material, simplifying key management.

        Args:
            api_key: The full API key

        Returns:
            32-byte key suitable for AES-256
        """
        salt = self._get_salt()
        return _derive_encryption_key(api_key, salt)

    def has_any_keys(self) -> bool:
        """Check if any API keys exist (for first-run setup)."""
        row = self._db.fetchone("SELECT COUNT(*) as count FROM api_keys WHERE revoked_at IS NULL")
        return row["count"] > 0 if row else False

    def create_bootstrap_key(
        self,
        name: str,
        rate_limit: int = 1000,
        permissions: Optional[List[str]] = None,
    ) -> Optional[Tuple[str, APIKeyMetadata]]:
        """
        Atomically create the first API key (bootstrap key).

        This method is race-condition safe: it uses a database transaction
        to ensure only one bootstrap key can be created even with concurrent
        requests.

        Args:
            name: Human-readable name for the key
            rate_limit: Max requests per minute
            permissions: List of allowed actions (defaults to all including admin)

        Returns:
            (full_key, metadata) if this is the first key and creation succeeded,
            None if keys already exist (caller should require auth instead).

        SECURITY: This method prevents the bootstrap race condition where
        multiple concurrent requests could all bypass auth by seeing no keys exist.
        """
        if permissions is None:
            permissions = ["redact", "restore", "chat", "admin"]

        # Generate key material before transaction (crypto can be slow)
        full_key = _generate_key()
        key_hash = _hash_key(full_key)
        key_prefix = _get_key_prefix(full_key)
        created_at = time.time()

        # Use BEGIN IMMEDIATE to acquire write lock immediately
        # This prevents race conditions between check and insert
        try:
            self._db.execute("BEGIN IMMEDIATE")

            # Check inside transaction - this is the atomic part
            row = self._db.fetchone(
                "SELECT COUNT(*) as count FROM api_keys WHERE revoked_at IS NULL"
            )
            if row and row["count"] > 0:
                # Keys already exist - rollback and return None
                self._db.execute("ROLLBACK")
                return None

            # No keys exist - create the bootstrap key
            cursor = self._db.execute("""
                INSERT INTO api_keys (key_hash, key_prefix, name, created_at, rate_limit, permissions)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (key_hash, key_prefix, name, created_at, rate_limit, json.dumps(permissions)))

            self._db.execute("COMMIT")

            key_id = cursor.lastrowid
            metadata = APIKeyMetadata(
                id=key_id,
                key_prefix=key_prefix,
                name=name,
                created_at=created_at,
                last_used_at=None,
                rate_limit=rate_limit,
                permissions=permissions,
                revoked_at=None,
            )

            logger.info(f"Created bootstrap API key: {key_prefix}... ({name})")
            return full_key, metadata

        except Exception as e:
            # Rollback on any error
            try:
                self._db.execute("ROLLBACK")
            except Exception:
                pass
            raise e

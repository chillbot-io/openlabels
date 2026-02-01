"""
Session management service.

Handles key management and session lifecycle.
Authentication is now handled via API keys at the API layer.

Usage:
    from scrubiq.services import SessionService

    service = SessionService(db)
    result = service.unlock(encryption_key)
    if result.success:
        # Session unlocked, keys available
        keys = service.get_key_manager()
"""

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..crypto import KeyManager
from ..crypto.kdf import SCRYPT_N_MAX
from ..constants import MIN_RESPONSE_TIME_MS
from ..storage.database import Database

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session authentication state."""
    LOCKED = "locked"
    UNLOCKED = "unlocked"


@dataclass
class UnlockResult:
    """Result of an unlock attempt."""
    success: bool
    error: Optional[str] = None
    is_new_vault: bool = False
    kdf_upgraded: bool = False


class SessionService:
    """
    Service for managing session encryption keys.

    Thread-safe: Uses locks for concurrent access to session state.

    Responsibilities:
    - Key generation and loading (KEK/DEK hierarchy)
    - Session state management
    - Timing jitter for security

    Authentication is now handled by API key validation at the API layer.
    This service focuses on encryption key management.
    """

    def __init__(
        self,
        db: Database,
        session_timeout_minutes: int = 15,
        scrypt_memory_mb: int = 16,
    ):
        """
        Initialize session service.

        Args:
            db: Database connection for storing auth state
            session_timeout_minutes: Session timeout in minutes
            scrypt_memory_mb: Memory for key derivation
        """
        self._db = db
        self._scrypt_memory_mb = scrypt_memory_mb
        self._timeout_minutes = session_timeout_minutes

        # Session state
        self._session_id = secrets.token_hex(16)
        self._keys: Optional[KeyManager] = None
        self._state = SessionState.LOCKED
        self._last_activity = time.monotonic()

        # Thread safety
        self._lock = threading.Lock()

        # Operation tracking - prevents timeout during in-flight operations
        self._operations_in_progress = 0
        self._operation_lock = threading.Lock()

    # =========================================================================
    # PROPERTIES
    # =========================================================================

    @property
    def session_id(self) -> str:
        """Get unique session identifier."""
        return self._session_id

    def set_session_id(self, session_id: str) -> None:
        """
        Set the session identifier.

        MUST be called before unlock() for proper isolation.
        Used by instance pool to set API key-specific session IDs.

        Args:
            session_id: Unique identifier for this session (e.g., "apikey:sk-7Kx9")

        Raises:
            RuntimeError: If session is already unlocked
        """
        with self._lock:
            if self._state == SessionState.UNLOCKED:
                raise RuntimeError("Cannot change session_id after unlock")
            self._session_id = session_id

    @property
    def state(self) -> SessionState:
        """Get current session state."""
        with self._lock:
            return self._state

    @property
    def is_unlocked(self) -> bool:
        """Check if session is unlocked."""
        with self._lock:
            return self._state == SessionState.UNLOCKED and self._keys is not None

    @property
    def has_keys_stored(self) -> bool:
        """Check if encryption keys exist in storage."""
        return self._db.has_keys()

    @property
    def is_new_vault(self) -> bool:
        """Check if this is a new vault (no keys stored)."""
        return not self.has_keys_stored

    @property
    def vault_needs_upgrade(self) -> bool:
        """Check if vault KDF parameters need upgrade."""
        if not self.has_keys_stored:
            return False
        stored_n = self._db.get_stored_scrypt_n()
        if stored_n is None:
            return True
        return stored_n > SCRYPT_N_MAX

    def get_timeout_remaining(self) -> Optional[int]:
        """Get seconds until session times out, or None if expired."""
        with self._lock:
            elapsed = time.monotonic() - self._last_activity
            remaining = int(self._timeout_minutes * 60 - elapsed)
            return remaining if remaining > 0 else None

    # =========================================================================
    # KEY ACCESS
    # =========================================================================

    def get_key_manager(self) -> Optional[KeyManager]:
        """
        Get the key manager for encryption operations.

        Returns None if session is locked.

        SECURITY: Caller should not store references to KeyManager.
        Always call get_key_manager() to check current state.
        """
        with self._lock:
            if self._state != SessionState.UNLOCKED:
                return None
            return self._keys

    # =========================================================================
    # UNLOCK / LOCK
    # =========================================================================

    def unlock(self, key_material: str) -> UnlockResult:
        """
        Unlock session with key material.

        With API key auth, the key_material is derived from the API key.
        Authentication is handled at the API layer via APIKeyService.

        Args:
            key_material: Key material (derived from API key)

        Returns:
            UnlockResult with success status and details
        """
        start_time = time.monotonic()

        def _add_timing_jitter():
            """Add timing jitter to prevent timing attacks."""
            elapsed_ms = (time.monotonic() - start_time) * 1000
            remaining_ms = MIN_RESPONSE_TIME_MS - elapsed_ms
            if remaining_ms > 0:
                jitter_ms = secrets.randbelow(2000)
                time.sleep((remaining_ms + jitter_ms) / 1000)

        with self._lock:
            # Load or create keys
            stored = self._db.load_keys()
            is_new_vault = stored is None
            kdf_upgraded = False

            try:
                if stored is None:
                    # New vault - generate keys
                    self._keys = KeyManager(key_material, memory_mb=self._scrypt_memory_mb)
                    self._keys.generate_dek()
                    self._db.store_keys(
                        self._keys.salt,
                        self._keys.get_encrypted_dek(),
                        self._keys.scrypt_n,
                    )
                    self._db.conn.commit()
                else:
                    # Existing vault - load keys
                    salt, encrypted_dek, stored_n = stored
                    scrypt_n = stored_n if stored_n else 131072  # Legacy default

                    self._keys = KeyManager(
                        key_material,
                        salt=salt,
                        memory_mb=self._scrypt_memory_mb,
                        scrypt_n=scrypt_n,
                    )
                    self._keys.load_dek(encrypted_dek)

            except Exception as e:
                # Key loading failed - wrong key or corrupted
                logger.debug(f"Key loading failed: {e}")
                self._keys = None
                _add_timing_jitter()
                return UnlockResult(success=False, error="Invalid key")

            # Success - update state
            self._last_activity = time.monotonic()
            self._state = SessionState.UNLOCKED

            # Check for KDF upgrade
            if self._keys.needs_kdf_upgrade(SCRYPT_N_MAX):
                try:
                    logger.info("Upgrading vault KDF parameters...")
                    new_salt, new_encrypted_dek, new_n = self._keys.upgrade_kdf(
                        key_material, SCRYPT_N_MAX, self._scrypt_memory_mb
                    )
                    self._db.store_keys(new_salt, new_encrypted_dek, new_n)
                    self._db.conn.commit()
                    kdf_upgraded = True
                except Exception as e:
                    # Non-fatal - just log
                    logger.warning(f"KDF upgrade failed: {e}")

            _add_timing_jitter()
            return UnlockResult(
                success=True,
                is_new_vault=is_new_vault,
                kdf_upgraded=kdf_upgraded,
            )

    def lock(self) -> None:
        """
        Lock session, clear keys from memory.

        Safe to call multiple times.
        """
        with self._lock:
            if self._keys:
                self._keys.lock()
            self._state = SessionState.LOCKED

    def destroy(self) -> None:
        """
        Destroy session and all key material.

        Call on application exit for secure cleanup.
        """
        with self._lock:
            if self._keys:
                self._keys.destroy()
                self._keys = None
            self._state = SessionState.LOCKED

    # =========================================================================
    # ACTIVITY TRACKING
    # =========================================================================

    def touch(self) -> None:
        """
        Update last activity timestamp.

        Call this on each user interaction to prevent timeout.
        """
        with self._lock:
            self._last_activity = time.monotonic()

    def check_timeout(self) -> bool:
        """
        Check if session has timed out due to inactivity.

        Will NOT lock if there are operations in progress. This prevents
        mid-operation failures that could leave the system in an inconsistent
        state (e.g., partially tokenized text, incomplete audit logs).

        Returns:
            True if session was locked (or should be locked but has active ops)

        Thread Safety:
            Holds _operation_lock while calling lock() to prevent race condition
            where start_operation() could increment counter after we check but
            before we lock.
        """
        remaining = self.get_timeout_remaining()
        if remaining is None or remaining <= 0:
            # Check if we have operations in progress
            # Hold _operation_lock while locking to prevent race with start_operation
            with self._operation_lock:
                if self._operations_in_progress > 0:
                    logger.warning(
                        f"Session timeout deferred: {self._operations_in_progress} "
                        "operation(s) in progress"
                    )
                    return True  # Signal timeout, but don't lock
                # Lock while holding _operation_lock to ensure atomicity
                self.lock()
            return True
        return False

    def start_operation(self) -> bool:
        """
        Mark the start of an operation that should not be interrupted.

        Returns:
            True if operation can proceed, False if session is locked

        Usage:
            if session.start_operation():
                try:
                    # Do work...
                finally:
                    session.end_operation()

        Thread Safety:
            Acquires both _operation_lock and _lock to prevent race conditions
            where session could be locked between state check and counter increment.
        """
        # Acquire operation lock first, then session lock (consistent ordering)
        # This prevents race condition where check_timeout() could lock the session
        # after we check state but before we increment the operation counter
        with self._operation_lock:
            with self._lock:
                if self._state != SessionState.UNLOCKED:
                    return False
                # Increment while holding both locks to ensure atomicity
                # with respect to check_timeout() and lock()
                self._operations_in_progress += 1
                self._last_activity = time.monotonic()  # Touch on operation start
            return True

    def end_operation(self) -> None:
        """
        Mark the end of an operation.

        Always call this in a finally block after start_operation().
        """
        with self._operation_lock:
            self._operations_in_progress = max(0, self._operations_in_progress - 1)
            self._last_activity = time.monotonic()  # Touch on operation end

            # If we were waiting to timeout and no more ops, lock now
            remaining = self.get_timeout_remaining()
            if remaining is not None and remaining <= 0 and self._operations_in_progress == 0:
                logger.info("Session timeout after deferred operation completed")
                self.lock()

    @property
    def has_operations_in_progress(self) -> bool:
        """Check if there are operations in progress."""
        with self._operation_lock:
            return self._operations_in_progress > 0

    # =========================================================================
    # ENCRYPTION HELPERS
    # =========================================================================

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using session keys.

        Raises:
            RuntimeError: If session is locked
        """
        with self._lock:
            if self._keys is None:
                raise RuntimeError("Session not unlocked")
            return self._keys.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using session keys.

        Raises:
            RuntimeError: If session is locked
        """
        with self._lock:
            if self._keys is None:
                raise RuntimeError("Session not unlocked")
            return self._keys.decrypt(ciphertext)

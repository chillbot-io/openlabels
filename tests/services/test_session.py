"""Tests for session management service.

Tests SessionService: key management, session lifecycle, encryption.
"""

import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database
from scrubiq.services.session import (
    SessionService,
    SessionState,
    UnlockResult,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def db():
    """Create a database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        database = Database(db_path)
        database.connect()
        yield database
        database.close()


@pytest.fixture
def session(db):
    """Create a session service."""
    return SessionService(db, session_timeout_minutes=5)


@pytest.fixture
def unlocked_session(db):
    """Create an unlocked session."""
    service = SessionService(db, session_timeout_minutes=5)
    key = secrets.token_hex(32)
    service.unlock(key)
    return service, key


# =============================================================================
# SESSION STATE TESTS
# =============================================================================

class TestSessionState:
    """Tests for SessionState enum."""

    def test_locked_state(self):
        """LOCKED state value."""
        assert SessionState.LOCKED.value == "locked"

    def test_unlocked_state(self):
        """UNLOCKED state value."""
        assert SessionState.UNLOCKED.value == "unlocked"


class TestUnlockResult:
    """Tests for UnlockResult dataclass."""

    def test_success_result(self):
        """Success result."""
        result = UnlockResult(success=True)

        assert result.success is True
        assert result.error is None
        assert result.is_new_vault is False
        assert result.kdf_upgraded is False

    def test_failure_result(self):
        """Failure result with error."""
        result = UnlockResult(success=False, error="Invalid key")

        assert result.success is False
        assert result.error == "Invalid key"

    def test_new_vault_result(self):
        """New vault result."""
        result = UnlockResult(success=True, is_new_vault=True)

        assert result.is_new_vault is True


# =============================================================================
# SESSION SERVICE INITIALIZATION TESTS
# =============================================================================

class TestSessionServiceInit:
    """Tests for SessionService initialization."""

    def test_create_session_service(self, db):
        """Can create SessionService."""
        service = SessionService(db)

        assert service is not None
        assert service.state == SessionState.LOCKED

    def test_session_id_generated(self, db):
        """Session ID is generated on creation."""
        service = SessionService(db)

        assert service.session_id is not None
        assert len(service.session_id) == 32  # hex string

    def test_initial_state_locked(self, db):
        """Initial state is LOCKED."""
        service = SessionService(db)

        assert service.state == SessionState.LOCKED
        assert service.is_unlocked is False

    def test_custom_timeout(self, db):
        """Custom timeout is used."""
        service = SessionService(db, session_timeout_minutes=30)

        assert service._timeout_minutes == 30


# =============================================================================
# SESSION ID TESTS
# =============================================================================

class TestSessionId:
    """Tests for session ID management."""

    def test_set_session_id(self, db):
        """Can set session ID before unlock."""
        service = SessionService(db)

        service.set_session_id("custom-session-id")

        assert service.session_id == "custom-session-id"

    def test_set_session_id_after_unlock_raises(self, db):
        """Cannot set session ID after unlock."""
        service = SessionService(db)
        key = secrets.token_hex(32)
        service.unlock(key)

        with pytest.raises(RuntimeError) as exc:
            service.set_session_id("new-id")

        assert "Cannot change session_id after unlock" in str(exc.value)


# =============================================================================
# UNLOCK TESTS
# =============================================================================

class TestUnlock:
    """Tests for SessionService.unlock method."""

    def test_unlock_new_vault(self, db):
        """unlock() creates new vault."""
        service = SessionService(db)
        key = secrets.token_hex(32)

        result = service.unlock(key)

        assert result.success is True
        assert result.is_new_vault is True
        assert service.is_unlocked is True

    def test_unlock_existing_vault(self, db):
        """unlock() loads existing vault."""
        # Create vault
        service1 = SessionService(db)
        key = secrets.token_hex(32)
        service1.unlock(key)
        service1.lock()

        # Reload vault
        service2 = SessionService(db)
        result = service2.unlock(key)

        assert result.success is True
        assert result.is_new_vault is False
        assert service2.is_unlocked is True

    def test_unlock_wrong_key_fails(self, db):
        """unlock() fails with wrong key."""
        # Create vault
        service1 = SessionService(db)
        key1 = secrets.token_hex(32)
        service1.unlock(key1)
        service1.lock()

        # Try wrong key
        service2 = SessionService(db)
        key2 = secrets.token_hex(32)
        result = service2.unlock(key2)

        assert result.success is False
        assert result.error is not None
        assert service2.is_unlocked is False

    def test_unlock_updates_activity(self, db):
        """unlock() updates last activity time."""
        service = SessionService(db)
        key = secrets.token_hex(32)

        before = time.monotonic()
        service.unlock(key)
        after = time.monotonic()

        assert before <= service._last_activity <= after


# =============================================================================
# LOCK TESTS
# =============================================================================

class TestLock:
    """Tests for SessionService.lock method."""

    def test_lock_session(self, unlocked_session):
        """lock() locks the session."""
        service, key = unlocked_session

        service.lock()

        assert service.state == SessionState.LOCKED
        assert service.is_unlocked is False

    def test_lock_clears_keys(self, unlocked_session):
        """lock() clears key manager."""
        service, key = unlocked_session

        service.lock()

        assert service.get_key_manager() is None

    def test_lock_idempotent(self, unlocked_session):
        """lock() can be called multiple times."""
        service, key = unlocked_session

        service.lock()
        service.lock()  # Should not raise

        assert service.is_unlocked is False

    def test_lock_on_already_locked(self, session):
        """lock() on already locked session is safe."""
        session.lock()  # Should not raise

        assert session.is_unlocked is False


# =============================================================================
# DESTROY TESTS
# =============================================================================

class TestDestroy:
    """Tests for SessionService.destroy method."""

    def test_destroy_clears_state(self, unlocked_session):
        """destroy() clears all state."""
        service, key = unlocked_session

        service.destroy()

        assert service.state == SessionState.LOCKED
        assert service.get_key_manager() is None

    def test_destroy_on_locked_session(self, session):
        """destroy() on locked session is safe."""
        session.destroy()  # Should not raise

        assert session.is_unlocked is False


# =============================================================================
# KEY MANAGER ACCESS TESTS
# =============================================================================

class TestKeyManagerAccess:
    """Tests for get_key_manager method."""

    def test_get_key_manager_when_unlocked(self, unlocked_session):
        """get_key_manager returns KeyManager when unlocked."""
        service, key = unlocked_session

        km = service.get_key_manager()

        assert km is not None

    def test_get_key_manager_when_locked(self, session):
        """get_key_manager returns None when locked."""
        result = session.get_key_manager()

        assert result is None


# =============================================================================
# VAULT STATE TESTS
# =============================================================================

class TestVaultState:
    """Tests for vault state properties."""

    def test_is_new_vault_true_initially(self, db):
        """is_new_vault is True when no keys stored."""
        service = SessionService(db)

        assert service.is_new_vault is True
        assert service.has_keys_stored is False

    def test_is_new_vault_false_after_unlock(self, db):
        """is_new_vault is False after unlock."""
        service = SessionService(db)
        key = secrets.token_hex(32)
        service.unlock(key)

        assert service.is_new_vault is False
        assert service.has_keys_stored is True


# =============================================================================
# TIMEOUT TESTS
# =============================================================================

class TestTimeout:
    """Tests for session timeout."""

    def test_get_timeout_remaining(self, unlocked_session):
        """get_timeout_remaining returns remaining seconds."""
        service, key = unlocked_session

        remaining = service.get_timeout_remaining()

        assert remaining is not None
        assert remaining > 0
        assert remaining <= 5 * 60  # 5 minute timeout

    def test_timeout_remaining_none_when_expired(self, db):
        """get_timeout_remaining returns None when expired."""
        service = SessionService(db, session_timeout_minutes=0)
        key = secrets.token_hex(32)
        service.unlock(key)

        # Force last activity to be in the past
        service._last_activity = time.monotonic() - 100

        remaining = service.get_timeout_remaining()

        assert remaining is None or remaining <= 0

    def test_check_timeout_locks_session(self, db):
        """check_timeout locks expired session."""
        service = SessionService(db, session_timeout_minutes=1)
        key = secrets.token_hex(32)
        service.unlock(key)

        # Force expiration
        service._last_activity = time.monotonic() - 120

        result = service.check_timeout()

        assert result is True
        assert service.is_unlocked is False

    def test_check_timeout_not_expired(self, unlocked_session):
        """check_timeout doesn't lock non-expired session."""
        service, key = unlocked_session

        result = service.check_timeout()

        assert result is False
        assert service.is_unlocked is True


# =============================================================================
# ACTIVITY TRACKING TESTS
# =============================================================================

class TestActivityTracking:
    """Tests for activity tracking."""

    def test_touch_updates_timestamp(self, unlocked_session):
        """touch() updates last activity."""
        service, key = unlocked_session

        old_activity = service._last_activity
        time.sleep(0.01)

        service.touch()

        assert service._last_activity > old_activity

    def test_touch_prevents_timeout(self, db):
        """touch() prevents timeout."""
        service = SessionService(db, session_timeout_minutes=1)
        key = secrets.token_hex(32)
        service.unlock(key)

        # Would be timed out
        service._last_activity = time.monotonic() - 50

        # But we touch it
        service.touch()

        result = service.check_timeout()

        assert result is False
        assert service.is_unlocked is True


# =============================================================================
# OPERATION TRACKING TESTS
# =============================================================================

class TestOperationTracking:
    """Tests for operation tracking."""

    def test_start_operation_succeeds_when_unlocked(self, unlocked_session):
        """start_operation returns True when unlocked."""
        service, key = unlocked_session

        result = service.start_operation()

        assert result is True
        assert service.has_operations_in_progress is True

        service.end_operation()

    def test_start_operation_fails_when_locked(self, session):
        """start_operation returns False when locked."""
        result = session.start_operation()

        assert result is False
        assert session.has_operations_in_progress is False

    def test_end_operation_decrements_counter(self, unlocked_session):
        """end_operation decrements operation count."""
        service, key = unlocked_session

        service.start_operation()
        assert service.has_operations_in_progress is True

        service.end_operation()
        assert service.has_operations_in_progress is False

    def test_end_operation_updates_activity(self, unlocked_session):
        """end_operation updates last activity."""
        service, key = unlocked_session

        service.start_operation()
        old_activity = service._last_activity

        time.sleep(0.01)
        service.end_operation()

        assert service._last_activity > old_activity

    def test_timeout_deferred_during_operation(self, db):
        """Timeout is deferred when operation in progress."""
        service = SessionService(db, session_timeout_minutes=1)
        key = secrets.token_hex(32)
        service.unlock(key)

        # Start operation
        service.start_operation()

        # Force expiration
        service._last_activity = time.monotonic() - 120

        # Check timeout - should signal but not lock
        result = service.check_timeout()

        assert result is True
        assert service.is_unlocked is True  # Still unlocked!

        service.end_operation()

    def test_operation_count_never_negative(self, unlocked_session):
        """Operation count never goes negative."""
        service, key = unlocked_session

        # End without start
        service.end_operation()
        service.end_operation()

        assert service._operations_in_progress == 0


# =============================================================================
# ENCRYPTION HELPER TESTS
# =============================================================================

class TestEncryptionHelpers:
    """Tests for encrypt/decrypt helpers."""

    def test_encrypt_when_unlocked(self, unlocked_session):
        """encrypt() works when unlocked."""
        service, key = unlocked_session

        plaintext = b"hello world"
        ciphertext = service.encrypt(plaintext)

        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)

    def test_decrypt_when_unlocked(self, unlocked_session):
        """decrypt() works when unlocked."""
        service, key = unlocked_session

        plaintext = b"hello world"
        ciphertext = service.encrypt(plaintext)
        decrypted = service.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_when_locked_raises(self, session):
        """encrypt() raises when locked."""
        with pytest.raises(RuntimeError) as exc:
            session.encrypt(b"data")

        assert "Session not unlocked" in str(exc.value)

    def test_decrypt_when_locked_raises(self, session):
        """decrypt() raises when locked."""
        with pytest.raises(RuntimeError) as exc:
            session.decrypt(b"data")

        assert "Session not unlocked" in str(exc.value)

    def test_encrypt_different_data_different_ciphertext(self, unlocked_session):
        """Different data produces different ciphertext."""
        service, key = unlocked_session

        ct1 = service.encrypt(b"data1")
        ct2 = service.encrypt(b"data2")

        assert ct1 != ct2

    def test_encrypt_same_data_different_ciphertext(self, unlocked_session):
        """Same data produces different ciphertext (random IV)."""
        service, key = unlocked_session

        ct1 = service.encrypt(b"same data")
        ct2 = service.encrypt(b"same data")

        assert ct1 != ct2  # Due to random IV


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_unlock_attempts(self, db):
        """Concurrent unlock attempts are safe."""
        service = SessionService(db)
        key = secrets.token_hex(32)
        results = []
        errors = []

        def try_unlock():
            try:
                result = service.unlock(key)
                results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=try_unlock) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # All should succeed (same key)
        assert all(r.success for r in results)

    def test_concurrent_operations(self, unlocked_session):
        """Concurrent operations are safe."""
        service, key = unlocked_session
        errors = []

        def do_operation():
            try:
                if service.start_operation():
                    time.sleep(0.001)
                    service.end_operation()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=do_operation) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert service._operations_in_progress == 0

    def test_concurrent_encrypt_decrypt(self, unlocked_session):
        """Concurrent encrypt/decrypt is safe."""
        service, key = unlocked_session
        errors = []

        def encrypt_decrypt():
            try:
                for _ in range(20):
                    data = secrets.token_bytes(32)
                    ct = service.encrypt(data)
                    pt = service.decrypt(ct)
                    assert pt == data
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=encrypt_decrypt) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# =============================================================================
# TIMING JITTER TESTS
# =============================================================================

class TestTimingJitter:
    """Tests for timing jitter security measure."""

    def test_unlock_has_minimum_time(self, db):
        """unlock() takes minimum time for security."""
        service = SessionService(db)
        key = secrets.token_hex(32)

        start = time.monotonic()
        service.unlock(key)
        elapsed = time.monotonic() - start

        # Should take at least MIN_RESPONSE_TIME_MS (likely 100ms)
        # But allow some tolerance for CI variance
        assert elapsed >= 0.05  # At least 50ms


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_key_material_rejected(self, db):
        """Empty key material is rejected for security."""
        service = SessionService(db)

        result = service.unlock("")

        # Empty key should be rejected (security best practice)
        assert result.success is False

    def test_very_long_key_material(self, db):
        """Very long key material works."""
        service = SessionService(db)
        key = secrets.token_hex(1024)  # Very long

        result = service.unlock(key)

        assert result.success is True

    def test_binary_like_key_material(self, db):
        """Key material with special chars works."""
        service = SessionService(db)
        key = "key\x00with\nnull\tand\rspecial"

        result = service.unlock(key)

        assert result.success is True

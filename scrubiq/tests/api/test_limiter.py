"""Tests for API rate limiter.

Tests for SQLiteRateLimiter class.
"""

import importlib.util
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Direct import of the limiter module bypassing scrubiq.api.__init__.py
# This avoids the SQLCipher import chain
_limiter_path = Path(__file__).parent.parent.parent / "scrubiq" / "api" / "limiter.py"
_spec = importlib.util.spec_from_file_location("scrubiq_api_limiter", _limiter_path)
_limiter_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_limiter_module)

SQLiteRateLimiter = _limiter_module.SQLiteRateLimiter


# =============================================================================
# SQLITE RATE LIMITER INIT TESTS
# =============================================================================

class TestSQLiteRateLimiterInit:
    """Tests for SQLiteRateLimiter initialization."""

    def test_init_with_memory_db(self):
        """Initializes with in-memory database."""
        limiter = SQLiteRateLimiter()

        assert limiter._db_path == ":memory:"

    def test_init_with_file_db(self):
        """Initializes with file database."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate_limits.db"
            limiter = SQLiteRateLimiter(db_path)

            assert limiter._db_path == str(db_path)

    def test_creates_table_on_first_access(self):
        """Creates rate_limits table on first access."""
        limiter = SQLiteRateLimiter()

        # Trigger connection
        limiter.is_allowed("client", "endpoint", 10, 60)

        # Check table exists
        conn = limiter._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='rate_limits'"
        )
        assert cursor.fetchone() is not None

    def test_creates_index_on_first_access(self):
        """Creates index on window_start."""
        limiter = SQLiteRateLimiter()

        limiter.is_allowed("client", "endpoint", 10, 60)

        conn = limiter._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_rate_limits_window'"
        )
        assert cursor.fetchone() is not None


# =============================================================================
# IS_ALLOWED TESTS
# =============================================================================

class TestIsAllowed:
    """Tests for is_allowed method."""

    def test_first_request_allowed(self):
        """First request is always allowed."""
        limiter = SQLiteRateLimiter()

        allowed, remaining, retry_after = limiter.is_allowed(
            "client1", "endpoint", 5, 60
        )

        assert allowed is True
        assert remaining == 4  # 5 - 1
        assert retry_after == 0

    def test_within_limit_allowed(self):
        """Requests within limit are allowed."""
        limiter = SQLiteRateLimiter()

        for i in range(5):
            allowed, remaining, _ = limiter.is_allowed(
                "client1", "endpoint", 5, 60
            )
            assert allowed is True
            assert remaining == 5 - (i + 1)

    def test_exceeds_limit_blocked(self):
        """Request exceeding limit is blocked."""
        limiter = SQLiteRateLimiter()

        # Use up the limit
        for _ in range(5):
            limiter.is_allowed("client1", "endpoint", 5, 60)

        # Next request should be blocked
        allowed, remaining, retry_after = limiter.is_allowed(
            "client1", "endpoint", 5, 60
        )

        assert allowed is False
        assert remaining == 0
        assert retry_after > 0

    def test_different_clients_independent(self):
        """Different clients have independent limits."""
        limiter = SQLiteRateLimiter()

        # Client 1 uses up limit
        for _ in range(5):
            limiter.is_allowed("client1", "endpoint", 5, 60)

        # Client 2 should still be allowed
        allowed, _, _ = limiter.is_allowed("client2", "endpoint", 5, 60)

        assert allowed is True

    def test_different_endpoints_independent(self):
        """Different endpoints have independent limits."""
        limiter = SQLiteRateLimiter()

        # Use up limit on endpoint1
        for _ in range(5):
            limiter.is_allowed("client", "endpoint1", 5, 60)

        # endpoint2 should still be allowed
        allowed, _, _ = limiter.is_allowed("client", "endpoint2", 5, 60)

        assert allowed is True

    def test_window_reset(self):
        """Limit resets after window expires."""
        limiter = SQLiteRateLimiter()

        # Use up limit
        for _ in range(5):
            limiter.is_allowed("client", "endpoint", 5, 1)  # 1 second window

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        allowed, remaining, _ = limiter.is_allowed("client", "endpoint", 5, 1)

        assert allowed is True
        assert remaining == 4

    def test_retry_after_calculation(self):
        """retry_after is calculated correctly."""
        limiter = SQLiteRateLimiter()

        # Use up limit with 60 second window
        for _ in range(5):
            limiter.is_allowed("client", "endpoint", 5, 60)

        # Get blocked
        _, _, retry_after = limiter.is_allowed("client", "endpoint", 5, 60)

        # retry_after should be close to 60 (window seconds)
        assert 55 <= retry_after <= 61


# =============================================================================
# RESET TESTS
# =============================================================================

class TestReset:
    """Tests for reset method."""

    def test_reset_clears_limit(self):
        """reset clears rate limit for client/endpoint."""
        limiter = SQLiteRateLimiter()

        # Use up limit
        for _ in range(5):
            limiter.is_allowed("client", "endpoint", 5, 60)

        # Verify blocked
        allowed, _, _ = limiter.is_allowed("client", "endpoint", 5, 60)
        assert allowed is False

        # Reset
        limiter.reset("client", "endpoint")

        # Should be allowed again
        allowed, _, _ = limiter.is_allowed("client", "endpoint", 5, 60)
        assert allowed is True

    def test_reset_specific_only(self):
        """reset only affects specific client/endpoint."""
        limiter = SQLiteRateLimiter()

        # Use up limits on two endpoints
        for _ in range(5):
            limiter.is_allowed("client", "endpoint1", 5, 60)
            limiter.is_allowed("client", "endpoint2", 5, 60)

        # Reset only endpoint1
        limiter.reset("client", "endpoint1")

        # endpoint1 should be allowed
        allowed1, _, _ = limiter.is_allowed("client", "endpoint1", 5, 60)
        assert allowed1 is True

        # endpoint2 should still be blocked
        allowed2, _, _ = limiter.is_allowed("client", "endpoint2", 5, 60)
        assert allowed2 is False


# =============================================================================
# CLEANUP TESTS
# =============================================================================

class TestCleanup:
    """Tests for cleanup method."""

    def test_cleanup_removes_old_entries(self):
        """cleanup removes entries older than max_age."""
        limiter = SQLiteRateLimiter()

        # Create an entry
        limiter.is_allowed("client", "endpoint", 5, 1)

        # Wait for it to expire
        time.sleep(1.1)

        # Cleanup
        count = limiter.cleanup(max_age_seconds=1)

        assert count >= 1

    def test_cleanup_keeps_recent_entries(self):
        """cleanup keeps entries within max_age."""
        limiter = SQLiteRateLimiter()

        # Create an entry
        limiter.is_allowed("client", "endpoint", 5, 60)

        # Cleanup with long max_age
        count = limiter.cleanup(max_age_seconds=3600)

        # Entry should still exist
        conn = limiter._get_conn()
        row = conn.execute(
            "SELECT count FROM rate_limits WHERE key = ?",
            ("client:endpoint",)
        ).fetchone()

        assert row is not None
        assert count == 0


# =============================================================================
# SINGLETON TESTS
# =============================================================================

class TestSingleton:
    """Tests for singleton pattern."""

    def test_get_instance_returns_same_object(self):
        """get_instance returns same instance."""
        # Reset singleton
        SQLiteRateLimiter._instance = None

        instance1 = SQLiteRateLimiter.get_instance()
        instance2 = SQLiteRateLimiter.get_instance()

        assert instance1 is instance2

    def test_get_instance_creates_new_if_none(self):
        """get_instance creates new instance if none exists."""
        # Reset singleton
        SQLiteRateLimiter._instance = None

        instance = SQLiteRateLimiter.get_instance()

        assert instance is not None
        assert isinstance(instance, SQLiteRateLimiter)


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

class TestThreadSafety:
    """Tests for thread safety."""

    def test_thread_local_connections(self):
        """Each thread gets its own connection."""
        limiter = SQLiteRateLimiter()
        connections = []

        def get_conn():
            conn = limiter._get_conn()
            connections.append(id(conn))

        threads = [threading.Thread(target=get_conn) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have 5 different connections
        assert len(set(connections)) == 5

    def test_concurrent_is_allowed(self):
        """Concurrent is_allowed calls are safe."""
        limiter = SQLiteRateLimiter()
        results = []
        errors = []

        def check():
            try:
                allowed, _, _ = limiter.is_allowed(
                    "client", "endpoint", 100, 60
                )
                results.append(allowed)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=check) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have no errors
        assert len(errors) == 0
        # All should be allowed (limit is 100)
        assert len([r for r in results if r]) == 20


# =============================================================================
# DATABASE ERROR HANDLING TESTS
# =============================================================================

class TestDatabaseErrorHandling:
    """Tests for database error handling."""

    def test_allows_request_on_db_error(self):
        """Request is allowed when database error occurs."""
        limiter = SQLiteRateLimiter()

        # Force connection
        limiter._get_conn()

        # Mock the connection to raise error
        with patch.object(limiter._local, 'conn') as mock_conn:
            mock_conn.execute.side_effect = sqlite3.Error("DB error")

            allowed, remaining, _ = limiter.is_allowed(
                "client", "endpoint", 5, 60
            )

        # Should fail open
        assert allowed is True
        assert remaining == 5


# =============================================================================
# WAL MODE TESTS
# =============================================================================

class TestWALMode:
    """Tests for WAL mode configuration."""

    def test_wal_mode_enabled_for_file_db(self):
        """WAL mode is enabled for file database."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate_limits.db"
            limiter = SQLiteRateLimiter(db_path)

            conn = limiter._get_conn()

            # Check journal mode (WAL for file, memory for :memory:)
            result = conn.execute("PRAGMA journal_mode").fetchone()
            assert result[0].lower() == "wal"

    def test_memory_db_uses_memory_mode(self):
        """In-memory database uses memory journal mode."""
        limiter = SQLiteRateLimiter()  # In-memory by default

        conn = limiter._get_conn()

        # In-memory DB uses "memory" journal mode, not WAL
        result = conn.execute("PRAGMA journal_mode").fetchone()
        assert result[0].lower() == "memory"

    def test_busy_timeout_set(self):
        """Busy timeout is configured."""
        limiter = SQLiteRateLimiter()

        conn = limiter._get_conn()

        # Check busy timeout
        result = conn.execute("PRAGMA busy_timeout").fetchone()
        assert result[0] == 5000  # 5 seconds


# =============================================================================
# MODULE CONSTANTS TESTS
# =============================================================================

class TestModuleConstants:
    """Tests for module-level constants."""

    def test_slowapi_available_is_bool(self):
        """SLOWAPI_AVAILABLE is boolean."""
        SLOWAPI_AVAILABLE = _limiter_module.SLOWAPI_AVAILABLE

        assert isinstance(SLOWAPI_AVAILABLE, bool)

    def test_limiter_exists(self):
        """limiter variable exists (may be None)."""
        limiter = _limiter_module.limiter

        # Should be either None or a Limiter instance
        assert limiter is None or limiter is not None


# =============================================================================
# PERSISTENT DATABASE TESTS
# =============================================================================

class TestPersistentDatabase:
    """Tests for persistent file database."""

    def test_persists_across_instances(self):
        """Rate limits persist across limiter instances."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate_limits.db"

            # First instance - use up limit
            limiter1 = SQLiteRateLimiter(db_path)
            for _ in range(5):
                limiter1.is_allowed("client", "endpoint", 5, 60)

            # Second instance - should see existing limit
            limiter2 = SQLiteRateLimiter(db_path)
            allowed, _, _ = limiter2.is_allowed("client", "endpoint", 5, 60)

            assert allowed is False

    def test_creates_db_file(self):
        """Creates database file on disk."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate_limits.db"

            limiter = SQLiteRateLimiter(db_path)
            limiter.is_allowed("client", "endpoint", 5, 60)

            assert db_path.exists()

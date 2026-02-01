"""
Rate limiter configuration.

Provides two rate limiting mechanisms:
1. slowapi - Standard FastAPI rate limiting (if available)
2. SQLiteRateLimiter - Process-safe rate limiting via SQLite

SQLiteRateLimiter is preferred for multi-worker deployments as it
shares state across processes through the database.
"""

import logging
import time
import sqlite3
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SQLiteRateLimiter:
    """
    Process-safe rate limiter using SQLite for state storage.

    This rate limiter works correctly across multiple uvicorn workers
    because SQLite handles concurrent access with WAL mode.

    Usage:
        limiter = SQLiteRateLimiter(db_path)
        if not limiter.is_allowed("user_ip", "endpoint", limit=10, window=60):
            raise HTTPException(429, "Rate limit exceeded")
    """

    _instance: Optional["SQLiteRateLimiter"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize rate limiter with SQLite database."""
        if db_path is None:
            # Use in-memory for testing, or default path
            self._db_path = ":memory:"
        else:
            self._db_path = str(db_path)

        self._conn: Optional[sqlite3.Connection] = None
        self._local = threading.local()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=5.0,
            )
            self._local.conn.execute("PRAGMA journal_mode = WAL")
            self._local.conn.execute("PRAGMA busy_timeout = 5000")
            self._init_schema(self._local.conn)
        return self._local.conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        """Create rate limit table if not exists."""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 1,
                window_start REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rate_limits_window
            ON rate_limits(window_start)
        """)
        conn.commit()

    def is_allowed(
        self,
        client_key: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int, int]:
        """
        Check if request is allowed under rate limit.

        Args:
            client_key: Client identifier (usually IP)
            endpoint: Endpoint being accessed
            limit: Maximum requests per window
            window_seconds: Window duration in seconds

        Returns:
            Tuple of (allowed, remaining, retry_after_seconds)

        SECURITY: Uses atomic operations to prevent TOCTOU race conditions.
        Concurrent requests cannot bypass rate limits by racing between
        check and increment.
        """
        conn = self._get_conn()
        key = f"{client_key}:{endpoint}"
        now = time.time()
        window_start_threshold = now - window_seconds

        try:
            # Clean up expired entries periodically (1% of requests)
            if hash(key) % 100 == 0:
                conn.execute(
                    "DELETE FROM rate_limits WHERE window_start < ?",
                    (window_start_threshold,)
                )

            # SECURITY FIX: Use atomic INSERT OR REPLACE with conditional logic
            # This prevents TOCTOU race conditions where concurrent requests
            # could bypass rate limits by racing between SELECT and UPDATE.
            #
            # We use a single atomic operation:
            # 1. Try to insert new record (if none exists)
            # 2. Or update existing record atomically
            # 3. Return the new count in one round-trip

            # First, atomically insert or update and get the result
            # Use INSERT ... ON CONFLICT to handle both cases atomically
            conn.execute("""
                INSERT INTO rate_limits (key, count, window_start)
                VALUES (?, 1, ?)
                ON CONFLICT(key) DO UPDATE SET
                    count = CASE
                        WHEN window_start < ? THEN 1
                        ELSE count + 1
                    END,
                    window_start = CASE
                        WHEN window_start < ? THEN ?
                        ELSE window_start
                    END
            """, (key, now, window_start_threshold, window_start_threshold, now))
            conn.commit()

            # Now fetch the current state (after our atomic update)
            row = conn.execute(
                "SELECT count, window_start FROM rate_limits WHERE key = ?",
                (key,)
            ).fetchone()

            if row is None:
                # Should not happen after INSERT, but handle gracefully
                return True, limit - 1, 0

            count, window_start = row

            if count > limit:
                # Rate limit exceeded (we already incremented, so check > not >=)
                retry_after = int(window_start + window_seconds - now) + 1
                return False, 0, max(1, retry_after)

            return True, limit - count, 0

        except sqlite3.Error as e:
            logger.warning(f"Rate limit check failed: {e}, allowing request")
            return True, limit, 0

    def reset(self, client_key: str, endpoint: str) -> None:
        """Reset rate limit for a client/endpoint pair."""
        conn = self._get_conn()
        key = f"{client_key}:{endpoint}"
        conn.execute("DELETE FROM rate_limits WHERE key = ?", (key,))
        conn.commit()

    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """Remove expired entries older than max_age."""
        conn = self._get_conn()
        threshold = time.time() - max_age_seconds
        cursor = conn.execute(
            "DELETE FROM rate_limits WHERE window_start < ?",
            (threshold,)
        )
        conn.commit()
        return cursor.rowcount

    @classmethod
    def get_instance(cls, db_path: Optional[Path] = None) -> "SQLiteRateLimiter":
        """Get or create singleton instance."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance


# Limiter instance - initialized if slowapi is available
limiter = None
SLOWAPI_AVAILABLE = False

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["100/minute"],
        headers_enabled=True,
    )
    SLOWAPI_AVAILABLE = True
    logger.info("Rate limiting enabled via slowapi")
except ImportError:
    logger.warning(
        "slowapi not installed - rate limiting disabled. "
        "Install with: pip install slowapi"
    )

# Re-export for convenience
if SLOWAPI_AVAILABLE:
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from slowapi import _rate_limit_exceeded_handler

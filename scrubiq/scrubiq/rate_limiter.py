"""
Persistent Rate Limiter for ScrubIQ.

SECURITY FIX: Rate limit state is now persisted to SQLite instead of
in-memory dict. This prevents attackers from bypassing rate limits by
crashing/restarting the server.

For cloud deployments, consider using Redis for distributed rate limiting.
This SQLite-based solution works well for single-instance deployments.

Usage:
    from .rate_limiter import RateLimiter, check_rate_limit
    
    # In route:
    check_rate_limit(request, "unlock", limit=5, window_seconds=60)
"""

import logging
import os
import time
from typing import Optional, Tuple
from fastapi import Request

logger = logging.getLogger(__name__)


# --- CONFIGURATION ---
# Environment variable to trust proxy headers (only set if behind known proxy)
_TRUST_PROXY = os.environ.get("TRUST_PROXY", "").lower() in ("1", "true", "yes")
_TRUSTED_PROXIES = set(
    p.strip() for p in os.environ.get("TRUSTED_PROXY_IPS", "").split(",") if p.strip()
)


def get_client_ip(request: Request) -> str:
    """
    Get client IP address securely.
    
    Only trusts X-Forwarded-For if:
    1. TRUST_PROXY env var is set, AND
    2. Request comes from a trusted proxy IP
    
    This prevents attackers from spoofing their IP via X-Forwarded-For header.
    """
    direct_ip = request.client.host if request.client else "unknown"
    
    # Only trust forwarded headers if explicitly configured
    if _TRUST_PROXY and direct_ip in _TRUSTED_PROXIES:
        # Get the leftmost (original client) IP from X-Forwarded-For
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # X-Forwarded-For format: client, proxy1, proxy2, ...
            client_ip = forwarded.split(",")[0].strip()
            if client_ip:
                return client_ip
    
    return direct_ip


# --- RATE LIMITER ---
class RateLimiter:
    """
    SQLite-backed rate limiter that persists across restarts.
    
    Uses a simple sliding window algorithm with configurable limits per action.
    
    Table schema (auto-created):
        rate_limits (
            id INTEGER PRIMARY KEY,
            action TEXT NOT NULL,        -- e.g., "unlock", "upload"
            client_ip TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            window_start REAL NOT NULL,  -- Unix timestamp
            UNIQUE(action, client_ip)
        )
    """
    
    def __init__(self, db):
        """
        Initialize rate limiter with database connection.
        
        Args:
            db: Database instance from storage.database
        """
        self._db = db
        self._ensure_table()
    
    def _ensure_table(self) -> None:
        """Create rate_limits table if it doesn't exist."""
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 1,
                window_start REAL NOT NULL,
                UNIQUE(action, client_ip)
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_rate_limits_action_ip 
            ON rate_limits(action, client_ip)
        """)
    
    def check(
        self,
        client_ip: str,
        action: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int, Optional[int]]:
        """
        Check if request is within rate limit.

        SECURITY: Uses atomic UPDATE to prevent race conditions where
        concurrent requests could bypass the rate limit.

        Args:
            client_ip: Client IP address
            action: Action being rate-limited (e.g., "unlock")
            limit: Maximum attempts allowed in window
            window_seconds: Time window in seconds

        Returns:
            (allowed, current_count, retry_after_seconds)
            - allowed: True if request should proceed
            - current_count: Number of attempts in current window
            - retry_after_seconds: Seconds until window resets (if blocked)
        """
        current_time = time.time()
        window_cutoff = current_time - window_seconds

        with self._db.transaction():
            # SECURITY: Atomic upsert with conditional increment
            # This prevents race conditions by doing check + update in single statement
            self._db.conn.execute("""
                INSERT INTO rate_limits (action, client_ip, attempt_count, window_start)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(action, client_ip) DO UPDATE SET
                    attempt_count = CASE
                        WHEN window_start < ? THEN 1
                        ELSE attempt_count + 1
                    END,
                    window_start = CASE
                        WHEN window_start < ? THEN ?
                        ELSE window_start
                    END
            """, (action, client_ip, current_time, window_cutoff, window_cutoff, current_time))

            # Now read the updated state
            row = self._db.conn.execute("""
                SELECT attempt_count, window_start
                FROM rate_limits
                WHERE action = ? AND client_ip = ?
            """, (action, client_ip)).fetchone()

            attempt_count = row["attempt_count"]
            window_start = row["window_start"]

            # Check if over limit (we already incremented, so check > limit)
            if attempt_count > limit:
                retry_after = int(window_seconds - (current_time - window_start))
                return False, attempt_count, max(1, retry_after)

            return True, attempt_count, None
    
    def reset(self, client_ip: str, action: str) -> None:
        """
        Reset rate limit for a client/action (e.g., after successful auth).
        
        Args:
            client_ip: Client IP address
            action: Action to reset
        """
        self._db.execute("""
            DELETE FROM rate_limits WHERE action = ? AND client_ip = ?
        """, (action, client_ip))
    
    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """
        Remove expired rate limit entries.
        
        Args:
            max_age_seconds: Remove entries older than this (default 1 hour)
            
        Returns:
            Number of entries removed
        """
        cutoff = time.time() - max_age_seconds
        cursor = self._db.execute("""
            DELETE FROM rate_limits WHERE window_start < ?
        """, (cutoff,))
        return cursor.rowcount


# --- GLOBAL INSTANCE & HELPERS ---
# Global rate limiter instance (set during app initialization)
_rate_limiter: Optional[RateLimiter] = None

# Fallback in-memory limiter for when DB not available
# Protected by _memory_limits_lock for thread safety
import threading
_memory_limits: dict = {}  # (action, ip) -> (count, window_start)
_memory_limits_lock = threading.Lock()


def init_rate_limiter(db) -> RateLimiter:
    """
    Initialize the global rate limiter with a database connection.
    
    Call this during app startup after database is connected.
    
    Args:
        db: Database instance
        
    Returns:
        RateLimiter instance
    """
    global _rate_limiter
    _rate_limiter = RateLimiter(db)
    logger.info("Persistent rate limiter initialized")
    return _rate_limiter


def get_rate_limiter() -> Optional[RateLimiter]:
    """Get the global rate limiter instance."""
    return _rate_limiter


def check_rate_limit(
    request: Request,
    action: str,
    limit: int = 5,
    window_seconds: int = 60,
) -> None:
    """
    Check rate limit for a request. Raises APIError(429) if exceeded.

    Falls back to in-memory limiting if database limiter not initialized.

    Args:
        request: FastAPI request object
        action: Action being rate-limited (e.g., "unlock", "upload")
        limit: Maximum attempts allowed in window
        window_seconds: Time window in seconds

    Raises:
        APIError: 429 if rate limit exceeded
    """
    # Import here to avoid circular imports
    from .api.errors import rate_limited

    client_ip = get_client_ip(request)

    # Use persistent limiter if available
    if _rate_limiter is not None:
        allowed, count, retry_after = _rate_limiter.check(
            client_ip=client_ip,
            action=action,
            limit=limit,
            window_seconds=window_seconds,
        )

        if not allowed:
            logger.warning(
                f"Rate limit exceeded for {action} from {client_ip} "
                f"(count={count}, limit={limit})"
            )
            raise rate_limited(
                retry_after=retry_after,
                detail=f"Too many {action} attempts. Try again in {retry_after} seconds.",
            )
        return

    # Fallback to in-memory limiting
    _check_memory_rate_limit(client_ip, action, limit, window_seconds)


def _check_memory_rate_limit(
    client_ip: str,
    action: str,
    limit: int,
    window_seconds: int,
) -> None:
    """
    In-memory fallback rate limiter.

    Used when database limiter not initialized.
    WARNING: Resets on server restart.
    Thread-safe: Protected by _memory_limits_lock.
    """
    # Import here to avoid circular imports
    from .api.errors import rate_limited

    current_time = time.time()
    key = (action, client_ip)

    with _memory_limits_lock:
        if key in _memory_limits:
            count, window_start = _memory_limits[key]

            if current_time - window_start > window_seconds:
                # Reset window
                _memory_limits[key] = (1, current_time)
            else:
                if count >= limit:
                    retry_after = int(window_seconds - (current_time - window_start))
                    logger.warning(
                        f"Rate limit exceeded for {action} from {client_ip} "
                        f"(in-memory fallback)"
                    )
                    raise rate_limited(
                        retry_after=retry_after,
                        detail=f"Too many {action} attempts. Try again in {retry_after} seconds.",
                    )
                _memory_limits[key] = (count + 1, window_start)
        else:
            _memory_limits[key] = (1, current_time)


def reset_rate_limit(request: Request, action: str) -> None:
    """
    Reset rate limit for a client after successful action (e.g., login).

    Args:
        request: FastAPI request object
        action: Action to reset
    """
    client_ip = get_client_ip(request)

    if _rate_limiter is not None:
        _rate_limiter.reset(client_ip, action)
    else:
        key = (action, client_ip)
        with _memory_limits_lock:
            _memory_limits.pop(key, None)


def check_api_key_rate_limit(request: Request, action: str = "api") -> None:
    """
    Check rate limit for an API key. Uses the key's configured rate limit.

    This should be called AFTER API key validation (so request.state.api_key exists).

    Args:
        request: FastAPI request object (must have api_key in state)
        action: Action being rate-limited (default: "api")

    Raises:
        APIError: 429 if rate limit exceeded
    """
    from .api.errors import rate_limited

    # Get API key metadata from request state
    api_key_meta = getattr(request.state, "api_key", None)
    if api_key_meta is None:
        # No API key in request - fall back to IP-based limiting
        check_rate_limit(request, action, limit=100, window_seconds=60)
        return

    # Use API key prefix as identifier (more specific than IP)
    key_id = f"apikey:{api_key_meta.key_prefix}"

    # Use the key's configured rate limit (requests per minute)
    limit = api_key_meta.rate_limit
    window_seconds = 60  # Always per-minute for API keys

    if _rate_limiter is not None:
        allowed, count, retry_after = _rate_limiter.check(
            client_ip=key_id,  # Using key_id instead of IP
            action=action,
            limit=limit,
            window_seconds=window_seconds,
        )

        if not allowed:
            logger.warning(
                f"Rate limit exceeded for {api_key_meta.key_prefix} "
                f"(count={count}, limit={limit})"
            )
            raise rate_limited(
                retry_after=retry_after,
                detail=f"Rate limit exceeded ({limit} requests/minute). Try again in {retry_after} seconds.",
            )
        return

    # Fallback to in-memory limiting
    _check_memory_rate_limit(key_id, action, limit, window_seconds)

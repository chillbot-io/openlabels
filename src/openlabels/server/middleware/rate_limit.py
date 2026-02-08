"""Rate limiting with Redis primary and in-memory fallback.

Provides two complementary rate limiters:

* **IP-based** — ``create_limiter()`` builds a :class:`slowapi.Limiter`
  for unauthenticated endpoints (``/auth/*``, ``/health``).
* **Per-tenant** — :class:`TenantRateLimiter` tracks per-tenant request
  counts with sliding windows for authenticated API endpoints.
"""

from __future__ import annotations

import logging
import time
import threading
from collections import defaultdict
from typing import Annotated

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter

from openlabels.server.config import get_settings
from openlabels.server.utils import get_client_ip

logger = logging.getLogger(__name__)

_KEY_PREFIX = "openlabels:ratelimit"


# ---------------------------------------------------------------------------
# IP-based rate limiting (slowapi — for unauthenticated endpoints)
# ---------------------------------------------------------------------------


def _get_storage_uri() -> str | None:
    """Resolve the storage URI for rate-limit counters.

    Priority:
      1. ``rate_limit.storage_uri`` (explicit override)
      2. ``redis.url`` if Redis is enabled
      3. ``None`` → in-memory storage
    """
    settings = get_settings()

    if settings.rate_limit.storage_uri is not None:
        # Empty string forces in-memory even when Redis is available.
        return settings.rate_limit.storage_uri or None

    if settings.redis.enabled:
        return settings.redis.url

    return None


def _validate_redis(storage_uri: str) -> bool:
    """Check whether the Redis instance at *storage_uri* is reachable."""
    try:
        from limits.storage import RedisStorage

        storage = RedisStorage(storage_uri)
        storage.check()
        return True
    except ImportError:
        logger.warning(
            "limits[redis] not installed — using in-memory rate limiting. "
            "Install with: pip install limits[redis]"
        )
    except Exception as e:
        logger.warning(
            f"Redis unavailable for rate limiting ({type(e).__name__}: {e}) — "
            "using in-memory fallback"
        )
    return False


def create_limiter() -> Limiter:
    """Create a :class:`Limiter` with the best available storage backend.

    Tries Redis first (if configured and reachable), otherwise falls back
    to in-memory storage.
    """
    storage_uri = _get_storage_uri()

    if storage_uri and _validate_redis(storage_uri):
        logger.info(f"Rate limiter using Redis storage: {storage_uri}")
        return Limiter(
            key_func=get_client_ip,
            storage_uri=storage_uri,
            key_prefix=_KEY_PREFIX,
        )

    logger.info("Rate limiter using in-memory storage")
    return Limiter(key_func=get_client_ip, key_prefix=_KEY_PREFIX)


# ---------------------------------------------------------------------------
# Per-tenant rate limiting (for authenticated API endpoints)
# ---------------------------------------------------------------------------


class TenantRateLimiter:
    """Sliding-window rate limiter keyed by tenant ID.

    Thread-safe — safe to share as a singleton across async workers.

    Usage as a FastAPI dependency::

        @router.get("/scans")
        async def list_scans(
            tenant: TenantContextDep,
            _rl: TenantRateLimitDep,
        ) -> ...:
            ...
    """

    def __init__(
        self,
        requests_per_minute: int = 300,
        requests_per_hour: int = 10_000,
    ) -> None:
        self.rpm_limit = requests_per_minute
        self.rph_limit = requests_per_hour
        self._lock = threading.Lock()
        self._minute_counts: dict[str, list[float]] = defaultdict(list)
        self._hour_counts: dict[str, list[float]] = defaultdict(list)

    def check_rate_limit(self, tenant_id: str) -> tuple[bool, dict[str, int]]:
        """Check and record a request for *tenant_id*.

        Returns ``(allowed, headers)`` where *headers* is a dict of
        ``X-RateLimit-*`` values to include in the response.
        """
        now = time.monotonic()

        with self._lock:
            # --- per-minute window ---
            minute_ago = now - 60
            minute_list = self._minute_counts[tenant_id]
            self._minute_counts[tenant_id] = minute_list = [
                t for t in minute_list if t > minute_ago
            ]
            minute_remaining = max(0, self.rpm_limit - len(minute_list))

            if len(minute_list) >= self.rpm_limit:
                return False, {
                    "X-RateLimit-Limit": self.rpm_limit,
                    "X-RateLimit-Remaining": 0,
                    "X-RateLimit-Reset": int(minute_list[0] - minute_ago),
                }

            # --- per-hour window ---
            hour_ago = now - 3600
            hour_list = self._hour_counts[tenant_id]
            self._hour_counts[tenant_id] = hour_list = [
                t for t in hour_list if t > hour_ago
            ]

            if len(hour_list) >= self.rph_limit:
                return False, {
                    "X-RateLimit-Limit": self.rph_limit,
                    "X-RateLimit-Remaining": 0,
                    "X-RateLimit-Reset": int(hour_list[0] - hour_ago),
                }

            # Record this request
            minute_list.append(now)
            hour_list.append(now)

        return True, {
            "X-RateLimit-Limit": self.rpm_limit,
            "X-RateLimit-Remaining": minute_remaining - 1,
        }


# Module-level singleton — initialised lazily by the dependency.
_tenant_limiter: TenantRateLimiter | None = None


def get_tenant_rate_limiter() -> TenantRateLimiter:
    """Return (or create) the global :class:`TenantRateLimiter`."""
    global _tenant_limiter
    if _tenant_limiter is None:
        settings = get_settings()
        _tenant_limiter = TenantRateLimiter(
            requests_per_minute=settings.rate_limit.tenant_rpm,
            requests_per_hour=settings.rate_limit.tenant_rph,
        )
    return _tenant_limiter

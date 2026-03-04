"""Rate limiting with Redis primary and in-memory fallback.

Provides two complementary rate limiters:

* **IP-based** — ``create_limiter()`` builds a :class:`slowapi.Limiter`
  for unauthenticated endpoints (``/auth/*``, ``/health``).
* **Per-tenant** — :class:`TenantRateLimiter` tracks per-tenant request
  counts with sliding windows for authenticated API endpoints.
  Uses Redis when available for cross-instance accuracy; falls back
  to in-memory counters (per-instance only) otherwise.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

from slowapi import Limiter

from openlabels.server.config import get_settings
from openlabels.server.utils import get_client_ip

logger = logging.getLogger(__name__)

_KEY_PREFIX = "openlabels:ratelimit"
_TENANT_KEY_PREFIX = "openlabels:tenant_rl:"


# IP-based rate limiting (slowapi — for unauthenticated endpoints)
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


# Per-tenant rate limiting (for authenticated API endpoints)

# Maximum number of distinct tenants tracked in the in-memory backend
# before stale entries are evicted.  This caps worst-case memory usage
# regardless of how many unique tenant IDs are seen.
_MAX_TENANTS = 10_000

# Interval (in seconds) between full sweeps that remove tenants whose
# timestamps have all expired.  This is tracked via a monotonic clock
# and checked inside ``check_and_record`` so no background thread is
# needed.
_SWEEP_INTERVAL = 300  # 5 minutes


class _InMemoryTenantBackend:
    """In-memory sliding-window counters with stale-entry eviction.

    Two eviction strategies prevent unbounded memory growth:

    1. **Periodic sweep** — every ``_SWEEP_INTERVAL`` seconds the full
       dict is scanned and tenants whose timestamps are all older than
       the hour window are removed.
    2. **Max-size LRU** — if the number of tracked tenants exceeds
       ``_MAX_TENANTS`` after recording a request, the oldest-accessed
       half of entries are evicted.
    """

    def __init__(
        self,
        max_tenants: int = _MAX_TENANTS,
        sweep_interval: float = _SWEEP_INTERVAL,
    ) -> None:
        self._lock = threading.Lock()
        self._minute_counts: dict[str, list[float]] = defaultdict(list)
        self._hour_counts: dict[str, list[float]] = defaultdict(list)
        # Track last-access time per tenant for LRU eviction
        self._last_access: dict[str, float] = {}
        self._max_tenants = max_tenants
        self._sweep_interval = sweep_interval
        self._last_sweep: float = time.monotonic()

    # -- public API --------------------------------------------------------

    def check_and_record(
        self, tenant_id: str, rpm_limit: int, rph_limit: int,
    ) -> tuple[bool, int, int]:
        """Returns (allowed, minute_remaining, hour_remaining)."""
        now = time.monotonic()

        with self._lock:
            # Run periodic sweep if interval has elapsed
            if now - self._last_sweep >= self._sweep_interval:
                self._sweep_stale(now)
                self._last_sweep = now

            minute_ago = now - 60
            minute_list = self._minute_counts[tenant_id]
            self._minute_counts[tenant_id] = minute_list = [
                t for t in minute_list if t > minute_ago
            ]

            if len(minute_list) >= rpm_limit:
                return False, 0, 0

            hour_ago = now - 3600
            hour_list = self._hour_counts[tenant_id]
            self._hour_counts[tenant_id] = hour_list = [
                t for t in hour_list if t > hour_ago
            ]

            if len(hour_list) >= rph_limit:
                return False, 0, 0

            minute_list.append(now)
            hour_list.append(now)
            self._last_access[tenant_id] = now

            # Enforce max-size cap
            if len(self._last_access) > self._max_tenants:
                self._evict_lru()

        return True, max(0, rpm_limit - len(minute_list)), max(0, rph_limit - len(hour_list))

    # -- eviction helpers (must be called under self._lock) ----------------

    def _sweep_stale(self, now: float) -> None:
        """Remove tenants with no timestamps within the hour window."""
        hour_ago = now - 3600
        stale_ids = [
            tid for tid, timestamps in self._hour_counts.items()
            if not timestamps or timestamps[-1] <= hour_ago
        ]
        for tid in stale_ids:
            self._minute_counts.pop(tid, None)
            self._hour_counts.pop(tid, None)
            self._last_access.pop(tid, None)

    def _evict_lru(self) -> None:
        """Evict the oldest-accessed half of tenants to stay under the cap."""
        sorted_tenants = sorted(
            self._last_access.items(), key=lambda item: item[1],
        )
        evict_count = len(sorted_tenants) // 2
        for tid, _ in sorted_tenants[:evict_count]:
            self._minute_counts.pop(tid, None)
            self._hour_counts.pop(tid, None)
            self._last_access.pop(tid, None)


class _RedisTenantBackend:
    """Redis-backed fixed-window counters shared across all instances.

    Uses two keys per tenant per window:
    - ``openlabels:tenant_rl:{tenant_id}:m:{window}`` — minute window
    - ``openlabels:tenant_rl:{tenant_id}:h:{window}`` — hour window

    INCR + EXPIRE is atomic enough for rate limiting (slight over-count
    at window boundaries is acceptable).
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def check_and_record(
        self, tenant_id: str, rpm_limit: int, rph_limit: int,
    ) -> tuple[bool, int, int]:
        """Returns (allowed, minute_remaining, hour_remaining)."""
        now = int(time.time())
        minute_window = now // 60
        hour_window = now // 3600

        minute_key = f"{_TENANT_KEY_PREFIX}{tenant_id}:m:{minute_window}"
        hour_key = f"{_TENANT_KEY_PREFIX}{tenant_id}:h:{hour_window}"

        pipe = self._redis.pipeline()
        pipe.incr(minute_key)
        pipe.expire(minute_key, 120)  # 2 min TTL (covers window + margin)
        pipe.incr(hour_key)
        pipe.expire(hour_key, 7200)  # 2 hour TTL
        results = await pipe.execute()

        minute_count = results[0]
        hour_count = results[2]

        if minute_count > rpm_limit:
            return False, 0, 0
        if hour_count > rph_limit:
            return False, 0, 0

        return (
            True,
            max(0, rpm_limit - minute_count),
            max(0, rph_limit - hour_count),
        )


class TenantRateLimiter:
    """Sliding-window rate limiter keyed by tenant ID.

    Uses Redis when available for cross-instance accuracy.
    Falls back to in-memory counters (per-instance only) when Redis
    is unavailable.

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
        redis_client: Any = None,
    ) -> None:
        self.rpm_limit = requests_per_minute
        self.rph_limit = requests_per_hour
        self._redis_backend: _RedisTenantBackend | None = None
        self._memory_backend = _InMemoryTenantBackend()

        if redis_client is not None:
            self._redis_backend = _RedisTenantBackend(redis_client)
            logger.info("Tenant rate limiter using Redis (shared across instances)")
        else:
            # SECURITY (M-30): In-memory rate limiting is per-worker-process.
            # With N workers each tracking limits independently, the effective
            # cluster-wide limit is N × configured limit.  Divide by the
            # configured worker count so the aggregate stays close to the
            # intended cap.
            settings = get_settings()
            worker_count = max(settings.server.workers, 1)
            self.rpm_limit = max(1, requests_per_minute // worker_count)
            self.rph_limit = max(1, requests_per_hour // worker_count)
            logger.warning(
                "Tenant rate limiter using in-memory storage "
                "(per-instance only — limits not shared across workers). "
                "Effective per-worker limits: %d rpm, %d rph (divided by %d workers). "
                "Configure Redis for accurate cross-instance rate limiting.",
                self.rpm_limit,
                self.rph_limit,
                worker_count,
            )

    @property
    def is_distributed(self) -> bool:
        return self._redis_backend is not None

    async def check_rate_limit(self, tenant_id: str) -> tuple[bool, dict[str, int]]:
        """Check and record a request for *tenant_id*.

        Returns ``(allowed, headers)`` where *headers* is a dict of
        ``X-RateLimit-*`` values to include in the response.
        """
        if self._redis_backend is not None:
            try:
                allowed, minute_rem, _ = await self._redis_backend.check_and_record(
                    tenant_id, self.rpm_limit, self.rph_limit,
                )
                if not allowed:
                    return False, {
                        "X-RateLimit-Limit": self.rpm_limit,
                        "X-RateLimit-Remaining": 0,
                        "X-RateLimit-Reset": 60,
                    }
                return True, {
                    "X-RateLimit-Limit": self.rpm_limit,
                    "X-RateLimit-Remaining": minute_rem,
                }
            except Exception as e:
                # SECURITY (M-30): Log warning when falling back to in-memory
                # at runtime — limits will be per-worker, not cluster-wide.
                logger.warning(
                    "Redis tenant rate limit failed (%s), falling back to "
                    "in-memory (per-worker limits apply)",
                    e,
                )

        # In-memory fallback — when Redis was configured but failed at runtime,
        # divide limits by worker count since each worker tracks independently
        # (M-30).  When Redis was never configured, limits were already divided
        # in __init__, so use them as-is.
        if self._redis_backend is not None:
            settings = get_settings()
            worker_count = max(settings.server.workers, 1)
            mem_rpm = max(1, self.rpm_limit // worker_count)
            mem_rph = max(1, self.rph_limit // worker_count)
        else:
            mem_rpm = self.rpm_limit
            mem_rph = self.rph_limit
        allowed, minute_rem, _ = self._memory_backend.check_and_record(
            tenant_id, mem_rpm, mem_rph,
        )
        if not allowed:
            return False, {
                "X-RateLimit-Limit": self.rpm_limit,
                "X-RateLimit-Remaining": 0,
                "X-RateLimit-Reset": 60,
            }
        return True, {
            "X-RateLimit-Limit": self.rpm_limit,
            "X-RateLimit-Remaining": minute_rem,
        }


# Module-level singleton — initialised lazily by the dependency.
_tenant_limiter: TenantRateLimiter | None = None


def get_tenant_rate_limiter() -> TenantRateLimiter:
    """Return (or create) the global :class:`TenantRateLimiter`."""
    global _tenant_limiter
    if _tenant_limiter is None:
        settings = get_settings()

        redis_client = None
        if settings.redis.enabled:
            try:
                import redis.asyncio as aioredis

                redis_client = aioredis.from_url(
                    settings.redis.url,
                    socket_connect_timeout=settings.redis.connect_timeout,
                    socket_timeout=settings.redis.socket_timeout,
                    decode_responses=True,
                )
            except ImportError:
                logger.info("redis package not installed — tenant rate limiter in-memory only")
            except Exception as e:
                logger.warning("Redis connection for tenant rate limiter failed: %s", e)

        _tenant_limiter = TenantRateLimiter(
            requests_per_minute=settings.rate_limit.tenant_rpm,
            requests_per_hour=settings.rate_limit.tenant_rph,
            redis_client=redis_client,
        )
    return _tenant_limiter

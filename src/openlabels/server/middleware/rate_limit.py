"""Rate limiting with Redis primary and in-memory fallback.

The ``create_limiter()`` function is the public entry point.  It builds
a :class:`slowapi.Limiter` backed by either Redis or an in-memory store,
depending on configuration and availability.
"""

from __future__ import annotations

import logging

from slowapi import Limiter

from openlabels.server.config import get_settings
from openlabels.server.utils import get_client_ip

logger = logging.getLogger(__name__)

_KEY_PREFIX = "openlabels:ratelimit"


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

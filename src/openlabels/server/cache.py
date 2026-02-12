"""
Redis caching infrastructure for OpenLabels.

Provides:
- Redis connection management with connection pooling
- Cache decorator for function results
- Cache invalidation utilities
- Fallback to in-memory cache if Redis unavailable
- TTL-based expiration support

Usage:
    from openlabels.server.cache import cache, get_cache_manager, invalidate_cache

    # Decorator for caching function results
    @cache(ttl=300, key_prefix="labels")
    async def get_labels(tenant_id: str) -> list[dict]:
        ...

    # Manual cache operations
    cache_manager = await get_cache_manager()
    await cache_manager.set("my_key", my_value, ttl=60)
    value = await cache_manager.get("my_key")
    await cache_manager.delete("my_key")

    # Invalidation by pattern
    await invalidate_cache("labels:*")
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from functools import wraps
from typing import Any, Optional, ParamSpec, TypeVar

try:
    from redis.exceptions import RedisError
except ImportError:
    # redis not installed - define a placeholder that will never match at runtime
    class RedisError(Exception):  # type: ignore[no-redef]
        """Placeholder when redis is not installed."""
        pass

logger = logging.getLogger(__name__)

# Type variables for generic decorators
P = ParamSpec("P")
T = TypeVar("T")

# Global cache manager instance
_cache_manager: Optional[CacheManager] = None
_cache_lock = asyncio.Lock()


class InMemoryCache:
    """
    Simple in-memory LRU cache with TTL support.

    Used as fallback when Redis is unavailable.
    Thread-safe for asyncio operations.
    """

    def __init__(self, max_size: int = 1000):
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._max_size = max_size
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0

    async def get(self, key: str) -> Any | None:
        """Get value from cache if not expired."""
        async with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None

            value, expires_at = self._cache[key]

            # Check TTL expiration
            if expires_at and time.time() > expires_at:
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end for LRU
            self._cache.move_to_end(key)
            self._hits += 1
            return value

    async def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        """Set value in cache with optional TTL."""
        async with self._lock:
            expires_at = time.time() + ttl if ttl else None

            # Evict expired entries first before removing valid ones
            if len(self._cache) >= self._max_size:
                now = time.time()
                expired_keys = [
                    k for k, (_, exp) in self._cache.items()
                    if exp and now > exp
                ]
                for k in expired_keys:
                    del self._cache[k]

            # If still at capacity, remove oldest (LRU) items
            while len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)

            self._cache[key] = (value, expires_at)
            self._cache.move_to_end(key)
            return True

    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """Delete keys matching a pattern (simple glob-style with *)."""
        import fnmatch

        async with self._lock:
            keys_to_delete = [
                k for k in self._cache.keys()
                if fnmatch.fnmatch(k, pattern)
            ]
            for key in keys_to_delete:
                del self._cache[key]
            return len(keys_to_delete)

    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()

    async def exists(self, key: str) -> bool:
        """Check if key exists and is not expired.

        Does NOT update LRU ordering (unlike get()), so health checks
        and existence probes don't artificially keep keys hot.
        """
        async with self._lock:
            if key not in self._cache:
                return False
            _, expires_at = self._cache[key]
            if expires_at and time.time() > expires_at:
                del self._cache[key]
                return False
            return True

    @property
    def stats(self) -> dict:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "type": "memory",
            "size": len(self._cache),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%",
        }


class RedisCache:
    """
    Redis-based cache with connection pooling.

    Uses redis-py async client for non-blocking operations.
    """

    def __init__(
        self,
        url: str,
        key_prefix: str = "openlabels:",
        max_connections: int = 10,
        connect_timeout: float = 5.0,
        socket_timeout: float = 5.0,
    ):
        self._url = url
        self._key_prefix = key_prefix
        self._max_connections = max_connections
        self._connect_timeout = connect_timeout
        self._socket_timeout = socket_timeout
        self._client: Any | None = None
        self._connected = False
        self._hits = 0
        self._misses = 0

    def _make_key(self, key: str) -> str:
        """Add prefix to key."""
        return f"{self._key_prefix}{key}"

    async def connect(self) -> bool:
        """Initialize Redis connection pool."""
        try:
            import redis.asyncio as redis

            self._client = redis.from_url(
                self._url,
                max_connections=self._max_connections,
                socket_connect_timeout=self._connect_timeout,
                socket_timeout=self._socket_timeout,
                decode_responses=True,
            )

            # Test connection
            await self._client.ping()
            self._connected = True
            logger.info(f"Redis cache connected: {self._url}")
            return True

        except ImportError:
            logger.warning("redis package not installed - falling back to memory cache")
            return False
        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            # Connection failures are expected if Redis is not available
            logger.warning(f"Redis connection failed: {type(e).__name__}: {e} - falling back to memory cache")
            return False

    async def close(self) -> None:
        """Close Redis connection."""
        if self._client:
            await self._client.close()
            self._connected = False
            logger.info("Redis cache connection closed")

    async def get(self, key: str) -> Any | None:
        """Get value from Redis."""
        if not self._connected or not self._client:
            return None

        try:
            full_key = self._make_key(key)
            value = await self._client.get(full_key)

            if value is None:
                self._misses += 1
                return None

            self._hits += 1
            # Try to deserialize JSON, fall back to raw value
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value

        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            # Redis errors should be logged for monitoring
            logger.warning(f"Redis get error for {key}: {type(e).__name__}: {e}")
            self._misses += 1
            return None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        """Set value in Redis with optional TTL."""
        if not self._connected or not self._client:
            return False

        try:
            full_key = self._make_key(key)

            # Serialize value to JSON
            if not isinstance(value, str):
                value = json.dumps(value, default=str)

            if ttl:
                await self._client.setex(full_key, ttl, value)
            else:
                await self._client.set(full_key, value)

            return True

        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            # Redis errors should be logged for monitoring
            logger.warning(f"Redis set error for {key}: {type(e).__name__}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from Redis."""
        if not self._connected or not self._client:
            return False

        try:
            full_key = self._make_key(key)
            result = await self._client.delete(full_key)
            return result > 0

        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            # Redis errors should be logged for monitoring
            logger.warning(f"Redis delete error for {key}: {type(e).__name__}: {e}")
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """Delete keys matching a pattern."""
        if not self._connected or not self._client:
            return 0

        try:
            full_pattern = self._make_key(pattern)
            deleted = 0

            # Use SCAN to avoid blocking on large keyspaces
            cursor = 0
            while True:
                cursor, keys = await self._client.scan(
                    cursor=cursor,
                    match=full_pattern,
                    count=100,
                )

                if keys:
                    deleted += await self._client.delete(*keys)

                if cursor == 0:
                    break

            return deleted

        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            # Redis errors should be logged for monitoring
            logger.warning(f"Redis delete_pattern error for {pattern}: {type(e).__name__}: {e}")
            return 0

    async def clear(self) -> None:
        """Clear all cache entries with our prefix."""
        await self.delete_pattern("*")

    async def exists(self, key: str) -> bool:
        """Check if key exists in Redis."""
        if not self._connected or not self._client:
            return False

        try:
            full_key = self._make_key(key)
            return await self._client.exists(full_key) > 0
        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            # Redis errors should be logged for monitoring
            logger.warning(f"Redis exists error for {key}: {type(e).__name__}: {e}")
            return False

    @property
    def is_connected(self) -> bool:
        """Check if Redis is connected."""
        return self._connected

    @property
    def stats(self) -> dict:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "type": "redis",
            "connected": self._connected,
            "url": self._url,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%",
        }


class CacheManager:
    """
    Unified cache manager with Redis primary and in-memory fallback.

    Automatically falls back to in-memory cache if Redis is unavailable.
    Provides consistent interface regardless of backend.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        key_prefix: str = "openlabels:",
        default_ttl: int = 300,
        max_connections: int = 10,
        connect_timeout: float = 5.0,
        socket_timeout: float = 5.0,
        memory_cache_max_size: int = 1000,
        enabled: bool = True,
    ):
        self._enabled = enabled
        self._default_ttl = default_ttl
        self._redis_url = redis_url
        self._key_prefix = key_prefix

        # Initialize backends
        self._redis: RedisCache | None = None
        self._memory = InMemoryCache(max_size=memory_cache_max_size)
        self._key_locks: dict[str, asyncio.Lock] = {}

        if redis_url and enabled:
            self._redis = RedisCache(
                url=redis_url,
                key_prefix=key_prefix,
                max_connections=max_connections,
                connect_timeout=connect_timeout,
                socket_timeout=socket_timeout,
            )

    async def initialize(self) -> None:
        """Initialize cache connections."""
        if not self._enabled:
            logger.info("Cache is disabled")
            return

        if self._redis:
            connected = await self._redis.connect()
            if not connected:
                logger.info("Using in-memory cache fallback")

    async def close(self) -> None:
        """Close cache connections."""
        if self._redis:
            await self._redis.close()

    @property
    def _backend(self) -> InMemoryCache | RedisCache:
        """Get the active cache backend."""
        if self._redis and self._redis.is_connected:
            return self._redis
        return self._memory

    async def get(self, key: str) -> Any | None:
        """Get value from cache."""
        if not self._enabled:
            return None
        return await self._backend.get(key)

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
    ) -> bool:
        """Set value in cache."""
        if not self._enabled:
            return False
        return await self._backend.set(key, value, ttl or self._default_ttl)

    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        if not self._enabled:
            return False
        return await self._backend.delete(key)

    async def delete_pattern(self, pattern: str) -> int:
        """Delete keys matching a pattern."""
        if not self._enabled:
            return 0
        return await self._backend.delete_pattern(pattern)

    async def clear(self) -> None:
        """Clear all cache entries."""
        if self._enabled:
            await self._backend.clear()

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        if not self._enabled:
            return False
        return await self._backend.exists(key)

    async def get_or_set(
        self,
        key: str,
        factory: Callable[[], Any],
        ttl: int | None = None,
    ) -> Any:
        """Get value from cache or compute and store it.

        Uses a per-key lock to prevent cache stampede: when many
        concurrent coroutines miss the same key simultaneously, only one
        executes the factory while the others wait and then read the
        cached result.
        """
        if not self._enabled:
            return await factory() if asyncio.iscoroutinefunction(factory) else factory()

        value = await self.get(key)
        if value is not None:
            return value

        # Acquire per-key lock to prevent stampede
        lock = self._key_locks.setdefault(key, asyncio.Lock())
        async with lock:
            # Double-check after acquiring lock
            value = await self.get(key)
            if value is not None:
                return value

            # Compute value
            value = await factory() if asyncio.iscoroutinefunction(factory) else factory()
            await self.set(key, value, ttl)

        # Cleanup: only remove if the lock in the dict is still the same
        # object we used (prevents removing a lock a new waiter created).
        if self._key_locks.get(key) is lock:
            self._key_locks.pop(key, None)
        return value

    @property
    def is_redis_connected(self) -> bool:
        """Check if Redis is connected."""
        return self._redis is not None and self._redis.is_connected

    @property
    def stats(self) -> dict:
        """Get cache statistics."""
        backend_stats = self._backend.stats
        return {
            "enabled": self._enabled,
            "backend": backend_stats,
            "default_ttl": self._default_ttl,
            "key_prefix": self._key_prefix,
        }


async def get_cache_manager() -> CacheManager:
    """
    Get or create the global cache manager instance.

    Uses lazy initialization and caches the instance.
    """
    global _cache_manager

    async with _cache_lock:
        if _cache_manager is None:
            from openlabels.server.config import get_settings

            settings = get_settings()
            redis_config = settings.redis

            _cache_manager = CacheManager(
                redis_url=redis_config.url if redis_config.enabled else None,
                key_prefix=redis_config.key_prefix,
                default_ttl=redis_config.cache_ttl_seconds,
                max_connections=redis_config.max_connections,
                connect_timeout=redis_config.connect_timeout,
                socket_timeout=redis_config.socket_timeout,
                memory_cache_max_size=redis_config.memory_cache_max_size,
                enabled=redis_config.enabled,
            )
            await _cache_manager.initialize()

    return _cache_manager


async def close_cache() -> None:
    """Close the global cache manager."""
    global _cache_manager

    async with _cache_lock:
        if _cache_manager:
            await _cache_manager.close()
            _cache_manager = None


def _make_cache_key(
    key_prefix: str,
    func_name: str,
    args: tuple,
    kwargs: dict,
    key_builder: Callable[..., str] | None = None,
) -> str:
    """
    Generate a cache key from function arguments.

    Args:
        key_prefix: Prefix for the cache key
        func_name: Name of the cached function
        args: Positional arguments
        kwargs: Keyword arguments
        key_builder: Optional custom key builder function

    Returns:
        A unique cache key string
    """
    if key_builder:
        return f"{key_prefix}:{key_builder(*args, **kwargs)}"

    # Build key from function name and arguments
    key_parts = [key_prefix, func_name]

    # Add positional args (skip 'self' or 'cls' if present)
    for arg in args:
        if hasattr(arg, "__dict__"):
            # For objects, use a hash of their representation
            key_parts.append(hashlib.md5(str(arg).encode()).hexdigest()[:8])
        else:
            key_parts.append(str(arg))

    # Add sorted keyword args
    for k, v in sorted(kwargs.items()):
        if hasattr(v, "__dict__"):
            key_parts.append(f"{k}={hashlib.md5(str(v).encode()).hexdigest()[:8]}")
        else:
            key_parts.append(f"{k}={v}")

    return ":".join(key_parts)


def cache(
    ttl: int | None = None,
    key_prefix: str = "",
    key_builder: Callable[..., str] | None = None,
    skip_cache_if: Callable[..., bool] | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator for caching async function results.

    Args:
        ttl: Time-to-live in seconds (uses default if None)
        key_prefix: Prefix for cache keys (defaults to function module)
        key_builder: Custom function to build cache key from arguments
        skip_cache_if: Function that returns True if caching should be skipped

    Example:
        @cache(ttl=300, key_prefix="labels")
        async def get_labels(tenant_id: str) -> list[dict]:
            ...

        @cache(key_builder=lambda tenant_id, **kw: f"tenant:{tenant_id}")
        async def get_tenant_data(tenant_id: str) -> dict:
            ...
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        # Use function module and name as default prefix
        prefix = key_prefix or f"{func.__module__}.{func.__name__}"

        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Check if caching should be skipped
            if skip_cache_if and skip_cache_if(*args, **kwargs):
                return await func(*args, **kwargs)

            # Get cache manager
            try:
                cache_manager = await get_cache_manager()
            except (RedisError, ConnectionError, OSError, RuntimeError) as e:
                # Cache unavailability is non-critical - proceed without cache
                logger.debug(f"Cache unavailable: {type(e).__name__}: {e}")
                return await func(*args, **kwargs)

            # Generate cache key
            cache_key = _make_cache_key(
                prefix,
                func.__name__,
                args,
                kwargs,
                key_builder,
            )

            # Try to get from cache
            cached_value = await cache_manager.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit: {cache_key}")
                return cached_value

            # Execute function and cache result
            logger.debug(f"Cache miss: {cache_key}")
            result = await func(*args, **kwargs)

            # Only cache non-None results
            if result is not None:
                await cache_manager.set(cache_key, result, ttl)

            return result

        # Attach cache invalidation helper to the wrapper
        wrapper.invalidate = lambda *a, **kw: _invalidate_func_cache(
            prefix, func.__name__, a, kw, key_builder
        )

        return wrapper

    return decorator


async def _invalidate_func_cache(
    prefix: str,
    func_name: str,
    args: tuple,
    kwargs: dict,
    key_builder: Callable[..., str] | None,
) -> bool:
    """Invalidate cache for a specific function call."""
    try:
        cache_manager = await get_cache_manager()
        cache_key = _make_cache_key(prefix, func_name, args, kwargs, key_builder)
        return await cache_manager.delete(cache_key)
    except (RedisError, ConnectionError, OSError, RuntimeError) as e:
        # Cache invalidation failures should be logged for debugging
        logger.warning(f"Cache invalidation failed: {type(e).__name__}: {e}")
        return False


async def invalidate_cache(pattern: str) -> int:
    """
    Invalidate cache entries matching a pattern.

    Args:
        pattern: Glob-style pattern (e.g., "labels:*", "tenant:123:*")

    Returns:
        Number of deleted entries
    """
    try:
        cache_manager = await get_cache_manager()
        return await cache_manager.delete_pattern(pattern)
    except (RedisError, ConnectionError, OSError, RuntimeError) as e:
        # Cache invalidation failures should be logged for debugging
        logger.warning(f"Cache invalidation failed for pattern {pattern}: {type(e).__name__}: {e}")
        return 0


async def get_cache_stats() -> dict:
    """Get cache statistics."""
    try:
        cache_manager = await get_cache_manager()
        return cache_manager.stats
    except (RedisError, ConnectionError, OSError, RuntimeError) as e:
        # Stats retrieval failures are non-critical
        logger.warning(f"Failed to get cache stats: {type(e).__name__}: {e}")
        return {"error": str(e)}

"""Tests for cache infrastructure (InMemoryCache, CacheManager)."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.server.cache import CacheManager, InMemoryCache


# ---------------------------------------------------------------------------
# InMemoryCache
# ---------------------------------------------------------------------------


class TestInMemoryCacheBasic:
    @pytest.mark.asyncio
    async def test_set_and_get(self):
        cache = InMemoryCache()
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"

    @pytest.mark.asyncio
    async def test_get_missing_returns_none(self):
        cache = InMemoryCache()
        assert await cache.get("missing") is None

    @pytest.mark.asyncio
    async def test_set_complex_value(self):
        cache = InMemoryCache()
        data = {"items": [1, 2, 3], "nested": {"a": True}}
        await cache.set("complex", data)
        assert await cache.get("complex") == data

    @pytest.mark.asyncio
    async def test_delete(self):
        cache = InMemoryCache()
        await cache.set("key", "val")
        result = await cache.delete("key")
        assert result is True
        assert await cache.get("key") is None

    @pytest.mark.asyncio
    async def test_delete_missing(self):
        cache = InMemoryCache()
        result = await cache.delete("missing")
        assert result is False

    @pytest.mark.asyncio
    async def test_exists(self):
        cache = InMemoryCache()
        await cache.set("key", "val")
        assert await cache.exists("key") is True
        assert await cache.exists("missing") is False

    @pytest.mark.asyncio
    async def test_clear(self):
        cache = InMemoryCache()
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.clear()
        assert await cache.get("a") is None
        assert await cache.get("b") is None


class TestInMemoryCacheTTL:
    @pytest.mark.asyncio
    async def test_ttl_expiration(self):
        cache = InMemoryCache()
        await cache.set("key", "val", ttl=1)

        # Not expired yet
        assert await cache.get("key") == "val"

        # Fast-forward time
        with patch("time.time", return_value=time.time() + 2):
            assert await cache.get("key") is None

    @pytest.mark.asyncio
    async def test_no_ttl_never_expires(self):
        cache = InMemoryCache()
        await cache.set("key", "val")  # No TTL

        with patch("time.time", return_value=time.time() + 999999):
            assert await cache.get("key") == "val"


class TestInMemoryCacheLRU:
    @pytest.mark.asyncio
    async def test_eviction_at_max_size(self):
        cache = InMemoryCache(max_size=3)
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.set("c", 3)
        await cache.set("d", 4)  # Should evict 'a'

        assert await cache.get("a") is None
        assert await cache.get("b") == 2
        assert await cache.get("d") == 4

    @pytest.mark.asyncio
    async def test_lru_access_prevents_eviction(self):
        cache = InMemoryCache(max_size=3)
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.set("c", 3)
        await cache.get("a")  # Touch 'a' to make it most recent
        await cache.set("d", 4)  # Should evict 'b' (least recently used)

        assert await cache.get("a") == 1  # Still there
        assert await cache.get("b") is None  # Evicted


class TestInMemoryCacheStats:
    @pytest.mark.asyncio
    async def test_hit_miss_stats(self):
        cache = InMemoryCache()
        await cache.set("key", "val")

        await cache.get("key")  # Hit
        await cache.get("missing")  # Miss

        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["type"] == "memory"


class TestInMemoryCachePatternDelete:
    @pytest.mark.asyncio
    async def test_delete_pattern(self):
        cache = InMemoryCache()
        await cache.set("prefix:a", 1)
        await cache.set("prefix:b", 2)
        await cache.set("other:c", 3)

        deleted = await cache.delete_pattern("prefix:*")
        assert deleted == 2
        assert await cache.get("other:c") == 3


# ---------------------------------------------------------------------------
# CacheManager
# ---------------------------------------------------------------------------


class TestCacheManagerMemoryBackend:
    @pytest.mark.asyncio
    async def test_get_set_without_redis(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        await mgr.set("key", "val", ttl=60)
        assert await mgr.get("key") == "val"

    @pytest.mark.asyncio
    async def test_disabled_cache(self):
        mgr = CacheManager(enabled=False)
        await mgr.initialize()

        await mgr.set("key", "val")
        assert await mgr.get("key") is None

    @pytest.mark.asyncio
    async def test_delete(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        await mgr.set("key", "val")
        result = await mgr.delete("key")
        assert result is True
        assert await mgr.get("key") is None

    @pytest.mark.asyncio
    async def test_delete_pattern(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        await mgr.set("ns:a", 1)
        await mgr.set("ns:b", 2)
        deleted = await mgr.delete_pattern("ns:*")
        assert deleted == 2

    @pytest.mark.asyncio
    async def test_exists(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        await mgr.set("key", "val")
        assert await mgr.exists("key") is True
        assert await mgr.exists("missing") is False

    @pytest.mark.asyncio
    async def test_stats(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        stats = mgr.stats
        assert stats["enabled"] is True
        assert "backend" in stats


class TestCacheManagerGetOrSet:
    @pytest.mark.asyncio
    async def test_get_or_set_miss(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        result = await mgr.get_or_set("key", lambda: 42)
        assert result == 42
        # Should be cached now
        assert await mgr.get("key") == 42

    @pytest.mark.asyncio
    async def test_get_or_set_hit(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        await mgr.set("key", "cached")
        result = await mgr.get_or_set("key", lambda: "new")
        assert result == "cached"

    @pytest.mark.asyncio
    async def test_get_or_set_async_factory(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        await mgr.initialize()

        async def factory():
            return {"computed": True}

        result = await mgr.get_or_set("key", factory)
        assert result == {"computed": True}

    @pytest.mark.asyncio
    async def test_get_or_set_disabled(self):
        mgr = CacheManager(enabled=False)

        call_count = 0
        def factory():
            nonlocal call_count
            call_count += 1
            return "value"

        await mgr.get_or_set("key", factory)
        await mgr.get_or_set("key", factory)
        assert call_count == 2  # Never cached


class TestCacheManagerRedisProperties:
    def test_is_redis_connected_no_redis(self):
        mgr = CacheManager(redis_url=None, enabled=True)
        assert mgr.is_redis_connected is False

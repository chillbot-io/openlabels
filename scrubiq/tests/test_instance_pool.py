"""Tests for the instance pool (instance_pool.py).

Tests cover:
- InstancePool class initialization
- get_or_create() - instance creation and retrieval
- LRU eviction when pool is full
- Idle timeout eviction
- Thread safety
- Statistics tracking
- Instance isolation (multi-tenant)
- Global pool functions (init_pool, get_pool, close_pool)
"""

import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# --- Fixtures ---

@pytest.fixture
def mock_config():
    """Create a mock Config object."""
    config = MagicMock()
    config.data_dir = "/tmp/scrubiq_test"
    config.models_dir = "/tmp/scrubiq_test/models"
    config.db_path = "/tmp/scrubiq_test/db.sqlite"
    return config


@pytest.fixture
def mock_scrubiq_class():
    """Mock the ScrubIQ class to avoid actual initialization."""
    with patch("scrubiq.instance_pool.ScrubIQ") as mock_class:
        # Create a mock instance that will be returned
        mock_instance = MagicMock()
        mock_instance.unlock = MagicMock()
        mock_instance.close = MagicMock()
        mock_instance._session = MagicMock()

        mock_class.return_value = mock_instance
        mock_class.preload_models_async = MagicMock()

        yield mock_class


@pytest.fixture
def instance_pool(mock_config, mock_scrubiq_class):
    """Create an InstancePool with mocked dependencies."""
    from scrubiq.instance_pool import InstancePool

    pool = InstancePool(
        config=mock_config,
        max_instances=5,
        idle_timeout_seconds=60,
    )
    yield pool
    pool.close()


# --- InstancePool Initialization Tests ---

class TestInstancePoolInit:
    """Tests for InstancePool initialization."""

    def test_init_sets_config(self, mock_config, mock_scrubiq_class):
        """Should store the config."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config)

        assert pool._config is mock_config
        pool.close()

    def test_init_sets_max_instances(self, mock_config, mock_scrubiq_class):
        """Should set max instances."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=10)

        assert pool._max_instances == 10
        pool.close()

    def test_init_sets_idle_timeout(self, mock_config, mock_scrubiq_class):
        """Should set idle timeout."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, idle_timeout_seconds=300)

        assert pool._idle_timeout == 300
        pool.close()

    def test_init_uses_defaults(self, mock_config, mock_scrubiq_class):
        """Should use default values when not specified."""
        from scrubiq.instance_pool import (
            InstancePool,
            DEFAULT_MAX_INSTANCES,
            DEFAULT_IDLE_TIMEOUT_SECONDS,
        )

        pool = InstancePool(mock_config)

        assert pool._max_instances == DEFAULT_MAX_INSTANCES
        assert pool._idle_timeout == DEFAULT_IDLE_TIMEOUT_SECONDS
        pool.close()

    def test_init_creates_empty_instances_dict(self, mock_config, mock_scrubiq_class):
        """Should initialize with empty instances dict."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config)

        assert len(pool._instances) == 0
        pool.close()

    def test_init_creates_stats(self, mock_config, mock_scrubiq_class):
        """Should initialize statistics."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config)

        assert pool._stats["hits"] == 0
        assert pool._stats["misses"] == 0
        assert pool._stats["evictions"] == 0
        assert pool._stats["creates"] == 0
        pool.close()


# --- get_or_create Tests ---

class TestGetOrCreate:
    """Tests for get_or_create method."""

    def test_creates_new_instance(self, instance_pool, mock_scrubiq_class):
        """Should create new instance when not in pool."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance = instance_pool.get_or_create("sk-test", encryption_key)

        assert instance is not None
        assert mock_scrubiq_class.called

    def test_returns_existing_instance(self, instance_pool, mock_scrubiq_class):
        """Should return existing instance from pool."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        # Create first instance
        instance1 = instance_pool.get_or_create("sk-test", encryption_key)

        # Reset mock to track new calls
        mock_scrubiq_class.reset_mock()

        # Get same instance again
        instance2 = instance_pool.get_or_create("sk-test", encryption_key)

        # Should return same instance, no new creation
        assert instance1 is instance2
        assert not mock_scrubiq_class.called

    def test_tracks_cache_hits(self, instance_pool):
        """Should track cache hits."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)
        instance_pool.get_or_create("sk-test", encryption_key)

        assert instance_pool._stats["hits"] == 1
        assert instance_pool._stats["misses"] == 1

    def test_tracks_cache_misses(self, instance_pool):
        """Should track cache misses."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test1", encryption_key)
        instance_pool.get_or_create("sk-test2", encryption_key)

        assert instance_pool._stats["misses"] == 2
        assert instance_pool._stats["creates"] == 2

    def test_updates_last_accessed_time(self, instance_pool):
        """Should update last_accessed_at on access."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)
        first_access = instance_pool._instances["sk-test"].last_accessed_at

        time.sleep(0.01)  # Small delay

        instance_pool.get_or_create("sk-test", encryption_key)
        second_access = instance_pool._instances["sk-test"].last_accessed_at

        assert second_access > first_access

    def test_increments_access_count(self, instance_pool):
        """Should increment access count on each access."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)
        assert instance_pool._instances["sk-test"].access_count == 1

        instance_pool.get_or_create("sk-test", encryption_key)
        assert instance_pool._instances["sk-test"].access_count == 2

    def test_moves_to_end_on_access_lru(self, instance_pool):
        """Should move accessed instance to end (LRU order)."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        # Create multiple instances
        instance_pool.get_or_create("sk-first", encryption_key)
        instance_pool.get_or_create("sk-second", encryption_key)
        instance_pool.get_or_create("sk-third", encryption_key)

        # Access the first one again
        instance_pool.get_or_create("sk-first", encryption_key)

        # First should now be last (most recently used)
        keys = list(instance_pool._instances.keys())
        assert keys[-1] == "sk-first"


# --- LRU Eviction Tests ---

class TestLRUEviction:
    """Tests for LRU eviction when pool is full."""

    def test_evicts_lru_when_full(self, mock_config, mock_scrubiq_class):
        """Should evict least recently used instance when at capacity."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=3, idle_timeout_seconds=3600)
        encryption_key = b"test_key_32_bytes_long_12345678"

        try:
            # Fill the pool
            pool.get_or_create("sk-first", encryption_key)
            pool.get_or_create("sk-second", encryption_key)
            pool.get_or_create("sk-third", encryption_key)

            assert len(pool._instances) == 3

            # Add one more - should evict oldest
            pool.get_or_create("sk-fourth", encryption_key)

            # First should be evicted
            assert "sk-first" not in pool._instances
            assert "sk-fourth" in pool._instances
            assert len(pool._instances) == 3
        finally:
            pool.close()

    def test_eviction_calls_close(self, mock_config, mock_scrubiq_class):
        """Evicted instances should have close() called."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=2, idle_timeout_seconds=3600)
        encryption_key = b"test_key_32_bytes_long_12345678"

        try:
            # Fill pool
            instance1 = pool.get_or_create("sk-first", encryption_key)
            pool.get_or_create("sk-second", encryption_key)

            # Trigger eviction
            pool.get_or_create("sk-third", encryption_key)

            # First instance should have close() called
            instance1.close.assert_called()
        finally:
            pool.close()

    def test_eviction_increments_stats(self, mock_config, mock_scrubiq_class):
        """Evictions should increment stats."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=2, idle_timeout_seconds=3600)
        encryption_key = b"test_key_32_bytes_long_12345678"

        try:
            pool.get_or_create("sk-first", encryption_key)
            pool.get_or_create("sk-second", encryption_key)
            pool.get_or_create("sk-third", encryption_key)

            assert pool._stats["evictions"] >= 1
        finally:
            pool.close()


# --- Idle Timeout Eviction Tests ---

class TestIdleTimeoutEviction:
    """Tests for idle timeout eviction."""

    def test_evicts_idle_instances(self, mock_config, mock_scrubiq_class):
        """Should evict instances that exceed idle timeout."""
        from scrubiq.instance_pool import InstancePool

        # Very short timeout for testing
        pool = InstancePool(mock_config, max_instances=10, idle_timeout_seconds=0.01)
        encryption_key = b"test_key_32_bytes_long_12345678"

        try:
            pool.get_or_create("sk-test", encryption_key)
            time.sleep(0.02)  # Wait for timeout

            # Trigger eviction check by getting another instance
            pool.get_or_create("sk-new", encryption_key)

            # Old instance should be evicted
            assert "sk-test" not in pool._instances
        finally:
            pool.close()

    def test_cleanup_idle_removes_idle_instances(self, mock_config, mock_scrubiq_class):
        """cleanup_idle() should remove all idle instances."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=10, idle_timeout_seconds=0.01)
        encryption_key = b"test_key_32_bytes_long_12345678"

        try:
            pool.get_or_create("sk-test1", encryption_key)
            pool.get_or_create("sk-test2", encryption_key)
            time.sleep(0.02)

            count = pool.cleanup_idle()

            assert count == 2
            assert len(pool._instances) == 0
        finally:
            pool.close()

    def test_cleanup_idle_returns_count(self, mock_config, mock_scrubiq_class):
        """cleanup_idle() should return number of evicted instances."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=10, idle_timeout_seconds=0.01)
        encryption_key = b"test_key_32_bytes_long_12345678"

        try:
            pool.get_or_create("sk-test1", encryption_key)
            pool.get_or_create("sk-test2", encryption_key)
            pool.get_or_create("sk-test3", encryption_key)
            time.sleep(0.02)

            count = pool.cleanup_idle()

            assert count == 3
        finally:
            pool.close()


# --- Thread Safety Tests ---

class TestThreadSafety:
    """Tests for thread safety of the instance pool."""

    def test_concurrent_get_or_create(self, mock_config, mock_scrubiq_class):
        """Concurrent get_or_create should be thread-safe."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=100, idle_timeout_seconds=3600)
        encryption_key = b"test_key_32_bytes_long_12345678"
        errors = []

        def worker(key_suffix):
            try:
                for _ in range(10):
                    pool.get_or_create(f"sk-{key_suffix}", encryption_key)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(10)
        ]

        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0
        finally:
            pool.close()

    def test_concurrent_access_same_key(self, mock_config, mock_scrubiq_class):
        """Concurrent access to same key should be safe."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=100, idle_timeout_seconds=3600)
        encryption_key = b"test_key_32_bytes_long_12345678"
        instances = []

        def worker():
            instance = pool.get_or_create("sk-shared", encryption_key)
            instances.append(instance)

        threads = [
            threading.Thread(target=worker)
            for _ in range(20)
        ]

        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # All should get same instance
            assert len(set(id(i) for i in instances)) == 1
        finally:
            pool.close()


# --- remove() Tests ---

class TestRemove:
    """Tests for explicit instance removal."""

    def test_remove_existing_instance(self, instance_pool):
        """Should remove existing instance."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)
        result = instance_pool.remove("sk-test")

        assert result is True
        assert "sk-test" not in instance_pool._instances

    def test_remove_nonexistent_instance(self, instance_pool):
        """Should return False for nonexistent instance."""
        result = instance_pool.remove("sk-nonexistent")

        assert result is False

    def test_remove_calls_close(self, instance_pool, mock_scrubiq_class):
        """Removed instance should have close() called."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance = instance_pool.get_or_create("sk-test", encryption_key)
        instance_pool.remove("sk-test")

        instance.close.assert_called()


# --- Statistics Tests ---

class TestStatistics:
    """Tests for pool statistics."""

    def test_get_stats_returns_all_fields(self, instance_pool):
        """get_stats() should return all statistics."""
        stats = instance_pool.get_stats()

        assert "hits" in stats
        assert "misses" in stats
        assert "evictions" in stats
        assert "creates" in stats
        assert "current_size" in stats
        assert "max_size" in stats
        assert "hit_rate" in stats

    def test_hit_rate_calculation(self, instance_pool):
        """Hit rate should be calculated correctly."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        # 1 miss, 3 hits
        instance_pool.get_or_create("sk-test", encryption_key)  # Miss
        instance_pool.get_or_create("sk-test", encryption_key)  # Hit
        instance_pool.get_or_create("sk-test", encryption_key)  # Hit
        instance_pool.get_or_create("sk-test", encryption_key)  # Hit

        stats = instance_pool.get_stats()

        # 3 hits / (3 hits + 1 miss) = 0.75
        assert stats["hit_rate"] == 0.75

    def test_hit_rate_zero_when_no_access(self, instance_pool):
        """Hit rate should be 0 when no accesses."""
        stats = instance_pool.get_stats()

        assert stats["hit_rate"] == 0.0


# --- list_instances Tests ---

class TestListInstances:
    """Tests for listing active instances."""

    def test_list_instances_returns_info(self, instance_pool):
        """list_instances() should return instance info."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)
        instances = instance_pool.list_instances()

        assert len(instances) == 1
        assert instances[0]["api_key_prefix"] == "sk-test"
        assert "created_at" in instances[0]
        assert "last_accessed_at" in instances[0]
        assert "access_count" in instances[0]
        assert "idle_seconds" in instances[0]

    def test_list_instances_calculates_idle_time(self, instance_pool):
        """Idle time should be calculated correctly."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)
        time.sleep(0.1)

        instances = instance_pool.list_instances()

        assert instances[0]["idle_seconds"] >= 0.1


# --- close() Tests ---

class TestClose:
    """Tests for pool shutdown."""

    def test_close_evicts_all_instances(self, mock_config, mock_scrubiq_class):
        """close() should evict all instances."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=10, idle_timeout_seconds=3600)
        encryption_key = b"test_key_32_bytes_long_12345678"

        pool.get_or_create("sk-test1", encryption_key)
        pool.get_or_create("sk-test2", encryption_key)
        pool.get_or_create("sk-test3", encryption_key)

        pool.close()

        assert len(pool._instances) == 0

    def test_close_calls_close_on_all(self, mock_config, mock_scrubiq_class):
        """close() should call close() on all instances."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config, max_instances=10, idle_timeout_seconds=3600)
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance1 = pool.get_or_create("sk-test1", encryption_key)
        instance2 = pool.get_or_create("sk-test2", encryption_key)

        pool.close()

        instance1.close.assert_called()
        instance2.close.assert_called()


# --- Preload Models Tests ---

class TestPreloadModels:
    """Tests for model preloading."""

    def test_preload_models_calls_scrubiq_preload(self, mock_config, mock_scrubiq_class):
        """preload_models() should call ScrubIQ.preload_models_async()."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config)
        pool.preload_models()

        mock_scrubiq_class.preload_models_async.assert_called_once_with(mock_config)
        pool.close()

    def test_preload_models_only_once(self, mock_config, mock_scrubiq_class):
        """preload_models() should only run once."""
        from scrubiq.instance_pool import InstancePool

        pool = InstancePool(mock_config)

        pool.preload_models()
        pool.preload_models()
        pool.preload_models()

        # Should only be called once
        assert mock_scrubiq_class.preload_models_async.call_count == 1
        pool.close()


# --- Global Pool Functions Tests ---

class TestGlobalPoolFunctions:
    """Tests for global pool functions."""

    def test_init_pool_creates_pool(self, mock_config, mock_scrubiq_class):
        """init_pool() should create global pool."""
        from scrubiq import instance_pool

        # Reset global state
        instance_pool._pool = None

        try:
            pool = instance_pool.init_pool(mock_config)

            assert pool is not None
            assert instance_pool._pool is pool
        finally:
            instance_pool.close_pool()

    def test_init_pool_returns_existing(self, mock_config, mock_scrubiq_class):
        """init_pool() should return existing pool if already initialized."""
        from scrubiq import instance_pool

        # Reset global state
        instance_pool._pool = None

        try:
            pool1 = instance_pool.init_pool(mock_config)
            pool2 = instance_pool.init_pool(mock_config)

            assert pool1 is pool2
        finally:
            instance_pool.close_pool()

    def test_get_pool_returns_pool(self, mock_config, mock_scrubiq_class):
        """get_pool() should return the global pool."""
        from scrubiq import instance_pool

        # Reset global state
        instance_pool._pool = None

        try:
            instance_pool.init_pool(mock_config)
            pool = instance_pool.get_pool()

            assert pool is not None
        finally:
            instance_pool.close_pool()

    def test_get_pool_raises_if_not_initialized(self, mock_scrubiq_class):
        """get_pool() should raise if pool not initialized."""
        from scrubiq import instance_pool

        # Reset global state
        instance_pool._pool = None

        with pytest.raises(RuntimeError, match="not initialized"):
            instance_pool.get_pool()

    def test_close_pool_closes_and_clears(self, mock_config, mock_scrubiq_class):
        """close_pool() should close and clear global pool."""
        from scrubiq import instance_pool

        # Reset global state
        instance_pool._pool = None

        instance_pool.init_pool(mock_config)
        instance_pool.close_pool()

        assert instance_pool._pool is None


# --- Instance Creation Tests ---

class TestInstanceCreation:
    """Tests for instance creation internals."""

    def test_creates_instance_with_config(self, instance_pool, mock_scrubiq_class):
        """Should create ScrubIQ instance with pool config."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)

        mock_scrubiq_class.assert_called_with(instance_pool._config)

    def test_sets_session_id_before_unlock(self, instance_pool, mock_scrubiq_class):
        """Should set session ID before unlock for proper isolation."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)

        # Get the mock instance
        instance = mock_scrubiq_class.return_value

        # Session ID should be set with API key prefix
        instance._session.set_session_id.assert_called_with("apikey:sk-test")

    def test_unlock_called_with_hex_key(self, instance_pool, mock_scrubiq_class):
        """Should call unlock with hex-encoded key."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        instance_pool.get_or_create("sk-test", encryption_key)

        instance = mock_scrubiq_class.return_value

        # Unlock should be called with hex of encryption key
        expected_hex = encryption_key.hex()
        instance.unlock.assert_called_with(expected_hex)

    def test_closes_on_unlock_failure(self, instance_pool, mock_scrubiq_class):
        """Should close instance if unlock fails."""
        encryption_key = b"test_key_32_bytes_long_12345678"

        mock_scrubiq_class.return_value.unlock.side_effect = ValueError("Invalid key")

        with pytest.raises(ValueError):
            instance_pool.get_or_create("sk-test", encryption_key)

        mock_scrubiq_class.return_value.close.assert_called()


# --- PooledInstance Tests ---

class TestPooledInstance:
    """Tests for PooledInstance dataclass."""

    def test_pooled_instance_stores_metadata(self, mock_scrubiq_class):
        """PooledInstance should store all metadata."""
        from scrubiq.instance_pool import PooledInstance

        mock_instance = MagicMock()
        now = time.time()

        pooled = PooledInstance(
            instance=mock_instance,
            api_key_prefix="sk-test",
            created_at=now,
            last_accessed_at=now,
            access_count=5,
        )

        assert pooled.instance is mock_instance
        assert pooled.api_key_prefix == "sk-test"
        assert pooled.created_at == now
        assert pooled.last_accessed_at == now
        assert pooled.access_count == 5

    def test_pooled_instance_default_access_count(self, mock_scrubiq_class):
        """access_count should default to 0."""
        from scrubiq.instance_pool import PooledInstance

        pooled = PooledInstance(
            instance=MagicMock(),
            api_key_prefix="sk-test",
            created_at=time.time(),
            last_accessed_at=time.time(),
        )

        assert pooled.access_count == 0

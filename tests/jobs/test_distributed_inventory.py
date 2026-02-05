"""
Comprehensive tests for the distributed scan inventory.

Tests focus on:
- Redis-based distributed caching operations
- In-memory fallback behavior
- Atomic file scanning operations
- Cache management and TTL handling
- Multi-worker consistency
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
import asyncio
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock

from openlabels.jobs.inventory import (
    DistributedScanInventory,
    InventoryService,
    DEFAULT_INVENTORY_TTL,
)


class TestDistributedScanInventoryInit:
    """Tests for DistributedScanInventory initialization."""

    def test_init_stores_tenant_id(self):
        """Should store the tenant ID."""
        tenant_id = uuid4()
        target_id = uuid4()

        inv = DistributedScanInventory(tenant_id, target_id)

        assert inv.tenant_id == tenant_id

    def test_init_stores_target_id(self):
        """Should store the target ID."""
        tenant_id = uuid4()
        target_id = uuid4()

        inv = DistributedScanInventory(tenant_id, target_id)

        assert inv.target_id == target_id

    def test_init_default_ttl(self):
        """Should use default TTL if not specified."""
        inv = DistributedScanInventory(uuid4(), uuid4())

        assert inv.ttl == DEFAULT_INVENTORY_TTL

    def test_init_custom_ttl(self):
        """Should accept custom TTL."""
        inv = DistributedScanInventory(uuid4(), uuid4(), ttl=7200)

        assert inv.ttl == 7200

    def test_init_creates_empty_local_caches(self):
        """Should initialize empty local caches."""
        inv = DistributedScanInventory(uuid4(), uuid4())

        assert inv._local_folder_cache == {}
        assert inv._local_file_cache == {}
        assert inv._local_scanned_files == set()

    def test_init_not_initialized(self):
        """Should not be initialized by default."""
        inv = DistributedScanInventory(uuid4(), uuid4())

        assert inv._initialized is False
        assert inv._use_redis is False

    def test_init_creates_correct_key_prefix(self):
        """Should create correct key prefix from tenant and target IDs."""
        tenant_id = uuid4()
        target_id = uuid4()

        inv = DistributedScanInventory(tenant_id, target_id)

        expected_prefix = f"inventory:{tenant_id}:{target_id}"
        assert inv._key_prefix == expected_prefix
        assert inv._folders_key == f"{expected_prefix}:folders"
        assert inv._files_key == f"{expected_prefix}:files"
        assert inv._scanned_key == f"{expected_prefix}:scanned"


class TestDistributedScanInventoryInitialize:
    """Tests for DistributedScanInventory.initialize()."""

    @pytest.fixture
    def inventory(self):
        """Create a DistributedScanInventory instance."""
        return DistributedScanInventory(uuid4(), uuid4())

    async def test_initialize_uses_in_memory_when_redis_not_connected(self, inventory):
        """Should use in-memory cache when Redis is not connected."""
        mock_cache_manager = MagicMock()
        mock_cache_manager.is_redis_connected = False
        inventory._cache_manager = mock_cache_manager

        await inventory.initialize()

        assert inventory._initialized is True
        assert inventory._use_redis is False

    async def test_initialize_uses_redis_when_connected(self, inventory):
        """Should use Redis when connected."""
        mock_redis_client = AsyncMock()
        mock_redis_cache = MagicMock()
        mock_redis_cache._client = mock_redis_client

        mock_cache_manager = MagicMock()
        mock_cache_manager.is_redis_connected = True
        mock_cache_manager._redis = mock_redis_cache
        inventory._cache_manager = mock_cache_manager

        await inventory.initialize()

        assert inventory._initialized is True
        assert inventory._use_redis is True
        assert inventory._redis_client is mock_redis_client

    async def test_initialize_handles_exception(self, inventory):
        """Should fall back to in-memory on exception."""
        inventory._cache_manager = None

        with patch('openlabels.server.cache.get_cache_manager', side_effect=Exception("Connection failed")):
            await inventory.initialize()

        assert inventory._initialized is True
        assert inventory._use_redis is False

    async def test_initialize_only_runs_once(self, inventory):
        """Should only initialize once."""
        inventory._initialized = True
        inventory._use_redis = True

        # This should not change anything since already initialized
        await inventory.initialize()

        assert inventory._initialized is True


class TestDistributedScanInventoryFolderOperations:
    """Tests for folder cache operations."""

    @pytest.fixture
    def inventory(self):
        """Create an initialized DistributedScanInventory with in-memory cache."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False
        return inv

    async def test_set_folder_stores_in_local_cache(self, inventory):
        """Should store folder data in local cache."""
        folder_data = {"folder_path": "/test", "file_count": 5}

        result = await inventory.set_folder("/test", folder_data)

        assert result is True
        assert inventory._local_folder_cache["/test"] == folder_data

    async def test_get_folder_returns_from_local_cache(self, inventory):
        """Should return folder data from local cache."""
        folder_data = {"folder_path": "/test", "file_count": 5}
        inventory._local_folder_cache["/test"] = folder_data

        result = await inventory.get_folder("/test")

        assert result == folder_data

    async def test_get_folder_returns_none_for_missing(self, inventory):
        """Should return None for non-existent folder."""
        result = await inventory.get_folder("/nonexistent")

        assert result is None

    async def test_get_folder_increments_hits_on_hit(self, inventory):
        """Should increment hits counter on cache hit."""
        inventory._local_folder_cache["/test"] = {"data": "value"}
        initial_hits = inventory._hits

        await inventory.get_folder("/test")

        assert inventory._hits == initial_hits + 1

    async def test_get_folder_increments_misses_on_miss(self, inventory):
        """Should increment misses counter on cache miss."""
        initial_misses = inventory._misses

        await inventory.get_folder("/nonexistent")

        assert inventory._misses == initial_misses + 1

    async def test_get_all_folders_returns_all(self, inventory):
        """Should return all folder data."""
        inventory._local_folder_cache = {
            "/a": {"path": "/a"},
            "/b": {"path": "/b"},
        }

        result = await inventory.get_all_folders()

        assert len(result) == 2
        assert "/a" in result
        assert "/b" in result

    async def test_delete_folder_removes_from_cache(self, inventory):
        """Should remove folder from cache."""
        inventory._local_folder_cache["/test"] = {"data": "value"}

        result = await inventory.delete_folder("/test")

        assert result is True
        assert "/test" not in inventory._local_folder_cache

    async def test_delete_folder_returns_false_for_missing(self, inventory):
        """Should return False when deleting non-existent folder."""
        result = await inventory.delete_folder("/nonexistent")

        assert result is False


class TestDistributedScanInventoryFileOperations:
    """Tests for file cache operations."""

    @pytest.fixture
    def inventory(self):
        """Create an initialized DistributedScanInventory with in-memory cache."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False
        return inv

    async def test_set_file_stores_in_local_cache(self, inventory):
        """Should store file data in local cache."""
        file_data = {"file_path": "/test/file.txt", "content_hash": "abc123"}

        result = await inventory.set_file("/test/file.txt", file_data)

        assert result is True
        assert inventory._local_file_cache["/test/file.txt"] == file_data

    async def test_get_file_returns_from_local_cache(self, inventory):
        """Should return file data from local cache."""
        file_data = {"file_path": "/test/file.txt", "content_hash": "abc123"}
        inventory._local_file_cache["/test/file.txt"] = file_data

        result = await inventory.get_file("/test/file.txt")

        assert result == file_data

    async def test_get_file_returns_none_for_missing(self, inventory):
        """Should return None for non-existent file."""
        result = await inventory.get_file("/nonexistent.txt")

        assert result is None

    async def test_get_all_files_returns_all(self, inventory):
        """Should return all file data."""
        inventory._local_file_cache = {
            "/a.txt": {"path": "/a.txt"},
            "/b.txt": {"path": "/b.txt"},
        }

        result = await inventory.get_all_files()

        assert len(result) == 2
        assert "/a.txt" in result
        assert "/b.txt" in result

    async def test_delete_file_removes_from_cache(self, inventory):
        """Should remove file from cache."""
        inventory._local_file_cache["/test.txt"] = {"data": "value"}

        result = await inventory.delete_file("/test.txt")

        assert result is True
        assert "/test.txt" not in inventory._local_file_cache


class TestDistributedScanInventoryAtomicScanning:
    """Tests for atomic file scanning operations."""

    @pytest.fixture
    def inventory(self):
        """Create an initialized DistributedScanInventory with in-memory cache."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False
        return inv

    async def test_mark_file_scanned_returns_true_first_time(self, inventory):
        """Should return True when first marking a file."""
        result = await inventory.mark_file_scanned("/test/file.txt")

        assert result is True
        assert "/test/file.txt" in inventory._local_scanned_files

    async def test_mark_file_scanned_returns_false_second_time(self, inventory):
        """Should return False when file already marked."""
        await inventory.mark_file_scanned("/test/file.txt")

        result = await inventory.mark_file_scanned("/test/file.txt")

        assert result is False

    async def test_is_file_scanned_returns_true_for_scanned(self, inventory):
        """Should return True for scanned files."""
        inventory._local_scanned_files.add("/test/file.txt")

        result = await inventory.is_file_scanned("/test/file.txt")

        assert result is True

    async def test_is_file_scanned_returns_false_for_not_scanned(self, inventory):
        """Should return False for unscanned files."""
        result = await inventory.is_file_scanned("/test/file.txt")

        assert result is False

    async def test_get_scanned_files_returns_all(self, inventory):
        """Should return all scanned files."""
        inventory._local_scanned_files = {"/a.txt", "/b.txt", "/c.txt"}

        result = await inventory.get_scanned_files()

        assert result == {"/a.txt", "/b.txt", "/c.txt"}

    async def test_get_scanned_count_returns_count(self, inventory):
        """Should return correct count of scanned files."""
        inventory._local_scanned_files = {"/a.txt", "/b.txt", "/c.txt"}

        result = await inventory.get_scanned_count()

        assert result == 3


class TestDistributedScanInventoryRedisOperations:
    """Tests for Redis-based operations."""

    @pytest.fixture
    def inventory_with_redis(self):
        """Create an initialized DistributedScanInventory with mocked Redis."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = True
        inv._redis_client = AsyncMock()
        return inv

    async def test_set_folder_uses_redis_hset(self, inventory_with_redis):
        """Should use Redis HSET for folder storage."""
        inv = inventory_with_redis
        inv._redis_client.hset = AsyncMock(return_value=1)
        inv._redis_client.ttl = AsyncMock(return_value=-1)
        inv._redis_client.expire = AsyncMock(return_value=True)

        await inv.set_folder("/test", {"path": "/test"})

        inv._redis_client.hset.assert_called_once()
        inv._redis_client.expire.assert_called_once()

    async def test_get_folder_uses_redis_hget(self, inventory_with_redis):
        """Should use Redis HGET for folder retrieval."""
        inv = inventory_with_redis
        inv._redis_client.hget = AsyncMock(return_value='{"path": "/test"}')

        result = await inv.get_folder("/test")

        assert result == {"path": "/test"}
        inv._redis_client.hget.assert_called_once()

    async def test_mark_file_scanned_uses_redis_sadd(self, inventory_with_redis):
        """Should use Redis SADD for atomic file marking."""
        inv = inventory_with_redis
        inv._redis_client.sadd = AsyncMock(return_value=1)
        inv._redis_client.ttl = AsyncMock(return_value=-1)
        inv._redis_client.expire = AsyncMock(return_value=True)

        result = await inv.mark_file_scanned("/test/file.txt")

        assert result is True
        inv._redis_client.sadd.assert_called_once()

    async def test_mark_file_scanned_returns_false_when_already_exists(self, inventory_with_redis):
        """Should return False when Redis SADD returns 0."""
        inv = inventory_with_redis
        inv._redis_client.sadd = AsyncMock(return_value=0)

        result = await inv.mark_file_scanned("/test/file.txt")

        assert result is False

    async def test_get_scanned_count_uses_redis_scard(self, inventory_with_redis):
        """Should use Redis SCARD for scanned file count."""
        inv = inventory_with_redis
        inv._redis_client.scard = AsyncMock(return_value=42)

        result = await inv.get_scanned_count()

        assert result == 42

    async def test_redis_error_falls_back_to_local_cache(self, inventory_with_redis):
        """Should fall back to local cache on Redis error."""
        inv = inventory_with_redis
        inv._redis_client.hget = AsyncMock(side_effect=Exception("Redis error"))
        inv._local_folder_cache["/test"] = {"path": "/test"}

        result = await inv.get_folder("/test")

        assert result == {"path": "/test"}


class TestDistributedScanInventoryScanProgress:
    """Tests for scan progress tracking."""

    @pytest.fixture
    def inventory(self):
        """Create an initialized DistributedScanInventory with in-memory cache."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False
        return inv

    async def test_get_scan_progress_returns_counts(self, inventory):
        """Should return correct progress counts."""
        inventory._local_folder_cache = {"/a": {}, "/b": {}}
        inventory._local_file_cache = {"/a.txt": {}, "/b.txt": {}, "/c.txt": {}}
        inventory._local_scanned_files = {"/a.txt", "/b.txt"}

        result = await inventory.get_scan_progress()

        assert result["scanned_files"] == 2
        assert result["total_files"] == 3
        assert result["total_folders"] == 2
        assert result["progress_pct"] == pytest.approx(66.67, rel=0.01)

    async def test_get_scan_progress_handles_zero_files(self, inventory):
        """Should handle zero files gracefully."""
        result = await inventory.get_scan_progress()

        assert result["scanned_files"] == 0
        assert result["total_files"] == 0
        assert result["progress_pct"] == 0


class TestDistributedScanInventoryCacheManagement:
    """Tests for cache management operations."""

    @pytest.fixture
    def inventory(self):
        """Create an initialized DistributedScanInventory with in-memory cache."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False
        return inv

    async def test_clear_inventory_clears_all_local_caches(self, inventory):
        """Should clear all local caches."""
        inventory._local_folder_cache = {"/a": {}}
        inventory._local_file_cache = {"/a.txt": {}}
        inventory._local_scanned_files = {"/a.txt"}

        result = await inventory.clear_inventory()

        assert result is True
        assert inventory._local_folder_cache == {}
        assert inventory._local_file_cache == {}
        assert inventory._local_scanned_files == set()

    async def test_clear_inventory_deletes_redis_keys(self):
        """Should delete Redis keys when using Redis."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = True
        inv._redis_client = AsyncMock()
        inv._redis_client.delete = AsyncMock(return_value=4)

        await inv.clear_inventory()

        inv._redis_client.delete.assert_called_once()

    async def test_refresh_ttl_succeeds_for_local_cache(self, inventory):
        """Should return True for local cache (no TTL needed)."""
        result = await inventory.refresh_ttl()

        assert result is True

    async def test_refresh_ttl_calls_redis_expire(self):
        """Should call Redis EXPIRE for all keys."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = True
        inv._redis_client = AsyncMock()
        inv._redis_client.expire = AsyncMock(return_value=True)

        result = await inv.refresh_ttl()

        assert result is True
        assert inv._redis_client.expire.call_count == 4  # 4 keys

    def test_stats_property_returns_stats(self):
        """Should return correct stats dictionary."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._hits = 10
        inv._misses = 5

        stats = inv.stats

        assert stats["backend"] == "memory"
        assert stats["hits"] == 10
        assert stats["misses"] == 5
        assert stats["hit_rate"] == "66.7%"
        assert stats["ttl"] == DEFAULT_INVENTORY_TTL


class TestDistributedScanInventorySerialization:
    """Tests for JSON serialization/deserialization."""

    @pytest.fixture
    def inventory(self):
        """Create a DistributedScanInventory instance."""
        return DistributedScanInventory(uuid4(), uuid4())

    def test_serialize_handles_dict(self, inventory):
        """Should serialize dict to JSON string."""
        data = {"key": "value", "number": 42}

        result = inventory._serialize(data)

        assert result == '{"key": "value", "number": 42}'

    def test_serialize_handles_datetime(self, inventory):
        """Should serialize datetime using str()."""
        dt = datetime(2024, 1, 15, 12, 30, 0, tzinfo=timezone.utc)
        data = {"timestamp": dt}

        result = inventory._serialize(data)

        assert "2024-01-15" in result

    def test_serialize_handles_uuid(self, inventory):
        """Should serialize UUID using str()."""
        test_uuid = uuid4()
        data = {"id": test_uuid}

        result = inventory._serialize(data)

        assert str(test_uuid) in result

    def test_deserialize_returns_dict(self, inventory):
        """Should deserialize JSON string to dict."""
        data = '{"key": "value", "number": 42}'

        result = inventory._deserialize(data)

        assert result == {"key": "value", "number": 42}

    def test_deserialize_returns_none_for_invalid_json(self, inventory):
        """Should return None for invalid JSON."""
        result = inventory._deserialize("not valid json")

        assert result is None

    def test_deserialize_returns_none_for_none_input(self, inventory):
        """Should return None for None input."""
        result = inventory._deserialize(None)

        assert result is None


class TestInventoryServiceWithDistributedCache:
    """Tests for InventoryService with distributed cache integration."""

    @pytest.fixture
    def service_with_distributed_cache(self):
        """Create an InventoryService with distributed cache enabled."""
        mock_session = AsyncMock()
        return InventoryService(
            mock_session,
            uuid4(),
            uuid4(),
            use_distributed_cache=True,
        )

    @pytest.fixture
    def service_without_distributed_cache(self):
        """Create an InventoryService without distributed cache."""
        mock_session = AsyncMock()
        return InventoryService(
            mock_session,
            uuid4(),
            uuid4(),
            use_distributed_cache=False,
        )

    def test_creates_distributed_inventory_when_enabled(self, service_with_distributed_cache):
        """Should create distributed inventory when enabled."""
        assert service_with_distributed_cache._distributed_inventory is not None
        assert isinstance(
            service_with_distributed_cache._distributed_inventory,
            DistributedScanInventory
        )

    def test_no_distributed_inventory_when_disabled(self, service_without_distributed_cache):
        """Should not create distributed inventory when disabled."""
        assert service_without_distributed_cache._distributed_inventory is None

    async def test_mark_file_scanned_distributed_returns_true_when_disabled(
        self, service_without_distributed_cache
    ):
        """Should return True when distributed cache is disabled."""
        result = await service_without_distributed_cache.mark_file_scanned_distributed("/test.txt")

        assert result is True

    async def test_mark_file_scanned_distributed_uses_distributed_inventory(
        self, service_with_distributed_cache
    ):
        """Should delegate to distributed inventory when enabled."""
        service = service_with_distributed_cache
        service._distributed_inventory._initialized = True
        service._distributed_inventory._use_redis = False

        result = await service.mark_file_scanned_distributed("/test.txt")

        assert result is True
        assert "/test.txt" in service._distributed_inventory._local_scanned_files

    async def test_is_file_scanned_distributed_returns_false_when_disabled(
        self, service_without_distributed_cache
    ):
        """Should return False when distributed cache is disabled."""
        result = await service_without_distributed_cache.is_file_scanned_distributed("/test.txt")

        assert result is False

    async def test_get_distributed_scan_progress_returns_none_when_disabled(
        self, service_without_distributed_cache
    ):
        """Should return None when distributed cache is disabled."""
        result = await service_without_distributed_cache.get_distributed_scan_progress()

        assert result is None

    async def test_clear_distributed_cache_does_nothing_when_disabled(
        self, service_without_distributed_cache
    ):
        """Should not raise when distributed cache is disabled."""
        # Should not raise
        await service_without_distributed_cache.clear_distributed_cache()

    def test_distributed_inventory_property(self, service_with_distributed_cache):
        """Should expose distributed_inventory property."""
        assert service_with_distributed_cache.distributed_inventory is not None

    async def test_sync_folder_to_distributed_cache(self, service_with_distributed_cache):
        """Should sync folder data to distributed cache."""
        service = service_with_distributed_cache
        service._distributed_inventory._initialized = True
        service._distributed_inventory._use_redis = False

        mock_folder = MagicMock()
        mock_folder.folder_path = "/test"
        mock_folder.adapter = "filesystem"
        mock_folder.file_count = 10
        mock_folder.total_size_bytes = 1024
        mock_folder.folder_modified = datetime.now(timezone.utc)
        mock_folder.last_scanned_at = datetime.now(timezone.utc)
        mock_folder.last_scan_job_id = uuid4()
        mock_folder.has_sensitive_files = True
        mock_folder.highest_risk_tier = "HIGH"
        mock_folder.total_entities_found = 5

        await service.sync_folder_to_distributed_cache("/test", mock_folder)

        assert "/test" in service._distributed_inventory._local_folder_cache

    async def test_sync_file_to_distributed_cache(self, service_with_distributed_cache):
        """Should sync file data to distributed cache."""
        service = service_with_distributed_cache
        service._distributed_inventory._initialized = True
        service._distributed_inventory._use_redis = False

        mock_file = MagicMock()
        mock_file.file_path = "/test/file.txt"
        mock_file.file_name = "file.txt"
        mock_file.adapter = "filesystem"
        mock_file.content_hash = "abc123"
        mock_file.file_size = 1024
        mock_file.file_modified = datetime.now(timezone.utc)
        mock_file.risk_score = 75
        mock_file.risk_tier = "HIGH"
        mock_file.entity_counts = {"ssn": 5}
        mock_file.total_entities = 5
        mock_file.exposure_level = "INTERNAL"
        mock_file.owner = "user@example.com"
        mock_file.current_label_id = None
        mock_file.current_label_name = None
        mock_file.label_applied_at = None
        mock_file.last_scanned_at = datetime.now(timezone.utc)
        mock_file.last_scan_job_id = uuid4()
        mock_file.needs_rescan = False
        mock_file.scan_count = 1
        mock_file.content_changed_count = 0

        await service.sync_file_to_distributed_cache("/test/file.txt", mock_file)

        assert "/test/file.txt" in service._distributed_inventory._local_file_cache


class TestDistributedScanInventoryConcurrency:
    """Tests for concurrent access patterns."""

    async def test_concurrent_mark_file_scanned_local(self):
        """Test concurrent marking of same file returns correct results."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False

        # Simulate concurrent marking
        results = await asyncio.gather(
            inv.mark_file_scanned("/test/file.txt"),
            inv.mark_file_scanned("/test/file.txt"),
            inv.mark_file_scanned("/test/file.txt"),
        )

        # Only one should succeed
        assert sum(results) == 1
        assert "/test/file.txt" in inv._local_scanned_files

    async def test_concurrent_set_folder_operations(self):
        """Test concurrent folder set operations."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False

        async def set_folder(path):
            await inv.set_folder(path, {"path": path})
            return path

        paths = [f"/folder/{i}" for i in range(100)]
        results = await asyncio.gather(*[set_folder(p) for p in paths])

        assert len(results) == 100
        assert len(inv._local_folder_cache) == 100

    async def test_concurrent_get_and_set_operations(self):
        """Test concurrent get and set operations."""
        inv = DistributedScanInventory(uuid4(), uuid4())
        inv._initialized = True
        inv._use_redis = False

        # Pre-populate some data
        for i in range(50):
            inv._local_file_cache[f"/file{i}.txt"] = {"index": i}

        async def read_write_operation(index):
            # Read existing
            await inv.get_file(f"/file{index % 50}.txt")
            # Write new
            await inv.set_file(f"/new_file{index}.txt", {"index": index})
            return index

        results = await asyncio.gather(*[read_write_operation(i) for i in range(100)])

        assert len(results) == 100
        assert len(inv._local_file_cache) == 150  # 50 original + 100 new

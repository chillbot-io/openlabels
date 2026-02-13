"""
Data inventory service for delta scanning.
- Folder-level tracking for non-sensitive content
- File-level tracking for sensitive files
- Content hash comparison for change detection
- Distributed caching via Redis for multi-worker consistency
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from redis.exceptions import RedisError
except ImportError:
    class RedisError(Exception):  # type: ignore[no-redef]
        """Placeholder when redis is not installed."""
        pass

from openlabels.adapters.base import FileInfo
from openlabels.server.models import (
    FileInventory,
    FolderInventory,
    ScanResult,
)

if TYPE_CHECKING:
    from openlabels.server.cache import CacheManager

logger = logging.getLogger(__name__)

# Default TTL for scan inventory cache (1 hour)
DEFAULT_INVENTORY_TTL = 3600

# Bounded LRU cache sizes for on-demand lookups (B4)
_FILE_CACHE_MAX = 2000
_FOLDER_CACHE_MAX = 500


class DistributedScanInventory:
    """
    Distributed scan inventory cache using Redis.

    Provides consistent view of folder and file inventory across multiple workers
    processing the same scan target. Uses Redis hash structures for efficient
    storage and retrieval.

    Key structure:
    - openlabels:inventory:{tenant_id}:{target_id}:folders - Hash of folder data
    - openlabels:inventory:{tenant_id}:{target_id}:files - Hash of file data
    - openlabels:inventory:{tenant_id}:{target_id}:scanned - Set of scanned file paths

    Falls back to in-memory cache if Redis is unavailable.
    """

    def __init__(
        self,
        tenant_id: UUID,
        target_id: UUID,
        ttl: int = DEFAULT_INVENTORY_TTL,
        cache_manager: Optional[CacheManager] = None,
    ):
        """
        Initialize the distributed scan inventory.

        Args:
            tenant_id: Tenant ID
            target_id: Scan target ID
            ttl: Time-to-live in seconds for cache entries (default: 1 hour)
            cache_manager: Optional CacheManager instance (will be fetched if not provided)
        """
        self.tenant_id = tenant_id
        self.target_id = target_id
        self.ttl = ttl
        self._cache_manager = cache_manager
        self._redis_client: Any | None = None
        self._use_redis = False
        self._initialized = False

        # Fallback in-memory caches
        self._local_folder_cache: dict[str, dict] = {}
        self._local_file_cache: dict[str, dict] = {}
        self._local_scanned_files: set[str] = set()
        self._local_lock = asyncio.Lock()

        # Stats tracking
        self._hits = 0
        self._misses = 0

        # Key prefixes
        self._key_prefix = f"inventory:{tenant_id}:{target_id}"
        self._folders_key = f"{self._key_prefix}:folders"
        self._files_key = f"{self._key_prefix}:files"
        self._scanned_key = f"{self._key_prefix}:scanned"
        self._meta_key = f"{self._key_prefix}:meta"

    async def initialize(self) -> None:
        """
        Initialize the cache connection.

        Attempts to connect to Redis. Falls back to in-memory if unavailable.
        """
        if self._initialized:
            return

        try:
            if self._cache_manager is None:
                from openlabels.server.cache import get_cache_manager
                self._cache_manager = await get_cache_manager()

            # Check if Redis is available and get the underlying client
            if self._cache_manager.is_redis_connected:
                # Access the Redis client directly for hash operations
                redis_cache = self._cache_manager._redis
                if redis_cache and redis_cache._client:
                    self._redis_client = redis_cache._client
                    self._use_redis = True
                    logger.info(
                        f"Distributed inventory initialized with Redis for "
                        f"tenant={self.tenant_id}, target={self.target_id}"
                    )
                else:
                    logger.info(
                        f"Redis client not available, using in-memory cache for "
                        f"tenant={self.tenant_id}, target={self.target_id}"
                    )
            else:
                logger.info(
                    f"Redis not connected, using in-memory cache for "
                    f"tenant={self.tenant_id}, target={self.target_id}"
                )

        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            logger.warning(
                f"Failed to initialize Redis for distributed inventory: "
                f"{type(e).__name__}: {e}. Using in-memory fallback."
            )
            self._use_redis = False

        self._initialized = True

    def _make_redis_key(self, key: str) -> str:
        """Create a full Redis key with the openlabels prefix."""
        return f"openlabels:{key}"

    def _serialize(self, data: dict) -> str:
        """Serialize dictionary to JSON string for Redis storage."""
        return json.dumps(data, default=str)

    def _deserialize(self, data: str) -> dict:
        """Deserialize JSON string from Redis to dictionary."""
        if data is None:
            return None
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return None

    # Folder Operations
    async def get_folder(self, path: str) -> dict | None:
        """
        Get folder data from cache.

        Args:
            path: Folder path

        Returns:
            Folder data dictionary or None if not found
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._folders_key)
                data = await self._redis_client.hget(key, path)
                if data:
                    self._hits += 1
                    logger.debug(f"Cache hit: folder {path}")
                    return self._deserialize(data)
                else:
                    self._misses += 1
                    logger.debug(f"Cache miss: folder {path}")
                    return None
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_folder error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            data = self._local_folder_cache.get(path)
            if data:
                self._hits += 1
                logger.debug(f"Local cache hit: folder {path}")
            else:
                self._misses += 1
                logger.debug(f"Local cache miss: folder {path}")
            return data

    async def set_folder(self, path: str, data: dict) -> bool:
        """
        Set folder data in cache.

        Args:
            path: Folder path
            data: Folder data dictionary

        Returns:
            True if successful
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._folders_key)
                serialized = self._serialize(data)
                async with self._redis_client.pipeline(transaction=False) as pipe:
                    pipe.hset(key, path, serialized)
                    pipe.expire(key, self.ttl, nx=True)
                    await pipe.execute()
                logger.debug(f"Set folder in Redis: {path}")
                return True
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis set_folder error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            self._local_folder_cache[path] = data
            logger.debug(f"Set folder in local cache: {path}")
            return True

    async def get_all_folders(self) -> dict[str, dict]:
        """
        Get all folder data from cache.

        Returns:
            Dictionary mapping folder paths to folder data
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._folders_key)
                data = await self._redis_client.hgetall(key)
                result = {}
                for path, serialized in data.items():
                    folder_data = self._deserialize(serialized)
                    if folder_data:
                        result[path] = folder_data
                logger.debug(f"Retrieved {len(result)} folders from Redis")
                return result
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_all_folders error: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            return dict(self._local_folder_cache)

    async def delete_folder(self, path: str) -> bool:
        """
        Delete folder data from cache.

        Args:
            path: Folder path

        Returns:
            True if deleted, False if not found
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._folders_key)
                result = await self._redis_client.hdel(key, path)
                return result > 0
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis delete_folder error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            if path in self._local_folder_cache:
                del self._local_folder_cache[path]
                return True
            return False

    # File Operations
    async def get_file(self, path: str) -> dict | None:
        """
        Get file data from cache.

        Args:
            path: File path

        Returns:
            File data dictionary or None if not found
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._files_key)
                data = await self._redis_client.hget(key, path)
                if data:
                    self._hits += 1
                    logger.debug(f"Cache hit: file {path}")
                    return self._deserialize(data)
                else:
                    self._misses += 1
                    logger.debug(f"Cache miss: file {path}")
                    return None
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_file error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            data = self._local_file_cache.get(path)
            if data:
                self._hits += 1
                logger.debug(f"Local cache hit: file {path}")
            else:
                self._misses += 1
                logger.debug(f"Local cache miss: file {path}")
            return data

    async def set_file(self, path: str, data: dict) -> bool:
        """
        Set file data in cache.

        Args:
            path: File path
            data: File data dictionary

        Returns:
            True if successful
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._files_key)
                serialized = self._serialize(data)
                async with self._redis_client.pipeline(transaction=False) as pipe:
                    pipe.hset(key, path, serialized)
                    pipe.expire(key, self.ttl, nx=True)
                    await pipe.execute()
                logger.debug(f"Set file in Redis: {path}")
                return True
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis set_file error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            self._local_file_cache[path] = data
            logger.debug(f"Set file in local cache: {path}")
            return True

    async def get_all_files(self) -> dict[str, dict]:
        """
        Get all file data from cache.

        Returns:
            Dictionary mapping file paths to file data
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._files_key)
                data = await self._redis_client.hgetall(key)
                result = {}
                for path, serialized in data.items():
                    file_data = self._deserialize(serialized)
                    if file_data:
                        result[path] = file_data
                logger.debug(f"Retrieved {len(result)} files from Redis")
                return result
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_all_files error: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            return dict(self._local_file_cache)

    async def delete_file(self, path: str) -> bool:
        """
        Delete file data from cache.

        Args:
            path: File path

        Returns:
            True if deleted, False if not found
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._files_key)
                result = await self._redis_client.hdel(key, path)
                return result > 0
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis delete_file error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            if path in self._local_file_cache:
                del self._local_file_cache[path]
                return True
            return False

    # Atomic Scanned File Tracking
    async def mark_file_scanned(self, path: str) -> bool:
        """
        Atomically mark a file as scanned.

        This is an atomic operation that ensures only one worker marks a file
        as scanned, preventing duplicate processing.

        Args:
            path: File path

        Returns:
            True if this call marked the file (first to mark),
            False if already marked by another worker
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._scanned_key)
                async with self._redis_client.pipeline(transaction=False) as pipe:
                    pipe.sadd(key, path)
                    pipe.expire(key, self.ttl, nx=True)
                    results = await pipe.execute()
                added = results[0] > 0
                if added:
                    logger.debug(f"Marked file as scanned (Redis): {path}")
                else:
                    logger.debug(f"File already marked as scanned (Redis): {path}")
                return added
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis mark_file_scanned error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache (less atomic, but still works for single-process)
        async with self._local_lock:
            if path in self._local_scanned_files:
                logger.debug(f"File already marked as scanned (local): {path}")
                return False
            self._local_scanned_files.add(path)
            logger.debug(f"Marked file as scanned (local): {path}")
            return True

    async def is_file_scanned(self, path: str) -> bool:
        """
        Check if a file has been marked as scanned.

        Args:
            path: File path

        Returns:
            True if file has been marked as scanned
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._scanned_key)
                return await self._redis_client.sismember(key, path)
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis is_file_scanned error for {path}: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            return path in self._local_scanned_files

    async def get_scanned_files(self) -> set[str]:
        """
        Get all files that have been marked as scanned.

        Returns:
            Set of scanned file paths
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._scanned_key)
                members = await self._redis_client.smembers(key)
                return set(members)
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_scanned_files error: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            return set(self._local_scanned_files)

    async def get_scanned_count(self) -> int:
        """
        Get count of files marked as scanned.

        Returns:
            Number of scanned files
        """
        await self.initialize()

        if self._use_redis:
            try:
                key = self._make_redis_key(self._scanned_key)
                return await self._redis_client.scard(key)
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_scanned_count error: {type(e).__name__}: {e}")
                # Fall through to local cache

        # Use local cache
        async with self._local_lock:
            return len(self._local_scanned_files)

    # Scan Progress and Statistics
    async def get_scan_progress(self) -> dict:
        """
        Get current scan progress statistics.

        Returns:
            Dictionary with progress stats:
            - scanned_files: Number of files marked as scanned
            - total_files: Number of files in inventory
            - total_folders: Number of folders in inventory
            - progress_pct: Percentage complete (if total > 0)
        """
        await self.initialize()

        scanned_count = await self.get_scanned_count()

        if self._use_redis:
            try:
                files_key = self._make_redis_key(self._files_key)
                folders_key = self._make_redis_key(self._folders_key)

                total_files = await self._redis_client.hlen(files_key)
                total_folders = await self._redis_client.hlen(folders_key)
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_scan_progress error: {type(e).__name__}: {e}")
                # Fall through to local cache
                async with self._local_lock:
                    total_files = len(self._local_file_cache)
                    total_folders = len(self._local_folder_cache)
        else:
            async with self._local_lock:
                total_files = len(self._local_file_cache)
                total_folders = len(self._local_folder_cache)

        progress_pct = (scanned_count / total_files * 100) if total_files > 0 else 0

        return {
            "scanned_files": scanned_count,
            "total_files": total_files,
            "total_folders": total_folders,
            "progress_pct": round(progress_pct, 2),
        }

    async def set_metadata(self, key: str, value: Any) -> bool:
        """
        Set scan metadata value.

        Args:
            key: Metadata key
            value: Metadata value

        Returns:
            True if successful
        """
        await self.initialize()

        if self._use_redis:
            try:
                redis_key = self._make_redis_key(self._meta_key)
                serialized = self._serialize({"value": value})
                async with self._redis_client.pipeline(transaction=False) as pipe:
                    pipe.hset(redis_key, key, serialized)
                    pipe.expire(redis_key, self.ttl, nx=True)
                    await pipe.execute()
                return True
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis set_metadata error for {key}: {type(e).__name__}: {e}")

        return False

    async def get_metadata(self, key: str) -> Any | None:
        """
        Get scan metadata value.

        Args:
            key: Metadata key

        Returns:
            Metadata value or None
        """
        await self.initialize()

        if self._use_redis:
            try:
                redis_key = self._make_redis_key(self._meta_key)
                data = await self._redis_client.hget(redis_key, key)
                if data:
                    deserialized = self._deserialize(data)
                    return deserialized.get("value") if deserialized else None
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis get_metadata error for {key}: {type(e).__name__}: {e}")

        return None

    # Cache Management
    async def clear_inventory(self) -> bool:
        """
        Clear all inventory cache data for this tenant/target.

        Should be called after scan completes to free up Redis memory.

        Returns:
            True if successful
        """
        await self.initialize()

        if self._use_redis:
            try:
                keys_to_delete = [
                    self._make_redis_key(self._folders_key),
                    self._make_redis_key(self._files_key),
                    self._make_redis_key(self._scanned_key),
                    self._make_redis_key(self._meta_key),
                ]
                if keys_to_delete:
                    await self._redis_client.delete(*keys_to_delete)
                logger.info(
                    f"Cleared inventory cache for tenant={self.tenant_id}, "
                    f"target={self.target_id}"
                )
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis clear_inventory error: {type(e).__name__}: {e}")
                # Continue to clear local cache anyway

        # Clear local caches
        async with self._local_lock:
            self._local_folder_cache.clear()
            self._local_file_cache.clear()
            self._local_scanned_files.clear()

        return True

    async def refresh_ttl(self) -> bool:
        """
        Refresh TTL on all inventory cache keys.

        Call periodically during long-running scans to prevent expiration.

        Returns:
            True if successful
        """
        await self.initialize()

        if self._use_redis:
            try:
                keys = [
                    self._make_redis_key(self._folders_key),
                    self._make_redis_key(self._files_key),
                    self._make_redis_key(self._scanned_key),
                    self._make_redis_key(self._meta_key),
                ]
                async with self._redis_client.pipeline(transaction=False) as pipe:
                    for key in keys:
                        pipe.expire(key, self.ttl)
                    await pipe.execute()
                logger.debug("Refreshed TTL for inventory cache")
                return True
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis refresh_ttl error: {type(e).__name__}: {e}")
                return False

        return True  # No TTL management needed for local cache

    @property
    def stats(self) -> dict:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "backend": "redis" if self._use_redis else "memory",
            "tenant_id": str(self.tenant_id),
            "target_id": str(self.target_id),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%",
            "ttl": self.ttl,
        }

    @property
    def is_redis_connected(self) -> bool:
        """Check if using Redis backend."""
        return self._use_redis


class InventoryService:
    """
    Service for managing the data inventory.

    The inventory enables delta scanning by tracking:
    - All folders (at folder level)
    - Sensitive files only (at file level with content hashes)

    Supports optional distributed caching via Redis for multi-worker consistency.
    When use_distributed_cache is True, folder/file inventory state is shared
    across workers processing the same scan target.
    """

    def __init__(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        target_id: UUID,
        use_distributed_cache: bool = False,
        distributed_cache_ttl: int = DEFAULT_INVENTORY_TTL,
        cache_manager: Optional[CacheManager] = None,
    ):
        """
        Initialize the inventory service.

        Args:
            session: Database session
            tenant_id: Tenant ID
            target_id: Scan target ID
            use_distributed_cache: Whether to use Redis-based distributed caching
            distributed_cache_ttl: TTL for distributed cache entries (default: 1 hour)
            cache_manager: Optional CacheManager instance for distributed cache
        """
        self.session = session
        self.tenant_id = tenant_id
        self.target_id = target_id
        self._folder_cache: OrderedDict[str, FolderInventory] = OrderedDict()
        self._file_cache: OrderedDict[str, FileInventory] = OrderedDict()

        # Distributed cache for multi-worker consistency
        self._use_distributed_cache = use_distributed_cache
        self._distributed_inventory: DistributedScanInventory | None = None

        if use_distributed_cache:
            self._distributed_inventory = DistributedScanInventory(
                tenant_id=tenant_id,
                target_id=target_id,
                ttl=distributed_cache_ttl,
                cache_manager=cache_manager,
            )

    async def initialize_distributed_cache(self) -> None:
        """
        Initialize the distributed cache connection.

        Call this before starting scan operations when using distributed caching.
        """
        if self._distributed_inventory:
            await self._distributed_inventory.initialize()

    @property
    def distributed_inventory(self) -> DistributedScanInventory | None:
        """Get the distributed inventory instance (if enabled)."""
        return self._distributed_inventory

    async def _get_folder_inv(self, folder_path: str) -> FolderInventory | None:
        """On-demand folder inventory lookup: LRU cache -> DB query."""
        if folder_path in self._folder_cache:
            self._folder_cache.move_to_end(folder_path)
            return self._folder_cache[folder_path]

        query = select(FolderInventory).where(
            and_(
                FolderInventory.tenant_id == self.tenant_id,
                FolderInventory.target_id == self.target_id,
                FolderInventory.folder_path == folder_path,
            )
        )
        result = await self.session.execute(query)
        folder_inv = result.scalar_one_or_none()

        if folder_inv is not None:
            self._cache_folder(folder_path, folder_inv)
        return folder_inv

    async def _get_file_inv(self, file_path: str) -> FileInventory | None:
        """On-demand file inventory lookup: LRU cache -> DB query."""
        if file_path in self._file_cache:
            self._file_cache.move_to_end(file_path)
            return self._file_cache[file_path]

        query = select(FileInventory).where(
            and_(
                FileInventory.tenant_id == self.tenant_id,
                FileInventory.target_id == self.target_id,
                FileInventory.file_path == file_path,
            )
        )
        result = await self.session.execute(query)
        file_inv = result.scalar_one_or_none()

        if file_inv is not None:
            self._cache_file(file_path, file_inv)
        return file_inv

    def _cache_folder(self, path: str, inv: FolderInventory) -> None:
        """Add to bounded LRU cache, evicting oldest if over limit."""
        self._folder_cache[path] = inv
        self._folder_cache.move_to_end(path)
        while len(self._folder_cache) > _FOLDER_CACHE_MAX:
            self._folder_cache.popitem(last=False)

    def _cache_file(self, path: str, inv: FileInventory) -> None:
        """Add to bounded LRU cache, evicting oldest if over limit."""
        self._file_cache[path] = inv
        self._file_cache.move_to_end(path)
        while len(self._file_cache) > _FILE_CACHE_MAX:
            self._file_cache.popitem(last=False)

    async def sync_folder_to_distributed_cache(self, folder_path: str, folder_inv: FolderInventory) -> None:
        """
        Sync a folder inventory entry to the distributed cache.

        Args:
            folder_path: Path to the folder
            folder_inv: FolderInventory model instance
        """
        if not self._distributed_inventory:
            return

        folder_data = {
            "folder_path": folder_inv.folder_path,
            "adapter": folder_inv.adapter,
            "file_count": folder_inv.file_count,
            "total_size_bytes": folder_inv.total_size_bytes,
            "folder_modified": folder_inv.folder_modified.isoformat() if folder_inv.folder_modified else None,
            "last_scanned_at": folder_inv.last_scanned_at.isoformat() if folder_inv.last_scanned_at else None,
            "last_scan_job_id": str(folder_inv.last_scan_job_id) if folder_inv.last_scan_job_id else None,
            "has_sensitive_files": folder_inv.has_sensitive_files,
            "highest_risk_tier": folder_inv.highest_risk_tier,
            "total_entities_found": folder_inv.total_entities_found,
        }
        await self._distributed_inventory.set_folder(folder_path, folder_data)

    async def sync_file_to_distributed_cache(self, file_path: str, file_inv: FileInventory) -> None:
        """
        Sync a file inventory entry to the distributed cache.

        Args:
            file_path: Path to the file
            file_inv: FileInventory model instance
        """
        if not self._distributed_inventory:
            return

        file_data = {
            "file_path": file_inv.file_path,
            "file_name": file_inv.file_name,
            "adapter": file_inv.adapter,
            "content_hash": file_inv.content_hash,
            "file_size": file_inv.file_size,
            "file_modified": file_inv.file_modified.isoformat() if file_inv.file_modified else None,
            "risk_score": file_inv.risk_score,
            "risk_tier": file_inv.risk_tier,
            "entity_counts": file_inv.entity_counts,
            "total_entities": file_inv.total_entities,
            "exposure_level": file_inv.exposure_level,
            "owner": file_inv.owner,
            "current_label_id": file_inv.current_label_id,
            "current_label_name": file_inv.current_label_name,
            "label_applied_at": file_inv.label_applied_at.isoformat() if file_inv.label_applied_at else None,
            "last_scanned_at": file_inv.last_scanned_at.isoformat() if file_inv.last_scanned_at else None,
            "last_scan_job_id": str(file_inv.last_scan_job_id) if file_inv.last_scan_job_id else None,
            "needs_rescan": file_inv.needs_rescan,
            "scan_count": file_inv.scan_count,
            "content_changed_count": file_inv.content_changed_count,
        }
        await self._distributed_inventory.set_file(file_path, file_data)

    async def mark_file_scanned_distributed(self, file_path: str) -> bool:
        """
        Atomically mark a file as scanned in distributed cache.

        This prevents multiple workers from processing the same file.

        Args:
            file_path: Path to the file

        Returns:
            True if this call marked the file (first to mark),
            False if already marked by another worker
        """
        if not self._distributed_inventory:
            return True  # No distributed cache, always process

        return await self._distributed_inventory.mark_file_scanned(file_path)

    async def is_file_scanned_distributed(self, file_path: str) -> bool:
        """
        Check if a file has been marked as scanned in distributed cache.

        Args:
            file_path: Path to the file

        Returns:
            True if file has been scanned by any worker
        """
        if not self._distributed_inventory:
            return False

        return await self._distributed_inventory.is_file_scanned(file_path)

    async def get_distributed_scan_progress(self) -> dict | None:
        """
        Get scan progress from distributed cache.

        Returns:
            Progress dictionary or None if distributed cache not enabled
        """
        if not self._distributed_inventory:
            return None

        return await self._distributed_inventory.get_scan_progress()

    async def clear_distributed_cache(self) -> None:
        """Clear all distributed cache data for this scan."""
        if self._distributed_inventory:
            await self._distributed_inventory.clear_inventory()

    async def refresh_distributed_cache_ttl(self) -> None:
        """Refresh TTL on distributed cache keys."""
        if self._distributed_inventory:
            await self._distributed_inventory.refresh_ttl()

    async def should_scan_folder(
        self,
        folder_path: str,
        folder_modified: datetime | None = None,
        force_full_scan: bool = False,
    ) -> bool:
        """
        Check if a folder needs scanning.

        Args:
            folder_path: Path to the folder
            folder_modified: Folder modification time
            force_full_scan: Force scan regardless of inventory

        Returns:
            True if folder should be scanned
        """
        if force_full_scan:
            return True

        folder_inv = await self._get_folder_inv(folder_path)
        if folder_inv is None:
            return True  # New folder

        # If no last scan, needs scanning
        if not folder_inv.last_scanned_at:
            return True

        # If folder modified since last scan, needs scanning
        if folder_modified and folder_inv.folder_modified:
            if folder_modified > folder_inv.folder_modified:
                return True

        # If has sensitive files, always scan
        if folder_inv.has_sensitive_files:
            return True

        return False

    async def should_scan_file(
        self,
        file_info: FileInfo,
        content_hash: str | None = None,
        force_full_scan: bool = False,
    ) -> tuple[bool, str]:
        """
        Check if a file needs scanning.

        Args:
            file_info: File information
            content_hash: Pre-computed content hash (if available)
            force_full_scan: Force scan regardless of inventory

        Returns:
            Tuple of (should_scan, reason)
        """
        if force_full_scan:
            return True, "full_scan"

        file_path = file_info.path
        file_inv = await self._get_file_inv(file_path)

        if file_inv is None:
            return True, "new_file"

        # Check if flagged for rescan
        if file_inv.needs_rescan:
            return True, "flagged_rescan"

        # Check content hash if available
        if content_hash and file_inv.content_hash:
            if content_hash != file_inv.content_hash:
                return True, "content_changed"

        # Check file modification time
        if file_info.modified and file_inv.file_modified:
            if file_info.modified > file_inv.file_modified:
                return True, "modified_time"

        # Check file size changed
        if file_info.size != file_inv.file_size:
            return True, "size_changed"

        return False, "unchanged"

    def compute_content_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of file content."""
        return hashlib.sha256(content).hexdigest()

    async def update_folder_inventory(
        self,
        folder_path: str,
        adapter: str,
        job_id: UUID,
        file_count: int = 0,
        total_size: int = 0,
        folder_modified: datetime | None = None,
        has_sensitive: bool = False,
        highest_risk: str | None = None,
        total_entities: int = 0,
    ) -> FolderInventory:
        """
        Update or create folder inventory entry.

        Args:
            folder_path: Path to the folder
            adapter: Adapter type
            job_id: Current scan job ID
            file_count: Number of files in folder
            total_size: Total size of files in folder
            folder_modified: Folder modification time
            has_sensitive: Whether folder contains sensitive files
            highest_risk: Highest risk tier in folder
            total_entities: Total entities found in folder

        Returns:
            Updated or created FolderInventory
        """
        folder_inv = await self._get_folder_inv(folder_path)

        if folder_inv is not None:
            folder_inv.file_count = file_count
            folder_inv.total_size_bytes = total_size
            folder_inv.folder_modified = folder_modified
            folder_inv.last_scanned_at = datetime.now(timezone.utc)
            folder_inv.last_scan_job_id = job_id
            folder_inv.has_sensitive_files = has_sensitive
            folder_inv.highest_risk_tier = highest_risk
            folder_inv.total_entities_found = total_entities
        else:
            folder_inv = FolderInventory(
                tenant_id=self.tenant_id,
                target_id=self.target_id,
                folder_path=folder_path,
                adapter=adapter,
                file_count=file_count,
                total_size_bytes=total_size,
                folder_modified=folder_modified,
                last_scanned_at=datetime.now(timezone.utc),
                last_scan_job_id=job_id,
                has_sensitive_files=has_sensitive,
                highest_risk_tier=highest_risk,
                total_entities_found=total_entities,
            )
            self.session.add(folder_inv)
            self._cache_folder(folder_path, folder_inv)

        # Sync to distributed cache for multi-worker consistency
        await self.sync_folder_to_distributed_cache(folder_path, folder_inv)

        return folder_inv

    async def update_file_inventory(
        self,
        file_info: FileInfo,
        scan_result: ScanResult,
        content_hash: str,
        job_id: UUID,
        folder_id: UUID | None = None,
    ) -> FileInventory:
        """
        Update or create file inventory entry for a sensitive file.

        Args:
            file_info: File information
            scan_result: Scan result for the file
            content_hash: SHA-256 hash of file content
            job_id: Current scan job ID
            folder_id: Parent folder inventory ID

        Returns:
            Updated or created FileInventory
        """
        file_path = file_info.path
        file_inv = await self._get_file_inv(file_path)

        if file_inv is not None:
            # Track content changes
            if file_inv.content_hash != content_hash:
                file_inv.content_changed_count += 1

            file_inv.content_hash = content_hash
            file_inv.file_size = file_info.size
            file_inv.file_modified = file_info.modified
            file_inv.risk_score = scan_result.risk_score
            file_inv.risk_tier = scan_result.risk_tier
            file_inv.entity_counts = scan_result.entity_counts
            file_inv.total_entities = scan_result.total_entities
            file_inv.exposure_level = scan_result.exposure_level
            file_inv.owner = scan_result.owner
            file_inv.last_scanned_at = datetime.now(timezone.utc)
            file_inv.last_scan_job_id = job_id
            file_inv.scan_count += 1
            file_inv.needs_rescan = False

            # Update label info if present
            if scan_result.label_applied:
                file_inv.current_label_id = scan_result.current_label_id
                file_inv.current_label_name = scan_result.current_label_name
                file_inv.label_applied_at = scan_result.label_applied_at
        else:
            file_inv = FileInventory(
                tenant_id=self.tenant_id,
                target_id=self.target_id,
                folder_id=folder_id,
                file_path=file_path,
                file_name=file_info.name,
                adapter=file_info.adapter,
                content_hash=content_hash,
                file_size=file_info.size,
                file_modified=file_info.modified,
                risk_score=scan_result.risk_score,
                risk_tier=scan_result.risk_tier,
                entity_counts=scan_result.entity_counts,
                total_entities=scan_result.total_entities,
                exposure_level=scan_result.exposure_level,
                owner=scan_result.owner,
                last_scanned_at=datetime.now(timezone.utc),
                last_scan_job_id=job_id,
                current_label_id=scan_result.current_label_id if scan_result.label_applied else None,
                current_label_name=scan_result.current_label_name if scan_result.label_applied else None,
                label_applied_at=scan_result.label_applied_at if scan_result.label_applied else None,
            )
            self.session.add(file_inv)
            self._cache_file(file_path, file_inv)

        # Sync to distributed cache for multi-worker consistency
        await self.sync_file_to_distributed_cache(file_path, file_inv)

        return file_inv

    async def mark_missing_files(self, job_id: UUID) -> int:
        """
        Mark files not seen in the current scan for rescan.

        Uses a single DB UPDATE instead of iterating an in-memory cache:
        any file whose last_scan_job_id doesn't match the current job
        wasn't seen and may have been deleted, moved, or access revoked.

        Args:
            job_id: Current scan job ID

        Returns:
            Count of files marked for rescan
        """
        stmt = (
            update(FileInventory)
            .where(
                and_(
                    FileInventory.tenant_id == self.tenant_id,
                    FileInventory.target_id == self.target_id,
                    FileInventory.last_scan_job_id != job_id,
                    FileInventory.needs_rescan == False,
                )
            )
            .values(needs_rescan=True)
        )
        result = await self.session.execute(stmt)
        return result.rowcount

    async def get_inventory_stats(self) -> dict:
        """Get statistics about the current inventory via DB aggregation."""
        base_filter = and_(
            FileInventory.tenant_id == self.tenant_id,
            FileInventory.target_id == self.target_id,
        )

        # Folder count
        folder_q = select(func.count()).select_from(FolderInventory).where(
            and_(
                FolderInventory.tenant_id == self.tenant_id,
                FolderInventory.target_id == self.target_id,
            )
        )
        folder_count = (await self.session.execute(folder_q)).scalar() or 0

        # File aggregate stats
        file_q = select(
            func.count().label("total"),
            func.coalesce(func.sum(FileInventory.total_entities), 0).label("total_entities"),
        ).where(base_filter)
        file_row = (await self.session.execute(file_q)).one()

        # Labeled count (non-null current_label_id)
        labeled_q = select(func.count()).select_from(FileInventory).where(
            and_(base_filter, FileInventory.current_label_id.isnot(None))
        )
        labeled_count = (await self.session.execute(labeled_q)).scalar() or 0

        # Pending rescan count
        rescan_q = select(func.count()).select_from(FileInventory).where(
            and_(base_filter, FileInventory.needs_rescan == True)
        )
        pending_rescan = (await self.session.execute(rescan_q)).scalar() or 0

        # Risk tier breakdown
        risk_q = (
            select(FileInventory.risk_tier, func.count().label("cnt"))
            .where(base_filter)
            .group_by(FileInventory.risk_tier)
        )
        risk_rows = (await self.session.execute(risk_q)).all()

        risk_tiers = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        for row in risk_rows:
            if row.risk_tier in risk_tiers:
                risk_tiers[row.risk_tier] = row.cnt

        stats = {
            "total_folders": folder_count,
            "total_sensitive_files": file_row.total or 0,
            "risk_tier_breakdown": risk_tiers,
            "total_entities": file_row.total_entities,
            "labeled_files": labeled_count,
            "pending_rescan": pending_rescan,
        }

        # Include distributed cache stats if enabled
        if self._distributed_inventory:
            stats["distributed_cache"] = self._distributed_inventory.stats
            progress = await self.get_distributed_scan_progress()
            if progress:
                stats["distributed_progress"] = progress

        return stats


def get_folder_path(file_path: str) -> str:
    """Extract folder path from file path."""
    return str(Path(file_path).parent)

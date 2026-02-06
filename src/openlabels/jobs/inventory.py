"""
Data inventory service for delta scanning.

This module provides inventory management to enable efficient delta scans:
- Folder-level tracking for non-sensitive content
- File-level tracking for sensitive files
- Content hash comparison for change detection
- Distributed caching via Redis for multi-worker consistency
"""

import asyncio
import hashlib
import json
import logging
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select, and_, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from redis.exceptions import RedisError
except ImportError:
    class RedisError(Exception):  # type: ignore[no-redef]
        """Placeholder when redis is not installed."""
        pass

from openlabels.server.models import (
    FolderInventory,
    FileInventory,
    ScanTarget,
    ScanResult,
)
from openlabels.adapters.base import FileInfo

if TYPE_CHECKING:
    from openlabels.server.cache import CacheManager

logger = logging.getLogger(__name__)

# Default TTL for scan inventory cache (1 hour)
DEFAULT_INVENTORY_TTL = 3600


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
        cache_manager: Optional["CacheManager"] = None,
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
        self._redis_client: Optional[Any] = None
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

    # -------------------------------------------------------------------------
    # Folder Operations
    # -------------------------------------------------------------------------

    async def get_folder(self, path: str) -> Optional[dict]:
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
                await self._redis_client.hset(key, path, serialized)
                # Set TTL on the hash key (only if not already set)
                ttl = await self._redis_client.ttl(key)
                if ttl < 0:  # -1 means no TTL, -2 means key doesn't exist
                    await self._redis_client.expire(key, self.ttl)
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

    # -------------------------------------------------------------------------
    # File Operations
    # -------------------------------------------------------------------------

    async def get_file(self, path: str) -> Optional[dict]:
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
                await self._redis_client.hset(key, path, serialized)
                # Set TTL on the hash key (only if not already set)
                ttl = await self._redis_client.ttl(key)
                if ttl < 0:
                    await self._redis_client.expire(key, self.ttl)
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

    # -------------------------------------------------------------------------
    # Atomic Scanned File Tracking
    # -------------------------------------------------------------------------

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
                # SADD returns 1 if the element was added, 0 if it already existed
                result = await self._redis_client.sadd(key, path)
                # Set TTL on first addition
                if result > 0:
                    ttl = await self._redis_client.ttl(key)
                    if ttl < 0:
                        await self._redis_client.expire(key, self.ttl)
                    logger.debug(f"Marked file as scanned (Redis): {path}")
                    return True
                else:
                    logger.debug(f"File already marked as scanned (Redis): {path}")
                    return False
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

    # -------------------------------------------------------------------------
    # Scan Progress and Statistics
    # -------------------------------------------------------------------------

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
                await self._redis_client.hset(redis_key, key, serialized)
                ttl = await self._redis_client.ttl(redis_key)
                if ttl < 0:
                    await self._redis_client.expire(redis_key, self.ttl)
                return True
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(f"Redis set_metadata error for {key}: {type(e).__name__}: {e}")

        return False

    async def get_metadata(self, key: str) -> Optional[Any]:
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

    # -------------------------------------------------------------------------
    # Cache Management
    # -------------------------------------------------------------------------

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
                for key in keys:
                    await self._redis_client.expire(key, self.ttl)
                logger.debug(f"Refreshed TTL for inventory cache")
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
        cache_manager: Optional["CacheManager"] = None,
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
        self._folder_cache: dict[str, FolderInventory] = {}
        self._file_cache: dict[str, FileInventory] = {}

        # Distributed cache for multi-worker consistency
        self._use_distributed_cache = use_distributed_cache
        self._distributed_inventory: Optional[DistributedScanInventory] = None

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
    def distributed_inventory(self) -> Optional[DistributedScanInventory]:
        """Get the distributed inventory instance (if enabled)."""
        return self._distributed_inventory

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

    async def get_distributed_scan_progress(self) -> Optional[dict]:
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

    async def load_folder_inventory(self) -> dict[str, FolderInventory]:
        """Load existing folder inventory into cache."""
        query = select(FolderInventory).where(
            and_(
                FolderInventory.tenant_id == self.tenant_id,
                FolderInventory.target_id == self.target_id,
            )
        )
        result = await self.session.execute(query)
        folders = result.scalars().all()

        self._folder_cache = {f.folder_path: f for f in folders}
        return self._folder_cache

    async def load_file_inventory(self) -> dict[str, FileInventory]:
        """Load existing file inventory into cache."""
        query = select(FileInventory).where(
            and_(
                FileInventory.tenant_id == self.tenant_id,
                FileInventory.target_id == self.target_id,
            )
        )
        result = await self.session.execute(query)
        files = result.scalars().all()

        self._file_cache = {f.file_path: f for f in files}
        return self._file_cache

    async def should_scan_folder(
        self,
        folder_path: str,
        folder_modified: Optional[datetime] = None,
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

        if folder_path not in self._folder_cache:
            return True  # New folder

        folder_inv = self._folder_cache[folder_path]

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
        content_hash: Optional[str] = None,
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

        if file_path not in self._file_cache:
            return True, "new_file"

        file_inv = self._file_cache[file_path]

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
        folder_modified: Optional[datetime] = None,
        has_sensitive: bool = False,
        highest_risk: Optional[str] = None,
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
        if folder_path in self._folder_cache:
            folder_inv = self._folder_cache[folder_path]
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
            self._folder_cache[folder_path] = folder_inv

        # Sync to distributed cache for multi-worker consistency
        await self.sync_folder_to_distributed_cache(folder_path, folder_inv)

        return folder_inv

    async def update_file_inventory(
        self,
        file_info: FileInfo,
        scan_result: ScanResult,
        content_hash: str,
        job_id: UUID,
        folder_id: Optional[UUID] = None,
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

        if file_path in self._file_cache:
            file_inv = self._file_cache[file_path]

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
            self._file_cache[file_path] = file_inv

        # Sync to distributed cache for multi-worker consistency
        await self.sync_file_to_distributed_cache(file_path, file_inv)

        return file_inv

    async def mark_missing_files(self, seen_paths: set[str], job_id: UUID) -> int:
        """
        Mark files that were not seen in current scan.

        Files that exist in inventory but weren't seen may have been:
        - Deleted
        - Moved
        - Access revoked

        Args:
            seen_paths: Set of file paths seen in current scan
            job_id: Current scan job ID

        Returns:
            Count of files marked for rescan
        """
        marked_count = 0

        for file_path, file_inv in self._file_cache.items():
            if file_path not in seen_paths:
                # File not seen - mark for rescan
                file_inv.needs_rescan = True
                marked_count += 1

        return marked_count

    async def get_inventory_stats(self) -> dict:
        """Get statistics about the current inventory."""
        folder_count = len(self._folder_cache)
        file_count = len(self._file_cache)

        risk_tiers = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        total_entities = 0
        labeled_count = 0

        for file_inv in self._file_cache.values():
            if file_inv.risk_tier in risk_tiers:
                risk_tiers[file_inv.risk_tier] += 1
            total_entities += file_inv.total_entities
            if file_inv.current_label_id:
                labeled_count += 1

        stats = {
            "total_folders": folder_count,
            "total_sensitive_files": file_count,
            "risk_tier_breakdown": risk_tiers,
            "total_entities": total_entities,
            "labeled_files": labeled_count,
            "pending_rescan": sum(1 for f in self._file_cache.values() if f.needs_rescan),
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

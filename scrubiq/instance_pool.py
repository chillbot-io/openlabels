"""ScrubIQ instance pool for multi-tenant API key isolation.

Each API key gets its own ScrubIQ instance with isolated:
- Token store (encrypted PHI mappings)
- Entity graph (conversation state)
- Conversations and messages
- Audit log entries

Shared across instances:
- ML models (preloaded once, stateless)
- Database connection
- Configuration

Memory management:
- LRU eviction when pool exceeds max size
- Instances evicted after idle timeout
"""

import logging
import threading
import time
from collections import OrderedDict
from typing import Optional, Dict, Tuple
from dataclasses import dataclass

from .config import Config
from .core import ScrubIQ

logger = logging.getLogger(__name__)

# Default pool settings
DEFAULT_MAX_INSTANCES = 100
DEFAULT_IDLE_TIMEOUT_SECONDS = 3600  # 1 hour


@dataclass
class PooledInstance:
    """Wrapper for a pooled ScrubIQ instance with metadata."""
    instance: ScrubIQ
    api_key_prefix: str
    created_at: float
    last_accessed_at: float
    access_count: int = 0


class InstancePool:
    """
    Thread-safe pool of ScrubIQ instances keyed by API key prefix.

    Features:
    - Lazy instance creation on first access
    - LRU eviction when pool is full
    - Idle timeout eviction
    - Shared model preloading

    Usage:
        pool = InstancePool(config, max_instances=50)

        # Get or create instance for an API key
        instance = pool.get_or_create(
            api_key_prefix="sk-7Kx9",
            encryption_key=derived_key,
        )

        # Use the instance
        result = instance.redact(text)
    """

    def __init__(
        self,
        config: Config,
        max_instances: int = DEFAULT_MAX_INSTANCES,
        idle_timeout_seconds: int = DEFAULT_IDLE_TIMEOUT_SECONDS,
    ):
        """
        Initialize the instance pool.

        Args:
            config: ScrubIQ configuration (shared across instances)
            max_instances: Maximum number of concurrent instances
            idle_timeout_seconds: Evict instances idle longer than this
        """
        self._config = config
        self._max_instances = max_instances
        self._idle_timeout = idle_timeout_seconds

        # OrderedDict for LRU tracking (most recently used at end)
        self._instances: OrderedDict[str, PooledInstance] = OrderedDict()
        self._lock = threading.RLock()

        # Track if models are preloaded
        self._models_preloaded = False

        # Statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "creates": 0,
        }

    def preload_models(self) -> None:
        """
        Preload ML models before any instances are created.

        Call this during app startup. Models are loaded once and
        shared across all instances via class-level caching in ScrubIQ.
        """
        if self._models_preloaded:
            return

        logger.info("Preloading ML models for instance pool...")
        ScrubIQ.preload_models_async(self._config)
        self._models_preloaded = True

    def get_or_create(
        self,
        api_key_prefix: str,
        encryption_key: bytes,
    ) -> ScrubIQ:
        """
        Get existing instance or create new one for the API key.

        Args:
            api_key_prefix: API key prefix (e.g., "sk-7Kx9")
            encryption_key: Derived encryption key for this API key

        Returns:
            ScrubIQ instance for this API key
        """
        with self._lock:
            now = time.time()

            # Check for existing instance
            if api_key_prefix in self._instances:
                pooled = self._instances[api_key_prefix]
                pooled.last_accessed_at = now
                pooled.access_count += 1

                # Move to end (most recently used)
                self._instances.move_to_end(api_key_prefix)

                self._stats["hits"] += 1
                logger.debug(f"Pool hit for {api_key_prefix}")
                return pooled.instance

            # Need to create new instance
            self._stats["misses"] += 1

            # Evict if at capacity
            self._evict_if_needed()

            # Create new instance
            instance = self._create_instance(api_key_prefix, encryption_key)

            pooled = PooledInstance(
                instance=instance,
                api_key_prefix=api_key_prefix,
                created_at=now,
                last_accessed_at=now,
                access_count=1,
            )

            self._instances[api_key_prefix] = pooled
            self._stats["creates"] += 1

            logger.info(f"Created new instance for {api_key_prefix} (pool size: {len(self._instances)})")
            return instance

    def _create_instance(
        self,
        api_key_prefix: str,
        encryption_key: bytes,
    ) -> ScrubIQ:
        """Create and unlock a new ScrubIQ instance."""
        # Create instance with shared config
        instance = ScrubIQ(self._config)

        # Set session_id BEFORE unlock for proper token isolation
        # This ensures all tokens are stored with this API key's prefix
        instance._session.set_session_id(f"apikey:{api_key_prefix}")

        # Derive key material from encryption key (hex-encoded)
        # SECURITY FIX: Use full 64-char hex (32 bytes) instead of truncated 32-char (16 bytes)
        # Truncation was reducing AES-256 to AES-128 effective strength
        key_material = encryption_key.hex()

        try:
            instance.unlock(key_material)
        except Exception as e:
            logger.error(f"Failed to unlock instance for {api_key_prefix}: {e}")
            instance.close()
            raise

        return instance

    def _evict_if_needed(self) -> None:
        """Evict instances if pool is at capacity or instances are idle."""
        now = time.time()

        # First, evict idle instances
        idle_keys = []
        for key, pooled in self._instances.items():
            if now - pooled.last_accessed_at > self._idle_timeout:
                idle_keys.append(key)

        for key in idle_keys:
            self._evict(key, reason="idle")

        # Then, evict LRU if still at capacity
        while len(self._instances) >= self._max_instances:
            # Pop first item (least recently used)
            oldest_key = next(iter(self._instances))
            self._evict(oldest_key, reason="capacity")

    def _evict(self, api_key_prefix: str, reason: str) -> None:
        """Evict an instance from the pool."""
        if api_key_prefix not in self._instances:
            return

        pooled = self._instances.pop(api_key_prefix)

        try:
            pooled.instance.close()
        except Exception as e:
            logger.warning(f"Error closing evicted instance {api_key_prefix}: {e}")

        self._stats["evictions"] += 1
        logger.info(f"Evicted instance {api_key_prefix} ({reason})")

    def remove(self, api_key_prefix: str) -> bool:
        """
        Explicitly remove an instance (e.g., when API key is revoked).

        Args:
            api_key_prefix: API key prefix to remove

        Returns:
            True if instance was removed, False if not found
        """
        with self._lock:
            if api_key_prefix in self._instances:
                self._evict(api_key_prefix, reason="explicit")
                return True
            return False

    def cleanup_idle(self) -> int:
        """
        Remove all idle instances. Call periodically.

        Returns:
            Number of instances evicted
        """
        with self._lock:
            now = time.time()
            idle_keys = [
                key for key, pooled in self._instances.items()
                if now - pooled.last_accessed_at > self._idle_timeout
            ]

            for key in idle_keys:
                self._evict(key, reason="idle_cleanup")

            return len(idle_keys)

    def get_stats(self) -> Dict:
        """Get pool statistics."""
        with self._lock:
            return {
                **self._stats,
                "current_size": len(self._instances),
                "max_size": self._max_instances,
                "hit_rate": (
                    self._stats["hits"] / (self._stats["hits"] + self._stats["misses"])
                    if (self._stats["hits"] + self._stats["misses"]) > 0
                    else 0.0
                ),
            }

    def list_instances(self) -> list:
        """List all active instances (for debugging/admin)."""
        with self._lock:
            return [
                {
                    "api_key_prefix": pooled.api_key_prefix,
                    "created_at": pooled.created_at,
                    "last_accessed_at": pooled.last_accessed_at,
                    "access_count": pooled.access_count,
                    "idle_seconds": time.time() - pooled.last_accessed_at,
                }
                for pooled in self._instances.values()
            ]

    def close(self) -> None:
        """Close all instances and shutdown the pool."""
        with self._lock:
            logger.info(f"Closing instance pool ({len(self._instances)} instances)")

            for key in list(self._instances.keys()):
                self._evict(key, reason="shutdown")

            self._instances.clear()


# Global pool instance (set during app initialization)
_pool: Optional[InstancePool] = None
_pool_lock = threading.Lock()  # Protects global _pool access


def init_pool(config: Config, **kwargs) -> InstancePool:
    """Initialize the global instance pool (thread-safe)."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            # Already initialized - return existing pool
            return _pool
        _pool = InstancePool(config, **kwargs)
        _pool.preload_models()
        return _pool


def get_pool() -> InstancePool:
    """Get the global instance pool (thread-safe)."""
    with _pool_lock:
        if _pool is None:
            raise RuntimeError("Instance pool not initialized")
        return _pool


def close_pool() -> None:
    """Close the global instance pool (thread-safe)."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.close()
            _pool = None

"""
Worker process for job execution.

Features:
- Configurable concurrency at runtime via shared state
- Graceful shutdown with signal handlers
- Per-tenant job isolation
- Redis-based state management with fallback to in-memory
"""

import asyncio
import json
import logging
import os
import signal
import socket
import time
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError

try:
    from redis.exceptions import RedisError
except ImportError:
    class RedisError(Exception):  # type: ignore[no-redef]
        """Placeholder when redis is not installed."""
        pass

from openlabels.exceptions import JobError
from openlabels.jobs.queue import JobQueue, dequeue_next_job
from openlabels.jobs.tasks.label import execute_label_task
from openlabels.jobs.tasks.label_sync import execute_label_sync_task
from openlabels.jobs.tasks.scan import execute_scan_task, run_shutdown_callbacks
from openlabels.server.config import get_settings
from openlabels.server.db import get_session_context, init_db

logger = logging.getLogger(__name__)

# Worker state configuration
WORKER_STATE_KEY_PREFIX = "openlabels:worker:state:"
WORKER_STATE_TTL_SECONDS = 60  # Workers should heartbeat to stay registered

# Global state manager instance
_state_manager: Optional["WorkerStateManager"] = None
_state_manager_lock = asyncio.Lock()


class InMemoryWorkerState:
    """
    Simple in-memory worker state storage with TTL support.

    Used as fallback when Redis is unavailable.
    """

    def __init__(self) -> None:
        self._states: dict[str, tuple[dict[str, Any], float]] = {}
        self._lock = asyncio.Lock()

    async def set_state(self, worker_id: str, state: dict[str, Any], ttl: int = WORKER_STATE_TTL_SECONDS) -> bool:
        """Set worker state with TTL."""
        async with self._lock:
            expires_at = time.time() + ttl
            self._states[worker_id] = (state, expires_at)
            return True

    async def get_state(self, worker_id: str) -> Optional[dict[str, Any]]:
        """Get worker state if not expired."""
        async with self._lock:
            if worker_id not in self._states:
                return None

            state, expires_at = self._states[worker_id]
            if time.time() > expires_at:
                del self._states[worker_id]
                return None

            return state

    async def get_all_workers(self) -> dict[str, dict[str, Any]]:
        """Get all non-expired worker states."""
        async with self._lock:
            now = time.time()
            # Clean up expired entries and return valid ones
            expired = [wid for wid, (_, exp) in self._states.items() if now > exp]
            for wid in expired:
                del self._states[wid]

            return {wid: state for wid, (state, _) in self._states.items()}

    async def delete_state(self, worker_id: str) -> bool:
        """Delete worker state."""
        async with self._lock:
            if worker_id in self._states:
                del self._states[worker_id]
                return True
            return False


class WorkerStateManager:
    """
    Redis-based worker state management with in-memory fallback.

    Provides distributed worker state storage that works across multiple machines.
    Falls back to in-memory storage if Redis is unavailable.

    Features:
    - TTL-based expiration (workers must heartbeat to stay registered)
    - Graceful fallback to in-memory if Redis unavailable
    - Atomic operations for state updates
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        key_prefix: str = WORKER_STATE_KEY_PREFIX,
        default_ttl: int = WORKER_STATE_TTL_SECONDS,
        connect_timeout: float = 5.0,
        socket_timeout: float = 5.0,
    ) -> None:
        self._redis_url = redis_url
        self._key_prefix = key_prefix
        self._default_ttl = default_ttl
        self._connect_timeout = connect_timeout
        self._socket_timeout = socket_timeout

        self._redis_client: Optional[Any] = None
        self._redis_connected = False
        self._memory_fallback = InMemoryWorkerState()

    def _make_key(self, worker_id: str) -> str:
        """Create Redis key for worker state."""
        return f"{self._key_prefix}{worker_id}"

    async def initialize(self) -> None:
        """Initialize Redis connection if configured."""
        if not self._redis_url:
            logger.info("No Redis URL configured - using in-memory worker state storage")
            return

        try:
            import redis.asyncio as redis

            self._redis_client = redis.from_url(
                self._redis_url,
                socket_connect_timeout=self._connect_timeout,
                socket_timeout=self._socket_timeout,
                decode_responses=True,
            )

            # Test connection
            await self._redis_client.ping()
            self._redis_connected = True
            logger.info(f"Worker state manager connected to Redis: {self._redis_url}")

        except ImportError:
            logger.warning(
                "redis package not installed - using in-memory worker state storage"
            )
        except (RedisError, ConnectionError, OSError, TimeoutError) as e:
            logger.warning(
                f"Redis connection failed: {type(e).__name__}: {e} - "
                "falling back to in-memory worker state storage"
            )

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis_client:
            await self._redis_client.close()
            self._redis_connected = False
            logger.info("Worker state manager Redis connection closed")

    async def set_state(
        self,
        worker_id: str,
        state: dict[str, Any],
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Set worker state in Redis with TTL.

        Args:
            worker_id: Unique identifier for the worker
            state: Worker state dictionary
            ttl: Time-to-live in seconds (default: WORKER_STATE_TTL_SECONDS)

        Returns:
            True if state was set successfully
        """
        ttl = ttl or self._default_ttl

        if self._redis_connected and self._redis_client:
            try:
                key = self._make_key(worker_id)
                value = json.dumps(state, default=str)
                await self._redis_client.setex(key, ttl, value)
                return True
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(
                    f"Redis set_state error for worker {worker_id}: "
                    f"{type(e).__name__}: {e} - falling back to in-memory"
                )
                # Fall through to in-memory fallback

        return await self._memory_fallback.set_state(worker_id, state, ttl)

    async def get_state(self, worker_id: str) -> Optional[dict[str, Any]]:
        """
        Get worker state from Redis.

        Args:
            worker_id: Unique identifier for the worker

        Returns:
            Worker state dictionary or None if not found/expired
        """
        if self._redis_connected and self._redis_client:
            try:
                key = self._make_key(worker_id)
                value = await self._redis_client.get(key)
                if value:
                    return json.loads(value)
                return None
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(
                    f"Redis get_state error for worker {worker_id}: "
                    f"{type(e).__name__}: {e} - falling back to in-memory"
                )
                # Fall through to in-memory fallback

        return await self._memory_fallback.get_state(worker_id)

    async def get_all_workers(self) -> dict[str, dict[str, Any]]:
        """
        Get all registered worker states.

        Returns:
            Dictionary mapping worker IDs to their states
        """
        if self._redis_connected and self._redis_client:
            try:
                workers: dict[str, dict[str, Any]] = {}
                pattern = f"{self._key_prefix}*"

                # Use SCAN to avoid blocking on large keyspaces
                cursor = 0
                while True:
                    cursor, keys = await self._redis_client.scan(
                        cursor=cursor,
                        match=pattern,
                        count=100,
                    )

                    if keys:
                        values = await self._redis_client.mget(*keys)
                        for key, value in zip(keys, values):
                            if value:
                                worker_id = key[len(self._key_prefix):]
                                try:
                                    workers[worker_id] = json.loads(value)
                                except (json.JSONDecodeError, TypeError):
                                    logger.debug(f"Invalid JSON for worker state key: {key}")

                    if cursor == 0:
                        break

                return workers
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(
                    f"Redis get_all_workers error: {type(e).__name__}: {e} - "
                    "falling back to in-memory"
                )
                # Fall through to in-memory fallback

        return await self._memory_fallback.get_all_workers()

    async def delete_state(self, worker_id: str) -> bool:
        """
        Delete worker state.

        Args:
            worker_id: Unique identifier for the worker

        Returns:
            True if state was deleted
        """
        if self._redis_connected and self._redis_client:
            try:
                key = self._make_key(worker_id)
                result = await self._redis_client.delete(key)
                return result > 0
            except (RedisError, ConnectionError, OSError, TimeoutError) as e:
                logger.warning(
                    f"Redis delete_state error for worker {worker_id}: "
                    f"{type(e).__name__}: {e} - falling back to in-memory"
                )
                # Fall through to in-memory fallback

        return await self._memory_fallback.delete_state(worker_id)

    @property
    def is_redis_connected(self) -> bool:
        """Check if Redis is connected."""
        return self._redis_connected


async def get_worker_state_manager() -> WorkerStateManager:
    """
    Get or create the global worker state manager instance.

    Uses lazy initialization and caches the instance.
    """
    global _state_manager

    async with _state_manager_lock:
        if _state_manager is None:
            settings = get_settings()
            redis_config = settings.redis

            _state_manager = WorkerStateManager(
                redis_url=redis_config.url if redis_config.enabled else None,
                key_prefix=WORKER_STATE_KEY_PREFIX,
                default_ttl=WORKER_STATE_TTL_SECONDS,
                connect_timeout=redis_config.connect_timeout,
                socket_timeout=redis_config.socket_timeout,
            )
            await _state_manager.initialize()

    return _state_manager


async def close_worker_state_manager() -> None:
    """Close the global worker state manager."""
    global _state_manager

    async with _state_manager_lock:
        if _state_manager:
            await _state_manager.close()
            _state_manager = None


class Worker:
    """
    Worker process that executes jobs from the queue.

    Supports runtime concurrency adjustment via Redis-based state management.
    State is automatically synced to Redis (or in-memory fallback) with TTL-based expiration.
    """

    def __init__(self, concurrency: Optional[int] = None) -> None:
        """
        Initialize the worker.

        Args:
            concurrency: Number of concurrent jobs (default: CPU count)
        """
        self.concurrency = concurrency or os.cpu_count() or 4
        self.target_concurrency = self.concurrency  # Desired concurrency (can change at runtime)
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid4().hex[:8]}"
        self.running = False
        self._current_jobs: set[str] = set()
        self._worker_tasks: list[asyncio.Task[None]] = []
        self._concurrency_check_interval = 5  # Check for concurrency changes every 5 seconds
        self._state_manager: Optional[WorkerStateManager] = None

    async def start(self) -> None:
        """Start the worker loop with dynamic concurrency support."""
        settings = get_settings()
        await init_db(
            settings.database.url,
            pool_size=settings.database.pool_size,
            max_overflow=settings.database.max_overflow,
        )

        # Initialize state manager (Redis-based with in-memory fallback)
        self._state_manager = await get_worker_state_manager()

        self.running = True
        logger.info(f"Worker {self.worker_id} started with concurrency={self.concurrency}")

        # Write initial state
        await self._state_manager.set_state(self.worker_id, {
            "worker_id": self.worker_id,
            "concurrency": self.concurrency,
            "target_concurrency": self.target_concurrency,
            "status": "running",
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
        })

        # Set up signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

        # Start initial worker tasks
        self._worker_tasks = [
            asyncio.create_task(self._worker_loop(i))
            for i in range(self.concurrency)
        ]

        # Start concurrency monitor (also handles heartbeat)
        monitor_task = asyncio.create_task(self._concurrency_monitor())

        # Start stuck job reclaimer
        reclaimer_task = asyncio.create_task(self._stuck_job_reclaimer())

        # Start job cleanup task (TTL expiration)
        cleanup_task = asyncio.create_task(self._job_cleanup_task())

        try:
            # Wait for all workers
            await asyncio.gather(
                *self._worker_tasks, monitor_task, reclaimer_task, cleanup_task,
                return_exceptions=True
            )
        finally:
            # Clean up state on shutdown
            if self._state_manager:
                await self._state_manager.delete_state(self.worker_id)

    def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info(f"Worker {self.worker_id} shutting down...")
        self.running = False

        # Schedule async state update for "stopping" status
        # The actual state deletion happens in start()'s finally block
        if self._state_manager:
            asyncio.create_task(self._update_stopping_state())

        # Release heavy resources (ML models, etc.) to free memory
        try:
            run_shutdown_callbacks()
        except (RuntimeError, OSError) as e:
            logger.warning(f"Error running shutdown callbacks: {e}")

    async def _update_stopping_state(self) -> None:
        """Update worker state to stopping (called during shutdown)."""
        if self._state_manager:
            try:
                await self._state_manager.set_state(self.worker_id, {
                    "worker_id": self.worker_id,
                    "concurrency": len([t for t in self._worker_tasks if not t.done()]),
                    "target_concurrency": self.target_concurrency,
                    "status": "stopping",
                    "pid": os.getpid(),
                    "hostname": socket.gethostname(),
                })
            except (RedisError, ConnectionError, OSError, RuntimeError) as e:
                logger.debug(f"Failed to update stopping state: {e}")

    async def _stuck_job_reclaimer(self) -> None:
        """
        Periodically reclaim stuck jobs that have been running for too long.

        This handles the case where a worker crashes after dequeuing a job
        but before completing or failing it.

        Uses an advisory lock so only one worker instance runs this per cycle.
        """
        from openlabels.server.advisory_lock import AdvisoryLockID, try_advisory_lock

        reclaim_interval = 300  # Check every 5 minutes

        while self.running:
            try:
                async with get_session_context() as session:
                    if not await try_advisory_lock(session, AdvisoryLockID.STUCK_JOB_RECLAIM):
                        logger.debug("Stuck job reclaimer: another instance is running, skipping")
                    else:
                        from sqlalchemy import select

                        from openlabels.server.models import Tenant

                        result = await session.execute(select(Tenant))
                        tenants = result.scalars().all()

                        total_reclaimed = 0
                        for tenant in tenants:
                            queue = JobQueue(session, tenant.id)
                            reclaimed = await queue.reclaim_stuck_jobs()
                            total_reclaimed += reclaimed

                        if total_reclaimed > 0:
                            logger.info(f"Reclaimed {total_reclaimed} stuck jobs")

            except (SQLAlchemyError, ConnectionError, OSError, RuntimeError) as e:
                logger.warning(f"Stuck job reclaimer error - jobs may remain stuck: {type(e).__name__}: {e}")

            await asyncio.sleep(reclaim_interval)

    async def _job_cleanup_task(self) -> None:
        """
        Periodically clean up expired jobs based on TTL configuration.

        Removes completed/failed/cancelled jobs that exceed their retention period.
        Runs once per hour to minimize database load.

        Uses an advisory lock so only one worker instance runs this per cycle.
        """
        from openlabels.server.advisory_lock import AdvisoryLockID, try_advisory_lock

        cleanup_interval = 3600  # Run once per hour

        while self.running:
            try:
                async with get_session_context() as session:
                    if not await try_advisory_lock(session, AdvisoryLockID.JOB_CLEANUP):
                        logger.debug("Job cleanup: another instance is running, skipping")
                    else:
                        from sqlalchemy import select

                        from openlabels.server.models import Tenant

                        result = await session.execute(select(Tenant))
                        tenants = result.scalars().all()

                        total_cleaned = 0
                        for tenant in tenants:
                            queue = JobQueue(session, tenant.id)
                            counts = await queue.cleanup_expired_jobs()
                            total_cleaned += sum(counts.values())

                        if total_cleaned > 0:
                            logger.info(f"Cleaned up {total_cleaned} expired jobs")

            except (SQLAlchemyError, ConnectionError, OSError, RuntimeError) as e:
                logger.warning(f"Job cleanup task error - expired jobs may accumulate: {type(e).__name__}: {e}")

            await asyncio.sleep(cleanup_interval)

    async def _concurrency_monitor(self) -> None:
        """
        Monitor for concurrency changes and maintain heartbeat via Redis state.

        Allows runtime adjustment of worker count without restart.
        Also serves as the heartbeat mechanism - TTL is refreshed on each update.
        """
        while self.running:
            try:
                if not self._state_manager:
                    await asyncio.sleep(self._concurrency_check_interval)
                    continue

                # Check for concurrency changes from external source
                state = await self._state_manager.get_state(self.worker_id)
                if state:
                    new_target = state.get("target_concurrency")

                    if new_target and new_target != self.target_concurrency:
                        logger.info(f"Concurrency change requested: {self.target_concurrency} -> {new_target}")
                        await self._adjust_concurrency(new_target)

                # Update state with current worker count (also refreshes TTL)
                await self._state_manager.set_state(self.worker_id, {
                    "worker_id": self.worker_id,
                    "concurrency": len([t for t in self._worker_tasks if not t.done()]),
                    "target_concurrency": self.target_concurrency,
                    "status": "running",
                    "pid": os.getpid(),
                    "hostname": socket.gethostname(),
                })

            except (RedisError, ConnectionError, OSError, RuntimeError) as e:
                # Non-critical but worth logging at info level for operational visibility
                logger.info(f"Concurrency monitor error - workers may not scale dynamically: {type(e).__name__}: {e}")

            await asyncio.sleep(self._concurrency_check_interval)

    async def _adjust_concurrency(self, new_concurrency: int) -> None:
        """
        Adjust the number of worker tasks at runtime.

        Args:
            new_concurrency: New target concurrency
        """
        new_concurrency = max(1, min(new_concurrency, 32))  # Clamp to 1-32
        old_concurrency = self.target_concurrency
        self.target_concurrency = new_concurrency

        current_workers = len([t for t in self._worker_tasks if not t.done()])

        if new_concurrency > current_workers:
            # Add workers
            for i in range(current_workers, new_concurrency):
                task = asyncio.create_task(self._worker_loop(i))
                self._worker_tasks.append(task)
                logger.info(f"Added worker {i} (concurrency now {i + 1})")

        elif new_concurrency < current_workers:
            # Remove workers by letting them exit naturally
            # They'll check target_concurrency and exit if over
            logger.info(f"Reducing workers from {current_workers} to {new_concurrency}")

        logger.info(f"Concurrency adjusted: {old_concurrency} -> {new_concurrency}")

    async def _worker_loop(self, worker_num: int) -> None:
        """
        Main worker loop for processing jobs.

        Args:
            worker_num: Worker number for logging
        """
        worker_tag = f"{self.worker_id}:{worker_num}"

        while self.running:
            # Check if this worker should exit due to concurrency reduction
            active_workers = len([t for t in self._worker_tasks if not t.done()])
            if worker_num >= self.target_concurrency and active_workers > self.target_concurrency:
                logger.info(f"Worker {worker_tag} exiting (concurrency reduced)")
                return

            try:
                async with get_session_context() as session:
                    job = await dequeue_next_job(session, worker_tag)

                    if job:
                        queue = JobQueue(session, job.tenant_id)
                        await self._execute_job(session, queue, job)

            except SQLAlchemyError as e:
                logger.error(
                    f"Worker {worker_tag} database error while polling for jobs: "
                    f"{type(e).__name__}: {e}"
                )
            except OSError as e:
                logger.error(
                    f"Worker {worker_tag} OS error (network/filesystem issue): "
                    f"{type(e).__name__}: {e}"
                )
            except asyncio.CancelledError:
                logger.info(f"Worker {worker_tag} task cancelled during shutdown")
                raise
            except RuntimeError as e:
                logger.error(
                    f"Worker {worker_tag} runtime error during job polling: "
                    f"{type(e).__name__}: {e}"
                )

            # Sleep between poll cycles
            await asyncio.sleep(1)

    async def _execute_job(self, session, queue: JobQueue, job) -> None:
        """
        Execute a single job.

        Args:
            session: Database session
            queue: Job queue instance
            job: Job to execute
        """
        logger.info(f"Executing job {job.id} ({job.task_type})")

        try:
            if job.task_type == "scan":
                result = await execute_scan_task(session, job.payload)
            elif job.task_type == "label":
                result = await execute_label_task(session, job.payload)
            elif job.task_type == "label_sync":
                result = await execute_label_sync_task(session, job.payload)
            elif job.task_type == "export":
                from openlabels.jobs.tasks.export import execute_export_task
                result = await execute_export_task(session, job.payload)
            else:
                raise JobError(
                    f"Unknown task type: {job.task_type}",
                    job_id=str(job.id),
                    job_type=job.task_type,
                    context="dispatching job to task handler",
                )

            await queue.complete(job.id, result)
            logger.info(f"Job {job.id} completed successfully")

        except JobError as e:
            # Domain-specific job error - log with full context
            logger.error(f"Job {job.id} ({job.task_type}) failed: {e}")
            await queue.fail(job.id, str(e))
        except SQLAlchemyError as e:
            # Database error during job execution
            error_msg = f"Database error during {job.task_type} task: {type(e).__name__}: {e}"
            logger.error(f"Job {job.id} failed with database error: {error_msg}")
            await queue.fail(job.id, error_msg)
        except PermissionError as e:
            # File/resource permission issue
            error_msg = f"Permission denied during {job.task_type} task: {e}"
            logger.error(f"Job {job.id} failed with permission error: {error_msg}")
            await queue.fail(job.id, error_msg)
        except FileNotFoundError as e:
            # Missing file/resource
            error_msg = f"File not found during {job.task_type} task: {e}"
            logger.error(f"Job {job.id} failed - file not found: {error_msg}")
            await queue.fail(job.id, error_msg)
        except OSError as e:
            # General OS/IO error
            error_msg = f"OS error during {job.task_type} task: {type(e).__name__}: {e}"
            logger.error(f"Job {job.id} failed with OS error: {error_msg}")
            await queue.fail(job.id, error_msg)
        except ValueError as e:
            # Invalid input/data
            error_msg = f"Invalid data in {job.task_type} task: {e}"
            logger.error(f"Job {job.id} failed with value error: {error_msg}")
            await queue.fail(job.id, error_msg)
        except asyncio.CancelledError:
            # Task cancelled - re-raise to allow graceful shutdown
            logger.warning(f"Job {job.id} cancelled during execution")
            await queue.fail(job.id, "Job cancelled during execution")
            raise
        except RuntimeError as e:
            # Catch-all for runtime issues
            error_msg = f"Runtime error in {job.task_type} task: {type(e).__name__}: {e}"
            logger.error(f"Job {job.id} failed with runtime error: {error_msg}")
            await queue.fail(job.id, error_msg)


def run_worker(concurrency: Optional[int] = None) -> None:
    """
    Run the worker process.

    Args:
        concurrency: Number of concurrent jobs
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    worker = Worker(concurrency=concurrency)
    asyncio.run(worker.start())

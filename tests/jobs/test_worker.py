"""
Comprehensive tests for the job worker process.

Tests focus on:
- Worker initialization and configuration
- Concurrency management
- Redis-based state management (with in-memory fallback)
- Job execution routing
- Graceful shutdown handling
"""

import sys
import os
import json

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch

from openlabels.jobs.worker import (
    Worker,
    WorkerStateManager,
    InMemoryWorkerState,
    get_worker_state_manager,
    close_worker_state_manager,
    WORKER_STATE_KEY_PREFIX,
    WORKER_STATE_TTL_SECONDS,
)


class TestInMemoryWorkerState:
    """Tests for InMemoryWorkerState class."""

    async def test_set_and_get_state(self):
        """Should set and retrieve worker state."""
        state = InMemoryWorkerState()
        worker_id = "test-worker-1"
        worker_state = {"concurrency": 4, "status": "running"}

        result = await state.set_state(worker_id, worker_state)
        assert result is True

        retrieved = await state.get_state(worker_id)
        assert retrieved == worker_state

    async def test_get_state_returns_none_for_missing(self):
        """Should return None for non-existent worker."""
        state = InMemoryWorkerState()
        result = await state.get_state("nonexistent-worker")
        assert result is None

    async def test_get_state_expires_after_ttl(self):
        """Should return None for expired state."""
        state = InMemoryWorkerState()
        worker_id = "test-worker-1"
        worker_state = {"status": "running"}

        # Set with very short TTL
        await state.set_state(worker_id, worker_state, ttl=0)

        # Should be expired immediately
        import time
        time.sleep(0.01)
        result = await state.get_state(worker_id)
        assert result is None

    async def test_get_all_workers(self):
        """Should return all non-expired worker states."""
        state = InMemoryWorkerState()

        await state.set_state("worker-1", {"status": "running"}, ttl=60)
        await state.set_state("worker-2", {"status": "running"}, ttl=60)

        workers = await state.get_all_workers()
        assert len(workers) == 2
        assert "worker-1" in workers
        assert "worker-2" in workers

    async def test_delete_state(self):
        """Should delete worker state."""
        state = InMemoryWorkerState()
        worker_id = "test-worker-1"

        await state.set_state(worker_id, {"status": "running"})
        result = await state.delete_state(worker_id)
        assert result is True

        retrieved = await state.get_state(worker_id)
        assert retrieved is None

    async def test_delete_nonexistent_returns_false(self):
        """Should return False when deleting non-existent worker."""
        state = InMemoryWorkerState()
        result = await state.delete_state("nonexistent")
        assert result is False


class TestWorkerStateManager:
    """Tests for WorkerStateManager class."""

    async def test_init_without_redis_uses_memory(self):
        """Should use in-memory storage when no Redis URL provided."""
        manager = WorkerStateManager(redis_url=None)
        await manager.initialize()

        assert manager.is_redis_connected is False

    async def test_set_and_get_state_in_memory(self):
        """Should work with in-memory fallback."""
        manager = WorkerStateManager(redis_url=None)
        await manager.initialize()

        worker_id = "test-worker"
        state = {"concurrency": 4, "status": "running"}

        result = await manager.set_state(worker_id, state)
        assert result is True

        retrieved = await manager.get_state(worker_id)
        assert retrieved == state

    async def test_get_all_workers_in_memory(self):
        """Should get all workers from in-memory storage."""
        manager = WorkerStateManager(redis_url=None)
        await manager.initialize()

        await manager.set_state("worker-1", {"status": "running"})
        await manager.set_state("worker-2", {"status": "running"})

        workers = await manager.get_all_workers()
        assert len(workers) == 2

    async def test_delete_state_in_memory(self):
        """Should delete state from in-memory storage."""
        manager = WorkerStateManager(redis_url=None)
        await manager.initialize()

        await manager.set_state("worker-1", {"status": "running"})
        result = await manager.delete_state("worker-1")
        assert result is True

        retrieved = await manager.get_state("worker-1")
        assert retrieved is None

    async def test_key_prefix_default(self):
        """Should use default key prefix."""
        manager = WorkerStateManager()
        assert manager._key_prefix == WORKER_STATE_KEY_PREFIX

    async def test_custom_key_prefix(self):
        """Should accept custom key prefix."""
        manager = WorkerStateManager(key_prefix="custom:prefix:")
        assert manager._key_prefix == "custom:prefix:"

    async def test_make_key(self):
        """Should create Redis key correctly."""
        manager = WorkerStateManager(key_prefix="test:")
        key = manager._make_key("worker-1")
        assert key == "test:worker-1"


class TestWorkerStateManagerWithMockedRedis:
    """Tests for WorkerStateManager with mocked Redis."""

    async def test_redis_connection_failure_falls_back_to_memory(self):
        """Should fall back to memory when Redis is unavailable."""
        manager = WorkerStateManager(redis_url="redis://nonexistent:6379")

        # Initialize will attempt Redis connection:
        # - If redis package is not installed, ImportError is caught -> memory fallback
        # - If redis package is installed, connection to nonexistent host fails -> memory fallback
        # Either way, the manager falls back to in-memory state storage.
        await manager.initialize()

        assert manager.is_redis_connected is False

        # Should still work with memory fallback
        result = await manager.set_state("worker-1", {"status": "running"})
        assert result is True

    async def test_redis_operation_failure_falls_back_to_memory(self):
        """Should fall back to memory on Redis operation failure."""
        manager = WorkerStateManager(redis_url="redis://localhost:6379")
        manager._redis_connected = True
        manager._redis_client = AsyncMock()
        manager._redis_client.get.side_effect = ConnectionError("Redis error")

        # Should fall back to memory and return None (not set in memory)
        result = await manager.get_state("worker-1")
        assert result is None


class TestWorkerInitialization:
    """Tests for Worker class initialization."""

    def test_init_with_default_concurrency(self):
        """Worker should initialize with CPU count as default concurrency."""
        with patch('os.cpu_count', return_value=8):
            worker = Worker()

        assert worker.concurrency == 8

    def test_init_with_custom_concurrency(self):
        """Worker should accept custom concurrency."""
        worker = Worker(concurrency=4)

        assert worker.concurrency == 4
        assert worker.target_concurrency == 4

    def test_init_with_none_cpu_count(self):
        """Worker should fall back to 4 if cpu_count returns None."""
        with patch('os.cpu_count', return_value=None):
            worker = Worker()

        assert worker.concurrency == 4

    def test_init_creates_unique_worker_id(self):
        """Each worker should have a unique ID."""
        worker1 = Worker()
        worker2 = Worker()

        # Worker IDs should be different
        assert worker1.worker_id != worker2.worker_id

    def test_init_sets_running_false(self):
        """Worker should not be running initially."""
        worker = Worker()

        assert worker.running is False

    def test_init_creates_empty_job_tracking(self):
        """Worker should initialize with empty job tracking."""
        worker = Worker()

        assert worker._current_jobs == set()
        assert worker._worker_tasks == []

    def test_init_state_manager_is_none(self):
        """Worker should initialize with None state manager."""
        worker = Worker()
        assert worker._state_manager is None


class TestWorkerConcurrencyAdjustment:
    """Tests for runtime concurrency adjustment."""

    async def test_adjust_concurrency_clamps_minimum(self):
        """Concurrency should not go below 1."""
        worker = Worker(concurrency=4)
        worker._worker_tasks = [MagicMock(done=lambda: False) for _ in range(4)]

        await worker._adjust_concurrency(0)

        assert worker.target_concurrency == 1

    async def test_adjust_concurrency_clamps_maximum(self):
        """Concurrency should not exceed 32."""
        worker = Worker(concurrency=4)
        worker._worker_tasks = [MagicMock(done=lambda: False) for _ in range(4)]

        await worker._adjust_concurrency(100)

        assert worker.target_concurrency == 32

    async def test_adjust_concurrency_adds_workers(self):
        """Should create new worker tasks when increasing concurrency."""
        worker = Worker(concurrency=2)
        worker.running = True
        worker._worker_tasks = []

        # Mock the worker tasks
        mock_task1 = MagicMock()
        mock_task1.done.return_value = False
        mock_task2 = MagicMock()
        mock_task2.done.return_value = False
        worker._worker_tasks = [mock_task1, mock_task2]

        # Patch create_task to track calls
        with patch('asyncio.create_task') as mock_create:
            mock_create.return_value = MagicMock(done=lambda: False)
            await worker._adjust_concurrency(4)

        # Should have created 2 new tasks (4 - 2 = 2)
        assert mock_create.call_count == 2

    async def test_adjust_concurrency_logs_reduction(self):
        """Should log when reducing concurrency."""
        worker = Worker(concurrency=4)

        mock_task = MagicMock()
        mock_task.done.return_value = False
        worker._worker_tasks = [mock_task for _ in range(4)]

        # Reduce concurrency - workers exit naturally
        await worker._adjust_concurrency(2)

        assert worker.target_concurrency == 2


class TestWorkerShutdown:
    """Tests for graceful shutdown handling."""

    def test_handle_shutdown_sets_running_false(self):
        """Shutdown handler should set running to False."""
        worker = Worker()
        worker.running = True
        worker._state_manager = None  # No state manager

        worker._handle_shutdown()

        assert worker.running is False

    async def test_handle_shutdown_schedules_state_update(self):
        """Shutdown handler should schedule async state update."""
        worker = Worker()
        worker.running = True
        worker._state_manager = AsyncMock()
        worker._update_stopping_state = AsyncMock()

        with patch('asyncio.create_task') as mock_create_task:
            worker._handle_shutdown()

        # Should have created a task to update stopping state
        mock_create_task.assert_called_once()

    async def test_update_stopping_state(self):
        """Should update worker state to stopping."""
        worker = Worker()
        worker._state_manager = AsyncMock()
        worker._worker_tasks = []

        await worker._update_stopping_state()

        worker._state_manager.set_state.assert_called_once()
        call_args = worker._state_manager.set_state.call_args
        assert call_args[0][0] == worker.worker_id
        assert call_args[0][1]["status"] == "stopping"


class TestWorkerJobExecution:
    """Tests for job execution routing."""

    @pytest.fixture
    def worker(self):
        """Create a worker instance."""
        return Worker(concurrency=1)

    async def test_execute_scan_job(self, worker):
        """Should route scan jobs to execute_scan_task."""
        mock_session = AsyncMock()
        mock_queue = MagicMock()
        mock_queue.complete = AsyncMock()
        mock_queue.fail = AsyncMock()

        mock_job = MagicMock()
        mock_job.id = uuid4()
        mock_job.task_type = "scan"
        mock_job.payload = {"scan_id": str(uuid4())}

        with patch('openlabels.jobs.worker.execute_scan_task', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = {"files_scanned": 10}
            await worker._execute_job(mock_session, mock_queue, mock_job)

        mock_scan.assert_called_once_with(mock_session, mock_job.payload)
        mock_queue.complete.assert_called_once()

    async def test_execute_label_job(self, worker):
        """Should route label jobs to execute_label_task."""
        mock_session = AsyncMock()
        mock_queue = MagicMock()
        mock_queue.complete = AsyncMock()
        mock_queue.fail = AsyncMock()

        mock_job = MagicMock()
        mock_job.id = uuid4()
        mock_job.task_type = "label"
        mock_job.payload = {"label_id": str(uuid4())}

        with patch('openlabels.jobs.worker.execute_label_task', new_callable=AsyncMock) as mock_label:
            mock_label.return_value = {"files_labeled": 5}
            await worker._execute_job(mock_session, mock_queue, mock_job)

        mock_label.assert_called_once_with(mock_session, mock_job.payload)
        mock_queue.complete.assert_called_once()

    async def test_execute_label_sync_job(self, worker):
        """Should route label_sync jobs to execute_label_sync_task."""
        mock_session = AsyncMock()
        mock_queue = MagicMock()
        mock_queue.complete = AsyncMock()
        mock_queue.fail = AsyncMock()

        mock_job = MagicMock()
        mock_job.id = uuid4()
        mock_job.task_type = "label_sync"
        mock_job.payload = {}

        with patch('openlabels.jobs.worker.execute_label_sync_task', new_callable=AsyncMock) as mock_sync:
            mock_sync.return_value = {"synced": True}
            await worker._execute_job(mock_session, mock_queue, mock_job)

        mock_sync.assert_called_once_with(mock_session, mock_job.payload)
        mock_queue.complete.assert_called_once()

    async def test_execute_unknown_task_type_fails(self, worker):
        """Unknown task type should fail the job."""
        mock_session = AsyncMock()
        mock_queue = MagicMock()
        mock_queue.complete = AsyncMock()
        mock_queue.fail = AsyncMock()

        mock_job = MagicMock()
        mock_job.id = uuid4()
        mock_job.task_type = "unknown_type"
        mock_job.payload = {}

        await worker._execute_job(mock_session, mock_queue, mock_job)

        mock_queue.fail.assert_called_once()
        # Check error message contains task type
        call_args = mock_queue.fail.call_args
        assert "unknown_type" in call_args[0][1]

    async def test_execute_job_handles_task_exception(self, worker):
        """Task exceptions should be caught and job marked failed."""
        mock_session = AsyncMock()
        mock_queue = MagicMock()
        mock_queue.complete = AsyncMock()
        mock_queue.fail = AsyncMock()

        mock_job = MagicMock()
        mock_job.id = uuid4()
        mock_job.task_type = "scan"
        mock_job.payload = {}

        with patch('openlabels.jobs.worker.execute_scan_task', new_callable=AsyncMock) as mock_scan:
            mock_scan.side_effect = RuntimeError("Scan failed: disk full")
            await worker._execute_job(mock_session, mock_queue, mock_job)

        mock_queue.fail.assert_called_once()
        mock_queue.complete.assert_not_called()


class TestWorkerLoop:
    """Tests for worker loop behavior."""

    async def test_worker_loop_exits_on_concurrency_reduction(self):
        """Worker should exit when its number exceeds target concurrency."""
        worker = Worker(concurrency=4)
        worker.running = True
        worker.target_concurrency = 2

        # Create mock tasks (4 of them, not done)
        worker._worker_tasks = [MagicMock(done=lambda: False) for _ in range(4)]

        # Worker 3 should exit (0-indexed, target is 2, so workers 0,1 stay, 2,3 exit)
        # We need to mock the get_session_context to avoid actual DB connection
        with patch('openlabels.jobs.worker.get_session_context') as mock_ctx:
            # Make the context manager work
            mock_ctx.return_value.__aenter__ = AsyncMock()
            mock_ctx.return_value.__aexit__ = AsyncMock()

            # Run the worker loop for worker_num=3
            await worker._worker_loop(3)

        # Worker 3 exited immediately because worker_num (3) >= target_concurrency (2)
        # and active_workers (4) > target_concurrency (2).
        # The loop returned without ever trying to get a database session.
        mock_ctx.assert_not_called()



class TestWorkerEdgeCases:
    """Edge case tests for worker robustness."""

    def test_worker_id_includes_hostname(self):
        """Worker ID should include hostname for identification."""
        import socket

        worker = Worker()
        hostname = socket.gethostname()

        assert hostname in worker.worker_id

    def test_worker_id_includes_pid(self):
        """Worker ID should include process ID."""
        worker = Worker()
        pid = str(os.getpid())

        assert pid in worker.worker_id

    async def test_concurrency_monitor_handles_errors(self):
        """Concurrency monitor should handle state manager errors gracefully."""
        worker = Worker()
        worker.running = True
        worker._state_manager = AsyncMock()
        worker._state_manager.get_state.side_effect = Exception("Redis error")
        worker._state_manager.set_state.side_effect = Exception("Redis error")

        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            # Run one iteration then exit
            worker.running = False
            await worker._concurrency_monitor()

        # Should not raise, just continue

    async def test_concurrency_monitor_handles_missing_state_manager(self):
        """Concurrency monitor should handle missing state manager."""
        worker = Worker()
        worker.running = True
        worker._state_manager = None

        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            # Run one iteration then exit
            worker.running = False
            await worker._concurrency_monitor()

        # Should not raise

    def test_worker_accepts_zero_concurrency(self):
        """Worker should handle 0 concurrency by using CPU count."""
        with patch('os.cpu_count', return_value=4):
            worker = Worker(concurrency=0)

        # 0 is falsy, so should fall back to CPU count
        assert worker.concurrency == 4



class TestGetWorkerStateManager:
    """Tests for get_worker_state_manager function."""

    async def test_returns_state_manager(self):
        """Should return a WorkerStateManager instance."""
        # Reset global state
        await close_worker_state_manager()

        with patch('openlabels.jobs.worker.get_settings') as mock_settings:
            mock_settings.return_value.redis.enabled = False
            mock_settings.return_value.redis.url = None
            mock_settings.return_value.redis.connect_timeout = 5.0
            mock_settings.return_value.redis.socket_timeout = 5.0

            manager = await get_worker_state_manager()

        assert isinstance(manager, WorkerStateManager)

        # Clean up
        await close_worker_state_manager()

    async def test_returns_same_instance(self):
        """Should return the same instance on multiple calls."""
        await close_worker_state_manager()

        with patch('openlabels.jobs.worker.get_settings') as mock_settings:
            mock_settings.return_value.redis.enabled = False
            mock_settings.return_value.redis.url = None
            mock_settings.return_value.redis.connect_timeout = 5.0
            mock_settings.return_value.redis.socket_timeout = 5.0

            manager1 = await get_worker_state_manager()
            manager2 = await get_worker_state_manager()

        assert manager1 is manager2

        # Clean up
        await close_worker_state_manager()

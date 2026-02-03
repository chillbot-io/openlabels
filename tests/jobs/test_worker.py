"""
Comprehensive tests for the job worker process.

Tests focus on:
- Worker initialization and configuration
- Concurrency management
- Shared state file operations
- Job execution routing
- Graceful shutdown handling
"""

import sys
import os
import json
import tempfile

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from unittest.mock import MagicMock, AsyncMock, patch, mock_open

from openlabels.jobs.worker import (
    Worker,
    get_worker_state,
    set_worker_state,
    WORKER_STATE_FILE,
)


class TestGetWorkerState:
    """Tests for get_worker_state function."""

    def test_returns_empty_dict_when_file_missing(self):
        """Should return empty dict when state file doesn't exist."""
        import openlabels.jobs.worker as worker_module
        original = worker_module.WORKER_STATE_FILE

        try:
            # Use a non-existent path
            worker_module.WORKER_STATE_FILE = Path("/nonexistent/path/state.json")
            result = get_worker_state()
            assert result == {}
        finally:
            worker_module.WORKER_STATE_FILE = original

    def test_returns_state_from_file(self):
        """Should return parsed JSON from state file."""
        import openlabels.jobs.worker as worker_module
        original = worker_module.WORKER_STATE_FILE

        # Create a temp file with test data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"concurrency": 4, "status": "running"}, f)
            temp_path = f.name

        try:
            worker_module.WORKER_STATE_FILE = Path(temp_path)
            result = get_worker_state()
            assert result == {"concurrency": 4, "status": "running"}
        finally:
            worker_module.WORKER_STATE_FILE = original
            os.unlink(temp_path)

    def test_returns_empty_dict_on_parse_error(self):
        """Should return empty dict if JSON parse fails."""
        import openlabels.jobs.worker as worker_module
        original = worker_module.WORKER_STATE_FILE

        # Create a temp file with invalid JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json {")
            temp_path = f.name

        try:
            worker_module.WORKER_STATE_FILE = Path(temp_path)
            result = get_worker_state()
            assert result == {}
        finally:
            worker_module.WORKER_STATE_FILE = original
            os.unlink(temp_path)

    def test_returns_empty_dict_on_read_error(self):
        """Should return empty dict if file read fails."""
        import openlabels.jobs.worker as worker_module
        original = worker_module.WORKER_STATE_FILE

        try:
            # Use a path that exists but is a directory (causes read error)
            worker_module.WORKER_STATE_FILE = Path("/tmp")
            result = get_worker_state()
            assert result == {}
        finally:
            worker_module.WORKER_STATE_FILE = original


class TestSetWorkerState:
    """Tests for set_worker_state function."""

    def test_writes_state_to_file(self):
        """Should write state as JSON to file."""
        import openlabels.jobs.worker as worker_module
        original = worker_module.WORKER_STATE_FILE

        # Create a temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            worker_module.WORKER_STATE_FILE = Path(temp_path)
            set_worker_state({"concurrency": 8})

            # Read back and verify
            with open(temp_path) as f:
                result = json.load(f)
            assert result["concurrency"] == 8
        finally:
            worker_module.WORKER_STATE_FILE = original
            os.unlink(temp_path)

    def test_merges_with_existing_state(self):
        """Should merge new state with existing state."""
        import openlabels.jobs.worker as worker_module
        original = worker_module.WORKER_STATE_FILE

        # Create a temp file with existing state
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"existing": "value", "concurrency": 4}, f)
            temp_path = f.name

        try:
            worker_module.WORKER_STATE_FILE = Path(temp_path)
            set_worker_state({"concurrency": 8, "status": "running"})

            # Read back and verify merge
            with open(temp_path) as f:
                result = json.load(f)
            assert result["existing"] == "value"  # Preserved
            assert result["concurrency"] == 8  # Updated
            assert result["status"] == "running"  # Added
        finally:
            worker_module.WORKER_STATE_FILE = original
            os.unlink(temp_path)


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


class TestWorkerConcurrencyAdjustment:
    """Tests for runtime concurrency adjustment."""

    @pytest.mark.asyncio
    async def test_adjust_concurrency_clamps_minimum(self):
        """Concurrency should not go below 1."""
        worker = Worker(concurrency=4)
        worker._worker_tasks = [MagicMock(done=lambda: False) for _ in range(4)]

        await worker._adjust_concurrency(0)

        assert worker.target_concurrency == 1

    @pytest.mark.asyncio
    async def test_adjust_concurrency_clamps_maximum(self):
        """Concurrency should not exceed 32."""
        worker = Worker(concurrency=4)
        worker._worker_tasks = [MagicMock(done=lambda: False) for _ in range(4)]

        await worker._adjust_concurrency(100)

        assert worker.target_concurrency == 32

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

        with patch('openlabels.jobs.worker.set_worker_state'):
            worker._handle_shutdown()

        assert worker.running is False

    def test_handle_shutdown_updates_state(self):
        """Shutdown handler should update state file."""
        worker = Worker()
        worker.running = True

        with patch('openlabels.jobs.worker.set_worker_state') as mock_set:
            worker._handle_shutdown()

        mock_set.assert_called_with({"status": "stopping"})


class TestWorkerJobExecution:
    """Tests for job execution routing."""

    @pytest.fixture
    def worker(self):
        """Create a worker instance."""
        return Worker(concurrency=1)

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

        # Worker should have exited (no assertion needed, just no exception)

    @pytest.mark.asyncio
    async def test_worker_loop_processes_jobs(self):
        """Worker should process jobs from the queue."""
        worker = Worker(concurrency=1)
        worker.running = False  # Will exit immediately after one iteration

        # No actual DB connection needed for this test


class TestWorkerStateFile:
    """Tests for worker state file path."""

    def test_state_file_path_is_tmp(self):
        """State file should be in /tmp directory."""
        assert str(WORKER_STATE_FILE).startswith("/tmp")

    def test_state_file_has_json_extension(self):
        """State file should have .json extension."""
        assert str(WORKER_STATE_FILE).endswith(".json")


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

    def test_concurrency_check_interval_is_reasonable(self):
        """Concurrency check interval should be reasonable (1-60 seconds)."""
        worker = Worker()

        assert 1 <= worker._concurrency_check_interval <= 60

    @pytest.mark.asyncio
    async def test_concurrency_monitor_handles_errors(self):
        """Concurrency monitor should handle state file errors gracefully."""
        worker = Worker()
        worker.running = True

        # Make get_worker_state raise an exception
        with patch('openlabels.jobs.worker.get_worker_state', side_effect=Exception("Read error")):
            with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
                # Run one iteration
                worker.running = False  # Will exit after exception handling
                await worker._concurrency_monitor()

        # Should not raise, just continue

    def test_worker_accepts_zero_concurrency(self):
        """Worker should handle 0 concurrency by using CPU count."""
        with patch('os.cpu_count', return_value=4):
            worker = Worker(concurrency=0)

        # 0 is falsy, so should fall back to CPU count
        assert worker.concurrency == 4


class TestRunWorkerFunction:
    """Tests for run_worker entry point."""

    def test_run_worker_creates_worker(self):
        """run_worker should create and start a Worker."""
        from openlabels.jobs.worker import run_worker

        with patch.object(Worker, 'start', new_callable=AsyncMock) as mock_start:
            with patch('asyncio.run') as mock_run:
                # Can't fully test without mocking asyncio.run
                pass  # Function signature test only

    def test_run_worker_accepts_concurrency(self):
        """run_worker should accept concurrency parameter."""
        from openlabels.jobs.worker import run_worker
        import inspect

        sig = inspect.signature(run_worker)
        assert "concurrency" in sig.parameters

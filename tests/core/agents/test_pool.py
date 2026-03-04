"""
Tests for the agent pool manager (openlabels.core.agents.pool).

Covers:
- AgentPoolConfig auto-detection
- AgentPool lifecycle (creation, start, stop, context manager)
- Pool state transitions
- Work submission and result collection
- PoolStats tracking
- Health check
- ScanOrchestrator path validation enforcement
- ScanOrchestrator error handling
- Concurrency safety (state lock)
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.core.agents.pool import (
    _MAX_FILE_BYTES,
    AgentPool,
    AgentPoolConfig,
    FileResult,
    PoolState,
    PoolStats,
    ScanOrchestrator,
)
from openlabels.core.agents.worker import (
    AgentResult,
    EntityMatch,
    OptimizationBackend,
    WorkItem,
)
from openlabels.core.path_validation import PathValidationError

# ── Helpers ──────────────────────────────────────────────────────────


def _make_agent_result(
    work_id: str = "test:0",
    file_path: str = "/tmp/test.txt",
    chunk_index: int = 0,
    entities: list[EntityMatch] | None = None,
    processing_time_ms: float = 10.0,
    agent_id: int = 0,
    error: str | None = None,
) -> AgentResult:
    return AgentResult(
        work_id=work_id,
        file_path=file_path,
        chunk_index=chunk_index,
        entities=entities or [],
        processing_time_ms=processing_time_ms,
        agent_id=agent_id,
        error=error,
    )


def _make_work_item(
    id: str = "test:0",
    file_path: str = "/tmp/test.txt",
    text: str = "some test text",
    chunk_index: int = 0,
    total_chunks: int = 1,
) -> WorkItem:
    return WorkItem(
        id=id,
        file_path=file_path,
        text=text,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
    )


# ── AgentPoolConfig tests ───────────────────────────────────────────


class TestAgentPoolConfig:
    """Test configuration and auto-detection logic."""

    def test_default_config(self):
        config = AgentPoolConfig()
        assert config.num_agents == 0
        assert config.input_queue_size == 100
        assert config.output_queue_size == 1000
        assert config.backend == OptimizationBackend.PYTORCH
        assert config.device == "cpu"
        assert config.agent_startup_timeout == 60.0
        assert config.shutdown_timeout == 30.0

    def test_custom_config(self):
        config = AgentPoolConfig(
            num_agents=4,
            input_queue_size=50,
            backend=OptimizationBackend.ONNX,
            device="cuda",
        )
        assert config.num_agents == 4
        assert config.input_queue_size == 50
        assert config.backend == OptimizationBackend.ONNX
        assert config.device == "cuda"

    @patch("openlabels.core.agents.pool.psutil")
    def test_auto_detect_agents_returns_positive(self, mock_psutil):
        mock_psutil.cpu_count.return_value = 8
        mock_mem = MagicMock()
        mock_mem.available = 16 * 1024 * 1024 * 1024  # 16 GB
        mock_psutil.virtual_memory.return_value = mock_mem

        config = AgentPoolConfig()
        count = config.auto_detect_agents()
        assert count >= 1

    @patch("openlabels.core.agents.pool.psutil")
    def test_auto_detect_agents_minimum_one(self, mock_psutil):
        """Even with minimal resources, at least 1 agent is returned."""
        mock_psutil.cpu_count.return_value = 1
        mock_mem = MagicMock()
        mock_mem.available = 2 * 1024 * 1024 * 1024  # 2 GB (just above MIN_SYSTEM_MEMORY_MB)
        mock_psutil.virtual_memory.return_value = mock_mem

        config = AgentPoolConfig()
        count = config.auto_detect_agents()
        assert count >= 1

    @patch("openlabels.core.agents.pool.psutil")
    def test_auto_detect_agents_fallback_on_error(self, mock_psutil):
        """CPU count falls back to os.cpu_count() on psutil failure."""
        mock_psutil.cpu_count.side_effect = RuntimeError("no cpus")
        mock_mem = MagicMock()
        mock_mem.available = 16 * 1024 * 1024 * 1024
        mock_psutil.virtual_memory.return_value = mock_mem

        config = AgentPoolConfig()
        count = config.auto_detect_agents()
        assert count >= 1

    @patch("openlabels.core.agents.pool.psutil")
    def test_auto_detect_memory_fallback_on_error(self, mock_psutil):
        """Memory detection falls back to CPU count on psutil failure."""
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.virtual_memory.side_effect = OSError("no memory info")

        config = AgentPoolConfig()
        count = config.auto_detect_agents()
        assert count >= 1


# ── PoolStats tests ──────────────────────────────────────────────────


class TestPoolStats:
    """Test runtime statistics tracking."""

    def test_initial_stats(self):
        stats = PoolStats()
        assert stats.items_submitted == 0
        assert stats.items_completed == 0
        assert stats.items_failed == 0
        assert stats.items_pending == 0
        assert stats.avg_processing_ms == 0.0

    def test_items_pending(self):
        stats = PoolStats()
        stats.items_submitted = 10
        stats.items_completed = 3
        stats.items_failed = 2
        assert stats.items_pending == 5

    def test_avg_processing_ms(self):
        stats = PoolStats()
        stats.items_completed = 4
        stats.total_processing_ms = 100.0
        assert stats.avg_processing_ms == 25.0

    def test_avg_processing_ms_zero_completed(self):
        stats = PoolStats()
        assert stats.avg_processing_ms == 0.0

    def test_throughput_per_second(self):
        stats = PoolStats()
        stats.start_time = time.time() - 10.0
        stats.items_completed = 50
        throughput = stats.throughput_per_second
        assert 4.0 <= throughput <= 6.0  # ~5 per second

    def test_throughput_zero_elapsed(self):
        stats = PoolStats()
        stats.start_time = time.time()
        assert stats.throughput_per_second == 0.0


# ── FileResult tests ─────────────────────────────────────────────────


class TestFileResult:
    """Test the FileResult data class."""

    def test_has_errors_false(self):
        result = FileResult(
            file_path="/tmp/test.txt",
            entity_counts={"SSN": 1},
            total_entities=1,
            total_processing_ms=10.0,
            chunk_count=1,
            errors=[],
        )
        assert not result.has_errors

    def test_has_errors_true(self):
        result = FileResult(
            file_path="/tmp/test.txt",
            entity_counts={},
            total_entities=0,
            total_processing_ms=10.0,
            chunk_count=1,
            errors=["Something went wrong"],
        )
        assert result.has_errors


# ── AgentPool lifecycle tests ────────────────────────────────────────


class TestAgentPoolLifecycle:
    """Test pool creation, start, and stop."""

    def test_pool_initial_state(self):
        pool = AgentPool(AgentPoolConfig(num_agents=2))
        assert pool.state == PoolState.INITIALIZING
        assert pool.num_agents == 2

    def test_pool_auto_detect_agents(self):
        """Pool with num_agents=0 auto-detects agent count."""
        pool = AgentPool(AgentPoolConfig(num_agents=0))
        assert pool.num_agents >= 1

    @pytest.mark.asyncio
    async def test_pool_start_and_stop(self):
        """Pool transitions through INITIALIZING -> RUNNING -> STOPPED."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            pool = AgentPool(AgentPoolConfig(num_agents=1))
            assert pool.state == PoolState.INITIALIZING

            await pool.start()
            assert pool.state == PoolState.RUNNING

            await pool.stop(wait=False)
            assert pool.state == PoolState.STOPPED

    @pytest.mark.asyncio
    async def test_pool_start_twice_raises(self):
        """Starting a running pool raises RuntimeError."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            pool = AgentPool(AgentPoolConfig(num_agents=1))
            await pool.start()

            with pytest.raises(RuntimeError, match="Cannot start pool"):
                await pool.start()

            await pool.stop(wait=False)

    @pytest.mark.asyncio
    async def test_pool_stop_idempotent(self):
        """Stopping an already stopped pool is a no-op."""
        pool = AgentPool(AgentPoolConfig(num_agents=1))
        pool._state = PoolState.STOPPED
        await pool.stop()  # Should not raise
        assert pool.state == PoolState.STOPPED

    @pytest.mark.asyncio
    async def test_pool_context_manager(self):
        """Pool can be used as async context manager."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            config = AgentPoolConfig(num_agents=1)
            async with AgentPool(config) as pool:
                assert pool.state == PoolState.RUNNING

            assert pool.state == PoolState.STOPPED

    @pytest.mark.asyncio
    async def test_pool_context_manager_exception(self):
        """On exception, pool stops without waiting (wait=False)."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            config = AgentPoolConfig(num_agents=1)
            with pytest.raises(ValueError, match="test error"):
                async with AgentPool(config) as pool:
                    raise ValueError("test error")

            assert pool.state == PoolState.STOPPED

    @pytest.mark.asyncio
    async def test_pool_graceful_shutdown(self):
        """Graceful shutdown sends poison pills and joins processes."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = False  # Process exits quickly
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            pool = AgentPool(AgentPoolConfig(num_agents=2))
            await pool.start()
            await pool.stop(wait=True)

            assert pool.state == PoolState.STOPPED
            # Processes should have been joined
            assert mock_proc.join.called

    @pytest.mark.asyncio
    async def test_pool_force_terminate_on_timeout(self):
        """Processes that don't exit on join are force-terminated."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True  # Never exits
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            pool = AgentPool(AgentPoolConfig(num_agents=1, shutdown_timeout=0.1))
            await pool.start()
            await pool.stop(wait=True)

            assert mock_proc.terminate.called


# ── AgentPool submission and results tests ───────────────────────────


class TestAgentPoolSubmission:
    """Test work submission and result collection."""

    @pytest.mark.asyncio
    async def test_submit_in_wrong_state_raises(self):
        """Submitting work when not RUNNING raises RuntimeError."""
        pool = AgentPool(AgentPoolConfig(num_agents=1))
        item = _make_work_item()
        with pytest.raises(RuntimeError, match="Cannot submit work"):
            await pool.submit(item)

    @pytest.mark.asyncio
    async def test_submit_updates_stats(self):
        """Submitting work increments items_submitted counter."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            pool = AgentPool(AgentPoolConfig(num_agents=1))
            await pool.start()

            item = _make_work_item()
            await pool.submit(item)
            assert pool.stats.items_submitted == 1

            await pool.stop(wait=False)

    @pytest.mark.asyncio
    async def test_submit_batch(self):
        """submit_batch submits all items."""
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            pool = AgentPool(AgentPoolConfig(num_agents=1))
            await pool.start()

            items = [_make_work_item(id=f"test:{i}") for i in range(5)]
            await pool.submit_batch(items)
            assert pool.stats.items_submitted == 5

            await pool.stop(wait=False)


# ── AgentPool health check tests ────────────────────────────────────


class TestAgentPoolHealthCheck:
    """Test health check reporting."""

    def test_health_check_initializing(self):
        pool = AgentPool(AgentPoolConfig(num_agents=2))
        health = pool.health_check()
        assert health["state"] == "initializing"
        assert health["agents_total"] == 2
        assert health["agents_alive"] == 0

    @pytest.mark.asyncio
    async def test_health_check_running(self):
        with patch("openlabels.core.agents.pool.mp.Process") as MockProcess:
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_proc.pid = 12345
            MockProcess.return_value = mock_proc

            pool = AgentPool(AgentPoolConfig(num_agents=2))
            await pool.start()

            health = pool.health_check()
            assert health["state"] == "running"
            assert health["agents_alive"] == 2

            await pool.stop(wait=False)


# ── ScanOrchestrator path validation tests ───────────────────────────


class TestScanOrchestratorPathValidation:
    """Test that file read operations enforce path validation."""

    @pytest.mark.asyncio
    async def test_extract_legacy_validates_path(self):
        """Legacy extraction path must call validate_path before reading."""
        orchestrator = ScanOrchestrator()

        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()

        mock_chunker = MagicMock()
        mock_chunk = MagicMock()
        mock_chunk.text = "test text"
        mock_chunker.chunk.return_value = [mock_chunk]

        mock_extract = MagicMock()
        mock_result = MagicMock()
        mock_result.text = "test text"
        mock_extract.return_value = mock_result

        with patch("openlabels.core.agents.pool.validate_path") as mock_validate, \
             patch("openlabels.core.agents.pool.os.path.getsize", return_value=100), \
             patch("builtins.open", MagicMock()):
            mock_validate.return_value = "/safe/path.txt"

            await orchestrator._extract_legacy(
                "/safe/path.txt", mock_pool, mock_chunker, mock_extract
            )

            mock_validate.assert_called_once_with(
                "/safe/path.txt", require_exists=True
            )

    @pytest.mark.asyncio
    async def test_extract_legacy_rejects_traversal(self):
        """Legacy extraction rejects path traversal attempts."""
        orchestrator = ScanOrchestrator()

        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()
        mock_chunker = MagicMock()
        mock_extract = MagicMock()

        with patch(
            "openlabels.core.agents.pool.validate_path",
            side_effect=PathValidationError("Path traversal is not allowed"),
        ):
            # The error propagates (caught by _extract_and_submit's
            # except clause as a ValueError subclass)
            with pytest.raises(PathValidationError):
                await orchestrator._extract_legacy(
                    "/data/../etc/passwd", mock_pool, mock_chunker, mock_extract
                )

    @pytest.mark.asyncio
    async def test_extract_legacy_rejects_system_path(self):
        """Legacy extraction rejects system paths."""
        orchestrator = ScanOrchestrator()

        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()
        mock_chunker = MagicMock()
        mock_extract = MagicMock()

        with patch(
            "openlabels.core.agents.pool.validate_path",
            side_effect=PathValidationError("Access to system directories is not allowed"),
        ):
            with pytest.raises(PathValidationError):
                await orchestrator._extract_legacy(
                    "/etc/passwd", mock_pool, mock_chunker, mock_extract
                )

    @pytest.mark.asyncio
    async def test_extract_unified_validates_path_when_no_adapter(self):
        """Unified extraction path validates when falling back to direct file read."""
        orchestrator = ScanOrchestrator()

        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()

        mock_chunker = MagicMock()
        mock_chunk = MagicMock()
        mock_chunk.text = "test text"
        mock_chunker.chunk.return_value = [mock_chunk]

        mock_extract = MagicMock()
        mock_result = MagicMock()
        mock_result.text = "test text"
        mock_extract.return_value = mock_result

        file_info = MagicMock()
        file_info.path = "/safe/test.txt"
        file_info.exposure = MagicMock()
        file_info.exposure.value = "PRIVATE"
        file_info.owner = "alice"
        file_info.permissions = None
        file_info.adapter = "filesystem"
        file_info.item_id = None

        with patch("openlabels.core.agents.pool.validate_path") as mock_validate, \
             patch("openlabels.core.agents.pool.os.path.getsize", return_value=100), \
             patch("builtins.open", MagicMock()):
            mock_validate.return_value = "/safe/test.txt"

            await orchestrator._extract_unified(
                file_info, mock_pool, mock_chunker, mock_extract
            )

            mock_validate.assert_called_once_with(
                "/safe/test.txt", require_exists=True
            )

    @pytest.mark.asyncio
    async def test_extract_unified_rejects_traversal_no_adapter(self):
        """Unified extraction rejects path traversal when no adapter."""
        orchestrator = ScanOrchestrator()

        mock_pool = MagicMock()
        mock_chunker = MagicMock()
        mock_extract = MagicMock()

        file_info = MagicMock()
        file_info.path = "/data/../etc/shadow"
        file_info.exposure = MagicMock()
        file_info.exposure.value = "PRIVATE"
        file_info.owner = "alice"
        file_info.permissions = None
        file_info.adapter = "filesystem"
        file_info.item_id = None

        with patch(
            "openlabels.core.agents.pool.validate_path",
            side_effect=PathValidationError("Path traversal is not allowed"),
        ):
            with pytest.raises(PathValidationError):
                await orchestrator._extract_unified(
                    file_info, mock_pool, mock_chunker, mock_extract
                )


# ── ScanOrchestrator error handling tests ────────────────────────────


class TestScanOrchestratorErrorHandling:
    """Test error handling in the orchestrator pipeline."""

    @pytest.mark.asyncio
    async def test_extract_and_submit_handles_extraction_error(self):
        """Errors during extraction increment error counter."""
        orchestrator = ScanOrchestrator()
        orchestrator._extract_queue = asyncio.Queue()
        await orchestrator._extract_queue.put("/tmp/bad_file.txt")
        await orchestrator._extract_queue.put(None)  # sentinel

        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()

        with patch("openlabels.core.agents.pool.validate_path", side_effect=OSError("no file")):
            with patch("openlabels.core.extractors.extract_text"):
                with patch("openlabels.core.pipeline.chunking.TextChunker"):
                    await orchestrator._extract_and_submit(mock_pool)

        assert orchestrator.stats["errors"] == 1

    @pytest.mark.asyncio
    async def test_extract_and_submit_handles_value_error(self):
        """ValueError during extraction (e.g. path validation) increments error counter."""
        orchestrator = ScanOrchestrator()
        orchestrator._extract_queue = asyncio.Queue()
        await orchestrator._extract_queue.put("/etc/shadow")
        await orchestrator._extract_queue.put(None)

        mock_pool = MagicMock()

        with patch(
            "openlabels.core.agents.pool.validate_path",
            side_effect=PathValidationError("blocked"),
        ):
            with patch("openlabels.core.extractors.extract_text"):
                with patch("openlabels.core.pipeline.chunking.TextChunker"):
                    await orchestrator._extract_and_submit(mock_pool)

        # PathValidationError is a ValueError subclass, caught by the handler
        assert orchestrator.stats["errors"] == 1

    @pytest.mark.asyncio
    async def test_extract_legacy_skips_oversized_file(self):
        """Files exceeding _MAX_FILE_BYTES are skipped."""
        orchestrator = ScanOrchestrator()

        mock_pool = MagicMock()
        mock_pool.submit = AsyncMock()
        mock_chunker = MagicMock()
        mock_extract = MagicMock()

        with patch("openlabels.core.agents.pool.validate_path", return_value="/tmp/big.bin"), \
             patch("openlabels.core.agents.pool.os.path.getsize", return_value=_MAX_FILE_BYTES + 1):
            await orchestrator._extract_legacy(
                "/tmp/big.bin", mock_pool, mock_chunker, mock_extract
            )

        # Should not have submitted any work
        mock_pool.submit.assert_not_called()

    @pytest.mark.asyncio
    async def test_walk_files_legacy_nonexistent_path(self):
        """Walking a nonexistent directory logs error and returns."""
        orchestrator = ScanOrchestrator()
        await orchestrator._walk_files_legacy("/nonexistent/path/xyz", True, None)
        # Should complete without error; nothing queued
        assert orchestrator._extract_queue.empty()

    @pytest.mark.asyncio
    async def test_persist_batch_handler_error(self):
        """Handler errors are caught and logged."""
        async def failing_handler(results):
            raise ConnectionError("DB down")

        orchestrator = ScanOrchestrator(result_handler=failing_handler)
        file_result = FileResult(
            file_path="/tmp/test.txt",
            entity_counts={},
            total_entities=0,
            total_processing_ms=10.0,
            chunk_count=1,
            errors=[],
        )

        # Should not raise
        await orchestrator._persist_batch([file_result])


# ── ScanOrchestrator concurrency tests ───────────────────────────────


class TestScanOrchestratorConcurrency:
    """Test concurrent access to shared state."""

    @pytest.mark.asyncio
    async def test_state_lock_protects_file_chunks(self):
        """Multiple concurrent updates to _file_chunks are serialized."""
        orchestrator = ScanOrchestrator()

        async def update_chunks(file_id: int):
            async with orchestrator._state_lock:
                orchestrator._file_chunks[f"/tmp/file{file_id}.txt"] = file_id
                await asyncio.sleep(0.001)

        await asyncio.gather(*[update_chunks(i) for i in range(10)])
        assert len(orchestrator._file_chunks) == 10

    @pytest.mark.asyncio
    async def test_aggregate_file_results_combines_chunks(self):
        """Aggregation correctly combines entity counts from multiple chunks."""
        orchestrator = ScanOrchestrator()
        orchestrator._file_results["/tmp/multi.txt"] = [
            _make_agent_result(
                work_id="multi:0",
                file_path="/tmp/multi.txt",
                chunk_index=0,
                entities=[
                    EntityMatch(
                        entity_type="SSN",
                        value="123-45-6789",
                        start=0,
                        end=11,
                        confidence=0.99,
                        source="checksum",
                    ),
                ],
                processing_time_ms=20.0,
            ),
            _make_agent_result(
                work_id="multi:1",
                file_path="/tmp/multi.txt",
                chunk_index=1,
                entities=[
                    EntityMatch(
                        entity_type="EMAIL",
                        value="a@b.com",
                        start=0,
                        end=7,
                        confidence=0.95,
                        source="regex",
                    ),
                    EntityMatch(
                        entity_type="SSN",
                        value="987-65-4321",
                        start=10,
                        end=21,
                        confidence=0.98,
                        source="checksum",
                    ),
                ],
                processing_time_ms=30.0,
            ),
        ]

        result = orchestrator._aggregate_file_results("/tmp/multi.txt")
        assert result.entity_counts == {"SSN": 2, "EMAIL": 1}
        assert result.total_entities == 3
        assert result.total_processing_ms == 50.0
        assert result.chunk_count == 2
        assert not result.has_errors

    @pytest.mark.asyncio
    async def test_aggregate_empty_chunks(self):
        """Aggregation handles file with no chunks gracefully."""
        orchestrator = ScanOrchestrator()
        result = orchestrator._aggregate_file_results("/tmp/empty.txt")
        assert result.total_entities == 0
        assert result.chunk_count == 0
        assert not result.has_errors


# ── ScanOrchestrator walk_files tests ────────────────────────────────


class TestScanOrchestratorWalkFiles:
    """Test the file walking stages."""

    @pytest.mark.asyncio
    async def test_walk_files_no_provider(self):
        """_walk_files returns immediately if no change_provider set."""
        orchestrator = ScanOrchestrator()
        await orchestrator._walk_files()
        assert orchestrator._extract_queue.empty()

    @pytest.mark.asyncio
    async def test_walk_files_legacy_with_patterns(self):
        """Legacy walker respects file patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            for name in ["test.txt", "test.py", "test.csv"]:
                with open(os.path.join(tmpdir, name), "w") as f:
                    f.write("content")

            orchestrator = ScanOrchestrator()
            await orchestrator._walk_files_legacy(tmpdir, recursive=False, patterns=["*.txt"])

            items = []
            while not orchestrator._extract_queue.empty():
                items.append(await orchestrator._extract_queue.get())

            assert len(items) == 1
            assert items[0].endswith("test.txt")

    @pytest.mark.asyncio
    async def test_walk_files_legacy_recursive(self):
        """Legacy walker supports recursive directory traversal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "sub")
            os.makedirs(subdir)
            with open(os.path.join(tmpdir, "a.txt"), "w") as f:
                f.write("content")
            with open(os.path.join(subdir, "b.txt"), "w") as f:
                f.write("content")

            orchestrator = ScanOrchestrator()
            await orchestrator._walk_files_legacy(tmpdir, recursive=True, patterns=None)

            items = []
            while not orchestrator._extract_queue.empty():
                items.append(await orchestrator._extract_queue.get())

            assert len(items) == 2


# ── ScanOrchestrator risk scoring tests ──────────────────────────────


class TestScanOrchestratorRiskScoring:
    """Additional risk scoring edge cases."""

    def test_capped_at_100(self):
        """Risk score is capped at 100 even with many entities."""
        score, tier, content_score, mult = ScanOrchestrator._compute_risk(
            {"SSN": 20}, 20, "PUBLIC"
        )
        assert score == 100
        assert content_score == 100  # 20*10 capped at 100
        assert mult == 2.0
        assert tier == "CRITICAL"

    def test_zero_entities(self):
        score, tier, content_score, mult = ScanOrchestrator._compute_risk(
            {}, 0, "PRIVATE"
        )
        assert score == 0
        assert tier == "MINIMAL"

    def test_content_score_capped_at_100(self):
        """Content score itself is capped at 100 before multiplier."""
        score, tier, content_score, mult = ScanOrchestrator._compute_risk(
            {"SSN": 15}, 15, "PRIVATE"
        )
        assert content_score == 100  # 15*10 = 150 -> capped at 100
        assert score == 100

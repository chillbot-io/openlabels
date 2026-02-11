"""Tests for the bounded-concurrency file processing pipeline."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from openlabels.jobs.pipeline import (
    FilePipeline,
    MemoryBudgetSemaphore,
    PipelineConfig,
    PipelineContext,
    PipelineStats,
)


@dataclass
class FakeFileInfo:
    """Minimal file info for testing."""
    path: str
    name: str
    size: int


async def _make_file_iterator(files: list[FakeFileInfo]):
    """Create an async iterator from a list of files."""
    for f in files:
        yield f


# ── MemoryBudgetSemaphore ─────────────────────────────────────────


class TestMemoryBudgetSemaphore:
    @pytest.mark.asyncio
    async def test_acquire_within_budget(self):
        budget = MemoryBudgetSemaphore(max_bytes=1000)
        await budget.acquire(500)
        assert budget.current_bytes == 500
        assert budget.available_bytes == 500

    @pytest.mark.asyncio
    async def test_release_frees_budget(self):
        budget = MemoryBudgetSemaphore(max_bytes=1000)
        await budget.acquire(500)
        budget.release(500)
        assert budget.current_bytes == 0
        assert budget.available_bytes == 1000

    @pytest.mark.asyncio
    async def test_allows_single_oversized_file(self):
        """A single file larger than budget should still proceed to prevent deadlock."""
        budget = MemoryBudgetSemaphore(max_bytes=100)
        # Should not deadlock — must allow at least one file through
        await budget.acquire(200)
        assert budget.current_bytes == 200

    @pytest.mark.asyncio
    async def test_blocks_when_budget_full(self):
        """Second acquire should block until first is released."""
        budget = MemoryBudgetSemaphore(max_bytes=100)
        await budget.acquire(80)

        acquired = asyncio.Event()

        async def _try_acquire():
            await budget.acquire(80)
            acquired.set()

        task = asyncio.create_task(_try_acquire())
        # Let the event loop schedule the task — it should block
        await asyncio.sleep(0)
        assert not acquired.is_set()

        budget.release(80)  # Free space
        # Wait for the task to acquire with a timeout
        try:
            await asyncio.wait_for(acquired.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        assert acquired.is_set()

        budget.release(80)  # Clean up
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_release_does_not_go_negative(self):
        budget = MemoryBudgetSemaphore(max_bytes=100)
        budget.release(500)  # Release more than allocated
        assert budget.current_bytes == 0


# ── PipelineStats ─────────────────────────────────────────────────


class TestPipelineStats:
    def test_to_dict(self):
        stats = PipelineStats(files_scanned=10, files_with_pii=3, total_entities=15)
        d = stats.to_dict()
        assert d["files_scanned"] == 10
        assert d["files_with_pii"] == 3
        assert d["total_entities"] == 15

    def test_record_result_with_pii(self):
        stats = PipelineStats()
        stats.record_result("HIGH", 5)
        assert stats.files_scanned == 1
        assert stats.files_with_pii == 1
        assert stats.total_entities == 5
        assert stats.high_count == 1

    def test_record_result_without_pii(self):
        stats = PipelineStats()
        stats.record_result("MINIMAL", 0)
        assert stats.files_scanned == 1
        assert stats.files_with_pii == 0
        assert stats.minimal_count == 1

    def test_record_multiple_results(self):
        stats = PipelineStats()
        stats.record_result("CRITICAL", 10)
        stats.record_result("HIGH", 5)
        stats.record_result("CRITICAL", 3)
        assert stats.files_scanned == 3
        assert stats.files_with_pii == 3
        assert stats.total_entities == 18
        assert stats.critical_count == 2
        assert stats.high_count == 1


# ── PipelineContext ───────────────────────────────────────────────


class TestPipelineContext:
    @pytest.mark.asyncio
    async def test_increment_and_decrement_active(self):
        ctx = PipelineContext(config=PipelineConfig())
        assert await ctx.increment_active() == 1
        assert await ctx.increment_active() == 2
        assert await ctx.decrement_active() == 1
        assert await ctx.decrement_active() == 0

    @pytest.mark.asyncio
    async def test_high_water_mark(self):
        ctx = PipelineContext(config=PipelineConfig())
        await ctx.increment_active()
        await ctx.increment_active()
        await ctx.increment_active()
        assert ctx.stats.pipeline_concurrency_high_water == 3
        await ctx.decrement_active()
        assert ctx.stats.pipeline_concurrency_high_water == 3  # Stays at peak

    @pytest.mark.asyncio
    async def test_should_commit(self):
        config = PipelineConfig(commit_interval=3)
        ctx = PipelineContext(config=config)
        assert not await ctx.should_commit()  # 1
        assert not await ctx.should_commit()  # 2
        assert await ctx.should_commit()  # 3 → commit
        assert not await ctx.should_commit()  # 1 (reset)


# ── FilePipeline ──────────────────────────────────────────────────


class TestFilePipeline:
    @pytest.mark.asyncio
    async def test_processes_all_files(self):
        """Pipeline should process every file from the iterator."""
        processed = []

        async def process_fn(file_info, ctx):
            processed.append(file_info.name)
            ctx.stats.record_result("MINIMAL", 0)

        files = [FakeFileInfo(path=f"/f{i}", name=f"f{i}.txt", size=100) for i in range(5)]
        config = PipelineConfig(max_concurrent_files=3, memory_budget_mb=1)
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=AsyncMock(),
        )
        stats = await pipeline.run(_make_file_iterator(files))

        assert stats.files_scanned == 5
        assert len(processed) == 5

    @pytest.mark.asyncio
    async def test_respects_concurrency_limit(self):
        """At most max_concurrent_files should run simultaneously."""
        max_concurrent = 0
        current = 0
        lock = asyncio.Lock()

        async def process_fn(file_info, ctx):
            nonlocal max_concurrent, current
            async with lock:
                current += 1
                if current > max_concurrent:
                    max_concurrent = current
            await asyncio.sleep(0.02)  # Simulate work
            async with lock:
                current -= 1
            ctx.stats.record_result("MINIMAL", 0)

        files = [FakeFileInfo(path=f"/f{i}", name=f"f{i}", size=100) for i in range(20)]
        config = PipelineConfig(max_concurrent_files=4, memory_budget_mb=10)
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=AsyncMock(),
        )
        await pipeline.run(_make_file_iterator(files))

        assert max_concurrent <= 4

    @pytest.mark.asyncio
    async def test_cancellation_stops_processing(self):
        """Pipeline should stop when cancellation function returns True."""
        call_count = 0

        async def process_fn(file_info, ctx):
            nonlocal call_count
            call_count += 1
            ctx.stats.record_result("MINIMAL", 0)

        cancel_after = 3

        async def cancellation_fn():
            return call_count >= cancel_after

        files = [FakeFileInfo(path=f"/f{i}", name=f"f{i}", size=100) for i in range(100)]
        config = PipelineConfig(
            max_concurrent_files=1,  # Sequential for deterministic test
            memory_budget_mb=1,
            cancellation_check_interval=1,
        )
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=AsyncMock(),
            cancellation_fn=cancellation_fn,
        )
        await pipeline.run(_make_file_iterator(files))

        assert pipeline.cancelled
        # Should have stopped close to cancel_after (may overshoot slightly)
        assert call_count <= cancel_after + 2

    @pytest.mark.asyncio
    async def test_commits_periodically(self):
        """Pipeline should call commit_fn at intervals."""
        commit_fn = AsyncMock()

        async def process_fn(file_info, ctx):
            ctx.stats.record_result("MINIMAL", 0)

        files = [FakeFileInfo(path=f"/f{i}", name=f"f{i}", size=100) for i in range(10)]
        config = PipelineConfig(
            max_concurrent_files=1,
            memory_budget_mb=1,
            commit_interval=3,
        )
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=commit_fn,
        )
        await pipeline.run(_make_file_iterator(files))

        # Should have committed at least a few times (every 3 files + final)
        assert commit_fn.call_count >= 3

    @pytest.mark.asyncio
    async def test_handles_process_errors_gracefully(self):
        """Errors in process_fn should be caught without killing the pipeline."""
        async def process_fn(file_info, ctx):
            if "bad" in file_info.name:
                raise ValueError("bad file")
            ctx.stats.record_result("MINIMAL", 0)

        files = [
            FakeFileInfo(path="/good1", name="good1.txt", size=100),
            FakeFileInfo(path="/bad", name="bad.txt", size=100),
            FakeFileInfo(path="/good2", name="good2.txt", size=100),
        ]
        config = PipelineConfig(max_concurrent_files=1, memory_budget_mb=1)
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=AsyncMock(),
        )
        stats = await pipeline.run(_make_file_iterator(files))

        assert stats.files_scanned == 2
        assert stats.files_errored == 1

    @pytest.mark.asyncio
    async def test_empty_iterator(self):
        """Pipeline should handle empty file list gracefully."""
        async def process_fn(file_info, ctx):
            pass

        config = PipelineConfig(max_concurrent_files=4, memory_budget_mb=1)
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=AsyncMock(),
        )
        stats = await pipeline.run(_make_file_iterator([]))

        assert stats.files_scanned == 0
        assert stats.files_errored == 0

    @pytest.mark.asyncio
    async def test_sequential_mode(self):
        """With max_concurrent=1, should behave like sequential processing."""
        order = []

        async def process_fn(file_info, ctx):
            order.append(file_info.name)
            ctx.stats.record_result("MINIMAL", 0)

        files = [FakeFileInfo(path=f"/f{i}", name=f"f{i}", size=100) for i in range(5)]
        config = PipelineConfig(max_concurrent_files=1, memory_budget_mb=1)
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=AsyncMock(),
        )
        await pipeline.run(_make_file_iterator(files))

        assert order == ["f0", "f1", "f2", "f3", "f4"]

    @pytest.mark.asyncio
    async def test_memory_budget_limits_concurrency(self):
        """Large files should reduce effective concurrency via memory budget."""
        max_concurrent = 0
        current = 0
        lock = asyncio.Lock()

        async def process_fn(file_info, ctx):
            nonlocal max_concurrent, current
            async with lock:
                current += 1
                if current > max_concurrent:
                    max_concurrent = current
            await asyncio.sleep(0.02)
            async with lock:
                current -= 1
            ctx.stats.record_result("MINIMAL", 0)

        # 8 files at 200MB each with 512MB budget → ~2-3 concurrent
        files = [
            FakeFileInfo(path=f"/f{i}", name=f"f{i}", size=200 * 1024 * 1024)
            for i in range(8)
        ]
        config = PipelineConfig(max_concurrent_files=8, memory_budget_mb=512)
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=AsyncMock(),
        )
        await pipeline.run(_make_file_iterator(files))

        # Memory budget should have limited actual concurrency below max_concurrent_files
        assert max_concurrent <= 4  # 512MB / 200MB ≈ 2-3 concurrent

    @pytest.mark.asyncio
    async def test_final_commit_always_runs(self):
        """Commit should always run after all tasks complete, even if process errors."""
        commit_fn = AsyncMock()

        async def process_fn(file_info, ctx):
            raise ValueError("boom")

        files = [FakeFileInfo(path="/f1", name="f1", size=100)]
        config = PipelineConfig(max_concurrent_files=1, memory_budget_mb=1)
        pipeline = FilePipeline(
            config=config,
            process_fn=process_fn,
            commit_fn=commit_fn,
        )
        await pipeline.run(_make_file_iterator(files))

        # Final commit should still be called
        assert commit_fn.called

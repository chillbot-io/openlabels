"""
Bounded-concurrency pipeline for overlapping I/O and compute within a single worker.

Instead of processing files sequentially (list → read → detect → save, one at a time),
the pipeline runs up to N files concurrently using asyncio.Semaphore. This overlaps:
- Network I/O (downloading file content from S3/GCS/Azure)
- CPU-bound detection (regex, checksum, ML inference via to_thread)
- Database writes (saving ScanResult rows)

Typical speedup: 4-8× per worker compared to sequential processing.

Memory safety: A MemoryBudgetSemaphore tracks cumulative in-flight file content
to prevent OOM when processing many large files concurrently.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for the concurrent file processing pipeline.

    Attributes:
        max_concurrent_files: Maximum files being processed simultaneously.
            Higher values overlap more I/O but use more memory.
            Recommended: 4-8 for cloud adapters, 2-4 for local filesystem.
        memory_budget_mb: Maximum cumulative in-flight file content in MB.
            Prevents OOM when processing many large files. When the budget
            is exhausted, new files wait until in-flight files complete.
        commit_interval: Flush database writes every N files.
        cancellation_check_interval: Check for job cancellation every N files.
    """

    max_concurrent_files: int = 8
    memory_budget_mb: int = 512
    commit_interval: int = 50
    cancellation_check_interval: int = 10


class MemoryBudgetSemaphore:
    """Semaphore that tracks byte-level memory budget instead of simple counts.

    Unlike asyncio.Semaphore which limits concurrency by count, this limits
    by cumulative byte size of in-flight work. This prevents OOM when a few
    large files would exceed available memory.

    Usage::

        budget = MemoryBudgetSemaphore(max_bytes=512 * 1024 * 1024)
        async with budget.acquire(file_size=50_000_000):
            content = await adapter.read_file(file_info)
            result = await detect(content)
    """

    def __init__(self, max_bytes: int) -> None:
        self._max_bytes = max_bytes
        self._current_bytes = 0
        self._condition = asyncio.Condition()

    @property
    def current_bytes(self) -> int:
        return self._current_bytes

    @property
    def available_bytes(self) -> int:
        return max(0, self._max_bytes - self._current_bytes)

    async def acquire(self, size: int) -> None:
        """Wait until *size* bytes can be reserved within the budget."""
        async with self._condition:
            # Always allow at least one file through even if it exceeds budget
            # (otherwise a single file larger than budget would deadlock)
            await self._condition.wait_for(
                lambda: self._current_bytes + size <= self._max_bytes
                or self._current_bytes == 0
            )
            self._current_bytes += size

    def release(self, size: int) -> None:
        """Release *size* bytes back to the budget.

        Note: This uses a fire-and-forget notify. Since asyncio.Condition
        requires the lock to notify, we schedule it as a task.
        """
        self._current_bytes = max(0, self._current_bytes - size)
        # Schedule notification on the event loop
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._notify())
        except RuntimeError:
            pass  # No event loop — testing outside async context

    async def _notify(self) -> None:
        async with self._condition:
            self._condition.notify_all()


@dataclass
class PipelineStats:
    """Mutable statistics accumulated during pipeline execution."""

    files_scanned: int = 0
    files_with_pii: int = 0
    total_entities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    minimal_count: int = 0
    files_skipped: int = 0
    files_errored: int = 0
    pipeline_concurrency_high_water: int = 0

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "files_with_pii": self.files_with_pii,
            "total_entities": self.total_entities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "minimal_count": self.minimal_count,
            "files_skipped": self.files_skipped,
            "files_errored": self.files_errored,
            "pipeline_concurrency_high_water": self.pipeline_concurrency_high_water,
        }

    def record_result(self, risk_tier: str, total_entities: int) -> None:
        """Record a single file's result into aggregate stats."""
        self.files_scanned += 1
        if total_entities > 0:
            self.files_with_pii += 1
        self.total_entities += total_entities
        tier_key = f"{risk_tier.lower()}_count"
        current = getattr(self, tier_key, None)
        if current is not None:
            setattr(self, tier_key, current + 1)


@dataclass
class PipelineContext:
    """Shared mutable state for the pipeline.

    Provides thread-safe (asyncio-safe) counters and cancellation flag
    that all concurrent file tasks can read/write.
    """

    config: PipelineConfig
    stats: PipelineStats = field(default_factory=PipelineStats)
    cancelled: bool = False
    _files_since_commit: int = 0
    _active_tasks: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def increment_active(self) -> int:
        async with self._lock:
            self._active_tasks += 1
            if self._active_tasks > self.stats.pipeline_concurrency_high_water:
                self.stats.pipeline_concurrency_high_water = self._active_tasks
            return self._active_tasks

    async def decrement_active(self) -> int:
        async with self._lock:
            self._active_tasks -= 1
            return self._active_tasks

    async def should_commit(self) -> bool:
        """Check if we should commit and reset counter if so."""
        async with self._lock:
            self._files_since_commit += 1
            if self._files_since_commit >= self.config.commit_interval:
                self._files_since_commit = 0
                return True
            return False


class FilePipeline:
    """Bounded-concurrency file processing pipeline.

    Consumes an async iterator of FileInfo objects and processes them
    through a caller-supplied ``process_fn`` with at most
    ``config.max_concurrent_files`` in flight at once, subject to
    the memory budget constraint.

    Usage::

        pipeline = FilePipeline(
            config=PipelineConfig(max_concurrent_files=8, memory_budget_mb=512),
            process_fn=my_process_one_file,
            commit_fn=session.commit,
            cancellation_fn=check_cancelled,
        )
        stats = await pipeline.run(adapter.list_files(path))
    """

    def __init__(
        self,
        config: PipelineConfig,
        process_fn: Callable[..., Coroutine[Any, Any, None]],
        commit_fn: Callable[[], Coroutine[Any, Any, None]],
        cancellation_fn: Callable[[], Coroutine[Any, Any, bool]] | None = None,
    ) -> None:
        self._config = config
        self._process_fn = process_fn
        self._commit_fn = commit_fn
        self._cancellation_fn = cancellation_fn
        self._concurrency_sem = asyncio.Semaphore(config.max_concurrent_files)
        self._memory_budget = MemoryBudgetSemaphore(
            max_bytes=config.memory_budget_mb * 1024 * 1024
        )
        self._ctx = PipelineContext(config=config)
        self._errors: list[str] = []

    @property
    def stats(self) -> PipelineStats:
        return self._ctx.stats

    @property
    def cancelled(self) -> bool:
        return self._ctx.cancelled

    async def run(self, file_iterator) -> PipelineStats:
        """Consume the file iterator and process all files concurrently.

        Returns accumulated pipeline statistics.
        """
        pending: set[asyncio.Task] = set()

        try:
            async for file_info in file_iterator:
                if self._ctx.cancelled:
                    break

                # Check cancellation periodically
                total_processed = (
                    self._ctx.stats.files_scanned
                    + self._ctx.stats.files_skipped
                    + self._ctx.stats.files_errored
                )
                if (
                    self._cancellation_fn
                    and total_processed % self._config.cancellation_check_interval == 0
                ):
                    if await self._cancellation_fn():
                        self._ctx.cancelled = True
                        break

                # Wait for a concurrency slot
                await self._concurrency_sem.acquire()

                # Wait for memory budget (using file size as estimate)
                file_size = max(file_info.size, 1024)  # minimum 1KB estimate
                await self._memory_budget.acquire(file_size)

                task = asyncio.create_task(
                    self._run_one(file_info, file_size),
                    name=f"pipeline-{file_info.name}",
                )
                pending.add(task)
                task.add_done_callback(pending.discard)

                # Eagerly collect completed tasks to free resources
                done = {t for t in pending if t.done()}
                for t in done:
                    pending.discard(t)
                    # Propagate exceptions via result() so they're not silent
                    try:
                        t.result()
                    except Exception:
                        pass  # Already logged in _run_one

        finally:
            # Wait for all in-flight tasks to complete
            if pending:
                results = await asyncio.gather(*pending, return_exceptions=True)
                for r in results:
                    if isinstance(r, Exception):
                        logger.warning("Pipeline task error during drain: %s", r)

            # Final commit for any remaining unflushed writes
            try:
                await self._commit_fn()
            except (OSError, RuntimeError) as e:
                logger.error("Final pipeline commit failed: %s", e)

        return self._ctx.stats

    async def _run_one(self, file_info, estimated_size: int) -> None:
        """Process a single file within the pipeline."""
        try:
            await self._ctx.increment_active()
            await self._process_fn(file_info, self._ctx)

            # Periodic commit
            if await self._ctx.should_commit():
                try:
                    await self._commit_fn()
                except (OSError, RuntimeError) as e:
                    logger.warning("Pipeline periodic commit failed: %s", e)
        except (PermissionError, OSError, UnicodeDecodeError, ValueError) as e:
            self._ctx.stats.files_errored += 1
            logger.warning("Pipeline error processing %s: %s", file_info.path, e)
        except Exception as e:
            self._ctx.stats.files_errored += 1
            logger.error("Unexpected pipeline error for %s: %s", file_info.path, e)
        finally:
            await self._ctx.decrement_active()
            self._memory_budget.release(estimated_size)
            self._concurrency_sem.release()

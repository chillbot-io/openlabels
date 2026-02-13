"""
Agent pool manager for parallel classification.

Manages a pool of classification agents (worker processes) that pull
work from a shared queue. Automatically scales based on available
CPU cores and memory.
"""

from __future__ import annotations

import asyncio
import logging
import multiprocessing as mp
import os
import time
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum

import psutil

from openlabels.core.agents.worker import (
    AgentResult,
    OptimizationBackend,
    WorkItem,
    agent_process_entry,
)

logger = logging.getLogger(__name__)


# Memory footprint per agent (NER model + overhead)
AGENT_MEMORY_MB = 400  # ~350MB model + 50MB overhead
MIN_SYSTEM_MEMORY_MB = 2048  # Keep 2GB free for OS
from openlabels.core.constants import MAX_DECOMPRESSED_SIZE

_MAX_FILE_BYTES = MAX_DECOMPRESSED_SIZE


@dataclass
class FileResult:
    """Aggregated result for a complete file (all chunks combined)."""

    file_path: str
    entity_counts: dict[str, int]
    total_entities: int
    total_processing_ms: float
    chunk_count: int
    errors: list[str]

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


# Type for result handler callback (async function that persists results)
ResultHandler = Callable[[list[FileResult]], Awaitable[None]]


class PoolState(str, Enum):
    """Pool lifecycle states."""

    INITIALIZING = "initializing"
    RUNNING = "running"
    DRAINING = "draining"  # Finishing current work
    STOPPED = "stopped"


@dataclass
class AgentPoolConfig:
    """Configuration for the agent pool."""

    # Number of agents (0 = auto-detect based on CPU/memory)
    num_agents: int = 0

    # Queue sizes (bounded for backpressure)
    input_queue_size: int = 100
    output_queue_size: int = 1000

    # Optimization backend
    backend: OptimizationBackend = OptimizationBackend.PYTORCH

    # Path to optimized model (for OpenVINO/ONNX)
    model_path: str | None = None

    # Device for inference
    device: str = "cpu"

    # Startup timeout per agent (seconds)
    agent_startup_timeout: float = 60.0

    # Graceful shutdown timeout (seconds)
    shutdown_timeout: float = 30.0

    # Batch collection settings
    result_batch_size: int = 50
    result_batch_timeout: float = 0.5  # seconds

    def auto_detect_agents(self) -> int:
        """
        Determine optimal number of agents based on system resources.

        Strategy:
        1. CPU cores set the upper bound (agents are CPU-bound)
        2. Available memory may reduce this further
        3. Leave headroom for file I/O and other processes
        """
        # Get CPU count (physical cores, not hyperthreads for CPU-bound work)
        try:
            cpu_count = psutil.cpu_count(logical=False) or os.cpu_count() or 4
        except (OSError, RuntimeError, AttributeError) as e:
            logger.debug(f"Failed to get physical CPU count: {e}")
            cpu_count = os.cpu_count() or 4

        # Get available memory
        try:
            mem = psutil.virtual_memory()
            available_mb = mem.available // (1024 * 1024)
            usable_mb = available_mb - MIN_SYSTEM_MEMORY_MB
            memory_agents = max(1, usable_mb // AGENT_MEMORY_MB)
        except (OSError, RuntimeError, AttributeError) as e:
            logger.debug(f"Failed to get available memory: {e}")
            memory_agents = cpu_count

        # Use minimum of CPU and memory constraints
        # Reserve 1 core for file I/O and coordination
        optimal = min(cpu_count - 1, memory_agents)
        optimal = max(1, optimal)  # At least 1 agent

        logger.info(
            f"Auto-detected agents: {optimal} "
            f"(CPUs: {cpu_count}, memory allows: {memory_agents})"
        )

        return optimal


@dataclass
class PoolStats:
    """Runtime statistics for the pool."""

    items_submitted: int = 0
    items_completed: int = 0
    items_failed: int = 0
    total_processing_ms: float = 0.0
    start_time: float = field(default_factory=time.time)

    @property
    def items_pending(self) -> int:
        return self.items_submitted - self.items_completed - self.items_failed

    @property
    def avg_processing_ms(self) -> float:
        if self.items_completed == 0:
            return 0.0
        return self.total_processing_ms / self.items_completed

    @property
    def throughput_per_second(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return self.items_completed / elapsed


class AgentPool:
    """
    Manages a pool of classification agent processes.

    Usage:
        async with AgentPool(config) as pool:
            # Submit work
            for chunk in file_chunks:
                await pool.submit(WorkItem(...))

            # Collect results
            async for result in pool.results():
                process_result(result)
    """

    def __init__(self, config: AgentPoolConfig | None = None):
        self.config = config or AgentPoolConfig()
        self._state = PoolState.INITIALIZING
        self._stats = PoolStats()

        # Determine number of agents
        if self.config.num_agents <= 0:
            self._num_agents = self.config.auto_detect_agents()
        else:
            self._num_agents = self.config.num_agents

        # Multiprocessing primitives (created in start())
        self._input_queue: mp.Queue | None = None
        self._output_queue: mp.Queue | None = None
        self._processes: list[mp.Process] = []

        # Async coordination
        self._result_task: asyncio.Task | None = None
        self._result_queue: asyncio.Queue[AgentResult] = asyncio.Queue()

    @property
    def state(self) -> PoolState:
        return self._state

    @property
    def stats(self) -> PoolStats:
        return self._stats

    @property
    def num_agents(self) -> int:
        return self._num_agents

    async def start(self) -> None:
        """Start the agent pool."""
        if self._state != PoolState.INITIALIZING:
            raise RuntimeError(f"Cannot start pool in state {self._state}")

        logger.info(f"Starting agent pool with {self._num_agents} agents")

        # Create bounded queues
        self._input_queue = mp.Queue(maxsize=self.config.input_queue_size)
        self._output_queue = mp.Queue(maxsize=self.config.output_queue_size)

        # Spawn agent processes
        for i in range(self._num_agents):
            p = mp.Process(
                target=agent_process_entry,
                args=(
                    i,
                    self._input_queue,
                    self._output_queue,
                    self.config.backend.value,
                    self.config.model_path,
                    self.config.device,
                ),
                daemon=True,
                name=f"Agent-{i}",
            )
            p.start()
            self._processes.append(p)
            logger.debug(f"Started agent process {i} (PID: {p.pid})")

        # Start background task to collect results
        self._result_task = asyncio.create_task(self._collect_results())

        self._state = PoolState.RUNNING
        self._stats.start_time = time.time()
        logger.info(f"Agent pool running with {self._num_agents} agents")

    async def stop(self, wait: bool = True) -> None:
        """
        Stop the agent pool.

        Args:
            wait: If True, wait for pending work to complete (drain).
                  If False, terminate immediately.
        """
        if self._state == PoolState.STOPPED:
            return

        if wait:
            self._state = PoolState.DRAINING
            logger.info("Draining agent pool...")

            # Send poison pills to all agents
            for _ in range(self._num_agents):
                if self._input_queue:
                    self._input_queue.put(None)

            # Wait for processes to finish (with timeout)
            deadline = time.time() + self.config.shutdown_timeout
            for p in self._processes:
                remaining = max(0, deadline - time.time())
                p.join(timeout=remaining)
                if p.is_alive():
                    logger.warning(f"Force terminating agent {p.name}")
                    p.terminate()
        else:
            # Immediate termination
            for p in self._processes:
                if p.is_alive():
                    p.terminate()

        # Cancel result collection task
        if self._result_task:
            self._result_task.cancel()
            try:
                await self._result_task
            except asyncio.CancelledError:
                # Expected when cancelling the task - not an error
                logger.debug("Result collection task cancelled during pool shutdown")

        # Clean up queues
        if self._input_queue:
            self._input_queue.close()
        if self._output_queue:
            self._output_queue.close()

        self._processes.clear()
        self._state = PoolState.STOPPED
        logger.info("Agent pool stopped")

    async def submit(self, item: WorkItem) -> None:
        """
        Submit a work item for classification.

        Blocks if the input queue is full (backpressure).
        """
        if self._state != PoolState.RUNNING:
            raise RuntimeError(f"Cannot submit work in state {self._state}")

        # Run blocking put in thread pool to avoid blocking event loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._input_queue.put, item)
        self._stats.items_submitted += 1

    async def submit_batch(self, items: list[WorkItem]) -> None:
        """Submit multiple work items."""
        for item in items:
            await self.submit(item)

    async def _collect_results(self) -> None:
        """Background task to move results from MP queue to async queue."""
        loop = asyncio.get_running_loop()

        while self._state in (PoolState.RUNNING, PoolState.DRAINING):
            try:
                # Non-blocking get with timeout
                result = await loop.run_in_executor(
                    None,
                    lambda: self._output_queue.get(timeout=0.1)
                )

                # Update stats
                self._stats.items_completed += 1
                self._stats.total_processing_ms += result.processing_time_ms
                if result.error:
                    self._stats.items_failed += 1

                # Forward to async queue
                await self._result_queue.put(result)

            except (RuntimeError, OSError, EOFError) as e:
                # Queue.get timeout or other error, continue
                logger.debug(f"Result collection interrupted: {e}")

    async def results(self) -> AsyncIterator[AgentResult]:
        """
        Async iterator over classification results.

        Yields results as they become available.
        """
        while True:
            # Check if we should stop
            if (
                self._state == PoolState.STOPPED
                or (self._state == PoolState.DRAINING and self._stats.items_pending == 0)
            ):
                # Drain remaining results
                while not self._result_queue.empty():
                    yield await self._result_queue.get()
                break

            try:
                result = await asyncio.wait_for(
                    self._result_queue.get(),
                    timeout=0.5
                )
                yield result
            except asyncio.TimeoutError:
                # Timeout is expected - allows checking for shutdown between waits
                continue

    async def results_batched(
        self,
        batch_size: int | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[list[AgentResult]]:
        """
        Async iterator yielding batches of results.

        Yields when batch_size is reached OR timeout expires (whichever first).
        Useful for batched database inserts.
        """
        batch_size = batch_size or self.config.result_batch_size
        timeout = timeout or self.config.result_batch_timeout

        batch: list[AgentResult] = []
        batch_start = time.time()

        async for result in self.results():
            batch.append(result)

            # Yield if batch is full or timeout expired
            elapsed = time.time() - batch_start
            if len(batch) >= batch_size or elapsed >= timeout:
                yield batch
                batch = []
                batch_start = time.time()

        # Yield remaining
        if batch:
            yield batch

    async def __aenter__(self) -> AgentPool:
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.stop(wait=exc_type is None)

    def health_check(self) -> dict:
        """Get pool health status."""
        alive_count = sum(1 for p in self._processes if p.is_alive())

        return {
            "state": self._state.value,
            "agents_total": self._num_agents,
            "agents_alive": alive_count,
            "items_submitted": self._stats.items_submitted,
            "items_completed": self._stats.items_completed,
            "items_pending": self._stats.items_pending,
            "avg_processing_ms": round(self._stats.avg_processing_ms, 1),
            "throughput_per_sec": round(self._stats.throughput_per_second, 1),
        }


class ScanOrchestrator:
    """
    Unified scan pipeline orchestrator.

    Merges the sequential (``execute_scan_task``) and parallel
    (``execute_parallel_scan_task``) code paths into a single
    pipeline that supports **both** multi-process classification
    agents **and** the full feature set:

    1. ChangeProvider → files to consider
    2. Adapter → read content
    3. Inventory → delta check (skip unchanged)
    4. Agent pool → parallel NER classification
    5. Result pipeline → scoring, exposure, inventory update,
       MIP labeling, DB persist, Parquet flush, WebSocket events

    Thread Safety:
        Uses asyncio.Lock to protect shared state (_file_chunks, _file_results)
        from concurrent access by multiple coroutines.
    """

    def __init__(
        self,
        pool_config: AgentPoolConfig | None = None,
        result_handler: ResultHandler | None = None,
        # ── Phase F additions ───────────────────────────────
        adapter: object | None = None,       # ReadAdapter
        change_provider: object | None = None,  # ChangeProvider
        inventory: object | None = None,      # InventoryService
        session: object | None = None,        # AsyncSession
        job: object | None = None,            # ScanJob
        settings: object | None = None,       # AppSettings
    ):
        self.pool_config = pool_config or AgentPoolConfig()
        self.result_handler = result_handler

        # Phase F: unified pipeline context
        self._adapter = adapter
        self._change_provider = change_provider
        self._inventory = inventory
        self._session = session
        self._job = job
        self._settings = settings

        # Bounded queues for pipeline stages
        self._extract_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        # Track chunks per file for aggregation
        self._file_chunks: dict[str, int] = {}       # file_path -> expected chunk count
        self._file_results: dict[str, list[AgentResult]] = defaultdict(list)
        self._file_metadata: dict[str, dict] = {}    # file_path -> adapter metadata

        # Lock for protecting shared state during concurrent access
        self._state_lock: asyncio.Lock = asyncio.Lock()

        # Statistics (updated during pipeline)
        self.stats: dict = {
            "files_scanned": 0,
            "files_with_pii": 0,
            "total_entities": 0,
            "files_skipped": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "minimal_count": 0,
            "errors": 0,
        }

        # Folder-level stats for inventory updates
        self._folder_stats: dict[str, dict] = {}

        # Track all file paths seen during walk (for mark_missing_files)
        self._seen_file_paths: set[str] = set()

    async def run(self) -> PoolStats:
        """Run the unified scan pipeline.

        Requires ``adapter``, ``change_provider``, ``inventory``,
        ``session``, ``job``, and ``settings`` to be set.
        """
        async with AgentPool(self.pool_config) as pool:
            walker_task = asyncio.create_task(self._walk_files())
            extractor_task = asyncio.create_task(
                self._extract_and_submit(pool)
            )
            collector_task = asyncio.create_task(
                self._collect_and_store(pool)
            )

            await walker_task
            await self._extract_queue.put(None)
            await extractor_task
            await collector_task

            return pool.stats

    # kept for backward compatibility with tests / callers that
    # don't use the unified pipeline context
    async def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        file_patterns: list[str] | None = None,
        on_result: Callable[[AgentResult], None] | None = None,
    ) -> PoolStats:
        """
        Scan a directory for sensitive data (legacy API).

        If a *change_provider* was set on __init__, ``run()`` is preferred.
        This method exists for backward compatibility.
        """
        async with AgentPool(self.pool_config) as pool:
            walker_task = asyncio.create_task(
                self._walk_files_legacy(path, recursive, file_patterns)
            )
            extractor_task = asyncio.create_task(
                self._extract_and_submit(pool)
            )
            collector_task = asyncio.create_task(
                self._collect_and_store(pool, on_result)
            )

            await walker_task
            await self._extract_queue.put(None)
            await extractor_task
            await collector_task

            return pool.stats

    # ── Stage 1: Walk files ────────────────────────────────────────────

    async def _walk_files(self) -> None:
        """Queue files from the ChangeProvider for extraction."""
        if self._change_provider is None:
            return

        max_file_size = 0
        if self._settings:
            scan_config = getattr(self._settings, 'scan', None)
            if scan_config:
                max_file_size = scan_config.max_file_size_mb * 1024 * 1024

        async for file_info in self._change_provider.changed_files():
            self._seen_file_paths.add(file_info.path)

            # Size guard
            if max_file_size and file_info.size > max_file_size:
                logger.warning("Skipping oversized file: %s (%d bytes)", file_info.path, file_info.size)
                self.stats["files_skipped"] += 1
                continue

            await self._extract_queue.put(file_info)

        logger.debug("File walker completed")

    async def _walk_files_legacy(
        self,
        path: str,
        recursive: bool,
        patterns: list[str] | None,
    ) -> None:
        """Walk directory and queue files for extraction (legacy Path.rglob)."""
        import fnmatch
        from pathlib import Path as _P

        root = _P(path)
        if not root.exists():
            logger.error("Path does not exist: %s", path)
            return

        iterator = root.rglob("*") if recursive else root.glob("*")

        for file_path in iterator:
            if not file_path.is_file():
                continue
            if patterns and not any(fnmatch.fnmatch(file_path.name, p) for p in patterns):
                continue
            await self._extract_queue.put(str(file_path))

        logger.debug("File walker completed")

    # ── Stage 2: Extract + submit ──────────────────────────────────────

    async def _extract_and_submit(self, pool: AgentPool) -> None:
        """Extract text, run delta checks, attach metadata, submit."""
        from openlabels.core.extractors import extract_text
        from openlabels.core.pipeline.chunking import TextChunker

        chunker = TextChunker()

        while True:
            item = await self._extract_queue.get()
            if item is None:
                break

            try:
                # Unified path: item is a FileInfo from ChangeProvider
                if hasattr(item, 'path') and hasattr(item, 'exposure'):
                    await self._extract_unified(item, pool, chunker, extract_text)
                else:
                    # Legacy path: item is a file-path string
                    await self._extract_legacy(item, pool, chunker, extract_text)

            except (OSError, ValueError, RuntimeError, MemoryError) as e:
                path = item.path if hasattr(item, 'path') else item
                logger.warning("Failed to process %s: %s", path, e)
                self.stats["errors"] += 1

        logger.debug("Extractor completed")

    async def _extract_unified(self, file_info, pool, chunker, extract_text) -> None:
        """Extract and submit via the unified pipeline (with delta + metadata)."""
        # Delta check — skip unchanged files
        if self._inventory and self._adapter:
            content = await self._adapter.read_file(file_info)
            content_hash = self._inventory.compute_content_hash(content)
            force_full = False
            if self._job and hasattr(self._job, '_force_full_scan'):
                force_full = self._job._force_full_scan

            should_scan, reason = await self._inventory.should_scan_file(
                file_info, content_hash, force_full,
            )
            if not should_scan:
                self.stats["files_skipped"] += 1
                return
        else:
            # No inventory — read via adapter (or fallback to direct read)
            if self._adapter:
                content = await self._adapter.read_file(file_info)
            else:
                file_size = os.path.getsize(file_info.path)
                if file_size > _MAX_FILE_BYTES:
                    logger.warning("Skipping %s: %d MB exceeds limit", file_info.path, file_size // 1024 // 1024)
                    return
                with open(file_info.path, 'rb') as f:
                    content = f.read()
            content_hash = None

        # Text extraction
        result = extract_text(content, file_info.path)
        text = result.text
        if not text or not text.strip():
            return

        # Chunk
        chunks = chunker.chunk(text)

        async with self._state_lock:
            self._file_chunks[file_info.path] = len(chunks)
            # Store adapter metadata for the result pipeline (F.6)
            self._file_metadata[file_info.path] = {
                "exposure_level": file_info.exposure.value if hasattr(file_info.exposure, 'value') else str(file_info.exposure),
                "owner": file_info.owner,
                "permissions": file_info.permissions,
                "adapter": file_info.adapter,
                "item_id": file_info.item_id,
                "content_hash": content_hash,
                "file_info": file_info,
            }

        # Submit each chunk with adapter metadata in WorkItem.metadata
        for i, chunk in enumerate(chunks):
            work = WorkItem(
                id=f"{file_info.path}:{i}",
                file_path=file_info.path,
                text=chunk.text,
                chunk_index=i,
                total_chunks=len(chunks),
                metadata={
                    "exposure_level": file_info.exposure.value if hasattr(file_info.exposure, 'value') else str(file_info.exposure),
                    "owner": file_info.owner,
                    "adapter": file_info.adapter,
                },
            )
            await pool.submit(work)

    async def _extract_legacy(self, file_path, pool, chunker, extract_text) -> None:
        """Extract and submit via legacy path (file_path string, no delta)."""
        file_size = os.path.getsize(file_path)
        if file_size > _MAX_FILE_BYTES:
            logger.warning("Skipping %s: %d MB exceeds limit", file_path, file_size // 1024 // 1024)
            return
        with open(file_path, 'rb') as f:
            content = f.read()

        result = extract_text(content, file_path)
        text = result.text
        if not text or not text.strip():
            return

        chunks = chunker.chunk(text)

        async with self._state_lock:
            self._file_chunks[file_path] = len(chunks)

        for i, chunk in enumerate(chunks):
            work = WorkItem(
                id=f"{file_path}:{i}",
                file_path=file_path,
                text=chunk.text,
                chunk_index=i,
                total_chunks=len(chunks),
            )
            await pool.submit(work)

    # ── Stage 3: Collect results + full pipeline ───────────────────────

    async def _collect_and_store(
        self,
        pool: AgentPool,
        on_result: Callable[[AgentResult], None] | None = None,
    ) -> None:
        """Collect agent results, aggregate per-file, run result pipeline."""
        completed_files: list[FileResult] = []

        async for batch in pool.results_batched():
            for result in batch:
                async with self._state_lock:
                    self._file_results[result.file_path].append(result)

                    expected_chunks = self._file_chunks.get(result.file_path, 1)
                    collected_chunks = len(self._file_results[result.file_path])

                    if collected_chunks >= expected_chunks:
                        file_result = self._aggregate_file_results(result.file_path)
                        completed_files.append(file_result)

                        del self._file_results[result.file_path]
                        if result.file_path in self._file_chunks:
                            del self._file_chunks[result.file_path]

                if on_result:
                    on_result(result)

            # Persist batch
            if completed_files:
                await self._persist_batch(completed_files)
                completed_files = []

            logger.debug("Collected batch of %d chunk results", len(batch))

        # Final batch
        if completed_files:
            await self._persist_batch(completed_files)

        logger.debug("Collector completed")

    async def _persist_batch(self, completed_files: list[FileResult]) -> None:
        """Run the full result pipeline on a batch of completed files.

        If the unified pipeline context (session, job, etc.) is set, runs
        the full pipeline.  Otherwise falls back to the legacy
        result_handler callback.
        """
        if self._session and self._job:
            await self._persist_unified(completed_files)
        elif self.result_handler:
            try:
                await self.result_handler(completed_files)
                logger.debug("Persisted %d file results via handler", len(completed_files))
            except (OSError, RuntimeError, ConnectionError) as e:
                logger.error("Failed to persist results: %s", e)

    async def _persist_unified(self, completed_files: list[FileResult]) -> None:
        """Full result pipeline: score → persist → inventory → WebSocket."""
        from openlabels.jobs.inventory import get_folder_path
        from openlabels.server.models import ScanResult

        # Import WebSocket sender once (not per-file)
        _send_file_result = None
        _send_progress = None
        try:
            from openlabels.server.routes.ws import send_scan_file_result, send_scan_progress
            _send_file_result = send_scan_file_result
            _send_progress = send_scan_progress
        except ImportError:
            pass

        for file_result in completed_files:
            try:
                meta = self._file_metadata.get(file_result.file_path, {})
                file_info = meta.get("file_info")
                content_hash = meta.get("content_hash")
                exposure_level = meta.get("exposure_level", "PRIVATE")
                owner = meta.get("owner")

                # ── Risk scoring (full engine, not hardcoded) ──────
                risk_score, risk_tier, content_score, exp_multiplier = self._compute_risk(
                    file_result.entity_counts,
                    file_result.total_entities,
                    exposure_level,
                )

                # ── DB persist ─────────────────────────────────────
                scan_result = ScanResult(
                    tenant_id=self._job.tenant_id,
                    job_id=self._job.id,
                    file_path=file_result.file_path,
                    file_name=file_info.name if file_info else file_result.file_path.rsplit("/", 1)[-1],
                    file_size=file_info.size if file_info else None,
                    file_modified=file_info.modified if file_info else None,
                    content_hash=content_hash,
                    risk_score=risk_score,
                    risk_tier=risk_tier,
                    entity_counts=file_result.entity_counts,
                    total_entities=file_result.total_entities,
                    exposure_level=exposure_level,
                    owner=owner,
                    content_score=float(content_score),
                    exposure_multiplier=exp_multiplier,
                )
                self._session.add(scan_result)

                # ── Update stats ───────────────────────────────────
                self.stats["files_scanned"] += 1
                if file_result.total_entities > 0:
                    self.stats["files_with_pii"] += 1
                self.stats["total_entities"] += file_result.total_entities
                tier_key = f"{risk_tier.lower()}_count"
                self.stats[tier_key] = self.stats.get(tier_key, 0) + 1

                # ── Folder stats for inventory ─────────────────────
                if file_info:
                    folder_path = get_folder_path(file_info.path)
                    if folder_path not in self._folder_stats:
                        self._folder_stats[folder_path] = {
                            "file_count": 0,
                            "total_size": 0,
                            "has_sensitive": False,
                            "highest_risk": None,
                            "total_entities": 0,
                        }
                    fs = self._folder_stats[folder_path]
                    fs["file_count"] += 1
                    fs["total_size"] += file_info.size
                    if file_result.total_entities > 0:
                        fs["has_sensitive"] = True
                        fs["total_entities"] += file_result.total_entities
                        _rp = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1}
                        if fs["highest_risk"] is None or _rp.get(risk_tier, 0) > _rp.get(fs["highest_risk"], 0):
                            fs["highest_risk"] = risk_tier

                    # ── File inventory update (sensitive files) ────
                    if file_result.total_entities > 0 and self._inventory:
                        await self._inventory.update_file_inventory(
                            file_info=file_info,
                            scan_result=scan_result,
                            content_hash=content_hash,
                            job_id=self._job.id,
                        )

                # ── WebSocket streaming ────────────────────────────
                if _send_file_result:
                    try:
                        await _send_file_result(
                            scan_id=self._job.id,
                            file_path=file_result.file_path,
                            risk_score=risk_score,
                            risk_tier=risk_tier,
                            entity_counts=file_result.entity_counts,
                        )
                    except (ConnectionError, OSError):
                        pass

                # Send progress updates every 10 files
                if _send_progress and self.stats["files_scanned"] % 10 == 0:
                    try:
                        await _send_progress(
                            scan_id=self._job.id,
                            status="running",
                            progress={
                                "files_scanned": self.stats["files_scanned"],
                                "files_with_pii": self.stats["files_with_pii"],
                                "files_skipped": self.stats["files_skipped"],
                            },
                        )
                    except (ConnectionError, OSError):
                        pass

                # ── Job progress ───────────────────────────────────
                self._job.files_scanned = self.stats["files_scanned"]
                self._job.files_with_pii = self.stats["files_with_pii"]
                self._job.progress = {
                    "mode": "unified",
                    "files_scanned": self.stats["files_scanned"],
                    "files_with_pii": self.stats["files_with_pii"],
                    "files_skipped": self.stats["files_skipped"],
                }

                # Clean up metadata for this file
                self._file_metadata.pop(file_result.file_path, None)

            except (PermissionError, OSError) as e:
                logger.error("Error persisting result for %s: %s", file_result.file_path, e)
                self.stats["errors"] += 1

        # Commit batch
        await self._session.commit()

    @staticmethod
    def _compute_risk(
        entity_counts: dict[str, int],
        total_entities: int,
        exposure_level: str,
    ) -> tuple[int, str, int, float]:
        """Compute risk score and tier from entity counts + exposure.

        Uses the same tier thresholds as the detection engine, with an
        exposure multiplier for non-private files.

        Returns:
            (risk_score, risk_tier, content_score, exposure_multiplier)
        """
        # Base score from entity count (content_score before multiplier)
        content_score = min(total_entities * 10, 100)

        # Exposure multiplier
        exposure_multipliers = {
            "PRIVATE": 1.0,
            "INTERNAL": 1.2,
            "ORG_WIDE": 1.5,
            "PUBLIC": 2.0,
        }
        multiplier = exposure_multipliers.get(exposure_level, 1.0)
        score = min(int(content_score * multiplier), 100)

        # Tier from score
        if score >= 80:
            tier = "CRITICAL"
        elif score >= 60:
            tier = "HIGH"
        elif score >= 40:
            tier = "MEDIUM"
        elif score >= 10:
            tier = "LOW"
        else:
            tier = "MINIMAL"

        return score, tier, content_score, multiplier

    def _aggregate_file_results(self, file_path: str) -> FileResult:
        """Aggregate all chunk results for a file into a single FileResult."""
        chunk_results = self._file_results.get(file_path, [])

        entity_counts: dict[str, int] = defaultdict(int)
        total_processing_ms = 0.0
        errors: list[str] = []

        for chunk in chunk_results:
            total_processing_ms += chunk.processing_time_ms
            if chunk.error:
                errors.append(f"Chunk {chunk.chunk_index}: {chunk.error}")
            for entity in chunk.entities:
                entity_counts[entity.entity_type] += 1

        return FileResult(
            file_path=file_path,
            entity_counts=dict(entity_counts),
            total_entities=sum(entity_counts.values()),
            total_processing_ms=total_processing_ms,
            chunk_count=len(chunk_results),
            errors=errors,
        )

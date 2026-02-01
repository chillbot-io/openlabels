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
import psutil
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator, Callable, Optional

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
    model_path: Optional[str] = None

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
        except Exception:
            cpu_count = os.cpu_count() or 4

        # Get available memory
        try:
            mem = psutil.virtual_memory()
            available_mb = mem.available // (1024 * 1024)
            usable_mb = available_mb - MIN_SYSTEM_MEMORY_MB
            memory_agents = max(1, usable_mb // AGENT_MEMORY_MB)
        except Exception:
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

    def __init__(self, config: Optional[AgentPoolConfig] = None):
        self.config = config or AgentPoolConfig()
        self._state = PoolState.INITIALIZING
        self._stats = PoolStats()

        # Determine number of agents
        if self.config.num_agents <= 0:
            self._num_agents = self.config.auto_detect_agents()
        else:
            self._num_agents = self.config.num_agents

        # Multiprocessing primitives (created in start())
        self._input_queue: Optional[mp.Queue] = None
        self._output_queue: Optional[mp.Queue] = None
        self._processes: list[mp.Process] = []

        # Async coordination
        self._result_task: Optional[asyncio.Task] = None
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
                pass

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
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._input_queue.put, item)
        self._stats.items_submitted += 1

    async def submit_batch(self, items: list[WorkItem]) -> None:
        """Submit multiple work items."""
        for item in items:
            await self.submit(item)

    async def _collect_results(self) -> None:
        """Background task to move results from MP queue to async queue."""
        loop = asyncio.get_event_loop()

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

            except Exception:
                # Queue.get timeout or other error, continue
                pass

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
                continue

    async def results_batched(
        self,
        batch_size: Optional[int] = None,
        timeout: Optional[float] = None,
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

    async def __aenter__(self) -> "AgentPool":
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
    High-level orchestrator for file scanning operations.

    Coordinates:
    1. File walker (async, I/O bound)
    2. Text extraction (mixed I/O and CPU)
    3. Agent pool (CPU bound classification)
    4. Policy evaluation (lightweight)
    5. Result storage (async I/O)
    """

    def __init__(
        self,
        pool_config: Optional[AgentPoolConfig] = None,
        policy_engine: Optional[object] = None,  # PolicyEngine type
    ):
        self.pool_config = pool_config or AgentPoolConfig()
        self.policy_engine = policy_engine

        # Bounded queues for pipeline stages
        self._extract_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    async def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        file_patterns: Optional[list[str]] = None,
        on_result: Optional[Callable[[AgentResult], None]] = None,
    ) -> PoolStats:
        """
        Scan a directory for sensitive data.

        Args:
            path: Directory to scan
            recursive: Scan subdirectories
            file_patterns: Glob patterns to include (e.g., ["*.pdf", "*.docx"])
            on_result: Callback for each result

        Returns:
            Final pool statistics
        """
        from openlabels.core.pipeline.chunking import TextChunker

        async with AgentPool(self.pool_config) as pool:
            # Start concurrent tasks
            walker_task = asyncio.create_task(
                self._walk_files(path, recursive, file_patterns)
            )
            extractor_task = asyncio.create_task(
                self._extract_and_submit(pool)
            )
            collector_task = asyncio.create_task(
                self._collect_and_store(pool, on_result)
            )

            # Wait for walker to finish
            await walker_task

            # Signal end of extraction queue
            await self._extract_queue.put(None)
            await extractor_task

            # Wait for all results
            await collector_task

            return pool.stats

    async def _walk_files(
        self,
        path: str,
        recursive: bool,
        patterns: Optional[list[str]],
    ) -> None:
        """Walk directory and queue files for extraction."""
        import fnmatch
        from pathlib import Path

        root = Path(path)
        if not root.exists():
            logger.error(f"Path does not exist: {path}")
            return

        iterator = root.rglob("*") if recursive else root.glob("*")

        for file_path in iterator:
            if not file_path.is_file():
                continue

            # Check patterns
            if patterns:
                if not any(fnmatch.fnmatch(file_path.name, p) for p in patterns):
                    continue

            # Queue for extraction (backpressure if queue is full)
            await self._extract_queue.put(str(file_path))

        logger.debug("File walker completed")

    async def _extract_and_submit(self, pool: AgentPool) -> None:
        """Extract text from files and submit to agent pool."""
        from openlabels.core.extraction import extract_text
        from openlabels.core.pipeline.chunking import TextChunker

        chunker = TextChunker()

        while True:
            file_path = await self._extract_queue.get()
            if file_path is None:
                break

            try:
                # Extract text (this is I/O bound for most files)
                text = await asyncio.to_thread(extract_text, file_path)

                if not text or not text.strip():
                    continue

                # Chunk the text
                chunks = chunker.chunk(text)

                # Submit each chunk as a work item
                for i, chunk in enumerate(chunks):
                    item = WorkItem(
                        id=f"{file_path}:{i}",
                        file_path=file_path,
                        text=chunk.text,
                        chunk_index=i,
                        total_chunks=len(chunks),
                    )
                    await pool.submit(item)

            except Exception as e:
                logger.warning(f"Failed to process {file_path}: {e}")

        logger.debug("Extractor completed")

    async def _collect_and_store(
        self,
        pool: AgentPool,
        on_result: Optional[Callable[[AgentResult], None]],
    ) -> None:
        """Collect results and apply policy evaluation."""
        async for batch in pool.results_batched():
            for result in batch:
                # Apply policy evaluation if configured
                if self.policy_engine and result.entities:
                    # policy_result = self.policy_engine.evaluate(result.entities)
                    # result.metadata['policies'] = policy_result
                    pass

                # Call user callback
                if on_result:
                    on_result(result)

            # TODO: Batch insert to database
            logger.debug(f"Collected batch of {len(batch)} results")

        logger.debug("Collector completed")

"""
Worker process for job execution.

Features:
- Configurable concurrency at runtime via shared state
- Graceful shutdown with signal handlers
- Per-tenant job isolation
"""

import asyncio
import logging
import os
import signal
import socket
from pathlib import Path
from typing import Optional
from uuid import uuid4

from openlabels.server.config import get_settings
from openlabels.server.db import init_db, get_session_context
from openlabels.jobs.queue import JobQueue
from openlabels.jobs.tasks.scan import execute_scan_task
from openlabels.jobs.tasks.label import execute_label_task
from openlabels.jobs.tasks.label_sync import execute_label_sync_task

logger = logging.getLogger(__name__)

# Shared state file for runtime configuration
# Workers check this periodically to adjust concurrency
WORKER_STATE_FILE = Path("/tmp/openlabels_worker_state.json")


def get_worker_state() -> dict:
    """Get current worker state from shared state file."""
    import json

    if WORKER_STATE_FILE.exists():
        try:
            with open(WORKER_STATE_FILE) as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to read worker state: {e}")
    return {}


def set_worker_state(state: dict) -> None:
    """Update worker state in shared state file."""
    import json

    current = get_worker_state()
    current.update(state)
    with open(WORKER_STATE_FILE, "w") as f:
        json.dump(current, f)


class Worker:
    """
    Worker process that executes jobs from the queue.

    Supports runtime concurrency adjustment via shared state file.
    """

    def __init__(self, concurrency: Optional[int] = None):
        """
        Initialize the worker.

        Args:
            concurrency: Number of concurrent jobs (default: CPU count)
        """
        self.concurrency = concurrency or os.cpu_count() or 4
        self.target_concurrency = self.concurrency  # Desired concurrency (can change at runtime)
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid4().hex[:8]}"
        self.running = False
        self._current_jobs: set = set()
        self._worker_tasks: list = []
        self._concurrency_check_interval = 5  # Check for concurrency changes every 5 seconds

    async def start(self) -> None:
        """Start the worker loop with dynamic concurrency support."""
        settings = get_settings()
        await init_db(settings.database.url)

        self.running = True
        logger.info(f"Worker {self.worker_id} started with concurrency={self.concurrency}")

        # Write initial state
        set_worker_state({
            "worker_id": self.worker_id,
            "concurrency": self.concurrency,
            "target_concurrency": self.target_concurrency,
            "status": "running",
            "pid": os.getpid(),
        })

        # Set up signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

        # Start initial worker tasks
        self._worker_tasks = [
            asyncio.create_task(self._worker_loop(i))
            for i in range(self.concurrency)
        ]

        # Start concurrency monitor
        monitor_task = asyncio.create_task(self._concurrency_monitor())

        # Wait for all workers
        await asyncio.gather(*self._worker_tasks, monitor_task, return_exceptions=True)

    def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info(f"Worker {self.worker_id} shutting down...")
        self.running = False
        set_worker_state({"status": "stopping"})

    async def _concurrency_monitor(self) -> None:
        """
        Monitor for concurrency changes via shared state file.

        Allows runtime adjustment of worker count without restart.
        """
        while self.running:
            try:
                state = get_worker_state()
                new_target = state.get("target_concurrency")

                if new_target and new_target != self.target_concurrency:
                    logger.info(f"Concurrency change requested: {self.target_concurrency} -> {new_target}")
                    await self._adjust_concurrency(new_target)

                # Update state with current worker count
                set_worker_state({
                    "concurrency": len([t for t in self._worker_tasks if not t.done()]),
                    "target_concurrency": self.target_concurrency,
                })

            except Exception as e:
                logger.debug(f"Concurrency monitor error: {e}")

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
                    # Get tenant IDs to process (simplified - in production would iterate tenants)
                    from sqlalchemy import select
                    from openlabels.server.models import Tenant

                    result = await session.execute(select(Tenant))
                    tenants = result.scalars().all()

                    for tenant in tenants:
                        queue = JobQueue(session, tenant.id)
                        job = await queue.dequeue(worker_tag)

                        if job:
                            await self._execute_job(session, queue, job)
                            break  # Process one job at a time per tenant

            except Exception as e:
                logger.error(f"Worker {worker_tag} error: {e}")

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
            else:
                raise ValueError(f"Unknown task type: {job.task_type}")

            await queue.complete(job.id, result)
            logger.info(f"Job {job.id} completed successfully")

        except Exception as e:
            logger.error(f"Job {job.id} failed: {e}")
            await queue.fail(job.id, str(e))


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

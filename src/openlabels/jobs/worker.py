"""
Worker process for job execution.

Features:
- Configurable concurrency at runtime via shared state
- Graceful shutdown with signal handlers
- Per-tenant job isolation
- File locking for safe concurrent state access
"""

import asyncio
import fcntl
import json
import logging
import os
import signal
import socket
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError

from openlabels.server.config import get_settings
from openlabels.server.db import init_db, get_session_context
from openlabels.jobs.queue import JobQueue
from openlabels.jobs.tasks.scan import execute_scan_task
from openlabels.jobs.tasks.label import execute_label_task
from openlabels.jobs.tasks.label_sync import execute_label_sync_task
from openlabels.core.exceptions import JobError

logger = logging.getLogger(__name__)

# Shared state file for runtime configuration
# Workers check this periodically to adjust concurrency
WORKER_STATE_FILE = Path("/tmp/openlabels_worker_state.json")
WORKER_STATE_LOCK_FILE = Path("/tmp/openlabels_worker_state.lock")


@contextmanager
def _file_lock(lock_path: Path):
    """
    Context manager for file-based locking.

    Uses fcntl.flock for safe concurrent access across multiple processes.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
        lock_fd.close()


def get_worker_state() -> dict:
    """Get current worker state from shared state file (with file locking)."""
    try:
        with _file_lock(WORKER_STATE_LOCK_FILE):
            if WORKER_STATE_FILE.exists():
                with open(WORKER_STATE_FILE) as f:
                    return json.load(f)
    except Exception as e:
        logger.debug(f"Failed to read worker state file: {e}")
    return {}


def set_worker_state(state: dict) -> None:
    """Update worker state in shared state file (with file locking)."""
    try:
        with _file_lock(WORKER_STATE_LOCK_FILE):
            current = {}
            if WORKER_STATE_FILE.exists():
                try:
                    with open(WORKER_STATE_FILE) as f:
                        current = json.load(f)
                except (json.JSONDecodeError, IOError) as parse_err:
                    # Non-critical: state file may be corrupted or being written by another process
                    logger.debug(f"Could not parse worker state file: {parse_err}")
            current.update(state)
            with open(WORKER_STATE_FILE, "w") as f:
                json.dump(current, f)
    except Exception as e:
        logger.warning(f"Failed to write worker state file: {e}")


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

        # Start stuck job reclaimer
        reclaimer_task = asyncio.create_task(self._stuck_job_reclaimer())

        # Start job cleanup task (TTL expiration)
        cleanup_task = asyncio.create_task(self._job_cleanup_task())

        # Wait for all workers
        await asyncio.gather(
            *self._worker_tasks, monitor_task, reclaimer_task, cleanup_task,
            return_exceptions=True
        )

    def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info(f"Worker {self.worker_id} shutting down...")
        self.running = False
        set_worker_state({"status": "stopping"})

    async def _stuck_job_reclaimer(self) -> None:
        """
        Periodically reclaim stuck jobs that have been running for too long.

        This handles the case where a worker crashes after dequeuing a job
        but before completing or failing it.
        """
        reclaim_interval = 300  # Check every 5 minutes

        while self.running:
            try:
                async with get_session_context() as session:
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
                        await session.commit()
                        logger.info(f"Reclaimed {total_reclaimed} stuck jobs")

            except Exception as e:
                # Log at warning level since stuck jobs could lead to data processing issues
                logger.warning(f"Stuck job reclaimer error - jobs may remain stuck: {type(e).__name__}: {e}")

            await asyncio.sleep(reclaim_interval)

    async def _job_cleanup_task(self) -> None:
        """
        Periodically clean up expired jobs based on TTL configuration.

        Removes completed/failed/cancelled jobs that exceed their retention period.
        Runs once per hour to minimize database load.
        """
        cleanup_interval = 3600  # Run once per hour

        while self.running:
            try:
                async with get_session_context() as session:
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
                        await session.commit()
                        logger.info(f"Cleaned up {total_cleaned} expired jobs")

            except Exception as e:
                # Log at warning level since cleanup failures could cause disk/DB bloat
                logger.warning(f"Job cleanup task error - expired jobs may accumulate: {type(e).__name__}: {e}")

            await asyncio.sleep(cleanup_interval)

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

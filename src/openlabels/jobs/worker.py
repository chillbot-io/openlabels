"""
Worker process for job execution.
"""

import asyncio
import logging
import os
import signal
import socket
from typing import Optional
from uuid import uuid4

from openlabels.server.config import get_settings
from openlabels.server.db import init_db, get_session_context
from openlabels.jobs.queue import JobQueue
from openlabels.jobs.tasks.scan import execute_scan_task
from openlabels.jobs.tasks.label import execute_label_task

logger = logging.getLogger(__name__)


class Worker:
    """Worker process that executes jobs from the queue."""

    def __init__(self, concurrency: Optional[int] = None):
        """
        Initialize the worker.

        Args:
            concurrency: Number of concurrent jobs (default: CPU count)
        """
        self.concurrency = concurrency or os.cpu_count() or 4
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid4().hex[:8]}"
        self.running = False
        self._current_jobs: set = set()

    async def start(self) -> None:
        """Start the worker loop."""
        settings = get_settings()
        await init_db(settings.database.url)

        self.running = True
        logger.info(f"Worker {self.worker_id} started with concurrency={self.concurrency}")

        # Set up signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

        # Start worker tasks
        workers = [
            asyncio.create_task(self._worker_loop(i))
            for i in range(self.concurrency)
        ]

        # Wait for all workers
        await asyncio.gather(*workers, return_exceptions=True)

    def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info(f"Worker {self.worker_id} shutting down...")
        self.running = False

    async def _worker_loop(self, worker_num: int) -> None:
        """
        Main worker loop for processing jobs.

        Args:
            worker_num: Worker number for logging
        """
        worker_tag = f"{self.worker_id}:{worker_num}"

        while self.running:
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

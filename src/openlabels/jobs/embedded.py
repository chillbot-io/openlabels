"""
Embedded job worker for in-process execution.

Runs inside the FastAPI server process so that ``openlabels serve`` is
self-contained — no separate ``openlabels worker`` command required for
single-server or desktop deployments.

The embedded worker is lighter than the standalone ``Worker`` class:
- No signal handler registration (the server manages its own lifecycle)
- No Redis state management (state is local to the process)
- No partition maintenance (the lifespan already handles this)
- Supports graceful shutdown via ``asyncio.Event``

For scaled / multi-machine deployments, use the standalone worker
(``openlabels worker``) instead.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError

from openlabels.exceptions import JobError
from openlabels.jobs.queue import JobQueue, dequeue_next_job
from openlabels.server.config import get_settings
from openlabels.server.db import get_session_context

logger = logging.getLogger(__name__)

# Default poll interval when no jobs are available
POLL_INTERVAL_SECONDS = 1.0

# How often to reclaim stuck jobs (seconds)
STUCK_RECLAIM_INTERVAL = 300


async def embedded_worker_loop(
    *,
    shutdown_event: asyncio.Event,
    concurrency: int | None = None,
) -> None:
    """
    Run an embedded job worker inside the server process.

    Polls the job queue for pending tasks and executes them with bounded
    concurrency.  Designed to be launched via
    ``BackgroundTaskManager.supervised_task()``.

    Args:
        shutdown_event: Set by the task manager to request graceful stop.
        concurrency: Max concurrent jobs.  Defaults to
            ``settings.jobs.default_worker_concurrency`` (typically 4).
    """
    settings = get_settings()
    if concurrency is None:
        concurrency = min(
            settings.jobs.default_worker_concurrency,
            os.cpu_count() or 4,
        )
    # Clamp
    concurrency = max(1, min(concurrency, settings.jobs.max_worker_concurrency))

    worker_id = f"embedded-{socket.gethostname()}-{os.getpid()}-{uuid4().hex[:6]}"
    semaphore = asyncio.Semaphore(concurrency)
    active_tasks: set[asyncio.Task] = set()

    logger.info(
        "Embedded worker %s started (concurrency=%d)", worker_id, concurrency,
    )

    # Kick off the stuck-job reclaimer as a child task
    reclaimer = asyncio.create_task(
        _stuck_job_reclaimer(shutdown_event, worker_id),
        name="embedded-reclaimer",
    )

    try:
        while not shutdown_event.is_set():
            # Wait for a concurrency slot *before* polling the DB.
            # Use a short timeout so we re-check shutdown_event regularly.
            try:
                await asyncio.wait_for(semaphore.acquire(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Poll for next job
            job = None
            try:
                async with get_session_context() as session:
                    job = await dequeue_next_job(session, worker_id)
                    if job:
                        await session.commit()
            except SQLAlchemyError as db_err:
                logger.warning("Embedded worker poll failed: %s", db_err)
                semaphore.release()
                await _interruptible_sleep(shutdown_event, 5.0)
                continue

            if job is None:
                semaphore.release()
                await _interruptible_sleep(shutdown_event, POLL_INTERVAL_SECONDS)
                continue

            # Dispatch job in a background task so we can keep polling
            task = asyncio.create_task(
                _run_job(job.id, job.task_type, job.payload, job.tenant_id, worker_id, semaphore),
                name=f"job-{job.id}",
            )
            active_tasks.add(task)
            task.add_done_callback(active_tasks.discard)

        # Shutdown requested — wait for active tasks to finish
        if active_tasks:
            logger.info(
                "Embedded worker draining %d active jobs...", len(active_tasks),
            )
            done, pending = await asyncio.wait(active_tasks, timeout=60.0)
            for t in pending:
                t.cancel()

    finally:
        reclaimer.cancel()
        try:
            await reclaimer
        except asyncio.CancelledError:
            pass

        # Release ML models
        try:
            from openlabels.jobs.tasks.scan import cleanup_processor
            cleanup_processor()
        except (ImportError, RuntimeError):
            pass

        logger.info("Embedded worker %s stopped", worker_id)


async def _run_job(
    job_id,
    task_type: str,
    payload: dict,
    tenant_id,
    worker_id: str,
    semaphore: asyncio.Semaphore,
) -> None:
    """Execute a single job and mark it complete/failed in the queue."""
    try:
        async with get_session_context() as session:
            # SECURITY: Set RLS tenant context so all subsequent queries
            # in this session are scoped to the job's tenant, matching
            # the standalone worker behaviour.
            from openlabels.server.db import set_rls_tenant_id
            await set_rls_tenant_id(session, tenant_id)

            queue = JobQueue(session, tenant_id)

            # SECURITY: Override payload tenant_id with the job's
            # authoritative tenant_id to prevent cross-tenant access.
            if payload and tenant_id:
                payload["tenant_id"] = str(tenant_id)

            try:
                result = await _dispatch(session, task_type, payload)
                await queue.complete(job_id, result=result)
                logger.info(
                    "Job %s (%s) completed by %s",
                    job_id, task_type, worker_id,
                )
            except JobError as e:
                error_msg = f"{task_type} task failed: {e}"
                logger.error("Job %s failed: %s", job_id, error_msg)
                await _safe_fail(queue, job_id, error_msg)
            except SQLAlchemyError as e:
                error_msg = f"Database error in {task_type}: {type(e).__name__}: {e}"
                logger.error("Job %s failed: %s", job_id, error_msg)
                await _safe_fail(queue, job_id, error_msg)
            except (PermissionError, FileNotFoundError, OSError) as e:
                error_msg = f"I/O error in {task_type}: {type(e).__name__}: {e}"
                logger.error("Job %s failed: %s", job_id, error_msg)
                await _safe_fail(queue, job_id, error_msg)
            except ValueError as e:
                error_msg = f"Invalid data in {task_type}: {e}"
                logger.error("Job %s failed: %s", job_id, error_msg)
                await _safe_fail(queue, job_id, error_msg)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                error_msg = f"Unexpected error in {task_type}: {type(e).__name__}: {e}"
                logger.error("Job %s failed: %s", job_id, error_msg, exc_info=True)
                await _safe_fail(queue, job_id, error_msg)
    finally:
        semaphore.release()


async def _safe_fail(queue: JobQueue, job_id, error_msg: str) -> None:
    """Call queue.fail() with protection against secondary failures.

    If queue.fail() itself raises (e.g. lost DB connection), the error
    is logged so the job can be reclaimed by the stuck-job reclaimer
    rather than silently remaining in RUNNING state forever.
    """
    try:
        await queue.fail(job_id, error_msg)
    except Exception as fail_exc:
        logger.error(
            "CRITICAL: queue.fail() itself failed for job %s — "
            "job will remain in RUNNING state until reclaimed by "
            "stuck-job reclaimer. Original error: %s | "
            "queue.fail() error: %s",
            job_id, error_msg, fail_exc,
        )


async def _dispatch(session, task_type: str, payload: dict) -> dict:
    """Route a job to the appropriate task handler."""
    if task_type in ("scan", "rescan"):
        from openlabels.jobs.tasks.scan import execute_scan_task
        return await execute_scan_task(session, payload)
    elif task_type == "scan_partition":
        from openlabels.jobs.tasks.scan_partition import execute_scan_partition_task
        return await execute_scan_partition_task(session, payload)
    elif task_type == "label":
        from openlabels.jobs.tasks.label import execute_label_task
        return await execute_label_task(session, payload)
    elif task_type == "label_sync":
        from openlabels.jobs.tasks.label_sync import execute_label_sync_task
        return await execute_label_sync_task(session, payload)
    elif task_type == "export":
        from openlabels.jobs.tasks.export import execute_export_task
        return await execute_export_task(session, payload)
    else:
        raise JobError(
            f"Unknown task type: {task_type}",
            job_type=task_type,
            context="embedded worker dispatch",
        )


async def _stuck_job_reclaimer(
    shutdown_event: asyncio.Event,
    worker_id: str,
) -> None:
    """Periodically reclaim jobs stuck in RUNNING state."""
    from openlabels.server.advisory_lock import AdvisoryLockID, try_advisory_lock

    while not shutdown_event.is_set():
        await _interruptible_sleep(shutdown_event, STUCK_RECLAIM_INTERVAL)
        if shutdown_event.is_set():
            break

        try:
            async with get_session_context() as session:
                if not await try_advisory_lock(session, AdvisoryLockID.STUCK_JOB_RECLAIM):
                    continue

                from sqlalchemy import select

                from openlabels.server.models import Tenant

                result = await session.execute(select(Tenant.id))
                tenant_ids = [row[0] for row in result.all()]

                total_reclaimed = 0
                settings = get_settings()
                timeout = settings.jobs.stuck_job_timeout

                for tid in tenant_ids:
                    queue = JobQueue(session, tid)
                    reclaimed = await queue.reclaim_stuck_jobs(timeout_seconds=timeout)
                    total_reclaimed += reclaimed

                if total_reclaimed:
                    logger.info(
                        "Embedded worker reclaimed %d stuck jobs", total_reclaimed,
                    )
        except (SQLAlchemyError, OSError, RuntimeError) as e:
            logger.warning("Stuck job reclamation failed: %s", e)


async def _interruptible_sleep(
    shutdown_event: asyncio.Event, seconds: float,
) -> None:
    """Sleep that wakes early when *shutdown_event* is set."""
    try:
        await asyncio.wait_for(shutdown_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass

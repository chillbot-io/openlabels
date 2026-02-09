"""
PostgreSQL-backed job queue with retry logic and dead letter support.

Features:
- Priority-based job ordering
- Exponential backoff for retries (2^n seconds, capped at 1 hour)
- Dead letter queue for permanently failed jobs
- Concurrent worker support via SELECT FOR UPDATE SKIP LOCKED
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Optional
from uuid import UUID, uuid4

from sqlalchemy import select, update, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import JobQueue as JobQueueModel
from openlabels.server.metrics import (
    record_job_enqueued,
    record_job_completed,
    record_job_failed,
    update_queue_depth,
)

# Retry configuration
BASE_RETRY_DELAY_SECONDS = 2  # 2 seconds initial delay
MAX_RETRY_DELAY_SECONDS = 3600  # Cap at 1 hour

# Job timeout - jobs running longer than this are considered stuck
DEFAULT_JOB_TIMEOUT_SECONDS = 3600  # 1 hour

logger = logging.getLogger(__name__)

# Callback invoked when a job completes or fails permanently.
JobCallback = Callable[["JobQueueModel"], Awaitable[None]]


def calculate_retry_delay(retry_count: int) -> timedelta:
    """
    Calculate retry delay using exponential backoff.

    delay = min(base * 2^retry_count, max_delay)

    Example: base=2s -> 2s, 4s, 8s, 16s, 32s, ...
    """
    delay_seconds = min(
        BASE_RETRY_DELAY_SECONDS * (2 ** retry_count),
        MAX_RETRY_DELAY_SECONDS,
    )
    return timedelta(seconds=delay_seconds)


class JobQueue:
    """PostgreSQL-backed job queue with priority support and retry logic."""

    def __init__(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        on_complete: JobCallback | None = None,
        on_failed: JobCallback | None = None,
    ):
        """
        Initialize the job queue.

        Args:
            session: Database session
            tenant_id: Tenant ID for job isolation
            on_complete: Async callback invoked after a job completes
            on_failed: Async callback invoked after a job permanently fails
        """
        self.session = session
        self.tenant_id = tenant_id
        self._on_complete = on_complete
        self._on_failed = on_failed

    async def enqueue(
        self,
        task_type: str,
        payload: dict,
        priority: int = 50,
        scheduled_for: Optional[datetime] = None,
    ) -> UUID:
        """
        Add a job to the queue.

        Args:
            task_type: Type of task ('scan', 'label', 'export')
            payload: Task-specific payload data
            priority: Priority 0-100 (higher = more urgent)
            scheduled_for: Optional time to start the job

        Returns:
            Job ID
        """
        job = JobQueueModel(
            id=uuid4(),
            tenant_id=self.tenant_id,
            task_type=task_type,
            payload=payload,
            priority=priority,
            status="pending",
            scheduled_for=scheduled_for,
        )
        self.session.add(job)
        await self.session.flush()

        # Record metrics
        record_job_enqueued(task_type)

        return job.id

    async def dequeue(
        self,
        worker_id: str,
        max_concurrent: int | None = None,
    ) -> Optional[JobQueueModel]:
        """
        Get the next job for processing.

        Uses SELECT FOR UPDATE SKIP LOCKED for safe concurrent access.

        Args:
            worker_id: Identifier of the worker claiming the job
            max_concurrent: Maximum running jobs allowed for this tenant.
                If the tenant already has this many running jobs, returns
                ``None`` immediately to prevent starvation.

        Returns:
            Job model or None if no jobs available
        """
        if max_concurrent is not None:
            running = await self.get_running_count()
            if running >= max_concurrent:
                return None

        now = datetime.now(timezone.utc)

        # Find next available job
        query = (
            select(JobQueueModel)
            .where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "pending",
                (JobQueueModel.scheduled_for.is_(None)) | (JobQueueModel.scheduled_for <= now),
            )
            .order_by(
                JobQueueModel.priority.desc(),
                JobQueueModel.created_at.asc(),
            )
            .limit(1)
            .with_for_update(skip_locked=True)
        )

        result = await self.session.execute(query)
        job = result.scalar_one_or_none()

        if job:
            job.status = "running"
            job.worker_id = worker_id
            job.started_at = now
            await self.session.flush()

        return job

    async def complete(self, job_id: UUID, result: Optional[dict] = None) -> None:
        """
        Mark a job as completed.

        Args:
            job_id: Job ID to complete
            result: Optional result data
        """
        # Get job to record task_type for metrics
        job = await self.session.get(JobQueueModel, job_id)
        task_type = job.task_type if job else "unknown"

        await self.session.execute(
            update(JobQueueModel)
            .where(JobQueueModel.id == job_id)
            .values(
                status="completed",
                completed_at=datetime.now(timezone.utc),
                result=result,
            )
        )

        # Record metrics
        record_job_completed(task_type)

        # Fire completion callback
        if self._on_complete and job:
            try:
                await self._on_complete(job)
            except Exception as exc:  # noqa: BLE001 — catch-all for arbitrary user callback
                logger.error("on_complete callback failed for job %s: %s", job_id, exc)

    async def fail(
        self,
        job_id: UUID,
        error: str,
        retry: bool = True,
    ) -> None:
        """
        Mark a job as failed, with automatic retry using exponential backoff.

        If retries remain, the job is scheduled for retry after a delay of:
        delay = 2^retry_count seconds (capped at 1 hour)

        Args:
            job_id: Job ID that failed
            error: Error message
            retry: Whether to retry the job (respects max_retries)
        """
        job = await self.session.get(JobQueueModel, job_id)
        if not job:
            return

        if retry and job.retry_count < job.max_retries:
            # Calculate retry delay with exponential backoff
            delay = calculate_retry_delay(job.retry_count)
            retry_at = datetime.now(timezone.utc) + delay

            job.status = "pending"
            job.retry_count += 1
            job.worker_id = None
            job.started_at = None
            job.error = error
            job.scheduled_for = retry_at  # Delay next execution
        else:
            # Move to dead letter queue (failed status)
            job.status = "failed"
            job.completed_at = datetime.now(timezone.utc)
            job.error = error

            # Record failed metric only when permanently failed
            record_job_failed(job.task_type)

        await self.session.flush()

        # Fire failure callback when permanently failed
        if job.status == "failed" and self._on_failed:
            try:
                await self._on_failed(job)
            except Exception as exc:  # noqa: BLE001 — catch-all for arbitrary user callback
                logger.error("on_failed callback failed for job %s: %s", job_id, exc)

    async def get_job(self, job_id: UUID) -> Optional[JobQueueModel]:
        """Get a job by ID."""
        return await self.session.get(JobQueueModel, job_id)

    async def cancel(self, job_id: UUID) -> bool:
        """
        Cancel a pending or running job.

        Returns:
            True if cancelled, False if not cancellable
        """
        job = await self.session.get(JobQueueModel, job_id)
        if not job:
            return False

        if job.status not in ("pending", "running"):
            return False

        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        await self.session.flush()
        return True

    async def get_pending_count(self) -> int:
        """Get count of pending jobs using efficient SQL COUNT."""
        query = select(func.count()).select_from(JobQueueModel).where(
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "pending",
        )
        result = await self.session.execute(query)
        return result.scalar() or 0

    async def get_running_count(self) -> int:
        """Get count of running jobs using efficient SQL COUNT."""
        query = select(func.count()).select_from(JobQueueModel).where(
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "running",
        )
        result = await self.session.execute(query)
        return result.scalar() or 0

    # =========================================================================
    # Dead Letter Queue (DLQ) Operations
    # =========================================================================

    async def get_failed_jobs(
        self,
        task_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[JobQueueModel]:
        """
        Get jobs that have permanently failed (dead letter queue).

        Args:
            task_type: Optional filter by task type
            limit: Maximum number of jobs to return
            offset: Offset for pagination

        Returns:
            List of failed job models
        """
        conditions = [
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "failed",
        ]
        if task_type:
            conditions.append(JobQueueModel.task_type == task_type)

        query = (
            select(JobQueueModel)
            .where(and_(*conditions))
            .order_by(JobQueueModel.completed_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_failed_count(self, task_type: Optional[str] = None) -> int:
        """Get count of failed jobs in dead letter queue."""
        conditions = [
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "failed",
        ]
        if task_type:
            conditions.append(JobQueueModel.task_type == task_type)

        query = select(func.count()).select_from(JobQueueModel).where(and_(*conditions))
        result = await self.session.execute(query)
        return result.scalar() or 0

    async def requeue_failed(
        self,
        job_id: UUID,
        reset_retries: bool = True,
    ) -> bool:
        """
        Requeue a failed job from the dead letter queue.

        Args:
            job_id: Job ID to requeue
            reset_retries: Whether to reset retry count (default: True)

        Returns:
            True if requeued successfully, False if job not found or not failed
        """
        job = await self.session.get(JobQueueModel, job_id)
        if not job:
            return False

        # Refresh to get latest state from database (in case of concurrent modifications)
        await self.session.refresh(job)

        if job.status != "failed":
            return False

        if job.tenant_id != self.tenant_id:
            return False

        job.status = "pending"
        job.worker_id = None
        job.started_at = None
        job.completed_at = None
        job.scheduled_for = None  # Execute immediately
        job.error = None

        if reset_retries:
            job.retry_count = 0

        await self.session.flush()
        return True

    async def requeue_all_failed(
        self,
        task_type: Optional[str] = None,
        reset_retries: bool = True,
    ) -> int:
        """
        Requeue all failed jobs of a specific type.

        Args:
            task_type: Optional filter by task type (requeue all if None)
            reset_retries: Whether to reset retry counts

        Returns:
            Number of jobs requeued
        """
        conditions = [
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "failed",
        ]
        if task_type:
            conditions.append(JobQueueModel.task_type == task_type)

        values = {
            "status": "pending",
            "worker_id": None,
            "started_at": None,
            "completed_at": None,
            "scheduled_for": None,
            "error": None,
        }
        if reset_retries:
            values["retry_count"] = 0

        result = await self.session.execute(
            update(JobQueueModel)
            .where(and_(*conditions))
            .values(**values)
        )
        await self.session.flush()
        return result.rowcount

    async def purge_failed(
        self,
        task_type: Optional[str] = None,
        older_than_days: Optional[int] = None,
    ) -> int:
        """
        Delete failed jobs from the dead letter queue.

        Args:
            task_type: Optional filter by task type
            older_than_days: Only delete jobs older than N days

        Returns:
            Number of jobs deleted
        """
        from sqlalchemy import delete

        conditions = [
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "failed",
        ]
        if task_type:
            conditions.append(JobQueueModel.task_type == task_type)
        if older_than_days:
            cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
            conditions.append(JobQueueModel.completed_at < cutoff)

        result = await self.session.execute(
            delete(JobQueueModel).where(and_(*conditions))
        )
        await self.session.flush()
        return result.rowcount

    async def get_queue_stats(self) -> dict:
        """
        Get comprehensive queue statistics.

        Returns:
            Dictionary with job counts by status and task type
        """
        # Count by status
        status_query = (
            select(JobQueueModel.status, func.count())
            .where(JobQueueModel.tenant_id == self.tenant_id)
            .group_by(JobQueueModel.status)
        )
        status_result = await self.session.execute(status_query)
        by_status = dict(status_result.all())

        # Count failed by task type
        failed_query = (
            select(JobQueueModel.task_type, func.count())
            .where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "failed",
            )
            .group_by(JobQueueModel.task_type)
        )
        failed_result = await self.session.execute(failed_query)
        failed_by_type = dict(failed_result.all())

        stats = {
            "pending": by_status.get("pending", 0),
            "running": by_status.get("running", 0),
            "completed": by_status.get("completed", 0),
            "failed": by_status.get("failed", 0),
            "cancelled": by_status.get("cancelled", 0),
            "failed_by_type": failed_by_type,
        }

        # Update Prometheus queue depth gauges
        update_queue_depth(
            pending=stats["pending"],
            running=stats["running"],
            failed=stats["failed"],
        )

        return stats

    # =========================================================================
    # Stuck Job Recovery
    # =========================================================================

    async def reclaim_stuck_jobs(
        self,
        timeout_seconds: int = DEFAULT_JOB_TIMEOUT_SECONDS,
    ) -> int:
        """
        Reclaim jobs that have been running for too long (likely crashed workers).

        This handles the case where a worker crashes after dequeuing a job but
        before completing or failing it. The job would otherwise remain stuck
        in "running" status forever.

        Args:
            timeout_seconds: Jobs running longer than this are considered stuck

        Returns:
            Number of jobs reclaimed
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)

        # Find stuck jobs
        query = (
            select(JobQueueModel)
            .where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "running",
                JobQueueModel.started_at < cutoff,
            )
            .with_for_update(skip_locked=True)
        )

        result = await self.session.execute(query)
        stuck_jobs = result.scalars().all()

        reclaimed = 0
        for job in stuck_jobs:
            # Treat as a failure and let retry logic handle it
            job.status = "pending"
            job.retry_count += 1
            job.worker_id = None
            job.started_at = None
            job.error = f"Reclaimed: job was stuck (running for >{timeout_seconds}s)"

            if job.retry_count >= job.max_retries:
                # Move to dead letter queue
                job.status = "failed"
                job.completed_at = datetime.now(timezone.utc)

            reclaimed += 1

        if reclaimed > 0:
            await self.session.flush()

        return reclaimed

    async def get_stuck_jobs_count(
        self,
        timeout_seconds: int = DEFAULT_JOB_TIMEOUT_SECONDS,
    ) -> int:
        """Get count of potentially stuck jobs."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)

        query = (
            select(func.count())
            .select_from(JobQueueModel)
            .where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "running",
                JobQueueModel.started_at < cutoff,
            )
        )

        result = await self.session.execute(query)
        return result.scalar() or 0

    # =========================================================================
    # Job TTL / Expiration
    # =========================================================================

    async def cleanup_expired_jobs(
        self,
        completed_ttl_days: Optional[int] = None,
        failed_ttl_days: Optional[int] = None,
    ) -> dict[str, int]:
        """
        Clean up expired jobs based on TTL configuration.

        Completed jobs are deleted after completed_ttl_days.
        Failed jobs are kept longer (failed_ttl_days) for debugging.

        Args:
            completed_ttl_days: Days to keep completed jobs (uses config default if None)
            failed_ttl_days: Days to keep failed jobs (uses config default if None)

        Returns:
            Dictionary with counts of deleted jobs by status
        """
        from sqlalchemy import delete

        # Get TTL values from config if not provided
        try:
            from openlabels.server.config import get_settings
            settings = get_settings()
            completed_ttl_days = completed_ttl_days or settings.jobs.completed_job_ttl_days
            failed_ttl_days = failed_ttl_days or settings.jobs.failed_job_ttl_days
        except (ImportError, RuntimeError, AttributeError) as config_err:
            # Settings may not be available in tests or standalone usage - use defaults
            import logging
            logging.getLogger(__name__).debug(f"Using default TTL values (config unavailable): {config_err}")
            completed_ttl_days = completed_ttl_days or 7
            failed_ttl_days = failed_ttl_days or 30

        now = datetime.now(timezone.utc)
        deleted_counts = {"completed": 0, "failed": 0, "cancelled": 0}

        # Delete old completed jobs
        completed_cutoff = now - timedelta(days=completed_ttl_days)
        completed_result = await self.session.execute(
            delete(JobQueueModel).where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "completed",
                JobQueueModel.completed_at < completed_cutoff,
            )
        )
        deleted_counts["completed"] = completed_result.rowcount

        # Delete old cancelled jobs (same TTL as completed)
        cancelled_result = await self.session.execute(
            delete(JobQueueModel).where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "cancelled",
                JobQueueModel.completed_at < completed_cutoff,
            )
        )
        deleted_counts["cancelled"] = cancelled_result.rowcount

        # Delete old failed jobs (longer retention)
        failed_cutoff = now - timedelta(days=failed_ttl_days)
        failed_result = await self.session.execute(
            delete(JobQueueModel).where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "failed",
                JobQueueModel.completed_at < failed_cutoff,
            )
        )
        deleted_counts["failed"] = failed_result.rowcount

        await self.session.flush()

        total = sum(deleted_counts.values())
        if total > 0:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(
                f"Cleaned up {total} expired jobs for tenant {self.tenant_id}: "
                f"completed={deleted_counts['completed']}, "
                f"failed={deleted_counts['failed']}, "
                f"cancelled={deleted_counts['cancelled']}"
            )

        return deleted_counts

    async def get_stale_pending_jobs(
        self,
        max_age_hours: Optional[int] = None,
    ) -> list[JobQueueModel]:
        """
        Get pending jobs that have been waiting too long.

        Useful for alerting on jobs that may be stuck in pending state.

        Args:
            max_age_hours: Maximum age for pending jobs (uses config default if None)

        Returns:
            List of stale pending jobs
        """
        try:
            from openlabels.server.config import get_settings
            settings = get_settings()
            max_age_hours = max_age_hours or settings.jobs.pending_job_max_age_hours
        except (ImportError, RuntimeError, AttributeError) as config_err:
            # Settings may not be available in tests or standalone usage - use defaults
            import logging
            logging.getLogger(__name__).debug(f"Using default max_age_hours (config unavailable): {config_err}")
            max_age_hours = max_age_hours or 24

        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        query = (
            select(JobQueueModel)
            .where(
                JobQueueModel.tenant_id == self.tenant_id,
                JobQueueModel.status == "pending",
                JobQueueModel.created_at < cutoff,
            )
            .order_by(JobQueueModel.created_at.asc())
        )

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_job_age_stats(self) -> dict:
        """
        Get statistics about job ages for monitoring using efficient SQL aggregation.

        Uses SQL MIN and AVG functions instead of loading all jobs into memory.

        Returns:
            Dictionary with age statistics by status
        """
        from sqlalchemy import extract

        now = datetime.now(timezone.utc)

        stats = {
            "pending": {"count": 0, "oldest_hours": 0.0, "avg_hours": 0.0},
            "running": {"count": 0, "oldest_hours": 0.0, "avg_hours": 0.0},
        }

        # Pending jobs stats using SQL aggregation
        # Get count, oldest (MIN created_at), and average age
        pending_query = select(
            func.count().label("count"),
            func.min(JobQueueModel.created_at).label("oldest"),
            func.avg(
                extract('epoch', func.cast(now, JobQueueModel.created_at.type))
                - extract('epoch', JobQueueModel.created_at)
            ).label("avg_age_seconds"),
        ).where(
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "pending",
        )
        pending_result = await self.session.execute(pending_query)
        pending_row = pending_result.one()

        if pending_row.count and pending_row.count > 0:
            stats["pending"]["count"] = pending_row.count
            if pending_row.oldest:
                oldest_age = (now - pending_row.oldest).total_seconds() / 3600
                stats["pending"]["oldest_hours"] = round(oldest_age, 2)
            if pending_row.avg_age_seconds:
                stats["pending"]["avg_hours"] = round(pending_row.avg_age_seconds / 3600, 2)

        # Running jobs stats using SQL aggregation
        running_query = select(
            func.count().label("count"),
            func.min(JobQueueModel.started_at).label("oldest"),
            func.avg(
                extract('epoch', func.cast(now, JobQueueModel.started_at.type))
                - extract('epoch', JobQueueModel.started_at)
            ).label("avg_age_seconds"),
        ).where(
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "running",
            JobQueueModel.started_at.isnot(None),
        )
        running_result = await self.session.execute(running_query)
        running_row = running_result.one()

        if running_row.count and running_row.count > 0:
            stats["running"]["count"] = running_row.count
            if running_row.oldest:
                oldest_age = (now - running_row.oldest).total_seconds() / 3600
                stats["running"]["oldest_hours"] = round(oldest_age, 2)
            if running_row.avg_age_seconds:
                stats["running"]["avg_hours"] = round(running_row.avg_age_seconds / 3600, 2)

        return stats


async def dequeue_next_job(
    session: AsyncSession,
    worker_id: str,
) -> Optional[JobQueueModel]:
    """
    Dequeue the next available job across all tenants in a single query.

    Replaces per-tenant iteration with one SELECT FOR UPDATE SKIP LOCKED,
    reducing the polling cost from O(tenants) queries to O(1).

    Args:
        session: Database session
        worker_id: Identifier of the worker claiming the job

    Returns:
        Job model or None if no jobs available
    """
    now = datetime.now(timezone.utc)

    query = (
        select(JobQueueModel)
        .where(
            JobQueueModel.status == "pending",
            (JobQueueModel.scheduled_for.is_(None)) | (JobQueueModel.scheduled_for <= now),
        )
        .order_by(
            JobQueueModel.priority.desc(),
            JobQueueModel.created_at.asc(),
        )
        .limit(1)
        .with_for_update(skip_locked=True)
    )

    result = await session.execute(query)
    job = result.scalar_one_or_none()

    if job:
        job.status = "running"
        job.worker_id = worker_id
        job.started_at = now
        await session.flush()

    return job

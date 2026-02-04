"""
PostgreSQL-backed job queue with retry logic and dead letter support.

Features:
- Priority-based job ordering
- Exponential backoff for retries (2^n seconds, capped at 1 hour)
- Dead letter queue for permanently failed jobs
- Concurrent worker support via SELECT FOR UPDATE SKIP LOCKED
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import select, update, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import JobQueue as JobQueueModel

# Retry configuration
BASE_RETRY_DELAY_SECONDS = 2  # 2 seconds initial delay
MAX_RETRY_DELAY_SECONDS = 3600  # Cap at 1 hour


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

    def __init__(self, session: AsyncSession, tenant_id: UUID):
        """
        Initialize the job queue.

        Args:
            session: Database session
            tenant_id: Tenant ID for job isolation
        """
        self.session = session
        self.tenant_id = tenant_id

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
        return job.id

    async def dequeue(self, worker_id: str) -> Optional[JobQueueModel]:
        """
        Get the next job for processing.

        Uses SELECT FOR UPDATE SKIP LOCKED for safe concurrent access.

        Args:
            worker_id: Identifier of the worker claiming the job

        Returns:
            Job model or None if no jobs available
        """
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
        await self.session.execute(
            update(JobQueueModel)
            .where(JobQueueModel.id == job_id)
            .values(
                status="completed",
                completed_at=datetime.now(timezone.utc),
                result=result,
            )
        )

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

        await self.session.flush()

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
        """Get count of pending jobs."""
        query = select(JobQueueModel.id).where(
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "pending",
        )
        result = await self.session.execute(query)
        return len(result.all())

    async def get_running_count(self) -> int:
        """Get count of running jobs."""
        query = select(JobQueueModel.id).where(
            JobQueueModel.tenant_id == self.tenant_id,
            JobQueueModel.status == "running",
        )
        result = await self.session.execute(query)
        return len(result.all())

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

        return {
            "pending": by_status.get("pending", 0),
            "running": by_status.get("running", 0),
            "completed": by_status.get("completed", 0),
            "failed": by_status.get("failed", 0),
            "cancelled": by_status.get("cancelled", 0),
            "failed_by_type": failed_by_type,
        }

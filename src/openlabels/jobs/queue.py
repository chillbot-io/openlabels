"""
PostgreSQL-backed job queue.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import JobQueue as JobQueueModel


class JobQueue:
    """PostgreSQL-backed job queue with priority support."""

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
        now = datetime.utcnow()

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
                completed_at=datetime.utcnow(),
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
        Mark a job as failed.

        Args:
            job_id: Job ID that failed
            error: Error message
            retry: Whether to retry the job
        """
        job = await self.session.get(JobQueueModel, job_id)
        if not job:
            return

        if retry and job.retry_count < job.max_retries:
            job.status = "pending"
            job.retry_count += 1
            job.worker_id = None
            job.error = error
        else:
            job.status = "failed"
            job.completed_at = datetime.utcnow()
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
        job.completed_at = datetime.utcnow()
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

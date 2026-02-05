"""
Job service for managing background job queue operations.

Provides a service-layer wrapper around JobQueue with:
- Tenant isolation
- Proper error handling with custom exceptions
- Logging
- Type hints and documentation
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.services.base import BaseService
from openlabels.server.models import JobQueue as JobQueueModel
from openlabels.server.exceptions import (
    NotFoundError,
    BadRequestError,
)
from openlabels.jobs.queue import JobQueue

logger = logging.getLogger(__name__)


class JobService(BaseService):
    """
    Service for managing background jobs.

    Wraps JobQueue with service-layer patterns including:
    - Consistent error handling via custom exceptions
    - Tenant isolation enforcement
    - Comprehensive logging
    - Pagination support for list operations

    Example:
        service = JobService(session, tenant_id)
        job_id = await service.enqueue("scan", {"target_id": str(target.id)})
        job = await service.get_job(job_id)
    """

    def __init__(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        user_id: Optional[UUID] = None,
    ):
        """
        Initialize the job service.

        Args:
            session: Database session for queries
            tenant_id: Tenant ID for data isolation
            user_id: Optional user ID for audit trails
        """
        super().__init__(session, tenant_id, user_id)
        self._queue = JobQueue(session, tenant_id)

    async def enqueue(
        self,
        task_type: str,
        payload: dict,
        priority: int = 50,
    ) -> UUID:
        """
        Add a job to the queue.

        Args:
            task_type: Type of task ('scan', 'label', 'export', 'label_sync')
            payload: Task-specific payload data
            priority: Priority 0-100 (higher = more urgent)

        Returns:
            Job ID

        Raises:
            BadRequestError: If task_type is invalid
        """
        valid_task_types = {"scan", "label", "export", "label_sync"}
        if task_type not in valid_task_types:
            raise BadRequestError(
                message=f"Invalid task type: {task_type}",
                details={"valid_types": list(valid_task_types)},
            )

        job_id = await self._queue.enqueue(
            task_type=task_type,
            payload=payload,
            priority=priority,
        )

        self._logger.info(
            f"Enqueued {task_type} job {job_id} for tenant {self.tenant_id} "
            f"(priority={priority})"
        )

        return job_id

    async def get_job(self, job_id: UUID) -> Optional[JobQueueModel]:
        """
        Get a job by ID.

        Args:
            job_id: The job ID to retrieve

        Returns:
            JobQueueModel if found, None otherwise

        Raises:
            NotFoundError: If job not found or belongs to another tenant
        """
        job = await self._queue.get_job(job_id)

        if not job:
            raise NotFoundError(
                message="Job not found",
                resource_type="Job",
                resource_id=str(job_id),
            )

        # Enforce tenant isolation
        if job.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Job not found",
                resource_type="Job",
                resource_id=str(job_id),
            )

        return job

    async def cancel_job(self, job_id: UUID) -> bool:
        """
        Cancel a pending or running job.

        Args:
            job_id: The job ID to cancel

        Returns:
            True if cancelled successfully

        Raises:
            NotFoundError: If job not found
            BadRequestError: If job cannot be cancelled (already completed/failed)
        """
        job = await self._queue.get_job(job_id)

        if not job or job.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Job not found",
                resource_type="Job",
                resource_id=str(job_id),
            )

        if job.status not in ("pending", "running"):
            raise BadRequestError(
                message=f"Cannot cancel job in {job.status} status",
                details={
                    "job_id": str(job_id),
                    "status": job.status,
                    "cancellable_statuses": ["pending", "running"],
                },
            )

        result = await self._queue.cancel(job_id)

        if result:
            self._logger.info(
                f"Cancelled job {job_id} for tenant {self.tenant_id}"
            )
        else:
            self._logger.warning(
                f"Failed to cancel job {job_id} for tenant {self.tenant_id}"
            )

        return result

    async def get_queue_stats(self) -> dict:
        """
        Get comprehensive queue statistics.

        Returns:
            Dictionary with job counts by status and task type:
                - pending: Number of pending jobs
                - running: Number of running jobs
                - completed: Number of completed jobs
                - failed: Number of failed jobs
                - cancelled: Number of cancelled jobs
                - failed_by_type: Dict of failed count per task type
        """
        stats = await self._queue.get_queue_stats()

        self._logger.debug(
            f"Queue stats for tenant {self.tenant_id}: "
            f"pending={stats['pending']}, running={stats['running']}, "
            f"failed={stats['failed']}"
        )

        return stats

    async def list_jobs(
        self,
        status: Optional[str] = None,
        task_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[JobQueueModel], int]:
        """
        List jobs with filtering and pagination.

        Args:
            status: Filter by status ('pending', 'running', 'completed', 'failed', 'cancelled')
            task_type: Filter by task type ('scan', 'label', 'export', 'label_sync')
            limit: Maximum number of jobs to return
            offset: Number of jobs to skip

        Returns:
            Tuple of (list of jobs, total count)
        """
        # Build filter conditions
        conditions = [JobQueueModel.tenant_id == self.tenant_id]

        if status:
            conditions.append(JobQueueModel.status == status)
        if task_type:
            conditions.append(JobQueueModel.task_type == task_type)

        # Get total count
        count_query = (
            select(func.count())
            .select_from(JobQueueModel)
            .where(and_(*conditions))
        )
        count_result = await self._session.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated jobs
        query = (
            select(JobQueueModel)
            .where(and_(*conditions))
            .order_by(
                JobQueueModel.priority.desc(),
                JobQueueModel.created_at.desc(),
            )
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(query)
        jobs = list(result.scalars().all())

        self._logger.debug(
            f"Listed {len(jobs)} jobs for tenant {self.tenant_id} "
            f"(status={status}, task_type={task_type}, offset={offset}, "
            f"limit={limit}, total={total})"
        )

        return jobs, total

    async def get_failed_jobs(
        self,
        task_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[JobQueueModel], int]:
        """
        Get failed jobs from the dead letter queue.

        Args:
            task_type: Filter by task type (optional)
            limit: Maximum number of jobs to return
            offset: Number of jobs to skip

        Returns:
            Tuple of (list of failed jobs, total count)
        """
        # Get total count
        total = await self._queue.get_failed_count(task_type)

        # Get paginated failed jobs
        jobs = await self._queue.get_failed_jobs(
            task_type=task_type,
            limit=limit,
            offset=offset,
        )

        self._logger.debug(
            f"Listed {len(jobs)} failed jobs for tenant {self.tenant_id} "
            f"(task_type={task_type}, offset={offset}, limit={limit}, total={total})"
        )

        return jobs, total

    async def requeue_failed(
        self,
        job_id: UUID,
        reset_retries: bool = True,
    ) -> bool:
        """
        Requeue a failed job from the dead letter queue.

        Args:
            job_id: ID of the failed job to requeue
            reset_retries: Whether to reset the retry count (default True)

        Returns:
            True if requeued successfully

        Raises:
            NotFoundError: If job not found
            BadRequestError: If job is not in failed status
        """
        job = await self._queue.get_job(job_id)

        if not job or job.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Job not found",
                resource_type="Job",
                resource_id=str(job_id),
            )

        if job.status != "failed":
            raise BadRequestError(
                message="Only failed jobs can be requeued",
                details={
                    "job_id": str(job_id),
                    "status": job.status,
                },
            )

        result = await self._queue.requeue_failed(
            job_id=job_id,
            reset_retries=reset_retries,
        )

        if result:
            self._logger.info(
                f"Requeued failed job {job_id} for tenant {self.tenant_id} "
                f"(reset_retries={reset_retries})"
            )
        else:
            self._logger.warning(
                f"Failed to requeue job {job_id} for tenant {self.tenant_id}"
            )

        return result

    async def requeue_all_failed(
        self,
        task_type: Optional[str] = None,
        reset_retries: bool = True,
    ) -> int:
        """
        Requeue all failed jobs of a specific type.

        Args:
            task_type: Filter by task type (requeue all if None)
            reset_retries: Whether to reset retry counts

        Returns:
            Number of jobs requeued
        """
        count = await self._queue.requeue_all_failed(
            task_type=task_type,
            reset_retries=reset_retries,
        )

        self._logger.info(
            f"Requeued {count} failed jobs for tenant {self.tenant_id} "
            f"(task_type={task_type}, reset_retries={reset_retries})"
        )

        return count

    async def purge_failed(
        self,
        task_type: Optional[str] = None,
        older_than_days: Optional[int] = None,
    ) -> int:
        """
        Delete failed jobs from the dead letter queue.

        Args:
            task_type: Filter by task type (optional)
            older_than_days: Only delete jobs older than N days (optional)

        Returns:
            Number of jobs deleted
        """
        count = await self._queue.purge_failed(
            task_type=task_type,
            older_than_days=older_than_days,
        )

        self._logger.info(
            f"Purged {count} failed jobs for tenant {self.tenant_id} "
            f"(task_type={task_type}, older_than_days={older_than_days})"
        )

        return count

    async def cleanup_expired(
        self,
        completed_ttl_days: Optional[int] = None,
        failed_ttl_days: Optional[int] = None,
    ) -> dict[str, int]:
        """
        Clean up expired jobs based on TTL.

        Args:
            completed_ttl_days: Days to keep completed jobs
            failed_ttl_days: Days to keep failed jobs

        Returns:
            Dictionary with counts of deleted jobs by status
        """
        result = await self._queue.cleanup_expired_jobs(
            completed_ttl_days=completed_ttl_days,
            failed_ttl_days=failed_ttl_days,
        )

        total = sum(result.values())
        if total > 0:
            self._logger.info(
                f"Cleaned up {total} expired jobs for tenant {self.tenant_id}: "
                f"{result}"
            )

        return result

    async def reclaim_stuck(
        self,
        timeout_seconds: int = 3600,
    ) -> int:
        """
        Reclaim jobs stuck in running state.

        Jobs that have been running longer than timeout_seconds are
        considered stuck (likely from crashed workers) and are reclaimed.

        Args:
            timeout_seconds: Jobs running longer than this are reclaimed

        Returns:
            Number of jobs reclaimed
        """
        count = await self._queue.reclaim_stuck_jobs(
            timeout_seconds=timeout_seconds,
        )

        if count > 0:
            self._logger.info(
                f"Reclaimed {count} stuck jobs for tenant {self.tenant_id} "
                f"(timeout={timeout_seconds}s)"
            )

        return count

    async def get_age_stats(self) -> dict:
        """
        Get statistics about job ages for monitoring.

        Returns:
            Dictionary with age statistics by status:
                - pending: {count, oldest_hours, avg_hours}
                - running: {count, oldest_hours, avg_hours}
        """
        return await self._queue.get_job_age_stats()

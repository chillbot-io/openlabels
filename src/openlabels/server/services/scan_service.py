"""
Scan service for managing scan jobs.

Encapsulates all business logic related to scans including:
- Creating scan jobs
- Listing and filtering scans
- Cancelling and retrying scans
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import ScanJob, ScanTarget
from openlabels.server.exceptions import NotFoundError, BadRequestError
from openlabels.jobs import JobQueue

logger = logging.getLogger(__name__)


class ScanService:
    """Service for managing scan jobs."""

    def __init__(self, session: AsyncSession, tenant_id: UUID, user_id: UUID):
        """
        Initialize the scan service.

        Args:
            session: Database session
            tenant_id: Current tenant ID
            user_id: Current user ID
        """
        self.session = session
        self.tenant_id = tenant_id
        self.user_id = user_id

    async def create_scan(
        self,
        target_id: UUID,
        name: Optional[str] = None,
    ) -> ScanJob:
        """
        Create a new scan job.

        Args:
            target_id: ID of the target to scan
            name: Optional name for the scan job

        Returns:
            Created ScanJob instance

        Raises:
            NotFoundError: If target not found or doesn't belong to tenant
        """
        # Verify target exists AND belongs to user's tenant (prevent cross-tenant access)
        target = await self.session.get(ScanTarget, target_id)
        if not target or target.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Target not found",
                resource_type="ScanTarget",
                resource_id=str(target_id),
            )

        # Create scan job
        job = ScanJob(
            tenant_id=self.tenant_id,
            target_id=target_id,
            name=name or f"Scan: {target.name}",
            status="pending",
            created_by=self.user_id,
        )
        self.session.add(job)
        await self.session.flush()

        # Enqueue the job in the job queue
        queue = JobQueue(self.session, self.tenant_id)
        await queue.enqueue(
            task_type="scan",
            payload={"job_id": str(job.id)},
            priority=50,
        )

        # Refresh to load server-generated defaults (created_at)
        await self.session.refresh(job)

        return job

    async def list_scans(
        self,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[ScanJob], int]:
        """
        List scan jobs with pagination.

        Args:
            status: Optional status filter
            page: Page number (1-indexed)
            page_size: Number of items per page

        Returns:
            Tuple of (list of ScanJob instances, total count)
        """
        # Build base conditions
        conditions = [ScanJob.tenant_id == self.tenant_id]
        if status:
            conditions.append(ScanJob.status == status)

        # Count total using SQL COUNT (efficient, no row loading)
        count_query = select(func.count()).select_from(ScanJob).where(*conditions)
        count_result = await self.session.execute(count_query)
        total = count_result.scalar() or 0

        # Calculate offset
        offset = (page - 1) * page_size

        # Get paginated results
        query = (
            select(ScanJob)
            .where(*conditions)
            .order_by(ScanJob.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        result = await self.session.execute(query)
        jobs = list(result.scalars().all())

        return jobs, total

    async def get_scan(self, scan_id: UUID) -> ScanJob:
        """
        Get scan job by ID.

        Args:
            scan_id: Scan job ID

        Returns:
            ScanJob instance

        Raises:
            NotFoundError: If scan not found or doesn't belong to tenant
        """
        job = await self.session.get(ScanJob, scan_id)
        if not job or job.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Scan not found",
                resource_type="ScanJob",
                resource_id=str(scan_id),
            )
        return job

    async def cancel_scan(self, scan_id: UUID) -> ScanJob:
        """
        Cancel a pending or running scan.

        Args:
            scan_id: Scan job ID

        Returns:
            Updated ScanJob instance

        Raises:
            NotFoundError: If scan not found
            BadRequestError: If scan cannot be cancelled
        """
        job = await self.get_scan(scan_id)

        if job.status not in ("pending", "running"):
            raise BadRequestError(
                message="Scan cannot be cancelled",
                details={"current_status": job.status, "allowed_statuses": ["pending", "running"]},
            )

        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        await self.session.flush()

        return job

    async def retry_scan(self, scan_id: UUID) -> ScanJob:
        """
        Retry a failed or cancelled scan.

        Args:
            scan_id: Scan job ID to retry

        Returns:
            New ScanJob instance

        Raises:
            NotFoundError: If scan or target not found
            BadRequestError: If scan cannot be retried
        """
        job = await self.get_scan(scan_id)

        if job.status not in ("failed", "cancelled"):
            raise BadRequestError(
                message="Only failed or cancelled scans can be retried",
                details={"current_status": job.status, "allowed_statuses": ["failed", "cancelled"]},
            )

        # Get the target
        target = await self.session.get(ScanTarget, job.target_id)
        if not target:
            raise NotFoundError(
                message="Target no longer exists",
                resource_type="ScanTarget",
                resource_id=str(job.target_id),
            )

        # Create a new scan job
        new_job = ScanJob(
            tenant_id=self.tenant_id,
            target_id=job.target_id,
            target_name=target.name,
            name=f"{job.name} (retry)",
            status="pending",
            created_by=self.user_id,
        )
        self.session.add(new_job)
        await self.session.flush()

        # Enqueue the job
        queue = JobQueue(self.session, self.tenant_id)
        await queue.enqueue(
            task_type="scan",
            payload={"job_id": str(new_job.id)},
            priority=60,  # Slightly higher priority for retries
        )

        return new_job

    async def delete_scan(self, scan_id: UUID) -> None:
        """
        Delete/cancel a scan job (same as cancel_scan).

        Args:
            scan_id: Scan job ID

        Raises:
            NotFoundError: If scan not found
            BadRequestError: If scan cannot be cancelled
        """
        await self.cancel_scan(scan_id)

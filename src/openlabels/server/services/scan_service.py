"""
Scan service for managing scan jobs.

Encapsulates all business logic for scan operations:
- Creating new scans
- Retrieving scan status
- Listing scans with filtering and pagination
- Cancelling and retrying scans
- Deleting scans

Example usage in a route:
    @router.post("")
    async def create_scan(
        request: ScanCreate,
        session: AsyncSession = Depends(get_session),
        user: CurrentUser = Depends(require_admin),
    ) -> ScanResponse:
        settings = get_settings()
        tenant = TenantContext.from_current_user(user)
        service = ScanService(session, tenant, settings)
        job = await service.create_scan(request.target_id, request.name)
        return ScanResponse.model_validate(job)
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import delete, func, select

from openlabels.jobs import JobQueue
from openlabels.server.exceptions import BadRequestError, NotFoundError
from openlabels.server.models import ScanJob, ScanTarget
from openlabels.server.services.base import BaseService


class ScanService(BaseService):
    """
    Service for scan job management.

    Provides methods for creating, retrieving, listing, cancelling,
    retrying, and deleting scan jobs. All operations are tenant-isolated.

    This service extends BaseService to inherit:
    - Database session management
    - Tenant context for isolation
    - Settings access
    - Logging utilities

    Attributes:
        session: Async database session (from BaseService)
        tenant_id: Current tenant UUID (from BaseService)
        user_id: Current user UUID (from BaseService)
        settings: Application settings (from BaseService)
    """

    async def _get_target_or_raise(self, target_id: UUID) -> ScanTarget:
        """
        Get a scan target by ID, ensuring tenant isolation.

        Args:
            target_id: UUID of the target to retrieve

        Returns:
            ScanTarget if found and belongs to current tenant

        Raises:
            NotFoundError: If target not found or belongs to different tenant
        """
        target = await self.session.get(ScanTarget, target_id)
        if not target or target.tenant_id != self.tenant_id:
            self._log_warning(
                f"Target not found: {target_id}",
                target_id=str(target_id),
            )
            raise NotFoundError(
                message="Target not found",
                resource_type="ScanTarget",
                resource_id=str(target_id),
            )
        return target

    async def _get_scan_or_raise(self, scan_id: UUID) -> ScanJob:
        """
        Get a scan job by ID, ensuring tenant isolation.

        Args:
            scan_id: UUID of the scan to retrieve

        Returns:
            ScanJob if found and belongs to current tenant

        Raises:
            NotFoundError: If scan not found or belongs to different tenant
        """
        job = await self.session.get(ScanJob, scan_id)
        if not job or job.tenant_id != self.tenant_id:
            self._log_warning(
                f"Scan not found: {scan_id}",
                scan_id=str(scan_id),
            )
            raise NotFoundError(
                message="Scan not found",
                resource_type="ScanJob",
                resource_id=str(scan_id),
            )
        return job

    async def create_scan(
        self,
        target_id: UUID,
        name: Optional[str] = None,
    ) -> ScanJob:
        """
        Create a new scan job for a target.

        Creates a scan job in 'pending' status and enqueues it
        for processing by the job worker.

        Args:
            target_id: UUID of the target to scan
            name: Optional name for the scan (defaults to "Scan: {target.name}")

        Returns:
            The created ScanJob with status 'pending'

        Raises:
            NotFoundError: If target_id does not exist or belongs to different tenant
        """
        # Verify target exists and belongs to tenant
        target = await self._get_target_or_raise(target_id)

        # Create scan job
        job = ScanJob(
            tenant_id=self.tenant_id,
            target_id=target_id,
            target_name=target.name,
            name=name or f"Scan: {target.name}",
            status="pending",
            created_by=self.user_id,
        )
        self.session.add(job)
        await self.flush()

        self._log_info(
            f"Created scan job {job.id} for target {target.name}",
            job_id=str(job.id),
            target_id=str(target_id),
        )

        # Enqueue the job for processing
        queue = JobQueue(self.session, self.tenant_id)
        await queue.enqueue(
            task_type="scan",
            payload={"job_id": str(job.id)},
            priority=50,
        )

        # Refresh to load server-generated defaults
        await self.session.refresh(job)

        return job

    async def get_scan(self, scan_id: UUID) -> ScanJob:
        """
        Get a scan job by ID.

        Args:
            scan_id: UUID of the scan to retrieve

        Returns:
            ScanJob if found

        Raises:
            NotFoundError: If scan not found or belongs to different tenant
        """
        return await self._get_scan_or_raise(scan_id)

    async def list_scans(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ScanJob], int]:
        """
        List scan jobs with optional filtering and pagination.

        Args:
            status: Optional status filter ('pending', 'running', 'completed', 'failed', 'cancelled')
            limit: Maximum number of results to return (default 50)
            offset: Number of results to skip (default 0)

        Returns:
            Tuple of (list of ScanJob objects, total count)
        """
        # Build base conditions
        conditions = [ScanJob.tenant_id == self.tenant_id]
        if status:
            conditions.append(ScanJob.status == status)

        # Get total count using efficient SQL COUNT
        count_query = select(func.count()).select_from(ScanJob).where(*conditions)
        count_result = await self.session.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated results
        query = (
            select(ScanJob)
            .where(*conditions)
            .order_by(ScanJob.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(query)
        jobs = list(result.scalars().all())

        self._log_debug(
            f"Listed {len(jobs)} scans (total: {total})",
            status_filter=status,
            limit=limit,
            offset=offset,
        )

        return jobs, total

    async def cancel_scan(self, scan_id: UUID) -> ScanJob:
        """
        Cancel a pending or running scan.

        Args:
            scan_id: UUID of the scan to cancel

        Returns:
            Updated ScanJob with status 'cancelled'

        Raises:
            NotFoundError: If scan not found or belongs to different tenant
            BadRequestError: If scan is not in a cancellable state
        """
        job = await self._get_scan_or_raise(scan_id)

        if job.status not in ("pending", "running"):
            self._log_warning(
                f"Cannot cancel scan {scan_id}: status is {job.status}",
                scan_id=str(scan_id),
                current_status=job.status,
            )
            raise BadRequestError(
                message="Scan cannot be cancelled",
                details={
                    "current_status": job.status,
                    "allowed_statuses": ["pending", "running"],
                },
            )

        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        await self.flush()

        self._log_info(
            f"Cancelled scan {scan_id}",
            scan_id=str(scan_id),
        )

        return job

    async def retry_scan(self, scan_id: UUID) -> ScanJob:
        """
        Retry a failed or cancelled scan by creating a new scan job.

        Creates a new scan job for the same target with slightly
        higher priority. The original scan is not modified.

        Args:
            scan_id: UUID of the scan to retry

        Returns:
            New ScanJob with status 'pending'

        Raises:
            NotFoundError: If scan not found, target no longer exists,
                          or belongs to different tenant
            BadRequestError: If scan is not in a retryable state
        """
        job = await self._get_scan_or_raise(scan_id)

        if job.status not in ("failed", "cancelled"):
            self._log_warning(
                f"Cannot retry scan {scan_id}: status is {job.status}",
                scan_id=str(scan_id),
                current_status=job.status,
            )
            raise BadRequestError(
                message="Only failed or cancelled scans can be retried",
                details={
                    "current_status": job.status,
                    "allowed_statuses": ["failed", "cancelled"],
                },
            )

        # Verify target still exists
        target = await self.session.get(ScanTarget, job.target_id)
        if not target:
            self._log_warning(
                f"Cannot retry scan {scan_id}: target {job.target_id} no longer exists",
                scan_id=str(scan_id),
                target_id=str(job.target_id),
            )
            raise NotFoundError(
                message="Target no longer exists",
                resource_type="ScanTarget",
                resource_id=str(job.target_id),
            )

        # Create a new scan job for retry
        new_job = ScanJob(
            tenant_id=self.tenant_id,
            target_id=job.target_id,
            target_name=target.name,
            name=f"{job.name} (retry)",
            status="pending",
            created_by=self.user_id,
        )
        self.session.add(new_job)
        await self.flush()

        self._log_info(
            f"Created retry scan {new_job.id} for original scan {scan_id}",
            new_job_id=str(new_job.id),
            original_job_id=str(scan_id),
            target_id=str(job.target_id),
        )

        # Enqueue with slightly higher priority for retries
        queue = JobQueue(self.session, self.tenant_id)
        await queue.enqueue(
            task_type="scan",
            payload={"job_id": str(new_job.id)},
            priority=60,  # Higher priority for retries
        )

        await self.session.refresh(new_job)

        return new_job

    async def delete_scan(self, scan_id: UUID) -> bool:
        """
        Delete a scan job.

        Only completed, failed, or cancelled scans can be deleted.
        Pending or running scans must be cancelled first.

        Args:
            scan_id: UUID of the scan to delete

        Returns:
            True if deleted successfully

        Raises:
            NotFoundError: If scan not found or belongs to different tenant
            BadRequestError: If scan is pending or running
        """
        job = await self._get_scan_or_raise(scan_id)

        if job.status in ("pending", "running"):
            self._log_warning(
                f"Cannot delete scan {scan_id}: status is {job.status}",
                scan_id=str(scan_id),
                current_status=job.status,
            )
            raise BadRequestError(
                message="Cannot delete pending or running scans. Cancel first.",
                details={
                    "current_status": job.status,
                    "suggestion": "Cancel the scan before deleting",
                },
            )

        self.session.delete(job)  # delete() is synchronous
        await self.flush()

        self._log_info(
            f"Deleted scan {scan_id}",
            scan_id=str(scan_id),
        )

        return True

    async def get_scan_stats(self) -> dict[str, int]:
        """
        Get scan statistics for the current tenant.

        Returns:
            Dictionary with counts by status:
            {
                "pending": 5,
                "running": 2,
                "completed": 100,
                "failed": 3,
                "cancelled": 1,
                "total": 111
            }
        """
        # Get counts by status using efficient SQL aggregation
        query = (
            select(ScanJob.status, func.count())
            .where(ScanJob.tenant_id == self.tenant_id)
            .group_by(ScanJob.status)
        )
        result = await self.session.execute(query)
        by_status = dict(result.all())

        stats = {
            "pending": by_status.get("pending", 0),
            "running": by_status.get("running", 0),
            "completed": by_status.get("completed", 0),
            "failed": by_status.get("failed", 0),
            "cancelled": by_status.get("cancelled", 0),
        }
        stats["total"] = sum(stats.values())

        return stats

    async def get_recent_scans(self, limit: int = 5) -> list[ScanJob]:
        """
        Get the most recent scan jobs for the dashboard.

        Args:
            limit: Maximum number of scans to return (default 5)

        Returns:
            List of most recent ScanJob objects
        """
        query = (
            select(ScanJob)
            .where(ScanJob.tenant_id == self.tenant_id)
            .order_by(ScanJob.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_active_scans(self) -> list[ScanJob]:
        """
        Get all active (pending or running) scans.

        Returns:
            List of ScanJob objects with status 'pending' or 'running'
        """
        query = (
            select(ScanJob)
            .where(
                ScanJob.tenant_id == self.tenant_id,
                ScanJob.status.in_(["pending", "running"]),
            )
            .order_by(ScanJob.created_at.desc())
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def cleanup_old_scans(
        self,
        days: int = 30,
        status: Optional[str] = None,
    ) -> int:
        """
        Delete scan jobs older than specified days.

        Args:
            days: Delete scans older than this many days (default 30)
            status: Optional status filter (e.g., 'completed', 'failed')
                   If None, only deletes completed and cancelled scans.

        Returns:
            Number of scans deleted
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        conditions = [
            ScanJob.tenant_id == self.tenant_id,
            ScanJob.created_at < cutoff,
        ]

        if status:
            conditions.append(ScanJob.status == status)
        else:
            # Default: only clean up terminal states
            conditions.append(ScanJob.status.in_(["completed", "cancelled"]))

        stmt = delete(ScanJob).where(*conditions)
        result = await self.session.execute(stmt)
        await self.flush()

        count = result.rowcount
        if count > 0:
            self._log_info(
                f"Cleaned up {count} old scans (older than {days} days)",
                deleted_count=count,
                days=days,
                status_filter=status,
            )

        return count

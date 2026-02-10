"""Scan job management service."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete, func, select

from openlabels.exceptions import BadRequestError, NotFoundError
from openlabels.jobs import JobQueue
from openlabels.server.models import ScanJob, ScanTarget
from openlabels.server.services.base import BaseService


class ScanService(BaseService):
    """Scan job CRUD, cancellation, retry, and statistics. Tenant-isolated."""

    async def create_scan(
        self,
        target_id: UUID,
        name: str | None = None,
    ) -> ScanJob:
        """Create a scan job in 'pending' status and enqueue it."""
        target = await self.get_tenant_entity(ScanTarget, target_id, "ScanTarget")

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

        queue = JobQueue(self.session, self.tenant_id)
        await queue.enqueue(
            task_type="scan",
            payload={"job_id": str(job.id)},
            priority=50,
        )

        await self.session.refresh(job)

        return job

    async def get_scan(self, scan_id: UUID) -> ScanJob:
        """Get a scan job by ID (tenant-isolated)."""
        return await self.get_tenant_entity(ScanJob, scan_id, "ScanJob")

    async def list_scans(
        self,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ScanJob], int]:
        """List scan jobs with optional status filter and pagination."""
        VALID_STATUSES = {"pending", "running", "completed", "failed", "cancelled"}
        conditions = [ScanJob.tenant_id == self.tenant_id]
        if status:
            if status not in VALID_STATUSES:
                # Return empty results for invalid status values rather than
                # letting invalid enum values reach PostgreSQL
                return [], 0
            conditions.append(ScanJob.status == status)

        count_query = select(func.count()).select_from(ScanJob).where(*conditions)
        count_result = await self.session.execute(count_query)
        total = count_result.scalar() or 0

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
        """Cancel a pending or running scan."""
        job = await self.get_tenant_entity(ScanJob, scan_id, "ScanJob")

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
        """Create a new scan job for the same target with higher priority."""
        job = await self.get_tenant_entity(ScanJob, scan_id, "ScanJob")

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

        queue = JobQueue(self.session, self.tenant_id)
        await queue.enqueue(
            task_type="scan",
            payload={"job_id": str(new_job.id)},
            priority=60,  # Higher priority for retries
        )

        await self.session.refresh(new_job)

        return new_job

    async def delete_scan(self, scan_id: UUID) -> bool:
        """Delete a completed/failed/cancelled scan. Active scans must be cancelled first."""
        job = await self.get_tenant_entity(ScanJob, scan_id, "ScanJob")

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
        """Return scan counts grouped by status for the current tenant."""
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
        status: str | None = None,
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

"""
Label service for managing sensitivity labels and label rules.

Provides:
- List and retrieve sensitivity labels
- Sync labels from Microsoft 365
- CRUD operations for label rules
- Bulk label application to scan results
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import delete as sa_delete, select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from openlabels.server.services.base import BaseService, TenantContext
from openlabels.server.config import Settings
from openlabels.server.models import SensitivityLabel, LabelRule, ScanResult
from openlabels.server.exceptions import (
    NotFoundError,
    ValidationError,
    BadRequestError,
    InternalError,
)

logger = logging.getLogger(__name__)


class LabelService(BaseService):
    """
    Service for managing sensitivity labels and label rules.

    Provides methods for:
    - Listing and retrieving labels
    - Triggering label sync from M365
    - Managing label rules (CRUD)
    - Bulk applying labels to scan results

    All operations are tenant-isolated.

    Example:
        context = TenantContext.from_current_user(user)
        service = LabelService(session, context, settings)
        labels, total = await service.list_labels(limit=10, offset=0)
    """

    def __init__(
        self,
        session: AsyncSession,
        tenant: TenantContext,
        settings: Settings,
    ):
        """
        Initialize the label service.

        Args:
            session: Async database session for queries
            tenant: Tenant context for data isolation
            settings: Application settings
        """
        super().__init__(session, tenant, settings)

    async def list_labels(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SensitivityLabel], int]:
        """
        List sensitivity labels with pagination.

        Args:
            limit: Maximum number of labels to return
            offset: Number of labels to skip

        Returns:
            Tuple of (list of labels, total count)
        """
        # Get total count
        count_query = (
            select(func.count())
            .select_from(SensitivityLabel)
            .where(SensitivityLabel.tenant_id == self.tenant_id)
        )
        count_result = await self.session.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated labels
        query = (
            select(SensitivityLabel)
            .where(SensitivityLabel.tenant_id == self.tenant_id)
            .order_by(SensitivityLabel.priority)
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(query)
        labels = list(result.scalars().all())

        self._log_debug(
            f"Listed {len(labels)} labels (offset={offset}, limit={limit}, total={total})"
        )

        return labels, total

    async def get_label(self, label_id: str) -> SensitivityLabel:
        """
        Get a sensitivity label by ID.

        Args:
            label_id: The label ID (MIP GUID)

        Returns:
            The sensitivity label

        Raises:
            NotFoundError: If label not found or belongs to another tenant
        """
        label = await self.session.get(SensitivityLabel, label_id)

        if not label or label.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Label not found",
                resource_type="SensitivityLabel",
                resource_id=label_id,
            )

        return label

    async def sync_labels(self, background: bool = True) -> dict:
        """
        Trigger label sync from Microsoft 365.

        Args:
            background: If True, runs sync as a background job

        Returns:
            Dictionary with sync status and job info

        Raises:
            BadRequestError: If Azure AD is not configured
            InternalError: If sync fails
        """
        auth = self.settings.auth

        # Check Azure AD configuration
        if auth.provider != "azure_ad" or not all([
            auth.tenant_id,
            auth.client_id,
            auth.client_secret,
        ]):
            raise BadRequestError(
                message="Azure AD not configured - cannot sync labels from M365",
                details={"provider": auth.provider},
            )

        if background:
            # Enqueue sync job
            from openlabels.jobs import JobQueue

            queue = JobQueue(self.session, self.tenant_id)
            job_id = await queue.enqueue(
                task_type="label_sync",
                payload={
                    "tenant_id": str(self.tenant_id),
                    "azure_tenant_id": auth.tenant_id,
                    "client_id": auth.client_id,
                    "client_secret": auth.client_secret,
                    "remove_stale": False,
                },
                priority=70,  # High priority
            )

            self._log_info(f"Queued label sync job {job_id}")

            return {
                "message": "Label sync job queued",
                "job_id": str(job_id),
                "background": True,
            }

        # Immediate sync
        try:
            from openlabels.jobs.tasks.label_sync import sync_labels_from_graph

            result = await sync_labels_from_graph(
                session=self.session,
                tenant_id=self.tenant_id,
                azure_tenant_id=auth.tenant_id,
                client_id=auth.client_id,
                client_secret=auth.client_secret,
                remove_stale=False,
            )

            await self.commit()

            # Invalidate caches
            self._invalidate_label_caches()

            self._log_info(f"Completed immediate label sync: {result.to_dict()}")

            return {
                "message": "Label sync completed",
                **result.to_dict(),
            }

        except Exception as e:
            self._log_error(f"Label sync failed: {e}")
            raise InternalError(
                message=f"Label sync failed: {str(e)}",
            )

    def _invalidate_label_caches(self) -> None:
        """Invalidate all label-related caches. Failures are logged but not raised."""
        # Invalidate internal label cache
        try:
            from openlabels.labeling.engine import get_label_cache
            get_label_cache().invalidate()
        except Exception as e:
            self._log_info(f"Failed to invalidate label cache: {type(e).__name__}: {e}")

        # Note: Redis cache invalidation is handled by the route layer
        # as it requires async operations

    async def get_label_rules(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[LabelRule], int]:
        """
        List label rules with pagination.

        Args:
            limit: Maximum number of rules to return
            offset: Number of rules to skip

        Returns:
            Tuple of (list of rules, total count)
        """
        # Get total count
        count_query = (
            select(func.count())
            .select_from(LabelRule)
            .where(LabelRule.tenant_id == self.tenant_id)
        )
        count_result = await self.session.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated rules with label names via JOIN
        query = (
            select(LabelRule)
            .options(selectinload(LabelRule.label))
            .where(LabelRule.tenant_id == self.tenant_id)
            .order_by(LabelRule.priority.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(query)
        rules = list(result.scalars().all())

        self._log_debug(
            f"Listed {len(rules)} label rules (offset={offset}, limit={limit}, total={total})"
        )

        return rules, total

    async def create_label_rule(self, rule_data: dict) -> LabelRule:
        """
        Create a new label rule.

        Args:
            rule_data: Dictionary containing:
                - rule_type: 'risk_tier' | 'entity_type'
                - match_value: Value to match (e.g., 'CRITICAL', 'SSN')
                - label_id: ID of the label to apply
                - priority: Rule priority (optional, default 0)

        Returns:
            The created LabelRule

        Raises:
            ValidationError: If rule_type is invalid
            NotFoundError: If label_id doesn't exist
        """
        rule_type = rule_data.get("rule_type")
        if rule_type not in ("risk_tier", "entity_type"):
            raise ValidationError(
                message="Invalid rule type",
                field="rule_type",
                reason="Must be 'risk_tier' or 'entity_type'",
            )

        label_id = rule_data.get("label_id")
        if not label_id:
            raise ValidationError(
                message="Label ID is required",
                field="label_id",
            )

        # Verify label exists and belongs to tenant
        label = await self.session.get(SensitivityLabel, label_id)
        if not label or label.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Label not found",
                resource_type="SensitivityLabel",
                resource_id=label_id,
            )

        rule = LabelRule(
            tenant_id=self.tenant_id,
            rule_type=rule_type,
            match_value=rule_data.get("match_value", ""),
            label_id=label_id,
            priority=rule_data.get("priority", 0),
            created_by=self.user_id,
        )

        self.session.add(rule)
        await self.flush()
        await self.session.refresh(rule)

        self._log_info(
            f"Created label rule {rule.id}: {rule_type}={rule.match_value} -> {label_id}"
        )

        return rule

    async def update_label_rule(
        self,
        rule_id: UUID,
        rule_data: dict,
    ) -> LabelRule:
        """
        Update an existing label rule.

        Args:
            rule_id: ID of the rule to update
            rule_data: Dictionary with fields to update:
                - rule_type: 'risk_tier' | 'entity_type' (optional)
                - match_value: Value to match (optional)
                - label_id: ID of the label (optional)
                - priority: Rule priority (optional)

        Returns:
            The updated LabelRule

        Raises:
            NotFoundError: If rule not found
            ValidationError: If rule_type is invalid
            NotFoundError: If new label_id doesn't exist
        """
        rule = await self.session.get(LabelRule, rule_id)
        if not rule or rule.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Label rule not found",
                resource_type="LabelRule",
                resource_id=str(rule_id),
            )

        # Validate rule_type if provided
        if "rule_type" in rule_data:
            rule_type = rule_data["rule_type"]
            if rule_type not in ("risk_tier", "entity_type"):
                raise ValidationError(
                    message="Invalid rule type",
                    field="rule_type",
                    reason="Must be 'risk_tier' or 'entity_type'",
                )
            rule.rule_type = rule_type

        # Validate label_id if provided
        if "label_id" in rule_data:
            label_id = rule_data["label_id"]
            label = await self.session.get(SensitivityLabel, label_id)
            if not label or label.tenant_id != self.tenant_id:
                raise NotFoundError(
                    message="Label not found",
                    resource_type="SensitivityLabel",
                    resource_id=label_id,
                )
            rule.label_id = label_id

        # Update other fields
        if "match_value" in rule_data:
            rule.match_value = rule_data["match_value"]
        if "priority" in rule_data:
            rule.priority = rule_data["priority"]

        await self.flush()

        self._log_info(f"Updated label rule {rule_id}")

        return rule

    async def delete_label_rule(self, rule_id: UUID) -> bool:
        """
        Delete a label rule.

        Args:
            rule_id: ID of the rule to delete

        Returns:
            True if deleted successfully

        Raises:
            NotFoundError: If rule not found
        """
        result = await self.session.execute(
            sa_delete(LabelRule).where(
                LabelRule.id == rule_id,
                LabelRule.tenant_id == self.tenant_id,
            )
        )
        if result.rowcount == 0:
            raise NotFoundError(
                message="Label rule not found",
                resource_type="LabelRule",
                resource_id=str(rule_id),
            )
        await self.flush()

        self._log_info(f"Deleted label rule {rule_id}")

        return True

    async def bulk_apply_labels(
        self,
        result_ids: list[UUID],
        label_id: str,
        chunk_size: int = 100,
    ) -> dict:
        """
        Bulk apply a label to multiple scan results.

        Processes results in chunks to avoid memory issues with large batches.
        Creates background jobs for each result to apply the label.

        Args:
            result_ids: List of scan result IDs to label
            label_id: ID of the label to apply
            chunk_size: Number of results to process per chunk

        Returns:
            Dictionary with counts:
                - success: Number of jobs queued successfully
                - failed: Number of results that failed to queue
                - skipped: Number of results skipped (not found or wrong tenant)
        """
        from openlabels.jobs import JobQueue

        # Verify label exists
        label = await self.session.get(SensitivityLabel, label_id)
        if not label or label.tenant_id != self.tenant_id:
            raise NotFoundError(
                message="Label not found",
                resource_type="SensitivityLabel",
                resource_id=label_id,
            )

        queue = JobQueue(self.session, self.tenant_id)

        success_count = 0
        failed_count = 0
        skipped_count = 0

        # Process in chunks
        for i in range(0, len(result_ids), chunk_size):
            chunk = result_ids[i:i + chunk_size]

            # Batch fetch results for this chunk
            results_query = (
                select(ScanResult)
                .where(
                    and_(
                        ScanResult.id.in_(chunk),
                        ScanResult.tenant_id == self.tenant_id,
                    )
                )
            )
            result = await self.session.execute(results_query)
            results = {r.id: r for r in result.scalars().all()}

            for result_id in chunk:
                scan_result = results.get(result_id)

                if not scan_result:
                    skipped_count += 1
                    self._log_debug(f"Skipped result {result_id}: not found or wrong tenant")
                    continue

                try:
                    await queue.enqueue(
                        task_type="label",
                        payload={
                            "result_id": str(result_id),
                            "label_id": label_id,
                            "file_path": scan_result.file_path,
                        },
                        priority=60,  # Higher priority than scans
                    )
                    success_count += 1

                except Exception as e:
                    failed_count += 1
                    self._log_error(f"Failed to queue label job for result {result_id}: {e}")

        self._log_info(
            f"Bulk label application: success={success_count}, "
            f"failed={failed_count}, skipped={skipped_count}"
        )

        return {
            "success": success_count,
            "failed": failed_count,
            "skipped": skipped_count,
        }

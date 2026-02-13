"""
Label synchronization task implementation.

Syncs sensitivity labels from Microsoft 365 to the local database.
Runs on a schedule or on-demand via API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.labeling.engine import create_labeling_engine
from openlabels.server.models import SensitivityLabel

logger = logging.getLogger(__name__)


class LabelSyncResult:
    """Result of a label sync operation."""

    def __init__(self):
        self.labels_synced = 0
        self.labels_added = 0
        self.labels_updated = 0
        self.labels_removed = 0
        self.errors: list[str] = []

    def to_dict(self) -> dict:
        return {
            "labels_synced": self.labels_synced,
            "labels_added": self.labels_added,
            "labels_updated": self.labels_updated,
            "labels_removed": self.labels_removed,
            "errors": self.errors,
        }


async def execute_label_sync_task(
    session: AsyncSession,
    payload: dict,
) -> dict:
    """
    Execute a label synchronization task.

    Args:
        session: Database session
        payload: Task payload containing tenant_id (credentials fetched from settings)

    Returns:
        Result dictionary with sync statistics

    Security Note:
        Credentials are NEVER passed via payload to prevent them from being
        logged, stored in job history, or exposed via job status APIs.
        All credentials are fetched from secure settings at execution time.
    """
    tenant_id = UUID(payload["tenant_id"])

    # SECURITY: Always get credentials from settings, never from payload
    # This prevents credentials from being logged or stored in job payloads
    try:
        from openlabels.server.config import get_settings
        settings = get_settings()
        auth = settings.auth

        if auth.provider != "azure_ad":
            return {
                "success": False,
                "error": "Azure AD not configured - cannot sync labels",
                **LabelSyncResult().to_dict(),
            }

        if not all([auth.tenant_id, auth.client_id, auth.client_secret]):
            return {
                "success": False,
                "error": "Azure AD credentials not configured - check AUTH_TENANT_ID, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET",
                **LabelSyncResult().to_dict(),
            }
    except (ImportError, RuntimeError, AttributeError) as e:
        logger.error(f"Failed to get settings for label sync: {e}")
        return {
            "success": False,
            "error": "Failed to retrieve credentials from settings",
            **LabelSyncResult().to_dict(),
        }

    logger.info(f"Starting label sync for tenant {tenant_id}")

    result = await sync_labels_from_graph(
        session=session,
        tenant_id=tenant_id,
        remove_stale=payload.get("remove_stale", False),
    )

    return {
        "success": len(result.errors) == 0,
        "error": "; ".join(result.errors) if result.errors else None,
        **result.to_dict(),
    }


async def sync_labels_from_graph(
    session: AsyncSession,
    tenant_id: UUID,
    remove_stale: bool = False,
) -> LabelSyncResult:
    """
    Sync sensitivity labels from Microsoft Graph API.

    Uses LabelingEngine.get_available_labels() for all Graph API
    communication (token acquisition, retry logic, pagination).

    Args:
        session: Database session
        tenant_id: OpenLabels tenant ID
        remove_stale: Whether to remove labels not in M365

    Returns:
        LabelSyncResult with statistics
    """
    result = LabelSyncResult()

    try:
        engine = create_labeling_engine()
        labels_data = await engine.get_available_labels(use_cache=False)

        if not labels_data:
            result.errors.append("No labels returned from Graph API")
            return result

        logger.info(f"Fetched {len(labels_data)} labels from M365")

        # Track which labels we've seen (for stale removal)
        seen_label_ids = set()

        # Extract all label IDs from the incoming data
        incoming_label_ids = [
            label_data.get("id") for label_data in labels_data if label_data.get("id")
        ]

        # Batch fetch all existing labels in a single query (avoids N+1)
        existing_labels = {}
        if incoming_label_ids:
            existing_query = select(SensitivityLabel).where(
                SensitivityLabel.id.in_(incoming_label_ids),
                SensitivityLabel.tenant_id == tenant_id,
            )
            existing_result = await session.execute(existing_query)
            existing_labels = {label.id: label for label in existing_result.scalars().all()}

        # Process each label using pre-fetched data
        for label_data in labels_data:
            label_id = label_data.get("id")
            if not label_id:
                continue

            seen_label_ids.add(label_id)

            try:
                # Check if label exists using pre-fetched data
                existing = existing_labels.get(label_id)

                if existing:
                    # Update existing label
                    existing.name = label_data.get("name", existing.name)
                    existing.description = label_data.get("description")
                    existing.color = label_data.get("color")
                    existing.priority = label_data.get("priority", 0)
                    existing.parent_id = label_data.get("parent_id")
                    existing.synced_at = datetime.now(timezone.utc)
                    result.labels_updated += 1
                else:
                    # Create new label
                    new_label = SensitivityLabel(
                        id=label_id,
                        tenant_id=tenant_id,
                        name=label_data.get("name", "Unknown"),
                        description=label_data.get("description"),
                        color=label_data.get("color"),
                        priority=label_data.get("priority", 0),
                        parent_id=label_data.get("parent_id"),
                        synced_at=datetime.now(timezone.utc),
                    )
                    session.add(new_label)
                    result.labels_added += 1

                result.labels_synced += 1

            except (SQLAlchemyError, ValueError, KeyError) as e:
                logger.error(f"Failed to sync label {label_id}: {e}")
                result.errors.append(f"Label {label_id}: {e}")

        # Optionally remove stale labels
        if remove_stale and seen_label_ids:
            removed_count = await _remove_stale_labels(session, tenant_id, seen_label_ids)
            result.labels_removed = removed_count
            if removed_count > 0:
                logger.info(f"Removed {removed_count} stale labels")

        await session.flush()
        logger.info(
            f"Label sync complete: {result.labels_added} added, "
            f"{result.labels_updated} updated, {result.labels_removed} removed"
        )

    except (SQLAlchemyError, ConnectionError, OSError, RuntimeError) as e:
        logger.error(f"Label sync failed: {e}")
        result.errors.append(str(e))

    return result


async def _remove_stale_labels(
    session: AsyncSession,
    tenant_id: UUID,
    current_label_ids: set[str],
) -> int:
    """Remove labels that no longer exist in M365."""
    # Find labels not in current set
    query = select(SensitivityLabel.id).where(
        SensitivityLabel.tenant_id == tenant_id,
        ~SensitivityLabel.id.in_(current_label_ids),
    )
    result = await session.execute(query)
    stale_ids = [row[0] for row in result.fetchall()]

    if stale_ids:
        # Delete stale labels
        await session.execute(
            delete(SensitivityLabel).where(SensitivityLabel.id.in_(stale_ids))
        )

    return len(stale_ids)

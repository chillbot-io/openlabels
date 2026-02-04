"""
Label synchronization task implementation.

Syncs sensitivity labels from Microsoft 365 to the local database.
Runs on a schedule or on-demand via API.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import SensitivityLabel, Tenant

logger = logging.getLogger(__name__)

# Check for httpx
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


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

        tenant_id_azure = auth.tenant_id
        client_id = auth.client_id
        client_secret = auth.client_secret

        if not all([tenant_id_azure, client_id, client_secret]):
            return {
                "success": False,
                "error": "Azure AD credentials not configured - check AUTH_TENANT_ID, AUTH_CLIENT_ID, AUTH_CLIENT_SECRET",
                **LabelSyncResult().to_dict(),
            }
    except Exception as e:
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
        azure_tenant_id=tenant_id_azure,
        client_id=client_id,
        client_secret=client_secret,
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
    azure_tenant_id: str,
    client_id: str,
    client_secret: str,
    remove_stale: bool = False,
) -> LabelSyncResult:
    """
    Sync sensitivity labels from Microsoft Graph API.

    Args:
        session: Database session
        tenant_id: OpenLabels tenant ID
        azure_tenant_id: Azure AD tenant ID
        client_id: Azure AD client ID
        client_secret: Azure AD client secret
        remove_stale: Whether to remove labels not in M365

    Returns:
        LabelSyncResult with statistics
    """
    result = LabelSyncResult()

    if not HTTPX_AVAILABLE:
        result.errors.append("httpx not installed - cannot sync labels")
        return result

    try:
        # Get access token
        token = await _get_graph_token(azure_tenant_id, client_id, client_secret)
        if not token:
            result.errors.append("Failed to obtain Graph API access token")
            return result

        # Fetch labels from Graph API
        labels_data = await _fetch_labels_from_graph(token)
        if labels_data is None:
            result.errors.append("Failed to fetch labels from Graph API")
            return result

        logger.info(f"Fetched {len(labels_data)} labels from M365")

        # Track which labels we've seen (for stale removal)
        seen_label_ids = set()

        # Process each label
        for label_data in labels_data:
            label_id = label_data.get("id")
            if not label_id:
                continue

            seen_label_ids.add(label_id)

            try:
                # Check if label exists
                existing = await session.get(SensitivityLabel, label_id)

                if existing:
                    # Update existing label
                    existing.name = label_data.get("name", existing.name)
                    existing.description = label_data.get("description")
                    existing.color = label_data.get("color")
                    existing.priority = label_data.get("priority", 0)
                    existing.parent_id = label_data.get("parent", {}).get("id") if label_data.get("parent") else None
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
                        parent_id=label_data.get("parent", {}).get("id") if label_data.get("parent") else None,
                        synced_at=datetime.now(timezone.utc),
                    )
                    session.add(new_label)
                    result.labels_added += 1

                result.labels_synced += 1

            except Exception as e:
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

    except Exception as e:
        logger.error(f"Label sync failed: {e}")
        result.errors.append(str(e))

    return result


async def _get_graph_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> Optional[str]:
    """Get OAuth2 access token for Microsoft Graph API."""
    if not HTTPX_AVAILABLE:
        return None

    max_retries = 3
    base_delay = 2.0

    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "scope": "https://graph.microsoft.com/.default",
                    },
                )

                if response.status_code == 200:
                    return response.json().get("access_token")
                elif response.status_code == 429:
                    # Rate limited
                    retry_after = int(response.headers.get("Retry-After", base_delay * (2 ** attempt)))
                    logger.warning(f"Rate limited, retrying after {retry_after}s")
                    await asyncio.sleep(retry_after)
                elif response.status_code >= 500:
                    # Server error - retry
                    await asyncio.sleep(base_delay * (2 ** attempt))
                else:
                    logger.error(f"Token error: {response.status_code} - {response.text[:200]}")
                    return None

        except httpx.RequestError as e:
            logger.warning(f"Token request failed (attempt {attempt + 1}): {e}")
            await asyncio.sleep(base_delay * (2 ** attempt))

    return None


async def _fetch_labels_from_graph(token: str) -> Optional[list[dict]]:
    """Fetch sensitivity labels from Microsoft Graph API."""
    if not HTTPX_AVAILABLE:
        return None

    all_labels = []
    url = "https://graph.microsoft.com/v1.0/informationProtection/policy/labels"

    max_retries = 3
    base_delay = 2.0

    while url:
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(
                        url,
                        headers={"Authorization": f"Bearer {token}"},
                    )

                    if response.status_code == 200:
                        data = response.json()
                        all_labels.extend(data.get("value", []))

                        # Handle pagination
                        url = data.get("@odata.nextLink")
                        break
                    elif response.status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", base_delay * (2 ** attempt)))
                        logger.warning(f"Rate limited, retrying after {retry_after}s")
                        await asyncio.sleep(retry_after)
                    elif response.status_code >= 500:
                        await asyncio.sleep(base_delay * (2 ** attempt))
                    else:
                        logger.error(f"Graph API error: {response.status_code} - {response.text[:500]}")
                        return None

            except httpx.RequestError as e:
                logger.warning(f"Graph request failed (attempt {attempt + 1}): {e}")
                await asyncio.sleep(base_delay * (2 ** attempt))
        else:
            # All retries exhausted
            return None

    return all_labels


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

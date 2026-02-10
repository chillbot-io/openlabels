"""
Microsoft Graph webhook change-notification provider.

Subscribes to ``/drives/{drive-id}/root`` changes and processes
incoming webhook notifications to detect file modifications in
SharePoint/OneDrive.

**Differences from M365 Audit:**

+---------------------+------------------+---------------------------+
| Dimension           | M365 Audit API   | Graph Webhooks            |
+---------------------+------------------+---------------------------+
| What it tells you   | Who accessed what | What changed              |
| User attribution    | Full (UPN, IP)   | None (change only)        |
| Latency             | 5-15 minutes     | Seconds                   |
| Use case            | Access tracking  | Trigger delta scans       |
+---------------------+------------------+---------------------------+

The ``GraphWebhookProvider`` is designed to be paired with the
``M365AuditProvider``: webhooks trigger fast change detection while
audit events provide the user-attribution data.

Subscription lifecycle:
    1. ``subscribe(drive_id, webhook_url)`` — creates a Graph
       subscription (max 30 days, must be renewed).
    2. Graph sends ``POST`` to the webhook endpoint when files change.
    3. The webhook endpoint (``routes/webhooks.py``) validates the
       notification and queues it.
    4. On each harvest cycle, ``collect()`` drains the queue and runs
       delta queries to identify actual changed files.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from openlabels.adapters.graph_client import GraphClient

from .base import RawAccessEvent

logger = logging.getLogger(__name__)

EVENT_SOURCE = "graph_webhook"

# Subscription max lifetime (Graph API limit: 30 days for drive items,
# but we renew at 29 days to be safe).
_SUBSCRIPTION_MAX_DAYS = 29


class GraphWebhookProvider:
    """Detects file changes via Microsoft Graph webhook notifications.

    Implements the ``EventProvider`` async protocol.

    Unlike OS providers, this provider depends on an external queue of
    webhook notifications (populated by ``routes/webhooks.py``).  If the
    queue is empty, ``collect()`` returns ``[]``.

    Parameters
    ----------
    graph_client:
        A configured :class:`GraphClient` instance (caller owns lifecycle).
    webhook_url:
        The public HTTPS URL that Graph will POST notifications to.
    client_state:
        Shared secret for validating inbound notifications.
    drive_ids:
        List of drive IDs to subscribe to.  Each drive gets its own
        Graph subscription.
    """

    def __init__(
        self,
        graph_client: GraphClient,
        *,
        webhook_url: str = "",
        client_state: str = "",
        drive_ids: list[str] | None = None,
    ) -> None:
        self._client = graph_client
        self._webhook_url = webhook_url
        self._client_state = client_state
        self._drive_ids = drive_ids or []

        # subscription_id → drive_id
        self._subscriptions: dict[str, str] = {}

    @property
    def name(self) -> str:
        return EVENT_SOURCE

    # ------------------------------------------------------------------
    # EventProvider.collect()
    # ------------------------------------------------------------------

    async def collect(self, since: datetime | None = None) -> list[RawAccessEvent]:
        """Process queued webhook notifications via delta queries.

        For each pending notification, runs a delta query on the
        affected drive to discover which files actually changed.
        Returns ``RawAccessEvent`` instances with ``action="write"``
        (webhooks only tell us *something* changed, not who did it).
        """
        from openlabels.monitoring.notification_queue import drain_graph_notifications

        notifications = drain_graph_notifications()
        if not notifications:
            return []

        # Deduplicate — multiple notifications may reference the same drive
        affected_drives: set[str] = set()
        for notification in notifications:
            resource = notification.get("resource", "")
            # resource looks like "/drives/{drive-id}/root"
            parts = resource.strip("/").split("/")
            if len(parts) >= 2 and parts[0] == "drives":
                affected_drives.add(parts[1])

        events: list[RawAccessEvent] = []
        for drive_id in affected_drives:
            try:
                drive_events = await self._delta_query(drive_id)
                events.extend(drive_events)
            except Exception:
                logger.warning(
                    "Delta query failed for drive %s",
                    drive_id,
                    exc_info=True,
                )

        return events

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    async def subscribe(self, drive_id: str) -> str:
        """Create a Graph change notification subscription for a drive.

        Returns the subscription ID.
        """
        expiration = datetime.now(timezone.utc) + timedelta(
            days=_SUBSCRIPTION_MAX_DAYS,
        )

        body = {
            "changeType": "updated",
            "notificationUrl": self._webhook_url,
            "resource": f"/drives/{drive_id}/root",
            "expirationDateTime": expiration.isoformat(),
            "clientState": self._client_state,
        }

        result = await self._client.post("/subscriptions", json=body)
        subscription_id = result["id"]
        self._subscriptions[subscription_id] = drive_id

        logger.info(
            "Graph webhook subscription created: %s for drive %s (expires %s)",
            subscription_id,
            drive_id,
            expiration.isoformat(),
        )
        return subscription_id

    async def subscribe_all(self) -> int:
        """Subscribe to all configured drive IDs.

        Returns the number of successful subscriptions.
        """
        count = 0
        for drive_id in self._drive_ids:
            try:
                await self.subscribe(drive_id)
                count += 1
            except Exception:
                logger.warning(
                    "Failed to subscribe to drive %s",
                    drive_id,
                    exc_info=True,
                )
        return count

    async def renew_subscription(self, subscription_id: str) -> str:
        """Renew a subscription by re-subscribing to the same drive.

        Since ``GraphClient.patch()`` is not yet available, this deletes
        the local tracking for the old subscription and creates a new one.
        The old Graph subscription will expire on its own.

        Returns the new subscription ID.
        """
        drive_id = self._subscriptions.pop(subscription_id, None)
        if drive_id is None:
            raise ValueError(f"Unknown subscription: {subscription_id}")
        return await self.subscribe(drive_id)

    # ------------------------------------------------------------------
    # Delta query
    # ------------------------------------------------------------------

    async def _delta_query(self, drive_id: str) -> list[RawAccessEvent]:
        """Run a delta query on a drive to find changed files."""
        resource_path = f"drives/{drive_id}"
        initial_path = f"/drives/{drive_id}/root/delta"

        items, is_delta = await self._client.get_with_delta(
            initial_path, resource_path,
        )

        events: list[RawAccessEvent] = []
        now = datetime.now(timezone.utc)

        for item in items:
            # Skip folders
            if "folder" in item:
                continue

            # Skip deleted items (delta reports deletions too)
            if item.get("deleted"):
                continue

            # Build file path from parent reference
            parent_path = item.get("parentReference", {}).get("path", "")
            parent_path = parent_path.replace("/drive/root:", "")
            name = item.get("name", "")
            if not name:
                continue

            file_path = f"{parent_path}/{name}"

            # Parse modification time
            modified_str = item.get("lastModifiedDateTime", "")
            if modified_str:
                try:
                    event_time = datetime.fromisoformat(
                        modified_str.replace("Z", "+00:00"),
                    )
                except (ValueError, TypeError):
                    event_time = now
            else:
                event_time = now

            events.append(RawAccessEvent(
                file_path=file_path,
                event_time=event_time,
                action="write",  # Webhooks only signal "change"
                event_source=EVENT_SOURCE,
                user_name=_extract_user(item),
                raw=item,
            ))

        return events


def _extract_user(item: dict) -> str | None:
    """Try to extract user info from a Graph drive item."""
    last_modified = item.get("lastModifiedBy", {})
    user = last_modified.get("user", {})
    return (
        user.get("email")
        or user.get("displayName")
        or None
    )

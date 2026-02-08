"""
In-memory queues for webhook notifications.

The webhook endpoints (``server/routes/webhooks.py``) push notifications
here; providers drain them on each harvest cycle.

**Two separate queues** prevent cross-contamination:
- ``graph_notifications`` — for Graph change notifications (consumed by
  ``GraphWebhookProvider``)
- ``m365_notifications`` — for M365 audit "content available" signals
  (consumed by ``M365AuditProvider`` if webhook-accelerated mode is
  desired; otherwise the provider polls the content API directly)

This module is intentionally dependency-free (no fastapi, no DB) so
that both the webhook route and the providers can import it without
circular imports or missing optional dependencies.

Concurrency note:
    These queues are safe only within a single-threaded asyncio event
    loop (FastAPI default).  Do NOT call ``push_*`` from a thread
    executor.  If threaded access is ever needed, wrap operations in
    an ``asyncio.Lock``.
"""

from __future__ import annotations

from typing import Any

# Maximum pending notifications per queue (back-pressure).
# Excess notifications are silently dropped with a warning log.
MAX_QUEUE_SIZE = 10_000

_graph_notifications: list[dict[str, Any]] = []
_m365_notifications: list[dict[str, Any]] = []


# -----------------------------------------------------------------------
# Graph change notifications
# -----------------------------------------------------------------------

def push_graph_notification(notification: dict[str, Any]) -> bool:
    """Add a Graph change notification to the queue.

    Returns ``False`` if the queue is full (notification dropped).
    """
    if len(_graph_notifications) >= MAX_QUEUE_SIZE:
        return False
    _graph_notifications.append(notification)
    return True


def drain_graph_notifications() -> list[dict[str, Any]]:
    """Drain and return all pending Graph change notifications."""
    notifications = list(_graph_notifications)
    _graph_notifications.clear()
    return notifications


# -----------------------------------------------------------------------
# M365 audit "content available" signals
# -----------------------------------------------------------------------

def push_m365_notification(notification: dict[str, Any]) -> bool:
    """Add an M365 audit notification to the queue.

    Returns ``False`` if the queue is full (notification dropped).
    """
    if len(_m365_notifications) >= MAX_QUEUE_SIZE:
        return False
    _m365_notifications.append(notification)
    return True


def drain_m365_notifications() -> list[dict[str, Any]]:
    """Drain and return all pending M365 audit notifications."""
    notifications = list(_m365_notifications)
    _m365_notifications.clear()
    return notifications

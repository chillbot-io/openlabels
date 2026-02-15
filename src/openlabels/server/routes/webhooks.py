"""
Webhook endpoints for external service notifications.

Currently handles:
- Microsoft 365 Management Activity API audit notifications
- Microsoft Graph change notifications (subscription validation + events)

Both M365 and Graph use the same validation pattern:
1. On subscription creation, they send a GET/POST with a ``validationToken``
   query param.  We must echo it back as ``text/plain``.
2. On actual notifications, they POST a JSON body with a ``clientState``
   field that must match our configured secret.

Security:
- ``clientState`` is a shared secret configured at subscription time and
  verified on every inbound notification.  This prevents spoofed
  notifications from arbitrary senders.
- If ``webhook_client_state`` is not configured (empty string), all
  notifications are **rejected** — this prevents an accidental open
  endpoint if an operator enables webhooks but forgets the secret.
- The validation token is echoed only for subscription handshakes — it
  is never stored or logged.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections import OrderedDict

from fastapi import APIRouter, Query, Request, Response, status

from openlabels.monitoring.notification_queue import (
    push_graph_notification,
    push_m365_notification,
)
from openlabels.server.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter()

# SECURITY: Replay protection — in-memory dedup cache keyed by notification hash.
# Entries expire after _REPLAY_WINDOW_SECONDS.  The cache is bounded to
# _REPLAY_CACHE_MAX entries to prevent unbounded memory growth.
_REPLAY_WINDOW_SECONDS = 300  # 5 minutes
_REPLAY_CACHE_MAX = 10_000
_seen_notifications: OrderedDict[str, float] = OrderedDict()


def _is_replay(notification: dict, source: str) -> bool:
    """Return True if this notification was already processed recently.

    Uses a SHA-256 hash of the notification's identifying fields as the
    dedup key, and rejects notifications seen within the replay window.
    """
    # Build a stable identity from the notification
    # M365: contentUri is unique per content blob
    # Graph: subscriptionId + resource + changeType form a unique event key
    if source == "M365":
        identity = notification.get("contentUri", "")
    else:
        identity = "|".join([
            notification.get("subscriptionId", ""),
            notification.get("resource", ""),
            notification.get("changeType", ""),
            notification.get("clientState", ""),
        ])

    if not identity:
        return False  # can't dedup without identity — allow through

    key = hashlib.sha256(identity.encode()).hexdigest()[:32]
    now = time.monotonic()

    # Evict stale entries
    while _seen_notifications:
        oldest_key, oldest_ts = next(iter(_seen_notifications.items()))
        if now - oldest_ts > _REPLAY_WINDOW_SECONDS:
            _seen_notifications.pop(oldest_key)
        else:
            break

    if key in _seen_notifications:
        logger.warning("%s webhook: replay detected (dedup key %s…), rejecting", source, key[:8])
        return True

    _seen_notifications[key] = now

    # Enforce max size
    while len(_seen_notifications) > _REPLAY_CACHE_MAX:
        _seen_notifications.popitem(last=False)

    return False


def _validate_client_state(
    client_state: str,
    expected_state: str,
    source: str,
) -> bool:
    """Validate clientState using constant-time comparison.

    Returns ``True`` if valid.  Rejects if ``expected_state`` is empty
    (misconfigured — better to reject than silently accept everything).
    """
    if not expected_state:
        logger.warning(
            "%s webhook: webhook_client_state not configured — "
            "rejecting notification (set OPENLABELS_MONITORING__WEBHOOK_CLIENT_STATE)",
            source,
        )
        return False

    if not hmac.compare_digest(client_state, expected_state):
        logger.warning("%s webhook: clientState mismatch — rejecting", source)
        return False

    return True


@router.post(
    "/webhooks/m365",
    status_code=status.HTTP_200_OK,
    summary="M365 audit webhook receiver",
    tags=["Webhooks"],
)
async def m365_webhook(
    request: Request,
    validationToken: str | None = Query(default=None),
) -> Response:
    """Receive M365 Management Activity API audit notifications."""
    # Case 1: Subscription validation handshake
    if validationToken is not None:
        # SECURITY: Validate token format to prevent reflection of arbitrary content
        if len(validationToken) > 1024 or not validationToken.isprintable():
            logger.warning("M365 webhook: suspicious validationToken rejected")
            return Response(status_code=status.HTTP_400_BAD_REQUEST)
        logger.info("M365 webhook: validation handshake received")
        return Response(
            content=validationToken,
            media_type="text/plain",
            status_code=status.HTTP_200_OK,
            headers={"X-Content-Type-Options": "nosniff"},
        )

    # Case 2: Content available notification
    settings = get_settings()
    expected_state = settings.monitoring.webhook_client_state

    try:
        body = await request.json()
    except Exception:
        logger.warning("M365 webhook: invalid JSON body")
        return Response(status_code=status.HTTP_400_BAD_REQUEST)

    if not isinstance(body, list):
        body = [body]

    accepted = 0
    for notification in body:
        client_state = notification.get("clientState", "")

        if not _validate_client_state(client_state, expected_state, "M365"):
            continue

        if _is_replay(notification, "M365"):
            continue

        if push_m365_notification(notification):
            accepted += 1
        else:
            logger.warning("M365 webhook: notification queue full, dropping")

    logger.debug(
        "M365 webhook: accepted %d/%d notification(s)",
        accepted,
        len(body),
    )
    return Response(status_code=status.HTTP_200_OK)


@router.post(
    "/webhooks/graph",
    status_code=status.HTTP_200_OK,
    summary="Graph change notification receiver",
    tags=["Webhooks"],
)
async def graph_webhook(
    request: Request,
    validationToken: str | None = Query(default=None),
) -> Response:
    """Receive Microsoft Graph change notifications (drive item changes)."""
    # Validation handshake
    if validationToken is not None:
        # SECURITY: Validate token format to prevent reflection of arbitrary content
        if len(validationToken) > 1024 or not validationToken.isprintable():
            logger.warning("Graph webhook: suspicious validationToken rejected")
            return Response(status_code=status.HTTP_400_BAD_REQUEST)
        logger.info("Graph webhook: validation handshake received")
        return Response(
            content=validationToken,
            media_type="text/plain",
            status_code=status.HTTP_200_OK,
            headers={"X-Content-Type-Options": "nosniff"},
        )

    # Change notification
    settings = get_settings()
    expected_state = settings.monitoring.webhook_client_state

    try:
        body = await request.json()
    except Exception:
        logger.warning("Graph webhook: invalid JSON body")
        return Response(status_code=status.HTTP_400_BAD_REQUEST)

    notifications = body.get("value", []) if isinstance(body, dict) else []

    accepted = 0
    for notification in notifications:
        client_state = notification.get("clientState", "")

        if not _validate_client_state(client_state, expected_state, "Graph"):
            continue

        if _is_replay(notification, "Graph"):
            continue

        if push_graph_notification(notification):
            accepted += 1
        else:
            logger.warning("Graph webhook: notification queue full, dropping")

    logger.debug(
        "Graph webhook: accepted %d/%d notification(s)",
        accepted,
        len(notifications),
    )
    return Response(status_code=status.HTTP_200_OK)

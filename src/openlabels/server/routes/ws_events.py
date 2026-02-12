"""
Global WebSocket endpoint for real-time frontend event streaming.

Provides a single multiplexed WebSocket connection at ``/ws/events``
that delivers all event types for the authenticated user's tenant:

- scan_progress, scan_completed, scan_failed
- label_applied
- remediation_completed
- job_status
- file_access
- health_update

Architecture:
- Connections are keyed by tenant_id (not scan_id like /ws/scans/).
- Uses a separate Redis pub/sub channel for cross-instance delivery.
- Falls back to local-only broadcast when Redis is unavailable.
- Reuses the same session-cookie auth as /ws/scans/.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from openlabels.server.routes.ws import (
    WS_MAX_MESSAGE_SIZE,
    WS_MAX_MESSAGES_PER_MINUTE,
    WS_RATE_WINDOW_SECONDS,
    authenticate_websocket,
    validate_websocket_origin,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Separate Redis channel for global events (distinct from scan-specific channel)
GLOBAL_PUBSUB_CHANNEL = "openlabels:ws:global"


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------


class GlobalConnection:
    """Authenticated WebSocket connection with tenant context."""

    __slots__ = ("websocket", "user_id", "tenant_id")

    def __init__(self, websocket: WebSocket, user_id: UUID, tenant_id: UUID):
        self.websocket = websocket
        self.user_id = user_id
        self.tenant_id = tenant_id


class GlobalConnectionManager:
    """Manages WebSocket connections keyed by tenant_id."""

    def __init__(self) -> None:
        self.connections: dict[UUID, list[GlobalConnection]] = {}

    async def connect(
        self, websocket: WebSocket, user_id: UUID, tenant_id: UUID
    ) -> GlobalConnection:
        await websocket.accept()
        conn = GlobalConnection(websocket, user_id, tenant_id)
        self.connections.setdefault(tenant_id, []).append(conn)
        logger.debug(
            "Global WS connected: user=%s tenant=%s (total=%d)",
            user_id, tenant_id, self.connection_count,
        )
        return conn

    def disconnect(self, conn: GlobalConnection) -> None:
        tenant_conns = self.connections.get(conn.tenant_id)
        if tenant_conns:
            self.connections[conn.tenant_id] = [
                c for c in tenant_conns if c.websocket is not conn.websocket
            ]
            if not self.connections[conn.tenant_id]:
                del self.connections[conn.tenant_id]
        logger.debug(
            "Global WS disconnected: user=%s tenant=%s (total=%d)",
            conn.user_id, conn.tenant_id, self.connection_count,
        )

    async def deliver_local(self, tenant_id: UUID, message: dict) -> None:
        """Deliver a message to all local connections for a tenant."""
        conns = self.connections.get(tenant_id)
        if not conns:
            return
        dead: list[GlobalConnection] = []
        for conn in conns:
            try:
                await conn.websocket.send_json(message)
            except (WebSocketDisconnect, ConnectionError, OSError, RuntimeError):
                dead.append(conn)
        for conn in dead:
            self.disconnect(conn)

    async def broadcast_all(self, message: dict) -> None:
        """Deliver a message to ALL connected tenants (e.g. health_update)."""
        for tenant_id in list(self.connections):
            await self.deliver_local(tenant_id, message)

    @property
    def connection_count(self) -> int:
        return sum(len(conns) for conns in self.connections.values())


class GlobalPubSubBroadcaster:
    """Distributes global events across instances via Redis pub/sub.

    Mirrors :class:`PubSubBroadcaster` from ws.py but routes by
    ``tenant_id`` instead of ``scan_id``.
    """

    def __init__(self, local: GlobalConnectionManager) -> None:
        self._local = local
        self._publisher: Any = None
        self._subscriber: Any = None
        self._pubsub: Any = None
        self._task: asyncio.Task | None = None
        self._running = False

    @property
    def is_distributed(self) -> bool:
        return self._running and self._publisher is not None

    async def start(self) -> bool:
        """Connect to Redis and start the subscriber loop.

        Returns True if Redis pub/sub is active, False for local-only.
        """
        from openlabels.server.config import get_settings

        settings = get_settings()
        if not settings.redis.enabled:
            logger.info("Global WS pub/sub: Redis disabled, local-only mode")
            return False

        try:
            import redis.asyncio as aioredis

            self._publisher = aioredis.from_url(
                settings.redis.url,
                socket_connect_timeout=settings.redis.connect_timeout,
                socket_timeout=settings.redis.socket_timeout,
                decode_responses=True,
            )
            await self._publisher.ping()

            self._subscriber = aioredis.from_url(
                settings.redis.url,
                socket_connect_timeout=settings.redis.connect_timeout,
                socket_timeout=settings.redis.socket_timeout,
                decode_responses=True,
            )
            self._pubsub = self._subscriber.pubsub()
            await self._pubsub.subscribe(GLOBAL_PUBSUB_CHANNEL)

            self._running = True
            self._task = asyncio.create_task(
                self._subscriber_loop(), name="ws-global-pubsub"
            )
            logger.info("Global WS pub/sub: Redis connected, distributed mode")
            return True

        except ImportError:
            logger.info("Global WS pub/sub: redis package not installed, local-only")
            return False
        except Exception as e:
            logger.warning(
                "Global WS pub/sub: Redis failed (%s: %s), local-only",
                type(e).__name__, e,
            )
            await self._cleanup()
            return False

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._cleanup()
        logger.info("Global WS pub/sub stopped")

    async def _cleanup(self) -> None:
        for client_name in ("_pubsub", "_subscriber", "_publisher"):
            client = getattr(self, client_name, None)
            if client:
                try:
                    if client_name == "_pubsub":
                        await client.unsubscribe(GLOBAL_PUBSUB_CHANNEL)
                    await client.close()
                except Exception:
                    pass
                setattr(self, client_name, None)

    async def publish(self, tenant_id: UUID, message: dict) -> None:
        """Publish a global event. Uses Redis if available, else local-only."""
        # Ensure tenant_id is in the payload for routing
        message["tenant_id"] = str(tenant_id)

        if self._publisher and self._running:
            try:
                payload = json.dumps(message, default=str)
                await self._publisher.publish(GLOBAL_PUBSUB_CHANNEL, payload)
                return
            except Exception as e:
                logger.warning("Global WS publish failed (%s), falling back to local", e)

        # Local fallback
        await self._local.deliver_local(tenant_id, message)

    async def publish_to_all(self, message: dict) -> None:
        """Publish an event to ALL tenants (e.g. health_update)."""
        message["tenant_id"] = "__all__"

        if self._publisher and self._running:
            try:
                payload = json.dumps(message, default=str)
                await self._publisher.publish(GLOBAL_PUBSUB_CHANNEL, payload)
                return
            except Exception as e:
                logger.warning("Global WS broadcast failed (%s), falling back to local", e)

        await self._local.broadcast_all(message)

    async def _subscriber_loop(self) -> None:
        while self._running:
            try:
                msg = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if msg is None:
                    await asyncio.sleep(0.01)
                    continue
                if msg["type"] != "message":
                    continue

                data = json.loads(msg["data"])
                tid_str = data.get("tenant_id")

                if tid_str == "__all__":
                    await self._local.broadcast_all(data)
                elif tid_str:
                    await self._local.deliver_local(UUID(tid_str), data)

            except asyncio.CancelledError:
                break
            except json.JSONDecodeError as e:
                logger.warning("Global WS pub/sub: invalid JSON: %s", e)
            except Exception as e:
                if self._running:
                    logger.error("Global WS subscriber error: %s: %s", type(e).__name__, e)
                    await asyncio.sleep(1.0)


# ---------------------------------------------------------------------------
# Module-level instances
# ---------------------------------------------------------------------------

global_manager = GlobalConnectionManager()
global_broadcaster = GlobalPubSubBroadcaster(global_manager)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/events")
async def websocket_global_events(websocket: WebSocket) -> None:
    """
    Global WebSocket endpoint for real-time frontend event streaming.

    Delivers all event types for the authenticated user's tenant over
    a single multiplexed connection.

    Security:
    - Validates Origin header (CSWSH prevention)
    - Authenticates via session cookie
    - Events are scoped to the user's tenant
    """
    if not validate_websocket_origin(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    auth_result = await authenticate_websocket(websocket)
    if not auth_result:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id, tenant_id = auth_result
    conn = await global_manager.connect(websocket, user_id, tenant_id)

    # Rate limiting state
    message_timestamps: list[float] = []

    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,
                )

                # Enforce payload size limit
                if len(data) > WS_MAX_MESSAGE_SIZE:
                    await websocket.send_json({
                        "type": "error",
                        "message": f"Message exceeds max size ({WS_MAX_MESSAGE_SIZE} bytes)",
                    })
                    continue

                # Enforce rate limit
                now = asyncio.get_event_loop().time()
                message_timestamps[:] = [
                    ts for ts in message_timestamps
                    if now - ts < WS_RATE_WINDOW_SECONDS
                ]
                if len(message_timestamps) >= WS_MAX_MESSAGES_PER_MINUTE:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Rate limit exceeded, slow down",
                    })
                    continue
                message_timestamps.append(now)

                # Handle client messages
                if data == "ping":
                    await websocket.send_text("pong")

            except asyncio.TimeoutError:
                # Send heartbeat on idle
                await websocket.send_json({"type": "heartbeat"})

    except WebSocketDisconnect:
        global_manager.disconnect(conn)


# ---------------------------------------------------------------------------
# Publishing helpers — called from other modules to push events
# ---------------------------------------------------------------------------


async def publish_scan_progress(
    tenant_id: UUID,
    scan_id: UUID,
    status_value: str,
    progress: dict,
) -> None:
    """Publish scan progress to global event stream."""
    await global_broadcaster.publish(tenant_id, {
        "type": "scan_progress",
        "scan_id": str(scan_id),
        "status": status_value,
        "progress": progress,
    })


async def publish_scan_completed(
    tenant_id: UUID,
    scan_id: UUID,
    status_value: str,
    summary: dict,
) -> None:
    """Publish scan completion to global event stream."""
    await global_broadcaster.publish(tenant_id, {
        "type": "scan_completed",
        "scan_id": str(scan_id),
        "status": status_value,
        "summary": summary,
    })


async def publish_scan_failed(
    tenant_id: UUID,
    scan_id: UUID,
    error: str,
) -> None:
    """Publish scan failure to global event stream."""
    await global_broadcaster.publish(tenant_id, {
        "type": "scan_failed",
        "scan_id": str(scan_id),
        "error": error,
    })


async def publish_label_applied(
    tenant_id: UUID,
    result_id: UUID,
    label_name: str,
) -> None:
    """Publish label application to global event stream."""
    await global_broadcaster.publish(tenant_id, {
        "type": "label_applied",
        "result_id": str(result_id),
        "label_name": label_name,
    })


async def publish_remediation_completed(
    tenant_id: UUID,
    action_id: UUID,
    action_type: str,
    action_status: str,
) -> None:
    """Publish remediation completion to global event stream."""
    await global_broadcaster.publish(tenant_id, {
        "type": "remediation_completed",
        "action_id": str(action_id),
        "action_type": action_type,
        "status": action_status,
    })


async def publish_job_status(
    tenant_id: UUID,
    job_id: UUID,
    job_status: str,
) -> None:
    """Publish job status change to global event stream."""
    await global_broadcaster.publish(tenant_id, {
        "type": "job_status",
        "job_id": str(job_id),
        "status": job_status,
    })


async def publish_file_access(
    tenant_id: UUID,
    file_path: str,
    user_name: str,
    action: str,
    event_time: str,
) -> None:
    """Publish file access event to global event stream."""
    await global_broadcaster.publish(tenant_id, {
        "type": "file_access",
        "file_path": file_path,
        "user_name": user_name,
        "action": action,
        "event_time": event_time,
    })


async def publish_health_update(
    component: str,
    health_status: str,
) -> None:
    """Publish health update to ALL tenants."""
    await global_broadcaster.publish_to_all({
        "type": "health_update",
        "component": component,
        "status": health_status,
    })

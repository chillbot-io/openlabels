"""
WebSocket endpoints for real-time updates.

Horizontal scaling:
- Uses Redis pub/sub to broadcast events across all API instances.
- Each instance maintains local WebSocket connections and subscribes to
  a shared Redis channel for cross-instance delivery.
- Falls back to local-only broadcast when Redis is unavailable.

Security features:
- WebSocket connections are authenticated using the same session cookie as HTTP requests
- Unauthenticated connections are rejected
- Origin validation prevents cross-site WebSocket hijacking (CSWSH)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from openlabels.server.config import get_settings
from openlabels.server.db import get_session_factory
from openlabels.server.models import ScanJob, Tenant, User
from openlabels.server.session import SessionStore

logger = logging.getLogger(__name__)

router = APIRouter()

# WebSocket rate limiting constants
WS_MAX_MESSAGE_SIZE = 4096  # 4 KB max inbound message size
WS_MAX_MESSAGES_PER_MINUTE = 60  # Max client messages per minute
WS_RATE_WINDOW_SECONDS = 60

# WebSocket connection limits (DoS protection)
WS_MAX_CONNECTIONS_PER_TENANT = 50  # Max concurrent connections per tenant
WS_MAX_CONNECTIONS_GLOBAL = 500  # Max concurrent connections across all tenants

# Redis pub/sub channel for WebSocket events
WS_PUBSUB_CHANNEL = "openlabels:ws:events"


def _get_pubsub_hmac_key() -> bytes:
    """Return the HMAC key for signing Redis pub/sub messages."""
    settings = get_settings()
    key = settings.server.secret_key.get_secret_value()
    if not key:
        key = "openlabels-dev-pubsub-key"
    return key.encode("utf-8")


def sign_pubsub_payload(payload: str) -> str:
    """Sign a JSON payload with HMAC-SHA256 and return ``sig:payload``."""
    sig = hmac.new(_get_pubsub_hmac_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{sig}:{payload}"


def verify_pubsub_payload(signed: str) -> str | None:
    """Verify and extract the payload from a signed ``sig:payload`` string.

    Returns the payload if valid, None if the signature is invalid.
    """
    sep = signed.find(":")
    if sep == -1:
        return None
    sig_received = signed[:sep]
    payload = signed[sep + 1:]
    sig_expected = hmac.new(_get_pubsub_hmac_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig_received, sig_expected):
        return payload
    return None


def validate_websocket_origin(websocket: WebSocket) -> bool:
    """
    Validate WebSocket origin to prevent Cross-Site WebSocket Hijacking (CSWSH).

    Security: Validates that the Origin header matches allowed origins from CORS config.
    This prevents malicious websites from establishing WebSocket connections.

    Args:
        websocket: The WebSocket connection

    Returns:
        True if origin is valid, False otherwise
    """
    settings = get_settings()

    # Get the Origin header
    origin = None
    for header_name, header_value in websocket.headers.items():
        if header_name.lower() == "origin":
            origin = header_value
            break

    if not origin:
        # SECURITY: Reject missing Origin header in production/staging to
        # prevent Cross-Site WebSocket Hijacking.  Non-browser clients can
        # set a valid Origin header explicitly.
        if settings.server.environment in ("production", "staging"):
            logger.warning("WebSocket connection rejected: missing Origin header")
            return False
        # Allow in development for convenience (e.g. CLI tools, tests)
        logger.debug("WebSocket connection without Origin header (dev mode)")
        return True

    # Parse the origin
    try:
        parsed = urlparse(origin)
        origin_host = f"{parsed.scheme}://{parsed.netloc}"
    except (ValueError, TypeError) as parse_err:
        # SECURITY: Log origin parsing failures - could indicate malformed attack attempts
        logger.warning(f"Failed to parse WebSocket origin '{origin}': {type(parse_err).__name__}: {parse_err}")
        return False

    # Check against allowed CORS origins only — do NOT fall back to the
    # client-controlled Host header, as an attacker can set both Host and
    # Origin to the same malicious value.
    if origin_host in settings.cors.allowed_origins:
        return True

    logger.warning(
        f"WebSocket connection rejected: invalid origin {origin} "
        f"(allowed: {settings.cors.allowed_origins})"
    )
    return False

# Cookie name must match auth.py
SESSION_COOKIE_NAME = "openlabels_session"


class AuthenticatedConnection:
    """Authenticated WebSocket connection with user context."""

    def __init__(self, websocket: WebSocket, user_id: UUID, tenant_id: UUID):
        self.websocket = websocket
        self.user_id = user_id
        self.tenant_id = tenant_id


class ConnectionManager:
    """Manages local WebSocket connections for this process."""

    def __init__(self):
        self.active_connections: dict[UUID, list[AuthenticatedConnection]] = {}
        self.connections_per_tenant: dict[UUID, int] = {}

    async def connect(
        self, scan_id: UUID, websocket: WebSocket, user_id: UUID, tenant_id: UUID
    ) -> AuthenticatedConnection | None:
        """Accept a new authenticated WebSocket connection.

        Returns None and closes with 1013 (Try Again Later) if connection
        limits are exceeded.
        """
        # Check global connection limit
        if self.connection_count >= WS_MAX_CONNECTIONS_GLOBAL:
            logger.warning(
                "WebSocket connection rejected: global limit reached (%d/%d)",
                self.connection_count, WS_MAX_CONNECTIONS_GLOBAL,
            )
            await websocket.close(code=1013)  # Try Again Later
            return None

        # Check per-tenant connection limit
        tenant_count = self.connections_per_tenant.get(tenant_id, 0)
        if tenant_count >= WS_MAX_CONNECTIONS_PER_TENANT:
            logger.warning(
                "WebSocket connection rejected: tenant %s limit reached (%d/%d)",
                tenant_id, tenant_count, WS_MAX_CONNECTIONS_PER_TENANT,
            )
            await websocket.close(code=1013)  # Try Again Later
            return None

        await websocket.accept()
        conn = AuthenticatedConnection(websocket, user_id, tenant_id)
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(conn)
        self.connections_per_tenant[tenant_id] = tenant_count + 1
        return conn

    def disconnect(self, scan_id: UUID, conn: AuthenticatedConnection):
        """Remove a WebSocket connection."""
        if scan_id in self.active_connections:
            prev_len = len(self.active_connections[scan_id])
            self.active_connections[scan_id] = [
                c for c in self.active_connections[scan_id]
                if c.websocket != conn.websocket
            ]
            removed = prev_len - len(self.active_connections[scan_id])
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

            # Decrement per-tenant counter
            if removed > 0 and conn.tenant_id in self.connections_per_tenant:
                self.connections_per_tenant[conn.tenant_id] -= removed
                if self.connections_per_tenant[conn.tenant_id] <= 0:
                    del self.connections_per_tenant[conn.tenant_id]

    async def deliver_local(self, scan_id: UUID, message: dict):
        """Deliver a message to all local connections watching a scan."""
        if scan_id not in self.active_connections:
            return
        dead_connections: list[AuthenticatedConnection] = []
        for conn in self.active_connections[scan_id]:
            try:
                await conn.websocket.send_json(message)
            except (WebSocketDisconnect, ConnectionError, OSError, RuntimeError):
                dead_connections.append(conn)
        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(scan_id, conn)

    @property
    def connection_count(self) -> int:
        """Total number of active connections on this instance."""
        return sum(len(conns) for conns in self.active_connections.values())


class PubSubBroadcaster:
    """Distributes WebSocket events across instances via Redis pub/sub.

    When Redis is available:
    - ``publish()`` sends to the Redis channel so ALL instances receive it.
    - A background subscriber task on each instance receives messages and
      delivers them to its local WebSocket connections.

    When Redis is unavailable:
    - Falls back to local-only delivery (single-instance mode).
    """

    def __init__(self, local_manager: ConnectionManager):
        self._local = local_manager
        self._publisher: Any = None  # redis.asyncio client for publishing
        self._subscriber: Any = None  # redis.asyncio client for subscribing
        self._pubsub: Any = None  # PubSub object
        self._task: asyncio.Task | None = None
        self._running = False

    @property
    def is_distributed(self) -> bool:
        """True if pub/sub is connected and cross-instance delivery is active."""
        return self._running and self._publisher is not None

    async def start(self) -> bool:
        """Connect to Redis and start the subscriber background task.

        Returns True if Redis pub/sub is active, False for local-only mode.
        """
        settings = get_settings()
        if not settings.redis.enabled:
            logger.info("WebSocket pub/sub: Redis disabled, using local-only mode")
            return False

        redis_url = settings.redis.url
        try:
            import redis.asyncio as aioredis

            # Publisher client (shared, non-blocking)
            self._publisher = aioredis.from_url(
                redis_url,
                socket_connect_timeout=settings.redis.connect_timeout,
                socket_timeout=settings.redis.socket_timeout,
                decode_responses=True,
            )
            await self._publisher.ping()

            # Subscriber client (dedicated connection for pub/sub)
            self._subscriber = aioredis.from_url(
                redis_url,
                socket_connect_timeout=settings.redis.connect_timeout,
                socket_timeout=settings.redis.socket_timeout,
                decode_responses=True,
            )
            self._pubsub = self._subscriber.pubsub()
            await self._pubsub.subscribe(WS_PUBSUB_CHANNEL)

            self._running = True
            self._task = asyncio.create_task(
                self._subscriber_loop(), name="ws-pubsub-subscriber"
            )
            logger.info("WebSocket pub/sub: Redis connected, cross-instance delivery active")
            return True

        except ImportError:
            logger.info("WebSocket pub/sub: redis package not installed, local-only mode")
            return False
        except Exception as e:
            logger.warning(
                "WebSocket pub/sub: Redis connection failed (%s: %s), local-only mode",
                type(e).__name__, e,
            )
            await self._cleanup_clients()
            return False

    async def stop(self):
        """Stop the subscriber and close Redis connections."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._cleanup_clients()
        logger.info("WebSocket pub/sub stopped")

    async def _cleanup_clients(self):
        """Close Redis clients."""
        if self._pubsub:
            try:
                await self._pubsub.unsubscribe(WS_PUBSUB_CHANNEL)
                await self._pubsub.close()
            except Exception as e:
                logger.debug("Redis pubsub close failed: %s", e)
            self._pubsub = None
        if self._subscriber:
            try:
                await self._subscriber.close()
            except Exception as e:
                logger.debug("Redis subscriber close failed: %s", e)
            self._subscriber = None
        if self._publisher:
            try:
                await self._publisher.close()
            except Exception as e:
                logger.debug("Redis publisher close failed: %s", e)
            self._publisher = None

    async def publish(self, scan_id: UUID, message: dict):
        """Publish an event. Uses Redis if available, local delivery otherwise."""
        if self._publisher and self._running:
            try:
                payload = json.dumps(message, default=str)
                signed = sign_pubsub_payload(payload)
                await self._publisher.publish(WS_PUBSUB_CHANNEL, signed)
                return
            except Exception as e:
                logger.warning("WebSocket pub/sub publish failed (%s), falling back to local", e)

        # Fallback: deliver locally only
        scan_id_from_msg = message.get("scan_id")
        if scan_id_from_msg:
            await self._local.deliver_local(UUID(scan_id_from_msg), message)

    async def _subscriber_loop(self):
        """Background task: receive messages from Redis and deliver to local connections."""
        while self._running:
            try:
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0,
                )
                if message is None:
                    await asyncio.sleep(0.01)
                    continue

                if message["type"] != "message":
                    continue

                # SECURITY: Verify HMAC signature before processing
                raw = message["data"]
                payload = verify_pubsub_payload(raw)
                if payload is None:
                    logger.warning("WebSocket pub/sub: rejected message with invalid HMAC signature")
                    continue

                data = json.loads(payload)
                scan_id_str = data.get("scan_id")
                if scan_id_str:
                    await self._local.deliver_local(UUID(scan_id_str), data)

            except asyncio.CancelledError:
                break
            except json.JSONDecodeError as e:
                logger.warning("WebSocket pub/sub: invalid JSON in message: %s", e)
            except Exception as e:
                if self._running:
                    logger.error("WebSocket pub/sub subscriber error: %s: %s", type(e).__name__, e)
                    await asyncio.sleep(1.0)  # Back off on errors


# Module-level instances
manager = ConnectionManager()
broadcaster = PubSubBroadcaster(manager)


async def authenticate_websocket(
    websocket: WebSocket,
) -> tuple[UUID, UUID] | None:
    """
    Authenticate WebSocket connection using session cookie.

    Returns (user_id, tenant_id) tuple if authenticated, None otherwise.
    """
    settings = get_settings()

    # In dev mode with auth disabled, use the existing dev tenant/user
    # that was created by the auth bootstrapper at startup — do NOT
    # auto-create users or bypass authentication entirely.
    # SECURITY: Only allow auth bypass in development environment
    if (settings.auth.provider == "none"
            and settings.server.debug
            and settings.server.host in ("127.0.0.1", "localhost", "::1")):
        async with get_session_factory()() as session:
            tenant_query = select(Tenant).where(
                (Tenant.idp_tenant_id == "dev-tenant") | (Tenant.azure_tenant_id == "dev-tenant")
            )
            result = await session.execute(tenant_query)
            tenant = result.scalars().first()
            if tenant:
                user_query = select(User).where(User.tenant_id == tenant.id)
                result = await session.execute(user_query)
                user = result.scalars().first()
                if user:
                    return (user.id, tenant.id)
        logger.warning("WebSocket: auth.provider=none but no dev tenant/user found")
        return None

    # Get session cookie from websocket headers
    cookies = websocket.cookies
    session_id = cookies.get(SESSION_COOKIE_NAME)

    if not session_id:
        logger.warning("WebSocket connection rejected: no session cookie")
        return None

    # Validate session
    async with get_session_factory()() as db_session:
        session_store = SessionStore(db_session)
        session_data = await session_store.get(session_id)

        if not session_data:
            logger.warning("WebSocket connection rejected: invalid session")
            return None

        # Check expiration
        expires_at_str = session_data.get("expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
            except (ValueError, TypeError):
                logger.warning("WebSocket connection rejected: invalid expires_at format")
                return None
            if expires_at < datetime.now(timezone.utc):
                logger.warning("WebSocket connection rejected: expired session")
                return None

        claims = session_data.get("claims", {})
        tenant_azure_id = claims.get("tid")
        user_email = claims.get("preferred_username")

        if not tenant_azure_id or not user_email:
            logger.warning("WebSocket connection rejected: missing claims")
            return None

        # Find user and tenant (try new field first, fall back to legacy)
        tenant_query = select(Tenant).where(
            (Tenant.idp_tenant_id == tenant_azure_id) | (Tenant.azure_tenant_id == tenant_azure_id)
        )
        result = await db_session.execute(tenant_query)
        tenant = result.scalars().first()

        if not tenant:
            logger.warning("WebSocket connection rejected: tenant not found")
            return None

        user_query = select(User).where(
            User.tenant_id == tenant.id,
            User.email == user_email,
        )
        result = await db_session.execute(user_query)
        user = result.scalar_one_or_none()

        if not user:
            logger.warning("WebSocket connection rejected: user not found")
            return None

        return (user.id, tenant.id)


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_id: UUID,
):
    """
    WebSocket endpoint for real-time scan progress updates.

    Security:
    - Validates Origin header to prevent cross-site WebSocket hijacking
    - Requires authentication via session cookie
    - Connection is rejected with close code 1008 if not authorized.
    """
    # Security: Validate origin before accepting connection
    if not validate_websocket_origin(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Authenticate before accepting connection
    auth_result = await authenticate_websocket(websocket)

    if not auth_result:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id, tenant_id = auth_result

    # Verify user has access to this scan (same tenant)
    async with get_session_factory()() as session:
        scan = await session.get(ScanJob, scan_id)
        if not scan or scan.tenant_id != tenant_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    conn = await manager.connect(scan_id, websocket, user_id, tenant_id)
    if conn is None:
        return

    # Rate limiting state
    message_timestamps: list[float] = []

    try:
        while True:
            # Keep connection alive and wait for messages
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

                # Enforce message rate limit
                now = asyncio.get_event_loop().time()
                message_timestamps = [
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

                # Handle any client messages (e.g., ping)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        manager.disconnect(scan_id, conn)


async def send_scan_progress(
    scan_id: UUID,
    status: str,
    progress: dict,
):
    """Send scan progress update to all connected clients (all instances)."""
    message = {
        "type": "progress",
        "scan_id": str(scan_id),
        "status": status,
        "progress": progress,
    }
    await broadcaster.publish(scan_id, message)


async def send_scan_file_result(
    scan_id: UUID,
    file_path: str,
    risk_score: int,
    risk_tier: str,
    entity_counts: dict,
):
    """Send individual file scan result to connected clients (all instances)."""
    message = {
        "type": "file_result",
        "scan_id": str(scan_id),
        "file_path": file_path,
        "risk_score": risk_score,
        "risk_tier": risk_tier,
        "entity_counts": entity_counts,
    }
    await broadcaster.publish(scan_id, message)


async def send_scan_completed(
    scan_id: UUID,
    status: str,
    summary: dict,
):
    """Send scan completion notification to connected clients (all instances)."""
    message = {
        "type": "completed",
        "scan_id": str(scan_id),
        "status": status,
        "summary": summary,
    }
    await broadcaster.publish(scan_id, message)

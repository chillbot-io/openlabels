"""
WebSocket endpoints for real-time updates.

Security: WebSocket connections are authenticated using the same session
cookie as HTTP requests. Unauthenticated connections are rejected.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID
import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.config import get_settings
from openlabels.server.db import get_session_factory
from openlabels.server.models import ScanJob, User, Tenant
from openlabels.server.session import SessionStore

logger = logging.getLogger(__name__)

router = APIRouter()

# Cookie name must match auth.py
SESSION_COOKIE_NAME = "openlabels_session"


class AuthenticatedConnection:
    """Authenticated WebSocket connection with user context."""

    def __init__(self, websocket: WebSocket, user_id: UUID, tenant_id: UUID):
        self.websocket = websocket
        self.user_id = user_id
        self.tenant_id = tenant_id


class ConnectionManager:
    """Manages WebSocket connections for scan progress updates."""

    def __init__(self):
        self.active_connections: dict[UUID, list[AuthenticatedConnection]] = {}

    async def connect(
        self, scan_id: UUID, websocket: WebSocket, user_id: UUID, tenant_id: UUID
    ) -> AuthenticatedConnection:
        """Accept a new authenticated WebSocket connection."""
        await websocket.accept()
        conn = AuthenticatedConnection(websocket, user_id, tenant_id)
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(conn)
        return conn

    def disconnect(self, scan_id: UUID, conn: AuthenticatedConnection):
        """Remove a WebSocket connection."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id] = [
                c for c in self.active_connections[scan_id]
                if c.websocket != conn.websocket
            ]
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: UUID, message: dict):
        """Send a message to all connections watching a scan."""
        if scan_id in self.active_connections:
            for conn in self.active_connections[scan_id]:
                try:
                    await conn.websocket.send_json(message)
                except Exception:
                    pass


manager = ConnectionManager()


async def authenticate_websocket(
    websocket: WebSocket,
) -> Optional[tuple[UUID, UUID]]:
    """
    Authenticate WebSocket connection using session cookie.

    Returns (user_id, tenant_id) tuple if authenticated, None otherwise.
    """
    settings = get_settings()

    # In dev mode, allow connections without auth
    if settings.auth.provider == "none":
        # Get or create dev user
        async with get_session_factory()() as session:
            # Find dev tenant
            tenant_query = select(Tenant).where(Tenant.azure_tenant_id == "dev-tenant")
            result = await session.execute(tenant_query)
            tenant = result.scalar_one_or_none()

            if not tenant:
                tenant = Tenant(name="Development Tenant", azure_tenant_id="dev-tenant")
                session.add(tenant)
                await session.flush()

            # Find dev user
            user_query = select(User).where(
                User.tenant_id == tenant.id,
                User.email == "dev@localhost",
            )
            result = await session.execute(user_query)
            user = result.scalar_one_or_none()

            if not user:
                user = User(
                    tenant_id=tenant.id,
                    email="dev@localhost",
                    name="Development User",
                    role="admin",
                )
                session.add(user)
                await session.flush()

            await session.commit()
            return (user.id, tenant.id)

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
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at < datetime.utcnow():
                logger.warning("WebSocket connection rejected: expired session")
                return None

        claims = session_data.get("claims", {})
        tenant_azure_id = claims.get("tid")
        user_email = claims.get("preferred_username")

        if not tenant_azure_id or not user_email:
            logger.warning("WebSocket connection rejected: missing claims")
            return None

        # Find user and tenant
        tenant_query = select(Tenant).where(Tenant.azure_tenant_id == tenant_azure_id)
        result = await db_session.execute(tenant_query)
        tenant = result.scalar_one_or_none()

        if not tenant:
            logger.warning(f"WebSocket connection rejected: tenant not found")
            return None

        user_query = select(User).where(
            User.tenant_id == tenant.id,
            User.email == user_email,
        )
        result = await db_session.execute(user_query)
        user = result.scalar_one_or_none()

        if not user:
            logger.warning(f"WebSocket connection rejected: user not found")
            return None

        return (user.id, tenant.id)


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_id: UUID,
):
    """
    WebSocket endpoint for real-time scan progress updates.

    Requires authentication via session cookie. Connection is rejected
    with close code 4001 if not authenticated.
    """
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

    try:
        while True:
            # Keep connection alive and wait for messages
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0,
                )
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
    """Send scan progress update to all connected clients."""
    message = {
        "type": "progress",
        "scan_id": str(scan_id),
        "status": status,
        "progress": progress,
    }
    await manager.broadcast(scan_id, message)


async def send_scan_file_result(
    scan_id: UUID,
    file_path: str,
    risk_score: int,
    risk_tier: str,
    entity_counts: dict,
):
    """Send individual file scan result to connected clients."""
    message = {
        "type": "file_result",
        "scan_id": str(scan_id),
        "file_path": file_path,
        "risk_score": risk_score,
        "risk_tier": risk_tier,
        "entity_counts": entity_counts,
    }
    await manager.broadcast(scan_id, message)


async def send_scan_completed(
    scan_id: UUID,
    status: str,
    summary: dict,
):
    """Send scan completion notification to connected clients."""
    message = {
        "type": "completed",
        "scan_id": str(scan_id),
        "status": status,
        "summary": summary,
    }
    await manager.broadcast(scan_id, message)

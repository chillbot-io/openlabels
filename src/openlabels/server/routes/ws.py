"""
WebSocket endpoints for real-time updates.
"""

from uuid import UUID
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import ScanJob

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for scan progress updates."""

    def __init__(self):
        self.active_connections: dict[UUID, list[WebSocket]] = {}

    async def connect(self, scan_id: UUID, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: UUID, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: UUID, message: dict):
        """Send a message to all connections watching a scan."""
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass


manager = ConnectionManager()


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_id: UUID,
):
    """WebSocket endpoint for real-time scan progress updates."""
    await manager.connect(scan_id, websocket)

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
        manager.disconnect(scan_id, websocket)


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

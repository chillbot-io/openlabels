"""
FastAPI Scanner Server.

Provides REST API and WebSocket endpoints for async file scanning.

Usage:
    # Start server
    openlabels serve --port 8000

    # Or directly with uvicorn
    uvicorn openlabels.api.server:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .models import ScanRequest, ScanJob, ScanResult, ScanStatus
from .scanner import get_scanner, AsyncScanner


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage scanner lifecycle."""
    yield
    # Shutdown scanner on app exit
    scanner = get_scanner()
    scanner.shutdown()


app = FastAPI(
    title="OpenLabels Scanner API",
    description="Async file scanning service for sensitive data detection",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for GUI clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "openlabels-scanner"}


@app.post("/scan", response_model=ScanJob)
async def start_scan(request: ScanRequest):
    """Start a new scan job.

    Returns immediately with job ID. Use /scan/{job_id}/events to stream results.
    """
    scanner = get_scanner()
    job = await scanner.start_scan(request)
    return job


@app.get("/scan/{job_id}", response_model=ScanJob)
async def get_scan_status(job_id: str):
    """Get status of a scan job."""
    scanner = get_scanner()
    job = await scanner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/scan/{job_id}/results", response_model=list[ScanResult])
async def get_scan_results(
    job_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Get scan results with pagination."""
    scanner = get_scanner()
    job = await scanner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    results = await scanner.get_results(job_id, offset, limit)
    return results


@app.delete("/scan/{job_id}")
async def cancel_scan(job_id: str):
    """Cancel a running scan."""
    scanner = get_scanner()
    job = await scanner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Job is not running")

    await scanner.cancel_job(job_id)
    return {"status": "cancelled", "job_id": job_id}


@app.get("/scan/{job_id}/events")
async def stream_scan_events(job_id: str):
    """Stream scan events using Server-Sent Events (SSE).

    Events:
    - progress: {"current": N, "total": M, "percent": P}
    - batch: {"results": [...]}
    - complete: {"results_count": N, "duration": T}
    - error: {"error": "message"}
    - status: {"status": "running"|"cancelled"|...}
    """
    scanner = get_scanner()
    job = await scanner.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        async for event in scanner.stream_events(job_id):
            data = json.dumps(event.data)
            yield f"event: {event.event}\ndata: {data}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@app.websocket("/scan/{job_id}/ws")
async def websocket_scan_events(websocket: WebSocket, job_id: str):
    """WebSocket endpoint for scan events.

    Preferred over SSE for bidirectional communication.
    Client can send {"action": "cancel"} to stop the scan.
    """
    scanner = get_scanner()
    job = await scanner.get_job(job_id)
    if not job:
        await websocket.close(code=4004, reason="Job not found")
        return

    await websocket.accept()

    # Task to stream events to client
    async def send_events():
        try:
            async for event in scanner.stream_events(job_id):
                await websocket.send_json({
                    "event": event.event,
                    "data": event.data,
                })
        except WebSocketDisconnect:
            pass

    # Task to receive commands from client
    async def receive_commands():
        try:
            while True:
                data = await websocket.receive_json()
                if data.get("action") == "cancel":
                    await scanner.cancel_job(job_id)
                    await websocket.send_json({
                        "event": "cancelled",
                        "data": {"job_id": job_id},
                    })
        except WebSocketDisconnect:
            pass

    # Run both tasks concurrently
    send_task = asyncio.create_task(send_events())
    recv_task = asyncio.create_task(receive_commands())

    try:
        await asyncio.gather(send_task, recv_task, return_exceptions=True)
    finally:
        send_task.cancel()
        recv_task.cancel()
        try:
            await websocket.close()
        except Exception:
            pass


def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Run the scanner server."""
    import uvicorn
    uvicorn.run(
        "openlabels.api.server:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    run_server()

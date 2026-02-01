"""
API Client for connecting GUI to the scanner server.

When the scanner server is running, the GUI can offload scanning
to the server for better performance and responsiveness.
"""

import json
from typing import Optional, Dict, Any, Callable
from urllib.request import urlopen, Request
from urllib.error import URLError
import threading

from PySide6.QtCore import QObject, Signal, QThread


class ScannerAPIClient(QObject):
    """Client for communicating with the Scanner API server.

    Provides WebSocket-based real-time updates when scanning via the server.
    Falls back gracefully if server is not available.
    """

    # Signals mirror ScanWorker for drop-in compatibility
    progress = Signal(int, int)      # current, total
    result = Signal(dict)            # single scan result
    batch_results = Signal(list)     # batched results
    finished = Signal()              # scan complete
    error = Signal(str)              # error message

    def __init__(self, server_url: str = "http://localhost:8000", parent=None):
        super().__init__(parent)
        self._server_url = server_url.rstrip("/")
        self._job_id: Optional[str] = None
        self._stop_requested = False
        self._ws_thread: Optional[QThread] = None

    @property
    def server_url(self) -> str:
        return self._server_url

    @server_url.setter
    def server_url(self, url: str):
        self._server_url = url.rstrip("/")

    def is_server_available(self) -> bool:
        """Check if the scanner server is running."""
        try:
            req = Request(f"{self._server_url}/health")
            with urlopen(req, timeout=2) as response:
                data = json.loads(response.read())
                return data.get("status") == "healthy"
        except (URLError, json.JSONDecodeError, TimeoutError):
            return False

    def start_scan(self, path: str, target_type: str = "local",
                   s3_credentials: Optional[Dict[str, str]] = None) -> bool:
        """Start a scan via the API server.

        Returns True if scan started successfully, False otherwise.
        """
        self._stop_requested = False

        # Build request payload
        payload = {
            "path": path,
            "target_type": target_type,
        }
        if s3_credentials:
            payload["s3_credentials"] = s3_credentials

        try:
            req = Request(
                f"{self._server_url}/scan",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as response:
                data = json.loads(response.read())
                self._job_id = data.get("job_id")

                if self._job_id:
                    # Start SSE listener in background thread
                    self._start_event_listener()
                    return True

        except (URLError, json.JSONDecodeError) as e:
            self.error.emit(f"Failed to start scan: {e}")

        return False

    def _start_event_listener(self):
        """Start listening for Server-Sent Events in a background thread."""
        thread = threading.Thread(target=self._listen_for_events, daemon=True)
        thread.start()

    def _listen_for_events(self):
        """Listen for SSE events from the server."""
        if not self._job_id:
            return

        url = f"{self._server_url}/scan/{self._job_id}/events"

        try:
            req = Request(url)
            req.add_header("Accept", "text/event-stream")

            with urlopen(req, timeout=300) as response:
                event_type = None
                data_buffer = []

                for line in response:
                    if self._stop_requested:
                        break

                    line = line.decode("utf-8").strip()

                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data_buffer.append(line[5:].strip())
                    elif line == "":
                        # Empty line = end of event
                        if event_type and data_buffer:
                            data_str = "".join(data_buffer)
                            self._handle_event(event_type, data_str)
                        event_type = None
                        data_buffer = []

        except (URLError, TimeoutError) as e:
            if not self._stop_requested:
                self.error.emit(f"Lost connection to server: {e}")

    def _handle_event(self, event_type: str, data_str: str):
        """Handle an SSE event."""
        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            return

        if event_type == "progress":
            current = data.get("current", 0)
            total = data.get("total", 0)
            self.progress.emit(current, total)

        elif event_type == "result":
            self.result.emit(data)

        elif event_type == "batch":
            results = data.get("results", [])
            if results:
                self.batch_results.emit(results)

        elif event_type == "complete":
            self.finished.emit()

        elif event_type == "error":
            self.error.emit(data.get("error", "Unknown error"))
            self.finished.emit()

        elif event_type == "status":
            status = data.get("status")
            if status == "cancelled":
                self.finished.emit()

    def stop(self):
        """Request the scan to stop."""
        self._stop_requested = True

        if self._job_id:
            try:
                req = Request(
                    f"{self._server_url}/scan/{self._job_id}",
                    method="DELETE",
                )
                with urlopen(req, timeout=5):
                    pass
            except URLError:
                pass  # Server may already be stopped

    def get_job_status(self) -> Optional[Dict[str, Any]]:
        """Get the current job status."""
        if not self._job_id:
            return None

        try:
            req = Request(f"{self._server_url}/scan/{self._job_id}")
            with urlopen(req, timeout=5) as response:
                return json.loads(response.read())
        except (URLError, json.JSONDecodeError):
            return None


def create_scanner(server_url: Optional[str] = None):
    """Create a scanner - either API client or local worker.

    If server_url is provided and server is available, returns API client.
    Otherwise returns the local ScanWorker.
    """
    if server_url:
        client = ScannerAPIClient(server_url)
        if client.is_server_available():
            return client

    # Fall back to local scanner
    from .scan_worker import ScanWorker
    return ScanWorker

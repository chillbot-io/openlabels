"""
Background worker for scan operations.

Runs scan tasks in a separate thread to keep UI responsive.
Emits progress signals for UI updates.

Supports two modes:
- Polling mode: Periodically checks scan status via REST API
- WebSocket mode: Real-time streaming updates (preferred)
"""

import json
import logging
import time
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Check for httpx
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Check for websockets
try:
    import websockets
    import asyncio
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

try:
    from PySide6.QtCore import QThread, Signal, QObject
    PYSIDE_AVAILABLE = True
except ImportError:
    PYSIDE_AVAILABLE = False
    QThread = object
    QObject = object


class ScanWorker(QThread if PYSIDE_AVAILABLE else object):
    """
    Worker thread for running scans.

    Supports two modes:
    - WebSocket mode: Real-time streaming (preferred, uses websockets library)
    - Polling mode: Periodic status checks (fallback)

    Signals:
        progress: Emitted with (current, total, message)
        file_scanned: Emitted when a file is processed (file_path, result)
        completed: Emitted when scan completes (results)
        error: Emitted on error (message)
        cancelled: Emitted when scan is cancelled
    """

    if PYSIDE_AVAILABLE:
        progress = Signal(int, int, str)
        file_scanned = Signal(str, dict)
        completed = Signal(list)
        error = Signal(str)
        cancelled = Signal()

    def __init__(
        self,
        target_id: str,
        server_url: str,
        parent: Optional[QObject] = None,
        use_websocket: bool = True,
    ):
        """
        Initialize the scan worker.

        Args:
            target_id: ID of the scan target
            server_url: Base URL of the OpenLabels server
            parent: Parent QObject
            use_websocket: Use WebSocket streaming if available
        """
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
        self.target_id = target_id
        self.server_url = server_url.rstrip("/")
        self.use_websocket = use_websocket and WEBSOCKETS_AVAILABLE
        self._cancelled = False
        self._scan_id: Optional[str] = None
        self._results: List[Dict] = []

    def run(self) -> None:
        """Run the scan in background."""
        if not PYSIDE_AVAILABLE:
            return

        if not HTTPX_AVAILABLE:
            self.error.emit("httpx not installed")
            return

        try:
            logger.info(f"Starting scan for target {self.target_id}")
            self.progress.emit(0, 100, "Initializing scan...")

            # Create scan job via API
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    f"{self.server_url}/api/scans",
                    json={"target_id": self.target_id},
                )

                if response.status_code != 201:
                    self.error.emit(f"Failed to create scan: {response.status_code}")
                    return

                scan_data = response.json()
                self._scan_id = scan_data.get("id")

                if not self._scan_id:
                    self.error.emit("No scan ID returned")
                    return

                self.progress.emit(5, 100, "Scan created, connecting...")

                # Use WebSocket for real-time updates if available
                if self.use_websocket:
                    self._run_websocket_mode(client)
                else:
                    self._run_polling_mode(client)

        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.error.emit(str(e))

    def _run_websocket_mode(self, client: "httpx.Client") -> None:
        """Run scan with WebSocket streaming for real-time updates."""
        import asyncio

        async def websocket_handler():
            # Convert HTTP URL to WebSocket URL
            ws_url = self.server_url.replace("http://", "ws://").replace("https://", "wss://")
            ws_url = f"{ws_url}/ws/scans/{self._scan_id}"

            try:
                async with websockets.connect(ws_url, ping_interval=20) as ws:
                    self.progress.emit(10, 100, "Connected, receiving results...")

                    while not self._cancelled:
                        try:
                            message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                            data = json.loads(message)

                            msg_type = data.get("type")

                            if msg_type == "file_result":
                                # Individual file result
                                file_result = {
                                    "file_path": data.get("file_path"),
                                    "risk_score": data.get("risk_score"),
                                    "risk_tier": data.get("risk_tier"),
                                    "entity_counts": data.get("entity_counts", {}),
                                }
                                self._results.append(file_result)
                                self.file_scanned.emit(
                                    data.get("file_path", ""),
                                    file_result,
                                )

                            elif msg_type == "progress":
                                # Progress update
                                progress = data.get("progress", {})
                                files_scanned = progress.get("files_scanned", 0)
                                current_file = progress.get("current_file", "")
                                # Estimate progress (10-90% for scanning)
                                pct = min(90, 10 + files_scanned)
                                self.progress.emit(pct, 100, f"Scanning: {current_file[:40]}")

                            elif msg_type == "completed":
                                # Scan completed
                                status = data.get("status", "completed")
                                summary = data.get("summary", {})
                                self.progress.emit(100, 100, f"Complete: {status}")
                                break

                            elif msg_type == "heartbeat":
                                # Keep-alive, send ping
                                await ws.send("ping")

                        except asyncio.TimeoutError:
                            # Check if cancelled
                            if self._cancelled:
                                self._cancel_scan(client)
                                self.cancelled.emit()
                                return
                            continue

            except Exception as e:
                logger.warning(f"WebSocket error, falling back to polling: {e}")
                # Fall back to polling mode
                self._run_polling_mode(client)
                return

        # Run async WebSocket handler
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(websocket_handler())
        finally:
            loop.close()

        if not self._cancelled:
            self.completed.emit(self._results)

    def _run_polling_mode(self, client: "httpx.Client") -> None:
        """Run scan with periodic polling for status updates."""
        poll_interval = 2.0  # seconds

        while True:
            if self._cancelled:
                self._cancel_scan(client)
                self.cancelled.emit()
                return

            # Get scan status
            status_response = client.get(
                f"{self.server_url}/api/scans/{self._scan_id}"
            )

            if status_response.status_code != 200:
                self.error.emit(f"Failed to get scan status: {status_response.status_code}")
                return

            status_data = status_response.json()
            status = status_data.get("status", "unknown")

            # Update progress
            progress = status_data.get("progress", {})
            current = progress.get("files_scanned", 0)
            total = progress.get("files_total", 100)
            current_file = progress.get("current_file", "")

            # Calculate percentage (reserve 5% for init, 5% for completion)
            if total > 0:
                pct = 5 + int(90 * current / total)
            else:
                pct = 50

            self.progress.emit(pct, 100, f"Scanning: {current_file[:50]}")

            # Check if completed
            if status in ("completed", "failed", "cancelled"):
                break

            time.sleep(poll_interval)

        # Fetch results
        self.progress.emit(95, 100, "Fetching results...")

        results_response = client.get(
            f"{self.server_url}/api/results",
            params={"job_id": self._scan_id},
        )

        if results_response.status_code == 200:
            results_data = results_response.json()
            self._results = results_data.get("items", [])

            # Emit individual file results
            for result in self._results:
                self.file_scanned.emit(
                    result.get("file_path", ""),
                    result,
                )

        self.progress.emit(100, 100, "Scan complete")
        self.completed.emit(self._results)

    def _cancel_scan(self, client: "httpx.Client") -> None:
        """Cancel the running scan."""
        if self._scan_id:
            try:
                client.delete(f"{self.server_url}/api/scans/{self._scan_id}")
            except Exception as e:
                logger.warning(f"Failed to cancel scan: {e}")

    def cancel(self) -> None:
        """Request cancellation of the scan."""
        self._cancelled = True


class LabelWorker(QThread if PYSIDE_AVAILABLE else object):
    """
    Worker thread for applying labels.

    Signals:
        progress: Emitted with (current, total, message)
        file_labeled: Emitted when a file is labeled (file_path, label)
        completed: Emitted when labeling completes (success_count, fail_count)
        error: Emitted on error (message)
    """

    if PYSIDE_AVAILABLE:
        progress = Signal(int, int, str)
        file_labeled = Signal(str, str)
        completed = Signal(int, int)
        error = Signal(str)

    def __init__(
        self,
        result_ids: List[str],
        label_id: str,
        server_url: str,
        parent: Optional[QObject] = None,
    ):
        """
        Initialize the label worker.

        Args:
            result_ids: IDs of results to label
            label_id: ID of the label to apply
            server_url: Base URL of the OpenLabels server
            parent: Parent QObject
        """
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
        self.result_ids = result_ids
        self.label_id = label_id
        self.server_url = server_url.rstrip("/")
        self._cancelled = False

    def run(self) -> None:
        """Run the labeling in background."""
        if not PYSIDE_AVAILABLE:
            return

        if not HTTPX_AVAILABLE:
            self.error.emit("httpx not installed")
            return

        try:
            success_count = 0
            fail_count = 0
            total = len(self.result_ids)

            with httpx.Client(timeout=60.0) as client:
                for i, result_id in enumerate(self.result_ids):
                    if self._cancelled:
                        break

                    self.progress.emit(i, total, f"Labeling file {i+1}/{total}")

                    try:
                        response = client.post(
                            f"{self.server_url}/api/labels/apply",
                            json={
                                "result_id": result_id,
                                "label_id": self.label_id,
                            },
                        )

                        if response.status_code == 202:
                            success_count += 1
                            self.file_labeled.emit(result_id, self.label_id)
                        else:
                            fail_count += 1
                            logger.warning(f"Failed to label {result_id}: {response.status_code}")

                    except Exception as e:
                        fail_count += 1
                        logger.warning(f"Failed to label {result_id}: {e}")

            self.progress.emit(total, total, "Labeling complete")
            self.completed.emit(success_count, fail_count)

        except Exception as e:
            logger.error(f"Labeling error: {e}")
            self.error.emit(str(e))

    def cancel(self) -> None:
        """Request cancellation of labeling."""
        self._cancelled = True


class APIWorker(QThread if PYSIDE_AVAILABLE else object):
    """
    Generic worker for API calls.

    Signals:
        completed: Emitted with result data
        error: Emitted on error (message)
    """

    if PYSIDE_AVAILABLE:
        completed = Signal(object)
        error = Signal(str)

    def __init__(
        self,
        method: str,
        url: str,
        parent: Optional[QObject] = None,
        json_data: Optional[dict] = None,
        params: Optional[dict] = None,
    ):
        """
        Initialize the API worker.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL to call
            parent: Parent QObject
            json_data: JSON body for POST/PUT requests
            params: Query parameters
        """
        if not PYSIDE_AVAILABLE:
            return

        super().__init__(parent)
        self.method = method.upper()
        self.url = url
        self.json_data = json_data
        self.params = params

    def run(self) -> None:
        """Run the API call."""
        if not PYSIDE_AVAILABLE:
            return

        if not HTTPX_AVAILABLE:
            self.error.emit("httpx not installed")
            return

        try:
            with httpx.Client(timeout=30.0) as client:
                if self.method == "GET":
                    response = client.get(self.url, params=self.params)
                elif self.method == "POST":
                    response = client.post(self.url, json=self.json_data, params=self.params)
                elif self.method == "PUT":
                    response = client.put(self.url, json=self.json_data, params=self.params)
                elif self.method == "DELETE":
                    response = client.delete(self.url, params=self.params)
                elif self.method == "PATCH":
                    response = client.patch(self.url, json=self.json_data, params=self.params)
                else:
                    self.error.emit(f"Unsupported HTTP method: {self.method}")
                    return

                if response.status_code >= 400:
                    self.error.emit(f"API error: {response.status_code}")
                    return

                # Try to parse JSON, fall back to text
                try:
                    result = response.json()
                except Exception:
                    result = response.text

                self.completed.emit(result)

        except Exception as e:
            logger.error(f"API call error: {e}")
            self.error.emit(str(e))

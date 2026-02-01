"""
Backend server manager for the GUI.

Automatically starts the FastAPI scanner server as a subprocess when
the GUI launches, providing async scanning with zero configuration.
"""

import atexit
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from typing import Optional

logger = logging.getLogger(__name__)


class BackendManager:
    """Manages the scanner backend server lifecycle.

    Starts the server automatically when needed and stops it on exit.
    Handles port selection, health checks, and graceful shutdown.
    """

    DEFAULT_PORT = 8765  # Use non-standard port to avoid conflicts
    STARTUP_TIMEOUT = 10.0  # seconds

    def __init__(self, port: Optional[int] = None):
        self._port = port or self._find_free_port()
        self._process: Optional[subprocess.Popen] = None
        self._started = False

    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    @property
    def is_running(self) -> bool:
        if self._process is None:
            return False
        return self._process.poll() is None

    def _find_free_port(self) -> int:
        """Find an available port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def _check_dependencies(self) -> bool:
        """Check if server dependencies are available."""
        try:
            import fastapi  # noqa: F401
            import uvicorn  # noqa: F401
            import pydantic  # noqa: F401
            return True
        except ImportError:
            return False

    def _health_check(self) -> bool:
        """Check if server is responding."""
        import urllib.request
        import urllib.error

        try:
            req = urllib.request.Request(f"{self.url}/health")
            with urllib.request.urlopen(req, timeout=1) as response:
                return response.status == 200
        except (urllib.error.URLError, TimeoutError, ConnectionRefusedError):
            return False

    def start(self) -> bool:
        """Start the backend server.

        Returns True if server started successfully, False otherwise.
        """
        if self._started and self.is_running:
            return True

        if not self._check_dependencies():
            logger.warning(
                "Backend server dependencies not installed. "
                "Install with: pip install fastapi uvicorn pydantic"
            )
            return False

        # Start uvicorn as subprocess
        cmd = [
            sys.executable, "-m", "uvicorn",
            "openlabels.api.server:app",
            "--host", "127.0.0.1",
            "--port", str(self._port),
            "--log-level", "warning",
        ]

        try:
            # Start process with minimal output
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                # Don't inherit handles on Windows
                close_fds=(os.name != 'nt'),
                # Create new process group for clean shutdown
                start_new_session=True,
            )

            # Register cleanup on exit
            atexit.register(self.stop)

            # Wait for server to be ready
            start_time = time.time()
            while time.time() - start_time < self.STARTUP_TIMEOUT:
                if self._health_check():
                    self._started = True
                    logger.info(f"Backend server started on {self.url}")
                    return True
                if not self.is_running:
                    # Process died, get error output
                    _, stderr = self._process.communicate(timeout=1)
                    logger.error(f"Backend server failed to start: {stderr.decode()}")
                    return False
                time.sleep(0.1)

            logger.error("Backend server startup timeout")
            self.stop()
            return False

        except Exception as e:
            logger.error(f"Failed to start backend server: {e}")
            return False

    def stop(self):
        """Stop the backend server gracefully."""
        if self._process is None:
            return

        if not self.is_running:
            self._process = None
            return

        try:
            # Try graceful shutdown first
            if os.name == 'nt':
                # Windows
                self._process.terminate()
            else:
                # Unix - send SIGTERM to process group
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)

            # Wait for graceful shutdown
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill
                if os.name == 'nt':
                    self._process.kill()
                else:
                    os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)

            logger.info("Backend server stopped")

        except (ProcessLookupError, OSError):
            pass  # Process already dead
        finally:
            self._process = None
            self._started = False


# Global backend manager instance
_backend: Optional[BackendManager] = None


def get_backend() -> BackendManager:
    """Get or create the global backend manager."""
    global _backend
    if _backend is None:
        _backend = BackendManager()
    return _backend


def start_backend() -> Optional[str]:
    """Start the backend server and return its URL.

    Returns None if server couldn't be started (falls back to in-process scanning).
    """
    backend = get_backend()
    if backend.start():
        return backend.url
    return None


def stop_backend():
    """Stop the backend server."""
    global _backend
    if _backend:
        _backend.stop()
        _backend = None

"""
Windows Service wrapper for OpenLabels.

Manages the Docker containers as a Windows service, providing:
- Automatic startup on boot
- Service control via Windows Services console
- Event log integration
- Graceful shutdown

Requires: pywin32

Usage:
    # Install service
    python -m openlabels.windows.service install

    # Start service
    python -m openlabels.windows.service start

    # Stop service
    python -m openlabels.windows.service stop

    # Remove service
    python -m openlabels.windows.service remove
"""

import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Windows service support
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    # Stub classes for non-Windows development
    class win32serviceutil:
        class ServiceFramework:
            pass
    class win32service:
        SERVICE_STOP_PENDING = 0
        SERVICE_STOPPED = 0
    class win32event:
        @staticmethod
        def CreateEvent(*args): return None
        @staticmethod
        def SetEvent(*args): pass
        @staticmethod
        def WaitForSingleObject(*args): return 0
        INFINITE = 0
    class servicemanager:
        @staticmethod
        def LogInfoMsg(msg): print(msg)
        @staticmethod
        def LogErrorMsg(msg): print(msg, file=sys.stderr)


class DockerManager:
    """Manages Docker Compose lifecycle."""

    def __init__(self, compose_file: Optional[Path] = None):
        self.compose_file = compose_file or self._find_compose_file()
        self.project_name = "openlabels"

    def _find_compose_file(self) -> Path:
        """Find docker-compose.yml in standard locations."""
        candidates = [
            Path(os.environ.get("OPENLABELS_HOME", "")) / "docker-compose.yml",
            Path(sys.prefix) / "openlabels" / "docker-compose.yml",
            Path(__file__).parent.parent.parent.parent.parent / "docker-compose.yml",
            Path("C:/ProgramData/OpenLabels/docker-compose.yml"),
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        raise FileNotFoundError("docker-compose.yml not found")

    def _run_compose(self, *args) -> subprocess.CompletedProcess:
        """Run docker-compose command."""
        cmd = [
            "docker", "compose",
            "-f", str(self.compose_file),
            "-p", self.project_name,
            *args
        ]
        return subprocess.run(cmd, capture_output=True, text=True)

    def start(self) -> bool:
        """Start containers."""
        result = self._run_compose("up", "-d")
        if result.returncode != 0:
            logger.error(f"Failed to start containers: {result.stderr}")
            return False
        return True

    def stop(self) -> bool:
        """Stop containers gracefully."""
        result = self._run_compose("down")
        if result.returncode != 0:
            logger.error(f"Failed to stop containers: {result.stderr}")
            return False
        return True

    def status(self) -> dict:
        """Get container status."""
        result = self._run_compose("ps", "--format", "json")
        if result.returncode != 0:
            return {"running": False, "error": result.stderr}
        return {"running": True, "output": result.stdout}

    def is_docker_available(self) -> bool:
        """Check if Docker is available."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False


class OpenLabelsService(win32serviceutil.ServiceFramework):
    """Windows Service for OpenLabels."""

    _svc_name_ = "OpenLabels"
    _svc_display_name_ = "OpenLabels Sensitivity Scanner"
    _svc_description_ = "Scans files for sensitive data and applies Microsoft Purview labels"

    def __init__(self, args):
        if PYWIN32_AVAILABLE:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.docker = DockerManager()
        self.running = False

    def SvcStop(self):
        """Handle service stop request."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False

        # Stop Docker containers
        servicemanager.LogInfoMsg("OpenLabels: Stopping containers...")
        self.docker.stop()
        servicemanager.LogInfoMsg("OpenLabels: Service stopped")

    def SvcDoRun(self):
        """Main service entry point."""
        servicemanager.LogInfoMsg("OpenLabels: Service starting...")

        # Check Docker availability
        if not self.docker.is_docker_available():
            servicemanager.LogErrorMsg("OpenLabels: Docker is not available")
            return

        # Start containers
        if not self.docker.start():
            servicemanager.LogErrorMsg("OpenLabels: Failed to start containers")
            return

        servicemanager.LogInfoMsg("OpenLabels: Service started successfully")
        self.running = True

        # Wait for stop signal
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


def install_service():
    """Install the Windows service."""
    if not PYWIN32_AVAILABLE:
        print("Error: pywin32 is required for Windows service support")
        print("Install it with: pip install pywin32")
        sys.exit(1)

    # Install service
    win32serviceutil.InstallService(
        OpenLabelsService._svc_name_,
        OpenLabelsService._svc_display_name_,
        startType=win32service.SERVICE_AUTO_START,
        description=OpenLabelsService._svc_description_,
    )
    print(f"Service '{OpenLabelsService._svc_display_name_}' installed successfully")


def main():
    """CLI entry point for service management."""
    if len(sys.argv) == 1:
        # Running as service
        if PYWIN32_AVAILABLE:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(OpenLabelsService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            print("Running in console mode (pywin32 not available)")
            docker = DockerManager()
            docker.start()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                docker.stop()
    else:
        # Service management commands
        if PYWIN32_AVAILABLE:
            win32serviceutil.HandleCommandLine(OpenLabelsService)
        else:
            print("Error: pywin32 required for service commands")
            sys.exit(1)


if __name__ == "__main__":
    main()

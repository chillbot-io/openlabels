"""
System tray application for OpenLabels.

Provides a Windows system tray icon with:
- Service status indicator (green/yellow/red)
- Quick access to web UI
- Start/Stop controls
- Configuration access
- Log viewer

Requires: PySide6
"""

import logging
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from PySide6.QtWidgets import (
        QApplication, QSystemTrayIcon, QMenu, QMessageBox
    )
    from PySide6.QtGui import QIcon, QAction, QPixmap, QPainter, QColor
    from PySide6.QtCore import QTimer, Qt
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False


class StatusChecker:
    """Checks OpenLabels service status."""

    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url

    def check_health(self) -> dict:
        """Check API health status."""
        try:
            import httpx
            response = httpx.get(f"{self.api_url}/health", timeout=5)
            if response.status_code == 200:
                return {"status": "healthy", "details": response.json()}
            return {"status": "unhealthy", "code": response.status_code}
        except Exception as e:
            return {"status": "offline", "error": str(e)}

    def check_docker(self) -> bool:
        """Check if Docker containers are running."""
        try:
            result = subprocess.run(
                ["docker", "compose", "-p", "openlabels", "ps", "-q"],
                capture_output=True,
                timeout=10
            )
            return bool(result.stdout.strip())
        except Exception as e:
            logger.debug(f"Docker check failed: {e}")
            return False


class SystemTrayApp:
    """System tray application for OpenLabels."""

    def __init__(self, api_url: str = "http://localhost:8000"):
        if not PYSIDE6_AVAILABLE:
            raise RuntimeError("PySide6 is required for the system tray app")

        self.api_url = api_url
        self.status_checker = StatusChecker(api_url)

        self.app = QApplication.instance() or QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)

        # Create tray icon
        self.tray_icon = QSystemTrayIcon()
        self.tray_icon.setToolTip("OpenLabels")

        # Create menu
        self.menu = self._create_menu()
        self.tray_icon.setContextMenu(self.menu)

        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(30000)  # Check every 30 seconds

        # Initial status check
        self._update_status()

    def _create_icon(self, color: str) -> QIcon:
        """Create a colored status icon."""
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        # Draw circle
        colors = {
            "green": QColor(76, 175, 80),    # Healthy
            "yellow": QColor(255, 193, 7),   # Warning
            "red": QColor(244, 67, 54),      # Error
            "gray": QColor(158, 158, 158),   # Offline
        }
        painter.setBrush(colors.get(color, colors["gray"]))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(4, 4, 24, 24)

        # Draw "O" for OpenLabels
        painter.setPen(QColor(255, 255, 255))
        font = painter.font()
        font.setPixelSize(14)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "O")

        painter.end()
        return QIcon(pixmap)

    def _create_menu(self) -> QMenu:
        """Create the context menu."""
        menu = QMenu()

        # Status (non-clickable)
        self.status_action = QAction("Status: Checking...")
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)

        menu.addSeparator()

        # Open Web UI
        open_ui = QAction("Open Dashboard")
        open_ui.triggered.connect(self._open_dashboard)
        menu.addAction(open_ui)

        # Open Config
        open_config = QAction("Edit Configuration...")
        open_config.triggered.connect(self._open_config)
        menu.addAction(open_config)

        menu.addSeparator()

        # Service controls
        start_action = QAction("Start Service")
        start_action.triggered.connect(self._start_service)
        menu.addAction(start_action)

        stop_action = QAction("Stop Service")
        stop_action.triggered.connect(self._stop_service)
        menu.addAction(stop_action)

        restart_action = QAction("Restart Service")
        restart_action.triggered.connect(self._restart_service)
        menu.addAction(restart_action)

        menu.addSeparator()

        # View logs
        logs_action = QAction("View Logs...")
        logs_action.triggered.connect(self._view_logs)
        menu.addAction(logs_action)

        menu.addSeparator()

        # Quit
        quit_action = QAction("Quit")
        quit_action.triggered.connect(self._quit)
        menu.addAction(quit_action)

        return menu

    def _update_status(self):
        """Update the tray icon based on service status."""
        health = self.status_checker.check_health()

        if health["status"] == "healthy":
            self.tray_icon.setIcon(self._create_icon("green"))
            self.status_action.setText("Status: Running")
            self.tray_icon.setToolTip("OpenLabels - Running")
        elif health["status"] == "unhealthy":
            self.tray_icon.setIcon(self._create_icon("yellow"))
            self.status_action.setText("Status: Unhealthy")
            self.tray_icon.setToolTip("OpenLabels - Unhealthy")
        else:
            # Check if Docker is running but API isn't responding
            if self.status_checker.check_docker():
                self.tray_icon.setIcon(self._create_icon("yellow"))
                self.status_action.setText("Status: Starting...")
                self.tray_icon.setToolTip("OpenLabels - Starting")
            else:
                self.tray_icon.setIcon(self._create_icon("red"))
                self.status_action.setText("Status: Stopped")
                self.tray_icon.setToolTip("OpenLabels - Stopped")

    def _open_dashboard(self):
        """Open the web dashboard in default browser."""
        webbrowser.open(self.api_url)

    def _open_config(self):
        """Open configuration file in default editor."""
        from openlabels.core.constants import DATA_DIR
        config_paths = [
            Path("C:/ProgramData/OpenLabels/config.yaml"),
            DATA_DIR / "config.yaml",
        ]
        for path in config_paths:
            if path.exists():
                subprocess.run(["notepad.exe", str(path)])
                return

        QMessageBox.warning(
            None,
            "Configuration Not Found",
            "No configuration file found. Create config.yaml in:\n"
            "C:\\ProgramData\\OpenLabels\\config.yaml"
        )

    def _start_service(self):
        """Start the OpenLabels service."""
        try:
            subprocess.run(
                ["docker", "compose", "-p", "openlabels", "up", "-d"],
                check=True
            )
            self._update_status()
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(None, "Error", f"Failed to start service: {e}")

    def _stop_service(self):
        """Stop the OpenLabels service."""
        try:
            subprocess.run(
                ["docker", "compose", "-p", "openlabels", "down"],
                check=True
            )
            self._update_status()
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(None, "Error", f"Failed to stop service: {e}")

    def _restart_service(self):
        """Restart the OpenLabels service."""
        self._stop_service()
        self._start_service()

    def _view_logs(self):
        """View Docker logs."""
        try:
            subprocess.Popen(
                ["cmd", "/c", "docker compose -p openlabels logs -f & pause"],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Failed to open logs: {e}")

    def _quit(self):
        """Quit the application."""
        self.tray_icon.hide()
        self.app.quit()

    def run(self):
        """Run the application."""
        self.tray_icon.show()
        return self.app.exec()


def main():
    """Entry point for system tray application."""
    if not PYSIDE6_AVAILABLE:
        print("Error: PySide6 is required for the system tray app")
        print("Install it with: pip install PySide6")
        sys.exit(1)

    app = SystemTrayApp()
    sys.exit(app.run())


if __name__ == "__main__":
    main()

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
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
    from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap
    from PySide6.QtWidgets import QApplication, QMenu, QMessageBox, QSystemTrayIcon
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
            # Docker check failures are expected if Docker is not installed
            logger.debug(f"Docker check failed: {type(e).__name__}: {e}")
            return False


if PYSIDE6_AVAILABLE:
    class ServiceWorker(QObject):
        """Background worker for service operations (start/stop/restart)."""

        finished = Signal(bool, str)  # (success, message)

        def __init__(self, command: list):
            super().__init__()
            self._command = command

        def run(self):
            try:
                subprocess.run(self._command, check=True, capture_output=True, timeout=120)
                self.finished.emit(True, "Operation completed successfully")
            except subprocess.CalledProcessError as e:
                stderr = e.stderr.decode(errors="replace") if e.stderr else str(e)
                self.finished.emit(False, f"Command failed: {stderr}")
            except subprocess.TimeoutExpired:
                self.finished.emit(False, "Operation timed out")
            except OSError as e:
                self.finished.emit(False, str(e))


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

        # Auto-start toggle
        self.auto_start_action = QAction("Start with Windows")
        self.auto_start_action.setCheckable(True)
        self.auto_start_action.setChecked(self._is_auto_start_enabled())
        self.auto_start_action.toggled.connect(self._toggle_auto_start)
        menu.addAction(self.auto_start_action)

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
        """Open configuration file in the OS default editor."""
        from openlabels.core.constants import DATA_DIR
        config_paths = [
            Path("C:/ProgramData/OpenLabels/config.yaml"),
            DATA_DIR / "config.yaml",
        ]
        for path in config_paths:
            if path.exists():
                os.startfile(str(path))
                return

        QMessageBox.warning(
            None,
            "Configuration Not Found",
            "No configuration file found. Create config.yaml in:\n"
            "C:\\ProgramData\\OpenLabels\\config.yaml"
        )

    # ------------------------------------------------------------------
    # Service controls (12.6: run in background thread)
    # ------------------------------------------------------------------

    def _run_service_command(self, command: list, status_text: str):
        """Run a service command in a background thread."""
        self.status_action.setText(f"Status: {status_text}")
        worker = ServiceWorker(command)
        thread = QThread()
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.finished.connect(lambda ok, msg: self._on_service_command_done(ok, msg))
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        # Keep references so they aren't garbage-collected
        self._active_thread = thread
        self._active_worker = worker
        thread.start()

    def _on_service_command_done(self, success: bool, message: str):
        """Handle completion of a background service command."""
        self._update_status()
        if not success:
            self.notify("Service Error", message, error=True)

    def _start_service(self):
        """Start the OpenLabels service in the background."""
        self._run_service_command(
            ["docker", "compose", "-p", "openlabels", "up", "-d"],
            "Starting...",
        )

    def _stop_service(self):
        """Stop the OpenLabels service in the background."""
        self._run_service_command(
            ["docker", "compose", "-p", "openlabels", "down"],
            "Stopping...",
        )

    def _restart_service(self):
        """Restart the OpenLabels service in the background."""
        self._run_service_command(
            ["docker", "compose", "-p", "openlabels", "restart"],
            "Restarting...",
        )

    def _view_logs(self):
        """Open the log viewer window."""
        from openlabels.windows.log_viewer import LogViewer
        if not hasattr(self, "_log_viewer") or self._log_viewer is None:
            self._log_viewer = LogViewer()
        self._log_viewer.show()
        self._log_viewer.raise_()
        self._log_viewer.activateWindow()

    # ------------------------------------------------------------------
    # Tray notifications (12.4)
    # ------------------------------------------------------------------

    def notify(self, title: str, message: str, *, error: bool = False, duration_ms: int = 5000):
        """Show a system tray balloon notification."""
        icon = QSystemTrayIcon.Critical if error else QSystemTrayIcon.Information
        self.tray_icon.showMessage(title, message, icon, duration_ms)

    def on_scan_completed(self, job_name: str, files_found: int):
        """Notify the user when a scan completes."""
        self.notify(
            "Scan Complete",
            f"{job_name}: {files_found} sensitive file{'s' if files_found != 1 else ''} found",
        )

    def on_label_applied(self, file_count: int, label_name: str):
        """Notify the user when labels have been applied."""
        self.notify(
            "Labels Applied",
            f"Applied '{label_name}' to {file_count} file{'s' if file_count != 1 else ''}",
        )

    # ------------------------------------------------------------------
    # Auto-start (12.5)
    # ------------------------------------------------------------------

    _REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    _REGISTRY_APP_NAME = "OpenLabels"

    def _is_auto_start_enabled(self) -> bool:
        """Check if OpenLabels is set to start with Windows."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, self._REGISTRY_KEY, 0, winreg.KEY_READ,
            )
            try:
                winreg.QueryValueEx(key, self._REGISTRY_APP_NAME)
                return True
            except FileNotFoundError:
                return False
            finally:
                winreg.CloseKey(key)
        except Exception:
            return False

    def _toggle_auto_start(self, enabled: bool):
        """Enable or disable auto-start on Windows login."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, self._REGISTRY_KEY,
                0, winreg.KEY_SET_VALUE,
            )
            try:
                if enabled:
                    winreg.SetValueEx(
                        key, self._REGISTRY_APP_NAME, 0,
                        winreg.REG_SZ, sys.executable,
                    )
                else:
                    try:
                        winreg.DeleteValue(key, self._REGISTRY_APP_NAME)
                    except FileNotFoundError:
                        pass
            finally:
                winreg.CloseKey(key)
        except Exception as e:
            logger.error(f"Failed to toggle auto-start: {e}")
            QMessageBox.warning(
                None, "Auto-Start Error",
                f"Could not {'enable' if enabled else 'disable'} auto-start: {e}",
            )
            # Revert checkbox without re-triggering the signal
            self.auto_start_action.blockSignals(True)
            self.auto_start_action.setChecked(not enabled)
            self.auto_start_action.blockSignals(False)

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

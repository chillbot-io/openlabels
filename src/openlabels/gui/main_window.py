"""
Main window for the OpenLabels GUI.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import (
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QMenu,
        QMenuBar,
        QMessageBox,
        QStatusBar,
        QTabWidget,
        QToolBar,
        QVBoxLayout,
        QWidget,
    )

    PYSIDE_AVAILABLE = True
except ImportError:
    # PySide6 not installed - GUI main window unavailable
    logger.debug("PySide6 not installed - GUI main window disabled")
    PYSIDE_AVAILABLE = False


if PYSIDE_AVAILABLE:
    from openlabels.gui.widgets.dashboard_widget import DashboardWidget
    from openlabels.gui.widgets.file_detail_widget import FileDetailWidget
    from openlabels.gui.widgets.health_widget import HealthWidget
    from openlabels.gui.widgets.labels_widget import LabelsWidget
    from openlabels.gui.widgets.monitoring_widget import MonitoringWidget
    from openlabels.gui.widgets.results_widget import ResultsWidget
    from openlabels.gui.widgets.scan_widget import ScanWidget
    from openlabels.gui.widgets.schedules_widget import SchedulesWidget
    from openlabels.gui.widgets.settings_widget import SettingsWidget
    from openlabels.gui.widgets.targets_widget import TargetsWidget
    from openlabels.gui.workers.scan_worker import APIWorker

    class MainWindow(QMainWindow):
        """Main application window."""

        def __init__(self, server_url: str = "http://localhost:8000"):
            super().__init__()

            self.server_url = server_url
            self._api_worker: Optional[APIWorker] = None

            self.setWindowTitle("OpenLabels")
            self.setMinimumSize(1200, 800)

            self._setup_menu()
            self._setup_toolbar()
            self._setup_ui()
            self._setup_statusbar()
            self._setup_refresh_timer()

            # Initial data load
            QTimer.singleShot(100, self._load_initial_data)

        def _setup_menu(self) -> None:
            """Set up the menu bar."""
            menubar = self.menuBar()

            # File menu
            file_menu = menubar.addMenu("&File")

            new_scan_action = QAction("&New Scan", self)
            new_scan_action.setShortcut("Ctrl+N")
            new_scan_action.triggered.connect(self._on_new_scan)
            file_menu.addAction(new_scan_action)

            file_menu.addSeparator()

            exit_action = QAction("E&xit", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)

            # Edit menu
            edit_menu = menubar.addMenu("&Edit")

            settings_action = QAction("&Settings", self)
            settings_action.setShortcut("Ctrl+,")
            settings_action.triggered.connect(self._on_settings)
            edit_menu.addAction(settings_action)

            # View menu
            view_menu = menubar.addMenu("&View")

            refresh_action = QAction("&Refresh", self)
            refresh_action.setShortcut("F5")
            refresh_action.triggered.connect(self._on_refresh)
            view_menu.addAction(refresh_action)

            # Help menu
            help_menu = menubar.addMenu("&Help")

            about_action = QAction("&About", self)
            about_action.triggered.connect(self._on_about)
            help_menu.addAction(about_action)

            docs_action = QAction("&Documentation", self)
            docs_action.setShortcut("F1")
            help_menu.addAction(docs_action)

            help_menu.addSeparator()

            update_action = QAction("Check for &Updates", self)
            help_menu.addAction(update_action)

        def _setup_toolbar(self) -> None:
            """Set up the toolbar."""
            toolbar = QToolBar("Main Toolbar")
            toolbar.setMovable(False)
            self.addToolBar(toolbar)

            # New scan button
            new_scan_action = QAction("New Scan", self)
            new_scan_action.triggered.connect(self._on_new_scan)
            toolbar.addAction(new_scan_action)

            # Refresh button
            refresh_action = QAction("Refresh", self)
            refresh_action.triggered.connect(self._on_refresh)
            toolbar.addAction(refresh_action)

        def _setup_ui(self) -> None:
            """Set up the main UI."""
            central_widget = QWidget()
            self.setCentralWidget(central_widget)

            layout = QVBoxLayout(central_widget)

            # Main horizontal split: tabs on left, file detail on right
            main_layout = QHBoxLayout()
            layout.addLayout(main_layout)

            # Tab widget for main screens
            self.tabs = QTabWidget()
            main_layout.addWidget(self.tabs, stretch=3)

            # Create widgets
            self.dashboard_widget = DashboardWidget()
            self.scan_widget = ScanWidget()
            self.results_widget = ResultsWidget()
            self.targets_widget = TargetsWidget()
            self.schedules_widget = SchedulesWidget()
            self.labels_widget = LabelsWidget()
            self.monitoring_widget = MonitoringWidget()
            self.health_widget = HealthWidget()
            self.settings_widget = SettingsWidget(server_url=self.server_url)

            # File detail panel (context card)
            self.file_detail_widget = FileDetailWidget()
            self.file_detail_widget.setMaximumWidth(400)
            self.file_detail_widget.setVisible(False)
            self.file_detail_widget.close_requested.connect(self._hide_file_detail)
            self.file_detail_widget.apply_label_requested.connect(self._on_apply_label)
            main_layout.addWidget(self.file_detail_widget, stretch=1)

            # Add tabs
            self.tabs.addTab(self.dashboard_widget, "Dashboard")
            self.tabs.addTab(self.scan_widget, "Scans")
            self.tabs.addTab(self.results_widget, "Results")
            self.tabs.addTab(self.targets_widget, "Targets")
            self.tabs.addTab(self.schedules_widget, "Schedules")
            self.tabs.addTab(self.labels_widget, "Labels")
            self.tabs.addTab(self.monitoring_widget, "Monitoring")
            self.tabs.addTab(self.health_widget, "Health")
            self.tabs.addTab(self.settings_widget, "Settings")

            # Connect signals
            self.tabs.currentChanged.connect(self._on_tab_changed)
            self.results_widget.result_selected.connect(self._on_result_selected)
            self.targets_widget.scan_requested.connect(self._on_scan_target)
            self.targets_widget.target_changed.connect(self._on_target_changed)
            self.schedules_widget.schedule_changed.connect(self._on_schedule_changed)
            self.labels_widget.label_rule_changed.connect(self._on_label_rule_changed)
            self.monitoring_widget.refresh_requested.connect(self._on_refresh)
            self.health_widget.refresh_requested.connect(self._load_health_status)
            self.settings_widget.settings_changed.connect(self._on_settings_changed)

        def _setup_statusbar(self) -> None:
            """Set up the status bar."""
            statusbar = QStatusBar()
            self.setStatusBar(statusbar)

            # Connection status
            self.connection_label = QLabel(f"Connecting to {self.server_url}...")
            statusbar.addWidget(self.connection_label)

            # Spacer
            statusbar.addWidget(QWidget(), 1)

            # Version
            from openlabels import __version__
            version_label = QLabel(f"v{__version__}")
            statusbar.addPermanentWidget(version_label)

        def _setup_refresh_timer(self) -> None:
            """Set up auto-refresh timer."""
            self._refresh_timer = QTimer(self)
            self._refresh_timer.timeout.connect(self._on_auto_refresh)
            self._refresh_timer.start(30000)  # Refresh every 30 seconds

        def _load_initial_data(self) -> None:
            """Load initial data from the server."""
            self._check_connection()
            self._load_dashboard_stats()
            self._load_dashboard_charts()
            self._load_health_status()
            self._load_targets()
            self._load_schedules()
            self._load_labels()
            self._load_label_rules()

        def _check_connection(self) -> None:
            """Check connection to server."""
            try:
                import httpx
                response = httpx.get(f"{self.server_url}/health", timeout=5.0)
                if response.status_code == 200:
                    self.connection_label.setText(f"Connected to {self.server_url}")
                    self.connection_label.setStyleSheet("color: green;")
                else:
                    self._handle_connection_error("Server returned error")
            except Exception as e:
                self._handle_connection_error(str(e))

        def _handle_connection_error(self, error: str) -> None:
            """Handle connection error."""
            self.connection_label.setText(f"Not connected: {error}")
            self.connection_label.setStyleSheet("color: red;")
            logger.warning(f"Connection error: {error}")

        def _load_dashboard_stats(self) -> None:
            """Load dashboard statistics."""
            try:
                import httpx
                response = httpx.get(
                    f"{self.server_url}/api/dashboard/stats",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    stats = response.json()
                    self.dashboard_widget.update_stats({
                        "total_files": stats.get("total_files_scanned", 0),
                        "high_risk_count": stats.get("critical_files", 0) + stats.get("high_files", 0),
                        "labeled_percentage": (
                            stats.get("labels_applied", 0) / max(1, stats.get("total_files_scanned", 1)) * 100
                        ),
                        "active_scans": stats.get("active_scans", 0),
                        "risk_distribution": {
                            "CRITICAL": stats.get("critical_files", 0),
                            "HIGH": stats.get("high_files", 0),
                            "MEDIUM": 0,
                            "LOW": 0,
                            "MINIMAL": 0,
                        },
                    })
            except Exception as e:
                logger.warning(f"Failed to load dashboard stats: {e}")

        def _load_dashboard_charts(self) -> None:
            """Load dashboard chart data (entity trends + access heatmap)."""
            try:
                import httpx

                # Load entity trends for time series chart
                response = httpx.get(
                    f"{self.server_url}/api/dashboard/entity-trends",
                    params={"days": 14},
                    timeout=10.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    series = data.get("series", {})
                    # Convert to expected format: {name: [(date, count), ...]}
                    chart_data = {}
                    for name, points in series.items():
                        chart_data[name] = [(p[0], p[1]) for p in points]
                    self.dashboard_widget.update_time_series(chart_data)

                # Load access heatmap
                response = httpx.get(
                    f"{self.server_url}/api/dashboard/access-heatmap",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    heatmap = data.get("data", [[0]*24 for _ in range(7)])
                    self.dashboard_widget.update_heat_map(heatmap)

            except Exception as e:
                logger.warning(f"Failed to load dashboard charts: {e}")
                # Fall back to sample data if API fails
                self.dashboard_widget.load_sample_charts()

        def _load_targets(self) -> None:
            """Load scan targets."""
            try:
                import httpx
                response = httpx.get(
                    f"{self.server_url}/api/targets",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    targets = response.json()
                    self.scan_widget.load_targets(targets)
                    self.targets_widget.load_targets(targets)
            except Exception as e:
                logger.warning(f"Failed to load targets: {e}")

        def _on_tab_changed(self, index: int) -> None:
            """Handle tab change."""
            tab_name = self.tabs.tabText(index)
            if tab_name == "Results":
                self._load_results()

        def _load_results(self) -> None:
            """Load scan results."""
            try:
                import httpx
                response = httpx.get(
                    f"{self.server_url}/api/results",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    self.results_widget.load_results(data.get("items", []))
            except Exception as e:
                logger.warning(f"Failed to load results: {e}")

        def _on_new_scan(self) -> None:
            """Handle new scan action."""
            self.tabs.setCurrentIndex(1)  # Switch to Scans tab

        def _on_settings(self) -> None:
            """Handle settings action."""
            self.tabs.setCurrentIndex(8)  # Switch to Settings tab

        def _on_settings_changed(self, settings: dict) -> None:
            """Handle settings changed."""
            logger.info(f"Settings changed: {settings}")
            # Apply relevant settings
            if "refresh_interval" in settings:
                interval = settings["refresh_interval"] * 1000  # Convert to ms
                self._refresh_timer.setInterval(interval)
            self.statusBar().showMessage("Settings saved", 3000)

        def _on_refresh(self) -> None:
            """Handle manual refresh."""
            self._load_initial_data()
            self.statusBar().showMessage("Refreshed", 2000)

        def _on_auto_refresh(self) -> None:
            """Handle auto refresh."""
            if self.tabs.currentIndex() == 0:  # Dashboard
                self._load_dashboard_stats()

        def _on_about(self) -> None:
            """Show about dialog."""
            from openlabels import __version__
            QMessageBox.about(
                self,
                "About OpenLabels",
                f"<h3>OpenLabels v{__version__}</h3>"
                "<p>Open Source Data Classification & Auto-Labeling Platform</p>"
                "<p>Copyright (c) 2024-2026 Chillbot.io</p>"
                "<p><a href='https://github.com/chillbot-io/openlabels'>GitHub</a></p>"
            )

        def _on_result_selected(self, result: dict) -> None:
            """Handle result selection - show file detail panel."""
            self.file_detail_widget.show_result(result)
            self.file_detail_widget.setVisible(True)

        def _hide_file_detail(self) -> None:
            """Hide the file detail panel."""
            self.file_detail_widget.setVisible(False)
            self.file_detail_widget.clear()

        def _on_apply_label(self, result_id: str, label_id: str) -> None:
            """Apply a label to a scan result."""
            try:
                import httpx
                response = httpx.post(
                    f"{self.server_url}/api/labels/apply",
                    json={"result_id": result_id, "label_id": label_id},
                    timeout=10.0,
                )
                if response.status_code == 202:
                    self.statusBar().showMessage("Label application queued", 3000)
                    self._load_results()
                else:
                    self.statusBar().showMessage(f"Failed to apply label: {response.text}", 5000)
            except Exception as e:
                logger.error(f"Failed to apply label: {e}")
                self.statusBar().showMessage(f"Error: {e}", 5000)

        def _on_scan_target(self, target_id: str) -> None:
            """Start a scan on a target."""
            try:
                import httpx
                response = httpx.post(
                    f"{self.server_url}/api/scans",
                    json={"target_id": target_id},
                    timeout=10.0,
                )
                if response.status_code in (200, 201):
                    self.statusBar().showMessage("Scan started", 3000)
                    self.tabs.setCurrentIndex(1)  # Switch to Scans tab
                else:
                    self.statusBar().showMessage(f"Failed to start scan: {response.text}", 5000)
            except Exception as e:
                logger.error(f"Failed to start scan: {e}")
                self.statusBar().showMessage(f"Error: {e}", 5000)

        def _on_target_changed(self) -> None:
            """Handle target created/updated/deleted."""
            self._load_targets()
            self.statusBar().showMessage("Targets updated", 2000)

        def _on_schedule_changed(self) -> None:
            """Handle schedule created/updated/deleted."""
            self._load_schedules()
            self.statusBar().showMessage("Schedules updated", 2000)

        def _on_label_rule_changed(self) -> None:
            """Handle label rule created/updated/deleted."""
            self._load_label_rules()
            self.statusBar().showMessage("Label rules updated", 2000)

        def _load_schedules(self) -> None:
            """Load scan schedules."""
            try:
                import httpx
                response = httpx.get(
                    f"{self.server_url}/api/schedules",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    schedules = response.json()
                    self.schedules_widget.load_schedules(schedules)
            except Exception as e:
                logger.warning(f"Failed to load schedules: {e}")

        def _load_label_rules(self) -> None:
            """Load label rules."""
            try:
                import httpx
                response = httpx.get(
                    f"{self.server_url}/api/labels/rules",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    rules = response.json()
                    self.labels_widget.load_rules(rules)
            except Exception as e:
                logger.warning(f"Failed to load label rules: {e}")

        def _load_labels(self) -> None:
            """Load sensitivity labels from server."""
            try:
                import httpx
                response = httpx.get(
                    f"{self.server_url}/api/labels",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    labels = response.json()
                    self.labels_widget.load_labels(labels)
                    self.file_detail_widget.set_available_labels(labels)
            except Exception as e:
                logger.warning(f"Failed to load labels: {e}")

        def _load_health_status(self) -> None:
            """Load system health status from server."""
            try:
                import httpx
                response = httpx.get(
                    f"{self.server_url}/api/health/status",
                    timeout=5.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    self.health_widget.update_status(data)
            except Exception as e:
                # Show connection error in health widget
                self.health_widget.update_status({
                    "api": "error", "api_text": "Not connected",
                    "db": "unknown", "db_text": "",
                    "queue": "unknown", "queue_text": "",
                    "ml": "unknown", "ml_text": "",
                    "mip": "unknown", "mip_text": "",
                    "ocr": "unknown", "ocr_text": "",
                })
                self.health_widget.add_error("Connection", str(e))

        def closeEvent(self, event) -> None:
            """Handle window close."""
            self._refresh_timer.stop()
            if self._api_worker:
                self._api_worker.quit()
                self._api_worker.wait()
            event.accept()

else:
    # Fallback when PySide6 is not available
    class MainWindow:
        def __init__(self, *args, **kwargs):
            raise ImportError("PySide6 is required for the GUI")

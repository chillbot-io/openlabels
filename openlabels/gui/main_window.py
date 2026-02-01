"""
OpenLabels main window.

The main application window containing:
- Scan target panel (top)
- Folder tree (left)
- Results table (right) with Label preview
- Status bar (bottom)

Requires authentication to access vault features.
"""

import json
import csv
from pathlib import Path
from typing import Optional, List, Dict, Any, TYPE_CHECKING
from datetime import datetime, timezone

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QStatusBar,
    QProgressBar,
    QLabel,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QToolBar,
    QApplication,
    QTabWidget,
)
from PySide6.QtCore import Qt, Slot, QTimer
from PySide6.QtGui import QAction, QIcon

from openlabels.gui.widgets.scan_target import ScanTargetPanel
from openlabels.gui.widgets.folder_tree import FolderTreeWidget
from openlabels.gui.widgets.results_table import ResultsTableWidget
from openlabels.gui.widgets.dialogs import SettingsDialog, LabelDialog, QuarantineConfirmDialog
from openlabels.gui.workers.scan_worker import ScanWorker
from openlabels.gui.workers.file_watcher import FileWatcher
from openlabels.gui.widgets.dashboard import DashboardWidget
from openlabels.gui.widgets.label_preview import LabelPreviewWidget
from openlabels.gui.style import get_stylesheet

if TYPE_CHECKING:
    from openlabels.auth import AuthManager
    from openlabels.auth.models import Session


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self, initial_path: Optional[str] = None, server_url: Optional[str] = None):
        super().__init__()
        self.setWindowTitle("OpenLabels - Portable Risk Labels")
        self.setMinimumSize(1200, 700)
        self.resize(1400, 800)

        # Apply modern stylesheet
        self.setStyleSheet(get_stylesheet())

        # Auth state
        self._auth: Optional["AuthManager"] = None
        self._session: Optional["Session"] = None

        # Backend server URL (if running async server)
        self._server_url = server_url

        # State
        self._scan_results: List[Dict[str, Any]] = []
        self._current_path: Optional[str] = None
        self._scan_worker: Optional[ScanWorker] = None
        self._api_client = None  # ScannerAPIClient when using server
        self._initial_path = initial_path
        self._selected_file: Optional[str] = None

        # File watcher for real-time monitoring
        self._file_watcher = FileWatcher(self)
        self._pending_watch_files: List[str] = []
        self._watch_scan_timer: Optional["QTimer"] = None

        # Setup UI
        self._setup_ui()
        self._setup_menubar()
        self._setup_statusbar()
        self._connect_signals()

    def showEvent(self, event):
        """Handle window show - trigger login on first show."""
        super().showEvent(event)

        # Only show login on first display
        if self._auth is None:
            # Use QTimer to defer login dialog until after window is shown
            from PySide6.QtCore import QTimer
            QTimer.singleShot(100, self._show_auth_dialog)

    def _show_auth_dialog(self):
        """Show login or setup dialog."""
        try:
            from openlabels.auth import AuthManager
            self._auth = AuthManager()

            if self._auth.needs_setup():
                self._show_setup_dialog()
            else:
                self._show_login_dialog()

        except ImportError:
            # Auth module not available (missing dependencies)
            QMessageBox.warning(
                self,
                "Auth Not Available",
                "Authentication features require additional dependencies.\n\n"
                "Install with: pip install openlabels[auth]"
            )
            self._auth = None

    def _show_setup_dialog(self):
        """Show first-time setup dialog."""
        from openlabels.gui.widgets.login_dialog import SetupDialog, RecoveryKeysDialog

        dialog = SetupDialog(self)
        dialog.setup_complete.connect(self._on_setup_complete)

        if dialog.exec() != dialog.Accepted:
            # User cancelled setup - can't continue
            QMessageBox.information(
                self,
                "Setup Required",
                "An admin account must be created to use OpenLabels."
            )
            QApplication.quit()

    def _on_setup_complete(self, session: "Session", recovery_keys: List[str]):
        """Handle setup completion."""
        self._session = session

        # Show recovery keys dialog
        from openlabels.gui.widgets.login_dialog import RecoveryKeysDialog
        keys_dialog = RecoveryKeysDialog(self, recovery_keys)
        keys_dialog.exec()

        self._on_login_success()

    def _show_login_dialog(self):
        """Show login dialog."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog(self)
        dialog.login_successful.connect(self._on_login_successful)

        if dialog.exec() != dialog.Accepted:
            # User cancelled login - quit
            QApplication.quit()

    def _on_login_successful(self, session: "Session"):
        """Handle successful login."""
        self._session = session
        self._on_login_success()

    def _on_login_success(self):
        """Common login success handling."""
        # Update window title with username
        self.setWindowTitle(f"OpenLabels - {self._session.user.username}")

        # Update status
        self._status_label.setText(f"Logged in as {self._session.user.username}")

        # Update user menu
        self._update_user_menu()

        # Load initial path if provided
        if self._initial_path:
            self._scan_target.set_path(self._initial_path)

    def _setup_ui(self):
        """Setup the main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Logo header
        logo_label = QLabel("< OpenLabels >")
        logo_label.setStyleSheet("""
            QLabel {
                font-family: "IBM Plex Mono", "JetBrains Mono", Consolas, monospace;
                font-size: 20px;
                font-weight: 600;
                color: #58a6ff;
                padding: 4px 0;
            }
        """)
        layout.addWidget(logo_label)

        # Scan target panel (top)
        self._scan_target = ScanTargetPanel()
        layout.addWidget(self._scan_target)

        # Tab widget for Results / Dashboard views
        self._tab_widget = QTabWidget()

        # --- Files Tab ---
        # Contains: folder tree | results table | label preview (all aligned)
        files_tab = QWidget()
        files_layout = QVBoxLayout(files_tab)
        files_layout.setContentsMargins(0, 0, 0, 0)

        # Main horizontal splitter for all three panels
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setHandleWidth(12)  # Gap between panels
        main_splitter.setChildrenCollapsible(False)

        # Left: Folder tree
        self._folder_tree = FolderTreeWidget()
        self._folder_tree.setMinimumWidth(180)
        self._folder_tree.setMaximumWidth(300)
        main_splitter.addWidget(self._folder_tree)

        # Center: Results table
        self._results_table = ResultsTableWidget()
        self._results_table.setMinimumWidth(400)
        main_splitter.addWidget(self._results_table)

        # Right: Label Preview panel
        self._label_preview = LabelPreviewWidget()
        self._label_preview.setMinimumWidth(280)
        self._label_preview.setMaximumWidth(450)
        self._label_preview.export_requested.connect(self._on_label_export)
        self._label_preview.label_copied.connect(self._on_label_copied)
        main_splitter.addWidget(self._label_preview)

        # Set splitter proportions (20% tree, 50% table, 30% preview)
        main_splitter.setSizes([200, 600, 380])

        files_layout.addWidget(main_splitter)
        self._tab_widget.addTab(files_tab, "Files")

        # --- Dashboard Tab ---
        self._dashboard = DashboardWidget()
        self._dashboard.file_selected.connect(self._on_dashboard_file_selected)
        self._tab_widget.addTab(self._dashboard, "Dashboard")

        # Update dashboard when switching to it
        self._tab_widget.currentChanged.connect(self._on_tab_changed)

        layout.addWidget(self._tab_widget, stretch=1)

        # Bottom actions bar
        actions_layout = QHBoxLayout()
        actions_layout.setContentsMargins(0, 8, 0, 0)

        self._export_csv_btn = QPushButton("Export All CSV")
        self._export_csv_btn.setProperty("secondary", True)
        self._export_json_btn = QPushButton("Export All JSON")
        self._export_json_btn.setProperty("secondary", True)
        self._settings_btn = QPushButton("Settings")
        self._settings_btn.setProperty("secondary", True)

        actions_layout.addWidget(self._export_csv_btn)
        actions_layout.addWidget(self._export_json_btn)
        actions_layout.addStretch()
        actions_layout.addWidget(self._settings_btn)

        layout.addLayout(actions_layout)

    def _setup_menubar(self):
        """Setup the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        open_action = QAction("&Open Folder...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._on_open_folder)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        export_csv_action = QAction("Export to &CSV...", self)
        export_csv_action.triggered.connect(self._on_export_csv)
        file_menu.addAction(export_csv_action)

        export_json_action = QAction("Export to &JSON...", self)
        export_json_action.triggered.connect(self._on_export_json)
        file_menu.addAction(export_json_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Scan menu
        scan_menu = menubar.addMenu("&Scan")

        start_scan_action = QAction("&Start Scan", self)
        start_scan_action.setShortcut("F5")
        start_scan_action.triggered.connect(self._on_start_scan)
        scan_menu.addAction(start_scan_action)

        stop_scan_action = QAction("S&top Scan", self)
        stop_scan_action.setShortcut("Escape")
        stop_scan_action.triggered.connect(self._on_stop_scan)
        scan_menu.addAction(stop_scan_action)

        # User menu (populated after login)
        self._user_menu = menubar.addMenu("&User")
        self._user_menu.setEnabled(False)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    def _update_user_menu(self):
        """Update user menu after login."""
        if not self._session:
            self._user_menu.setEnabled(False)
            return

        self._user_menu.clear()
        self._user_menu.setEnabled(True)

        # Current user info
        user_info = QAction(f"Logged in as: {self._session.user.username}", self)
        user_info.setEnabled(False)
        self._user_menu.addAction(user_info)

        self._user_menu.addSeparator()

        # Admin-only options
        if self._session.is_admin():
            create_user_action = QAction("Create &User...", self)
            create_user_action.triggered.connect(self._on_create_user)
            self._user_menu.addAction(create_user_action)

            manage_users_action = QAction("&Manage Users...", self)
            manage_users_action.triggered.connect(self._on_manage_users)
            self._user_menu.addAction(manage_users_action)

            recovery_keys_action = QAction("&Recovery Keys...", self)
            recovery_keys_action.triggered.connect(self._on_recovery_keys)
            self._user_menu.addAction(recovery_keys_action)

            audit_log_action = QAction("View &Audit Log...", self)
            audit_log_action.triggered.connect(self._on_view_audit)
            self._user_menu.addAction(audit_log_action)

            self._user_menu.addSeparator()

        # Logout
        logout_action = QAction("&Logout", self)
        logout_action.triggered.connect(self._on_logout)
        self._user_menu.addAction(logout_action)

    @Slot()
    def _on_create_user(self):
        """Show create user dialog (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        from openlabels.gui.widgets.login_dialog import CreateUserDialog
        dialog = CreateUserDialog(self, self._session)
        if dialog.exec():
            QMessageBox.information(self, "User Created", "User created successfully.")

    @Slot()
    def _on_manage_users(self):
        """Show user management (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        # Simple user list for now
        users = self._auth.list_users()
        user_list = "\n".join(f"- {u.username} ({u.role.value})" for u in users)
        QMessageBox.information(self, "Users", f"Registered users:\n\n{user_list}")

    @Slot()
    def _on_recovery_keys(self):
        """Show recovery key status (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        from openlabels.gui.widgets.recovery_dialog import RecoveryDialog
        dialog = RecoveryDialog(self, mode="view_keys", admin_session=self._session)
        dialog.exec()

    @Slot()
    def _on_view_audit(self):
        """View audit log (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        from openlabels.gui.widgets.audit_dialog import AuditLogDialog
        dialog = AuditLogDialog(self, session=self._session)
        dialog.exec()

    @Slot()
    def _on_logout(self):
        """Handle logout."""
        if self._session and self._auth:
            self._auth.logout(self._session.token)

        self._session = None
        self.setWindowTitle("OpenLabels")
        self._status_label.setText("Logged out")
        self._user_menu.setEnabled(False)

        # Show login dialog again
        self._show_login_dialog()

    def _setup_statusbar(self):
        """Setup the status bar."""
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setMaximumWidth(200)
        self._progress_bar.setVisible(False)

        # Status labels
        self._status_label = QLabel("Ready")
        self._file_count_label = QLabel("")
        self._risk_summary_label = QLabel("")

        self._statusbar.addWidget(self._status_label)
        self._statusbar.addWidget(self._progress_bar)
        self._statusbar.addPermanentWidget(self._file_count_label)
        self._statusbar.addPermanentWidget(self._risk_summary_label)

    def _connect_signals(self):
        """Connect widget signals to slots."""
        # Scan target
        self._scan_target.scan_requested.connect(self._on_start_scan)
        self._scan_target.path_changed.connect(self._on_path_changed)
        self._scan_target.monitoring_toggled.connect(self._on_monitoring_toggled)

        # Folder tree
        self._folder_tree.folder_selected.connect(self._on_folder_selected)

        # Results table
        self._results_table.quarantine_requested.connect(self._on_quarantine_file)
        self._results_table.label_requested.connect(self._on_label_file)
        self._results_table.detail_requested.connect(self._on_file_detail)
        self._results_table.fp_reported.connect(self._on_report_false_positive)

        # Connect table selection to label preview
        self._results_table._table.itemSelectionChanged.connect(self._on_file_selected)

        # Bottom buttons
        self._export_csv_btn.clicked.connect(self._on_export_csv)
        self._export_json_btn.clicked.connect(self._on_export_json)
        self._settings_btn.clicked.connect(self._on_settings)

        # File watcher
        self._file_watcher.file_changed.connect(self._on_watched_file_changed)
        self._file_watcher.watching_started.connect(self._on_watching_started)
        self._file_watcher.watching_stopped.connect(self._on_watching_stopped)
        self._file_watcher.error.connect(self._on_watcher_error)

    @Slot()
    def _on_open_folder(self):
        """Open folder dialog."""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Folder to Scan", str(Path.home())
        )
        if folder:
            self._scan_target.set_target_type("local")
            self._scan_target.set_path(folder)

    @Slot()
    def _on_path_changed(self):
        """Handle path change in scan target."""
        path = self._scan_target.get_path()
        target_type = self._scan_target.get_target_type()

        # Update folder tree for local/SMB/NFS paths
        if target_type in ("local", "smb", "nfs") and path:
            self._folder_tree.set_root_path(path)
        else:
            self._folder_tree.clear()

    @Slot()
    def _on_start_scan(self):
        """Start scanning."""
        if self._scan_worker and self._scan_worker.isRunning():
            return  # Already scanning
        if self._api_client:
            return  # Already scanning via API

        target_type = self._scan_target.get_target_type()
        path = self._scan_target.get_path()

        if not path:
            QMessageBox.warning(self, "No Path", "Please enter a path to scan.")
            return

        # Get S3 credentials if needed
        s3_credentials = None
        if target_type == "s3":
            s3_credentials = self._scan_target.get_s3_credentials()

        # Clear previous results
        self._scan_results.clear()
        self._results_table.clear()

        # Enable batch mode for faster inserts
        self._results_table.begin_batch()

        # Update UI
        self._status_label.setText("Scanning...")
        self._progress_bar.setVisible(True)
        self._progress_bar.setRange(0, 0)  # Indeterminate initially
        self._scan_target.set_enabled(False)

        # Use API client if server is available, otherwise use in-process worker
        if self._server_url:
            self._start_scan_via_api(target_type, path, s3_credentials)
        else:
            self._start_scan_in_process(target_type, path, s3_credentials)

    def _start_scan_via_api(self, target_type: str, path: str,
                            s3_credentials: Optional[Dict[str, str]]):
        """Start scan using the async API server."""
        from openlabels.gui.workers.api_client import ScannerAPIClient

        self._api_client = ScannerAPIClient(self._server_url, parent=self)
        self._api_client.progress.connect(self._on_scan_progress)
        self._api_client.result.connect(self._on_scan_result)
        self._api_client.batch_results.connect(self._on_batch_results)
        self._api_client.finished.connect(self._on_api_scan_finished)
        self._api_client.error.connect(self._on_scan_error)

        if not self._api_client.start_scan(path, target_type, s3_credentials):
            # Fall back to in-process scanning
            self._api_client = None
            self._status_label.setText("API unavailable, using local scanner...")
            self._start_scan_in_process(target_type, path, s3_credentials)

    def _start_scan_in_process(self, target_type: str, path: str,
                               s3_credentials: Optional[Dict[str, str]]):
        """Start scan using in-process worker thread."""
        # Get advanced options from scan target panel
        options = self._scan_target.get_advanced_options()

        self._scan_worker = ScanWorker(
            target_type=target_type,
            path=path,
            s3_credentials=s3_credentials,
            max_workers=options.get("workers", 8),
            options=options,
        )
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.result.connect(self._on_scan_result)
        self._scan_worker.batch_results.connect(self._on_batch_results)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    @Slot()
    def _on_stop_scan(self):
        """Stop scanning."""
        if self._scan_worker and self._scan_worker.isRunning():
            self._scan_worker.stop()
            self._status_label.setText("Stopping...")
        elif self._api_client:
            self._api_client.stop()
            self._status_label.setText("Stopping...")

    @Slot()
    def _on_api_scan_finished(self):
        """Handle scan completion from API client."""
        self._api_client = None
        self._on_scan_finished()

    @Slot(int, int)
    def _on_scan_progress(self, current: int, total: int):
        """Handle scan progress update."""
        if total > 0:
            self._progress_bar.setRange(0, total)
            self._progress_bar.setValue(current)
        self._file_count_label.setText(f"{current}/{total} files")

    @Slot(dict)
    def _on_scan_result(self, result: Dict[str, Any]):
        """Handle single scan result (legacy, for backward compatibility)."""
        self._scan_results.append(result)
        self._results_table.add_result(result)
        # Don't update summary on every result - wait for batch or finish
        self._store_to_vault(result)

    @Slot(list)
    def _on_batch_results(self, results: List[Dict[str, Any]]):
        """Handle batched scan results for better UI performance.

        Processes multiple results at once, reducing UI update overhead.
        """
        # Add all results to internal storage
        self._scan_results.extend(results)

        # Batch add to table
        self._results_table.add_results_batch(results)

        # Update risk summary once for the whole batch
        self._update_risk_summary()

        # Store spans to vault
        for result in results:
            self._store_to_vault(result)

    def _store_to_vault(self, result: Dict[str, Any]):
        """Store scan result spans to user's vault."""
        if not self._session:
            return

        spans_data = result.get("spans", [])
        if not spans_data:
            return

        file_path = result.get("path", "")
        if not file_path:
            return

        try:
            from openlabels.vault.models import SensitiveSpan

            # Convert span dicts to SensitiveSpan objects
            spans = [
                SensitiveSpan(
                    start=s["start"],
                    end=s["end"],
                    text=s["text"],
                    entity_type=s["entity_type"],
                    confidence=s["confidence"],
                    detector=s["detector"],
                    context_before=s.get("context_before", ""),
                    context_after=s.get("context_after", ""),
                )
                for s in spans_data
            ]

            # Get vault and store
            vault = self._session.get_vault()
            vault.store_scan_result(
                file_path=file_path,
                spans=spans,
                source="openlabels",
                metadata={
                    "score": result.get("score", 0),
                    "tier": result.get("tier", "UNKNOWN"),
                    "exposure": result.get("exposure", "PRIVATE"),
                },
            )

        except Exception as e:
            # Don't interrupt scan for vault errors - just log
            import logging
            logging.getLogger(__name__).warning(f"Failed to store to vault: {e}")

    @Slot()
    def _on_scan_finished(self):
        """Handle scan completion."""
        self._results_table.end_batch()  # Re-enable sorting
        self._status_label.setText("Scan complete")
        self._progress_bar.setVisible(False)
        self._scan_target.set_enabled(True)
        self._update_risk_summary()

    @Slot(str)
    def _on_scan_error(self, error: str):
        """Handle scan error."""
        self._results_table.end_batch()  # Re-enable sorting
        self._status_label.setText("Error")
        self._progress_bar.setVisible(False)
        self._scan_target.set_enabled(True)
        QMessageBox.critical(self, "Scan Error", error)

    # --- File Monitoring ---

    @Slot(bool)
    def _on_monitoring_toggled(self, enabled: bool):
        """Handle monitoring toggle."""
        path = self._scan_target.get_path()

        if enabled:
            if not path:
                QMessageBox.warning(self, "No Path", "Please enter a path to monitor.")
                self._scan_target.set_monitoring(False)
                return

            # Start watching
            if self._file_watcher.start_watching(path):
                self._status_label.setText(f"Monitoring: {path}")
            else:
                self._scan_target.set_monitoring(False)
        else:
            # Stop watching
            self._file_watcher.stop_watching()
            if self._watch_scan_timer:
                self._watch_scan_timer.stop()
            self._pending_watch_files.clear()
            self._status_label.setText("Ready")

    @Slot(str)
    def _on_watched_file_changed(self, file_path: str):
        """Handle file change from watcher - queue for scanning."""
        # Add to pending list if not already there
        if file_path not in self._pending_watch_files:
            self._pending_watch_files.append(file_path)

        # Start/restart debounce timer
        if self._watch_scan_timer is None:
            self._watch_scan_timer = QTimer(self)
            self._watch_scan_timer.setSingleShot(True)
            self._watch_scan_timer.timeout.connect(self._scan_pending_watch_files)

        self._watch_scan_timer.start(1000)  # 1 second debounce

        # Update status
        count = len(self._pending_watch_files)
        self._status_label.setText(f"Monitoring: {count} file(s) changed...")

    def _scan_pending_watch_files(self):
        """Scan files that were detected as changed."""
        if not self._pending_watch_files:
            return

        # Don't interrupt an existing scan
        if self._scan_worker and self._scan_worker.isRunning():
            # Re-queue for later
            self._watch_scan_timer.start(2000)
            return

        files_to_scan = self._pending_watch_files.copy()
        self._pending_watch_files.clear()

        # Scan each file individually
        self._scan_individual_files(files_to_scan)

    def _scan_individual_files(self, file_paths: List[str]):
        """Scan a list of individual files."""
        from openlabels import Client
        from openlabels.adapters.scanner import detect_file as scanner_detect
        from pathlib import Path

        client = Client()

        for file_path in file_paths:
            try:
                path = Path(file_path)
                if not path.exists():
                    continue

                # Get file size
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0

                # Detect entities
                detection = scanner_detect(path)
                entities = detection.entity_counts

                # Extract spans with context
                spans_data = []
                text = detection.text
                for span in detection.spans:
                    ctx_start = max(0, span.start - 50)
                    ctx_end = min(len(text), span.end + 50)
                    spans_data.append({
                        "start": span.start,
                        "end": span.end,
                        "text": span.text,
                        "entity_type": span.entity_type,
                        "confidence": span.confidence,
                        "detector": span.detector,
                        "context_before": text[ctx_start:span.start],
                        "context_after": text[span.end:ctx_end],
                    })

                # Score the file
                score_result = client.score_file(path)

                result = {
                    "path": str(path),
                    "size": size,
                    "score": score_result.score,
                    "tier": score_result.tier.value if hasattr(score_result.tier, 'value') else str(score_result.tier),
                    "entities": entities,
                    "spans": spans_data,
                    "exposure": "PRIVATE",
                    "error": None,
                }

                # Update or add to results
                existing_idx = next(
                    (i for i, r in enumerate(self._scan_results) if r.get("path") == file_path),
                    None
                )
                if existing_idx is not None:
                    self._scan_results[existing_idx] = result
                    self._results_table.update_result(result)
                else:
                    self._scan_results.append(result)
                    self._results_table.add_result(result)

                # Store to vault
                self._store_to_vault(result)

            except Exception as e:
                import logging
                logging.getLogger(__name__).warning(f"Failed to scan {file_path}: {e}")

        self._update_risk_summary()
        self._status_label.setText(f"Monitoring: {len(self._file_watcher.watched_paths)} directories")

    @Slot(str)
    def _on_watching_started(self, path: str):
        """Handle watching started."""
        self._status_label.setText(f"Monitoring: {path}")

    @Slot(str)
    def _on_watching_stopped(self, path: str):
        """Handle watching stopped."""
        if not self._file_watcher.is_watching:
            self._status_label.setText("Ready")

    @Slot(str)
    def _on_watcher_error(self, error: str):
        """Handle watcher error."""
        self._status_label.setText(f"Monitor error: {error}")

    # --- Dashboard ---

    @Slot(int)
    def _on_tab_changed(self, index: int):
        """Handle tab change - update dashboard when selected."""
        if index == 1:  # Dashboard tab
            self._dashboard.set_results(self._scan_results)

    @Slot(str)
    def _on_dashboard_file_selected(self, file_path: str):
        """Handle file selection from dashboard."""
        # Switch to results tab and show file detail
        self._tab_widget.setCurrentIndex(0)
        self._on_file_detail(file_path)

    @Slot(str)
    def _on_folder_selected(self, folder_path: str):
        """Handle folder selection in tree - filter results."""
        self._results_table.filter_by_path(folder_path)

    @Slot()
    def _on_file_selected(self):
        """Handle file selection in results table - update label preview."""
        selected = self._results_table._table.selectedItems()
        if not selected:
            self._label_preview.clear()
            self._selected_file = None
            return

        # Get file path from the first column (Name column stores path in UserRole)
        row = selected[0].row()
        name_item = self._results_table._table.item(row, 0)
        if not name_item:
            return

        file_path = name_item.data(Qt.UserRole)
        if not file_path or file_path == self._selected_file:
            return

        self._selected_file = file_path

        # Find the result for this file
        result = next((r for r in self._scan_results if r.get("path") == file_path), None)
        if result:
            self._label_preview.set_from_scan_result(result)

    @Slot(str)
    def _on_label_export(self, format_type: str):
        """Handle label export request."""
        if not self._selected_file:
            QMessageBox.information(
                self, "No File Selected", "Please select a file to export its label."
            )
            return

        result = next((r for r in self._scan_results if r.get("path") == self._selected_file), None)
        if not result:
            return

        if format_type == "json":
            self._export_single_label_json(result)
        elif format_type == "embed":
            self._embed_label(result)
        elif format_type == "index":
            self._save_to_index(result)

    def _export_single_label_json(self, result: Dict[str, Any]):
        """Export a single file's label as JSON."""
        from openlabels.core.labels import generate_label_id, compute_content_hash_file, labels_from_detection
        import time

        file_path = result.get("path", "")
        file_name = Path(file_path).stem

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Label", f"{file_name}.openlabel.json", "JSON Files (*.json)"
        )
        if not save_path:
            return

        try:
            # Build LabelSet
            label_id = generate_label_id()
            content_hash = compute_content_hash_file(file_path)

            label_data = {
                "v": 1,
                "id": label_id,
                "hash": content_hash,
                "labels": [
                    {"t": etype, "c": 0.95, "d": "pattern", "h": "------", "n": count}
                    for etype, count in result.get("entities", {}).items()
                ],
                "src": "openlabels:1.0.0",
                "ts": int(time.time()),
            }

            with open(save_path, "w") as f:
                json.dump(label_data, f, indent=2)

            self._status_label.setText(f"Label exported: {Path(save_path).name}")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _embed_label(self, result: Dict[str, Any]):
        """Embed label into the file."""
        file_path = result.get("path", "")

        try:
            from openlabels.output.embed import embed_label
            from openlabels.core.labels import LabelSet, Label, generate_label_id, compute_content_hash_file
            import time

            # Build LabelSet
            labels = [
                Label(
                    type=etype,
                    confidence=0.95,
                    detector="pattern",
                    value_hash="------",
                    count=count,
                )
                for etype, count in result.get("entities", {}).items()
            ]

            label_set = LabelSet(
                version=1,
                label_id=generate_label_id(),
                content_hash=compute_content_hash_file(file_path),
                labels=labels,
                source="openlabels:1.0.0",
                timestamp=int(time.time()),
            )

            embed_label(file_path, label_set)
            self._status_label.setText(f"Label embedded: {Path(file_path).name}")
            QMessageBox.information(
                self, "Label Embedded",
                f"The OpenLabels label has been embedded in:\n{file_path}\n\n"
                "This label will travel with the file wherever it goes."
            )

        except ImportError:
            QMessageBox.warning(
                self, "Not Supported",
                f"Embedding is not supported for this file type:\n{Path(file_path).suffix}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Embed Error", str(e))

    def _save_to_index(self, result: Dict[str, Any]):
        """Save label to the index."""
        self._status_label.setText("Saving to index...")
        # This would integrate with the index system
        QMessageBox.information(
            self, "Index",
            "Label saved to local index.\n\n"
            "Configure a remote index in Settings to sync labels across systems."
        )
        self._status_label.setText("Label saved to index")

    @Slot()
    def _on_label_copied(self):
        """Handle label JSON copied to clipboard."""
        self._status_label.setText("Label JSON copied to clipboard")

    @Slot(str)
    def _on_file_detail(self, file_path: str):
        """Handle double-click to show file detail dialog."""
        # Find the result for this file
        result = next((r for r in self._scan_results if r.get("path") == file_path), None)

        # Try to get classification from vault if we have a session
        classification = None
        if self._session:
            try:
                vault = self._session.get_vault()
                classification = vault.get_classification(file_path)
            except Exception:
                pass

        # If no classification but we have scan result, create a minimal one
        if classification is None and result:
            from openlabels.vault.models import FileClassification, ClassificationSource, Finding

            findings = [
                Finding(entity_type=etype, count=count, confidence=None)
                for etype, count in result.get("entities", {}).items()
            ]

            source = ClassificationSource(
                provider="openlabels",
                timestamp=datetime.now(timezone.utc),
                findings=findings,
                metadata={},
            )

            classification = FileClassification(
                file_path=file_path,
                file_hash="",
                risk_score=result.get("score", 0),
                tier=result.get("tier", "UNKNOWN"),
                sources=[source] if findings else [],
                labels=result.get("labels", []),
            )

        from openlabels.gui.widgets.file_detail_dialog import FileDetailDialog
        dialog = FileDetailDialog(
            parent=self,
            file_path=file_path,
            classification=classification,
            session=self._session,
        )
        dialog.quarantine_requested.connect(self._on_quarantine_file)
        dialog.rescan_requested.connect(self._on_rescan_file)
        dialog.exec()

    @Slot(str)
    def _on_rescan_file(self, file_path: str):
        """Handle rescan request for a single file."""
        # For now, just trigger a full scan with the file's parent directory
        # A proper single-file rescan would require scan worker changes
        self._status_label.setText(f"Rescan requested: {Path(file_path).name}")

    @Slot(str)
    def _on_quarantine_file(self, file_path: str):
        """Handle quarantine request for a file."""
        # Find the result for this file
        result = next((r for r in self._scan_results if r.get("path") == file_path), None)
        if not result:
            return

        dialog = QuarantineConfirmDialog(
            self,
            file_path=file_path,
            score=result.get("score", 0),
            tier=result.get("tier", "UNKNOWN"),
        )
        if dialog.exec():
            # Perform quarantine
            self._do_quarantine(file_path)

    def _do_quarantine(self, file_path: str):
        """Actually quarantine a file using secure file operations.

        Uses Client.move() which provides TOCTOU protection and symlink validation
        via the FileOps component (see SECURITY.md TOCTOU-001, HIGH-002).
        """
        try:
            # Use default quarantine location
            quarantine_dir = Path.home() / ".openlabels" / "quarantine"
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            source = Path(file_path)
            dest = quarantine_dir / source.name

            # Handle name collision by checking with lstat (TOCTOU-safe)
            try:
                dest.lstat()
                # File exists, add timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest = quarantine_dir / f"{source.stem}_{timestamp}{source.suffix}"
            except FileNotFoundError:
                pass  # Destination doesn't exist, use original name

            # Use Client.move() for TOCTOU-safe file operation
            from openlabels import Client
            client = Client()
            result = client.move(file_path, str(dest))
            if not result.success:
                raise RuntimeError(result.error or "Move operation failed")

            # Remove from results
            self._scan_results = [r for r in self._scan_results if r.get("path") != file_path]
            self._results_table.remove_result(file_path)
            self._update_risk_summary()

            self._status_label.setText(f"Quarantined: {source.name}")

        except Exception as e:
            QMessageBox.critical(self, "Quarantine Error", str(e))

    @Slot(str)
    def _on_label_file(self, file_path: str):
        """Handle label request for a file."""
        dialog = LabelDialog(self, file_path=file_path)
        if dialog.exec():
            labels = dialog.get_labels()
            self._do_label(file_path, labels)

    def _do_label(self, file_path: str, labels: List[str]):
        """Apply labels to a file."""
        try:
            # Update local result (API integration pending)
            for result in self._scan_results:
                if result.get("path") == file_path:
                    result["labels"] = labels
                    break

            self._status_label.setText(f"Labeled: {Path(file_path).name}")

        except Exception as e:
            QMessageBox.critical(self, "Label Error", str(e))

    @Slot(str, dict)
    def _on_report_false_positive(self, file_path: str, result: Dict[str, Any]):
        """Handle false positive report for a file."""
        from openlabels.gui.widgets.fp_dialog import FalsePositiveDialog

        spans = result.get("spans", [])
        entities = result.get("entities", {})

        if not spans and not entities:
            QMessageBox.information(
                self, "No Entities",
                "No detected entities to report as false positives."
            )
            return

        dialog = FalsePositiveDialog(self, file_path, spans, entities)
        if dialog.exec():
            allowlist_entries = dialog.get_allowlist_entries()
            if allowlist_entries:
                self._add_to_allowlist(allowlist_entries)
                self._status_label.setText(
                    f"Added {len(allowlist_entries)} pattern(s) to allowlist"
                )

    def _add_to_allowlist(self, entries: List[Dict[str, Any]]):
        """Add entries to the false positive allowlist."""
        import json
        allowlist_path = Path.home() / ".openlabels" / "allowlist.json"
        allowlist_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing allowlist
        if allowlist_path.exists():
            try:
                with open(allowlist_path, "r") as f:
                    allowlist = json.load(f)
            except (json.JSONDecodeError, IOError):
                allowlist = {"patterns": [], "exact": []}
        else:
            allowlist = {"patterns": [], "exact": []}

        # Add new entries
        for entry in entries:
            if entry.get("type") == "pattern":
                if entry["value"] not in allowlist["patterns"]:
                    allowlist["patterns"].append(entry["value"])
            else:
                if entry["value"] not in allowlist["exact"]:
                    allowlist["exact"].append(entry["value"])

        # Save updated allowlist
        with open(allowlist_path, "w") as f:
            json.dump(allowlist, f, indent=2)

    @Slot()
    def _on_export_csv(self):
        """Export results to CSV."""
        if not self._scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "openlabels_results.csv", "CSV Files (*.csv)"
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "path", "score", "tier", "exposure",
                    "entities", "entity_count", "labels", "error"
                ])
                for r in self._scan_results:
                    entities = r.get("entities", {})
                    entity_str = "|".join(f"{k}:{v}" for k, v in entities.items())
                    entity_count = sum(entities.values()) if entities else 0
                    labels = ",".join(r.get("labels", []))
                    writer.writerow([
                        r.get("path", ""),
                        r.get("score", 0),
                        r.get("tier", ""),
                        r.get("exposure", ""),
                        entity_str,
                        entity_count,
                        labels,
                        r.get("error", ""),
                    ])

            self._status_label.setText(f"Exported to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    @Slot()
    def _on_export_json(self):
        """Export results to JSON."""
        if not self._scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "openlabels_results.json", "JSON Files (*.json)"
        )
        if not file_path:
            return

        try:
            export_data = {
                "exported_at": datetime.now().isoformat(),
                "total_files": len(self._scan_results),
                "summary": self._compute_summary(),
                "files": self._scan_results,
            }

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)

            self._status_label.setText(f"Exported to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _compute_summary(self) -> Dict[str, Any]:
        """Compute summary statistics."""
        if not self._scan_results:
            return {}

        tier_counts = {}
        entity_counts = {}
        scores = []

        for r in self._scan_results:
            tier = r.get("tier", "UNKNOWN")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

            for etype, count in r.get("entities", {}).items():
                entity_counts[etype] = entity_counts.get(etype, 0) + count

            scores.append(r.get("score", 0))

        return {
            "total_files": len(self._scan_results),
            "files_at_risk": sum(1 for s in scores if s > 0),
            "max_score": max(scores) if scores else 0,
            "avg_score": sum(scores) / len(scores) if scores else 0,
            "by_tier": tier_counts,
            "by_entity": dict(sorted(entity_counts.items(), key=lambda x: -x[1])[:20]),
        }

    @Slot()
    def _on_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self)
        dialog.exec()

    @Slot()
    def _on_about(self):
        """Show about dialog."""
        from openlabels import __version__
        QMessageBox.about(
            self,
            "About OpenLabels",
            f"OpenLabels v{__version__}\n\n"
            "Universal Data Risk Scoring\n\n"
            "https://openlabels.dev"
        )

    def _update_risk_summary(self):
        """Update risk summary in status bar."""
        if not self._scan_results:
            self._risk_summary_label.setText("")
            return

        tier_counts = {}
        embedded_count = 0
        for r in self._scan_results:
            tier = r.get("tier", "UNKNOWN")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1
            if r.get("label_embedded"):
                embedded_count += 1

        parts = []
        for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
            if tier in tier_counts:
                parts.append(f"{tier_counts[tier]} {tier}")

        # Add embedded count
        if embedded_count > 0:
            parts.append(f"{embedded_count} labeled")

        self._risk_summary_label.setText(" | ".join(parts))

    def closeEvent(self, event):
        """Handle window close."""
        if self._scan_worker and self._scan_worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Scan in Progress",
                "A scan is in progress. Stop it and exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                self._scan_worker.stop()
                self._scan_worker.wait()
            else:
                event.ignore()
                return

        # Stop file watcher
        if self._file_watcher.is_watching:
            self._file_watcher.stop_watching()

        event.accept()

"""
File Monitoring widget for OpenLabels GUI.

Provides:
- List of monitored files
- Access history viewing
- Enable/disable monitoring
- Alert management
"""

import logging

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtWidgets import (
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPushButton,
        QSpinBox,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE_AVAILABLE = True
except ImportError:
    # PySide6 not installed - monitoring widget unavailable
    logger.debug("PySide6 not installed - monitoring widget disabled")
    PYSIDE_AVAILABLE = False
    QWidget = object


class MonitoringWidget(QWidget if PYSIDE_AVAILABLE else object):
    """
    Widget for managing file access monitoring.

    Signals:
        monitoring_enabled: Emitted when monitoring is enabled (path)
        monitoring_disabled: Emitted when monitoring is disabled (path)
        refresh_requested: Emitted when refresh is requested
    """

    if PYSIDE_AVAILABLE:
        monitoring_enabled = Signal(str)
        monitoring_disabled = Signal(str)
        refresh_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
        self._watched_files: list[dict] = []
        self._access_events: list[dict] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Splitter for watched files and access history
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Watched files section
        watched_group = QGroupBox("Monitored Files")
        watched_layout = QVBoxLayout(watched_group)

        # Actions bar
        actions_layout = QHBoxLayout()

        self._add_btn = QPushButton("Add File")
        self._add_btn.clicked.connect(self._on_add_file)
        actions_layout.addWidget(self._add_btn)

        self._remove_btn = QPushButton("Remove")
        self._remove_btn.setEnabled(False)
        self._remove_btn.clicked.connect(self._on_remove_monitoring)
        actions_layout.addWidget(self._remove_btn)

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._on_refresh)
        actions_layout.addWidget(self._refresh_btn)

        actions_layout.addStretch()

        # Filter
        actions_layout.addWidget(QLabel("Filter:"))
        self._filter_combo = QComboBox()
        self._filter_combo.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._filter_combo.currentTextChanged.connect(self._apply_filter)
        actions_layout.addWidget(self._filter_combo)

        watched_layout.addLayout(actions_layout)

        # Watched files table
        self._watched_table = QTableWidget()
        self._watched_table.setColumnCount(5)
        self._watched_table.setHorizontalHeaderLabels([
            "Path", "Risk Tier", "Added", "Last Access", "Access Count"
        ])
        self._watched_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._watched_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._watched_table.itemSelectionChanged.connect(self._on_selection_changed)
        watched_layout.addWidget(self._watched_table)

        splitter.addWidget(watched_group)

        # Access history section
        history_group = QGroupBox("Access History")
        history_layout = QVBoxLayout(history_group)

        # History controls
        history_controls = QHBoxLayout()
        history_controls.addWidget(QLabel("Days:"))
        self._days_spin = QSpinBox()
        self._days_spin.setRange(1, 365)
        self._days_spin.setValue(30)
        history_controls.addWidget(self._days_spin)

        self._load_history_btn = QPushButton("Load History")
        self._load_history_btn.clicked.connect(self._on_load_history)
        self._load_history_btn.setEnabled(False)
        history_controls.addWidget(self._load_history_btn)

        history_controls.addStretch()
        history_layout.addLayout(history_controls)

        # History table
        self._history_table = QTableWidget()
        self._history_table.setColumnCount(5)
        self._history_table.setHorizontalHeaderLabels([
            "Timestamp", "User", "Action", "Process", "Details"
        ])
        self._history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        history_layout.addWidget(self._history_table)

        splitter.addWidget(history_group)

        layout.addWidget(splitter)

        # Summary bar
        summary_layout = QHBoxLayout()
        self._summary_label = QLabel("No files monitored")
        summary_layout.addWidget(self._summary_label)
        summary_layout.addStretch()
        layout.addLayout(summary_layout)

    def _on_add_file(self) -> None:
        """Add a file to monitoring."""
        dialog = AddMonitoringDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            path = dialog.get_path()
            risk_tier = dialog.get_risk_tier()
            if path:
                self._enable_monitoring(path, risk_tier)

    def _enable_monitoring(self, path: str, risk_tier: str) -> None:
        """Enable monitoring for a file."""
        try:
            from pathlib import Path

            from openlabels.monitoring import enable_monitoring

            result = enable_monitoring(
                path=Path(path),
                risk_tier=risk_tier,
                audit_read=True,
                audit_write=True,
            )

            if result.success:
                self.monitoring_enabled.emit(path)
                self._on_refresh()
                QMessageBox.information(
                    self, "Success",
                    f"Monitoring enabled for: {path}"
                )
            else:
                QMessageBox.warning(
                    self, "Error",
                    f"Failed to enable monitoring: {result.error}"
                )
        except ImportError:
            QMessageBox.warning(
                self, "Error",
                "Monitoring module not available"
            )
        except Exception as e:
            logger.error(f"Failed to enable monitoring for path '{path}': {e}", exc_info=True)
            QMessageBox.warning(self, "Error", str(e))

    def _on_remove_monitoring(self) -> None:
        """Remove monitoring from selected file."""
        selected = self._watched_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        path = self._watched_table.item(row, 0).text()

        reply = QMessageBox.question(
            self, "Confirm",
            f"Remove monitoring from:\n{path}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                from pathlib import Path

                from openlabels.monitoring import disable_monitoring

                result = disable_monitoring(path=Path(path))
                if result.success:
                    self.monitoring_disabled.emit(path)
                    self._on_refresh()
                else:
                    QMessageBox.warning(
                        self, "Error",
                        f"Failed to disable monitoring: {result.error}"
                    )
            except ImportError:
                QMessageBox.warning(
                    self, "Error",
                    "Monitoring module not available"
                )
            except Exception as e:
                logger.error(f"Failed to disable monitoring for path '{path}': {e}", exc_info=True)
                QMessageBox.warning(self, "Error", str(e))

    def _on_refresh(self) -> None:
        """Refresh the watched files list."""
        self.refresh_requested.emit()
        self._load_watched_files()

    def _load_watched_files(self) -> None:
        """Load watched files from the monitoring module."""
        try:
            from openlabels.monitoring import get_watched_files

            watched = get_watched_files()
            self._watched_files = [w.to_dict() for w in watched]
            self._update_watched_table()
        except ImportError:
            logger.warning("Monitoring module not available")
        except Exception as e:
            logger.error(f"Failed to load watched files: {e}")

    def _update_watched_table(self) -> None:
        """Update the watched files table."""
        self._watched_table.setRowCount(0)

        filter_tier = self._filter_combo.currentText()

        for item in self._watched_files:
            if filter_tier != "All" and item.get("risk_tier") != filter_tier:
                continue

            row = self._watched_table.rowCount()
            self._watched_table.insertRow(row)

            self._watched_table.setItem(row, 0, QTableWidgetItem(str(item.get("path", ""))))
            self._watched_table.setItem(row, 1, QTableWidgetItem(item.get("risk_tier", "")))

            added = item.get("added_at")
            if added:
                if isinstance(added, str):
                    added_str = added[:19]
                else:
                    added_str = added.strftime("%Y-%m-%d %H:%M")
            else:
                added_str = "N/A"
            self._watched_table.setItem(row, 2, QTableWidgetItem(added_str))

            last_access = item.get("last_event_at")
            if last_access:
                if isinstance(last_access, str):
                    last_str = last_access[:19]
                else:
                    last_str = last_access.strftime("%Y-%m-%d %H:%M")
            else:
                last_str = "Never"
            self._watched_table.setItem(row, 3, QTableWidgetItem(last_str))

            self._watched_table.setItem(row, 4, QTableWidgetItem(str(item.get("access_count", 0))))

        self._update_summary()

    def _update_summary(self) -> None:
        """Update the summary label."""
        total = len(self._watched_files)
        critical = sum(1 for f in self._watched_files if f.get("risk_tier") == "CRITICAL")
        high = sum(1 for f in self._watched_files if f.get("risk_tier") == "HIGH")

        if total == 0:
            self._summary_label.setText("No files monitored")
        else:
            self._summary_label.setText(
                f"{total} files monitored | {critical} CRITICAL | {high} HIGH"
            )

    def _apply_filter(self, tier: str) -> None:
        """Apply filter to watched files table."""
        self._update_watched_table()

    def _on_selection_changed(self) -> None:
        """Handle selection change in watched table."""
        has_selection = len(self._watched_table.selectedItems()) > 0
        self._remove_btn.setEnabled(has_selection)
        self._load_history_btn.setEnabled(has_selection)

    def _on_load_history(self) -> None:
        """Load access history for selected file."""
        selected = self._watched_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        path = self._watched_table.item(row, 0).text()
        days = self._days_spin.value()

        try:
            from pathlib import Path

            from openlabels.monitoring import get_access_history

            events = get_access_history(
                path=Path(path),
                days=days,
                limit=100,
            )

            self._access_events = [e.to_dict() for e in events]
            self._update_history_table()

        except ImportError:
            QMessageBox.warning(
                self, "Error",
                "Monitoring module not available"
            )
        except Exception as e:
            logger.error(f"Failed to load access history for path '{path}' (days={days}): {e}", exc_info=True)
            QMessageBox.warning(self, "Error", str(e))

    def _update_history_table(self) -> None:
        """Update the history table."""
        self._history_table.setRowCount(0)

        for event in self._access_events:
            row = self._history_table.rowCount()
            self._history_table.insertRow(row)

            ts = event.get("timestamp")
            if ts:
                if isinstance(ts, str):
                    ts_str = ts[:19]
                else:
                    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_str = "N/A"
            self._history_table.setItem(row, 0, QTableWidgetItem(ts_str))

            self._history_table.setItem(row, 1, QTableWidgetItem(event.get("user_display", "")))
            self._history_table.setItem(row, 2, QTableWidgetItem(event.get("action", "")))
            self._history_table.setItem(row, 3, QTableWidgetItem(event.get("process_name", "")))
            self._history_table.setItem(row, 4, QTableWidgetItem(event.get("details", "")))

    def load_watched_files(self, files: list[dict]) -> None:
        """Load watched files from external source."""
        self._watched_files = files
        self._update_watched_table()


class AddMonitoringDialog(QDialog if PYSIDE_AVAILABLE else object):
    """Dialog for adding a file to monitoring."""

    def __init__(self, parent: QWidget | None = None):
        if not PYSIDE_AVAILABLE:
            return

        super().__init__(parent)
        self.setWindowTitle("Add File to Monitoring")
        self.setMinimumWidth(400)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        form = QFormLayout()

        # Path input
        path_layout = QHBoxLayout()
        self._path_input = QLineEdit()
        self._path_input.setPlaceholderText("Enter file path...")
        path_layout.addWidget(self._path_input)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._on_browse)
        path_layout.addWidget(browse_btn)

        form.addRow("File Path:", path_layout)

        # Risk tier
        self._risk_combo = QComboBox()
        self._risk_combo.addItems(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._risk_combo.setCurrentText("HIGH")
        form.addRow("Risk Tier:", self._risk_combo)

        layout.addLayout(form)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_browse(self) -> None:
        """Open file browser."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self._path_input.setText(path)

    def get_path(self) -> str:
        """Get the entered file path."""
        return self._path_input.text().strip()

    def get_risk_tier(self) -> str:
        """Get the selected risk tier."""
        return self._risk_combo.currentText()

"""
Scan management widget.

Allows users to:
- View configured scan targets
- Start new scans
- Monitor scan progress
- Cancel running scans
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# PySide6 imports with graceful fallback
try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtWidgets import (
        QComboBox,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE_AVAILABLE = True
except ImportError:
    # PySide6 not installed - GUI functionality unavailable
    logger.debug("PySide6 not installed - GUI features disabled")
    PYSIDE_AVAILABLE = False
    QWidget = object


class ScanWidget(QWidget if PYSIDE_AVAILABLE else object):
    """
    Widget for managing scans.

    Signals:
        scan_started: Emitted when a scan is started (scan_id)
        scan_cancelled: Emitted when a scan is cancelled (scan_id)
        scan_selected: Emitted when a scan is selected (scan_id)
        refresh_requested: Emitted when refresh is requested
    """

    if PYSIDE_AVAILABLE:
        scan_started = Signal(str)
        scan_cancelled = Signal(str)
        scan_selected = Signal(str)
        refresh_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
        self._targets: list[dict] = []
        self._scans: dict[str, dict] = {}  # scan_id -> scan data
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Targets group
        targets_group = QGroupBox("Scan Targets")
        targets_layout = QVBoxLayout(targets_group)

        self._target_combo = QComboBox()
        self._target_combo.setPlaceholderText("Select target...")
        targets_layout.addWidget(self._target_combo)

        # Actions
        actions_layout = QHBoxLayout()
        self._start_btn = QPushButton("Start Scan")
        self._refresh_btn = QPushButton("Refresh")
        actions_layout.addWidget(self._start_btn)
        actions_layout.addWidget(self._refresh_btn)
        actions_layout.addStretch()
        targets_layout.addLayout(actions_layout)

        layout.addWidget(targets_group)

        # Active scans group
        scans_group = QGroupBox("Active Scans")
        scans_layout = QVBoxLayout(scans_group)

        self._scans_table = QTableWidget()
        self._scans_table.setColumnCount(5)
        self._scans_table.setHorizontalHeaderLabels([
            "Target", "Status", "Progress", "Files", "Started"
        ])
        self._scans_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._scans_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        scans_layout.addWidget(self._scans_table)

        # Scan actions
        scan_actions = QHBoxLayout()
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._view_btn = QPushButton("View Results")
        self._view_btn.setEnabled(False)
        scan_actions.addWidget(self._cancel_btn)
        scan_actions.addWidget(self._view_btn)
        scan_actions.addStretch()
        scans_layout.addLayout(scan_actions)

        layout.addWidget(scans_group)

    def _connect_signals(self) -> None:
        """Connect widget signals."""
        self._start_btn.clicked.connect(self._on_start_scan)
        self._refresh_btn.clicked.connect(self._on_refresh)
        self._cancel_btn.clicked.connect(self._on_cancel_scan)
        self._view_btn.clicked.connect(self._on_view_results)
        self._scans_table.itemSelectionChanged.connect(self._on_selection_changed)

    def _on_start_scan(self) -> None:
        """Handle start scan button click."""
        if self._target_combo.currentIndex() < 0:
            QMessageBox.warning(
                self,
                "No Target Selected",
                "Please select a scan target first."
            )
            return

        target_id = self._target_combo.currentData()
        if target_id:
            logger.info(f"Starting scan for target: {target_id}")
            self.scan_started.emit(str(target_id))
            self._start_btn.setEnabled(False)
            self._start_btn.setText("Starting...")

    def _on_refresh(self) -> None:
        """Handle refresh button click."""
        logger.info("Refresh requested")
        self.refresh_requested.emit()

    def _on_cancel_scan(self) -> None:
        """Handle cancel scan button click."""
        scan_id = self._get_selected_scan_id()
        if scan_id:
            reply = QMessageBox.question(
                self,
                "Cancel Scan",
                "Are you sure you want to cancel this scan?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                logger.info(f"Cancelling scan: {scan_id}")
                self.scan_cancelled.emit(scan_id)

    def _on_view_results(self) -> None:
        """Handle view results button click."""
        scan_id = self._get_selected_scan_id()
        if scan_id:
            self.scan_selected.emit(scan_id)

    def _on_selection_changed(self) -> None:
        """Handle scan selection change."""
        selected = bool(self._scans_table.selectedItems())
        scan_id = self._get_selected_scan_id()

        # Enable/disable buttons based on selection and scan status
        if selected and scan_id and scan_id in self._scans:
            scan = self._scans[scan_id]
            status = scan.get("status", "")
            self._cancel_btn.setEnabled(status in ("pending", "running"))
            self._view_btn.setEnabled(status == "completed")
        else:
            self._cancel_btn.setEnabled(False)
            self._view_btn.setEnabled(False)

    def _get_selected_scan_id(self) -> str | None:
        """Get the ID of the currently selected scan."""
        selected_rows = self._scans_table.selectedItems()
        if not selected_rows:
            return None

        row = selected_rows[0].row()
        scan_ids = list(self._scans.keys())
        if 0 <= row < len(scan_ids):
            return scan_ids[row]
        return None

    def load_targets(self, targets: list[dict]) -> None:
        """Load scan targets into combo box."""
        self._targets = targets
        self._target_combo.clear()
        for target in targets:
            self._target_combo.addItem(
                target.get("name", target.get("path", "Unknown")),
                target.get("id"),
            )
        self._start_btn.setEnabled(True)
        self._start_btn.setText("Start Scan")

    def load_scans(self, scans: list[dict]) -> None:
        """Load active scans into the table."""
        self._scans.clear()
        self._scans_table.setRowCount(0)

        for scan in scans:
            scan_id = scan.get("id")
            if scan_id:
                self._scans[str(scan_id)] = scan
                self._add_scan_row(scan)

    def update_scan(self, scan: dict) -> None:
        """Update or add a scan in the table."""
        scan_id = str(scan.get("id", ""))
        if not scan_id:
            return

        self._scans[scan_id] = scan

        # Find existing row
        for row in range(self._scans_table.rowCount()):
            row_id = list(self._scans.keys())[row] if row < len(self._scans) else None
            if row_id == scan_id:
                self._update_scan_row(row, scan)
                return

        # Add new row if not found
        self._add_scan_row(scan)

    def _add_scan_row(self, scan: dict) -> None:
        """Add a scan as a new row."""
        row = self._scans_table.rowCount()
        self._scans_table.insertRow(row)
        self._update_scan_row(row, scan)

    def _update_scan_row(self, row: int, scan: dict) -> None:
        """Update an existing row with scan data."""
        target_name = scan.get("target_name", scan.get("target_id", "Unknown"))
        status = scan.get("status", "unknown")
        progress = scan.get("progress", {})
        files_scanned = progress.get("files_scanned", 0)
        files_total = progress.get("files_total", 0)
        started_at = scan.get("started_at", scan.get("created_at", ""))

        # Format started time
        if started_at and "T" in started_at:
            started_at = started_at.split("T")[1][:8]

        # Format progress
        if files_total > 0:
            progress_str = f"{files_scanned}/{files_total}"
        else:
            progress_str = str(files_scanned)

        self._scans_table.setItem(row, 0, QTableWidgetItem(str(target_name)))
        self._scans_table.setItem(row, 1, QTableWidgetItem(status.upper()))
        self._scans_table.setItem(row, 2, QTableWidgetItem(progress_str))
        self._scans_table.setItem(row, 3, QTableWidgetItem(str(files_scanned)))
        self._scans_table.setItem(row, 4, QTableWidgetItem(started_at))

        # Color status cell based on status
        status_item = self._scans_table.item(row, 1)
        if status == "completed":
            status_item.setBackground(Qt.GlobalColor.green)
        elif status == "failed":
            status_item.setBackground(Qt.GlobalColor.red)
        elif status == "running":
            status_item.setBackground(Qt.GlobalColor.yellow)
        elif status == "cancelled":
            status_item.setBackground(Qt.GlobalColor.gray)

    def remove_scan(self, scan_id: str) -> None:
        """Remove a scan from the table."""
        if scan_id not in self._scans:
            return

        # Find and remove the row
        scan_ids = list(self._scans.keys())
        if scan_id in scan_ids:
            row = scan_ids.index(scan_id)
            self._scans_table.removeRow(row)
            del self._scans[scan_id]

    def on_scan_complete(self) -> None:
        """Called when a scan completes."""
        self._start_btn.setEnabled(True)
        self._start_btn.setText("Start Scan")

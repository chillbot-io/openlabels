"""
Scan management widget.

Allows users to:
- View configured scan targets
- Start new scans
- Monitor scan progress
- Cancel running scans
"""

import logging
from typing import Optional, List

logger = logging.getLogger(__name__)

# PySide6 imports with graceful fallback
try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTableWidget, QTableWidgetItem, QProgressBar, QComboBox,
        QGroupBox, QHeaderView,
    )
    from PySide6.QtCore import Qt, Signal
    PYSIDE_AVAILABLE = True
except ImportError:
    PYSIDE_AVAILABLE = False
    QWidget = object


class ScanWidget(QWidget if PYSIDE_AVAILABLE else object):
    """
    Widget for managing scans.

    Signals:
        scan_started: Emitted when a scan is started (scan_id)
        scan_cancelled: Emitted when a scan is cancelled (scan_id)
        scan_selected: Emitted when a scan is selected (scan_id)
    """

    if PYSIDE_AVAILABLE:
        scan_started = Signal(str)
        scan_cancelled = Signal(str)
        scan_selected = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
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
        self._scans_table.itemSelectionChanged.connect(self._on_selection_changed)

    def _on_start_scan(self) -> None:
        """Handle start scan button click."""
        # TODO: Start scan for selected target
        logger.info("Start scan clicked")

    def _on_refresh(self) -> None:
        """Handle refresh button click."""
        # TODO: Refresh targets and scans
        logger.info("Refresh clicked")

    def _on_cancel_scan(self) -> None:
        """Handle cancel scan button click."""
        # TODO: Cancel selected scan
        logger.info("Cancel scan clicked")

    def _on_selection_changed(self) -> None:
        """Handle scan selection change."""
        selected = bool(self._scans_table.selectedItems())
        self._cancel_btn.setEnabled(selected)
        self._view_btn.setEnabled(selected)

    def load_targets(self, targets: List[dict]) -> None:
        """Load scan targets into combo box."""
        self._target_combo.clear()
        for target in targets:
            self._target_combo.addItem(
                target.get("name", target.get("path", "Unknown")),
                target.get("id"),
            )

    def update_scan(self, scan: dict) -> None:
        """Update or add a scan in the table."""
        # TODO: Update scan row
        pass

    def remove_scan(self, scan_id: str) -> None:
        """Remove a scan from the table."""
        # TODO: Remove scan row
        pass

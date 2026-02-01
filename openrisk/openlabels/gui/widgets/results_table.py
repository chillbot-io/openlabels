"""
Results table widget.

Displays scan results with risk scores, tiers, entities, and action buttons.
"""

from pathlib import Path
from typing import Optional, Dict, Any, List

from PySide6.QtWidgets import (
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QHeaderView,
    QAbstractItemView,
    QLineEdit,
    QComboBox,
)
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QColor, QBrush


# Tier colors
TIER_COLORS = {
    "CRITICAL": QColor(220, 53, 69),    # Red
    "HIGH": QColor(253, 126, 20),       # Orange
    "MEDIUM": QColor(255, 193, 7),      # Yellow
    "LOW": QColor(40, 167, 69),         # Green
    "MINIMAL": QColor(108, 117, 125),   # Gray
    "UNKNOWN": QColor(108, 117, 125),   # Gray
}


class ResultsTableWidget(QWidget):
    """Widget displaying scan results in a table."""

    # Signals
    quarantine_requested = Signal(str)  # file_path
    label_requested = Signal(str)       # file_path
    detail_requested = Signal(str)      # file_path (double-click)
    fp_reported = Signal(str, dict)     # file_path, result dict (for false positive reporting)

    COLUMNS = [
        ("Name", 140),
        ("Directory", 120),
        ("Size", 60),
        ("Score", 65),
        ("Tier", 55),
        ("Label", 60),
        ("Entities", 100),
        ("Actions", 110),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_results: List[Dict[str, Any]] = []
        self._filter_path: Optional[str] = None
        self._batch_mode = False  # Disable sorting during batch inserts
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 4, 0)  # Small right margin for panel separation
        layout.setSpacing(4)

        # Filter bar - search input spans to left edge for symmetry
        filter_layout = QHBoxLayout()
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.setSpacing(8)

        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Search by name...")
        self._filter_input.textChanged.connect(self._apply_filters)

        self._tier_filter = QComboBox()
        self._tier_filter.addItem("All Tiers", "")
        for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
            self._tier_filter.addItem(tier, tier)
        self._tier_filter.currentIndexChanged.connect(self._apply_filters)
        self._tier_filter.setMinimumWidth(100)

        filter_layout.addWidget(self._filter_input, stretch=1)
        filter_layout.addWidget(self._tier_filter)

        layout.addLayout(filter_layout)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # Column widths
        header = self._table.horizontalHeader()
        for i, (name, width) in enumerate(self.COLUMNS):
            self._table.setColumnWidth(i, width)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(6, QHeaderView.Stretch)  # Entities column stretches

        # Double-click to show details
        self._table.cellDoubleClicked.connect(self._on_double_click)

        layout.addWidget(self._table)

    def _on_double_click(self, row: int, column: int):
        """Handle double-click on a row to show details."""
        item = self._table.item(row, 0)  # Name column has path in UserRole
        if item:
            file_path = item.data(Qt.UserRole)
            if file_path:
                self.detail_requested.emit(file_path)

    def begin_batch(self):
        """Begin batch insert mode - disables sorting for performance."""
        self._batch_mode = True
        self._table.setSortingEnabled(False)
        # Don't disable updates entirely - it causes rendering glitches
        # Instead, just disable sorting which is the main performance hit

    def end_batch(self):
        """End batch insert mode - re-enables sorting."""
        self._batch_mode = False
        self._table.setSortingEnabled(True)
        # Force a repaint to ensure everything renders correctly
        self._table.viewport().update()

    def add_result(self, result: Dict[str, Any]):
        """Add a scan result to the table."""
        file_path = result.get("path", "")

        # Check if file already exists - update instead of adding duplicate
        for i, r in enumerate(self._all_results):
            if r.get("path") == file_path:
                self._all_results[i] = result
                self.update_result(result)
                return

        self._all_results.append(result)

        # Temporarily disable sorting if not in batch mode (for single adds)
        if not self._batch_mode:
            self._table.setSortingEnabled(False)

        self._add_row(result)

        # Re-enable sorting if not in batch mode
        if not self._batch_mode:
            self._table.setSortingEnabled(True)

    def add_results_batch(self, results: List[Dict[str, Any]]):
        """Add multiple results efficiently in a single batch.

        This is more efficient than calling add_result() repeatedly
        because it only updates the display once at the end.
        """
        if not results:
            return

        # Store all results
        self._all_results.extend(results)

        # Disable sorting during bulk insert
        was_sorting_enabled = self._table.isSortingEnabled()
        self._table.setSortingEnabled(False)

        # Add all rows
        for result in results:
            self._add_row(result)

        # Restore sorting state
        if was_sorting_enabled and not self._batch_mode:
            self._table.setSortingEnabled(True)

    def _add_row(self, result: Dict[str, Any]):
        """Add a row to the table for a result."""
        # Check if it passes current filter
        if not self._passes_filter(result):
            return

        row = self._table.rowCount()
        self._table.insertRow(row)

        path = result.get("path", "")
        name = Path(path).name if path else ""
        directory = str(Path(path).parent) if path else ""
        size = result.get("size", 0)
        score = result.get("score", 0)
        tier = result.get("tier", "UNKNOWN")
        entities = result.get("entities", {})
        error = result.get("error")

        # Name (col 0)
        name_item = QTableWidgetItem(name)
        name_item.setToolTip(path)
        name_item.setData(Qt.UserRole, path)  # Store full path
        self._table.setItem(row, 0, name_item)

        # Directory (col 1)
        dir_item = QTableWidgetItem(directory)
        dir_item.setToolTip(directory)
        self._table.setItem(row, 1, dir_item)

        # Size (col 2)
        size_str = self._format_size(size)
        size_item = QTableWidgetItem(size_str)
        size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._table.setItem(row, 2, size_item)

        # Score (col 3)
        score_item = QTableWidgetItem(str(score) if not error else "--")
        score_item.setTextAlignment(Qt.AlignCenter)
        score_item.setData(Qt.UserRole, score)  # For sorting
        if tier in TIER_COLORS:
            score_item.setForeground(QBrush(TIER_COLORS[tier]))
        self._table.setItem(row, 3, score_item)

        # Tier (col 4) - use text only, no background color (cleaner look)
        tier_display = tier if not error else "ERROR"
        tier_item = QTableWidgetItem(tier_display)
        tier_item.setTextAlignment(Qt.AlignCenter)
        if tier in TIER_COLORS:
            tier_item.setForeground(QBrush(TIER_COLORS[tier]))
        self._table.setItem(row, 4, tier_item)

        # Label embedded status (col 5)
        label_embedded = result.get("label_embedded", False)
        label_item = QTableWidgetItem("Yes" if label_embedded else "--")
        label_item.setTextAlignment(Qt.AlignCenter)
        if label_embedded:
            label_item.setForeground(QBrush(QColor(34, 197, 94)))  # Green
        else:
            label_item.setForeground(QBrush(QColor(148, 163, 184)))  # Gray
        self._table.setItem(row, 5, label_item)

        # Entities (col 6)
        if error:
            entities_str = f"Error: {error}"
        else:
            entities_str = ", ".join(f"{k}({v})" for k, v in entities.items()) if entities else "-"
        entities_item = QTableWidgetItem(entities_str)
        self._table.setItem(row, 6, entities_item)

        # Actions (col 7) - widget with buttons
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(2, 2, 2, 2)
        actions_layout.setSpacing(2)

        quarantine_btn = QPushButton("Q")
        quarantine_btn.setToolTip("Quarantine this file")
        quarantine_btn.setFixedWidth(28)
        quarantine_btn.setStyleSheet("font-weight: bold;")
        quarantine_btn.clicked.connect(lambda checked, p=path: self.quarantine_requested.emit(p))

        label_btn = QPushButton("L")
        label_btn.setToolTip("Add custom label")
        label_btn.setFixedWidth(28)
        label_btn.setStyleSheet("font-weight: bold;")
        label_btn.clicked.connect(lambda checked, p=path: self.label_requested.emit(p))

        fp_btn = QPushButton("FP")
        fp_btn.setToolTip("Report false positive")
        fp_btn.setFixedWidth(28)
        fp_btn.setStyleSheet("font-weight: bold; color: #d29922;")
        fp_btn.clicked.connect(lambda checked, p=path, r=result: self.fp_reported.emit(p, r))

        actions_layout.addWidget(quarantine_btn)
        actions_layout.addWidget(label_btn)
        actions_layout.addWidget(fp_btn)
        actions_layout.addStretch()

        self._table.setCellWidget(row, 7, actions_widget)

    def _passes_filter(self, result: Dict[str, Any]) -> bool:
        """Check if a result passes current filters."""
        path = result.get("path", "")
        tier = result.get("tier", "")

        # Path filter
        if self._filter_path:
            if not path.startswith(self._filter_path):
                return False

        # Text filter
        text_filter = self._filter_input.text().strip().lower()
        if text_filter:
            name = Path(path).name.lower() if path else ""
            if text_filter not in name:
                return False

        # Tier filter
        tier_filter = self._tier_filter.currentData()
        if tier_filter and tier != tier_filter:
            return False

        return True

    def _apply_filters(self):
        """Reapply all filters to the table."""
        self._table.setRowCount(0)
        for result in self._all_results:
            self._add_row(result)

    def filter_by_path(self, path: str):
        """Filter results to show only files under a path."""
        self._filter_path = path
        self._apply_filters()

    def clear_path_filter(self):
        """Clear the path filter."""
        self._filter_path = None
        self._apply_filters()

    def clear(self):
        """Clear all results."""
        self._all_results.clear()
        self._table.setRowCount(0)

    def remove_result(self, file_path: str):
        """Remove a result by file path."""
        # Remove from internal list
        self._all_results = [r for r in self._all_results if r.get("path") != file_path]

        # Remove from table
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item and item.data(Qt.UserRole) == file_path:
                self._table.removeRow(row)
                break

    def update_result(self, result: Dict[str, Any]):
        """Update an existing result in the table."""
        file_path = result.get("path", "")

        # Update in internal list
        for i, r in enumerate(self._all_results):
            if r.get("path") == file_path:
                self._all_results[i] = result
                break

        # Find and update the row in the table
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item and item.data(Qt.UserRole) == file_path:
                # Update the row in place
                score = result.get("score", 0)
                tier = result.get("tier", "UNKNOWN")
                entities = result.get("entities", {})
                error = result.get("error")

                # Score (col 3)
                score_item = self._table.item(row, 3)
                if score_item:
                    score_item.setText(str(score) if not error else "--")
                    score_item.setData(Qt.UserRole, score)
                    if tier in TIER_COLORS:
                        score_item.setForeground(QBrush(TIER_COLORS[tier]))

                # Tier (col 4) - colored text only
                tier_item = self._table.item(row, 4)
                if tier_item:
                    tier_item.setText(tier if not error else "ERROR")
                    if tier in TIER_COLORS:
                        tier_item.setForeground(QBrush(TIER_COLORS[tier]))

                # Entities (col 5)
                entities_item = self._table.item(row, 5)
                if entities_item:
                    if error:
                        entities_str = f"Error: {error}"
                    else:
                        entities_str = ", ".join(f"{k}({v})" for k, v in entities.items()) if entities else "-"
                    entities_item.setText(entities_str)

                break

    def get_all_results(self) -> List[Dict[str, Any]]:
        """Get all results."""
        return self._all_results.copy()

    def _format_size(self, size: int) -> str:
        """Format file size for display."""
        if size <= 0:
            return "-"
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"

"""
Results viewer widget.

Displays scan results with filtering, sorting, and export capabilities.
"""

import csv
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict

from openlabels.core.path_validation import validate_output_path, PathValidationError

logger = logging.getLogger(__name__)

try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTableWidget, QTableWidgetItem, QComboBox, QLineEdit,
        QGroupBox, QHeaderView, QSplitter, QTextEdit, QFileDialog,
        QMessageBox,
    )
    from PySide6.QtCore import Qt, Signal
    PYSIDE_AVAILABLE = True
except ImportError:
    # PySide6 not installed - results widget unavailable
    logger.debug("PySide6 not installed - results widget disabled")
    PYSIDE_AVAILABLE = False
    QWidget = object


class ResultsWidget(QWidget if PYSIDE_AVAILABLE else object):
    """
    Widget for viewing scan results.

    Features:
    - Filter by risk tier
    - Search by filename
    - View entity details
    - Export results

    Signals:
        result_selected: Emitted when a result is selected (result_id)
        label_requested: Emitted when labeling is requested (result_ids, label_id)
        refresh_requested: Emitted when refresh is requested
    """

    if PYSIDE_AVAILABLE:
        result_selected = Signal(dict)  # Emits the full result dict
        label_requested = Signal(list, str)
        refresh_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
        self._all_results: List[Dict] = []
        self._filtered_results: List[Dict] = []
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Filters
        filters_layout = QHBoxLayout()

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search files...")
        filters_layout.addWidget(self._search_edit)

        self._tier_combo = QComboBox()
        self._tier_combo.addItem("All Tiers", None)
        self._tier_combo.addItem("Critical", "CRITICAL")
        self._tier_combo.addItem("High", "HIGH")
        self._tier_combo.addItem("Medium", "MEDIUM")
        self._tier_combo.addItem("Low", "LOW")
        self._tier_combo.addItem("Minimal", "MINIMAL")
        filters_layout.addWidget(self._tier_combo)

        self._labeled_combo = QComboBox()
        self._labeled_combo.addItem("All Files", None)
        self._labeled_combo.addItem("Labeled", True)
        self._labeled_combo.addItem("Unlabeled", False)
        filters_layout.addWidget(self._labeled_combo)

        self._refresh_btn = QPushButton("Refresh")
        filters_layout.addWidget(self._refresh_btn)

        layout.addLayout(filters_layout)

        # Splitter for table and details
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Results table
        self._results_table = QTableWidget()
        self._results_table.setColumnCount(6)
        self._results_table.setHorizontalHeaderLabels([
            "File", "Risk", "Score", "Entities", "Labeled", "ID"
        ])
        self._results_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._results_table.setColumnHidden(5, True)  # Hide ID column
        self._results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._results_table.setSelectionMode(
            QTableWidget.SelectionMode.ExtendedSelection
        )
        splitter.addWidget(self._results_table)

        # Details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)

        self._details_label = QLabel("Select a file to view details")
        self._details_label.setWordWrap(True)
        details_layout.addWidget(self._details_label)

        self._entities_text = QTextEdit()
        self._entities_text.setReadOnly(True)
        details_layout.addWidget(self._entities_text)

        splitter.addWidget(details_widget)
        splitter.setSizes([600, 300])

        layout.addWidget(splitter)

        # Actions
        actions_layout = QHBoxLayout()

        self._label_btn = QPushButton("Apply Label")
        self._label_btn.setEnabled(False)
        actions_layout.addWidget(self._label_btn)

        self._export_btn = QPushButton("Export CSV")
        actions_layout.addWidget(self._export_btn)

        self._export_json_btn = QPushButton("Export JSON")
        actions_layout.addWidget(self._export_json_btn)

        actions_layout.addStretch()

        self._count_label = QLabel("0 results")
        actions_layout.addWidget(self._count_label)

        layout.addLayout(actions_layout)

    def _connect_signals(self) -> None:
        """Connect widget signals."""
        self._search_edit.textChanged.connect(self._apply_filters)
        self._tier_combo.currentIndexChanged.connect(self._apply_filters)
        self._labeled_combo.currentIndexChanged.connect(self._apply_filters)
        self._refresh_btn.clicked.connect(self._on_refresh)
        self._results_table.itemSelectionChanged.connect(self._on_selection_changed)
        self._label_btn.clicked.connect(self._on_label_clicked)
        self._export_btn.clicked.connect(self._on_export_csv)
        self._export_json_btn.clicked.connect(self._on_export_json)

    def _apply_filters(self) -> None:
        """Apply current filters to results."""
        search_text = self._search_edit.text().lower()
        tier_filter = self._tier_combo.currentData()
        labeled_filter = self._labeled_combo.currentData()

        self._filtered_results = []

        for result in self._all_results:
            # Apply search filter
            file_name = result.get("file_name", "").lower()
            file_path = result.get("file_path", "").lower()
            if search_text and search_text not in file_name and search_text not in file_path:
                continue

            # Apply tier filter
            if tier_filter and result.get("risk_tier") != tier_filter:
                continue

            # Apply labeled filter
            is_labeled = result.get("label_applied", result.get("labeled", False))
            if labeled_filter is True and not is_labeled:
                continue
            if labeled_filter is False and is_labeled:
                continue

            self._filtered_results.append(result)

        self._refresh_table()

    def _refresh_table(self) -> None:
        """Refresh the table with filtered results."""
        self._results_table.setRowCount(len(self._filtered_results))

        for row, result in enumerate(self._filtered_results):
            file_name = result.get("file_name", Path(result.get("file_path", "")).name)
            risk_tier = result.get("risk_tier", "UNKNOWN")
            risk_score = result.get("risk_score", 0)
            entity_count = sum(result.get("entity_counts", {}).values()) if isinstance(result.get("entity_counts"), dict) else result.get("entity_count", 0)
            is_labeled = result.get("label_applied", result.get("labeled", False))
            result_id = str(result.get("id", ""))

            self._results_table.setItem(row, 0, QTableWidgetItem(file_name))

            tier_item = QTableWidgetItem(risk_tier)
            self._color_tier_item(tier_item, risk_tier)
            self._results_table.setItem(row, 1, tier_item)

            self._results_table.setItem(row, 2, QTableWidgetItem(str(risk_score)))
            self._results_table.setItem(row, 3, QTableWidgetItem(str(entity_count)))
            self._results_table.setItem(row, 4, QTableWidgetItem("Yes" if is_labeled else "No"))
            self._results_table.setItem(row, 5, QTableWidgetItem(result_id))

        self._count_label.setText(f"{len(self._filtered_results)} results")

    def _color_tier_item(self, item: QTableWidgetItem, tier: str) -> None:
        """Color a table item based on risk tier."""
        colors = {
            "CRITICAL": Qt.GlobalColor.red,
            "HIGH": Qt.GlobalColor.darkYellow,
            "MEDIUM": Qt.GlobalColor.yellow,
            "LOW": Qt.GlobalColor.green,
            "MINIMAL": Qt.GlobalColor.gray,
        }
        if tier in colors:
            item.setBackground(colors[tier])

    def _on_refresh(self) -> None:
        """Handle refresh click."""
        logger.info("Refresh requested")
        self.refresh_requested.emit()

    def _on_selection_changed(self) -> None:
        """Handle selection change."""
        selected_rows = self._results_table.selectedItems()
        selected = bool(selected_rows)
        self._label_btn.setEnabled(selected)

        if selected:
            # Get first selected row
            row = selected_rows[0].row()
            if 0 <= row < len(self._filtered_results):
                result = self._filtered_results[row]
                self._show_details(result)
                # Emit signal for file detail panel
                self.result_selected.emit(result)

    def _show_details(self, result: dict) -> None:
        """Show details for a result."""
        file_path = result.get("file_path", "")
        risk_tier = result.get("risk_tier", "UNKNOWN")
        risk_score = result.get("risk_score", 0)

        self._details_label.setText(
            f"<b>Path:</b> {file_path}<br>"
            f"<b>Risk:</b> {risk_tier} ({risk_score})<br>"
            f"<b>Label:</b> {result.get('current_label_name', 'None')}"
        )

        # Show entity details
        entities = result.get("entity_counts", {})
        if entities:
            details = "<b>Detected Entities:</b>\n\n"
            for etype, count in sorted(entities.items(), key=lambda x: -x[1]):
                details += f"  {etype}: {count}\n"
        else:
            details = "No entities detected"

        self._entities_text.setText(details)

    def _on_label_clicked(self) -> None:
        """Handle label button click."""
        selected_ids = self._get_selected_result_ids()
        if not selected_ids:
            return

        # For now, emit signal - parent window should show label selection dialog
        # In a full implementation, we'd show a dialog to select a label
        logger.info(f"Label requested for {len(selected_ids)} results")
        self.label_requested.emit(selected_ids, "")

    def _get_selected_result_ids(self) -> List[str]:
        """Get IDs of selected results."""
        result_ids = []
        for item in self._results_table.selectedItems():
            if item.column() == 5:  # ID column
                result_ids.append(item.text())
            elif item.column() == 0:  # First column, get ID from same row
                row = item.row()
                id_item = self._results_table.item(row, 5)
                if id_item and id_item.text() not in result_ids:
                    result_ids.append(id_item.text())
        return list(set(result_ids))

    def _on_export_csv(self) -> None:
        """Export results to CSV."""
        if not self._filtered_results:
            QMessageBox.information(self, "Export", "No results to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export CSV",
            "openlabels_results.csv",
            "CSV Files (*.csv)",
        )

        if not file_path:
            return

        # Security: Validate output path to prevent writing to system directories
        try:
            validated_path = validate_output_path(file_path, create_parent=True)
        except PathValidationError as e:
            QMessageBox.critical(self, "Export Error", f"Invalid path: {e}")
            return

        try:
            with open(validated_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["File Path", "File Name", "Risk Tier", "Risk Score", "Entity Count", "Labeled", "Label Name"])

                for result in self._filtered_results:
                    entity_count = sum(result.get("entity_counts", {}).values()) if isinstance(result.get("entity_counts"), dict) else result.get("entity_count", 0)
                    writer.writerow([
                        result.get("file_path", ""),
                        result.get("file_name", ""),
                        result.get("risk_tier", ""),
                        result.get("risk_score", 0),
                        entity_count,
                        "Yes" if result.get("label_applied") else "No",
                        result.get("current_label_name", ""),
                    ])

            QMessageBox.information(self, "Export", f"Exported {len(self._filtered_results)} results to {validated_path}")

        except IOError as e:
            logger.error(f"I/O error while exporting CSV to '{validated_path}': {e}", exc_info=True)
            QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")
        except Exception as e:
            logger.error(f"Unexpected error while exporting CSV to '{validated_path}': {e}", exc_info=True)
            QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")

    def _on_export_json(self) -> None:
        """Export results to JSON."""
        if not self._filtered_results:
            QMessageBox.information(self, "Export", "No results to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export JSON",
            "openlabels_results.json",
            "JSON Files (*.json)",
        )

        if not file_path:
            return

        # Security: Validate output path to prevent writing to system directories
        try:
            validated_path = validate_output_path(file_path, create_parent=True)
        except PathValidationError as e:
            QMessageBox.critical(self, "Export Error", f"Invalid path: {e}")
            return

        try:
            with open(validated_path, "w", encoding="utf-8") as f:
                json.dump(self._filtered_results, f, indent=2, default=str)

            QMessageBox.information(self, "Export", f"Exported {len(self._filtered_results)} results to {validated_path}")

        except IOError as e:
            logger.error(f"I/O error while exporting JSON to '{validated_path}': {e}", exc_info=True)
            QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")
        except Exception as e:
            logger.error(f"Unexpected error while exporting JSON to '{validated_path}': {e}", exc_info=True)
            QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")

    def load_results(self, results: List[dict]) -> None:
        """Load results into the table."""
        self._all_results = results
        self._apply_filters()

    def show_details(self, result: dict) -> None:
        """Show details for a result (external call)."""
        self._show_details(result)

"""
Results viewer widget.

Displays scan results with filtering, sorting, and export capabilities.
"""

import logging
from typing import Optional, List

logger = logging.getLogger(__name__)

try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTableWidget, QTableWidgetItem, QComboBox, QLineEdit,
        QGroupBox, QHeaderView, QSplitter, QTextEdit,
    )
    from PySide6.QtCore import Qt, Signal
    PYSIDE_AVAILABLE = True
except ImportError:
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
        label_requested: Emitted when labeling is requested (result_ids)
    """

    if PYSIDE_AVAILABLE:
        result_selected = Signal(str)
        label_requested = Signal(list)

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

        self._refresh_btn = QPushButton("Refresh")
        filters_layout.addWidget(self._refresh_btn)

        layout.addLayout(filters_layout)

        # Splitter for table and details
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Results table
        self._results_table = QTableWidget()
        self._results_table.setColumnCount(5)
        self._results_table.setHorizontalHeaderLabels([
            "File", "Risk", "Score", "Entities", "Labeled"
        ])
        self._results_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        splitter.addWidget(self._results_table)

        # Details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)

        self._details_label = QLabel("Select a file to view details")
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

        self._export_btn = QPushButton("Export")
        actions_layout.addWidget(self._export_btn)

        actions_layout.addStretch()

        self._count_label = QLabel("0 results")
        actions_layout.addWidget(self._count_label)

        layout.addLayout(actions_layout)

    def _connect_signals(self) -> None:
        """Connect widget signals."""
        self._search_edit.textChanged.connect(self._on_filter_changed)
        self._tier_combo.currentIndexChanged.connect(self._on_filter_changed)
        self._refresh_btn.clicked.connect(self._on_refresh)
        self._results_table.itemSelectionChanged.connect(self._on_selection_changed)
        self._label_btn.clicked.connect(self._on_label_clicked)
        self._export_btn.clicked.connect(self._on_export_clicked)

    def _on_filter_changed(self) -> None:
        """Handle filter change."""
        # TODO: Apply filters to results
        logger.info("Filter changed")

    def _on_refresh(self) -> None:
        """Handle refresh click."""
        # TODO: Reload results
        logger.info("Refresh clicked")

    def _on_selection_changed(self) -> None:
        """Handle selection change."""
        selected = bool(self._results_table.selectedItems())
        self._label_btn.setEnabled(selected)

        if selected:
            # TODO: Load details for selected result
            pass

    def _on_label_clicked(self) -> None:
        """Handle label button click."""
        # TODO: Request labeling for selected results
        logger.info("Label clicked")

    def _on_export_clicked(self) -> None:
        """Handle export button click."""
        # TODO: Export results
        logger.info("Export clicked")

    def load_results(self, results: List[dict]) -> None:
        """Load results into the table."""
        self._results_table.setRowCount(len(results))

        for row, result in enumerate(results):
            self._results_table.setItem(
                row, 0, QTableWidgetItem(result.get("file_name", ""))
            )
            self._results_table.setItem(
                row, 1, QTableWidgetItem(result.get("risk_tier", ""))
            )
            self._results_table.setItem(
                row, 2, QTableWidgetItem(str(result.get("risk_score", 0)))
            )
            self._results_table.setItem(
                row, 3, QTableWidgetItem(str(result.get("entity_count", 0)))
            )
            self._results_table.setItem(
                row, 4, QTableWidgetItem("Yes" if result.get("labeled") else "No")
            )

        self._count_label.setText(f"{len(results)} results")

    def show_details(self, result: dict) -> None:
        """Show details for a result."""
        self._details_label.setText(result.get("file_path", ""))

        entities = result.get("entity_counts", {})
        details = "\n".join(
            f"{etype}: {count}" for etype, count in entities.items()
        )
        self._entities_text.setText(details or "No entities detected")

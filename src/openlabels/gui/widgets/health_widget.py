"""
Health widget for system monitoring.

Displays key system health indicators:
- Server status
- Service status (ML, MIP, OCR)
- Recent errors
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt, QTimer, Signal
    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE_AVAILABLE = True
except ImportError:
    # PySide6 not installed - health widget unavailable
    logger.debug("PySide6 not installed - health widget disabled")
    PYSIDE_AVAILABLE = False
    QWidget = object


class StatusIndicator(QFrame if PYSIDE_AVAILABLE else object):
    """A colored status indicator with label."""

    COLORS = {
        "healthy": "#28a745",
        "warning": "#ffc107",
        "error": "#dc3545",
        "unknown": "#6c757d",
    }

    def __init__(self, label: str, parent: QWidget | None = None):
        if not PYSIDE_AVAILABLE:
            return
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setSpacing(8)

        self._dot = QFrame()
        self._dot.setFixedSize(12, 12)
        self._dot.setStyleSheet(f"background-color: {self.COLORS['unknown']}; border-radius: 6px;")
        layout.addWidget(self._dot)

        self._label = QLabel(label)
        self._label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self._label)

        self._status_text = QLabel("Unknown")
        self._status_text.setStyleSheet("color: #666;")
        layout.addWidget(self._status_text)

        layout.addStretch()

    def set_status(self, status: str, text: str = "") -> None:
        """Update status indicator."""
        if not PYSIDE_AVAILABLE:
            return
        color = self.COLORS.get(status, self.COLORS["unknown"])
        self._dot.setStyleSheet(f"background-color: {color}; border-radius: 6px;")
        if text:
            self._status_text.setText(text)


class HealthWidget(QWidget if PYSIDE_AVAILABLE else object):
    """System health monitoring widget."""

    if PYSIDE_AVAILABLE:
        refresh_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        if not PYSIDE_AVAILABLE:
            return
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Header
        header = QHBoxLayout()
        header.addWidget(QLabel("<b>System Health</b>"))
        header.addStretch()

        self._last_update = QLabel("Updated: --")
        self._last_update.setStyleSheet("color: #888;")
        header.addWidget(self._last_update)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._on_refresh)
        header.addWidget(refresh_btn)

        layout.addLayout(header)

        # Status row
        status_layout = QHBoxLayout()

        # Server group
        server_group = QGroupBox("Server")
        server_layout = QVBoxLayout(server_group)
        self._api_status = StatusIndicator("API")
        server_layout.addWidget(self._api_status)
        self._db_status = StatusIndicator("Database")
        server_layout.addWidget(self._db_status)
        self._queue_status = StatusIndicator("Job Queue")
        server_layout.addWidget(self._queue_status)
        server_layout.addStretch()
        status_layout.addWidget(server_group)

        # Services group
        services_group = QGroupBox("Services")
        services_layout = QVBoxLayout(services_group)
        self._ml_status = StatusIndicator("ML Models")
        services_layout.addWidget(self._ml_status)
        self._mip_status = StatusIndicator("MIP SDK")
        services_layout.addWidget(self._mip_status)
        self._ocr_status = StatusIndicator("OCR")
        services_layout.addWidget(self._ocr_status)
        services_layout.addStretch()
        status_layout.addWidget(services_group)

        # Stats group
        stats_group = QGroupBox("Statistics")
        stats_layout = QGridLayout(stats_group)

        stats_layout.addWidget(QLabel("Scans Today:"), 0, 0)
        self._scans_today = QLabel("0")
        self._scans_today.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self._scans_today, 0, 1)

        stats_layout.addWidget(QLabel("Files Processed:"), 1, 0)
        self._files_processed = QLabel("0")
        self._files_processed.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self._files_processed, 1, 1)

        stats_layout.addWidget(QLabel("Success Rate:"), 2, 0)
        self._success_rate = QLabel("-")
        self._success_rate.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self._success_rate, 2, 1)

        stats_layout.setRowStretch(3, 1)
        status_layout.addWidget(stats_group)

        layout.addLayout(status_layout)

        # Error log
        error_group = QGroupBox("Recent Errors")
        error_layout = QVBoxLayout(error_group)

        self._error_table = QTableWidget()
        self._error_table.setColumnCount(3)
        self._error_table.setHorizontalHeaderLabels(["Time", "Source", "Message"])
        self._error_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._error_table.setMaximumHeight(150)
        error_layout.addWidget(self._error_table)

        layout.addWidget(error_group)
        layout.addStretch()

    def _on_refresh(self) -> None:
        self._last_update.setText(f"Updated: {datetime.now().strftime('%H:%M:%S')}")
        self.refresh_requested.emit()

    def update_status(self, data: dict) -> None:
        """Update all status indicators from a single dict."""
        if not PYSIDE_AVAILABLE:
            return

        # Server
        self._api_status.set_status(data.get("api", "unknown"), data.get("api_text", ""))
        self._db_status.set_status(data.get("db", "unknown"), data.get("db_text", ""))
        self._queue_status.set_status(data.get("queue", "unknown"), data.get("queue_text", ""))

        # Services
        self._ml_status.set_status(data.get("ml", "unknown"), data.get("ml_text", ""))
        self._mip_status.set_status(data.get("mip", "unknown"), data.get("mip_text", ""))
        self._ocr_status.set_status(data.get("ocr", "unknown"), data.get("ocr_text", ""))

        # Stats
        self._scans_today.setText(str(data.get("scans_today", 0)))
        self._files_processed.setText(f"{data.get('files_processed', 0):,}")

        rate = data.get("success_rate", 0)
        self._success_rate.setText(f"{rate:.1f}%")
        color = "#28a745" if rate >= 95 else "#ffc107" if rate >= 90 else "#dc3545"
        self._success_rate.setStyleSheet(f"font-weight: bold; color: {color};")

    def add_error(self, source: str, message: str) -> None:
        """Add an error to the log."""
        if not PYSIDE_AVAILABLE:
            return

        row = 0
        self._error_table.insertRow(row)
        self._error_table.setItem(row, 0, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self._error_table.setItem(row, 1, QTableWidgetItem(source))
        self._error_table.setItem(row, 2, QTableWidgetItem(message))

        # Keep only last 10
        while self._error_table.rowCount() > 10:
            self._error_table.removeRow(self._error_table.rowCount() - 1)

    def load_sample_data(self) -> None:
        """Load sample data for demonstration."""
        self.update_status({
            "api": "healthy", "api_text": "45ms",
            "db": "healthy", "db_text": "Connected",
            "queue": "healthy", "queue_text": "12 pending",
            "ml": "healthy", "ml_text": "2 models",
            "mip": "healthy", "mip_text": "v1.14",
            "ocr": "warning", "ocr_text": "Tesseract",
            "scans_today": 47,
            "files_processed": 15678,
            "success_rate": 98.7,
        })
        self.add_error("OCR", "Low confidence on invoice_scan.pdf")
        self.add_error("Scanner", "Timeout on large archive.zip")

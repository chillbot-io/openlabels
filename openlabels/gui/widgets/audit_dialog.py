"""
Audit Log Viewer Dialog.
"""

import csv
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QLabel,
    QComboBox,
    QDateEdit,
    QPushButton,
    QFrame,
    QFileDialog,
    QMessageBox,
    QAbstractItemView,
)
from PySide6.QtCore import Qt, QDate
from PySide6.QtGui import QColor

if TYPE_CHECKING:
    from openlabels.auth.models import Session
    from openlabels.vault.models import AuditEntry


class AuditLogDialog(QDialog):
    """Dialog for viewing and filtering the audit log."""

    def __init__(
        self,
        parent=None,
        session: "Session" = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Audit Log")
        self.setMinimumSize(900, 600)
        self.resize(1000, 700)

        self._session = session
        self._entries: List["AuditEntry"] = []
        self._filtered_entries: List["AuditEntry"] = []

        self._setup_ui()
        self._load_entries()

    def _setup_ui(self):
        """Setup the dialog UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Chain status header
        self._setup_status_header(layout)

        # Filters row
        self._setup_filters(layout)

        # Table
        self._setup_table(layout)

        # Bottom buttons
        self._setup_buttons(layout)

    def _setup_status_header(self, layout: QVBoxLayout):
        """Setup the chain integrity status header."""
        status_frame = QFrame()
        status_frame.setFrameShape(QFrame.StyledPanel)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(12, 8, 12, 8)

        self._chain_icon = QLabel()
        self._chain_status = QLabel("Verifying chain integrity...")
        self._chain_status.setStyleSheet("font-weight: bold;")

        self._entry_count = QLabel("")

        status_layout.addWidget(self._chain_icon)
        status_layout.addWidget(self._chain_status)
        status_layout.addStretch()
        status_layout.addWidget(self._entry_count)

        layout.addWidget(status_frame)

    def _setup_filters(self, layout: QVBoxLayout):
        """Setup filter controls."""
        filter_layout = QHBoxLayout()

        # Action filter
        filter_layout.addWidget(QLabel("Action:"))
        self._action_filter = QComboBox()
        self._action_filter.addItem("All Actions", None)
        self._action_filter.addItem("Vault Unlock", "vault_unlock")
        self._action_filter.addItem("Vault Lock", "vault_lock")
        self._action_filter.addItem("View Sensitive Data", "span_view")
        self._action_filter.addItem("Export Data", "span_export")
        self._action_filter.addItem("Scan Store", "scan_store")
        self._action_filter.addItem("Scan Delete", "scan_delete")
        self._action_filter.addItem("Classification Add", "classification_add")
        self._action_filter.addItem("User Reset", "user_reset")
        self._action_filter.addItem("Admin Audit View", "admin_audit_view")
        self._action_filter.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._action_filter)

        filter_layout.addSpacing(20)

        # User filter
        filter_layout.addWidget(QLabel("User:"))
        self._user_filter = QComboBox()
        self._user_filter.addItem("All Users", None)
        self._user_filter.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._user_filter)

        filter_layout.addSpacing(20)

        # Date range
        filter_layout.addWidget(QLabel("From:"))
        self._date_from = QDateEdit()
        self._date_from.setCalendarPopup(True)
        self._date_from.setDate(QDate.currentDate().addDays(-30))
        self._date_from.dateChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._date_from)

        filter_layout.addWidget(QLabel("To:"))
        self._date_to = QDateEdit()
        self._date_to.setCalendarPopup(True)
        self._date_to.setDate(QDate.currentDate())
        self._date_to.dateChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._date_to)

        filter_layout.addStretch()

        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._load_entries)
        filter_layout.addWidget(refresh_btn)

        layout.addLayout(filter_layout)

    def _setup_table(self, layout: QVBoxLayout):
        """Setup the audit entries table."""
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels([
            "Timestamp", "User", "Action", "Details", "Entry ID"
        ])

        # Configure table
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setSortingEnabled(True)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # Column widths
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Fixed)

        self._table.setColumnWidth(0, 150)  # Timestamp
        self._table.setColumnWidth(1, 120)  # User
        self._table.setColumnWidth(2, 140)  # Action
        self._table.setColumnWidth(4, 100)  # Entry ID

        layout.addWidget(self._table, stretch=1)

    def _setup_buttons(self, layout: QVBoxLayout):
        """Setup bottom buttons."""
        btn_layout = QHBoxLayout()

        # Export buttons
        export_csv_btn = QPushButton("Export CSV")
        export_csv_btn.clicked.connect(self._export_csv)
        btn_layout.addWidget(export_csv_btn)

        export_json_btn = QPushButton("Export JSON")
        export_json_btn.clicked.connect(self._export_json)
        btn_layout.addWidget(export_json_btn)

        btn_layout.addStretch()

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def _load_entries(self):
        """Load audit entries from the audit log."""
        if not self._session or not self._session.is_admin():
            self._chain_status.setText("Admin access required")
            self._chain_status.setStyleSheet("font-weight: bold; color: red;")
            return

        try:
            from openlabels.vault.audit import AuditLog
            from openlabels.auth.crypto import CryptoProvider
            from pathlib import Path

            data_dir = Path.home() / ".openlabels"
            audit = AuditLog(data_dir, CryptoProvider())

            # Verify chain integrity
            is_valid, message = audit.verify_chain(self._session._dek)

            if is_valid:
                self._chain_icon.setText("✓")
                self._chain_icon.setStyleSheet("color: green; font-size: 16px;")
                self._chain_status.setText(f"Chain Verified: {message}")
                self._chain_status.setStyleSheet("font-weight: bold; color: green;")
            else:
                self._chain_icon.setText("✗")
                self._chain_icon.setStyleSheet("color: red; font-size: 16px;")
                self._chain_status.setText(f"Chain Invalid: {message}")
                self._chain_status.setStyleSheet("font-weight: bold; color: red;")

            # Load all entries
            self._entries = list(audit.read(self._session._dek))

            # Get stats for entry count
            stats = audit.get_stats(self._session._dek)
            self._entry_count.setText(f"Total: {stats.get('total_entries', 0)} entries")

            # Populate user filter
            self._populate_user_filter()

            # Apply filters and display
            self._apply_filters()

        except Exception as e:
            self._chain_status.setText(f"Error loading audit log: {e}")
            self._chain_status.setStyleSheet("font-weight: bold; color: red;")

    def _populate_user_filter(self):
        """Populate user filter dropdown from loaded entries."""
        # Remember current selection
        current = self._user_filter.currentData()

        # Clear and repopulate
        self._user_filter.blockSignals(True)
        self._user_filter.clear()
        self._user_filter.addItem("All Users", None)

        # Get unique users
        users = set()
        for entry in self._entries:
            users.add(entry.user_id)

        for user_id in sorted(users):
            # Show truncated ID
            display = f"{user_id[:8]}..." if len(user_id) > 8 else user_id
            self._user_filter.addItem(display, user_id)

        # Restore selection if possible
        if current:
            idx = self._user_filter.findData(current)
            if idx >= 0:
                self._user_filter.setCurrentIndex(idx)

        self._user_filter.blockSignals(False)

    def _apply_filters(self):
        """Apply filters and update table."""
        action_value = self._action_filter.currentData()
        user_id = self._user_filter.currentData()
        date_from = self._date_from.date().toPython()
        date_to = self._date_to.date().toPython()

        self._filtered_entries = []

        for entry in self._entries:
            # Action filter
            if action_value and entry.action.value != action_value:
                continue

            # User filter
            if user_id and entry.user_id != user_id:
                continue

            # Date filter (inclusive on both ends)
            entry_date = entry.timestamp.date()
            if entry_date < date_from or entry_date > date_to:
                continue

            self._filtered_entries.append(entry)

        self._update_table()

    def _update_table(self):
        """Update table with filtered entries."""
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(self._filtered_entries))

        action_display = {
            "vault_unlock": "Vault Unlock",
            "vault_lock": "Vault Lock",
            "span_view": "View Sensitive",
            "span_export": "Export Data",
            "scan_store": "Scan Store",
            "scan_delete": "Scan Delete",
            "classification_add": "Add Classification",
            "user_reset": "User Reset",
            "admin_audit_view": "View Audit",
        }

        for row, entry in enumerate(self._filtered_entries):
            # Timestamp
            ts_item = QTableWidgetItem(entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"))
            ts_item.setData(Qt.UserRole, entry.timestamp)
            self._table.setItem(row, 0, ts_item)

            # User (truncated)
            user_display = f"{entry.user_id[:8]}..."
            self._table.setItem(row, 1, QTableWidgetItem(user_display))

            # Action
            action_text = action_display.get(entry.action.value, entry.action.value)
            action_item = QTableWidgetItem(action_text)

            # Color-code actions
            if entry.action.value in ("span_view", "span_export"):
                action_item.setForeground(QColor("#e67e22"))  # Orange for sensitive
            elif entry.action.value == "user_reset":
                action_item.setForeground(QColor("#e74c3c"))  # Red for admin action

            self._table.setItem(row, 2, action_item)

            # Details
            details = self._format_details(entry.details)
            self._table.setItem(row, 3, QTableWidgetItem(details))

            # Entry ID (truncated)
            id_display = f"{entry.id[:8]}..."
            self._table.setItem(row, 4, QTableWidgetItem(id_display))

        self._table.setSortingEnabled(True)

    def _format_details(self, details: dict) -> str:
        """Format details dict for display."""
        if not details:
            return ""

        parts = []
        for key, value in details.items():
            if key == "file_path":
                # Show just filename
                from pathlib import Path
                parts.append(f"file: {Path(value).name}")
            elif key == "entry_id":
                parts.append(f"entry: {value[:8]}...")
            elif key == "entity_counts":
                if value:
                    counts = ", ".join(f"{k}:{v}" for k, v in value.items())
                    parts.append(f"entities: {counts}")
            else:
                parts.append(f"{key}: {value}")

        return " | ".join(parts)

    def _export_csv(self):
        """Export filtered entries to CSV."""
        if not self._filtered_entries:
            QMessageBox.information(self, "No Data", "No entries to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Log", "audit_log.csv", "CSV Files (*.csv)"
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp", "User ID", "Action", "Details", "Entry ID", "Prev Hash"
                ])

                for entry in self._filtered_entries:
                    writer.writerow([
                        entry.timestamp.isoformat(),
                        entry.user_id,
                        entry.action.value,
                        json.dumps(entry.details),
                        entry.id,
                        entry.prev_hash,
                    ])

            QMessageBox.information(self, "Export Complete", f"Exported to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _export_json(self):
        """Export filtered entries to JSON."""
        if not self._filtered_entries:
            QMessageBox.information(self, "No Data", "No entries to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Log", "audit_log.json", "JSON Files (*.json)"
        )
        if not file_path:
            return

        try:
            export_data = {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "total_entries": len(self._filtered_entries),
                "entries": [entry.to_dict() for entry in self._filtered_entries],
            }

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)

            QMessageBox.information(self, "Export Complete", f"Exported to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

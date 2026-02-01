"""
Schedules management widget for OpenLabels GUI.

Provides interface for creating, viewing, editing, and deleting scan schedules.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView,
    QDialog,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QDialogButtonBox,
    QMessageBox,
    QLabel,
    QGroupBox,
    QSpinBox,
)


class ScheduleDialog(QDialog):
    """Dialog for creating/editing a scan schedule."""

    def __init__(self, parent=None, schedule: Optional[dict] = None, targets: list[dict] = None):
        super().__init__(parent)
        self.schedule = schedule
        self.targets = targets or []
        self.setWindowTitle("Edit Schedule" if schedule else "New Schedule")
        self.setMinimumWidth(500)
        self._setup_ui()

        if schedule:
            self._populate_from_schedule(schedule)

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Basic info
        basic_group = QGroupBox("Basic Information")
        basic_layout = QFormLayout(basic_group)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., Nightly Finance Scan")
        basic_layout.addRow("Name:", self.name_edit)

        self.target_combo = QComboBox()
        for target in self.targets:
            self.target_combo.addItem(target.get("name", ""), str(target.get("id", "")))
        basic_layout.addRow("Target:", self.target_combo)

        self.enabled_check = QCheckBox("Enabled")
        self.enabled_check.setChecked(True)
        basic_layout.addRow("", self.enabled_check)

        layout.addWidget(basic_group)

        # Schedule config
        schedule_group = QGroupBox("Schedule")
        schedule_layout = QFormLayout(schedule_group)

        self.schedule_type = QComboBox()
        self.schedule_type.addItems(["Daily", "Weekly", "Monthly", "Custom (Cron)"])
        self.schedule_type.currentTextChanged.connect(self._on_schedule_type_changed)
        schedule_layout.addRow("Frequency:", self.schedule_type)

        # Time
        self.hour_spin = QSpinBox()
        self.hour_spin.setRange(0, 23)
        self.hour_spin.setValue(2)  # Default: 2 AM

        self.minute_spin = QSpinBox()
        self.minute_spin.setRange(0, 59)
        self.minute_spin.setValue(0)

        time_layout = QHBoxLayout()
        time_layout.addWidget(self.hour_spin)
        time_layout.addWidget(QLabel(":"))
        time_layout.addWidget(self.minute_spin)
        time_layout.addStretch()
        schedule_layout.addRow("Time (24h):", time_layout)

        # Day of week (for weekly)
        self.day_combo = QComboBox()
        self.day_combo.addItems(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"])
        self.day_combo.setVisible(False)
        schedule_layout.addRow("Day:", self.day_combo)

        # Day of month (for monthly)
        self.day_of_month = QSpinBox()
        self.day_of_month.setRange(1, 28)
        self.day_of_month.setValue(1)
        self.day_of_month.setVisible(False)
        schedule_layout.addRow("Day of Month:", self.day_of_month)

        # Custom cron
        self.cron_edit = QLineEdit()
        self.cron_edit.setPlaceholderText("e.g., 0 2 * * * (2 AM daily)")
        self.cron_edit.setVisible(False)
        schedule_layout.addRow("Cron Expression:", self.cron_edit)

        layout.addWidget(schedule_group)

        # Store references for visibility toggling
        self._day_label = schedule_layout.labelForField(self.day_combo)
        self._dom_label = schedule_layout.labelForField(self.day_of_month)
        self._cron_label = schedule_layout.labelForField(self.cron_edit)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_schedule_type_changed(self, schedule_type: str):
        """Show/hide fields based on schedule type."""
        # Hide all optional fields first
        self.day_combo.setVisible(False)
        self.day_of_month.setVisible(False)
        self.cron_edit.setVisible(False)
        if self._day_label:
            self._day_label.setVisible(False)
        if self._dom_label:
            self._dom_label.setVisible(False)
        if self._cron_label:
            self._cron_label.setVisible(False)

        if schedule_type == "Weekly":
            self.day_combo.setVisible(True)
            if self._day_label:
                self._day_label.setVisible(True)
        elif schedule_type == "Monthly":
            self.day_of_month.setVisible(True)
            if self._dom_label:
                self._dom_label.setVisible(True)
        elif schedule_type == "Custom (Cron)":
            self.cron_edit.setVisible(True)
            if self._cron_label:
                self._cron_label.setVisible(True)

    def _populate_from_schedule(self, schedule: dict):
        """Populate fields from existing schedule."""
        self.name_edit.setText(schedule.get("name", ""))
        self.enabled_check.setChecked(schedule.get("enabled", True))

        # Find target in combo
        target_id = str(schedule.get("target_id", ""))
        for i in range(self.target_combo.count()):
            if self.target_combo.itemData(i) == target_id:
                self.target_combo.setCurrentIndex(i)
                break

        # Parse cron
        cron = schedule.get("cron", "")
        if cron:
            self._parse_cron(cron)

    def _parse_cron(self, cron: str):
        """Parse cron expression to set UI fields."""
        parts = cron.split()
        if len(parts) >= 5:
            try:
                self.minute_spin.setValue(int(parts[0]))
                self.hour_spin.setValue(int(parts[1]))

                # Determine schedule type
                if parts[2] != "*" and parts[3] == "*" and parts[4] == "*":
                    # Monthly
                    self.schedule_type.setCurrentText("Monthly")
                    self.day_of_month.setValue(int(parts[2]))
                elif parts[4] != "*":
                    # Weekly
                    self.schedule_type.setCurrentText("Weekly")
                    day_map = {"0": "Sunday", "1": "Monday", "2": "Tuesday",
                              "3": "Wednesday", "4": "Thursday", "5": "Friday", "6": "Saturday"}
                    self.day_combo.setCurrentText(day_map.get(parts[4], "Monday"))
                elif parts[2] == "*" and parts[3] == "*" and parts[4] == "*":
                    # Daily
                    self.schedule_type.setCurrentText("Daily")
                else:
                    # Custom
                    self.schedule_type.setCurrentText("Custom (Cron)")
                    self.cron_edit.setText(cron)
            except (ValueError, IndexError):
                self.schedule_type.setCurrentText("Custom (Cron)")
                self.cron_edit.setText(cron)

    def get_schedule_data(self) -> dict:
        """Get schedule data from form."""
        schedule_type = self.schedule_type.currentText()
        hour = self.hour_spin.value()
        minute = self.minute_spin.value()

        if schedule_type == "Daily":
            cron = f"{minute} {hour} * * *"
        elif schedule_type == "Weekly":
            day_map = {"Monday": "1", "Tuesday": "2", "Wednesday": "3",
                      "Thursday": "4", "Friday": "5", "Saturday": "6", "Sunday": "0"}
            day = day_map.get(self.day_combo.currentText(), "1")
            cron = f"{minute} {hour} * * {day}"
        elif schedule_type == "Monthly":
            day = self.day_of_month.value()
            cron = f"{minute} {hour} {day} * *"
        else:
            cron = self.cron_edit.text()

        return {
            "name": self.name_edit.text(),
            "target_id": self.target_combo.currentData(),
            "cron": cron,
            "enabled": self.enabled_check.isChecked(),
        }


class SchedulesWidget(QWidget):
    """Widget for managing scan schedules."""

    schedule_selected = Signal(str)  # Emits schedule ID
    run_now_requested = Signal(str)  # Emits schedule ID
    schedule_changed = Signal()  # Emits when schedules are created/updated/deleted

    def __init__(self, parent=None):
        super().__init__(parent)
        self._schedules: dict[str, dict] = {}
        self._targets: list[dict] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QHBoxLayout()
        header.addWidget(QLabel("<b>Scan Schedules</b>"))
        header.addStretch()

        self.add_btn = QPushButton("Add Schedule")
        self.add_btn.clicked.connect(self._on_add_schedule)
        header.addWidget(self.add_btn)

        layout.addLayout(header)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Name", "Target", "Schedule", "Next Run", "Enabled", "Actions"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)

        layout.addWidget(self.table)

    def set_targets(self, targets: list[dict]) -> None:
        """Set available targets for schedule creation."""
        self._targets = targets

    def load_schedules(self, schedules: list[dict]) -> None:
        """Load schedules into the table."""
        self.table.setRowCount(0)
        self._schedules.clear()

        for schedule in schedules:
            self._add_schedule_row(schedule)

    def _add_schedule_row(self, schedule: dict) -> None:
        """Add a schedule row to the table."""
        row = self.table.rowCount()
        self.table.insertRow(row)

        schedule_id = str(schedule.get("id", ""))
        self._schedules[schedule_id] = schedule

        # Name
        name_item = QTableWidgetItem(schedule.get("name", ""))
        name_item.setData(Qt.UserRole, schedule_id)
        self.table.setItem(row, 0, name_item)

        # Target
        target_name = schedule.get("target_name", "")
        if not target_name:
            # Try to find target name
            target_id = str(schedule.get("target_id", ""))
            for t in self._targets:
                if str(t.get("id", "")) == target_id:
                    target_name = t.get("name", "")
                    break
        target_item = QTableWidgetItem(target_name)
        self.table.setItem(row, 1, target_item)

        # Schedule (cron)
        cron = schedule.get("cron", "")
        cron_item = QTableWidgetItem(self._format_cron(cron))
        cron_item.setToolTip(f"Cron: {cron}")
        self.table.setItem(row, 2, cron_item)

        # Next run
        next_run = schedule.get("next_run_at", "")
        if next_run and isinstance(next_run, str):
            try:
                dt = datetime.fromisoformat(next_run.replace("Z", "+00:00"))
                next_run = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                pass
        next_run_item = QTableWidgetItem(str(next_run) if next_run else "-")
        self.table.setItem(row, 3, next_run_item)

        # Enabled
        enabled = "Yes" if schedule.get("enabled", True) else "No"
        enabled_item = QTableWidgetItem(enabled)
        self.table.setItem(row, 4, enabled_item)

        # Actions
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 2, 4, 2)
        actions_layout.setSpacing(4)

        run_btn = QPushButton("Run Now")
        run_btn.setFixedWidth(70)
        run_btn.clicked.connect(lambda: self.run_now_requested.emit(schedule_id))
        actions_layout.addWidget(run_btn)

        edit_btn = QPushButton("Edit")
        edit_btn.setFixedWidth(50)
        edit_btn.clicked.connect(lambda: self._on_edit_schedule(schedule_id))
        actions_layout.addWidget(edit_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.setFixedWidth(60)
        delete_btn.clicked.connect(lambda: self._on_delete_schedule(schedule_id))
        actions_layout.addWidget(delete_btn)

        actions_layout.addStretch()
        self.table.setCellWidget(row, 5, actions_widget)

    def _format_cron(self, cron: str) -> str:
        """Format cron expression for display."""
        if not cron:
            return "On demand"

        parts = cron.split()
        if len(parts) >= 5:
            minute, hour = parts[0], parts[1]
            day_of_month, month, day_of_week = parts[2], parts[3], parts[4]

            time_str = f"{hour}:{minute.zfill(2)}"

            if day_of_month == "*" and month == "*" and day_of_week == "*":
                return f"Daily at {time_str}"
            elif day_of_week != "*":
                days = {"0": "Sun", "1": "Mon", "2": "Tue", "3": "Wed",
                       "4": "Thu", "5": "Fri", "6": "Sat"}
                return f"Weekly on {days.get(day_of_week, day_of_week)} at {time_str}"
            elif day_of_month != "*":
                return f"Monthly on day {day_of_month} at {time_str}"

        return cron

    def _on_add_schedule(self) -> None:
        """Show dialog to add new schedule."""
        dialog = ScheduleDialog(self, targets=self._targets)
        if dialog.exec() == QDialog.Accepted:
            schedule_data = dialog.get_schedule_data()
            schedule_data["id"] = str(UUID(int=len(self._schedules)))
            self._add_schedule_row(schedule_data)
            self.schedule_changed.emit()

    def _on_edit_schedule(self, schedule_id: str) -> None:
        """Show dialog to edit schedule."""
        if schedule_id not in self._schedules:
            return

        schedule = self._schedules[schedule_id]
        dialog = ScheduleDialog(self, schedule=schedule, targets=self._targets)
        if dialog.exec() == QDialog.Accepted:
            updated_data = dialog.get_schedule_data()
            updated_data["id"] = schedule_id
            self._schedules[schedule_id] = updated_data
            self.load_schedules(list(self._schedules.values()))
            self.schedule_changed.emit()

    def _on_delete_schedule(self, schedule_id: str) -> None:
        """Confirm and delete schedule."""
        if schedule_id not in self._schedules:
            return

        schedule = self._schedules[schedule_id]
        result = QMessageBox.question(
            self,
            "Delete Schedule",
            f"Are you sure you want to delete schedule '{schedule.get('name')}'?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if result == QMessageBox.Yes:
            del self._schedules[schedule_id]
            self.load_schedules(list(self._schedules.values()))
            self.schedule_changed.emit()

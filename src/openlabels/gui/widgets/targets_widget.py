"""
Targets management widget for OpenLabels GUI.

Provides interface for creating, viewing, editing, and deleting scan targets.
"""

from __future__ import annotations

from uuid import UUID

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class TargetDialog(QDialog):
    """Dialog for creating/editing a scan target."""

    def __init__(self, parent=None, target: dict | None = None):
        super().__init__(parent)
        self.target = target
        self.setWindowTitle("Edit Target" if target else "New Target")
        self.setMinimumWidth(500)
        self._setup_ui()

        if target:
            self._populate_from_target(target)

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Basic info
        basic_group = QGroupBox("Basic Information")
        basic_layout = QFormLayout(basic_group)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., Finance Share, Marketing OneDrive")
        basic_layout.addRow("Name:", self.name_edit)

        self.adapter_combo = QComboBox()
        self.adapter_combo.addItems(["filesystem", "sharepoint", "onedrive", "s3", "gcs"])
        self.adapter_combo.currentTextChanged.connect(self._on_adapter_changed)
        basic_layout.addRow("Adapter:", self.adapter_combo)

        layout.addWidget(basic_group)

        # Adapter-specific config
        self.config_group = QGroupBox("Configuration")
        self.config_layout = QFormLayout(self.config_group)

        # Filesystem fields
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("e.g., /data/finance or \\\\server\\share")

        # SharePoint fields
        self.site_url_edit = QLineEdit()
        self.site_url_edit.setPlaceholderText("e.g., https://company.sharepoint.com/sites/Finance")

        # OneDrive fields
        self.user_email_edit = QLineEdit()
        self.user_email_edit.setPlaceholderText("e.g., user@company.com or 'all' for all users")

        # S3 fields
        self.s3_bucket_edit = QLineEdit()
        self.s3_bucket_edit.setPlaceholderText("e.g., my-data-bucket")
        self.s3_prefix_edit = QLineEdit()
        self.s3_prefix_edit.setPlaceholderText("e.g., documents/ (optional)")
        self.s3_region_edit = QLineEdit()
        self.s3_region_edit.setPlaceholderText("e.g., us-east-1")

        # GCS fields
        self.gcs_bucket_edit = QLineEdit()
        self.gcs_bucket_edit.setPlaceholderText("e.g., my-gcs-bucket")
        self.gcs_prefix_edit = QLineEdit()
        self.gcs_prefix_edit.setPlaceholderText("e.g., documents/ (optional)")
        self.gcs_project_edit = QLineEdit()
        self.gcs_project_edit.setPlaceholderText("e.g., my-gcp-project")

        layout.addWidget(self.config_group)

        # Initialize with filesystem fields
        self._on_adapter_changed("filesystem")

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_adapter_changed(self, adapter: str):
        """Update config fields based on adapter type."""
        # Clear existing fields
        while self.config_layout.rowCount() > 0:
            self.config_layout.removeRow(0)

        if adapter == "filesystem":
            self.config_layout.addRow("Path:", self.path_edit)
        elif adapter == "sharepoint":
            self.config_layout.addRow("Site URL:", self.site_url_edit)
        elif adapter == "onedrive":
            self.config_layout.addRow("User Email:", self.user_email_edit)
        elif adapter == "s3":
            self.config_layout.addRow("Bucket:", self.s3_bucket_edit)
            self.config_layout.addRow("Prefix:", self.s3_prefix_edit)
            self.config_layout.addRow("Region:", self.s3_region_edit)
        elif adapter == "gcs":
            self.config_layout.addRow("Bucket:", self.gcs_bucket_edit)
            self.config_layout.addRow("Prefix:", self.gcs_prefix_edit)
            self.config_layout.addRow("Project:", self.gcs_project_edit)

    def _populate_from_target(self, target: dict):
        """Populate fields from existing target."""
        self.name_edit.setText(target.get("name", ""))
        adapter = target.get("adapter", "filesystem")
        self.adapter_combo.setCurrentText(adapter)

        config = target.get("config", {})
        if adapter == "filesystem":
            self.path_edit.setText(config.get("path", ""))
        elif adapter == "sharepoint":
            self.site_url_edit.setText(config.get("site_url", ""))
        elif adapter == "onedrive":
            self.user_email_edit.setText(config.get("user_email", ""))
        elif adapter == "s3":
            self.s3_bucket_edit.setText(config.get("bucket", ""))
            self.s3_prefix_edit.setText(config.get("prefix", ""))
            self.s3_region_edit.setText(config.get("region", ""))
        elif adapter == "gcs":
            self.gcs_bucket_edit.setText(config.get("bucket", ""))
            self.gcs_prefix_edit.setText(config.get("prefix", ""))
            self.gcs_project_edit.setText(config.get("project", ""))

    def get_target_data(self) -> dict:
        """Get target data from form."""
        adapter = self.adapter_combo.currentText()
        config = {}

        if adapter == "filesystem":
            config["path"] = self.path_edit.text()
        elif adapter == "sharepoint":
            config["site_url"] = self.site_url_edit.text()
        elif adapter == "onedrive":
            config["user_email"] = self.user_email_edit.text()
        elif adapter == "s3":
            config["bucket"] = self.s3_bucket_edit.text()
            config["prefix"] = self.s3_prefix_edit.text()
            config["region"] = self.s3_region_edit.text()
        elif adapter == "gcs":
            config["bucket"] = self.gcs_bucket_edit.text()
            config["prefix"] = self.gcs_prefix_edit.text()
            config["project"] = self.gcs_project_edit.text()

        return {
            "name": self.name_edit.text(),
            "adapter": adapter,
            "config": config,
        }


class TargetsWidget(QWidget):
    """Widget for managing scan targets."""

    target_selected = Signal(str)  # Emits target ID
    scan_requested = Signal(str)  # Emits target ID
    target_changed = Signal()  # Emits when targets are created/updated/deleted

    def __init__(self, parent=None):
        super().__init__(parent)
        self._targets: dict[str, dict] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QHBoxLayout()
        header.addWidget(QLabel("<b>Scan Targets</b>"))
        header.addStretch()

        self.add_btn = QPushButton("Add Target")
        self.add_btn.clicked.connect(self._on_add_target)
        header.addWidget(self.add_btn)

        layout.addLayout(header)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Name", "Adapter", "Path/URL", "Enabled", "Actions"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)

        layout.addWidget(self.table)

    def load_targets(self, targets: list[dict]) -> None:
        """Load targets into the table."""
        self.table.setRowCount(0)
        self._targets.clear()

        for target in targets:
            self._add_target_row(target)

    def _add_target_row(self, target: dict) -> None:
        """Add a target row to the table."""
        row = self.table.rowCount()
        self.table.insertRow(row)

        target_id = str(target.get("id", ""))
        self._targets[target_id] = target

        # Name
        name_item = QTableWidgetItem(target.get("name", ""))
        name_item.setData(Qt.UserRole, target_id)
        self.table.setItem(row, 0, name_item)

        # Adapter
        adapter = target.get("adapter", "")
        adapter_item = QTableWidgetItem(adapter)
        self.table.setItem(row, 1, adapter_item)

        # Path/URL/Bucket
        config = target.get("config", {})
        bucket = config.get("bucket", "")
        path = config.get("path") or config.get("site_url") or config.get("user_email") or (
            f"s3://{bucket}/{config.get('prefix', '')}" if adapter == "s3" and bucket else
            f"gs://{bucket}/{config.get('prefix', '')}" if adapter == "gcs" and bucket else
            ""
        )
        path_item = QTableWidgetItem(path)
        self.table.setItem(row, 2, path_item)

        # Enabled
        enabled = "Yes" if target.get("enabled", True) else "No"
        enabled_item = QTableWidgetItem(enabled)
        self.table.setItem(row, 3, enabled_item)

        # Actions
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 2, 4, 2)
        actions_layout.setSpacing(4)

        scan_btn = QPushButton("Scan")
        scan_btn.setFixedWidth(60)
        scan_btn.clicked.connect(lambda: self.scan_requested.emit(target_id))
        actions_layout.addWidget(scan_btn)

        edit_btn = QPushButton("Edit")
        edit_btn.setFixedWidth(50)
        edit_btn.clicked.connect(lambda: self._on_edit_target(target_id))
        actions_layout.addWidget(edit_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.setFixedWidth(60)
        delete_btn.clicked.connect(lambda: self._on_delete_target(target_id))
        actions_layout.addWidget(delete_btn)

        actions_layout.addStretch()
        self.table.setCellWidget(row, 4, actions_widget)

    def _on_add_target(self) -> None:
        """Show dialog to add new target."""
        dialog = TargetDialog(self)
        if dialog.exec() == QDialog.Accepted:
            target_data = dialog.get_target_data()
            # Emit signal for parent to handle API call
            # For now, add locally for demo
            target_data["id"] = str(UUID(int=len(self._targets)))
            target_data["enabled"] = True
            self._add_target_row(target_data)
            self.target_changed.emit()

    def _on_edit_target(self, target_id: str) -> None:
        """Show dialog to edit target."""
        if target_id not in self._targets:
            return

        target = self._targets[target_id]
        dialog = TargetDialog(self, target)
        if dialog.exec() == QDialog.Accepted:
            updated_data = dialog.get_target_data()
            updated_data["id"] = target_id
            updated_data["enabled"] = target.get("enabled", True)
            self._targets[target_id] = updated_data
            # Refresh table
            self.load_targets(list(self._targets.values()))
            self.target_changed.emit()

    def _on_delete_target(self, target_id: str) -> None:
        """Confirm and delete target."""
        if target_id not in self._targets:
            return

        target = self._targets[target_id]
        result = QMessageBox.question(
            self,
            "Delete Target",
            f"Are you sure you want to delete target '{target.get('name')}'?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if result == QMessageBox.Yes:
            del self._targets[target_id]
            self.load_targets(list(self._targets.values()))
            self.target_changed.emit()

    def _on_row_double_clicked(self, row: int, col: int) -> None:
        """Handle row double click."""
        item = self.table.item(row, 0)
        if item:
            target_id = item.data(Qt.UserRole)
            self.target_selected.emit(target_id)

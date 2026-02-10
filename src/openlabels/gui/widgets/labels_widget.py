"""
Labels management widget for OpenLabels GUI.

Provides interface for viewing sensitivity labels and managing label rules.
"""

from uuid import UUID

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


class LabelRuleDialog(QDialog):
    """Dialog for creating/editing a label rule."""

    def __init__(self, parent=None, rule: dict | None = None, labels: list[dict] = None):
        super().__init__(parent)
        self.rule = rule
        self.labels = labels or []
        self.setWindowTitle("Edit Rule" if rule else "New Rule")
        self.setMinimumWidth(450)
        self._setup_ui()

        if rule:
            self._populate_from_rule(rule)

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Rule type
        form = QFormLayout()

        self.rule_type_combo = QComboBox()
        self.rule_type_combo.addItems(["risk_tier", "entity_type"])
        self.rule_type_combo.currentTextChanged.connect(self._on_rule_type_changed)
        form.addRow("Rule Type:", self.rule_type_combo)

        # Match value
        self.match_value_combo = QComboBox()
        self.match_value_combo.setEditable(True)
        self._update_match_values("risk_tier")
        form.addRow("Match Value:", self.match_value_combo)

        # Target label
        self.label_combo = QComboBox()
        for label in self.labels:
            self.label_combo.addItem(label.get("name", ""), label.get("id", ""))
        form.addRow("Apply Label:", self.label_combo)

        # Priority
        self.priority_spin = QSpinBox()
        self.priority_spin.setRange(0, 100)
        self.priority_spin.setValue(50)
        self.priority_spin.setToolTip("Higher priority rules are evaluated first")
        form.addRow("Priority:", self.priority_spin)

        layout.addLayout(form)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_rule_type_changed(self, rule_type: str):
        """Update match value options based on rule type."""
        self._update_match_values(rule_type)

    def _update_match_values(self, rule_type: str):
        """Update the match value combo based on rule type."""
        self.match_value_combo.clear()
        if rule_type == "risk_tier":
            self.match_value_combo.addItems(["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"])
        elif rule_type == "entity_type":
            # Common entity types
            self.match_value_combo.addItems([
                "SSN", "CREDIT_CARD", "EMAIL", "PHONE", "NPI", "DEA_NUMBER",
                "IBAN", "CUSIP", "ISIN", "AWS_ACCESS_KEY", "PRIVATE_KEY",
                "JWT", "PASSWORD", "MRN", "ICD10", "DATE_OF_BIRTH",
            ])

    def _populate_from_rule(self, rule: dict):
        """Populate fields from existing rule."""
        self.rule_type_combo.setCurrentText(rule.get("rule_type", "risk_tier"))
        self.match_value_combo.setCurrentText(rule.get("match_value", ""))
        self.priority_spin.setValue(rule.get("priority", 50))

        # Find label in combo
        label_id = rule.get("label_id", "")
        for i in range(self.label_combo.count()):
            if self.label_combo.itemData(i) == label_id:
                self.label_combo.setCurrentIndex(i)
                break

    def get_rule_data(self) -> dict:
        """Get rule data from form."""
        return {
            "rule_type": self.rule_type_combo.currentText(),
            "match_value": self.match_value_combo.currentText(),
            "label_id": self.label_combo.currentData(),
            "label_name": self.label_combo.currentText(),
            "priority": self.priority_spin.value(),
        }


class LabelsWidget(QWidget):
    """Widget for managing sensitivity labels and rules."""

    sync_labels_requested = Signal()  # Request to sync labels from M365
    apply_label_requested = Signal(str, str)  # result_id, label_id
    label_rule_changed = Signal()  # Emits when rules are created/updated/deleted

    def __init__(self, parent=None):
        super().__init__(parent)
        self._labels: dict[str, dict] = {}
        self._rules: dict[str, dict] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Tab widget for labels vs rules
        self.tabs = QTabWidget()

        # Labels tab
        labels_tab = QWidget()
        labels_layout = QVBoxLayout(labels_tab)

        # Labels header
        labels_header = QHBoxLayout()
        labels_header.addWidget(QLabel("<b>Sensitivity Labels</b>"))
        labels_header.addStretch()

        self.sync_btn = QPushButton("Sync from M365")
        self.sync_btn.clicked.connect(self.sync_labels_requested.emit)
        labels_header.addWidget(self.sync_btn)

        labels_layout.addLayout(labels_header)

        # Labels table
        self.labels_table = QTableWidget()
        self.labels_table.setColumnCount(5)
        self.labels_table.setHorizontalHeaderLabels(["Name", "Description", "Priority", "Color", "ID"])
        self.labels_table.horizontalHeader().setStretchLastSection(True)
        self.labels_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.labels_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.labels_table.setSelectionBehavior(QTableWidget.SelectRows)
        labels_layout.addWidget(self.labels_table)

        self.tabs.addTab(labels_tab, "Labels")

        # Rules tab
        rules_tab = QWidget()
        rules_layout = QVBoxLayout(rules_tab)

        # Rules header
        rules_header = QHBoxLayout()
        rules_header.addWidget(QLabel("<b>Auto-Label Rules</b>"))
        rules_header.addStretch()

        self.add_rule_btn = QPushButton("Add Rule")
        self.add_rule_btn.clicked.connect(self._on_add_rule)
        rules_header.addWidget(self.add_rule_btn)

        rules_layout.addLayout(rules_header)

        # Rules description
        desc = QLabel(
            "Rules determine which sensitivity label to apply based on detected risk tier or entity types. "
            "Higher priority rules are evaluated first."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: gray; margin-bottom: 8px;")
        rules_layout.addWidget(desc)

        # Rules table
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels(["Rule Type", "Match Value", "Apply Label", "Priority", "Actions"])
        self.rules_table.horizontalHeader().setStretchLastSection(True)
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.rules_table.setSelectionBehavior(QTableWidget.SelectRows)
        rules_layout.addWidget(self.rules_table)

        self.tabs.addTab(rules_tab, "Rules")

        layout.addWidget(self.tabs)

    def load_labels(self, labels: list[dict]) -> None:
        """Load labels into the table."""
        self.labels_table.setRowCount(0)
        self._labels.clear()

        for label in labels:
            self._add_label_row(label)

    def _add_label_row(self, label: dict) -> None:
        """Add a label row to the table."""
        row = self.labels_table.rowCount()
        self.labels_table.insertRow(row)

        label_id = str(label.get("id", ""))
        self._labels[label_id] = label

        # Name
        name_item = QTableWidgetItem(label.get("name", ""))
        name_item.setData(Qt.UserRole, label_id)
        self.labels_table.setItem(row, 0, name_item)

        # Description
        desc_item = QTableWidgetItem(label.get("description", ""))
        self.labels_table.setItem(row, 1, desc_item)

        # Priority
        priority_item = QTableWidgetItem(str(label.get("priority", 0)))
        self.labels_table.setItem(row, 2, priority_item)

        # Color
        color = label.get("color", "")
        color_item = QTableWidgetItem(color)
        if color and color.startswith("#"):
            color_item.setBackground(Qt.GlobalColor(Qt.white))  # Will be set by stylesheet
        self.labels_table.setItem(row, 3, color_item)

        # ID
        id_item = QTableWidgetItem(label_id[:8] + "..." if len(label_id) > 8 else label_id)
        id_item.setToolTip(label_id)
        self.labels_table.setItem(row, 4, id_item)

    def load_rules(self, rules: list[dict]) -> None:
        """Load rules into the table."""
        self.rules_table.setRowCount(0)
        self._rules.clear()

        for rule in rules:
            self._add_rule_row(rule)

    def _add_rule_row(self, rule: dict) -> None:
        """Add a rule row to the table."""
        row = self.rules_table.rowCount()
        self.rules_table.insertRow(row)

        rule_id = str(rule.get("id", ""))
        self._rules[rule_id] = rule

        # Rule type
        type_item = QTableWidgetItem(rule.get("rule_type", ""))
        type_item.setData(Qt.UserRole, rule_id)
        self.rules_table.setItem(row, 0, type_item)

        # Match value
        match_item = QTableWidgetItem(rule.get("match_value", ""))
        self.rules_table.setItem(row, 1, match_item)

        # Apply label
        label_name = rule.get("label_name", "")
        if not label_name:
            label_id = rule.get("label_id", "")
            if label_id in self._labels:
                label_name = self._labels[label_id].get("name", "")
        label_item = QTableWidgetItem(label_name)
        self.rules_table.setItem(row, 2, label_item)

        # Priority
        priority_item = QTableWidgetItem(str(rule.get("priority", 0)))
        self.rules_table.setItem(row, 3, priority_item)

        # Actions
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 2, 4, 2)
        actions_layout.setSpacing(4)

        edit_btn = QPushButton("Edit")
        edit_btn.setFixedWidth(50)
        edit_btn.clicked.connect(lambda: self._on_edit_rule(rule_id))
        actions_layout.addWidget(edit_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.setFixedWidth(60)
        delete_btn.clicked.connect(lambda: self._on_delete_rule(rule_id))
        actions_layout.addWidget(delete_btn)

        actions_layout.addStretch()
        self.rules_table.setCellWidget(row, 4, actions_widget)

    def _on_add_rule(self) -> None:
        """Show dialog to add new rule."""
        dialog = LabelRuleDialog(self, labels=list(self._labels.values()))
        if dialog.exec() == QDialog.Accepted:
            rule_data = dialog.get_rule_data()
            rule_data["id"] = str(UUID(int=len(self._rules)))
            self._add_rule_row(rule_data)
            self.label_rule_changed.emit()

    def _on_edit_rule(self, rule_id: str) -> None:
        """Show dialog to edit rule."""
        if rule_id not in self._rules:
            return

        rule = self._rules[rule_id]
        dialog = LabelRuleDialog(self, rule=rule, labels=list(self._labels.values()))
        if dialog.exec() == QDialog.Accepted:
            updated_data = dialog.get_rule_data()
            updated_data["id"] = rule_id
            self._rules[rule_id] = updated_data
            self.load_rules(list(self._rules.values()))
            self.label_rule_changed.emit()

    def _on_delete_rule(self, rule_id: str) -> None:
        """Confirm and delete rule."""
        if rule_id not in self._rules:
            return

        rule = self._rules[rule_id]
        result = QMessageBox.question(
            self,
            "Delete Rule",
            f"Are you sure you want to delete this rule?\n\n"
            f"Type: {rule.get('rule_type')}\n"
            f"Match: {rule.get('match_value')}\n"
            f"Label: {rule.get('label_name')}",
            QMessageBox.Yes | QMessageBox.No,
        )

        if result == QMessageBox.Yes:
            del self._rules[rule_id]
            self.load_rules(list(self._rules.values()))
            self.label_rule_changed.emit()

    def get_labels(self) -> list[dict]:
        """Get all loaded labels."""
        return list(self._labels.values())

    def get_rules(self) -> list[dict]:
        """Get all loaded rules."""
        return list(self._rules.values())

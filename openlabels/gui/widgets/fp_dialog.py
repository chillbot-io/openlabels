"""
False Positive Dialog.

Allows users to report detected entities as false positives and add them
to an allowlist for future scans.
"""

from pathlib import Path
from typing import Dict, Any, List

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QCheckBox,
    QGroupBox,
    QRadioButton,
    QButtonGroup,
)
from PySide6.QtCore import Qt


class FalsePositiveDialog(QDialog):
    """Dialog for reporting false positive detections."""

    def __init__(
        self,
        parent,
        file_path: str,
        spans: List[Dict[str, Any]],
        entities: Dict[str, int],
    ):
        super().__init__(parent)
        self._file_path = file_path
        self._spans = spans
        self._entities = entities
        self._selected_items: List[Dict[str, Any]] = []

        self.setWindowTitle("Report False Positive")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Header
        header = QLabel(f"File: {Path(self._file_path).name}")
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header)

        info = QLabel(
            "Select detected items that are false positives.\n"
            "They will be added to your allowlist and ignored in future scans."
        )
        info.setStyleSheet("color: #8b949e; margin-bottom: 8px;")
        info.setWordWrap(True)
        layout.addWidget(info)

        # List of detected entities
        group = QGroupBox("Detected Entities")
        group_layout = QVBoxLayout(group)

        self._list = QListWidget()
        self._list.setSelectionMode(QListWidget.MultiSelection)

        # Add spans (actual detected text)
        if self._spans:
            for span in self._spans:
                text = span.get("text", "")
                entity_type = span.get("type", "UNKNOWN")
                context = span.get("context", "")

                if text:
                    display = f"[{entity_type}] {text}"
                    if context:
                        display += f"  (in: ...{context}...)"

                    item = QListWidgetItem(display)
                    item.setData(Qt.UserRole, {
                        "text": text,
                        "type": entity_type,
                        "context": context,
                    })
                    self._list.addItem(item)

        # If no spans but we have entity counts, show types
        elif self._entities:
            for entity_type, count in self._entities.items():
                display = f"[{entity_type}] ({count} instances)"
                item = QListWidgetItem(display)
                item.setData(Qt.UserRole, {
                    "text": None,
                    "type": entity_type,
                    "count": count,
                })
                self._list.addItem(item)

        group_layout.addWidget(self._list)
        layout.addWidget(group)

        # Allowlist type selection
        type_group = QGroupBox("Add to Allowlist as")
        type_layout = QVBoxLayout(type_group)

        self._type_group = QButtonGroup(self)

        self._exact_radio = QRadioButton("Exact text match (recommended)")
        self._exact_radio.setChecked(True)
        self._type_group.addButton(self._exact_radio, 0)
        type_layout.addWidget(self._exact_radio)

        self._pattern_radio = QRadioButton("Pattern (will match similar text)")
        self._type_group.addButton(self._pattern_radio, 1)
        type_layout.addWidget(self._pattern_radio)

        layout.addWidget(type_group)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        add_btn = QPushButton("Add to Allowlist")
        add_btn.setProperty("primary", True)
        add_btn.clicked.connect(self._on_add)
        btn_layout.addWidget(add_btn)

        layout.addLayout(btn_layout)

    def _on_add(self):
        """Handle add button click."""
        selected = self._list.selectedItems()
        if not selected:
            return

        use_pattern = self._pattern_radio.isChecked()

        for item in selected:
            data = item.data(Qt.UserRole)
            text = data.get("text")
            entity_type = data.get("type")

            if text:
                entry = {
                    "value": text,
                    "type": "pattern" if use_pattern else "exact",
                    "entity_type": entity_type,
                }
                self._selected_items.append(entry)

        self.accept()

    def get_allowlist_entries(self) -> List[Dict[str, Any]]:
        """Get the list of entries to add to allowlist."""
        return self._selected_items

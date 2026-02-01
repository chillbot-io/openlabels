"""
File detail context card widget for OpenLabels GUI.

Displays detailed information about a selected scan result including:
- Risk score breakdown
- Entity summary
- Exposure analysis
- Label status and recommendations
"""

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QGroupBox,
    QFormLayout,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QScrollArea,
    QFrame,
    QComboBox,
)


class RiskGauge(QWidget):
    """Visual risk score gauge."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self._tier = "MINIMAL"
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Score bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(True)
        self.progress.setMinimumHeight(30)
        layout.addWidget(self.progress)

        # Tier label
        self.tier_label = QLabel()
        self.tier_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.tier_label)

    def set_score(self, score: int, tier: str):
        """Set the risk score and tier."""
        self._score = score
        self._tier = tier

        self.progress.setValue(score)
        self.progress.setFormat(f"{score} / 100")

        tier_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "MINIMAL": "#6c757d",
        }
        color = tier_colors.get(tier, "#6c757d")

        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {color};
                border-radius: 5px;
                text-align: center;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)

        self.tier_label.setText(f"<b style='color: {color};'>{tier}</b>")


class FileDetailWidget(QWidget):
    """
    Context card showing detailed information about a scan result.

    Matches the spec from the architecture doc:
    - Risk score with breakdown
    - Entity summary table
    - Exposure analysis
    - Label status and actions
    """

    apply_label_requested = Signal(str, str)  # result_id, label_id
    close_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._result: Optional[dict] = None
        self._available_labels: list[dict] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Header with close button
        header = QHBoxLayout()
        self.file_name_label = QLabel("<b>No file selected</b>")
        self.file_name_label.setStyleSheet("font-size: 14pt;")
        header.addWidget(self.file_name_label)
        header.addStretch()

        close_btn = QPushButton("x")
        close_btn.setFixedSize(24, 24)
        close_btn.clicked.connect(self.close_requested.emit)
        header.addWidget(close_btn)

        layout.addLayout(header)

        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        content_layout = QVBoxLayout(content)

        # Risk Score Section
        risk_group = QGroupBox("Risk Score")
        risk_layout = QVBoxLayout(risk_group)

        self.risk_gauge = RiskGauge()
        risk_layout.addWidget(self.risk_gauge)

        content_layout.addWidget(risk_group)

        # Score Breakdown Section
        breakdown_group = QGroupBox("Score Breakdown")
        self.breakdown_layout = QFormLayout(breakdown_group)
        content_layout.addWidget(breakdown_group)

        # Entities Section
        entities_group = QGroupBox("Sensitive Information Types (SITs)")
        entities_layout = QVBoxLayout(entities_group)

        self.entities_table = QTableWidget()
        self.entities_table.setColumnCount(4)
        self.entities_table.setHorizontalHeaderLabels(["Type", "Count", "Confidence", "Sample"])
        self.entities_table.horizontalHeader().setStretchLastSection(True)
        self.entities_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.entities_table.setMaximumHeight(200)
        entities_layout.addWidget(self.entities_table)

        content_layout.addWidget(entities_group)

        # Exposure Section
        exposure_group = QGroupBox("Exposure & Access")
        self.exposure_layout = QFormLayout(exposure_group)
        content_layout.addWidget(exposure_group)

        # Labeling Section
        label_group = QGroupBox("Labeling")
        label_layout = QVBoxLayout(label_group)

        label_info = QFormLayout()
        self.current_label = QLabel("-")
        label_info.addRow("Current Label:", self.current_label)

        self.recommended_label = QLabel("-")
        label_info.addRow("Recommended Label:", self.recommended_label)

        self.recommendation_reason = QLabel("-")
        self.recommendation_reason.setWordWrap(True)
        label_info.addRow("Reason:", self.recommendation_reason)

        label_layout.addLayout(label_info)

        # Label actions
        actions_layout = QHBoxLayout()

        self.apply_recommended_btn = QPushButton("Apply Recommended Label")
        self.apply_recommended_btn.clicked.connect(self._on_apply_recommended)
        actions_layout.addWidget(self.apply_recommended_btn)

        self.label_combo = QComboBox()
        self.label_combo.setMinimumWidth(150)
        actions_layout.addWidget(self.label_combo)

        self.apply_selected_btn = QPushButton("Apply")
        self.apply_selected_btn.clicked.connect(self._on_apply_selected)
        actions_layout.addWidget(self.apply_selected_btn)

        actions_layout.addStretch()
        label_layout.addLayout(actions_layout)

        content_layout.addWidget(label_group)

        # File Info Section
        info_group = QGroupBox("File Information")
        self.info_layout = QFormLayout(info_group)
        content_layout.addWidget(info_group)

        content_layout.addStretch()

        scroll.setWidget(content)
        layout.addWidget(scroll)

    def set_available_labels(self, labels: list[dict]) -> None:
        """Set available labels for the combo box."""
        self._available_labels = labels
        self.label_combo.clear()
        self.label_combo.addItem("Choose label...", "")
        for label in labels:
            self.label_combo.addItem(label.get("name", ""), label.get("id", ""))

    def show_result(self, result: dict) -> None:
        """Display a scan result."""
        self._result = result

        # Header
        file_name = result.get("file_name", "Unknown")
        self.file_name_label.setText(f"<b>{file_name}</b>")

        # Risk score
        risk_score = result.get("risk_score", 0)
        risk_tier = result.get("risk_tier", "MINIMAL")
        self.risk_gauge.set_score(risk_score, risk_tier)

        # Score breakdown
        self._clear_form(self.breakdown_layout)
        entity_counts = result.get("entity_counts", {})
        total_entities = result.get("total_entities", 0)
        exposure = result.get("exposure_level", "PRIVATE")

        self.breakdown_layout.addRow(
            "Entity severity:",
            QLabel(f"+{len(entity_counts)} types, {total_entities} total")
        )
        self.breakdown_layout.addRow(
            "Exposure level:",
            QLabel(f"{exposure}")
        )
        if result.get("content_score"):
            self.breakdown_layout.addRow(
                "Content score:",
                QLabel(f"{result.get('content_score'):.1f}")
            )

        # Entities table
        self.entities_table.setRowCount(0)
        findings = result.get("findings", [])

        # Group findings by type
        type_counts: dict[str, dict] = {}
        for finding in findings:
            entity_type = finding.get("entity_type", "UNKNOWN")
            if entity_type not in type_counts:
                type_counts[entity_type] = {
                    "count": 0,
                    "confidences": [],
                    "sample": finding.get("value_preview", ""),
                }
            type_counts[entity_type]["count"] += 1
            type_counts[entity_type]["confidences"].append(finding.get("confidence", 0))

        # Also add from entity_counts if no findings
        if not type_counts:
            for entity_type, count in entity_counts.items():
                type_counts[entity_type] = {
                    "count": count,
                    "confidences": [],
                    "sample": "***",
                }

        for entity_type, data in sorted(type_counts.items(), key=lambda x: -x[1]["count"]):
            row = self.entities_table.rowCount()
            self.entities_table.insertRow(row)

            self.entities_table.setItem(row, 0, QTableWidgetItem(entity_type))
            self.entities_table.setItem(row, 1, QTableWidgetItem(str(data["count"])))

            avg_conf = sum(data["confidences"]) / len(data["confidences"]) if data["confidences"] else 0
            conf_label = "HIGH" if avg_conf > 0.8 else "MEDIUM" if avg_conf > 0.5 else "LOW"
            self.entities_table.setItem(row, 2, QTableWidgetItem(conf_label))

            self.entities_table.setItem(row, 3, QTableWidgetItem(data["sample"]))

        # Exposure
        self._clear_form(self.exposure_layout)
        self.exposure_layout.addRow("Exposure Level:", QLabel(exposure))
        if result.get("owner"):
            self.exposure_layout.addRow("Owner:", QLabel(result.get("owner")))
        self.exposure_layout.addRow("Location:", QLabel(result.get("file_path", "")))

        # Labeling
        current = result.get("current_label_name")
        self.current_label.setText(current or "None")

        recommended = result.get("recommended_label_name")
        if not recommended:
            # Generate recommendation based on risk tier
            tier_map = {
                "CRITICAL": "Highly Confidential",
                "HIGH": "Confidential",
                "MEDIUM": "Internal",
            }
            recommended = tier_map.get(risk_tier)

        if recommended:
            self.recommended_label.setText(f"<span style='color: red;'>🔴</span> {recommended}")
            self.recommendation_reason.setText(f"Contains {total_entities} sensitive entities in {len(entity_counts)} types")
            self.apply_recommended_btn.setEnabled(True)
        else:
            self.recommended_label.setText("-")
            self.recommendation_reason.setText("No label needed for this risk level")
            self.apply_recommended_btn.setEnabled(False)

        # File info
        self._clear_form(self.info_layout)
        self.info_layout.addRow("Path:", QLabel(result.get("file_path", "")))
        if result.get("file_size"):
            size_mb = result.get("file_size", 0) / (1024 * 1024)
            self.info_layout.addRow("Size:", QLabel(f"{size_mb:.2f} MB"))
        if result.get("file_modified"):
            self.info_layout.addRow("Modified:", QLabel(str(result.get("file_modified"))))
        if result.get("content_hash"):
            hash_short = result.get("content_hash", "")[:16] + "..."
            self.info_layout.addRow("Hash:", QLabel(hash_short))

    def _clear_form(self, layout: QFormLayout) -> None:
        """Clear all rows from a form layout."""
        while layout.rowCount() > 0:
            layout.removeRow(0)

    def _on_apply_recommended(self) -> None:
        """Apply the recommended label."""
        if not self._result:
            return

        result_id = str(self._result.get("id", ""))
        recommended = self._result.get("recommended_label_id")

        if not recommended:
            # Find label by name
            recommended_name = self.recommended_label.text().replace("🔴", "").strip()
            for label in self._available_labels:
                if label.get("name") == recommended_name:
                    recommended = label.get("id")
                    break

        if recommended:
            self.apply_label_requested.emit(result_id, recommended)

    def _on_apply_selected(self) -> None:
        """Apply the selected label from combo box."""
        if not self._result:
            return

        result_id = str(self._result.get("id", ""))
        label_id = self.label_combo.currentData()

        if label_id:
            self.apply_label_requested.emit(result_id, label_id)

    def clear(self) -> None:
        """Clear the detail view."""
        self._result = None
        self.file_name_label.setText("<b>No file selected</b>")
        self.risk_gauge.set_score(0, "MINIMAL")
        self.entities_table.setRowCount(0)
        self._clear_form(self.breakdown_layout)
        self._clear_form(self.exposure_layout)
        self._clear_form(self.info_layout)
        self.current_label.setText("-")
        self.recommended_label.setText("-")
        self.recommendation_reason.setText("-")

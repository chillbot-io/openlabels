"""
File detail dialog - the OpenLabels explanation view.

Shows:
- The portable OpenLabels label (ID, hash, entities)
- File metadata (path, size, modified date)
- Risk score and tier visualization
- Classification sources (Macie, Purview, OpenLabels scanner, etc.)
- Detected entities (counts visible, actual text requires vault unlock)
- User-applied labels
- Actions (embed label, quarantine, rescan)
"""

from typing import Optional, TYPE_CHECKING
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QWidget,
    QGroupBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QLineEdit,
    QTabWidget,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from openlabels.gui.style import get_stylesheet, COLORS, get_tier_color

if TYPE_CHECKING:
    from openlabels.auth.models import Session
    from openlabels.vault.models import FileClassification, ClassificationSource


class FileDetailDialog(QDialog):
    """
    Detailed view of a file's OpenLabels classification.

    Shows the portable label format prominently, along with metadata
    and classification sources. Sensitive text requires vault unlock.
    """

    quarantine_requested = Signal(str)  # file_path
    label_changed = Signal(str, list)   # file_path, labels
    rescan_requested = Signal(str)      # file_path
    embed_requested = Signal(str)       # file_path

    def __init__(
        self,
        parent: Optional[QWidget],
        file_path: str,
        classification: Optional["FileClassification"] = None,
        session: Optional["Session"] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("OpenLabels - File Details")
        self.setMinimumSize(750, 650)
        self.setModal(True)

        # Apply stylesheet
        self.setStyleSheet(get_stylesheet())

        self._file_path = file_path
        self._classification = classification
        self._session = session
        self._vault_unlocked = False

        self._setup_ui()
        self._populate_data()

    def _setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(16)

        # File info section
        self._file_info_group = self._create_file_info_section()
        content_layout.addWidget(self._file_info_group)

        # Risk summary section
        self._risk_group = self._create_risk_section()
        content_layout.addWidget(self._risk_group)

        # Classification sources section
        self._sources_group = self._create_sources_section()
        content_layout.addWidget(self._sources_group)

        # Sensitive content section (vault-protected)
        self._content_group = self._create_content_section()
        content_layout.addWidget(self._content_group)

        # Labels section
        self._labels_group = self._create_labels_section()
        content_layout.addWidget(self._labels_group)

        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)

        # Action buttons
        actions_layout = QHBoxLayout()

        self._quarantine_btn = QPushButton("Quarantine")
        self._quarantine_btn.setStyleSheet("color: #dc3545;")
        self._quarantine_btn.clicked.connect(self._on_quarantine)
        actions_layout.addWidget(self._quarantine_btn)

        self._open_location_btn = QPushButton("Open Location")
        self._open_location_btn.clicked.connect(self._on_open_location)
        actions_layout.addWidget(self._open_location_btn)

        self._rescan_btn = QPushButton("Re-scan")
        self._rescan_btn.clicked.connect(self._on_rescan)
        actions_layout.addWidget(self._rescan_btn)

        actions_layout.addStretch()

        self._close_btn = QPushButton("Close")
        self._close_btn.clicked.connect(self.accept)
        actions_layout.addWidget(self._close_btn)

        layout.addLayout(actions_layout)

    def _create_file_info_section(self) -> QGroupBox:
        """Create file information section."""
        group = QGroupBox("File Information")
        layout = QFormLayout(group)

        self._path_label = QLabel()
        self._path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._path_label.setWordWrap(True)
        layout.addRow("Path:", self._path_label)

        self._size_label = QLabel()
        layout.addRow("Size:", self._size_label)

        self._modified_label = QLabel()
        layout.addRow("Modified:", self._modified_label)

        return group

    def _create_risk_section(self) -> QGroupBox:
        """Create risk summary section with OpenLabels branding."""
        group = QGroupBox("OpenLabels Risk Assessment")
        layout = QHBoxLayout(group)

        card_style = f"""
            QFrame {{
                background-color: {COLORS["bg_secondary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 12px;
                padding: 16px;
            }}
        """

        # Score
        score_frame = QFrame()
        score_frame.setStyleSheet(card_style)
        score_layout = QVBoxLayout(score_frame)

        self._score_label = QLabel("--")
        self._score_label.setFont(QFont("Arial", 36, QFont.Bold))
        self._score_label.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self._score_label)

        score_title = QLabel("Risk Score")
        score_title.setAlignment(Qt.AlignCenter)
        score_title.setStyleSheet(f"color: {COLORS['text_secondary']};")
        score_layout.addWidget(score_title)

        layout.addWidget(score_frame)

        # Tier
        tier_frame = QFrame()
        tier_frame.setStyleSheet(card_style)
        tier_layout = QVBoxLayout(tier_frame)

        self._tier_label = QLabel("--")
        self._tier_label.setFont(QFont("Arial", 24, QFont.Bold))
        self._tier_label.setAlignment(Qt.AlignCenter)
        tier_layout.addWidget(self._tier_label)

        tier_title = QLabel("Risk Tier")
        tier_title.setAlignment(Qt.AlignCenter)
        tier_title.setStyleSheet(f"color: {COLORS['text_secondary']};")
        tier_layout.addWidget(tier_title)

        layout.addWidget(tier_frame)

        # Entity summary
        entities_frame = QFrame()
        entities_frame.setStyleSheet(card_style)
        entities_layout = QVBoxLayout(entities_frame)

        self._entities_count_label = QLabel("--")
        self._entities_count_label.setFont(QFont("Arial", 36, QFont.Bold))
        self._entities_count_label.setAlignment(Qt.AlignCenter)
        self._entities_count_label.setStyleSheet(f"color: {COLORS['primary']};")
        entities_layout.addWidget(self._entities_count_label)

        entities_title = QLabel("Entities Found")
        entities_title.setAlignment(Qt.AlignCenter)
        entities_title.setStyleSheet(f"color: {COLORS['text_secondary']};")
        entities_layout.addWidget(entities_title)

        layout.addWidget(entities_frame)

        return group

    def _create_sources_section(self) -> QGroupBox:
        """Create classification sources section."""
        group = QGroupBox("Classification Sources")
        self._sources_layout = QVBoxLayout(group)

        # Placeholder - populated in _populate_data
        placeholder = QLabel("No classification sources")
        placeholder.setStyleSheet("color: #6c757d; font-style: italic;")
        self._sources_layout.addWidget(placeholder)

        return group

    def _create_content_section(self) -> QGroupBox:
        """Create sensitive content section (vault-protected)."""
        group = QGroupBox("Sensitive Content")
        layout = QVBoxLayout(group)

        # Lock indicator
        self._lock_frame = QFrame()
        self._lock_frame.setStyleSheet("""
            QFrame {
                background-color: #21262d;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 12px;
            }
            QLabel {
                color: #8b949e;
            }
        """)
        lock_layout = QHBoxLayout(self._lock_frame)

        lock_icon = QLabel("\U0001F512")  # Lock emoji
        lock_icon.setFont(QFont("Arial", 16))
        lock_layout.addWidget(lock_icon)

        lock_text = QLabel("Sensitive content is protected. Unlock vault to view.")
        lock_layout.addWidget(lock_text)

        lock_layout.addStretch()

        self._unlock_btn = QPushButton("Unlock")
        self._unlock_btn.clicked.connect(self._on_unlock_vault)
        lock_layout.addWidget(self._unlock_btn)

        layout.addWidget(self._lock_frame)

        # Content table (hidden until unlocked)
        self._content_table = QTableWidget()
        self._content_table.setColumnCount(4)
        self._content_table.setHorizontalHeaderLabels([
            "Type", "Content", "Confidence", "Context"
        ])
        self._content_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._content_table.setVisible(False)
        layout.addWidget(self._content_table)

        return group

    def _create_labels_section(self) -> QGroupBox:
        """Create user labels section."""
        group = QGroupBox("Labels")
        layout = QVBoxLayout(group)

        # Labels display
        self._labels_container = QHBoxLayout()

        self._labels_widget = QWidget()
        self._labels_flow = QHBoxLayout(self._labels_widget)
        self._labels_flow.setContentsMargins(0, 0, 0, 0)
        self._labels_container.addWidget(self._labels_widget)

        self._labels_container.addStretch()

        layout.addLayout(self._labels_container)

        # Add label input
        add_layout = QHBoxLayout()

        self._label_input = QLineEdit()
        self._label_input.setPlaceholderText("Add new label...")
        self._label_input.setMaximumWidth(200)
        add_layout.addWidget(self._label_input)

        self._add_label_btn = QPushButton("Add")
        self._add_label_btn.clicked.connect(self._on_add_label)
        add_layout.addWidget(self._add_label_btn)

        add_layout.addStretch()
        layout.addLayout(add_layout)

        return group

    def _populate_data(self):
        """Populate dialog with file data."""
        import os
        from pathlib import Path

        # File info
        self._path_label.setText(self._file_path)

        try:
            path = Path(self._file_path)
            if path.exists():
                stat = path.stat()
                self._size_label.setText(self._format_size(stat.st_size))
                self._modified_label.setText(
                    self._format_timestamp(stat.st_mtime)
                )
            else:
                self._size_label.setText("File not found")
                self._modified_label.setText("--")
        except Exception:
            self._size_label.setText("Unknown")
            self._modified_label.setText("Unknown")

        # Risk data
        if self._classification:
            self._score_label.setText(str(self._classification.risk_score))
            self._tier_label.setText(self._classification.tier)

            tier_color = get_tier_color(self._classification.tier)
            self._tier_label.setStyleSheet(f"color: {tier_color};")

            total_entities = sum(self._classification.all_findings.values())
            self._entities_count_label.setText(str(total_entities))

            # Populate sources
            self._populate_sources()

            # Populate labels
            self._populate_labels()
        else:
            self._score_label.setText("--")
            self._tier_label.setText("Not scanned")
            self._entities_count_label.setText("--")

    def _populate_sources(self):
        """Populate classification sources."""
        if not self._classification or not self._classification.sources:
            return

        # Clear placeholder
        while self._sources_layout.count():
            item = self._sources_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for source in self._classification.sources:
            source_widget = self._create_source_widget(source)
            self._sources_layout.addWidget(source_widget)

    def _create_source_widget(self, source: "ClassificationSource") -> QFrame:
        """Create a widget for a single classification source."""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 8px;
                margin-bottom: 8px;
            }
        """)
        layout = QVBoxLayout(frame)

        # Header with provider icon
        header_layout = QHBoxLayout()

        provider_icons = {
            "macie": "\U0001F4E6",      # Package (AWS)
            "purview": "\U0001F4CA",    # Chart (Microsoft)
            "dlp": "\U0001F50D",        # Magnifying glass (Google)
            "openlabels": "\U0001F3F7", # Label
            "manual": "\U0001F4DD",     # Memo
        }
        icon = provider_icons.get(source.provider, "\U0001F4C4")

        header = QLabel(f"{icon} {source.provider_display_name}")
        header.setFont(QFont("Arial", 12, QFont.Bold))
        header_layout.addWidget(header)

        timestamp = QLabel(source.timestamp.strftime("%Y-%m-%d %H:%M"))
        timestamp.setStyleSheet("color: #6c757d;")
        header_layout.addWidget(timestamp)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Metadata (provider-specific)
        if source.metadata:
            meta_text = []
            for key, value in source.metadata.items():
                if key not in ("scan_duration_ms",):  # Skip internal fields
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)
                    meta_text.append(f"{key}: {value}")

            if meta_text:
                meta_label = QLabel(" | ".join(meta_text))
                meta_label.setStyleSheet("color: #495057;")
                meta_label.setWordWrap(True)
                layout.addWidget(meta_label)

        # Findings
        if source.findings:
            findings_text = ", ".join(
                f"{f.entity_type}: {f.count}"
                for f in sorted(source.findings, key=lambda x: -x.count)[:5]
            )
            if len(source.findings) > 5:
                findings_text += f" (+{len(source.findings) - 5} more)"

            findings_label = QLabel(f"Findings: {findings_text}")
            findings_label.setStyleSheet("color: #495057;")
            layout.addWidget(findings_label)

        return frame

    def _populate_labels(self):
        """Populate user labels."""
        # Clear existing
        while self._labels_flow.count():
            item = self._labels_flow.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        labels = self._classification.labels if self._classification else []

        for label in labels:
            label_btn = QPushButton(f"{label} \u00D7")
            label_btn.setStyleSheet("""
                QPushButton {
                    background-color: #e9ecef;
                    border: 1px solid #ced4da;
                    border-radius: 12px;
                    padding: 4px 8px;
                }
                QPushButton:hover {
                    background-color: #dee2e6;
                }
            """)
            label_btn.clicked.connect(lambda checked, l=label: self._on_remove_label(l))
            self._labels_flow.addWidget(label_btn)

    def _on_unlock_vault(self):
        """Handle vault unlock."""
        if not self._session:
            QMessageBox.warning(
                self,
                "Not Logged In",
                "Please log in to view sensitive content.",
            )
            return

        try:
            vault = self._session.get_vault()

            # Get spans for this file
            spans = vault.get_spans_for_file(self._file_path)

            if not spans:
                QMessageBox.information(
                    self,
                    "No Sensitive Content",
                    "No sensitive content has been scanned for this file.",
                )
                return

            # Populate table
            self._content_table.setRowCount(len(spans))

            for i, span in enumerate(spans):
                # Type
                type_item = QTableWidgetItem(span.entity_type)
                self._content_table.setItem(i, 0, type_item)

                # Content (actual sensitive text)
                content_item = QTableWidgetItem(span.text)
                content_item.setBackground(QColor("#fff3cd"))
                self._content_table.setItem(i, 1, content_item)

                # Confidence
                conf_item = QTableWidgetItem(f"{span.confidence:.0%}")
                self._content_table.setItem(i, 2, conf_item)

                # Context
                context = f"...{span.context_before}[MATCH]{span.context_after}..."
                context_item = QTableWidgetItem(context)
                context_item.setToolTip(context)
                self._content_table.setItem(i, 3, context_item)

            # Show table, hide lock
            self._lock_frame.setVisible(False)
            self._content_table.setVisible(True)
            self._vault_unlocked = True

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to unlock vault: {str(e)}",
            )

    def _on_add_label(self):
        """Handle adding a label."""
        label = self._label_input.text().strip()
        if not label:
            return

        if self._session and self._classification:
            try:
                vault = self._session.get_vault()
                vault.add_label(self._file_path, label)

                # Update local state
                if label not in self._classification.labels:
                    self._classification.labels.append(label)

                self._populate_labels()
                self._label_input.clear()

                self.label_changed.emit(self._file_path, self._classification.labels)

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add label: {e}")

    def _on_remove_label(self, label: str):
        """Handle removing a label."""
        if self._session and self._classification:
            try:
                vault = self._session.get_vault()
                vault.remove_label(self._file_path, label)

                if label in self._classification.labels:
                    self._classification.labels.remove(label)

                self._populate_labels()

                self.label_changed.emit(self._file_path, self._classification.labels)

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to remove label: {e}")

    def _on_quarantine(self):
        """Handle quarantine request."""
        reply = QMessageBox.question(
            self,
            "Quarantine File",
            f"Move this file to quarantine?\n\n{self._file_path}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.quarantine_requested.emit(self._file_path)
            self.accept()

    def _on_open_location(self):
        """Open file location in system file manager."""
        import subprocess
        import sys
        from pathlib import Path

        folder = Path(self._file_path).parent

        try:
            if sys.platform == "darwin":
                subprocess.run(["open", str(folder)])
            elif sys.platform == "win32":
                subprocess.run(["explorer", str(folder)])
            else:
                subprocess.run(["xdg-open", str(folder)])
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Could not open location: {e}",
            )

    def _on_rescan(self):
        """Handle rescan request."""
        self.rescan_requested.emit(self._file_path)
        QMessageBox.information(
            self,
            "Scan Requested",
            "The file will be rescanned. Results will appear when complete.",
        )

    def _format_size(self, size: int) -> str:
        """Format file size for display."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for display."""
        from datetime import datetime
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

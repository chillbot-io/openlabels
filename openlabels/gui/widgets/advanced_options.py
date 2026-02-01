"""
Advanced Scanner Options Widget.

Exposes power-user scanner configuration options in a collapsible panel.
"""

import os
from typing import Dict, Any, Optional

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QSpinBox,
    QComboBox,
    QCheckBox,
    QLineEdit,
    QGroupBox,
    QFrame,
    QPushButton,
)
from PySide6.QtCore import Signal, Qt


class AdvancedOptionsWidget(QWidget):
    """Collapsible advanced scanner options panel."""

    options_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._expanded = False
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toggle header
        self._header = QPushButton("Advanced Options")
        self._header.setProperty("secondary", True)
        self._header.setCheckable(True)
        self._header.setChecked(False)
        self._header.toggled.connect(self._on_toggle)
        self._header.setFixedHeight(28)
        layout.addWidget(self._header)

        # Collapsible content
        self._content = QWidget()
        self._content.setVisible(False)
        content_layout = QVBoxLayout(self._content)
        content_layout.setContentsMargins(0, 8, 0, 0)
        content_layout.setSpacing(12)

        # --- Performance Section ---
        perf_group = QGroupBox("Performance")
        perf_layout = QVBoxLayout(perf_group)
        perf_layout.setSpacing(8)

        # Workers
        workers_row = QHBoxLayout()
        workers_label = QLabel("Parallel Workers:")
        workers_label.setFixedWidth(120)
        self._workers_spin = QSpinBox()
        self._workers_spin.setRange(1, 32)
        self._workers_spin.setValue(min(os.cpu_count() or 4, 8))
        self._workers_spin.setToolTip("Number of parallel threads for scanning")
        self._workers_spin.valueChanged.connect(self.options_changed)
        workers_row.addWidget(workers_label)
        workers_row.addWidget(self._workers_spin)
        workers_row.addStretch()
        perf_layout.addLayout(workers_row)

        # Batch size
        batch_row = QHBoxLayout()
        batch_label = QLabel("Batch Size:")
        batch_label.setFixedWidth(120)
        self._batch_spin = QSpinBox()
        self._batch_spin.setRange(10, 500)
        self._batch_spin.setValue(50)
        self._batch_spin.setToolTip("Results per batch update (higher = less UI updates)")
        self._batch_spin.valueChanged.connect(self.options_changed)
        batch_row.addWidget(batch_label)
        batch_row.addWidget(self._batch_spin)
        batch_row.addStretch()
        perf_layout.addLayout(batch_row)

        content_layout.addWidget(perf_group)

        # --- Scan Scope Section ---
        scope_group = QGroupBox("Scan Scope")
        scope_layout = QVBoxLayout(scope_group)
        scope_layout.setSpacing(8)

        # Recursive
        self._recursive_check = QCheckBox("Scan subdirectories recursively")
        self._recursive_check.setChecked(True)
        self._recursive_check.stateChanged.connect(self.options_changed)
        scope_layout.addWidget(self._recursive_check)

        # Follow symlinks
        self._symlinks_check = QCheckBox("Follow symbolic links")
        self._symlinks_check.setChecked(False)
        self._symlinks_check.stateChanged.connect(self.options_changed)
        scope_layout.addWidget(self._symlinks_check)

        # Hidden files
        self._hidden_check = QCheckBox("Include hidden files (.*)")
        self._hidden_check.setChecked(False)
        self._hidden_check.stateChanged.connect(self.options_changed)
        scope_layout.addWidget(self._hidden_check)

        # File extensions filter
        ext_row = QHBoxLayout()
        ext_label = QLabel("Extensions:")
        ext_label.setFixedWidth(120)
        self._extensions_input = QLineEdit()
        self._extensions_input.setPlaceholderText("e.g., .txt,.csv,.xlsx (empty = all)")
        self._extensions_input.setToolTip("Comma-separated list of extensions to scan")
        self._extensions_input.textChanged.connect(self.options_changed)
        ext_row.addWidget(ext_label)
        ext_row.addWidget(self._extensions_input)
        scope_layout.addLayout(ext_row)

        # Exclude patterns
        exclude_row = QHBoxLayout()
        exclude_label = QLabel("Exclude:")
        exclude_label.setFixedWidth(120)
        self._exclude_input = QLineEdit()
        self._exclude_input.setPlaceholderText("e.g., node_modules,*.log,temp*")
        self._exclude_input.setToolTip("Comma-separated patterns to exclude")
        self._exclude_input.setText("node_modules,__pycache__,.git")
        self._exclude_input.textChanged.connect(self.options_changed)
        exclude_row.addWidget(exclude_label)
        exclude_row.addWidget(self._exclude_input)
        scope_layout.addLayout(exclude_row)

        # Max file size
        size_row = QHBoxLayout()
        size_label = QLabel("Max File Size:")
        size_label.setFixedWidth(120)
        self._max_size_spin = QSpinBox()
        self._max_size_spin.setRange(0, 1000)
        self._max_size_spin.setValue(100)
        self._max_size_spin.setSuffix(" MB")
        self._max_size_spin.setSpecialValueText("No limit")
        self._max_size_spin.setToolTip("Skip files larger than this (0 = no limit)")
        self._max_size_spin.valueChanged.connect(self.options_changed)
        size_row.addWidget(size_label)
        size_row.addWidget(self._max_size_spin)
        size_row.addStretch()
        scope_layout.addLayout(size_row)

        content_layout.addWidget(scope_group)

        # --- Risk Settings Section ---
        risk_group = QGroupBox("Risk Assessment")
        risk_layout = QVBoxLayout(risk_group)
        risk_layout.setSpacing(8)

        # Exposure level
        exposure_row = QHBoxLayout()
        exposure_label = QLabel("Exposure Level:")
        exposure_label.setFixedWidth(120)
        self._exposure_combo = QComboBox()
        self._exposure_combo.addItems(["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"])
        self._exposure_combo.setToolTip("Assumed exposure level for risk calculation")
        self._exposure_combo.currentTextChanged.connect(self.options_changed)
        exposure_row.addWidget(exposure_label)
        exposure_row.addWidget(self._exposure_combo)
        exposure_row.addStretch()
        risk_layout.addLayout(exposure_row)

        # Alert threshold
        threshold_row = QHBoxLayout()
        threshold_label = QLabel("Alert Threshold:")
        threshold_label.setFixedWidth(120)
        self._threshold_spin = QSpinBox()
        self._threshold_spin.setRange(0, 100)
        self._threshold_spin.setValue(0)
        self._threshold_spin.setSpecialValueText("Disabled")
        self._threshold_spin.setToolTip("Alert when score exceeds this value (0 = disabled)")
        self._threshold_spin.valueChanged.connect(self.options_changed)
        threshold_row.addWidget(threshold_label)
        threshold_row.addWidget(self._threshold_spin)
        threshold_row.addStretch()
        risk_layout.addLayout(threshold_row)

        content_layout.addWidget(risk_group)

        # --- Output Section ---
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout(output_group)
        output_layout.setSpacing(8)

        # Auto-embed labels
        self._embed_check = QCheckBox("Auto-embed labels in files")
        self._embed_check.setChecked(True)
        self._embed_check.setToolTip("Automatically embed OpenLabels metadata in scanned files")
        self._embed_check.stateChanged.connect(self.options_changed)
        output_layout.addWidget(self._embed_check)

        # Store to vault
        self._vault_check = QCheckBox("Store findings to vault")
        self._vault_check.setChecked(True)
        self._vault_check.setToolTip("Store detected spans in encrypted vault")
        self._vault_check.stateChanged.connect(self.options_changed)
        output_layout.addWidget(self._vault_check)

        content_layout.addWidget(output_group)

        layout.addWidget(self._content)

    def _on_toggle(self, checked: bool):
        """Handle expand/collapse toggle."""
        self._expanded = checked
        self._content.setVisible(checked)
        if checked:
            self._header.setText("Advanced Options (collapse)")
        else:
            self._header.setText("Advanced Options")

    def get_options(self) -> Dict[str, Any]:
        """Get current option values."""
        extensions = self._extensions_input.text().strip()
        ext_list = [e.strip() for e in extensions.split(",") if e.strip()] if extensions else None

        exclude = self._exclude_input.text().strip()
        exclude_list = [e.strip() for e in exclude.split(",") if e.strip()] if exclude else []

        return {
            "workers": self._workers_spin.value(),
            "batch_size": self._batch_spin.value(),
            "recursive": self._recursive_check.isChecked(),
            "follow_symlinks": self._symlinks_check.isChecked(),
            "include_hidden": self._hidden_check.isChecked(),
            "extensions": ext_list,
            "exclude_patterns": exclude_list,
            "max_file_size_mb": self._max_size_spin.value() or None,
            "exposure": self._exposure_combo.currentText(),
            "alert_threshold": self._threshold_spin.value() or None,
            "auto_embed": self._embed_check.isChecked(),
            "store_to_vault": self._vault_check.isChecked(),
        }

    def set_options(self, options: Dict[str, Any]):
        """Set option values."""
        if "workers" in options:
            self._workers_spin.setValue(options["workers"])
        if "batch_size" in options:
            self._batch_spin.setValue(options["batch_size"])
        if "recursive" in options:
            self._recursive_check.setChecked(options["recursive"])
        if "follow_symlinks" in options:
            self._symlinks_check.setChecked(options["follow_symlinks"])
        if "include_hidden" in options:
            self._hidden_check.setChecked(options["include_hidden"])
        if "extensions" in options and options["extensions"]:
            self._extensions_input.setText(",".join(options["extensions"]))
        if "exclude_patterns" in options:
            self._exclude_input.setText(",".join(options["exclude_patterns"]))
        if "max_file_size_mb" in options:
            self._max_size_spin.setValue(options["max_file_size_mb"] or 0)
        if "exposure" in options:
            idx = self._exposure_combo.findText(options["exposure"])
            if idx >= 0:
                self._exposure_combo.setCurrentIndex(idx)
        if "alert_threshold" in options:
            self._threshold_spin.setValue(options["alert_threshold"] or 0)
        if "auto_embed" in options:
            self._embed_check.setChecked(options["auto_embed"])
        if "store_to_vault" in options:
            self._vault_check.setChecked(options["store_to_vault"])

    def is_expanded(self) -> bool:
        """Check if panel is expanded."""
        return self._expanded

    def set_expanded(self, expanded: bool):
        """Set expanded state."""
        self._header.setChecked(expanded)

"""
Settings widget for OpenLabels GUI.

Provides configuration options for:
- Server connection
- Detection settings
- Labeling preferences
- Notification settings
"""

import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QGroupBox, QLineEdit, QSpinBox, QCheckBox, QComboBox,
        QFormLayout, QMessageBox, QScrollArea,
    )
    from PySide6.QtCore import Qt, Signal
    PYSIDE_AVAILABLE = True
except ImportError:
    # PySide6 not installed - settings widget unavailable
    logger.debug("PySide6 not installed - settings widget disabled")
    PYSIDE_AVAILABLE = False
    QWidget = object


class SettingsWidget(QWidget if PYSIDE_AVAILABLE else object):
    """
    Widget for application settings.

    Signals:
        settings_changed: Emitted when settings are saved
    """

    if PYSIDE_AVAILABLE:
        settings_changed = Signal(dict)

    def __init__(self, server_url: str = "http://localhost:8000", parent: Optional[QWidget] = None):
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
        self._server_url = server_url
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        content = QWidget()
        layout = QVBoxLayout(content)

        # Server settings
        server_group = QGroupBox("Server Connection")
        server_layout = QFormLayout(server_group)

        self._server_url_input = QLineEdit(self._server_url)
        server_layout.addRow("Server URL:", self._server_url_input)

        self._auto_connect_cb = QCheckBox("Connect on startup")
        self._auto_connect_cb.setChecked(True)
        server_layout.addRow("", self._auto_connect_cb)

        self._refresh_interval = QSpinBox()
        self._refresh_interval.setRange(5, 300)
        self._refresh_interval.setValue(30)
        self._refresh_interval.setSuffix(" seconds")
        server_layout.addRow("Auto-refresh interval:", self._refresh_interval)

        layout.addWidget(server_group)

        # Detection settings
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QFormLayout(detection_group)

        self._enable_ml_cb = QCheckBox("Enable ML-based detection")
        self._enable_ml_cb.setChecked(False)
        self._enable_ml_cb.setToolTip("Requires ML models to be downloaded")
        detection_layout.addRow("", self._enable_ml_cb)

        self._enable_ocr_cb = QCheckBox("Enable OCR for images")
        self._enable_ocr_cb.setChecked(True)
        detection_layout.addRow("", self._enable_ocr_cb)

        self._confidence_threshold = QSpinBox()
        self._confidence_threshold.setRange(50, 100)
        self._confidence_threshold.setValue(70)
        self._confidence_threshold.setSuffix("%")
        detection_layout.addRow("Confidence threshold:", self._confidence_threshold)

        self._escalation_threshold = QSpinBox()
        self._escalation_threshold.setRange(50, 100)
        self._escalation_threshold.setValue(70)
        self._escalation_threshold.setSuffix("%")
        self._escalation_threshold.setToolTip("Spans below this confidence will trigger ML escalation")
        detection_layout.addRow("ML escalation threshold:", self._escalation_threshold)

        layout.addWidget(detection_group)

        # Labeling settings
        labeling_group = QGroupBox("Labeling Settings")
        labeling_layout = QFormLayout(labeling_group)

        self._auto_label_cb = QCheckBox("Auto-apply labels based on rules")
        self._auto_label_cb.setChecked(True)
        labeling_layout.addRow("", self._auto_label_cb)

        self._sync_labels_cb = QCheckBox("Auto-sync labels from M365")
        self._sync_labels_cb.setChecked(True)
        labeling_layout.addRow("", self._sync_labels_cb)

        self._label_cache_ttl = QSpinBox()
        self._label_cache_ttl.setRange(60, 3600)
        self._label_cache_ttl.setValue(300)
        self._label_cache_ttl.setSuffix(" seconds")
        labeling_layout.addRow("Label cache TTL:", self._label_cache_ttl)

        layout.addWidget(labeling_group)

        # Monitoring settings
        monitoring_group = QGroupBox("File Monitoring")
        monitoring_layout = QFormLayout(monitoring_group)

        self._auto_monitor_cb = QCheckBox("Auto-monitor high-risk files")
        self._auto_monitor_cb.setChecked(False)
        self._auto_monitor_cb.setToolTip("Automatically enable access monitoring for HIGH/CRITICAL files")
        monitoring_layout.addRow("", self._auto_monitor_cb)

        self._monitor_threshold = QComboBox()
        self._monitor_threshold.addItems(["CRITICAL", "HIGH", "MEDIUM"])
        self._monitor_threshold.setCurrentText("HIGH")
        monitoring_layout.addRow("Auto-monitor threshold:", self._monitor_threshold)

        layout.addWidget(monitoring_group)

        # Notification settings
        notification_group = QGroupBox("Notifications")
        notification_layout = QFormLayout(notification_group)

        self._notify_critical_cb = QCheckBox("Show notification for CRITICAL files")
        self._notify_critical_cb.setChecked(True)
        notification_layout.addRow("", self._notify_critical_cb)

        self._notify_scan_complete_cb = QCheckBox("Show notification when scan completes")
        self._notify_scan_complete_cb.setChecked(True)
        notification_layout.addRow("", self._notify_scan_complete_cb)

        layout.addWidget(notification_group)

        # Actions
        actions_layout = QHBoxLayout()
        actions_layout.addStretch()

        self._reset_btn = QPushButton("Reset to Defaults")
        self._reset_btn.clicked.connect(self._reset_defaults)
        actions_layout.addWidget(self._reset_btn)

        self._save_btn = QPushButton("Save Settings")
        self._save_btn.clicked.connect(self._save_settings)
        actions_layout.addWidget(self._save_btn)

        layout.addLayout(actions_layout)
        layout.addStretch()

        scroll.setWidget(content)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll)

    def _reset_defaults(self) -> None:
        """Reset all settings to defaults."""
        self._server_url_input.setText("http://localhost:8000")
        self._auto_connect_cb.setChecked(True)
        self._refresh_interval.setValue(30)
        self._enable_ml_cb.setChecked(False)
        self._enable_ocr_cb.setChecked(True)
        self._confidence_threshold.setValue(70)
        self._escalation_threshold.setValue(70)
        self._auto_label_cb.setChecked(True)
        self._sync_labels_cb.setChecked(True)
        self._label_cache_ttl.setValue(300)
        self._auto_monitor_cb.setChecked(False)
        self._monitor_threshold.setCurrentText("HIGH")
        self._notify_critical_cb.setChecked(True)
        self._notify_scan_complete_cb.setChecked(True)

    def _save_settings(self) -> None:
        """Save settings and emit signal."""
        settings = self.get_settings()
        self.settings_changed.emit(settings)
        QMessageBox.information(self, "Settings", "Settings saved successfully.")

    def get_settings(self) -> Dict:
        """Get current settings as dictionary."""
        return {
            "server_url": self._server_url_input.text(),
            "auto_connect": self._auto_connect_cb.isChecked(),
            "refresh_interval": self._refresh_interval.value(),
            "enable_ml": self._enable_ml_cb.isChecked(),
            "enable_ocr": self._enable_ocr_cb.isChecked(),
            "confidence_threshold": self._confidence_threshold.value() / 100.0,
            "escalation_threshold": self._escalation_threshold.value() / 100.0,
            "auto_label": self._auto_label_cb.isChecked(),
            "sync_labels": self._sync_labels_cb.isChecked(),
            "label_cache_ttl": self._label_cache_ttl.value(),
            "auto_monitor": self._auto_monitor_cb.isChecked(),
            "monitor_threshold": self._monitor_threshold.currentText(),
            "notify_critical": self._notify_critical_cb.isChecked(),
            "notify_scan_complete": self._notify_scan_complete_cb.isChecked(),
        }

    def set_settings(self, settings: Dict) -> None:
        """Load settings from dictionary."""
        if "server_url" in settings:
            self._server_url_input.setText(settings["server_url"])
        if "auto_connect" in settings:
            self._auto_connect_cb.setChecked(settings["auto_connect"])
        if "refresh_interval" in settings:
            self._refresh_interval.setValue(settings["refresh_interval"])
        if "enable_ml" in settings:
            self._enable_ml_cb.setChecked(settings["enable_ml"])
        if "enable_ocr" in settings:
            self._enable_ocr_cb.setChecked(settings["enable_ocr"])
        if "confidence_threshold" in settings:
            self._confidence_threshold.setValue(int(settings["confidence_threshold"] * 100))
        if "escalation_threshold" in settings:
            self._escalation_threshold.setValue(int(settings["escalation_threshold"] * 100))
        if "auto_label" in settings:
            self._auto_label_cb.setChecked(settings["auto_label"])
        if "sync_labels" in settings:
            self._sync_labels_cb.setChecked(settings["sync_labels"])
        if "label_cache_ttl" in settings:
            self._label_cache_ttl.setValue(settings["label_cache_ttl"])
        if "auto_monitor" in settings:
            self._auto_monitor_cb.setChecked(settings["auto_monitor"])
        if "monitor_threshold" in settings:
            self._monitor_threshold.setCurrentText(settings["monitor_threshold"])
        if "notify_critical" in settings:
            self._notify_critical_cb.setChecked(settings["notify_critical"])
        if "notify_scan_complete" in settings:
            self._notify_scan_complete_cb.setChecked(settings["notify_scan_complete"])

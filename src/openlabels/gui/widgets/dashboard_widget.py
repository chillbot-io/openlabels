"""
Dashboard widget for statistics and visualizations.

Displays:
- Risk tier distribution
- Scan statistics
- Recent activity
- Trend charts
"""

import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout,
        QFrame, QGroupBox, QScrollArea,
    )
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QFont
    PYSIDE_AVAILABLE = True
except ImportError:
    PYSIDE_AVAILABLE = False
    QWidget = object


class StatCard(QFrame if PYSIDE_AVAILABLE else object):
    """A card displaying a statistic."""

    def __init__(
        self,
        title: str,
        value: str,
        subtitle: str = "",
        parent: Optional[QWidget] = None,
    ):
        if not PYSIDE_AVAILABLE:
            return

        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        self.setMinimumSize(150, 100)

        layout = QVBoxLayout(self)

        title_label = QLabel(title)
        title_label.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(title_label)

        value_label = QLabel(value)
        value_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(value_label)

        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setStyleSheet("color: #888; font-size: 11px;")
            layout.addWidget(subtitle_label)

        layout.addStretch()

        self._value_label = value_label

    def set_value(self, value: str) -> None:
        """Update the displayed value."""
        if PYSIDE_AVAILABLE:
            self._value_label.setText(value)


class DashboardWidget(QWidget if PYSIDE_AVAILABLE else object):
    """
    Dashboard widget showing system statistics.

    Signals:
        refresh_requested: Emitted when refresh is needed
    """

    if PYSIDE_AVAILABLE:
        refresh_requested = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        if not PYSIDE_AVAILABLE:
            logger.warning("PySide6 not available")
            return

        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Stats row
        stats_layout = QHBoxLayout()

        self._total_files_card = StatCard("Total Files", "0", "scanned")
        stats_layout.addWidget(self._total_files_card)

        self._high_risk_card = StatCard("High Risk", "0", "files")
        stats_layout.addWidget(self._high_risk_card)

        self._labeled_card = StatCard("Labeled", "0%", "of files")
        stats_layout.addWidget(self._labeled_card)

        self._active_scans_card = StatCard("Active Scans", "0", "running")
        stats_layout.addWidget(self._active_scans_card)

        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        # Risk distribution
        risk_group = QGroupBox("Risk Distribution")
        risk_layout = QGridLayout(risk_group)

        self._risk_labels = {}
        tiers = [
            ("CRITICAL", "#dc3545"),
            ("HIGH", "#fd7e14"),
            ("MEDIUM", "#ffc107"),
            ("LOW", "#28a745"),
            ("MINIMAL", "#6c757d"),
        ]

        for i, (tier, color) in enumerate(tiers):
            tier_label = QLabel(tier)
            tier_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            risk_layout.addWidget(tier_label, i, 0)

            count_label = QLabel("0")
            risk_layout.addWidget(count_label, i, 1)

            bar = QFrame()
            bar.setFixedHeight(20)
            bar.setStyleSheet(f"background-color: {color};")
            bar.setMinimumWidth(0)
            risk_layout.addWidget(bar, i, 2)

            self._risk_labels[tier] = (count_label, bar)

        layout.addWidget(risk_group)

        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)

        self._activity_label = QLabel("No recent activity")
        self._activity_label.setStyleSheet("color: #666;")
        activity_layout.addWidget(self._activity_label)

        layout.addWidget(activity_group)

        layout.addStretch()

    def update_stats(self, stats: Dict) -> None:
        """Update dashboard statistics."""
        if not PYSIDE_AVAILABLE:
            return

        self._total_files_card.set_value(str(stats.get("total_files", 0)))
        self._high_risk_card.set_value(str(stats.get("high_risk_count", 0)))

        labeled_pct = stats.get("labeled_percentage", 0)
        self._labeled_card.set_value(f"{labeled_pct:.0f}%")

        self._active_scans_card.set_value(str(stats.get("active_scans", 0)))

        # Update risk distribution
        distribution = stats.get("risk_distribution", {})
        total = sum(distribution.values()) or 1

        for tier, (count_label, bar) in self._risk_labels.items():
            count = distribution.get(tier, 0)
            count_label.setText(str(count))
            bar.setFixedWidth(int(200 * count / total))

    def add_activity(self, message: str) -> None:
        """Add an activity message."""
        if PYSIDE_AVAILABLE:
            current = self._activity_label.text()
            if current == "No recent activity":
                self._activity_label.setText(message)
            else:
                lines = current.split("\n")[:9]  # Keep last 10
                lines.insert(0, message)
                self._activity_label.setText("\n".join(lines))

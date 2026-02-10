"""
Dashboard widget for statistics and visualizations.

Displays:
- Risk tier distribution
- Scan statistics
- Recent activity
- Trend charts (sensitive data over time, access heat map)
"""

import logging

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QScrollArea,
        QSplitter,
        QTabWidget,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE_AVAILABLE = True
except ImportError:
    # PySide6 not installed - dashboard widget unavailable
    logger.debug("PySide6 not installed - dashboard widget disabled")
    PYSIDE_AVAILABLE = False
    QWidget = object

# Import chart widgets (may fail if pyqtgraph not installed)
CHARTS_AVAILABLE = False
try:
    from .charts_widget import ChartPanel, HeatMapChart, SensitiveDataChart
    CHARTS_AVAILABLE = True
except ImportError:
    logger.info("Charts not available - install pyqtgraph for visualizations")


class StatCard(QFrame if PYSIDE_AVAILABLE else object):
    """A card displaying a statistic."""

    def __init__(
        self,
        title: str,
        value: str,
        subtitle: str = "",
        parent: QWidget | None = None,
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

    def __init__(self, parent: QWidget | None = None):
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

        # Main content: charts on left, risk/activity on right
        content_splitter = QSplitter(Qt.Horizontal)

        # Left side: Charts (if available)
        if CHARTS_AVAILABLE:
            self._chart_panel = ChartPanel()
            content_splitter.addWidget(self._chart_panel)
            # Note: Chart data will be loaded by main_window from API
        else:
            # Placeholder if charts not available
            chart_placeholder = QLabel("Install pyqtgraph for charts:\npip install pyqtgraph")
            chart_placeholder.setAlignment(Qt.AlignCenter)
            chart_placeholder.setStyleSheet("color: #888; font-style: italic;")
            content_splitter.addWidget(chart_placeholder)
            self._chart_panel = None

        # Right side: Risk distribution + Recent activity
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

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

        right_layout.addWidget(risk_group)

        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)

        self._activity_label = QLabel("No recent activity")
        self._activity_label.setStyleSheet("color: #666;")
        activity_layout.addWidget(self._activity_label)

        right_layout.addWidget(activity_group)
        right_layout.addStretch()

        content_splitter.addWidget(right_widget)

        # Set splitter proportions (70% charts, 30% stats)
        content_splitter.setSizes([700, 300])

        layout.addWidget(content_splitter, stretch=1)

    def update_stats(self, stats: dict) -> None:
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

    def update_time_series(self, data: dict[str, list[tuple[str, int]]]) -> None:
        """
        Update the sensitive data over time chart.

        Args:
            data: Dictionary mapping series name to list of (date_str, count) tuples.
                  Example: {"Total": [("2024-01-01", 50), ("2024-01-02", 75)],
                           "SSN": [("2024-01-01", 10), ...]}
        """
        if PYSIDE_AVAILABLE and CHARTS_AVAILABLE and self._chart_panel:
            self._chart_panel.set_time_series_data(data)

    def update_heat_map(self, data: list[list[int]]) -> None:
        """
        Update the access activity heat map.

        Args:
            data: 7x24 matrix where data[day][hour] = count
                  day 0 = Monday, day 6 = Sunday
                  hour 0 = midnight, hour 23 = 11 PM
        """
        if PYSIDE_AVAILABLE and CHARTS_AVAILABLE and self._chart_panel:
            self._chart_panel.set_heat_map_data(data)

    def load_sample_charts(self) -> None:
        """Load sample data into charts for demonstration."""
        if PYSIDE_AVAILABLE and CHARTS_AVAILABLE and self._chart_panel:
            self._chart_panel.load_sample_data()

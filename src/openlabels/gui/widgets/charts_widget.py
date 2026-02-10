"""
Chart widgets for OpenLabels GUI using pyqtgraph.

Provides data visualization components:
- HeatMapChart: Access patterns by hour/day (7x24 grid)
- SensitiveDataChart: Entity detection trends over time
"""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pyqtgraph as pg
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

# Configure pyqtgraph for better appearance
pg.setConfigOptions(antialias=True, background='w', foreground='k')


class HeatMapChart(QWidget):
    """
    Interactive heat map showing activity patterns by hour and day of week.

    Use cases:
    - File access patterns (when are sensitive files being accessed?)
    - Scan activity patterns (when are scans running?)
    - Detection patterns (when is PII being found?)
    """

    cell_clicked = Signal(int, int, int)  # day, hour, value

    DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    HOURS = [f"{h:02d}:00" for h in range(24)]

    def __init__(self, parent=None, title: str = "Activity Heatmap"):
        super().__init__(parent)
        self._title = title
        self._data = np.zeros((7, 24))

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Title
        title_label = QLabel(f"<b>{self._title}</b>")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 11pt; color: #333;")
        layout.addWidget(title_label)

        # Create plot widget
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setMinimumSize(400, 200)

        # Configure axes
        self.plot_widget.setLabel('left', 'Day')
        self.plot_widget.setLabel('bottom', 'Hour')

        # Set axis ticks
        left_axis = self.plot_widget.getAxis('left')
        left_axis.setTicks([[(i, self.DAYS[i]) for i in range(7)]])

        bottom_axis = self.plot_widget.getAxis('bottom')
        bottom_axis.setTicks([[(i, f"{i:02d}") for i in range(0, 24, 3)]])

        # Create image item for heat map
        self.img = pg.ImageItem()
        self.plot_widget.addItem(self.img)

        # Create color bar
        self.colormap = pg.colormap.get('CET-L9')  # Perceptually uniform colormap
        self.color_bar = pg.ColorBarItem(
            values=(0, 100),
            colorMap=self.colormap,
            label='Count'
        )
        self.color_bar.setImageItem(self.img)

        # Add color bar to the layout
        layout.addWidget(self.plot_widget)

        # Connect click events
        self.plot_widget.scene().sigMouseClicked.connect(self._on_click)

        # Add crosshair for hover
        self.vLine = pg.InfiniteLine(angle=90, movable=False, pen=pg.mkPen('g', width=1))
        self.hLine = pg.InfiniteLine(angle=0, movable=False, pen=pg.mkPen('g', width=1))
        self.plot_widget.addItem(self.vLine, ignoreBounds=True)
        self.plot_widget.addItem(self.hLine, ignoreBounds=True)

        # Hover label
        self.hover_label = QLabel("")
        self.hover_label.setStyleSheet("color: #666; font-size: 9pt;")
        self.hover_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.hover_label)

        # Connect mouse move
        self.plot_widget.scene().sigMouseMoved.connect(self._on_mouse_move)

    def set_data(self, data: list[list[int]]) -> None:
        """
        Set heat map data.

        Args:
            data: 7x24 matrix where data[day][hour] = count
                  day 0 = Monday, day 6 = Sunday
        """
        if len(data) != 7:
            raise ValueError("Data must have 7 rows (days)")
        for row in data:
            if len(row) != 24:
                raise ValueError("Each row must have 24 columns (hours)")

        self._data = np.array(data, dtype=float)
        max_val = self._data.max() or 1

        # Update image (transpose for correct orientation)
        self.img.setImage(self._data.T)

        # Position image correctly
        self.img.setRect(pg.QtCore.QRectF(-0.5, -0.5, 24, 7))

        # Update color bar range
        self.color_bar.setLevels((0, max_val))

        # Set view range
        self.plot_widget.setXRange(-0.5, 23.5)
        self.plot_widget.setYRange(-0.5, 6.5)

    def _on_mouse_move(self, pos):
        """Handle mouse move for hover info."""
        if self.plot_widget.sceneBoundingRect().contains(pos):
            mouse_point = self.plot_widget.plotItem.vb.mapSceneToView(pos)
            hour = int(round(mouse_point.x()))
            day = int(round(mouse_point.y()))

            if 0 <= hour < 24 and 0 <= day < 7:
                self.vLine.setPos(hour)
                self.hLine.setPos(day)
                value = int(self._data[day, hour])
                self.hover_label.setText(
                    f"{self.DAYS[day]} {hour:02d}:00-{hour:02d}:59 | Count: {value}"
                )
            else:
                self.hover_label.setText("")

    def _on_click(self, evt):
        """Handle click events."""
        pos = evt.scenePos()
        if self.plot_widget.sceneBoundingRect().contains(pos):
            mouse_point = self.plot_widget.plotItem.vb.mapSceneToView(pos)
            hour = int(round(mouse_point.x()))
            day = int(round(mouse_point.y()))

            if 0 <= hour < 24 and 0 <= day < 7:
                value = int(self._data[day, hour])
                self.cell_clicked.emit(day, hour, value)


class SensitiveDataChart(QWidget):
    """
    Interactive time series chart showing sensitive data detection trends.

    Shows entity counts over time with multiple series:
    - Total detections
    - By entity type (SSN, email, credit card, etc.)
    """

    point_clicked = Signal(str, int)  # date_str, total_count

    SERIES_COLORS = [
        '#1976D2',  # Blue - Total
        '#D32F2F',  # Red - SSN
        '#388E3C',  # Green - Email
        '#F57C00',  # Orange - Credit Card
        '#7B1FA2',  # Purple - Phone
        '#00796B',  # Teal - Address
        '#5D4037',  # Brown - Name
        '#455A64',  # Blue Grey - Other
    ]

    def __init__(self, parent=None, title: str = "Sensitive Data Over Time"):
        super().__init__(parent)
        self._title = title
        self._data: dict[str, list[tuple[str, int]]] = {}
        self._dates: list[str] = []
        self._plots: dict[str, pg.PlotDataItem] = {}

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Title
        title_label = QLabel(f"<b>{self._title}</b>")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 11pt; color: #333;")
        layout.addWidget(title_label)

        # Main content area
        content_layout = QHBoxLayout()

        # Create plot widget
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setMinimumSize(400, 250)
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.setLabel('left', 'Count')
        self.plot_widget.setLabel('bottom', 'Date')

        # Enable legend
        self.legend = self.plot_widget.addLegend(offset=(-10, 10))

        content_layout.addWidget(self.plot_widget, stretch=4)

        # Series toggles
        toggle_group = QGroupBox("Series")
        toggle_layout = QVBoxLayout(toggle_group)
        toggle_layout.setSpacing(2)

        self.checkboxes: dict[str, QCheckBox] = {}
        toggle_layout.addStretch()

        content_layout.addWidget(toggle_group, stretch=1)
        self.toggle_layout = toggle_layout
        self.toggle_group = toggle_group

        layout.addLayout(content_layout)

        # Hover info
        self.hover_label = QLabel("")
        self.hover_label.setStyleSheet("color: #666; font-size: 9pt;")
        self.hover_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.hover_label)

        # Crosshair
        self.vLine = pg.InfiniteLine(angle=90, movable=False, pen=pg.mkPen('g', width=1, style=Qt.DashLine))
        self.plot_widget.addItem(self.vLine, ignoreBounds=True)

        self.plot_widget.scene().sigMouseMoved.connect(self._on_mouse_move)

    def set_data(self, data: dict[str, list[tuple[str, int]]]) -> None:
        """
        Set chart data.

        Args:
            data: Dictionary mapping series name to list of (date_str, count) tuples.
        """
        self._data = data

        # Collect all dates
        all_dates = set()
        for series_data in data.values():
            for date_str, _ in series_data:
                all_dates.add(date_str)
        self._dates = sorted(all_dates)

        # Clear existing plots
        for plot in self._plots.values():
            self.plot_widget.removeItem(plot)
        self._plots.clear()

        # Clear legend
        self.legend.clear()

        # Clear checkboxes
        for cb in self.checkboxes.values():
            self.toggle_layout.removeWidget(cb)
            cb.deleteLater()
        self.checkboxes.clear()

        # Create date index map
        date_to_idx = {d: i for i, d in enumerate(self._dates)}

        # Plot each series
        for idx, (series_name, series_data) in enumerate(data.items()):
            color = self.SERIES_COLORS[idx % len(self.SERIES_COLORS)]

            # Build arrays
            x_vals = []
            y_vals = []
            for date_str, count in series_data:
                x_vals.append(date_to_idx[date_str])
                y_vals.append(count)

            # Sort by x
            sorted_pairs = sorted(zip(x_vals, y_vals))
            x_arr = np.array([p[0] for p in sorted_pairs])
            y_arr = np.array([p[1] for p in sorted_pairs])

            # Create plot
            pen = pg.mkPen(color=color, width=2)
            symbol_brush = pg.mkBrush(color)
            plot = self.plot_widget.plot(
                x_arr, y_arr,
                pen=pen,
                symbol='o',
                symbolSize=6,
                symbolBrush=symbol_brush,
                name=series_name
            )
            self._plots[series_name] = plot

            # Create checkbox
            cb = QCheckBox(series_name)
            cb.setChecked(True)
            cb.setStyleSheet(f"color: {color}; font-weight: bold;")
            cb.stateChanged.connect(lambda state, name=series_name: self._toggle_series(name, state))
            self.toggle_layout.insertWidget(self.toggle_layout.count() - 1, cb)
            self.checkboxes[series_name] = cb

        # Set x-axis ticks to show dates
        if self._dates:
            # Show subset of dates to avoid crowding
            step = max(1, len(self._dates) // 7)
            ticks = [(i, self._dates[i][-5:]) for i in range(0, len(self._dates), step)]
            bottom_axis = self.plot_widget.getAxis('bottom')
            bottom_axis.setTicks([ticks])

    def _toggle_series(self, series_name: str, state: int):
        """Toggle visibility of a series."""
        if series_name in self._plots:
            self._plots[series_name].setVisible(state == Qt.Checked.value)

    def _on_mouse_move(self, pos):
        """Handle mouse move for hover info."""
        if self.plot_widget.sceneBoundingRect().contains(pos):
            mouse_point = self.plot_widget.plotItem.vb.mapSceneToView(pos)
            x_idx = int(round(mouse_point.x()))

            if 0 <= x_idx < len(self._dates):
                self.vLine.setPos(x_idx)
                date_str = self._dates[x_idx]

                # Get values for all visible series
                parts = [f"<b>{date_str}</b>"]
                for series_name, series_data in self._data.items():
                    if series_name in self._plots and self._plots[series_name].isVisible():
                        date_values = {d: v for d, v in series_data}
                        value = date_values.get(date_str, 0)
                        parts.append(f"{series_name}: {value}")

                self.hover_label.setText(" | ".join(parts))
            else:
                self.hover_label.setText("")


class ChartPanel(QWidget):
    """
    Combined panel with both charts for the dashboard.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Time series chart (top)
        self.time_chart = SensitiveDataChart(title="Sensitive Data Detections Over Time")
        layout.addWidget(self.time_chart, stretch=1)

        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("color: #ddd;")
        layout.addWidget(divider)

        # Heat map (bottom)
        self.heat_map = HeatMapChart(title="File Access Activity by Hour")
        layout.addWidget(self.heat_map, stretch=1)

    def set_time_series_data(self, data: dict[str, list[tuple[str, int]]]) -> None:
        """Set data for the time series chart."""
        self.time_chart.set_data(data)

    def set_heat_map_data(self, data: list[list[int]]) -> None:
        """Set data for the heat map."""
        self.heat_map.set_data(data)

    def load_sample_data(self) -> None:
        """Load sample data for demonstration."""
        import random

        # Generate sample time series data (last 14 days)
        today = datetime.now()
        dates = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]

        # Create realistic-looking data with trends
        base_total = 100
        time_data = {"Total": [], "SSN": [], "Email": [], "Credit Card": [], "Phone": []}

        for i, d in enumerate(dates):
            # Slight upward trend with noise
            trend = i * 3
            noise = random.randint(-20, 20)
            total = base_total + trend + noise

            time_data["Total"].append((d, max(10, total)))
            time_data["SSN"].append((d, max(0, random.randint(5, 20) + i)))
            time_data["Email"].append((d, max(0, random.randint(30, 60) + noise // 2)))
            time_data["Credit Card"].append((d, max(0, random.randint(2, 12))))
            time_data["Phone"].append((d, max(0, random.randint(10, 30) + i // 2)))

        self.time_chart.set_data(time_data)

        # Generate sample heat map data (access patterns)
        heat_data = []
        for day in range(7):
            row = []
            for hour in range(24):
                # More activity during work hours (9-17) on weekdays (0-4)
                if day < 5 and 9 <= hour <= 17:
                    row.append(random.randint(30, 100))
                elif day < 5 and (7 <= hour <= 9 or 17 <= hour <= 19):
                    row.append(random.randint(10, 40))
                elif day >= 5 and 10 <= hour <= 16:
                    row.append(random.randint(5, 20))
                else:
                    row.append(random.randint(0, 8))
            heat_data.append(row)

        self.heat_map.set_data(heat_data)

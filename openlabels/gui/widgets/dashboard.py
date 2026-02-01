"""
Risk Dashboard with hierarchical drill-down heatmap.
"""

from pathlib import Path
from typing import List, Dict, Any

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QLabel,
    QPushButton,
    QFrame,
    QMenu,
    QAbstractItemView,
    QSizePolicy,
)
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QColor, QBrush, QPainter, QFont

from openlabels.dashboard_models import HeatmapNode


DEFAULT_ENTITY_TYPES = [
    "SSN", "EMAIL", "PHONE", "CREDIT_CARD", "NAME",
    "DOB", "ADDRESS", "MRN", "AWS_ACCESS_KEY", "IP_ADDRESS",
]


class HeatmapCell(QWidget):
    """Custom widget for a heatmap cell with gradient coloring."""

    def __init__(self, intensity: float = 0.0, count: int = 0, parent=None):
        super().__init__(parent)
        self._intensity = intensity
        self._count = count
        self.setMinimumSize(60, 30)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_data(self, intensity: float, count: int):
        """Update cell data."""
        self._intensity = intensity
        self._count = count
        self.update()

    def paintEvent(self, event):
        """Custom paint for gradient cell."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Calculate color based on intensity
        # White -> Yellow -> Orange -> Red
        if self._intensity <= 0:
            color = QColor(250, 250, 250)  # Light gray for zero
        elif self._intensity < 0.33:
            # White to Yellow
            t = self._intensity / 0.33
            color = QColor(
                255,
                255,
                int(255 * (1 - t)),
            )
        elif self._intensity < 0.66:
            # Yellow to Orange
            t = (self._intensity - 0.33) / 0.33
            color = QColor(
                255,
                int(255 - 55 * t),
                0,
            )
        else:
            # Orange to Red
            t = (self._intensity - 0.66) / 0.34
            color = QColor(
                255,
                int(200 - 150 * t),
                int(50 * (1 - t)),
            )

        # Fill background
        painter.fillRect(self.rect(), color)

        # Draw count text if non-zero
        if self._count > 0:
            painter.setPen(Qt.black if self._intensity < 0.5 else Qt.white)
            font = QFont()
            font.setPointSize(9)
            painter.setFont(font)
            painter.drawText(self.rect(), Qt.AlignCenter, str(self._count))

        painter.end()


class BreadcrumbBar(QWidget):
    """Breadcrumb navigation bar."""

    path_clicked = Signal(int)  # Index of clicked path segment

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._segments: List[str] = []

    def set_path(self, segments: List[str]):
        """Set the breadcrumb path."""
        self._segments = segments
        self._rebuild()

    def _rebuild(self):
        """Rebuild breadcrumb buttons."""
        # Clear existing
        while self._layout.count():
            item = self._layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for i, segment in enumerate(self._segments):
            if i > 0:
                sep = QLabel(">")
                sep.setStyleSheet("color: #666;")
                self._layout.addWidget(sep)

            btn = QPushButton(segment)
            btn.setFlat(True)
            btn.setStyleSheet("""
                QPushButton {
                    color: #0066cc;
                    text-decoration: underline;
                    border: none;
                    padding: 2px 4px;
                }
                QPushButton:hover {
                    color: #0044aa;
                }
            """)
            btn.clicked.connect(lambda checked, idx=i: self.path_clicked.emit(idx))
            self._layout.addWidget(btn)

        self._layout.addStretch()


class DashboardWidget(QWidget):
    """
    Hierarchical drill-down heatmap dashboard.

    Shows entity distribution across sources/buckets/folders with
    click-to-drill-down navigation.
    """

    # Signal when user clicks a file path at deepest level
    file_selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        # Data
        self._root = HeatmapNode(name="All Sources", path="")
        self._current_node: HeatmapNode = self._root
        self._path_stack: List[HeatmapNode] = [self._root]
        self._entity_types: List[str] = DEFAULT_ENTITY_TYPES.copy()
        self._scan_results: List[Dict[str, Any]] = []
        self._last_results_hash: int = 0  # Track if results changed

        self._setup_ui()

    def _setup_ui(self):
        """Setup the dashboard UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Header with breadcrumbs and stats
        header = QFrame()
        header.setFrameShape(QFrame.StyledPanel)
        header_layout = QHBoxLayout(header)

        self._breadcrumb = BreadcrumbBar()
        self._breadcrumb.path_clicked.connect(self._on_breadcrumb_click)
        header_layout.addWidget(self._breadcrumb, stretch=1)

        self._stats_label = QLabel()
        self._stats_label.setStyleSheet("color: #666;")
        header_layout.addWidget(self._stats_label)

        layout.addWidget(header)

        # Heatmap table
        self._table = QTableWidget()
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.cellDoubleClicked.connect(self._on_cell_double_click)
        self._table.verticalHeader().setVisible(False)

        layout.addWidget(self._table, stretch=1)

        # Legend
        self._setup_legend(layout)

        # Initial update
        self._update_breadcrumb()
        self._rebuild_table()

    def _setup_legend(self, layout: QVBoxLayout):
        """Setup color legend and add-column button."""
        legend = QWidget()
        legend_layout = QHBoxLayout(legend)
        legend_layout.setContentsMargins(0, 4, 0, 0)

        legend_layout.addWidget(QLabel("Intensity:"))

        for intensity, label in [(0, "None"), (0.25, "Low"), (0.5, "Med"), (0.75, "High"), (1.0, "Crit")]:
            cell = HeatmapCell(intensity, 0)
            cell.setFixedSize(30, 18)
            legend_layout.addWidget(cell)
            legend_layout.addWidget(QLabel(label))

        legend_layout.addStretch()

        self._add_col_btn = QPushButton("+ Column")
        self._add_col_btn.clicked.connect(self._on_add_entity_type)
        legend_layout.addWidget(self._add_col_btn)

        layout.addWidget(legend)

    def set_results(self, results: List[Dict[str, Any]]):
        """Set scan results and rebuild the heatmap (only if changed)."""
        # Quick check: if same length and same paths, skip rebuild
        results_hash = len(results)
        if results:
            # Include first and last path in hash for change detection
            results_hash = hash((len(results), results[0].get("path"), results[-1].get("path")))

        if results_hash == self._last_results_hash and len(results) == len(self._scan_results):
            return  # No change, skip expensive rebuild

        self._last_results_hash = results_hash
        self._scan_results = results
        self._build_hierarchy()
        self._navigate_to(self._root)

    def _build_hierarchy(self):
        """Build hierarchical data from scan results."""
        self._root = HeatmapNode(name="All Sources", path="")

        for result in self._scan_results:
            path = result.get("path", "")
            if not path:
                continue

            entities = result.get("entities", {})
            score = result.get("score", 0)

            # Determine source type
            if path.startswith("s3://"):
                source_type = "S3"
                # Parse s3://bucket/prefix/path
                parts = path[5:].split("/")
                bucket = parts[0] if parts else "unknown"
                sub_parts = parts[1:] if len(parts) > 1 else []
            elif path.startswith("\\\\"):
                source_type = "SMB"
                parts = path[2:].split("\\")
                bucket = parts[0] if parts else "unknown"
                sub_parts = parts[1:] if len(parts) > 1 else []
            else:
                source_type = "Local"
                # Use first directory component as "bucket"
                p = Path(path)
                parts = p.parts
                if len(parts) > 1:
                    bucket = parts[1] if parts[0] == "/" else parts[0]
                    sub_parts = list(parts[2:]) if parts[0] == "/" else list(parts[1:])
                else:
                    bucket = str(p)
                    sub_parts = []

            # Build hierarchy: Source -> Bucket -> Folders -> File
            # Add to source node
            if source_type not in self._root.children:
                self._root.children[source_type] = HeatmapNode(
                    name=source_type,
                    path=source_type
                )
            source_node = self._root.children[source_type]

            # Add to bucket node
            if bucket not in source_node.children:
                source_node.children[bucket] = HeatmapNode(
                    name=bucket,
                    path=f"{source_type}/{bucket}"
                )
            bucket_node = source_node.children[bucket]

            # Add to folder hierarchy (up to 2 levels deep for display)
            current_node = bucket_node
            for i, part in enumerate(sub_parts[:-1] if sub_parts else []):
                if i >= 2:  # Limit depth
                    break
                folder_path = f"{current_node.path}/{part}"
                if part not in current_node.children:
                    current_node.children[part] = HeatmapNode(
                        name=part,
                        path=folder_path
                    )
                current_node = current_node.children[part]

            # Add file as leaf node
            filename = Path(path).name
            if filename not in current_node.children:
                current_node.children[filename] = HeatmapNode(
                    name=filename,
                    path=path  # Full original path for files
                )
            file_node = current_node.children[filename]

            # Aggregate entity counts up the tree
            for entity_type, count in entities.items():
                file_node.add_entity(entity_type, count)
                current_node.add_entity(entity_type, count)
                bucket_node.add_entity(entity_type, count)
                source_node.add_entity(entity_type, count)
                self._root.add_entity(entity_type, count)

            # Aggregate scores and file counts
            file_node.total_score = score
            file_node.file_count = 1

            # Propagate up
            for node in [current_node, bucket_node, source_node, self._root]:
                node.total_score += score
                node.file_count += 1

    def _navigate_to(self, node: HeatmapNode):
        """Navigate to a node."""
        self._current_node = node

        # Rebuild path stack
        self._path_stack = [self._root]
        if node != self._root:
            # Find path from root to node
            path_parts = node.path.split("/") if node.path else []
            current = self._root
            for part in path_parts:
                if part in current.children:
                    current = current.children[part]
                    self._path_stack.append(current)

        self._update_breadcrumb()
        self._rebuild_table()

    def _update_breadcrumb(self):
        """Update breadcrumb display."""
        segments = [node.name for node in self._path_stack]
        self._breadcrumb.set_path(segments)

        # Update stats
        node = self._current_node
        self._stats_label.setText(
            f"{node.file_count} files | "
            f"{node.total_entities} entities | "
            f"Score: {node.total_score}"
        )

    def _rebuild_table(self):
        """Rebuild the heatmap table."""
        node = self._current_node
        children = list(node.children.values())

        # Sort by total entities (most risky first)
        children.sort(key=lambda n: n.total_entities, reverse=True)

        # Calculate max counts for intensity scaling
        max_counts = {}
        for entity_type in self._entity_types:
            max_count = max((c.entity_counts.get(entity_type, 0) for c in children), default=1)
            max_counts[entity_type] = max(1, max_count)

        # Setup table
        self._table.clear()
        self._table.setColumnCount(len(self._entity_types) + 2)  # Name + entities + total
        self._table.setRowCount(len(children))

        # Headers
        headers = ["Name"] + self._entity_types + ["Total"]
        self._table.setHorizontalHeaderLabels(headers)

        # Column widths
        self._table.setColumnWidth(0, 200)
        for i in range(1, len(self._entity_types) + 1):
            self._table.setColumnWidth(i, 70)
        self._table.setColumnWidth(len(self._entity_types) + 1, 60)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)

        # Populate rows
        for row, child in enumerate(children):
            # Name column
            name_item = QTableWidgetItem(child.name)
            name_item.setData(Qt.UserRole, child)  # Store node for drill-down

            # Add expand indicator if has children
            if child.children:
                name_item.setText(f"▸ {child.name}")

            self._table.setItem(row, 0, name_item)

            # Entity columns
            for col, entity_type in enumerate(self._entity_types, start=1):
                count = child.entity_counts.get(entity_type, 0)
                intensity = child.get_intensity(entity_type, max_counts[entity_type])

                # Create colored cell
                item = QTableWidgetItem(str(count) if count > 0 else "")
                item.setTextAlignment(Qt.AlignCenter)

                # Set background color
                color = self._intensity_to_color(intensity)
                item.setBackground(QBrush(color))

                # Text color
                if intensity > 0.5:
                    item.setForeground(QBrush(Qt.white))

                self._table.setItem(row, col, item)

            # Total column
            total_item = QTableWidgetItem(str(child.total_entities))
            total_item.setTextAlignment(Qt.AlignCenter)
            total_item.setFont(QFont("", -1, QFont.Bold))
            self._table.setItem(row, len(self._entity_types) + 1, total_item)

    def _intensity_to_color(self, intensity: float) -> QColor:
        """Convert intensity (0-1) to color."""
        if intensity <= 0:
            return QColor(250, 250, 250)
        elif intensity < 0.33:
            t = intensity / 0.33
            return QColor(255, 255, int(255 * (1 - t)))
        elif intensity < 0.66:
            t = (intensity - 0.33) / 0.33
            return QColor(255, int(255 - 55 * t), 0)
        else:
            t = (intensity - 0.66) / 0.34
            return QColor(255, int(200 - 150 * t), int(50 * (1 - t)))

    def _on_cell_double_click(self, row: int, col: int):
        """Handle double-click to drill down."""
        item = self._table.item(row, 0)
        if not item:
            return

        node = item.data(Qt.UserRole)
        if not isinstance(node, HeatmapNode):
            return

        if node.children:
            # Drill down
            self._navigate_to(node)
        else:
            # Leaf node (file) - emit signal
            self.file_selected.emit(node.path)

    def _on_breadcrumb_click(self, index: int):
        """Handle breadcrumb click to go back up."""
        if index < len(self._path_stack):
            self._navigate_to(self._path_stack[index])

    def _on_add_entity_type(self):
        """Show menu to add entity type column."""
        from openlabels.adapters.scanner.types import KNOWN_ENTITY_TYPES

        menu = QMenu(self)
        available = sorted(set(KNOWN_ENTITY_TYPES) - set(self._entity_types))

        # Add entity types found in data
        for result in self._scan_results:
            for et in result.get("entities", {}).keys():
                if et not in self._entity_types and et not in available:
                    available.append(et)
        available.sort()

        for et in available[:30]:
            action = menu.addAction(et)
            action.triggered.connect(lambda checked, e=et: self._add_entity_column(e))

        menu.exec(self._add_col_btn.mapToGlobal(self._add_col_btn.rect().bottomLeft()))

    def _add_entity_column(self, entity_type: str):
        """Add an entity type column."""
        if entity_type not in self._entity_types:
            self._entity_types.append(entity_type)
            self._rebuild_table()

    def remove_entity_column(self, entity_type: str):
        """Remove an entity type column."""
        if entity_type in self._entity_types:
            self._entity_types.remove(entity_type)
            self._rebuild_table()

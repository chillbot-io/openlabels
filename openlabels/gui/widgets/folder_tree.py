"""
Folder tree widget.

Displays a hierarchical view of folders with lazy loading.
"""

from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QTreeView,
    QVBoxLayout,
    QWidget,
    QFileSystemModel,
)
from PySide6.QtGui import QStandardItemModel, QStandardItem, QIcon
from PySide6.QtCore import Signal, Qt, QDir


class FolderTreeWidget(QWidget):
    """Widget displaying folder tree structure."""

    # Signals
    folder_selected = Signal(str)  # Emitted when a folder is selected

    def __init__(self, parent=None):
        super().__init__(parent)
        self._root_path: Optional[str] = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 4, 0)  # Small right margin for panel separation
        layout.setSpacing(0)

        # Tree view - no header for cleaner look
        self._tree = QTreeView()
        self._tree.setHeaderHidden(True)
        self._tree.setAnimated(True)
        self._tree.setIndentation(16)
        layout.addWidget(self._tree)

        # File system model for directory navigation
        self._model = QFileSystemModel()
        self._model.setFilter(QDir.AllDirs | QDir.NoDotAndDotDot)
        self._model.setRootPath("")

        self._tree.setModel(self._model)

        # Hide all columns except name
        for i in range(1, self._model.columnCount()):
            self._tree.hideColumn(i)

        # Connect selection change
        self._tree.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self._tree.doubleClicked.connect(self._on_double_clicked)

    def set_root_path(self, path: str):
        """Set the root path for the tree."""
        self._root_path = path
        path_obj = Path(path)

        if not path_obj.exists():
            self.clear()
            return

        # Set root index
        root_index = self._model.setRootPath(path)
        self._tree.setRootIndex(root_index)

        # Expand the first level
        self._tree.expandToDepth(0)

    def clear(self):
        """Clear the tree."""
        self._root_path = None
        self._model.setRootPath("")
        self._tree.setRootIndex(self._model.index(""))

    def _on_selection_changed(self, selected, deselected):
        """Handle selection change."""
        indexes = selected.indexes()
        if indexes:
            index = indexes[0]
            path = self._model.filePath(index)
            if path:
                self.folder_selected.emit(path)

    def _on_double_clicked(self, index):
        """Handle double-click on a folder."""
        path = self._model.filePath(index)
        if path:
            self.folder_selected.emit(path)

    def get_selected_path(self) -> Optional[str]:
        """Get the currently selected folder path."""
        indexes = self._tree.selectedIndexes()
        if indexes:
            return self._model.filePath(indexes[0])
        return None

    def select_path(self, path: str):
        """Select a specific path in the tree."""
        index = self._model.index(path)
        if index.isValid():
            self._tree.setCurrentIndex(index)
            self._tree.scrollTo(index)

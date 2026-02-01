"""
Main window for the OpenLabels GUI.
"""

from typing import Optional

try:
    from PySide6.QtWidgets import (
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QTabWidget,
        QLabel,
        QStatusBar,
        QMenuBar,
        QMenu,
        QToolBar,
    )
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QAction

    PYSIDE_AVAILABLE = True
except ImportError:
    PYSIDE_AVAILABLE = False


if PYSIDE_AVAILABLE:

    class MainWindow(QMainWindow):
        """Main application window."""

        def __init__(self, server_url: str = "http://localhost:8000"):
            super().__init__()

            self.server_url = server_url

            self.setWindowTitle("OpenLabels")
            self.setMinimumSize(1200, 800)

            self._setup_menu()
            self._setup_toolbar()
            self._setup_ui()
            self._setup_statusbar()

        def _setup_menu(self) -> None:
            """Set up the menu bar."""
            menubar = self.menuBar()

            # File menu
            file_menu = menubar.addMenu("&File")

            new_scan_action = QAction("&New Scan", self)
            new_scan_action.setShortcut("Ctrl+N")
            file_menu.addAction(new_scan_action)

            file_menu.addSeparator()

            exit_action = QAction("E&xit", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)

            # Edit menu
            edit_menu = menubar.addMenu("&Edit")

            settings_action = QAction("&Settings", self)
            settings_action.setShortcut("Ctrl+,")
            edit_menu.addAction(settings_action)

            # View menu
            view_menu = menubar.addMenu("&View")

            refresh_action = QAction("&Refresh", self)
            refresh_action.setShortcut("F5")
            view_menu.addAction(refresh_action)

            # Help menu
            help_menu = menubar.addMenu("&Help")

            about_action = QAction("&About", self)
            help_menu.addAction(about_action)

            docs_action = QAction("&Documentation", self)
            docs_action.setShortcut("F1")
            help_menu.addAction(docs_action)

            help_menu.addSeparator()

            update_action = QAction("Check for &Updates", self)
            help_menu.addAction(update_action)

        def _setup_toolbar(self) -> None:
            """Set up the toolbar."""
            toolbar = QToolBar("Main Toolbar")
            toolbar.setMovable(False)
            self.addToolBar(toolbar)

            # Will add toolbar actions as we implement widgets

        def _setup_ui(self) -> None:
            """Set up the main UI."""
            central_widget = QWidget()
            self.setCentralWidget(central_widget)

            layout = QVBoxLayout(central_widget)

            # Tab widget for main screens
            self.tabs = QTabWidget()
            layout.addWidget(self.tabs)

            # Add placeholder tabs
            self.tabs.addTab(self._create_dashboard_tab(), "Dashboard")
            self.tabs.addTab(self._create_scans_tab(), "Scans")
            self.tabs.addTab(self._create_results_tab(), "Results")
            self.tabs.addTab(self._create_schedules_tab(), "Schedules")
            self.tabs.addTab(self._create_labels_tab(), "Labels")
            self.tabs.addTab(self._create_settings_tab(), "Settings")

        def _setup_statusbar(self) -> None:
            """Set up the status bar."""
            statusbar = QStatusBar()
            self.setStatusBar(statusbar)

            # Connection status
            self.connection_label = QLabel(f"Connected to {self.server_url}")
            statusbar.addWidget(self.connection_label)

            # Spacer
            statusbar.addWidget(QWidget(), 1)

            # Version
            from openlabels import __version__
            version_label = QLabel(f"v{__version__}")
            statusbar.addPermanentWidget(version_label)

        def _create_dashboard_tab(self) -> QWidget:
            """Create the dashboard tab."""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.addWidget(QLabel("Dashboard - Coming Soon"))
            layout.addStretch()
            return widget

        def _create_scans_tab(self) -> QWidget:
            """Create the scans tab."""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.addWidget(QLabel("Scans - Coming Soon"))
            layout.addStretch()
            return widget

        def _create_results_tab(self) -> QWidget:
            """Create the results tab."""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.addWidget(QLabel("Results - Coming Soon"))
            layout.addStretch()
            return widget

        def _create_schedules_tab(self) -> QWidget:
            """Create the schedules tab."""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.addWidget(QLabel("Schedules - Coming Soon"))
            layout.addStretch()
            return widget

        def _create_labels_tab(self) -> QWidget:
            """Create the labels tab."""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.addWidget(QLabel("Labels - Coming Soon"))
            layout.addStretch()
            return widget

        def _create_settings_tab(self) -> QWidget:
            """Create the settings tab."""
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.addWidget(QLabel("Settings - Coming Soon"))
            layout.addStretch()
            return widget

else:
    # Fallback when PySide6 is not available
    class MainWindow:
        def __init__(self, *args, **kwargs):
            raise ImportError("PySide6 is required for the GUI")

"""
Log viewer window for OpenLabels.

Provides a Qt-based log viewer that streams Docker container logs
in real time via ``docker compose logs -f``, with search, filtering,
and auto-scroll capabilities.

Requires: PySide6
"""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)

try:
    from PySide6.QtCore import QObject, Qt, QThread, Signal
    from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
    from PySide6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPlainTextEdit,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False


if PYSIDE6_AVAILABLE:

    class _LogReader(QObject):
        """Background worker that reads log lines from a subprocess."""

        line_received = Signal(str)
        error = Signal(str)
        finished = Signal()

        def __init__(self, command: list):
            super().__init__()
            self._command = command
            self._running = True

        def run(self):
            try:
                proc = subprocess.Popen(
                    self._command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                while self._running:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    self.line_received.emit(line.rstrip("\n"))
                proc.terminate()
                proc.wait(timeout=5)
            except Exception as e:
                self.error.emit(str(e))
            finally:
                self.finished.emit()

        def stop(self):
            self._running = False

    class LogViewer(QWidget):
        """Real-time Docker log viewer window."""

        # Log level colours for visual distinction
        _LEVEL_COLORS = {
            "ERROR": QColor(244, 67, 54),
            "WARNING": QColor(255, 152, 0),
            "INFO": QColor(76, 175, 80),
            "DEBUG": QColor(158, 158, 158),
        }

        MAX_LINES = 10_000

        def __init__(
            self,
            project_name: str = "openlabels",
            parent: QWidget | None = None,
        ):
            super().__init__(parent)
            self._project_name = project_name
            self._reader: _LogReader | None = None
            self._thread: QThread | None = None
            self._auto_scroll = True
            self._line_count = 0

            self.setWindowTitle("OpenLabels – Log Viewer")
            self.resize(900, 600)
            self._build_ui()

        def _build_ui(self):
            layout = QVBoxLayout(self)

            # -- Toolbar --
            toolbar = QHBoxLayout()

            # Service filter
            toolbar.addWidget(QLabel("Service:"))
            self.service_combo = QComboBox()
            self.service_combo.addItems(["All", "api", "worker", "scheduler", "db"])
            self.service_combo.currentTextChanged.connect(self._restart_stream)
            toolbar.addWidget(self.service_combo)

            toolbar.addSpacing(12)

            # Search
            toolbar.addWidget(QLabel("Search:"))
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("Filter log lines...")
            self.search_input.textChanged.connect(self._highlight_search)
            toolbar.addWidget(self.search_input)

            # Auto-scroll
            self.auto_scroll_cb = QCheckBox("Auto-scroll")
            self.auto_scroll_cb.setChecked(True)
            self.auto_scroll_cb.toggled.connect(self._set_auto_scroll)
            toolbar.addWidget(self.auto_scroll_cb)

            # Clear
            clear_btn = QPushButton("Clear")
            clear_btn.clicked.connect(self._clear_logs)
            toolbar.addWidget(clear_btn)

            layout.addLayout(toolbar)

            # -- Log output --
            self.log_output = QPlainTextEdit()
            self.log_output.setReadOnly(True)
            self.log_output.setMaximumBlockCount(self.MAX_LINES)
            font = QFont("Consolas", 9)
            font.setStyleHint(QFont.Monospace)
            self.log_output.setFont(font)
            layout.addWidget(self.log_output)

            # -- Status bar --
            self.status_label = QLabel("Connecting...")
            layout.addWidget(self.status_label)

        # --------------------------------------------------------------
        # Stream management
        # --------------------------------------------------------------

        def start(self):
            """Start streaming logs."""
            self._stop_stream()
            cmd = ["docker", "compose", "-p", self._project_name, "logs", "-f", "--tail", "200"]

            service = self.service_combo.currentText()
            if service != "All":
                cmd.append(service)

            reader = _LogReader(cmd)
            thread = QThread()
            reader.moveToThread(thread)

            thread.started.connect(reader.run)
            reader.line_received.connect(self._append_line)
            reader.error.connect(self._on_error)
            reader.finished.connect(thread.quit)
            reader.finished.connect(reader.deleteLater)
            thread.finished.connect(thread.deleteLater)

            self._reader = reader
            self._thread = thread
            thread.start()
            self.status_label.setText("Streaming logs...")

        def _stop_stream(self):
            if self._reader:
                self._reader.stop()
                self._reader = None
            if self._thread and self._thread.isRunning():
                self._thread.quit()
                self._thread.wait(2000)
            self._thread = None

        def _restart_stream(self):
            self.start()

        # --------------------------------------------------------------
        # Log display
        # --------------------------------------------------------------

        def _append_line(self, line: str):
            self.log_output.appendPlainText(line)
            self._line_count += 1
            if self._auto_scroll:
                scrollbar = self.log_output.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())

        def _on_error(self, message: str):
            self.status_label.setText(f"Error: {message}")
            logger.warning("Log viewer stream error: %s", message)

        def _clear_logs(self):
            self.log_output.clear()
            self._line_count = 0

        def _set_auto_scroll(self, enabled: bool):
            self._auto_scroll = enabled

        def _highlight_search(self, text: str):
            """Highlight all occurrences of the search term."""
            # Reset formatting
            cursor = self.log_output.textCursor()
            cursor.select(QTextCursor.Document)
            default_fmt = QTextCharFormat()
            cursor.setCharFormat(default_fmt)
            cursor.clearSelection()

            if not text:
                return

            # Highlight matches
            highlight_fmt = QTextCharFormat()
            highlight_fmt.setBackground(QColor(255, 235, 59))  # Yellow

            document = self.log_output.document()
            cursor = QTextCursor(document)
            while True:
                cursor = document.find(text, cursor)
                if cursor.isNull():
                    break
                cursor.mergeCharFormat(highlight_fmt)

        # --------------------------------------------------------------
        # Lifecycle
        # --------------------------------------------------------------

        def showEvent(self, event):
            super().showEvent(event)
            self.start()

        def closeEvent(self, event):
            self._stop_stream()
            super().closeEvent(event)

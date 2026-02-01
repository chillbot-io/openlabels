"""
Real-time file monitoring service.
"""

import os
from typing import Set, Dict, Optional

from PySide6.QtCore import QObject, Signal, QFileSystemWatcher, QTimer


# Default extensions to monitor
DEFAULT_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml",
    ".log", ".md", ".doc", ".docx", ".xls", ".xlsx",
    ".pdf", ".rtf", ".html", ".htm", ".sql", ".db",
    ".env", ".ini", ".cfg", ".conf", ".config",
}


class FileWatcher(QObject):
    """Watches directories for file changes and emits signals."""

    file_changed = Signal(str)
    file_deleted = Signal(str)
    watching_started = Signal(str)
    watching_stopped = Signal(str)
    error = Signal(str)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)

        self._watcher = QFileSystemWatcher(self)
        self._watcher.directoryChanged.connect(self._on_directory_changed)
        self._watcher.fileChanged.connect(self._on_file_changed)

        self._watched_dirs: Set[str] = set()
        self._dir_contents: Dict[str, Dict[str, float]] = {}
        self._extensions = DEFAULT_EXTENSIONS.copy()

        self._pending_changes: Set[str] = set()
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(500)
        self._debounce_timer.timeout.connect(self._process_pending_changes)

        self._rescan_timer = QTimer(self)
        self._rescan_timer.setInterval(5000)
        self._rescan_timer.timeout.connect(self._rescan_directories)

        self._enabled = False

    @property
    def is_watching(self) -> bool:
        """Check if actively watching any directories."""
        return self._enabled and len(self._watched_dirs) > 0

    @property
    def watched_paths(self) -> Set[str]:
        """Get set of watched directory paths."""
        return self._watched_dirs.copy()

    def start_watching(self, path: str, recursive: bool = True) -> bool:
        """Start watching a directory for changes."""
        path = os.path.abspath(path)

        if not os.path.isdir(path):
            self.error.emit(f"Not a directory: {path}")
            return False

        try:
            # Add the main directory
            self._add_directory(path)

            # Add subdirectories if recursive
            if recursive:
                for root, dirs, files in os.walk(path):
                    # Skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    for d in dirs:
                        subdir = os.path.join(root, d)
                        self._add_directory(subdir)

            self._enabled = True
            self._rescan_timer.start()
            self.watching_started.emit(path)
            return True

        except Exception as e:
            self.error.emit(f"Failed to watch {path}: {e}")
            return False

    def _add_directory(self, path: str) -> None:
        """Add a single directory to watch."""
        if path in self._watched_dirs:
            return

        # Snapshot current contents
        self._dir_contents[path] = self._snapshot_directory(path)

        # Add to Qt watcher
        self._watcher.addPath(path)
        self._watched_dirs.add(path)

    def _snapshot_directory(self, path: str) -> Dict[str, float]:
        """Get snapshot of files and their modification times."""
        contents = {}
        try:
            for entry in os.scandir(path):
                if entry.is_file() and self._should_watch_file(entry.name):
                    try:
                        contents[entry.path] = entry.stat().st_mtime
                    except OSError:
                        pass
        except OSError:
            pass
        return contents

    def _should_watch_file(self, filename: str) -> bool:
        """Check if a file should be watched based on extension."""
        if filename.startswith("."):
            return False
        ext = os.path.splitext(filename)[1].lower()
        return ext in self._extensions

    def stop_watching(self, path: Optional[str] = None) -> None:
        """Stop watching a directory (or all if path is None)."""
        if path is None:
            # Stop all
            paths_to_remove = list(self._watched_dirs)
            for p in paths_to_remove:
                self._remove_directory(p)
            self._rescan_timer.stop()
            self._enabled = False
        else:
            path = os.path.abspath(path)
            # Remove this path and all subdirs
            paths_to_remove = [p for p in self._watched_dirs if p.startswith(path)]
            for p in paths_to_remove:
                self._remove_directory(p)

            if not self._watched_dirs:
                self._rescan_timer.stop()
                self._enabled = False

            self.watching_stopped.emit(path)

    def _remove_directory(self, path: str) -> None:
        """Remove a single directory from watch."""
        if path not in self._watched_dirs:
            return

        self._watcher.removePath(path)
        self._watched_dirs.discard(path)
        self._dir_contents.pop(path, None)

    def _on_directory_changed(self, path: str) -> None:
        """Handle directory change notification."""
        if not self._enabled:
            return

        # Compare current contents with snapshot
        old_contents = self._dir_contents.get(path, {})
        new_contents = self._snapshot_directory(path)

        # Find new/modified files
        for filepath, mtime in new_contents.items():
            old_mtime = old_contents.get(filepath)
            if old_mtime is None or mtime > old_mtime:
                self._pending_changes.add(filepath)

        # Find deleted files
        for filepath in old_contents:
            if filepath not in new_contents:
                self.file_deleted.emit(filepath)

        # Update snapshot
        self._dir_contents[path] = new_contents

        # Start debounce timer
        if self._pending_changes:
            self._debounce_timer.start()

    def _on_file_changed(self, path: str) -> None:
        """Handle direct file change notification."""
        if not self._enabled:
            return

        if os.path.exists(path):
            self._pending_changes.add(path)
            self._debounce_timer.start()
        else:
            self.file_deleted.emit(path)

    def _process_pending_changes(self) -> None:
        """Process pending file changes after debounce."""
        changes = self._pending_changes.copy()
        self._pending_changes.clear()

        for filepath in changes:
            if os.path.exists(filepath):
                self.file_changed.emit(filepath)

    def _rescan_directories(self) -> None:
        """Periodic rescan to catch any missed changes."""
        if not self._enabled:
            return

        for path in list(self._watched_dirs):
            if not os.path.exists(path):
                self._remove_directory(path)
                continue

            # Check for new subdirectories
            try:
                for entry in os.scandir(path):
                    if entry.is_dir() and not entry.name.startswith("."):
                        subdir = entry.path
                        if subdir not in self._watched_dirs:
                            self._add_directory(subdir)
            except OSError:
                pass

            # Check for changes
            self._on_directory_changed(path)

    def add_extension(self, ext: str) -> None:
        """Add a file extension to watch (include the dot)."""
        self._extensions.add(ext.lower())

    def remove_extension(self, ext: str) -> None:
        """Remove a file extension from watch list."""
        self._extensions.discard(ext.lower())

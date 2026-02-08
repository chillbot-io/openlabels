"""
Windows-specific components for OpenLabels.

This package contains:
- Windows service wrapper
- System tray application
- Log viewer
- Docker management
- Installer hooks

These modules depend on Windows-only packages (PySide6, pywin32).
Imports are lazy so the package can be imported on any platform
without raising ImportErrors.
"""

__all__ = ["OpenLabelsService", "SystemTrayApp", "LogViewer"]


def __getattr__(name: str):
    if name == "OpenLabelsService":
        from openlabels.windows.service import OpenLabelsService
        return OpenLabelsService
    if name == "SystemTrayApp":
        from openlabels.windows.tray import SystemTrayApp
        return SystemTrayApp
    if name == "LogViewer":
        from openlabels.windows.log_viewer import LogViewer
        return LogViewer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""
Windows-specific components for OpenLabels.

This package contains:
- Windows service wrapper
- Docker management
- Installer hooks

These modules depend on Windows-only packages (pywin32).
Imports are lazy so the package can be imported on any platform
without raising ImportErrors.
"""

__all__ = ["OpenLabelsService"]


def __getattr__(name: str):
    if name == "OpenLabelsService":
        from openlabels.windows.service import OpenLabelsService
        return OpenLabelsService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

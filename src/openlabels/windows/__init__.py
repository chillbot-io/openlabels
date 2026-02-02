"""
Windows-specific components for OpenLabels.

This package contains:
- Windows service wrapper
- System tray application
- Docker management
- Installer hooks
"""

from openlabels.windows.service import OpenLabelsService
from openlabels.windows.tray import SystemTrayApp

__all__ = ["OpenLabelsService", "SystemTrayApp"]

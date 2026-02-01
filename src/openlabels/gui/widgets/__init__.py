"""
GUI widgets for OpenLabels.

Widgets:
- ScanWidget: Manage and monitor scans
- ResultsWidget: View and filter scan results
- DashboardWidget: Statistics and visualizations
"""

try:
    from .scan_widget import ScanWidget
    from .results_widget import ResultsWidget
    from .dashboard_widget import DashboardWidget, StatCard

    __all__ = [
        "ScanWidget",
        "ResultsWidget",
        "DashboardWidget",
        "StatCard",
    ]
except ImportError:
    # PySide6 not available
    __all__ = []

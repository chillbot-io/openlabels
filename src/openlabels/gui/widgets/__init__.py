"""
GUI widgets for OpenLabels.

Widgets:
- ScanWidget: Manage and monitor scans
- ResultsWidget: View and filter scan results
- DashboardWidget: Statistics and visualizations
- TargetsWidget: Manage scan targets
- SchedulesWidget: Configure automated scan schedules
- LabelsWidget: Manage sensitivity labels and auto-label rules
- FileDetailWidget: Context card showing file details and risk info
"""

try:
    from .scan_widget import ScanWidget
    from .results_widget import ResultsWidget
    from .dashboard_widget import DashboardWidget, StatCard
    from .targets_widget import TargetsWidget, TargetDialog
    from .schedules_widget import SchedulesWidget, ScheduleDialog
    from .labels_widget import LabelsWidget, LabelRuleDialog
    from .file_detail_widget import FileDetailWidget, RiskGauge

    __all__ = [
        "ScanWidget",
        "ResultsWidget",
        "DashboardWidget",
        "StatCard",
        "TargetsWidget",
        "TargetDialog",
        "SchedulesWidget",
        "ScheduleDialog",
        "LabelsWidget",
        "LabelRuleDialog",
        "FileDetailWidget",
        "RiskGauge",
    ]
except ImportError:
    # PySide6 not available
    __all__ = []

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
- SettingsWidget: Application settings and configuration
- MonitoringWidget: File access monitoring management
"""

try:
    from .charts_widget import ChartPanel, HeatMapChart, SensitiveDataChart
    from .dashboard_widget import DashboardWidget, StatCard
    from .file_detail_widget import FileDetailWidget, RiskGauge
    from .health_widget import HealthWidget, StatusIndicator
    from .labels_widget import LabelRuleDialog, LabelsWidget
    from .monitoring_widget import AddMonitoringDialog, MonitoringWidget
    from .results_widget import ResultsWidget
    from .scan_widget import ScanWidget
    from .schedules_widget import ScheduleDialog, SchedulesWidget
    from .settings_widget import SettingsWidget
    from .targets_widget import TargetDialog, TargetsWidget

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
        "SettingsWidget",
        "MonitoringWidget",
        "AddMonitoringDialog",
        "HeatMapChart",
        "SensitiveDataChart",
        "ChartPanel",
        "HealthWidget",
        "StatusIndicator",
    ]
except ImportError:
    # PySide6 or pyqtgraph not available
    __all__ = []

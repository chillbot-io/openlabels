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
    from .scan_widget import ScanWidget
    from .results_widget import ResultsWidget
    from .dashboard_widget import DashboardWidget, StatCard
    from .targets_widget import TargetsWidget, TargetDialog
    from .schedules_widget import SchedulesWidget, ScheduleDialog
    from .labels_widget import LabelsWidget, LabelRuleDialog
    from .file_detail_widget import FileDetailWidget, RiskGauge
    from .settings_widget import SettingsWidget
    from .monitoring_widget import MonitoringWidget, AddMonitoringDialog
    from .charts_widget import HeatMapChart, SensitiveDataChart, ChartPanel
    from .health_widget import HealthWidget, StatusIndicator

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

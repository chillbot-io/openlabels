"""
OpenLabels CLI commands.

Commands:
    scan        Scan files for sensitive data and compute risk scores
    read        Read embedded label from a file
    find        Find files matching filter criteria
    quarantine  Move matching files to quarantine location
    tag         Apply OpenLabels tags to files
    encrypt     Encrypt files matching filter criteria
    restrict    Restrict access permissions on files
    report      Generate risk reports (json, csv, html)
    heatmap     Display risk heatmap of directory structure
    shell       Interactive shell for exploring data risk
    health      Run system health checks
    gui         Launch the graphical user interface
    serve       Start the scanner API server
"""

from .scan import add_scan_parser, cmd_scan
from .read import add_read_parser, cmd_read
from .find import add_find_parser, cmd_find
from .quarantine import add_quarantine_parser, cmd_quarantine
from .tag import add_tag_parser, cmd_tag
from .encrypt import add_encrypt_parser, cmd_encrypt
from .restrict import add_restrict_parser, cmd_restrict
from .report import add_report_parser, cmd_report
from .heatmap import add_heatmap_parser, cmd_heatmap
from .shell import add_shell_parser, cmd_shell
from .health import add_health_parser, cmd_health
from .gui import add_gui_parser, cmd_gui
from .inventory import add_inventory_parser, cmd_inventory
from .config import add_config_parser, cmd_config
from .export import add_export_parser, cmd_export
from .serve import add_serve_parser, cmd_serve

__all__ = [
    # Parsers
    "add_scan_parser",
    "add_read_parser",
    "add_find_parser",
    "add_quarantine_parser",
    "add_tag_parser",
    "add_encrypt_parser",
    "add_restrict_parser",
    "add_report_parser",
    "add_heatmap_parser",
    "add_shell_parser",
    "add_health_parser",
    "add_gui_parser",
    "add_inventory_parser",
    "add_config_parser",
    "add_export_parser",
    "add_serve_parser",
    # Commands
    "cmd_scan",
    "cmd_read",
    "cmd_find",
    "cmd_quarantine",
    "cmd_tag",
    "cmd_encrypt",
    "cmd_restrict",
    "cmd_report",
    "cmd_heatmap",
    "cmd_shell",
    "cmd_health",
    "cmd_gui",
    "cmd_inventory",
    "cmd_config",
    "cmd_export",
    "cmd_serve",
]

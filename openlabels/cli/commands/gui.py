"""
OpenLabels GUI command.

Launch the graphical user interface.

Usage:
    openlabels gui
    openlabels gui --path /data
"""

import sys

from openlabels.cli.output import error


def cmd_gui(args) -> int:
    """Launch the OpenLabels GUI."""
    try:
        from openlabels.gui import launch_gui
    except ImportError as e:
        if "PySide6" in str(e):
            error("PySide6 is required for the GUI.")
            error("Install it with: pip install PySide6")
            return 1
        raise

    initial_path = getattr(args, "path", None)
    return launch_gui(initial_path=initial_path)


def add_gui_parser(subparsers):
    """Add the gui subparser."""
    parser = subparsers.add_parser(
        "gui",
        help="Launch the graphical user interface",
    )
    parser.add_argument(
        "--path", "-p",
        help="Initial path to load in the GUI",
    )
    parser.set_defaults(func=cmd_gui)

    return parser

"""
OpenLabels CLI - Command-line interface.

Labels are the primitive. Risk is derived.

Usage:
    openlabels scan <path>              # Scan files and embed labels
    openlabels read <file>              # Read embedded label from file
    openlabels scan ./data -r           # Scan recursively
    openlabels report ./data            # Generate HTML report
    openlabels gui                      # Launch desktop GUI
    openlabels --version                # Show version
"""

import argparse
import sys
from typing import List, Optional

from openlabels import __version__
from openlabels.logging_config import setup_logging, get_logger
from openlabels.cli.output import set_progress_enabled, echo, error
from openlabels.shutdown import install_signal_handlers

logger = get_logger(__name__)


def cmd_version(args):
    """Show version information."""
    echo(f"openlabels {__version__}")
    echo("Scan files for sensitive data. Score risk.")
    echo("")
    echo("Quick start:")
    echo("  openlabels scan ./data        Scan and embed labels")
    echo("  openlabels read document.pdf  Read embedded label")
    echo("  openlabels scan ./data -r     Scan recursively")
    echo("  openlabels report ./data      Generate HTML report")
    echo("  openlabels gui                Launch desktop GUI")
    echo("")
    echo("Run 'openlabels --help' for all options.")


def main(argv: Optional[List[str]] = None):
    """Main CLI entry point."""
    # Install signal handlers for graceful shutdown (Ctrl+C, SIGTERM)
    install_signal_handlers()

    parser = argparse.ArgumentParser(
        prog="openlabels",
        description="OpenLabels - Scan files for sensitive data. Score risk.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  openlabels scan ./data              Scan and embed labels
  openlabels read document.pdf        Read embedded label
  openlabels scan ./data -r           Scan recursively
  openlabels report ./data            Generate HTML report
  openlabels gui                      Launch desktop GUI
        """,
    )
    parser.add_argument(
        "--version", "-V",
        action="store_true",
        help="Show version and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show errors",
    )
    # Hidden power-user options
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-audit",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Core commands
    from openlabels.cli.commands import (
        add_scan_parser,
        add_read_parser,
        add_find_parser,
        add_quarantine_parser,
        add_tag_parser,
        add_report_parser,
        add_heatmap_parser,
        add_gui_parser,
        add_health_parser,
        add_serve_parser,
    )

    add_scan_parser(subparsers)
    add_read_parser(subparsers)
    add_find_parser(subparsers)
    add_quarantine_parser(subparsers)
    add_tag_parser(subparsers)
    add_report_parser(subparsers)
    add_heatmap_parser(subparsers)
    add_gui_parser(subparsers)
    add_health_parser(subparsers)
    add_serve_parser(subparsers)

    args = parser.parse_args(argv)

    if args.version:
        cmd_version(args)
        return

    # Configure logging
    setup_logging(
        verbose=getattr(args, "verbose", False),
        quiet=getattr(args, "quiet", False),
        log_file=getattr(args, "log_file", None),
        audit_log=getattr(args, "audit_log", None),
        no_audit=getattr(args, "no_audit", False),
    )

    # Configure progress bars
    if getattr(args, "no_progress", False):
        set_progress_enabled(False)

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Execute command with error handling
    try:
        result = args.func(args)

        # Handle return code
        if isinstance(result, int):
            sys.exit(result)

    except KeyboardInterrupt:
        # User pressed Ctrl+C - exit quietly
        sys.exit(130)

    except PermissionError as e:
        error(f"Permission denied: {e.filename or e}")
        sys.exit(1)

    except FileNotFoundError as e:
        error(f"File not found: {e.filename or e}")
        sys.exit(1)

    except Exception as e:
        # Unexpected error - show message without stack trace for users
        # Stack trace is available with --verbose
        if getattr(args, "verbose", False):
            logger.exception("Unexpected error")
        error(f"{type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

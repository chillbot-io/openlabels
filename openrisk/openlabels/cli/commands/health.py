"""
OpenLabels health command.

Run system health checks to verify components are functional.

Usage:
    openlabels health              # Run all checks
    openlabels health --json       # JSON output
    openlabels health --check detector  # Run specific check
"""

import json
from typing import Optional

from openlabels.health import HealthChecker, CheckStatus
from openlabels.cli.output import echo, error, warn, success, dim, console
from openlabels.logging_config import get_logger

logger = get_logger(__name__)


def _status_icon(status: CheckStatus) -> str:
    """Get status icon for check result."""
    icons = {
        CheckStatus.PASS: "[green]PASS[/green]",
        CheckStatus.FAIL: "[red]FAIL[/red]",
        CheckStatus.WARN: "[yellow]WARN[/yellow]",
        CheckStatus.SKIP: "[dim]SKIP[/dim]",
    }
    return icons.get(status, "[dim]????[/dim]")


def cmd_health(args) -> int:
    """Execute the health command."""
    checker = HealthChecker()

    logger.info("Starting health checks")

    # Run specific check or all checks
    if args.check:
        result = checker.run_check(args.check)
        if result is None:
            error(f"Unknown check: {args.check}")
            return 1
        report = type('Report', (), {'checks': [result], 'healthy': result.passed})()
    else:
        report = checker.run_all()

    # JSON output
    if args.json:
        echo(json.dumps(report.to_dict(), indent=2))
        return 0 if report.healthy else 1

    # Rich output
    console.print("\n[bold blue]OpenLabels Health Check[/bold blue]\n")

    for check in report.checks:
        status_str = _status_icon(check.status)
        console.print(f"  {status_str}  [bold]{check.name}[/bold]")
        console.print(f"       {check.message}")

        if check.error:
            console.print(f"       [red]Error: {check.error}[/red]")

        if args.verbose and check.details:
            for key, value in check.details.items():
                dim(f"       {key}: {value}")

        dim(f"       ({check.duration_ms:.1f}ms)")
        echo("")

    # Summary
    passed = len([c for c in report.checks if c.status == CheckStatus.PASS])
    failed = len([c for c in report.checks if c.status == CheckStatus.FAIL])
    warnings = len([c for c in report.checks if c.status == CheckStatus.WARN])

    echo("")
    if report.healthy:
        if warnings > 0:
            success(f"Health check passed with {warnings} warning(s)")
        else:
            success(f"All {passed} health checks passed")
    else:
        error(f"Health check failed: {failed} failure(s), {warnings} warning(s)")

    logger.info(f"Health check complete", extra={
        "healthy": report.healthy,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
    })

    return 0 if report.healthy else 1


def add_health_parser(subparsers):
    """Add the health subparser."""
    parser = subparsers.add_parser(
        "health",
        help="Run system health checks",
    )
    parser.add_argument(
        "--check", "-c",
        metavar="NAME",
        help="Run specific check (python_version, dependencies, detector, database, disk_space, temp_directory, audit_log)",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed check information",
    )
    parser.set_defaults(func=cmd_health)

    return parser

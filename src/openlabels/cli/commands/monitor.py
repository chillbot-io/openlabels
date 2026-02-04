"""
File access monitoring commands.
"""

import sys
from pathlib import Path

import click


@click.group()
def monitor():
    """File access monitoring commands."""
    pass


@monitor.command("enable")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--risk-tier", default="HIGH", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
@click.option("--audit-read/--no-audit-read", default=True, help="Audit read access")
@click.option("--audit-write/--no-audit-write", default=True, help="Audit write access")
def monitor_enable(file_path: str, risk_tier: str, audit_read: bool, audit_write: bool):
    """Enable access monitoring on a file.

    On Windows: Adds SACL audit rules to capture access events.
    On Linux: Adds auditd rules via auditctl.

    Prerequisites:
        Windows: "Audit object access" must be enabled in security policy
        Linux: auditd service must be running, requires root

    Examples:
        openlabels monitor enable ./sensitive.xlsx
        openlabels monitor enable ./secrets.json --risk-tier CRITICAL
    """
    from openlabels.monitoring import enable_monitoring

    path = Path(file_path)

    result = enable_monitoring(
        path=path,
        risk_tier=risk_tier,
        audit_read=audit_read,
        audit_write=audit_write,
    )

    if result.success:
        click.echo(f"Monitoring enabled: {path}")
        click.echo(f"  Risk tier: {risk_tier}")
        if result.sacl_enabled:
            click.echo("  SACL: enabled")
        if result.audit_rule_enabled:
            click.echo("  Audit rule: enabled")
        if result.message:
            click.echo(f"  Note: {result.message}")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@monitor.command("disable")
@click.argument("file_path", type=click.Path(exists=True))
def monitor_disable(file_path: str):
    """Disable access monitoring on a file.

    Removes the SACL (Windows) or audit rule (Linux).

    Examples:
        openlabels monitor disable ./sensitive.xlsx
    """
    from openlabels.monitoring import disable_monitoring

    path = Path(file_path)

    result = disable_monitoring(path=path)

    if result.success:
        click.echo(f"Monitoring disabled: {path}")
        if result.message:
            click.echo(f"  {result.message}")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@monitor.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def monitor_list(as_json: bool):
    """List all monitored files.

    Shows files that have been registered for access monitoring.

    Examples:
        openlabels monitor list
        openlabels monitor list --json
    """
    from openlabels.monitoring import get_watched_files

    watched = get_watched_files()

    if as_json:
        import json as json_mod
        output = [w.to_dict() for w in watched]
        click.echo(json_mod.dumps(output, indent=2, default=str))
    elif not watched:
        click.echo("No files currently monitored")
    else:
        click.echo(f"{'Path':<50} {'Risk':<10} {'Added':<20}")
        click.echo("-" * 80)
        for w in watched:
            path_str = str(w.path)[:49]
            added = w.added_at.strftime("%Y-%m-%d %H:%M") if w.added_at else "N/A"
            click.echo(f"{path_str:<50} {w.risk_tier:<10} {added:<20}")


@monitor.command("history")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--days", default=30, type=int, help="Number of days to look back")
@click.option("--limit", default=50, type=int, help="Maximum events to return")
@click.option("--include-system", is_flag=True, help="Include system account access")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def monitor_history(file_path: str, days: int, limit: int, include_system: bool, as_json: bool):
    """Show access history for a file.

    Queries Windows Event Log or Linux audit logs for access events
    on the specified file.

    Examples:
        openlabels monitor history ./sensitive.xlsx
        openlabels monitor history ./secrets.json --days 7 --limit 100
        openlabels monitor history ./file.docx --json
    """
    from openlabels.monitoring import get_access_history

    path = Path(file_path)

    events = get_access_history(
        path=path,
        days=days,
        limit=limit,
        include_system=include_system,
    )

    if as_json:
        import json as json_mod
        output = [e.to_dict() for e in events]
        click.echo(json_mod.dumps(output, indent=2, default=str))
    elif not events:
        click.echo(f"No access events found for: {path}")
        click.echo(f"  (searched last {days} days)")
    else:
        click.echo(f"Access history for: {path}")
        click.echo(f"{'Timestamp':<20} {'User':<25} {'Action':<12} {'Process':<20}")
        click.echo("-" * 80)
        for event in events:
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            user = event.user_display[:24]
            action = event.action.value
            process = (event.process_name or "")[:19]
            click.echo(f"{ts:<20} {user:<25} {action:<12} {process:<20}")


@monitor.command("status")
@click.argument("file_path", type=click.Path(exists=True))
def monitor_status(file_path: str):
    """Check monitoring status for a file.

    Shows whether a file is being monitored and its configuration.

    Examples:
        openlabels monitor status ./sensitive.xlsx
    """
    from openlabels.monitoring import is_monitored, get_watched_files

    path = Path(file_path).resolve()

    if is_monitored(path):
        # Find the watched file entry
        watched = get_watched_files()
        entry = next((w for w in watched if w.path == path), None)

        click.echo(f"File: {path}")
        click.echo(f"Status: MONITORED")
        if entry:
            click.echo(f"  Risk tier: {entry.risk_tier}")
            click.echo(f"  Added: {entry.added_at.strftime('%Y-%m-%d %H:%M:%S') if entry.added_at else 'N/A'}")
            click.echo(f"  SACL enabled: {entry.sacl_enabled}")
            click.echo(f"  Audit rule enabled: {entry.audit_rule_enabled}")
            if entry.last_event_at:
                click.echo(f"  Last access: {entry.last_event_at.strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo(f"  Access count: {entry.access_count}")
    else:
        click.echo(f"File: {path}")
        click.echo("Status: NOT MONITORED")

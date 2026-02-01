"""
OpenLabels CLI entry point.

Usage:
    openlabels serve [--host HOST] [--port PORT] [--workers N]
    openlabels worker [--concurrency N]
    openlabels gui [--server URL]
    openlabels db upgrade
    openlabels config show
"""

import click
import sys


@click.group()
@click.version_option()
def cli():
    """OpenLabels - Data Classification & Auto-Labeling Platform"""
    pass


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--workers", default=4, type=int, help="Number of worker processes")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, workers: int, reload: bool):
    """Start the OpenLabels API server."""
    import uvicorn

    uvicorn.run(
        "openlabels.server.app:app",
        host=host,
        port=port,
        workers=1 if reload else workers,
        reload=reload,
    )


@cli.command()
@click.option("--concurrency", default=None, type=int, help="Number of concurrent jobs")
def worker(concurrency: int):
    """Start a worker process for job execution."""
    from openlabels.jobs.worker import run_worker

    run_worker(concurrency=concurrency)


@cli.command()
@click.option("--server", default="http://localhost:8000", help="Server URL to connect to")
def gui(server: str):
    """Launch the OpenLabels GUI application."""
    from openlabels.gui.main import run_gui

    run_gui(server_url=server)


@cli.group()
def db():
    """Database management commands."""
    pass


@db.command("upgrade")
@click.option("--revision", default="head", help="Revision to upgrade to")
def db_upgrade(revision: str):
    """Apply database migrations."""
    from openlabels.server.db import run_migrations

    run_migrations(revision)
    click.echo(f"Database upgraded to {revision}")


@db.command("downgrade")
@click.option("--revision", required=True, help="Revision to downgrade to")
def db_downgrade(revision: str):
    """Revert database migrations."""
    from openlabels.server.db import run_migrations

    run_migrations(revision, direction="downgrade")
    click.echo(f"Database downgraded to {revision}")


@cli.group()
def config():
    """Configuration management."""
    pass


@config.command("show")
def config_show():
    """Display current configuration."""
    from openlabels.server.config import get_settings

    settings = get_settings()
    click.echo(settings.model_dump_json(indent=2))


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """Set a configuration value."""
    click.echo(f"Setting {key} = {value}")
    click.echo("Note: Configuration changes require server restart")


@cli.group()
def user():
    """User management commands."""
    pass


@user.command("list")
def user_list():
    """List all users."""
    click.echo("Users:")
    # TODO: Implement


@user.command("create")
@click.argument("email")
@click.option("--role", default="viewer", type=click.Choice(["admin", "viewer"]))
def user_create(email: str, role: str):
    """Create a new user."""
    click.echo(f"Creating user {email} with role {role}")
    # TODO: Implement


@cli.group()
def target():
    """Scan target management."""
    pass


@target.command("list")
def target_list():
    """List configured scan targets."""
    click.echo("Targets:")
    # TODO: Implement


@target.command("add")
@click.argument("name")
@click.option("--adapter", required=True, type=click.Choice(["filesystem", "sharepoint", "onedrive"]))
@click.option("--path", required=True, help="Path or site URL to scan")
def target_add(name: str, adapter: str, path: str):
    """Add a new scan target."""
    click.echo(f"Adding target {name} ({adapter}: {path})")
    # TODO: Implement


@cli.group()
def scan():
    """Scan management commands."""
    pass


@scan.command("start")
@click.argument("target_name")
def scan_start(target_name: str):
    """Start a scan on the specified target."""
    click.echo(f"Starting scan on {target_name}")
    # TODO: Implement


@scan.command("status")
@click.argument("job_id")
def scan_status(job_id: str):
    """Check status of a scan job."""
    click.echo(f"Status of job {job_id}")
    # TODO: Implement


@scan.command("cancel")
@click.argument("job_id")
def scan_cancel(job_id: str):
    """Cancel a running scan."""
    click.echo(f"Cancelling job {job_id}")
    # TODO: Implement


@cli.group()
def labels():
    """Label management commands."""
    pass


@labels.command("sync")
def labels_sync():
    """Sync sensitivity labels from Microsoft 365."""
    click.echo("Syncing labels from M365...")
    # TODO: Implement


@cli.command()
@click.option("--output", default="./backup", help="Output directory")
def backup(output: str):
    """Backup OpenLabels data."""
    click.echo(f"Backing up to {output}")
    # TODO: Implement


@cli.command()
@click.option("--from", "from_path", required=True, help="Backup directory to restore from")
def restore(from_path: str):
    """Restore OpenLabels data from backup."""
    click.echo(f"Restoring from {from_path}")
    # TODO: Implement


@cli.group()
def export():
    """Export commands."""
    pass


@export.command("results")
@click.option("--job", required=True, help="Job ID to export")
@click.option("--format", "fmt", default="csv", type=click.Choice(["csv", "json"]))
@click.option("--output", required=True, help="Output file path")
def export_results(job: str, fmt: str, output: str):
    """Export scan results."""
    click.echo(f"Exporting job {job} to {output} as {fmt}")
    # TODO: Implement


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()

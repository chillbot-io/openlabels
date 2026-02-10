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

from openlabels.cli.commands import (
    backup,
    catalog,
    # Standalone commands
    classify,
    config,
    # Command groups
    db,
    doctor,
    export,
    find,
    gui,
    heatmap,
    labels,
    lock_down_cmd,
    models,
    monitor,
    quarantine,
    report,
    restore,
    scan,
    # Server commands
    serve,
    status,
    target,
    user,
    worker,
)


@click.group()
@click.version_option()
def cli():
    """OpenLabels - Data Classification & Auto-Labeling Platform"""
    pass


# Register server commands
cli.add_command(serve)
cli.add_command(worker)
cli.add_command(gui)

# Register command groups
cli.add_command(db)
cli.add_command(config)
cli.add_command(user)
cli.add_command(target)
cli.add_command(scan)
cli.add_command(labels)
cli.add_command(export)
cli.add_command(monitor)
cli.add_command(catalog)
cli.add_command(models)

# Register standalone commands
cli.add_command(classify)
cli.add_command(find)
cli.add_command(report)
cli.add_command(heatmap)
cli.add_command(quarantine)
cli.add_command(lock_down_cmd)
cli.add_command(status)
cli.add_command(backup)
cli.add_command(restore)
cli.add_command(doctor)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()

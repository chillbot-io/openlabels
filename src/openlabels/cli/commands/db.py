"""
Database management commands.
"""

import click


@click.group()
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

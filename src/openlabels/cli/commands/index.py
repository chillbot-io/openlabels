"""Directory tree index commands.

Provides ``openlabels index`` for bootstrapping and managing the
directory tree index used by the filesystem engine v2.
"""

from __future__ import annotations

import asyncio
import logging
import sys

import click

from openlabels.cli.base import server_options, spinner

logger = logging.getLogger(__name__)


@click.group()
def index() -> None:
    """Directory tree index management."""
    pass


@index.command("build")
@click.argument("target_name")
@click.option("--path", default=None, help="Override scan path from target config")
@server_options
def index_build(target_name: str, path: str | None, server: str, token: str | None) -> None:
    """Build the directory tree index for a target.

    Enumerates all directories via the target's adapter and populates
    the directory_tree table.  Safe to re-run — uses upsert to update
    existing rows.
    """
    asyncio.run(_run_bootstrap(target_name, path, rebuild=False))


@index.command("rebuild")
@click.argument("target_name")
@click.option("--path", default=None, help="Override scan path from target config")
@server_options
def index_rebuild(target_name: str, path: str | None, server: str, token: str | None) -> None:
    """Drop and rebuild the directory tree index for a target.

    Deletes all existing directory_tree rows for the target, then
    performs a full bootstrap.
    """
    asyncio.run(_run_bootstrap(target_name, path, rebuild=True))


@index.command("status")
@click.argument("target_name")
@server_options
def index_status(target_name: str, server: str, token: str | None) -> None:
    """Show directory tree index statistics for a target."""
    asyncio.run(_run_status(target_name))


async def _init_db():
    """Initialize the database connection for CLI use."""
    from openlabels.server.config import get_settings
    from openlabels.server.db import init_db

    settings = get_settings()
    await init_db(settings.database.url)


async def _resolve_target(session, target_name: str):
    """Look up a ScanTarget by name.  Returns (target, error_msg)."""
    from sqlalchemy import select
    from openlabels.server.models import ScanTarget

    result = await session.execute(
        select(ScanTarget).where(ScanTarget.name == target_name)
    )
    target = result.scalar_one_or_none()
    if target is None:
        return None, f"Target not found: {target_name}"
    return target, None


def _get_adapter(adapter_type: str, config: dict):
    """Instantiate an adapter from target config.

    Reuses the same factory logic as the scan pipeline.
    """
    from openlabels.jobs.tasks.scan import _get_adapter as scan_get_adapter
    return scan_get_adapter(adapter_type, config)


def _get_scan_path(target, path_override: str | None) -> str:
    """Determine the scan path from target config or override."""
    if path_override:
        return path_override
    config = target.config or {}
    # Filesystem targets store path in config
    scan_path = config.get("path", "")
    if not scan_path:
        click.echo(
            f"Error: Target '{target.name}' has no path configured. "
            "Use --path to specify one.",
            err=True,
        )
        sys.exit(1)
    return scan_path


async def _run_bootstrap(target_name: str, path_override: str | None, rebuild: bool) -> None:
    """Core bootstrap logic shared by build and rebuild commands."""
    from openlabels.jobs.index import (
        bootstrap_directory_tree,
        clear_directory_tree,
    )
    from openlabels.server.db import close_db, get_session_context

    await _init_db()

    try:
        async with get_session_context() as session:
            target, err = await _resolve_target(session, target_name)
            if err:
                click.echo(f"Error: {err}", err=True)
                sys.exit(1)

            scan_path = _get_scan_path(target, path_override)
            adapter = _get_adapter(target.adapter.value, target.config or {})

            if rebuild:
                deleted = await clear_directory_tree(
                    session, target.tenant_id, target.id
                )
                if deleted:
                    click.echo(f"Cleared {deleted:,} existing directory entries.")
                await session.flush()

            click.echo(
                f"Indexing directories for '{target.name}' "
                f"({target.adapter.value}) at {scan_path}..."
            )

            def on_progress(count: int) -> None:
                click.echo(f"  {count:,} directories indexed...", nl=True)

            async with adapter:
                stats = await bootstrap_directory_tree(
                    session=session,
                    adapter=adapter,
                    tenant_id=target.tenant_id,
                    target_id=target.id,
                    scan_path=scan_path,
                    on_progress=on_progress,
                )

        click.echo("")
        click.echo(f"Index complete:")
        click.echo(f"  Directories indexed:     {stats['total_dirs']:,}")
        click.echo(f"  Parent links resolved:   {stats['parent_links_resolved']:,}")
        click.echo(f"  Elapsed:                 {stats['elapsed_seconds']:.1f}s")

    finally:
        await close_db()


async def _run_status(target_name: str) -> None:
    """Show index stats for a target."""
    from openlabels.jobs.index import get_index_stats
    from openlabels.server.db import close_db, get_session_context

    await _init_db()

    try:
        async with get_session_context() as session:
            target, err = await _resolve_target(session, target_name)
            if err:
                click.echo(f"Error: {err}", err=True)
                sys.exit(1)

            stats = await get_index_stats(session, target.tenant_id, target.id)

        click.echo(f"Directory tree index: {target.name}")
        click.echo(f"  Adapter:             {target.adapter.value}")
        click.echo(f"  Directories indexed: {stats['total_dirs']:,}")
        click.echo(f"  Parent links:        {stats['with_parent_link']:,}")
        click.echo(f"  With SD hash:        {stats['with_sd_hash']:,}")
        click.echo(f"  With share:          {stats['with_share']:,}")

        if stats["last_updated"]:
            click.echo(f"  Last updated:        {stats['last_updated'].isoformat()}")
        else:
            click.echo(f"  Last updated:        never")

    finally:
        await close_db()

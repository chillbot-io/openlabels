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
@click.option("--collect-sd/--no-collect-sd", default=True,
              help="Collect security descriptors (default: on)")
@server_options
def index_build(
    target_name: str,
    path: str | None,
    collect_sd: bool,
    server: str,
    token: str | None,
) -> None:
    """Build the directory tree index for a target.

    Enumerates all directories via the target's adapter and populates
    the directory_tree table.  Safe to re-run — uses upsert to update
    existing rows.

    By default also collects security descriptors (POSIX uid/gid/mode
    or NTFS DACL) for each directory and populates the
    security_descriptors table.  Use --no-collect-sd to skip.
    """
    asyncio.run(_run_bootstrap(target_name, path, rebuild=False, collect_sd=collect_sd))


@index.command("rebuild")
@click.argument("target_name")
@click.option("--path", default=None, help="Override scan path from target config")
@click.option("--collect-sd/--no-collect-sd", default=True,
              help="Collect security descriptors (default: on)")
@server_options
def index_rebuild(
    target_name: str,
    path: str | None,
    collect_sd: bool,
    server: str,
    token: str | None,
) -> None:
    """Drop and rebuild the directory tree index for a target.

    Deletes all existing directory_tree rows for the target, then
    performs a full bootstrap.
    """
    asyncio.run(_run_bootstrap(target_name, path, rebuild=True, collect_sd=collect_sd))


@index.command("collect-sd")
@click.argument("target_name")
@server_options
def index_collect_sd(target_name: str, server: str, token: str | None) -> None:
    """Collect security descriptors for an existing index.

    Runs SD collection as a standalone pass over directories that don't
    yet have an sd_hash.  Useful after building an index with
    --no-collect-sd or to refresh permissions.
    """
    asyncio.run(_run_collect_sd(target_name))


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


async def _run_bootstrap(
    target_name: str,
    path_override: str | None,
    rebuild: bool,
    collect_sd: bool = True,
) -> None:
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

            def on_sd_progress(processed: int, total: int) -> None:
                click.echo(
                    f"  SD collection: {processed:,}/{total:,} directories...",
                    nl=True,
                )

            async with adapter:
                stats = await bootstrap_directory_tree(
                    session=session,
                    adapter=adapter,
                    tenant_id=target.tenant_id,
                    target_id=target.id,
                    scan_path=scan_path,
                    on_progress=on_progress,
                    collect_sd=collect_sd,
                    on_sd_progress=on_sd_progress,
                )

        click.echo("")
        click.echo("Index complete:")
        click.echo(f"  Directories indexed:     {stats['total_dirs']:,}")
        click.echo(f"  Parent links resolved:   {stats['parent_links_resolved']:,}")

        sd_stats = stats.get("sd_stats")
        if sd_stats:
            click.echo(f"  Unique security descs:   {sd_stats['unique_sds']:,}")
            click.echo(f"  World-accessible dirs:   {sd_stats['world_accessible']:,}")

        click.echo(f"  Elapsed:                 {stats['elapsed_seconds']:.1f}s")

    finally:
        await close_db()


async def _run_collect_sd(target_name: str) -> None:
    """Standalone SD collection for an existing index."""
    from openlabels.jobs.sd_collect import collect_security_descriptors
    from openlabels.server.db import close_db, get_session_context

    await _init_db()

    try:
        async with get_session_context() as session:
            target, err = await _resolve_target(session, target_name)
            if err:
                click.echo(f"Error: {err}", err=True)
                sys.exit(1)

            click.echo(
                f"Collecting security descriptors for '{target.name}'..."
            )

            def on_progress(processed: int, total: int) -> None:
                click.echo(
                    f"  {processed:,}/{total:,} directories...", nl=True,
                )

            sd_stats = await collect_security_descriptors(
                session=session,
                tenant_id=target.tenant_id,
                target_id=target.id,
                on_progress=on_progress,
            )

        click.echo("")
        click.echo("SD collection complete:")
        click.echo(f"  Directories processed:   {sd_stats['total_dirs']:,}")
        click.echo(f"  Unique security descs:   {sd_stats['unique_sds']:,}")
        click.echo(f"  World-accessible dirs:   {sd_stats['world_accessible']:,}")
        click.echo(f"  Elapsed:                 {sd_stats['elapsed_seconds']:.1f}s")

    finally:
        await close_db()


async def _run_status(target_name: str) -> None:
    """Show index stats for a target."""
    from openlabels.jobs.index import get_index_stats
    from openlabels.jobs.sd_collect import get_sd_stats
    from openlabels.server.db import close_db, get_session_context

    await _init_db()

    try:
        async with get_session_context() as session:
            target, err = await _resolve_target(session, target_name)
            if err:
                click.echo(f"Error: {err}", err=True)
                sys.exit(1)

            stats = await get_index_stats(session, target.tenant_id, target.id)
            sd_stats = await get_sd_stats(session, target.tenant_id, target.id)

        click.echo(f"Directory tree index: {target.name}")
        click.echo(f"  Adapter:             {target.adapter.value}")
        click.echo(f"  Directories indexed: {stats['total_dirs']:,}")
        click.echo(f"  Parent links:        {stats['with_parent_link']:,}")
        click.echo(f"  With SD hash:        {stats['with_sd_hash']:,}")
        click.echo(f"  With share:          {stats['with_share']:,}")

        if sd_stats["unique_sds"] > 0:
            click.echo(f"  Unique SDs:          {sd_stats['unique_sds']:,}")
            click.echo(f"  World-accessible:    {sd_stats['world_accessible']:,}")
            click.echo(f"  Custom ACL:          {sd_stats['custom_acl']:,}")

        if stats["last_updated"]:
            click.echo(f"  Last updated:        {stats['last_updated'].isoformat()}")
        else:
            click.echo(f"  Last updated:        never")

    finally:
        await close_db()

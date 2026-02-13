"""Catalog management commands (rebuild, compact)."""

from __future__ import annotations

import asyncio
import logging

import click

logger = logging.getLogger(__name__)


@click.group()
def catalog():
    """Manage the Parquet data-lake catalog."""
    pass


@catalog.command()
@click.option("--batch-size", default=10_000, show_default=True, help="Rows per batch")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def rebuild(batch_size: int, yes: bool) -> None:
    """Full re-export of PostgreSQL to Parquet.

    Streams all scan results, file inventory, access events, audit logs,
    and remediation actions from PostgreSQL to the Parquet catalog in
    batches.  Resets the flush state cursor so periodic flush picks up
    from the latest row.

    Use this for initial setup or disaster recovery.

    \b
    Examples:
        openlabels catalog rebuild
        openlabels catalog rebuild --batch-size 5000
    """
    if not yes:
        click.confirm(
            "This will re-export all data from PostgreSQL to the Parquet catalog. "
            "Existing Parquet files will be overwritten. Continue?",
            abort=True,
        )

    click.echo("Rebuilding Parquet catalog from PostgreSQL...")
    asyncio.run(_run_rebuild(batch_size))
    click.echo("Catalog rebuild complete.")


async def _run_rebuild(batch_size: int) -> None:
    """Async implementation of the catalog rebuild."""
    from sqlalchemy import func, select

    from openlabels.analytics.arrow_convert import (
        access_events_to_arrow,
        audit_log_to_arrow,
        file_inventory_to_arrow,
        folder_inventory_to_arrow,
        remediation_actions_to_arrow,
        scan_results_to_arrow,
    )
    from openlabels.analytics.flush import save_flush_state
    from openlabels.analytics.partition import (
        access_event_partition,
        audit_log_partition,
        file_inventory_path,
        folder_inventory_path,
        remediation_action_partition,
        scan_result_partition,
        timestamped_part_filename,
    )
    from openlabels.analytics.storage import create_storage
    from openlabels.server.config import get_settings
    from openlabels.server.db import close_db, get_session_context, init_db
    from openlabels.server.models import (
        AuditLog,
        FileAccessEvent,
        FileInventory,
        FolderInventory,
        RemediationAction,
        ScanResult,
    )

    settings = get_settings()
    storage = create_storage(settings.catalog)
    await init_db(settings.database.url)

    try:
        async with get_session_context() as session:
            total = (await session.execute(select(func.count()).select_from(ScanResult))).scalar() or 0
            click.echo(f"  Scan results: {total} rows")
            offset = 0
            last_scanned_at = None
            while offset < total:
                q = (
                    select(ScanResult)
                    .order_by(ScanResult.scanned_at)
                    .offset(offset)
                    .limit(batch_size)
                )
                result = await session.execute(q)
                rows = list(result.scalars())
                if not rows:
                    break

                table = scan_results_to_arrow(rows)

                # Group by tenant + target + scan_date
                groups: dict[tuple, list[int]] = {}
                for idx, r in enumerate(rows):
                    key = (str(r.tenant_id), str(r.target_id), r.scanned_at.date())
                    groups.setdefault(key, []).append(idx)

                for (tid, tgt, sd), indices in groups.items():
                    from uuid import UUID
                    part = scan_result_partition(UUID(tid), UUID(tgt), sd)
                    subset = table.take(indices)
                    storage.write_parquet(
                        f"{part}/{timestamped_part_filename()}",
                        subset,
                    )

                last_scanned_at = rows[-1].scanned_at
                offset += len(rows)
                click.echo(f"    Flushed {offset}/{total}")

            total = (await session.execute(select(func.count()).select_from(FileInventory))).scalar() or 0
            click.echo(f"  File inventory: {total} rows")
            offset = 0
            while offset < total:
                q = (
                    select(FileInventory)
                    .order_by(FileInventory.id)
                    .offset(offset)
                    .limit(batch_size)
                )
                result = await session.execute(q)
                rows = list(result.scalars())
                if not rows:
                    break

                table = file_inventory_to_arrow(rows)

                groups = {}
                for idx, r in enumerate(rows):
                    key = (str(r.tenant_id), str(r.target_id))
                    groups.setdefault(key, []).append(idx)

                for (tid, tgt), indices in groups.items():
                    from uuid import UUID
                    part = file_inventory_path(UUID(tid), UUID(tgt))
                    subset = table.take(indices)
                    storage.write_parquet(part, subset)

                offset += len(rows)
                click.echo(f"    Flushed {offset}/{total}")

            total = (await session.execute(select(func.count()).select_from(FolderInventory))).scalar() or 0
            click.echo(f"  Folder inventory: {total} rows")
            offset = 0
            while offset < total:
                q = (
                    select(FolderInventory)
                    .order_by(FolderInventory.id)
                    .offset(offset)
                    .limit(batch_size)
                )
                result = await session.execute(q)
                rows = list(result.scalars())
                if not rows:
                    break

                table = folder_inventory_to_arrow(rows)

                groups = {}
                for idx, r in enumerate(rows):
                    key = (str(r.tenant_id), str(r.target_id))
                    groups.setdefault(key, []).append(idx)

                for (tid, tgt), indices in groups.items():
                    from uuid import UUID
                    part = folder_inventory_path(UUID(tid), UUID(tgt))
                    subset = table.take(indices)
                    storage.write_parquet(part, subset)

                offset += len(rows)
                click.echo(f"    Flushed {offset}/{total}")

            total = (await session.execute(select(func.count()).select_from(FileAccessEvent))).scalar() or 0
            click.echo(f"  Access events: {total} rows")
            offset = 0
            last_ae_at = None
            while offset < total:
                q = (
                    select(FileAccessEvent)
                    .order_by(FileAccessEvent.collected_at)
                    .offset(offset)
                    .limit(batch_size)
                )
                result = await session.execute(q)
                rows = list(result.scalars())
                if not rows:
                    break

                table = access_events_to_arrow(rows)

                groups = {}
                for idx, r in enumerate(rows):
                    key = (str(r.tenant_id), r.event_time.date())
                    groups.setdefault(key, []).append(idx)

                for (tid, ed), indices in groups.items():
                    from uuid import UUID
                    part = access_event_partition(UUID(tid), ed)
                    subset = table.take(indices)
                    storage.write_parquet(
                        f"{part}/{timestamped_part_filename()}",
                        subset,
                    )

                last_ae_at = rows[-1].collected_at
                offset += len(rows)
                click.echo(f"    Flushed {offset}/{total}")

            total = (await session.execute(select(func.count()).select_from(AuditLog))).scalar() or 0
            click.echo(f"  Audit logs: {total} rows")
            offset = 0
            last_al_at = None
            while offset < total:
                q = (
                    select(AuditLog)
                    .order_by(AuditLog.created_at)
                    .offset(offset)
                    .limit(batch_size)
                )
                result = await session.execute(q)
                rows = list(result.scalars())
                if not rows:
                    break

                table = audit_log_to_arrow(rows)

                groups = {}
                for idx, r in enumerate(rows):
                    key = (str(r.tenant_id), r.created_at.date())
                    groups.setdefault(key, []).append(idx)

                for (tid, ld), indices in groups.items():
                    from uuid import UUID
                    part = audit_log_partition(UUID(tid), ld)
                    subset = table.take(indices)
                    storage.write_parquet(
                        f"{part}/{timestamped_part_filename()}",
                        subset,
                    )

                last_al_at = rows[-1].created_at
                offset += len(rows)
                click.echo(f"    Flushed {offset}/{total}")

            total = (await session.execute(select(func.count()).select_from(RemediationAction))).scalar() or 0
            click.echo(f"  Remediation actions: {total} rows")
            offset = 0
            last_ra_at = None
            while offset < total:
                q = (
                    select(RemediationAction)
                    .order_by(RemediationAction.created_at)
                    .offset(offset)
                    .limit(batch_size)
                )
                result = await session.execute(q)
                rows = list(result.scalars())
                if not rows:
                    break

                table = remediation_actions_to_arrow(rows)

                groups = {}
                for idx, r in enumerate(rows):
                    key = (str(r.tenant_id), r.created_at.date())
                    groups.setdefault(key, []).append(idx)

                for (tid, ad), indices in groups.items():
                    from uuid import UUID
                    part = remediation_action_partition(UUID(tid), ad)
                    subset = table.take(indices)
                    storage.write_parquet(
                        f"{part}/{timestamped_part_filename()}",
                        subset,
                    )

                last_ra_at = rows[-1].created_at
                offset += len(rows)
                click.echo(f"    Flushed {offset}/{total}")

        state = {
            "last_access_event_flush": last_ae_at.isoformat() if last_ae_at else None,
            "last_audit_log_flush": last_al_at.isoformat() if last_al_at else None,
            "last_remediation_action_flush": last_ra_at.isoformat() if last_ra_at else None,
            "schema_version": 1,
        }
        save_flush_state(storage, state)
        click.echo("  Flush state reset.")

    finally:
        await close_db()


@catalog.command()
@click.option("--table", "-t", default=None, help="Table to compact (default: all)")
@click.option("--threshold", default=10, show_default=True, help="Min files before compaction triggers")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def compact(table: str | None, threshold: int, yes: bool) -> None:
    """Merge small Parquet files into larger ones.

    Scans partitions and merges any that have more than --threshold
    files into optimally-sized Parquet files.

    \b
    Examples:
        openlabels catalog compact
        openlabels catalog compact --table scan_results
        openlabels catalog compact --threshold 5
    """
    if not yes:
        click.confirm(
            "This will compact Parquet files in the catalog. Continue?",
            abort=True,
        )

    click.echo("Compacting catalog partitions...")
    from openlabels.analytics.compaction import compact_catalog
    from openlabels.analytics.storage import create_storage
    from openlabels.server.config import get_settings

    settings = get_settings()
    storage = create_storage(settings.catalog)
    tables = [table] if table else [
        "scan_results", "file_inventory", "folder_inventory",
        "access_events", "audit_log", "remediation_actions",
    ]

    total_compacted = compact_catalog(storage, tables, threshold=threshold)
    click.echo(f"Compaction complete. {total_compacted} partitions compacted.")

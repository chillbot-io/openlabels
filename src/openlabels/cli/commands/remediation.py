"""
Remediation commands (quarantine and lock-down).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import click

from openlabels.cli.utils import collect_files, validate_where_filter
from openlabels.core.constants import MAX_DECOMPRESSED_SIZE
from openlabels.core.types import ExposureLevel

logger = logging.getLogger(__name__)


@click.command()
@click.argument("source", type=click.Path(exists=True), required=False)
@click.argument("destination", type=click.Path(), required=False)
@click.option("--where", "where_filter", callback=validate_where_filter,
              help='Filter to select files (e.g., "tier = CRITICAL AND has(SSN)")')
@click.option("--scan-path", type=click.Path(exists=True), help="Path to scan when using --where")
@click.option("-r", "--recursive", is_flag=True, help="Recursive scan when using --where")
@click.option("--preserve-acls/--no-preserve-acls", default=True, help="Preserve ACLs during move")
@click.option("--dry-run", is_flag=True, help="Preview without moving")
def quarantine(source: str | None, destination: str | None, where_filter: str | None,
               scan_path: str | None, recursive: bool, preserve_acls: bool, dry_run: bool):
    """Quarantine sensitive files to a secure location.

    Can quarantine a single file (source -> destination) or multiple files
    matching a filter (--where with --scan-path).

    Examples:
        openlabels quarantine ./sensitive.xlsx ./quarantine/
        openlabels quarantine --where "tier = CRITICAL" --scan-path ./data -r ./quarantine/ --dry-run
        openlabels quarantine --where "has(SSN) AND score > 80" --scan-path . -r /secure/vault/
    """
    from openlabels.remediation import quarantine as do_quarantine

    # Handle batch mode with --where
    if where_filter:
        if not scan_path:
            click.echo("Error: --scan-path required when using --where", err=True)
            sys.exit(1)
        if not destination and not source:
            click.echo("Error: destination required", err=True)
            sys.exit(1)

        dest_path = Path(destination if destination else source)

        # Find matching files
        from openlabels.cli.filter_executor import filter_scan_results
        from openlabels.core.processor import FileProcessor

        files = collect_files(scan_path, recursive)

        click.echo(f"Scanning {len(files)} files...", err=True)

        processor = FileProcessor()

        async def find_matches():
            all_results = []
            for file_path in files:
                try:
                    if os.path.getsize(file_path) > MAX_DECOMPRESSED_SIZE:
                        continue
                    with open(file_path, "rb") as f:
                        content = f.read()
                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level=ExposureLevel.PRIVATE,
                    )
                    all_results.append({
                        "file_path": str(file_path),
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                    })
                except PermissionError:
                    logger.debug(f"Permission denied: {file_path}")
                except OSError as e:
                    logger.debug(f"OS error processing {file_path}: {e}")
                except UnicodeDecodeError as e:
                    logger.debug(f"Encoding error processing {file_path}: {e}")
                except ValueError as e:
                    logger.debug(f"Value error processing {file_path}: {e}")
            return all_results

        results = asyncio.run(find_matches())
        matches = filter_scan_results(results, where_filter)

        if not matches:
            click.echo("No files match the filter")
            return

        click.echo(f"Found {len(matches)} matching files")

        if dry_run:
            click.echo("\nDRY RUN - Files that would be quarantined:")
            for m in matches:
                click.echo(f"  {m['file_path']} (score: {m['risk_score']}, tier: {m['risk_tier']})")
            return

        # Quarantine each file
        success_count = 0
        for m in matches:
            result = do_quarantine(
                source=Path(m["file_path"]),
                destination=dest_path,
                preserve_acls=preserve_acls,
                dry_run=False,
            )
            if result.success:
                click.echo(f"Quarantined: {m['file_path']}")
                success_count += 1
            else:
                click.echo(f"Failed: {m['file_path']} - {result.error}", err=True)

        click.echo(f"\nQuarantined {success_count}/{len(matches)} files to {dest_path}")

    else:
        # Single file mode
        if not source or not destination:
            click.echo("Error: SOURCE and DESTINATION required (or use --where with --scan-path)", err=True)
            sys.exit(1)

        source_path = Path(source)
        dest_path = Path(destination)

        if dry_run:
            click.echo(f"DRY RUN: Would move {source_path} -> {dest_path}")
            click.echo(f"  Preserve ACLs: {preserve_acls}")
            return

        result = do_quarantine(
            source=source_path,
            destination=dest_path,
            preserve_acls=preserve_acls,
            dry_run=dry_run,
        )

        if result.success:
            click.echo(f"Quarantined: {result.source_path}")
            click.echo(f"        To: {result.dest_path}")
            click.echo(f"        By: {result.performed_by}")
        else:
            click.echo(f"Error: {result.error}", err=True)
            sys.exit(1)


@click.command("lock-down")
@click.argument("file_path", type=click.Path(exists=True), required=False)
@click.option("--where", "where_filter", callback=validate_where_filter,
              help='Filter to select files (e.g., "tier = CRITICAL")')
@click.option("--scan-path", type=click.Path(exists=True), help="Path to scan when using --where")
@click.option("-r", "--recursive", is_flag=True, help="Recursive scan when using --where")
@click.option("--principals", multiple=True, help="Principals to grant access (repeatable)")
@click.option("--keep-inheritance", is_flag=True, help="Keep permission inheritance")
@click.option("--backup-acl", is_flag=True, help="Backup current ACL for rollback")
@click.option("--dry-run", is_flag=True, help="Preview without changing permissions")
def lock_down_cmd(file_path: str | None, where_filter: str | None, scan_path: str | None,
                  recursive: bool, principals: tuple, keep_inheritance: bool, backup_acl: bool, dry_run: bool):
    """Lock down file permissions to restrict access.

    Can lock down a single file or multiple files matching a filter.

    Examples:
        openlabels lock-down ./sensitive.xlsx
        openlabels lock-down --where "tier = CRITICAL" --scan-path ./data -r --dry-run
        openlabels lock-down --where "has(SSN)" --scan-path . -r --principals admin
    """
    from openlabels.remediation import lock_down

    principal_list = list(principals) if principals else None

    # Handle batch mode with --where
    if where_filter:
        if not scan_path:
            click.echo("Error: --scan-path required when using --where", err=True)
            sys.exit(1)

        from openlabels.cli.filter_executor import filter_scan_results
        from openlabels.core.processor import FileProcessor

        files = collect_files(scan_path, recursive)

        click.echo(f"Scanning {len(files)} files...", err=True)

        processor = FileProcessor()

        async def find_matches():
            all_results = []
            for fp in files:
                try:
                    if os.path.getsize(fp) > MAX_DECOMPRESSED_SIZE:
                        continue
                    with open(fp, "rb") as f:
                        content = f.read()
                    result = await processor.process_file(
                        file_path=str(fp),
                        content=content,
                        exposure_level=ExposureLevel.PRIVATE,
                    )
                    all_results.append({
                        "file_path": str(fp),
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                    })
                except PermissionError:
                    logger.debug(f"Permission denied: {fp}")
                except OSError as e:
                    logger.debug(f"OS error processing {fp}: {e}")
                except UnicodeDecodeError as e:
                    logger.debug(f"Encoding error processing {fp}: {e}")
                except ValueError as e:
                    logger.debug(f"Value error processing {fp}: {e}")
            return all_results

        results = asyncio.run(find_matches())
        matches = filter_scan_results(results, where_filter)

        if not matches:
            click.echo("No files match the filter")
            return

        click.echo(f"Found {len(matches)} matching files")

        if dry_run:
            click.echo("\nDRY RUN - Files that would be locked down:")
            for m in matches:
                click.echo(f"  {m['file_path']} (score: {m['risk_score']}, tier: {m['risk_tier']})")
            if principal_list:
                click.echo(f"\nAllowed principals: {principal_list}")
            return

        success_count = 0
        for m in matches:
            result = lock_down(
                path=Path(m["file_path"]),
                allowed_principals=principal_list,
                remove_inheritance=not keep_inheritance,
                backup_acl=backup_acl,
                dry_run=False,
            )
            if result.success:
                click.echo(f"Locked down: {m['file_path']}")
                success_count += 1
            else:
                click.echo(f"Failed: {m['file_path']} - {result.error}", err=True)

        click.echo(f"\nLocked down {success_count}/{len(matches)} files")

    else:
        # Single file mode
        if not file_path:
            click.echo("Error: FILE_PATH required (or use --where with --scan-path)", err=True)
            sys.exit(1)

        path = Path(file_path)

        if dry_run:
            click.echo(f"DRY RUN: Would lock down {path}")
            if principal_list:
                click.echo(f"  Allowed principals: {principal_list}")
            click.echo(f"  Remove inheritance: {not keep_inheritance}")
            return

        result = lock_down(
            path=path,
            allowed_principals=principal_list,
            remove_inheritance=not keep_inheritance,
            backup_acl=backup_acl,
            dry_run=dry_run,
        )

        if result.success:
            click.echo(f"Locked down: {result.source_path}")
            click.echo(f"  Principals: {', '.join(result.principals or [])}")
            if result.previous_acl and backup_acl:
                click.echo("  ACL backup saved (can be used for rollback)")
        else:
            click.echo(f"Error: {result.error}", err=True)
            sys.exit(1)

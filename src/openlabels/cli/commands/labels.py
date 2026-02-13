"""Label management commands."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
import httpx

from openlabels.cli.base import api_client, format_option, server_options
from openlabels.cli.output import OutputFormatter
from openlabels.cli.utils import handle_http_error


@click.group()
def labels() -> None:
    """Label management commands."""
    pass


@labels.command("list")
@server_options
@format_option()
def labels_list(server: str, token: str | None, output_format: str) -> None:
    """List configured sensitivity labels."""
    fmt = OutputFormatter(output_format)

    try:
        with api_client(server, token) as client:
            response = client.get("/api/labels")
            if response.status_code == 200:
                labels_data = response.json()
                display = []
                for label in labels_data:
                    display.append({
                        "name": label.get("name", ""),
                        "priority": label.get("priority", 0),
                        "id": label.get("id", ""),
                    })
                fmt.print_table(display, columns=["name", "priority", "id"])
            else:
                click.echo(f"Error: {response.status_code}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)


@labels.command("sync")
@server_options
def labels_sync(server: str, token: str | None) -> None:
    """Sync sensitivity labels from Microsoft 365."""
    try:
        with api_client(server, token) as client:
            click.echo("Syncing labels from M365...")
            response = client.post("/api/labels/sync")
            if response.status_code == 202:
                result = response.json()
                click.echo(f"Synced {result.get('labels_synced', 0)} labels")
            else:
                click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)


# Local commands (no server needed)
@labels.command("apply")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--label", required=True, help="Label name or ID to apply")
@click.option("--justification", help="Justification for downgrade (if applicable)")
@click.option("--dry-run", is_flag=True, help="Preview without applying")
def labels_apply(file_path: str, label: str, justification: str | None, dry_run: bool) -> None:
    """Apply a sensitivity label to a file.

    Uses the MIP SDK on Windows, or records the label in the database on other platforms.

    Examples:
        openlabels labels apply ./document.docx --label "Confidential"
        openlabels labels apply ./data.xlsx --label "Highly Confidential" --dry-run
    """
    path = Path(file_path)

    if dry_run:
        click.echo(f"DRY RUN: Would apply label '{label}' to {path}")
        return

    try:
        from openlabels.labeling import LabelingEngine, get_label_cache

        cache = get_label_cache()
        cached_label = cache.get_by_name(label)

        if cached_label:
            label_id = cached_label.label_id
            label_name = cached_label.name
        else:
            label_id = label
            label_name = label

        engine = LabelingEngine()

        click.echo(f"Applying label '{label_name}' to {path}...")
        result = asyncio.run(engine.apply_label(
            file_path=path,
            label_id=label_id,
            justification=justification,
        ))

        if result.success:
            click.echo(f"Label applied: {label_name}")
            if result.method:
                click.echo(f"  Method: {result.method}")
        else:
            click.echo(f"Failed to apply label: {result.error}", err=True)
            sys.exit(1)

    except ImportError as e:
        click.echo(f"Error: Labeling module not available: {e}", err=True)
        sys.exit(1)
    except PermissionError as e:
        click.echo(f"Error: Permission denied accessing file: {e}", err=True)
        sys.exit(1)
    except OSError as e:
        click.echo(f"Error: File system error: {e}", err=True)
        sys.exit(1)


@labels.command("remove")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--justification", help="Justification for label removal")
@click.option("--dry-run", is_flag=True, help="Preview without removing")
def labels_remove(file_path: str, justification: str | None, dry_run: bool) -> None:
    """Remove a sensitivity label from a file.

    Examples:
        openlabels labels remove ./document.docx
        openlabels labels remove ./data.xlsx --justification "Data declassified"
    """
    path = Path(file_path)

    if dry_run:
        click.echo(f"DRY RUN: Would remove label from {path}")
        return

    try:
        from openlabels.labeling import LabelingEngine

        engine = LabelingEngine()

        click.echo(f"Removing label from {path}...")
        result = asyncio.run(engine.remove_label(
            file_path=path,
            justification=justification,
        ))

        if result.success:
            click.echo("Label removed successfully")
        else:
            click.echo(f"Failed to remove label: {result.error}", err=True)
            sys.exit(1)

    except ImportError as e:
        click.echo(f"Error: Labeling module not available: {e}", err=True)
        sys.exit(1)
    except PermissionError as e:
        click.echo(f"Error: Permission denied accessing file: {e}", err=True)
        sys.exit(1)
    except OSError as e:
        click.echo(f"Error: File system error: {e}", err=True)
        sys.exit(1)


@labels.command("info")
@click.argument("file_path", type=click.Path(exists=True))
def labels_info(file_path: str) -> None:
    """Show label information for a file.

    Examples:
        openlabels labels info ./document.docx
    """
    path = Path(file_path)

    try:
        from openlabels.labeling import LabelingEngine

        engine = LabelingEngine()

        result = asyncio.run(engine.get_label_info(file_path=path))

        click.echo(f"File: {path}")
        click.echo("-" * 50)

        if result.has_label:
            click.echo(f"Label:       {result.label_name or result.label_id}")
            click.echo(f"Label ID:    {result.label_id}")
            if result.applied_at:
                click.echo(f"Applied:     {result.applied_at}")
            if result.applied_by:
                click.echo(f"Applied by:  {result.applied_by}")
            if result.protection:
                click.echo(f"Protection:  {result.protection}")
        else:
            click.echo("No sensitivity label applied")

    except ImportError as e:
        click.echo(f"Error: Labeling module not available: {e}", err=True)
        sys.exit(1)
    except PermissionError as e:
        click.echo(f"Error: Permission denied accessing file: {e}", err=True)
        sys.exit(1)
    except OSError as e:
        click.echo(f"Error: File system error: {e}", err=True)
        sys.exit(1)

"""Scan management commands."""

from __future__ import annotations

import click
import httpx

from openlabels.cli.base import get_api_client, server_options
from openlabels.cli.utils import handle_http_error


@click.group()
def scan() -> None:
    """Scan management commands."""
    pass


@scan.command("start")
@click.argument("target_name")
@server_options
def scan_start(target_name: str, server: str, token: str | None) -> None:
    """Start a scan on the specified target."""
    client = get_api_client(server, token)

    try:
        # First, find the target by name
        response = client.get("/api/targets")
        if response.status_code != 200:
            click.echo(f"Error fetching targets: {response.status_code}", err=True)
            return

        targets = response.json()
        target = next((t for t in targets if t.get("name") == target_name), None)

        if not target:
            click.echo(f"Target not found: {target_name}", err=True)
            return

        # Start the scan
        response = client.post(
            "/api/scans",
            json={"target_id": target["id"]}
        )

        if response.status_code == 201:
            scan_data = response.json()
            click.echo(f"Started scan: {scan_data.get('id')}")
            click.echo(f"Status: {scan_data.get('status')}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()


@scan.command("status")
@click.argument("job_id")
@click.option("--watch", "-w", is_flag=True, help="Poll until scan completes")
@server_options
def scan_status(job_id: str, watch: bool, server: str, token: str | None) -> None:
    """Check status of a scan job."""
    import time

    client = get_api_client(server, token)

    try:
        if watch:
            from openlabels.cli.base import file_progress

            with file_progress(0, "Scan") as progress:
                task = progress.add_task("Waiting for scan...", total=None)
                while True:
                    response = client.get(f"/api/scans/{job_id}")
                    if response.status_code != 200:
                        click.echo(f"Error: {response.status_code}", err=True)
                        return
                    scan_data = response.json()
                    scan_st = scan_data.get("status", "unknown")
                    prog = scan_data.get("progress", {})
                    scanned = prog.get("files_scanned", 0)
                    total = prog.get("files_total", 0)

                    if total > 0:
                        progress.update(task, total=total, completed=scanned,
                                        description=f"Scanning ({scan_st})")
                    else:
                        progress.update(task, description=f"Scan {scan_st}...")

                    if scan_st in ("completed", "failed", "cancelled"):
                        break
                    time.sleep(2)

            click.echo(f"Job ID:     {scan_data.get('id')}")
            click.echo(f"Status:     {scan_st}")
            click.echo(f"Completed:  {scan_data.get('completed_at', 'N/A')}")
            if scan_data.get("error"):
                click.echo(f"Error:      {scan_data['error']}")
        else:
            response = client.get(f"/api/scans/{job_id}")
            if response.status_code == 200:
                scan_data = response.json()
                click.echo(f"Job ID:     {scan_data.get('id')}")
                click.echo(f"Status:     {scan_data.get('status')}")
                click.echo(f"Started:    {scan_data.get('started_at', 'N/A')}")
                click.echo(f"Completed:  {scan_data.get('completed_at', 'N/A')}")

                prog = scan_data.get("progress", {})
                if prog:
                    click.echo(f"Progress:   {prog.get('files_scanned', 0)}/{prog.get('files_total', 0)} files")
            else:
                click.echo(f"Error: {response.status_code}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()


@scan.command("cancel")
@click.argument("job_id")
@server_options
def scan_cancel(job_id: str, server: str, token: str | None) -> None:
    """Cancel a running scan."""
    client = get_api_client(server, token)

    try:
        response = client.delete(f"/api/scans/{job_id}")
        if response.status_code in (200, 204):
            click.echo(f"Cancelled scan: {job_id}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()

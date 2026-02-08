"""Scan management commands."""

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
        response = client.get(f"{server}/api/targets")
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
            f"{server}/api/scans",
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
@server_options
def scan_status(job_id: str, server: str, token: str | None) -> None:
    """Check status of a scan job."""
    client = get_api_client(server, token)

    try:
        response = client.get(f"{server}/api/scans/{job_id}")
        if response.status_code == 200:
            scan_data = response.json()
            click.echo(f"Job ID:     {scan_data.get('id')}")
            click.echo(f"Status:     {scan_data.get('status')}")
            click.echo(f"Started:    {scan_data.get('started_at', 'N/A')}")
            click.echo(f"Completed:  {scan_data.get('completed_at', 'N/A')}")

            progress = scan_data.get("progress", {})
            if progress:
                click.echo(f"Progress:   {progress.get('files_scanned', 0)}/{progress.get('files_total', 0)} files")
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
        response = client.delete(f"{server}/api/scans/{job_id}")
        if response.status_code in (200, 204):
            click.echo(f"Cancelled scan: {job_id}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()

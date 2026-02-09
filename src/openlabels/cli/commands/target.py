"""Scan target management commands."""

import click
import httpx

from openlabels.cli.base import format_option, get_api_client, server_options
from openlabels.cli.output import OutputFormatter
from openlabels.cli.utils import handle_http_error


@click.group()
def target() -> None:
    """Scan target management."""
    pass


@target.command("list")
@server_options
@format_option()
def target_list(server: str, token: str | None, output_format: str) -> None:
    """List configured scan targets."""
    fmt = OutputFormatter(output_format)
    client = get_api_client(server, token)

    try:
        response = client.get("/api/targets")
        if response.status_code == 200:
            targets = response.json()
            display = []
            for t in targets:
                display.append({
                    "name": t.get("name", ""),
                    "adapter": t.get("adapter_type", ""),
                    "path": t.get("path", t.get("config", {}).get("path", "")),
                })
            fmt.print_table(display, columns=["name", "adapter", "path"])
        else:
            click.echo(f"Error: {response.status_code}", err=True)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()


@target.command("add")
@click.argument("name")
@click.option("--adapter", required=True, type=click.Choice(["filesystem", "sharepoint", "onedrive", "s3", "gcs"]))
@click.option("--path", required=True, help="Path or site URL to scan")
@server_options
def target_add(name: str, adapter: str, path: str, server: str, token: str | None) -> None:
    """Add a new scan target."""
    client = get_api_client(server, token)

    try:
        response = client.post(
            "/api/targets",
            json={
                "name": name,
                "adapter_type": adapter,
                "config": {"path": path},
            }
        )
        if response.status_code == 201:
            target_data = response.json()
            click.echo(f"Created target: {target_data.get('name')} (ID: {target_data.get('id')})")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()

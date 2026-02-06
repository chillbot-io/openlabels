"""
Scan target management commands.
"""

import click
import httpx

from openlabels.cli.utils import get_httpx_client, get_server_url, handle_http_error


@click.group()
def target():
    """Scan target management."""
    pass


@target.command("list")
def target_list():
    """List configured scan targets."""
    client = get_httpx_client()
    server = get_server_url()

    try:
        response = client.get(f"{server}/api/targets")
        if response.status_code == 200:
            targets = response.json()
            click.echo(f"{'Name':<25} {'Adapter':<12} {'Path':<40}")
            click.echo("-" * 80)
            for target in targets:
                name = target.get('name', '')[:24]
                adapter = target.get('adapter_type', '')
                path = target.get('path', target.get('config', {}).get('path', ''))[:39]
                click.echo(f"{name:<25} {adapter:<12} {path:<40}")
        else:
            click.echo(f"Error: {response.status_code}", err=True)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()


@target.command("add")
@click.argument("name")
@click.option("--adapter", required=True, type=click.Choice(["filesystem", "sharepoint", "onedrive"]))
@click.option("--path", required=True, help="Path or site URL to scan")
def target_add(name: str, adapter: str, path: str):
    """Add a new scan target."""
    client = get_httpx_client()
    server = get_server_url()

    try:
        response = client.post(
            f"{server}/api/targets",
            json={
                "name": name,
                "adapter_type": adapter,
                "config": {"path": path},
            }
        )
        if response.status_code == 201:
            target = response.json()
            click.echo(f"Created target: {target.get('name')} (ID: {target.get('id')})")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()

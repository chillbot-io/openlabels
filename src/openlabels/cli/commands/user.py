"""
User management commands.
"""

import click
import httpx

from openlabels.cli.utils import get_httpx_client, get_server_url


@click.group()
def user():
    """User management commands."""
    pass


@user.command("list")
def user_list():
    """List all users."""
    client = get_httpx_client()
    server = get_server_url()

    try:
        response = client.get(f"{server}/api/users")
        if response.status_code == 200:
            users = response.json()
            click.echo(f"{'Email':<30} {'Role':<10} {'Created':<20}")
            click.echo("-" * 60)
            for user in users:
                click.echo(f"{user.get('email', ''):<30} {user.get('role', ''):<10} {user.get('created_at', '')[:19]:<20}")
        elif response.status_code == 401:
            click.echo("Error: Authentication required. Set OPENLABELS_API_KEY", err=True)
        else:
            click.echo(f"Error: {response.status_code}", err=True)
    except httpx.TimeoutException:
        click.echo("Error: Request timed out connecting to server", err=True)
    except httpx.ConnectError as e:
        click.echo(f"Error: Cannot connect to server at {server}: {e}", err=True)
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: HTTP error {e.response.status_code}", err=True)
    finally:
        client.close()


@user.command("create")
@click.argument("email")
@click.option("--role", default="viewer", type=click.Choice(["admin", "viewer"]))
def user_create(email: str, role: str):
    """Create a new user."""
    client = get_httpx_client()
    server = get_server_url()

    try:
        response = client.post(
            f"{server}/api/users",
            json={"email": email, "role": role}
        )
        if response.status_code == 201:
            user = response.json()
            click.echo(f"Created user: {user.get('email')}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)
    except httpx.TimeoutException:
        click.echo("Error: Request timed out connecting to server", err=True)
    except httpx.ConnectError as e:
        click.echo(f"Error: Cannot connect to server at {server}: {e}", err=True)
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: HTTP error {e.response.status_code}", err=True)
    finally:
        client.close()

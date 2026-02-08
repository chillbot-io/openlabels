"""User management commands."""

import click
import httpx

from openlabels.cli.base import format_option, get_api_client, server_options
from openlabels.cli.output import OutputFormatter
from openlabels.cli.utils import handle_http_error


@click.group()
def user() -> None:
    """User management commands."""
    pass


@user.command("list")
@server_options
@format_option()
def user_list(server: str, token: str | None, output_format: str) -> None:
    """List all users."""
    fmt = OutputFormatter(output_format)
    client = get_api_client(server, token)

    try:
        response = client.get("/api/users")
        if response.status_code == 200:
            users = response.json()
            display = []
            for u in users:
                display.append({
                    "email": u.get("email", ""),
                    "role": u.get("role", ""),
                    "created": u.get("created_at", "")[:19],
                })
            fmt.print_table(display, columns=["email", "role", "created"])
        elif response.status_code == 401:
            click.echo("Error: Authentication required. Set OPENLABELS_API_KEY", err=True)
        else:
            click.echo(f"Error: {response.status_code}", err=True)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()


@user.command("create")
@click.argument("email")
@click.option("--role", default="viewer", type=click.Choice(["admin", "viewer"]))
@server_options
def user_create(email: str, role: str, server: str, token: str | None) -> None:
    """Create a new user."""
    client = get_api_client(server, token)

    try:
        response = client.post(
            "/api/users",
            json={"email": email, "role": role}
        )
        if response.status_code == 201:
            user_data = response.json()
            click.echo(f"Created user: {user_data.get('email')}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()

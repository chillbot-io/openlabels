"""Export commands."""

import click
import httpx

from openlabels.cli.base import get_api_client, server_options
from openlabels.cli.utils import handle_http_error
from openlabels.core.path_validation import PathValidationError, validate_output_path


@click.group()
def export() -> None:
    """Export commands."""
    pass


@export.command("results")
@click.option("--job", required=True, help="Job ID to export")
@click.option("--format", "fmt", default="csv", type=click.Choice(["csv", "json"]))
@click.option("--output", required=True, help="Output file path")
@server_options
def export_results(job: str, fmt: str, output: str, server: str, token: str | None) -> None:
    """Export scan results."""
    try:
        validated_output = validate_output_path(output, create_parent=True)
    except PathValidationError as e:
        click.echo(f"Error: Invalid output path: {e}", err=True)
        return

    client = get_api_client(server, token)

    try:
        response = client.get(
            f"{server}/api/results/export",
            params={"job_id": job, "format": fmt}
        )

        if response.status_code == 200:
            with open(validated_output, "wb") as f:
                f.write(response.content)
            click.echo(f"Exported to: {validated_output}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    except OSError as e:
        click.echo(f"Error: Cannot write to output file: {e}", err=True)
    finally:
        client.close()

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

    from openlabels.cli.base import spinner

    client = get_api_client(server, token)

    try:
        with spinner("Exporting results...") as progress:
            task = progress.add_task("Downloading export...", total=None)
            response = client.get(
                "/api/results/export",
                params={"job_id": job, "format": fmt}
            )

        if response.status_code == 200:
            with open(validated_output, "wb") as f:
                f.write(response.content)
            size_kb = len(response.content) / 1024
            click.echo(f"Exported to: {validated_output} ({size_kb:.1f} KB)")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    except OSError as e:
        click.echo(f"Error: Cannot write to output file: {e}", err=True)
    finally:
        client.close()


@export.command("siem")
@click.option(
    "--adapter",
    default=None,
    type=click.Choice(["splunk", "sentinel", "qradar", "elastic", "syslog_cef"]),
    help="Export to a specific adapter (all configured if omitted)",
)
@click.option("--since", default=None, help="Export records since ISO datetime")
@click.option("--test", "test_conn", is_flag=True, help="Test connection only")
@server_options
def export_siem(
    adapter: str | None,
    since: str | None,
    test_conn: bool,
    server: str,
    token: str | None,
) -> None:
    """Export findings to configured SIEM platforms."""
    from openlabels.cli.base import spinner

    client = get_api_client(server, token)

    try:
        if test_conn:
            with spinner("Testing SIEM connections..."):
                response = client.post("/api/v1/export/siem/test")
            if response.status_code == 200:
                data = response.json()
                for name, ok in data.get("results", {}).items():
                    status = "OK" if ok else "FAILED"
                    click.echo(f"  {name}: {status}")
            else:
                click.echo(f"Error: {response.status_code} - {response.text}", err=True)
            return

        payload: dict = {}
        if adapter:
            payload["adapter"] = adapter
        if since:
            payload["since"] = since

        with spinner("Exporting to SIEM..."):
            response = client.post("/api/v1/export/siem", json=payload)

        if response.status_code == 200:
            data = response.json()
            click.echo(f"Exported {data.get('total_records', 0)} records:")
            for name, count in data.get("exported", {}).items():
                click.echo(f"  {name}: {count} records")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()

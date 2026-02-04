"""
System commands (status, backup, restore).
"""

import json
import logging
from pathlib import Path

import click
import httpx

from openlabels.cli.utils import get_httpx_client, get_server_url

logger = logging.getLogger(__name__)


@click.command()
def status():
    """Show OpenLabels system status.

    Displays server connectivity, database status, job queue, and monitoring info.

    Examples:
        openlabels status
    """
    client = get_httpx_client()
    server = get_server_url()

    click.echo("OpenLabels Status")
    click.echo("=" * 50)

    # Check server health
    try:
        response = client.get(f"{server}/health", timeout=5.0)
        if response.status_code == 200:
            health = response.json()
            click.echo(f"Server:      ✓ Online ({server})")
            click.echo(f"  Version:   {health.get('version', 'unknown')}")
            click.echo(f"  Database:  {health.get('database', 'unknown')}")
        else:
            click.echo(f"Server:      ✗ Unhealthy (status {response.status_code})")
    except httpx.TimeoutException:
        click.echo(f"Server:      ✗ Offline (connection timed out)")
        click.echo("\nCannot retrieve additional status without server connection.")
        client.close()
        return
    except httpx.ConnectError as e:
        click.echo(f"Server:      ✗ Offline (cannot connect: {e})")
        click.echo("\nCannot retrieve additional status without server connection.")
        client.close()
        return

    # Get job queue status
    try:
        response = client.get(f"{server}/api/jobs/stats")
        if response.status_code == 200:
            stats = response.json()
            click.echo(f"\nJob Queue:")
            click.echo(f"  Pending:   {stats.get('pending', 0)}")
            click.echo(f"  Running:   {stats.get('running', 0)}")
            click.echo(f"  Completed: {stats.get('completed', 0)}")
            click.echo(f"  Failed:    {stats.get('failed', 0)}")
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        logger.debug(f"Failed to get job queue stats: {e}")

    # Get scan statistics
    try:
        response = client.get(f"{server}/api/dashboard/summary")
        if response.status_code == 200:
            summary = response.json()
            click.echo(f"\nScan Summary:")
            click.echo(f"  Total files scanned:  {summary.get('total_files', 0):,}")
            click.echo(f"  Sensitive files:      {summary.get('sensitive_files', 0):,}")
            click.echo(f"  Critical risk:        {summary.get('critical_count', 0):,}")
            click.echo(f"  High risk:            {summary.get('high_count', 0):,}")
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        logger.debug(f"Failed to get dashboard summary: {e}")

    # Get monitored files count
    try:
        from openlabels.monitoring import get_watched_files
        watched = get_watched_files()
        click.echo(f"\nMonitoring:")
        click.echo(f"  Files monitored:      {len(watched)}")
    except ImportError:
        logger.debug("Monitoring module not installed")
    except OSError as e:
        logger.debug(f"Failed to get watched files: {e}")

    # Check MIP availability
    try:
        from openlabels.labeling.mip import MIPClient
        mip = MIPClient()
        if mip.is_available():
            click.echo(f"\nMIP SDK:     ✓ Available")
        else:
            click.echo(f"\nMIP SDK:     ✗ Not available (Windows only)")
    except ImportError:
        click.echo(f"\nMIP SDK:     ✗ Not installed")
    except RuntimeError as e:
        logger.debug(f"Failed to check MIP availability: {e}")

    # Check ML models
    from openlabels.core.constants import DEFAULT_MODELS_DIR
    # PHI/PII-BERT: prefer INT8 quantized, fall back to original
    phi_bert = (DEFAULT_MODELS_DIR / "phi_bert_int8.onnx").exists() or \
               (DEFAULT_MODELS_DIR / "phi_bert.onnx").exists()
    pii_bert = (DEFAULT_MODELS_DIR / "pii_bert_int8.onnx").exists() or \
               (DEFAULT_MODELS_DIR / "pii_bert.onnx").exists()
    rapidocr = (DEFAULT_MODELS_DIR / "rapidocr" / "det.onnx").exists()

    click.echo(f"\nML Models:")
    click.echo(f"  PHI-BERT:  {'✓' if phi_bert else '✗'}")
    click.echo(f"  PII-BERT:  {'✓' if pii_bert else '✗'}")
    click.echo(f"  RapidOCR:  {'✓' if rapidocr else '✗'}")

    client.close()


@click.command()
@click.option("--output", default="./backup", help="Output directory")
def backup(output: str):
    """Backup OpenLabels data."""
    from datetime import datetime

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"openlabels_backup_{timestamp}"

    click.echo(f"Creating backup: {backup_name}")

    # Export data via API
    client = get_httpx_client()
    server = get_server_url()

    backup_dir = output_path / backup_name
    backup_dir.mkdir(exist_ok=True)

    try:
        # Export configurations
        for endpoint in ["targets", "labels", "labels/rules", "schedules"]:
            try:
                response = client.get(f"{server}/api/{endpoint}")
                if response.status_code == 200:
                    with open(backup_dir / f"{endpoint.replace('/', '_')}.json", "w") as f:
                        json.dump(response.json(), f, indent=2)
                    click.echo(f"  Exported: {endpoint}")
            except httpx.TimeoutException:
                click.echo(f"  Failed to export {endpoint}: request timed out", err=True)
            except httpx.ConnectError:
                click.echo(f"  Failed to export {endpoint}: cannot connect to server", err=True)
            except httpx.HTTPStatusError as e:
                click.echo(f"  Failed to export {endpoint}: HTTP {e.response.status_code}", err=True)

        click.echo(f"Backup created: {backup_dir}")

    except OSError as e:
        click.echo(f"Backup failed: file system error: {e}", err=True)
    finally:
        client.close()


@click.command()
@click.option("--from", "from_path", required=True, help="Backup directory to restore from")
def restore(from_path: str):
    """Restore OpenLabels data from backup."""
    backup_path = Path(from_path)

    if not backup_path.exists():
        click.echo(f"Backup not found: {from_path}", err=True)
        return

    click.echo(f"Restoring from: {backup_path}")

    client = get_httpx_client()
    server = get_server_url()

    try:
        # Restore configurations
        for file in backup_path.glob("*.json"):
            endpoint = file.stem.replace("_", "/")
            try:
                with open(file) as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        response = client.post(f"{server}/api/{endpoint}", json=item)
                        if response.status_code not in (200, 201):
                            click.echo(f"  Warning: Failed to restore item in {endpoint}", err=True)
                    click.echo(f"  Restored: {endpoint} ({len(data)} items)")
                else:
                    click.echo(f"  Skipped: {file.name} (not a list)")

            except json.JSONDecodeError as e:
                click.echo(f"  Failed to restore {file.name}: invalid JSON: {e}", err=True)
            except httpx.TimeoutException:
                click.echo(f"  Failed to restore {file.name}: request timed out", err=True)
            except httpx.ConnectError:
                click.echo(f"  Failed to restore {file.name}: cannot connect to server", err=True)
            except httpx.HTTPStatusError as e:
                click.echo(f"  Failed to restore {file.name}: HTTP {e.response.status_code}", err=True)

        click.echo("Restore completed")

    except OSError as e:
        click.echo(f"Restore failed: file system error: {e}", err=True)
    finally:
        client.close()

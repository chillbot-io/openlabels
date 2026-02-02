"""
OpenLabels CLI entry point.

Usage:
    openlabels serve [--host HOST] [--port PORT] [--workers N]
    openlabels worker [--concurrency N]
    openlabels gui [--server URL]
    openlabels db upgrade
    openlabels config show
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click


@click.group()
@click.version_option()
def cli():
    """OpenLabels - Data Classification & Auto-Labeling Platform"""
    pass


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--workers", default=4, type=int, help="Number of worker processes")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, workers: int, reload: bool):
    """Start the OpenLabels API server."""
    import uvicorn

    uvicorn.run(
        "openlabels.server.app:app",
        host=host,
        port=port,
        workers=1 if reload else workers,
        reload=reload,
    )


@cli.command()
@click.option("--concurrency", default=None, type=int, help="Number of concurrent jobs")
def worker(concurrency: int):
    """Start a worker process for job execution."""
    from openlabels.jobs.worker import run_worker

    run_worker(concurrency=concurrency)


@cli.command()
@click.option("--server", default="http://localhost:8000", help="Server URL to connect to")
def gui(server: str):
    """Launch the OpenLabels GUI application."""
    from openlabels.gui.main import run_gui

    run_gui(server_url=server)


@cli.group()
def db():
    """Database management commands."""
    pass


@db.command("upgrade")
@click.option("--revision", default="head", help="Revision to upgrade to")
def db_upgrade(revision: str):
    """Apply database migrations."""
    from openlabels.server.db import run_migrations

    run_migrations(revision)
    click.echo(f"Database upgraded to {revision}")


@db.command("downgrade")
@click.option("--revision", required=True, help="Revision to downgrade to")
def db_downgrade(revision: str):
    """Revert database migrations."""
    from openlabels.server.db import run_migrations

    run_migrations(revision, direction="downgrade")
    click.echo(f"Database downgraded to {revision}")


@cli.group()
def config():
    """Configuration management."""
    pass


@config.command("show")
def config_show():
    """Display current configuration."""
    from openlabels.server.config import get_settings

    settings = get_settings()
    click.echo(settings.model_dump_json(indent=2))


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """
    Set a configuration value.

    KEY is a dot-separated path like 'server.port' or 'cors.allowed_origins'.
    VALUE is the value to set. For lists, use comma-separated values.

    Examples:
        openlabels config set server.port 9000
        openlabels config set server.debug true
        openlabels config set cors.allowed_origins http://localhost:3000,http://example.com
    """
    import yaml
    from pathlib import Path

    # Determine config file location
    config_paths = [
        Path("config.yaml"),
        Path("config/config.yaml"),
        Path.home() / ".openlabels" / "config.yaml",
    ]

    config_path = None
    for p in config_paths:
        if p.exists():
            config_path = p
            break

    # Default to first path if none exist
    if config_path is None:
        config_path = config_paths[0]

    # Load existing config
    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}
        # Create parent directories if needed
        config_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse the key path
    keys = key.split(".")
    current = config

    # Navigate/create nested structure
    for k in keys[:-1]:
        if k not in current:
            current[k] = {}
        elif not isinstance(current[k], dict):
            click.echo(f"Error: Cannot set nested key under non-dict value at '{k}'", err=True)
            return
        current = current[k]

    # Convert value to appropriate type
    final_key = keys[-1]
    converted_value: any

    # Handle booleans
    if value.lower() in ("true", "yes", "on", "1"):
        converted_value = True
    elif value.lower() in ("false", "no", "off", "0"):
        converted_value = False
    # Handle integers
    elif value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        converted_value = int(value)
    # Handle floats
    elif value.replace(".", "", 1).replace("-", "", 1).isdigit():
        converted_value = float(value)
    # Handle lists (comma-separated)
    elif "," in value:
        converted_value = [v.strip() for v in value.split(",")]
    # Handle null
    elif value.lower() in ("null", "none", "~"):
        converted_value = None
    else:
        converted_value = value

    # Set the value
    current[final_key] = converted_value

    # Write config back
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    click.echo(f"Set {key} = {converted_value}")
    click.echo(f"Config saved to: {config_path}")
    click.echo("Note: Server restart required for changes to take effect")


def _get_httpx_client():
    """Get httpx client for CLI commands."""
    try:
        import httpx
        return httpx.Client(timeout=30.0)
    except ImportError:
        click.echo("Error: httpx not installed. Run: pip install httpx", err=True)
        sys.exit(1)


def _get_server_url():
    """Get server URL from environment or default."""
    import os
    return os.environ.get("OPENLABELS_SERVER", "http://localhost:8000")


@cli.group()
def user():
    """User management commands."""
    pass


@user.command("list")
def user_list():
    """List all users."""
    client = _get_httpx_client()
    server = _get_server_url()

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
    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@user.command("create")
@click.argument("email")
@click.option("--role", default="viewer", type=click.Choice(["admin", "viewer"]))
def user_create(email: str, role: str):
    """Create a new user."""
    client = _get_httpx_client()
    server = _get_server_url()

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
    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@cli.group()
def target():
    """Scan target management."""
    pass


@target.command("list")
def target_list():
    """List configured scan targets."""
    client = _get_httpx_client()
    server = _get_server_url()

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
    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@target.command("add")
@click.argument("name")
@click.option("--adapter", required=True, type=click.Choice(["filesystem", "sharepoint", "onedrive"]))
@click.option("--path", required=True, help="Path or site URL to scan")
def target_add(name: str, adapter: str, path: str):
    """Add a new scan target."""
    client = _get_httpx_client()
    server = _get_server_url()

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
    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@cli.group()
def scan():
    """Scan management commands."""
    pass


@scan.command("start")
@click.argument("target_name")
def scan_start(target_name: str):
    """Start a scan on the specified target."""
    client = _get_httpx_client()
    server = _get_server_url()

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
            scan = response.json()
            click.echo(f"Started scan: {scan.get('id')}")
            click.echo(f"Status: {scan.get('status')}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@scan.command("status")
@click.argument("job_id")
def scan_status(job_id: str):
    """Check status of a scan job."""
    client = _get_httpx_client()
    server = _get_server_url()

    try:
        response = client.get(f"{server}/api/scans/{job_id}")
        if response.status_code == 200:
            scan = response.json()
            click.echo(f"Job ID:     {scan.get('id')}")
            click.echo(f"Status:     {scan.get('status')}")
            click.echo(f"Started:    {scan.get('started_at', 'N/A')}")
            click.echo(f"Completed:  {scan.get('completed_at', 'N/A')}")

            progress = scan.get("progress", {})
            if progress:
                click.echo(f"Progress:   {progress.get('files_scanned', 0)}/{progress.get('files_total', 0)} files")
        else:
            click.echo(f"Error: {response.status_code}", err=True)

    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@scan.command("cancel")
@click.argument("job_id")
def scan_cancel(job_id: str):
    """Cancel a running scan."""
    client = _get_httpx_client()
    server = _get_server_url()

    try:
        response = client.delete(f"{server}/api/scans/{job_id}")
        if response.status_code in (200, 204):
            click.echo(f"Cancelled scan: {job_id}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@cli.group()
def labels():
    """Label management commands."""
    pass


@labels.command("list")
def labels_list():
    """List configured sensitivity labels."""
    client = _get_httpx_client()
    server = _get_server_url()

    try:
        response = client.get(f"{server}/api/labels")
        if response.status_code == 200:
            labels = response.json()
            click.echo(f"{'Name':<30} {'Priority':<10} {'ID'}")
            click.echo("-" * 80)
            for label in labels:
                click.echo(f"{label.get('name', ''):<30} {label.get('priority', 0):<10} {label.get('id', '')}")
        else:
            click.echo(f"Error: {response.status_code}", err=True)

    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@labels.command("sync")
def labels_sync():
    """Sync sensitivity labels from Microsoft 365."""
    client = _get_httpx_client()
    server = _get_server_url()

    try:
        click.echo("Syncing labels from M365...")
        response = client.post(f"{server}/api/labels/sync")
        if response.status_code == 202:
            result = response.json()
            click.echo(f"Synced {result.get('labels_synced', 0)} labels")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except Exception as e:
        click.echo(f"Error connecting to server: {e}", err=True)
    finally:
        client.close()


@labels.command("apply")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--label", required=True, help="Label name or ID to apply")
@click.option("--justification", help="Justification for downgrade (if applicable)")
@click.option("--dry-run", is_flag=True, help="Preview without applying")
def labels_apply(file_path: str, label: str, justification: Optional[str], dry_run: bool):
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

        # Try to get label from cache first
        cache = get_label_cache()
        cached_label = cache.get_by_name(label)

        if cached_label:
            label_id = cached_label.label_id
            label_name = cached_label.name
        else:
            # Assume it's a label ID
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
    except Exception as e:
        click.echo(f"Error applying label: {e}", err=True)
        sys.exit(1)


@labels.command("remove")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--justification", help="Justification for label removal")
@click.option("--dry-run", is_flag=True, help="Preview without removing")
def labels_remove(file_path: str, justification: Optional[str], dry_run: bool):
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
    except Exception as e:
        click.echo(f"Error removing label: {e}", err=True)
        sys.exit(1)


@labels.command("info")
@click.argument("file_path", type=click.Path(exists=True))
def labels_info(file_path: str):
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
    except Exception as e:
        click.echo(f"Error getting label info: {e}", err=True)
        sys.exit(1)


@cli.command()
def status():
    """Show OpenLabels system status.

    Displays server connectivity, database status, job queue, and monitoring info.

    Examples:
        openlabels status
    """
    client = _get_httpx_client()
    server = _get_server_url()

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
    except Exception as e:
        click.echo(f"Server:      ✗ Offline ({e})")
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
    except Exception:
        pass

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
    except Exception:
        pass

    # Get monitored files count
    try:
        from openlabels.monitoring import get_watched_files
        watched = get_watched_files()
        click.echo(f"\nMonitoring:")
        click.echo(f"  Files monitored:      {len(watched)}")
    except ImportError:
        pass
    except Exception:
        pass

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
    except Exception:
        pass

    # Check ML models
    try:
        models_dir = Path.home() / ".openlabels" / "models"
        phi_bert = models_dir / "phi-bert" / "model.onnx"
        pii_bert = models_dir / "pii-bert" / "model.onnx"
        rapidocr = models_dir / "rapidocr" / "det.onnx"

        click.echo(f"\nML Models:")
        click.echo(f"  PHI-BERT:  {'✓' if phi_bert.exists() else '✗'}")
        click.echo(f"  PII-BERT:  {'✓' if pii_bert.exists() else '✗'}")
        click.echo(f"  RapidOCR:  {'✓' if rapidocr.exists() else '✗'}")
    except Exception:
        pass

    client.close()


@cli.command()
@click.option("--output", default="./backup", help="Output directory")
def backup(output: str):
    """Backup OpenLabels data."""
    import shutil
    from datetime import datetime

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"openlabels_backup_{timestamp}"

    click.echo(f"Creating backup: {backup_name}")

    # Export data via API
    client = _get_httpx_client()
    server = _get_server_url()

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
            except Exception as e:
                click.echo(f"  Failed to export {endpoint}: {e}", err=True)

        click.echo(f"Backup created: {backup_dir}")

    except Exception as e:
        click.echo(f"Backup failed: {e}", err=True)
    finally:
        client.close()


@cli.command()
@click.option("--from", "from_path", required=True, help="Backup directory to restore from")
def restore(from_path: str):
    """Restore OpenLabels data from backup."""
    backup_path = Path(from_path)

    if not backup_path.exists():
        click.echo(f"Backup not found: {from_path}", err=True)
        return

    click.echo(f"Restoring from: {backup_path}")

    client = _get_httpx_client()
    server = _get_server_url()

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

            except Exception as e:
                click.echo(f"  Failed to restore {file.name}: {e}", err=True)

        click.echo("Restore completed")

    except Exception as e:
        click.echo(f"Restore failed: {e}", err=True)
    finally:
        client.close()


@cli.group()
def export():
    """Export commands."""
    pass


@export.command("results")
@click.option("--job", required=True, help="Job ID to export")
@click.option("--format", "fmt", default="csv", type=click.Choice(["csv", "json"]))
@click.option("--output", required=True, help="Output file path")
def export_results(job: str, fmt: str, output: str):
    """Export scan results."""
    client = _get_httpx_client()
    server = _get_server_url()

    try:
        response = client.get(
            f"{server}/api/results/export",
            params={"job_id": job, "format": fmt}
        )

        if response.status_code == 200:
            with open(output, "wb") as f:
                f.write(response.content)
            click.echo(f"Exported to: {output}")
        else:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)

    except Exception as e:
        click.echo(f"Error exporting results: {e}", err=True)
    finally:
        client.close()


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--exposure", default="PRIVATE", type=click.Choice(["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]))
@click.option("--enable-ml", is_flag=True, help="Enable ML-based detectors")
@click.option("--recursive", "-r", is_flag=True, help="Scan directories recursively")
@click.option("--output", "-o", help="Output file for results (JSON)")
@click.option("--min-score", default=0, type=int, help="Minimum risk score to report")
def classify(path: str, exposure: str, enable_ml: bool, recursive: bool, output: Optional[str], min_score: int):
    """Classify files locally (no server required).

    Can classify a single file or a directory of files.

    Examples:
        openlabels classify ./document.docx
        openlabels classify ./data/ --recursive --output results.json
        openlabels classify ./folder/ -r --min-score 50
    """
    target_path = Path(path)

    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*"))
        else:
            files = list(target_path.glob("*"))
        files = [f for f in files if f.is_file()]
        click.echo(f"Classifying {len(files)} files...")
    else:
        files = [target_path]
        click.echo(f"Classifying: {path}")

    try:
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=enable_ml)
        results = []

        async def process_all():
            all_results = []
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()

                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level=exposure,
                    )
                    all_results.append(result)
                except Exception as e:
                    click.echo(f"Error processing {file_path}: {e}", err=True)
            return all_results

        results = asyncio.run(process_all())

        # Filter by min_score
        results = [r for r in results if r.risk_score >= min_score]

        # Output results
        if output:
            # JSON output
            output_data = []
            for result in results:
                output_data.append({
                    "file": result.file_name,
                    "risk_score": result.risk_score,
                    "risk_tier": result.risk_tier.value,
                    "entity_counts": result.entity_counts,
                    "error": result.error,
                })
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)
            click.echo(f"\nResults written to: {output}")
            click.echo(f"Files processed: {len(results)}")
            click.echo(f"Files with risk >= {min_score}: {len([r for r in results if r.risk_score >= min_score])}")
        else:
            # Console output
            for result in results:
                click.echo(f"\n{'=' * 50}")
                click.echo(f"File: {result.file_name}")
                click.echo("-" * 50)
                click.echo(f"Risk Score: {result.risk_score}")
                click.echo(f"Risk Tier:  {result.risk_tier.value}")
                click.echo(f"Entities:   {sum(result.entity_counts.values())}")

                if result.entity_counts:
                    click.echo("\nDetected Entities:")
                    for entity_type, count in sorted(result.entity_counts.items(), key=lambda x: -x[1]):
                        click.echo(f"  {entity_type}: {count}")

                if result.error:
                    click.echo(f"\nError: {result.error}", err=True)

            if len(results) > 1:
                click.echo(f"\n{'=' * 50}")
                click.echo(f"Summary: {len(results)} files processed")
                high_risk = [r for r in results if r.risk_score >= 55]
                if high_risk:
                    click.echo(f"High/Critical risk: {len(high_risk)} files")

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
    except Exception as e:
        click.echo(f"Error classifying file: {e}", err=True)


# =============================================================================
# REMEDIATION COMMANDS
# =============================================================================


@cli.command()
@click.argument("source", type=click.Path(exists=True))
@click.argument("destination", type=click.Path())
@click.option("--preserve-acls/--no-preserve-acls", default=True, help="Preserve ACLs during move")
@click.option("--dry-run", is_flag=True, help="Preview without moving")
def quarantine(source: str, destination: str, preserve_acls: bool, dry_run: bool):
    """Quarantine a sensitive file to a secure location.

    Moves the file from SOURCE to DESTINATION, optionally preserving ACLs.
    On Windows uses robocopy for ACL preservation, on Unix uses rsync.

    Examples:
        openlabels quarantine ./sensitive.xlsx ./quarantine/
        openlabels quarantine ./file.docx /secure/vault/ --dry-run
    """
    from openlabels.remediation import quarantine as do_quarantine

    source_path = Path(source)
    dest_path = Path(destination)

    if dry_run:
        click.echo(f"DRY RUN: Would move {source_path} -> {dest_path}")
        click.echo(f"  Preserve ACLs: {preserve_acls}")

    result = do_quarantine(
        source=source_path,
        destination=dest_path,
        preserve_acls=preserve_acls,
        dry_run=dry_run,
    )

    if result.success:
        if dry_run:
            click.echo("Dry run completed successfully")
        else:
            click.echo(f"Quarantined: {result.source_path}")
            click.echo(f"        To: {result.dest_path}")
            click.echo(f"        By: {result.performed_by}")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@cli.command("lock-down")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--principals", multiple=True, help="Principals to grant access (repeatable)")
@click.option("--keep-inheritance", is_flag=True, help="Keep permission inheritance")
@click.option("--backup-acl", is_flag=True, help="Backup current ACL for rollback")
@click.option("--dry-run", is_flag=True, help="Preview without changing permissions")
def lock_down_cmd(file_path: str, principals: tuple, keep_inheritance: bool, backup_acl: bool, dry_run: bool):
    """Lock down file permissions to restrict access.

    Removes all permissions except for specified principals (defaults to
    Administrators on Windows, root on Unix).

    Examples:
        openlabels lock-down ./sensitive.xlsx
        openlabels lock-down ./file.docx --principals admin --principals secteam
        openlabels lock-down ./file.txt --dry-run --backup-acl
    """
    from openlabels.remediation import lock_down

    path = Path(file_path)
    principal_list = list(principals) if principals else None

    if dry_run:
        click.echo(f"DRY RUN: Would lock down {path}")
        if principal_list:
            click.echo(f"  Allowed principals: {principal_list}")
        click.echo(f"  Remove inheritance: {not keep_inheritance}")

    result = lock_down(
        path=path,
        allowed_principals=principal_list,
        remove_inheritance=not keep_inheritance,
        backup_acl=backup_acl,
        dry_run=dry_run,
    )

    if result.success:
        if dry_run:
            click.echo("Dry run completed successfully")
        else:
            click.echo(f"Locked down: {result.source_path}")
            click.echo(f"  Principals: {', '.join(result.principals or [])}")
        if result.previous_acl and backup_acl:
            click.echo(f"  ACL backup saved (can be used for rollback)")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


# =============================================================================
# MONITORING COMMANDS
# =============================================================================


@cli.group()
def monitor():
    """File access monitoring commands."""
    pass


@monitor.command("enable")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--risk-tier", default="HIGH", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
@click.option("--audit-read/--no-audit-read", default=True, help="Audit read access")
@click.option("--audit-write/--no-audit-write", default=True, help="Audit write access")
def monitor_enable(file_path: str, risk_tier: str, audit_read: bool, audit_write: bool):
    """Enable access monitoring on a file.

    On Windows: Adds SACL audit rules to capture access events.
    On Linux: Adds auditd rules via auditctl.

    Prerequisites:
        Windows: "Audit object access" must be enabled in security policy
        Linux: auditd service must be running, requires root

    Examples:
        openlabels monitor enable ./sensitive.xlsx
        openlabels monitor enable ./secrets.json --risk-tier CRITICAL
    """
    from openlabels.monitoring import enable_monitoring

    path = Path(file_path)

    result = enable_monitoring(
        path=path,
        risk_tier=risk_tier,
        audit_read=audit_read,
        audit_write=audit_write,
    )

    if result.success:
        click.echo(f"Monitoring enabled: {path}")
        click.echo(f"  Risk tier: {risk_tier}")
        if result.sacl_enabled:
            click.echo("  SACL: enabled")
        if result.audit_rule_enabled:
            click.echo("  Audit rule: enabled")
        if result.message:
            click.echo(f"  Note: {result.message}")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@monitor.command("disable")
@click.argument("file_path", type=click.Path(exists=True))
def monitor_disable(file_path: str):
    """Disable access monitoring on a file.

    Removes the SACL (Windows) or audit rule (Linux).

    Examples:
        openlabels monitor disable ./sensitive.xlsx
    """
    from openlabels.monitoring import disable_monitoring

    path = Path(file_path)

    result = disable_monitoring(path=path)

    if result.success:
        click.echo(f"Monitoring disabled: {path}")
        if result.message:
            click.echo(f"  {result.message}")
    else:
        click.echo(f"Error: {result.error}", err=True)
        sys.exit(1)


@monitor.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def monitor_list(as_json: bool):
    """List all monitored files.

    Shows files that have been registered for access monitoring.

    Examples:
        openlabels monitor list
        openlabels monitor list --json
    """
    from openlabels.monitoring import get_watched_files

    watched = get_watched_files()

    if as_json:
        import json as json_mod
        output = [w.to_dict() for w in watched]
        click.echo(json_mod.dumps(output, indent=2, default=str))
    elif not watched:
        click.echo("No files currently monitored")
    else:
        click.echo(f"{'Path':<50} {'Risk':<10} {'Added':<20}")
        click.echo("-" * 80)
        for w in watched:
            path_str = str(w.path)[:49]
            added = w.added_at.strftime("%Y-%m-%d %H:%M") if w.added_at else "N/A"
            click.echo(f"{path_str:<50} {w.risk_tier:<10} {added:<20}")


@monitor.command("history")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--days", default=30, type=int, help="Number of days to look back")
@click.option("--limit", default=50, type=int, help="Maximum events to return")
@click.option("--include-system", is_flag=True, help="Include system account access")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def monitor_history(file_path: str, days: int, limit: int, include_system: bool, as_json: bool):
    """Show access history for a file.

    Queries Windows Event Log or Linux audit logs for access events
    on the specified file.

    Examples:
        openlabels monitor history ./sensitive.xlsx
        openlabels monitor history ./secrets.json --days 7 --limit 100
        openlabels monitor history ./file.docx --json
    """
    from openlabels.monitoring import get_access_history

    path = Path(file_path)

    events = get_access_history(
        path=path,
        days=days,
        limit=limit,
        include_system=include_system,
    )

    if as_json:
        import json as json_mod
        output = [e.to_dict() for e in events]
        click.echo(json_mod.dumps(output, indent=2, default=str))
    elif not events:
        click.echo(f"No access events found for: {path}")
        click.echo(f"  (searched last {days} days)")
    else:
        click.echo(f"Access history for: {path}")
        click.echo(f"{'Timestamp':<20} {'User':<25} {'Action':<12} {'Process':<20}")
        click.echo("-" * 80)
        for event in events:
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            user = event.user_display[:24]
            action = event.action.value
            process = (event.process_name or "")[:19]
            click.echo(f"{ts:<20} {user:<25} {action:<12} {process:<20}")


@monitor.command("status")
@click.argument("file_path", type=click.Path(exists=True))
def monitor_status(file_path: str):
    """Check monitoring status for a file.

    Shows whether a file is being monitored and its configuration.

    Examples:
        openlabels monitor status ./sensitive.xlsx
    """
    from openlabels.monitoring import is_monitored, get_watched_files

    path = Path(file_path).resolve()

    if is_monitored(path):
        # Find the watched file entry
        watched = get_watched_files()
        entry = next((w for w in watched if w.path == path), None)

        click.echo(f"File: {path}")
        click.echo(f"Status: MONITORED")
        if entry:
            click.echo(f"  Risk tier: {entry.risk_tier}")
            click.echo(f"  Added: {entry.added_at.strftime('%Y-%m-%d %H:%M:%S') if entry.added_at else 'N/A'}")
            click.echo(f"  SACL enabled: {entry.sacl_enabled}")
            click.echo(f"  Audit rule enabled: {entry.audit_rule_enabled}")
            if entry.last_event_at:
                click.echo(f"  Last access: {entry.last_event_at.strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo(f"  Access count: {entry.access_count}")
    else:
        click.echo(f"File: {path}")
        click.echo("Status: NOT MONITORED")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()

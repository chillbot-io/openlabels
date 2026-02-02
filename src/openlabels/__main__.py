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
@click.option("--host", default="127.0.0.1", help="Host to bind to (use 0.0.0.0 for network access)")
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
# FIND COMMAND
# =============================================================================


def _validate_where_filter(ctx, param, value):
    """Validate the --where filter option."""
    if value is None:
        return None
    from openlabels.cli.filter_parser import parse_filter, ParseError, LexerError
    try:
        parse_filter(value)
        return value
    except (ParseError, LexerError) as e:
        raise click.BadParameter(f"Invalid filter: {e}")


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--where", "where_filter", callback=_validate_where_filter,
              help='Filter expression (e.g., "score > 75 AND has(SSN)")')
@click.option("--recursive", "-r", is_flag=True, help="Search directories recursively")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv", "paths"]),
              help="Output format")
@click.option("--limit", default=100, type=int, help="Maximum results to return")
@click.option("--sort", "sort_by", default="score", type=click.Choice(["score", "path", "tier", "entities"]),
              help="Sort results by field")
@click.option("--desc/--asc", "descending", default=True, help="Sort direction")
def find(path: str, where_filter: Optional[str], recursive: bool, fmt: str,
         limit: int, sort_by: str, descending: bool):
    """Find sensitive files matching filter criteria.

    Scans files and applies the filter to find matches.

    Filter Grammar:
        score > 75              - Risk score comparison
        tier = CRITICAL         - Exact tier match
        has(SSN)                - Has entity type with count > 0
        count(SSN) >= 10        - Entity count comparison
        path ~ ".*\\.xlsx$"     - Regex path match
        missing(owner)          - Field is empty/null
        NOT has(CREDIT_CARD)    - Negation
        expr AND expr           - Logical AND
        expr OR expr            - Logical OR
        (expr)                  - Grouping

    Examples:
        openlabels find ./data --where "score > 75"
        openlabels find ./docs -r --where "has(SSN) AND tier = CRITICAL"
        openlabels find . -r --where "count(CREDIT_CARD) >= 5" --format json
        openlabels find ./files --where "path ~ '.*\\.xlsx$' AND exposure = PUBLIC"
    """
    from openlabels.cli.filter_executor import filter_scan_results

    target_path = Path(path)

    # Collect files to scan
    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*"))
        else:
            files = list(target_path.glob("*"))
        files = [f for f in files if f.is_file()]
    else:
        files = [target_path]

    if not files:
        click.echo("No files found")
        return

    click.echo(f"Scanning {len(files)} files...", err=True)

    try:
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False)

        async def process_all():
            all_results = []
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()

                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level="PRIVATE",
                    )
                    # Convert to dict for filtering
                    all_results.append({
                        "file_path": str(file_path),
                        "file_name": result.file_name,
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                        "exposure_level": "PRIVATE",
                        "owner": None,
                    })
                except Exception:
                    pass  # Skip files that can't be processed
            return all_results

        results = asyncio.run(process_all())

        # Apply filter if specified
        if where_filter:
            results = filter_scan_results(results, where_filter)

        # Sort results
        sort_key_map = {
            "score": lambda x: x["risk_score"],
            "path": lambda x: x["file_path"],
            "tier": lambda x: ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x["risk_tier"]),
            "entities": lambda x: x["total_entities"],
        }
        results.sort(key=sort_key_map[sort_by], reverse=descending)

        # Apply limit
        results = results[:limit]

        if not results:
            click.echo("No matching files found")
            return

        # Output in requested format
        if fmt == "json":
            click.echo(json.dumps(results, indent=2))
        elif fmt == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["file_path", "risk_score", "risk_tier", "total_entities"])
            writer.writeheader()
            for r in results:
                writer.writerow({k: r[k] for k in ["file_path", "risk_score", "risk_tier", "total_entities"]})
            click.echo(output.getvalue())
        elif fmt == "paths":
            for r in results:
                click.echo(r["file_path"])
        else:
            # Table format
            click.echo(f"\n{'Path':<50} {'Score':<7} {'Tier':<10} {'Entities':<10}")
            click.echo("-" * 80)
            for r in results:
                path_str = r["file_path"]
                if len(path_str) > 49:
                    path_str = "..." + path_str[-46:]
                click.echo(f"{path_str:<50} {r['risk_score']:<7} {r['risk_tier']:<10} {r['total_entities']:<10}")

            click.echo(f"\nFound {len(results)} matching files")

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# =============================================================================
# REPORT COMMAND
# =============================================================================


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--where", "where_filter", callback=_validate_where_filter,
              help='Filter expression (e.g., "score > 75")')
@click.option("--recursive", "-r", is_flag=True, help="Search directories recursively")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json", "csv", "html"]),
              help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
@click.option("--title", default="OpenLabels Scan Report", help="Report title")
def report(path: str, where_filter: Optional[str], recursive: bool, fmt: str,
           output: Optional[str], title: str):
    """Generate a report of sensitive data findings.

    Examples:
        openlabels report ./data -r --format html -o report.html
        openlabels report ./docs --where "tier = CRITICAL" --format json
        openlabels report . -r --where "has(SSN)" --format csv -o findings.csv
    """
    from datetime import datetime
    from openlabels.cli.filter_executor import filter_scan_results

    target_path = Path(path)

    # Collect files
    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*"))
        else:
            files = list(target_path.glob("*"))
        files = [f for f in files if f.is_file()]
    else:
        files = [target_path]

    if not files:
        click.echo("No files found", err=True)
        return

    click.echo(f"Scanning {len(files)} files for report...", err=True)

    try:
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False)

        async def process_all():
            all_results = []
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level="PRIVATE",
                    )
                    all_results.append({
                        "file_path": str(file_path),
                        "file_name": result.file_name,
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                    })
                except Exception:
                    pass
            return all_results

        results = asyncio.run(process_all())

        # Apply filter
        if where_filter:
            results = filter_scan_results(results, where_filter)

        # Sort by risk score descending
        results.sort(key=lambda x: x["risk_score"], reverse=True)

        # Calculate summary statistics
        summary = {
            "total_files": len(files),
            "files_with_findings": len([r for r in results if r["total_entities"] > 0]),
            "total_entities": sum(r["total_entities"] for r in results),
            "by_tier": {
                "CRITICAL": len([r for r in results if r["risk_tier"] == "CRITICAL"]),
                "HIGH": len([r for r in results if r["risk_tier"] == "HIGH"]),
                "MEDIUM": len([r for r in results if r["risk_tier"] == "MEDIUM"]),
                "LOW": len([r for r in results if r["risk_tier"] == "LOW"]),
                "MINIMAL": len([r for r in results if r["risk_tier"] == "MINIMAL"]),
            },
            "by_entity": {},
        }

        # Aggregate entity counts
        for r in results:
            for entity_type, count in r["entity_counts"].items():
                summary["by_entity"][entity_type] = summary["by_entity"].get(entity_type, 0) + count

        # Generate report
        report_data = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "scan_path": str(target_path),
            "filter": where_filter,
            "summary": summary,
            "findings": results,
        }

        def _generate_text():
            lines = []
            lines.append("=" * 70)
            lines.append(title.center(70))
            lines.append("=" * 70)
            lines.append(f"\nGenerated: {report_data['generated_at']}")
            lines.append(f"Scan Path: {report_data['scan_path']}")
            if where_filter:
                lines.append(f"Filter: {where_filter}")
            lines.append("\n" + "-" * 70)
            lines.append("SUMMARY")
            lines.append("-" * 70)
            lines.append(f"Total files scanned: {summary['total_files']}")
            lines.append(f"Files with findings: {summary['files_with_findings']}")
            lines.append(f"Total entities found: {summary['total_entities']}")
            lines.append("\nBy Risk Tier:")
            for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
                count = summary["by_tier"][tier]
                if count > 0:
                    lines.append(f"  {tier}: {count}")
            if summary["by_entity"]:
                lines.append("\nBy Entity Type:")
                for entity, count in sorted(summary["by_entity"].items(), key=lambda x: -x[1]):
                    lines.append(f"  {entity}: {count}")
            if results:
                lines.append("\n" + "-" * 70)
                lines.append("FINDINGS")
                lines.append("-" * 70)
                for r in results[:50]:  # Limit to top 50 in text format
                    lines.append(f"\n{r['file_path']}")
                    lines.append(f"  Risk: {r['risk_score']} ({r['risk_tier']})")
                    if r["entity_counts"]:
                        entities_str = ", ".join(f"{k}:{v}" for k, v in r["entity_counts"].items())
                        lines.append(f"  Entities: {entities_str}")
                if len(results) > 50:
                    lines.append(f"\n... and {len(results) - 50} more findings")
            lines.append("\n" + "=" * 70)
            return "\n".join(lines)

        def _generate_html():
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #4a90d9; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p>Generated: {report_data['generated_at']}<br>
    Scan Path: {report_data['scan_path']}</p>
    {"<p>Filter: " + where_filter + "</p>" if where_filter else ""}
    <div class="summary">
        <h2>Summary</h2>
        <p>Total files: {summary['total_files']}<br>
        Files with findings: {summary['files_with_findings']}<br>
        Total entities: {summary['total_entities']}</p>
        <p>
        <span class="critical">CRITICAL: {summary['by_tier']['CRITICAL']}</span> |
        <span class="high">HIGH: {summary['by_tier']['HIGH']}</span> |
        <span class="medium">MEDIUM: {summary['by_tier']['MEDIUM']}</span> |
        <span class="low">LOW: {summary['by_tier']['LOW']}</span>
        </p>
    </div>
    <h2>Findings</h2>
    <table>
        <tr><th>File</th><th>Score</th><th>Tier</th><th>Entities</th></tr>
"""
            for r in results:
                tier_class = r['risk_tier'].lower()
                entities = ", ".join(f"{k}:{v}" for k, v in r["entity_counts"].items()) or "-"
                html += f"        <tr><td>{r['file_path']}</td><td>{r['risk_score']}</td>"
                html += f"<td class='{tier_class}'>{r['risk_tier']}</td><td>{entities}</td></tr>\n"
            html += """    </table>
</body>
</html>"""
            return html

        # Generate output
        if fmt == "json":
            content = json.dumps(report_data, indent=2, default=str)
        elif fmt == "csv":
            import csv
            import io
            output_io = io.StringIO()
            writer = csv.writer(output_io)
            writer.writerow(["file_path", "risk_score", "risk_tier", "entity_counts"])
            for r in results:
                entities = ";".join(f"{k}:{v}" for k, v in r["entity_counts"].items())
                writer.writerow([r["file_path"], r["risk_score"], r["risk_tier"], entities])
            content = output_io.getvalue()
        elif fmt == "html":
            content = _generate_html()
        else:
            content = _generate_text()

        # Output
        if output:
            with open(output, "w") as f:
                f.write(content)
            click.echo(f"Report written to: {output}")
        else:
            click.echo(content)

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error generating report: {e}", err=True)
        sys.exit(1)


# =============================================================================
# HEATMAP COMMAND
# =============================================================================


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Search directories recursively")
@click.option("--depth", default=2, type=int, help="Directory depth for aggregation")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json"]),
              help="Output format")
def heatmap(path: str, recursive: bool, depth: int, fmt: str):
    """Generate a risk heatmap by directory.

    Shows aggregated risk scores by directory path.

    Examples:
        openlabels heatmap ./data -r
        openlabels heatmap . -r --depth 3 --format json
    """
    from collections import defaultdict

    target_path = Path(path).resolve()

    # Collect files
    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*"))
        else:
            files = list(target_path.glob("*"))
        files = [f for f in files if f.is_file()]
    else:
        files = [target_path]

    if not files:
        click.echo("No files found", err=True)
        return

    click.echo(f"Scanning {len(files)} files for heatmap...", err=True)

    try:
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False)

        async def process_all():
            all_results = []
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level="PRIVATE",
                    )
                    all_results.append({
                        "file_path": file_path,
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                        "total_entities": sum(result.entity_counts.values()),
                    })
                except Exception:
                    pass
            return all_results

        results = asyncio.run(process_all())

        # Aggregate by directory
        dir_stats = defaultdict(lambda: {
            "files": 0,
            "total_score": 0,
            "max_score": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "entities": 0,
        })

        for r in results:
            # Get relative path from target
            try:
                rel_path = r["file_path"].relative_to(target_path)
            except ValueError:
                rel_path = r["file_path"]

            # Get directory at specified depth
            parts = rel_path.parts[:-1]  # Exclude filename
            if len(parts) > depth:
                parts = parts[:depth]
            dir_key = str(Path(*parts)) if parts else "."

            stats = dir_stats[dir_key]
            stats["files"] += 1
            stats["total_score"] += r["risk_score"]
            stats["max_score"] = max(stats["max_score"], r["risk_score"])
            stats["entities"] += r["total_entities"]
            if r["risk_tier"] == "CRITICAL":
                stats["critical"] += 1
            elif r["risk_tier"] == "HIGH":
                stats["high"] += 1
            elif r["risk_tier"] == "MEDIUM":
                stats["medium"] += 1

        # Calculate averages and sort
        heatmap_data = []
        for dir_path, stats in dir_stats.items():
            avg_score = stats["total_score"] / stats["files"] if stats["files"] > 0 else 0
            heatmap_data.append({
                "directory": dir_path,
                "files": stats["files"],
                "avg_score": round(avg_score, 1),
                "max_score": stats["max_score"],
                "critical": stats["critical"],
                "high": stats["high"],
                "medium": stats["medium"],
                "entities": stats["entities"],
            })

        # Sort by max score descending
        heatmap_data.sort(key=lambda x: (x["max_score"], x["avg_score"]), reverse=True)

        if fmt == "json":
            click.echo(json.dumps(heatmap_data, indent=2))
        else:
            # Text heatmap with visual indicators
            click.echo("\nRisk Heatmap by Directory")
            click.echo("=" * 80)
            click.echo(f"{'Directory':<35} {'Files':<7} {'Avg':<6} {'Max':<6} {'C':<4} {'H':<4} {'M':<4}")
            click.echo("-" * 80)

            for h in heatmap_data:
                # Visual risk indicator
                if h["max_score"] >= 80:
                    indicator = "[!!!!]"  # Critical
                elif h["max_score"] >= 55:
                    indicator = "[!!! ]"  # High
                elif h["max_score"] >= 31:
                    indicator = "[!!  ]"  # Medium
                elif h["max_score"] >= 11:
                    indicator = "[!   ]"  # Low
                else:
                    indicator = "[    ]"  # Minimal

                dir_str = h["directory"]
                if len(dir_str) > 34:
                    dir_str = "..." + dir_str[-31:]

                click.echo(f"{dir_str:<35} {h['files']:<7} {h['avg_score']:<6} {h['max_score']:<6} "
                          f"{h['critical']:<4} {h['high']:<4} {h['medium']:<4} {indicator}")

            click.echo("\nLegend: C=Critical, H=High, M=Medium")
            click.echo(f"Total: {len(results)} files in {len(heatmap_data)} directories")

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error generating heatmap: {e}", err=True)
        sys.exit(1)


# =============================================================================
# REMEDIATION COMMANDS
# =============================================================================


@cli.command()
@click.argument("source", type=click.Path(exists=True), required=False)
@click.argument("destination", type=click.Path(), required=False)
@click.option("--where", "where_filter", callback=_validate_where_filter,
              help='Filter to select files (e.g., "tier = CRITICAL AND has(SSN)")')
@click.option("--scan-path", type=click.Path(exists=True), help="Path to scan when using --where")
@click.option("-r", "--recursive", is_flag=True, help="Recursive scan when using --where")
@click.option("--preserve-acls/--no-preserve-acls", default=True, help="Preserve ACLs during move")
@click.option("--dry-run", is_flag=True, help="Preview without moving")
def quarantine(source: Optional[str], destination: Optional[str], where_filter: Optional[str],
               scan_path: Optional[str], recursive: bool, preserve_acls: bool, dry_run: bool):
    """Quarantine sensitive files to a secure location.

    Can quarantine a single file (source -> destination) or multiple files
    matching a filter (--where with --scan-path).

    Examples:
        openlabels quarantine ./sensitive.xlsx ./quarantine/
        openlabels quarantine --where "tier = CRITICAL" --scan-path ./data -r ./quarantine/ --dry-run
        openlabels quarantine --where "has(SSN) AND score > 80" --scan-path . -r /secure/vault/
    """
    from openlabels.remediation import quarantine as do_quarantine

    # Handle batch mode with --where
    if where_filter:
        if not scan_path:
            click.echo("Error: --scan-path required when using --where", err=True)
            sys.exit(1)
        if not destination and not source:
            click.echo("Error: destination required", err=True)
            sys.exit(1)

        dest_path = Path(destination if destination else source)

        # Find matching files
        from openlabels.cli.filter_executor import filter_scan_results
        from openlabels.core.processor import FileProcessor

        target_path = Path(scan_path)
        if target_path.is_dir():
            if recursive:
                files = list(target_path.rglob("*"))
            else:
                files = list(target_path.glob("*"))
            files = [f for f in files if f.is_file()]
        else:
            files = [target_path]

        click.echo(f"Scanning {len(files)} files...", err=True)

        processor = FileProcessor(enable_ml=False)

        async def find_matches():
            all_results = []
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level="PRIVATE",
                    )
                    all_results.append({
                        "file_path": str(file_path),
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                    })
                except Exception:
                    pass
            return all_results

        results = asyncio.run(find_matches())
        matches = filter_scan_results(results, where_filter)

        if not matches:
            click.echo("No files match the filter")
            return

        click.echo(f"Found {len(matches)} matching files")

        if dry_run:
            click.echo("\nDRY RUN - Files that would be quarantined:")
            for m in matches:
                click.echo(f"  {m['file_path']} (score: {m['risk_score']}, tier: {m['risk_tier']})")
            return

        # Quarantine each file
        success_count = 0
        for m in matches:
            result = do_quarantine(
                source=Path(m["file_path"]),
                destination=dest_path,
                preserve_acls=preserve_acls,
                dry_run=False,
            )
            if result.success:
                click.echo(f"Quarantined: {m['file_path']}")
                success_count += 1
            else:
                click.echo(f"Failed: {m['file_path']} - {result.error}", err=True)

        click.echo(f"\nQuarantined {success_count}/{len(matches)} files to {dest_path}")

    else:
        # Single file mode
        if not source or not destination:
            click.echo("Error: SOURCE and DESTINATION required (or use --where with --scan-path)", err=True)
            sys.exit(1)

        source_path = Path(source)
        dest_path = Path(destination)

        if dry_run:
            click.echo(f"DRY RUN: Would move {source_path} -> {dest_path}")
            click.echo(f"  Preserve ACLs: {preserve_acls}")
            return

        result = do_quarantine(
            source=source_path,
            destination=dest_path,
            preserve_acls=preserve_acls,
            dry_run=dry_run,
        )

        if result.success:
            click.echo(f"Quarantined: {result.source_path}")
            click.echo(f"        To: {result.dest_path}")
            click.echo(f"        By: {result.performed_by}")
        else:
            click.echo(f"Error: {result.error}", err=True)
            sys.exit(1)


@cli.command("lock-down")
@click.argument("file_path", type=click.Path(exists=True), required=False)
@click.option("--where", "where_filter", callback=_validate_where_filter,
              help='Filter to select files (e.g., "tier = CRITICAL")')
@click.option("--scan-path", type=click.Path(exists=True), help="Path to scan when using --where")
@click.option("-r", "--recursive", is_flag=True, help="Recursive scan when using --where")
@click.option("--principals", multiple=True, help="Principals to grant access (repeatable)")
@click.option("--keep-inheritance", is_flag=True, help="Keep permission inheritance")
@click.option("--backup-acl", is_flag=True, help="Backup current ACL for rollback")
@click.option("--dry-run", is_flag=True, help="Preview without changing permissions")
def lock_down_cmd(file_path: Optional[str], where_filter: Optional[str], scan_path: Optional[str],
                  recursive: bool, principals: tuple, keep_inheritance: bool, backup_acl: bool, dry_run: bool):
    """Lock down file permissions to restrict access.

    Can lock down a single file or multiple files matching a filter.

    Examples:
        openlabels lock-down ./sensitive.xlsx
        openlabels lock-down --where "tier = CRITICAL" --scan-path ./data -r --dry-run
        openlabels lock-down --where "has(SSN)" --scan-path . -r --principals admin
    """
    from openlabels.remediation import lock_down

    principal_list = list(principals) if principals else None

    # Handle batch mode with --where
    if where_filter:
        if not scan_path:
            click.echo("Error: --scan-path required when using --where", err=True)
            sys.exit(1)

        from openlabels.cli.filter_executor import filter_scan_results
        from openlabels.core.processor import FileProcessor

        target_path = Path(scan_path)
        if target_path.is_dir():
            if recursive:
                files = list(target_path.rglob("*"))
            else:
                files = list(target_path.glob("*"))
            files = [f for f in files if f.is_file()]
        else:
            files = [target_path]

        click.echo(f"Scanning {len(files)} files...", err=True)

        processor = FileProcessor(enable_ml=False)

        async def find_matches():
            all_results = []
            for fp in files:
                try:
                    with open(fp, "rb") as f:
                        content = f.read()
                    result = await processor.process_file(
                        file_path=str(fp),
                        content=content,
                        exposure_level="PRIVATE",
                    )
                    all_results.append({
                        "file_path": str(fp),
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                    })
                except Exception:
                    pass
            return all_results

        results = asyncio.run(find_matches())
        matches = filter_scan_results(results, where_filter)

        if not matches:
            click.echo("No files match the filter")
            return

        click.echo(f"Found {len(matches)} matching files")

        if dry_run:
            click.echo("\nDRY RUN - Files that would be locked down:")
            for m in matches:
                click.echo(f"  {m['file_path']} (score: {m['risk_score']}, tier: {m['risk_tier']})")
            if principal_list:
                click.echo(f"\nAllowed principals: {principal_list}")
            return

        success_count = 0
        for m in matches:
            result = lock_down(
                path=Path(m["file_path"]),
                allowed_principals=principal_list,
                remove_inheritance=not keep_inheritance,
                backup_acl=backup_acl,
                dry_run=False,
            )
            if result.success:
                click.echo(f"Locked down: {m['file_path']}")
                success_count += 1
            else:
                click.echo(f"Failed: {m['file_path']} - {result.error}", err=True)

        click.echo(f"\nLocked down {success_count}/{len(matches)} files")

    else:
        # Single file mode
        if not file_path:
            click.echo("Error: FILE_PATH required (or use --where with --scan-path)", err=True)
            sys.exit(1)

        path = Path(file_path)

        if dry_run:
            click.echo(f"DRY RUN: Would lock down {path}")
            if principal_list:
                click.echo(f"  Allowed principals: {principal_list}")
            click.echo(f"  Remove inheritance: {not keep_inheritance}")
            return

        result = lock_down(
            path=path,
            allowed_principals=principal_list,
            remove_inheritance=not keep_inheritance,
            backup_acl=backup_acl,
            dry_run=dry_run,
        )

        if result.success:
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

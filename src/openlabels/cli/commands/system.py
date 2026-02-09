"""System commands (status, backup, restore)."""

import json
import logging
import os
from pathlib import Path
from urllib.parse import urlparse

import click
import httpx

from openlabels.cli.base import get_api_client, server_options

logger = logging.getLogger(__name__)


def _parse_pg_env(db_url: str) -> dict[str, str]:
    """Parse a PostgreSQL connection URL into PGPASSWORD/PGHOST/etc env vars.

    This avoids passing credentials as CLI arguments to pg_dump/psql
    (which would be visible in ``ps`` output).
    """
    env: dict[str, str] = {}
    try:
        parsed = urlparse(db_url)
        if parsed.hostname:
            env["PGHOST"] = parsed.hostname
        if parsed.port:
            env["PGPORT"] = str(parsed.port)
        if parsed.username:
            env["PGUSER"] = parsed.username
        if parsed.password:
            env["PGPASSWORD"] = parsed.password
        if parsed.path and parsed.path != "/":
            env["PGDATABASE"] = parsed.path.lstrip("/")
    except (ValueError, TypeError):
        # Fallback: let pg_dump/psql parse the URL itself (less secure)
        pass
    return env


@click.command()
@server_options
def status(server: str, token: str | None) -> None:
    """Show OpenLabels system status.

    Displays server connectivity, database status, job queue, and monitoring info.

    Examples:
        openlabels status
    """
    client = get_api_client(server, token)

    click.echo("OpenLabels Status")
    click.echo("=" * 50)

    # Check server health
    try:
        response = client.get("/health", timeout=5.0)
        if response.status_code == 200:
            health = response.json()
            click.echo(f"Server:      \u2713 Online ({server})")
            click.echo(f"  Version:   {health.get('version', 'unknown')}")
            click.echo(f"  Database:  {health.get('database', 'unknown')}")
        else:
            click.echo(f"Server:      \u2717 Unhealthy (status {response.status_code})")
    except httpx.TimeoutException:
        click.echo("Server:      \u2717 Offline (connection timed out)")
        click.echo("\nCannot retrieve additional status without server connection.")
        client.close()
        return
    except httpx.ConnectError as e:
        click.echo(f"Server:      \u2717 Offline (cannot connect: {e})")
        click.echo("\nCannot retrieve additional status without server connection.")
        client.close()
        return

    # Get job queue status
    try:
        response = client.get("/api/jobs/stats")
        if response.status_code == 200:
            stats = response.json()
            click.echo("\nJob Queue:")
            click.echo(f"  Pending:   {stats.get('pending', 0)}")
            click.echo(f"  Running:   {stats.get('running', 0)}")
            click.echo(f"  Completed: {stats.get('completed', 0)}")
            click.echo(f"  Failed:    {stats.get('failed', 0)}")
    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        logger.debug(f"Failed to get job queue stats: {e}")

    # Get scan statistics
    try:
        response = client.get("/api/dashboard/summary")
        if response.status_code == 200:
            summary = response.json()
            click.echo("\nScan Summary:")
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
        click.echo("\nMonitoring:")
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
            click.echo("\nMIP SDK:     \u2713 Available")
        else:
            click.echo("\nMIP SDK:     \u2717 Not available (Windows only)")
    except ImportError:
        click.echo("\nMIP SDK:     \u2717 Not installed")
    except RuntimeError as e:
        logger.debug(f"Failed to check MIP availability: {e}")

    # Check ML models
    from openlabels.core.constants import DEFAULT_MODELS_DIR
    phi_bert = (DEFAULT_MODELS_DIR / "phi_bert_int8.onnx").exists() or \
               (DEFAULT_MODELS_DIR / "phi_bert.onnx").exists()
    pii_bert = (DEFAULT_MODELS_DIR / "pii_bert_int8.onnx").exists() or \
               (DEFAULT_MODELS_DIR / "pii_bert.onnx").exists()
    rapidocr = (DEFAULT_MODELS_DIR / "rapidocr" / "det.onnx").exists()

    check = "\u2713"
    cross = "\u2717"
    click.echo("\nML Models:")
    click.echo(f"  PHI-BERT:  {check if phi_bert else cross}")
    click.echo(f"  PII-BERT:  {check if pii_bert else cross}")
    click.echo(f"  RapidOCR:  {check if rapidocr else cross}")

    client.close()


@click.command()
@click.option("--output", default="./backup", help="Output directory")
@click.option("--include-db", is_flag=True, default=False, help="Include pg_dump database backup")
@click.option("--db-url", default=None, help="PostgreSQL connection URL (overrides config)")
@server_options
def backup(output: str, include_db: bool, db_url: str | None, server: str, token: str | None) -> None:
    """Backup OpenLabels data (API export + optional pg_dump).

    \b
    Examples:
        openlabels system backup
        openlabels system backup --include-db
        openlabels system backup --include-db --db-url postgresql://localhost/openlabels
    """
    import subprocess
    from datetime import datetime, timezone

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_name = f"openlabels_backup_{timestamp}"

    click.echo(f"Creating backup: {backup_name}")

    backup_dir = output_path / backup_name
    backup_dir.mkdir(exist_ok=True)

    # Export API data
    client = get_api_client(server, token)
    try:
        for endpoint in ["targets", "labels", "labels/rules", "schedules", "policies"]:
            try:
                response = client.get(f"/api/{endpoint}")
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
    except OSError as e:
        click.echo(f"API export failed: file system error: {e}", err=True)
    finally:
        client.close()

    # Export config
    try:
        from openlabels.server.config import load_yaml_config
        yaml_config = load_yaml_config()
        if yaml_config:
            config_path = backup_dir / "config.json"
            with open(config_path, "w") as f:
                json.dump(yaml_config, f, indent=2)
            click.echo("  Exported: config.json")
    except (ImportError, OSError) as e:
        logger.debug(f"Config export skipped: {e}")

    # Optional: pg_dump
    if include_db:
        db_connection = db_url
        if not db_connection:
            try:
                from openlabels.server.config import get_settings
                settings = get_settings()
                db_connection = settings.database.url.replace("+asyncpg", "")
            except (ImportError, ValueError) as e:
                click.echo(f"  Cannot determine database URL: {e}", err=True)

        if db_connection:
            dump_path = backup_dir / "database.sql.gz"
            click.echo("  Running pg_dump...")
            try:
                # Pass credentials exclusively via PG* env vars so that
                # passwords (and other connection details) are not visible
                # in ``ps`` output.
                import gzip
                pg_env = _parse_pg_env(db_connection)
                pg_cmd = ["pg_dump", "--no-owner", "--no-acl"]
                # Stream through gzip to avoid holding entire dump in memory
                proc = subprocess.Popen(
                    pg_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={**os.environ, **pg_env},
                )
                with gzip.open(dump_path, "wb") as gz:
                    while True:
                        chunk = proc.stdout.read(65536)
                        if not chunk:
                            break
                        gz.write(chunk)
                proc.wait(timeout=600)
                if proc.returncode == 0:
                    click.echo(f"  Exported: database.sql.gz ({dump_path.stat().st_size:,} bytes)")
                else:
                    stderr_out = proc.stderr.read().decode()[:200] if proc.stderr else ""
                    click.echo(f"  pg_dump failed: {stderr_out}", err=True)
            except FileNotFoundError:
                click.echo("  ERROR: pg_dump not found on PATH. Database backup SKIPPED.", err=True)
            except subprocess.TimeoutExpired:
                click.echo("  pg_dump timed out after 10 minutes.", err=True)

    click.echo(f"\nBackup created: {backup_dir}")


@click.command()
@click.option("--from", "from_path", required=True, help="Backup directory to restore from")
@click.option("--include-db", is_flag=True, default=False, help="Restore database from pg_dump backup")
@click.option("--db-url", default=None, help="PostgreSQL connection URL (overrides config)")
@server_options
def restore(from_path: str, include_db: bool, db_url: str | None, server: str, token: str | None) -> None:
    """Restore OpenLabels data from backup.

    \b
    Examples:
        openlabels system restore --from ./backup/openlabels_backup_20260209
        openlabels system restore --from ./backup/openlabels_backup_20260209 --include-db
    """
    import subprocess

    backup_path = Path(from_path)

    if not backup_path.exists():
        click.echo(f"Backup not found: {from_path}", err=True)
        return

    click.echo(f"Restoring from: {backup_path}")

    # Restore database if requested and dump file exists
    if include_db:
        dump_file = backup_path / "database.sql.gz"
        if not dump_file.exists():
            click.echo("  No database.sql.gz found in backup, skipping DB restore.", err=True)
        else:
            db_connection = db_url
            if not db_connection:
                try:
                    from openlabels.server.config import get_settings
                    settings = get_settings()
                    db_connection = settings.database.url.replace("+asyncpg", "")
                except (ImportError, ValueError) as e:
                    click.echo(f"  Cannot determine database URL: {e}", err=True)

            if db_connection:
                click.echo("  Restoring database from pg_dump...")
                try:
                    import gzip
                    # Stream gzip → psql via pipe to avoid loading
                    # entire dump into memory (mirrors backup streaming)
                    pg_env = _parse_pg_env(db_connection)
                    proc = subprocess.Popen(
                        ["psql"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env={**os.environ, **pg_env},
                    )
                    with gzip.open(dump_file, "rb") as gz:
                        while True:
                            chunk = gz.read(65536)
                            if not chunk:
                                break
                            proc.stdin.write(chunk)
                    proc.stdin.close()
                    proc.wait(timeout=600)
                    if proc.returncode == 0:
                        click.echo("  Database restored successfully")
                    else:
                        stderr_out = proc.stderr.read().decode()[:200] if proc.stderr else ""
                        click.echo(f"  psql errors: {stderr_out}", err=True)
                except FileNotFoundError:
                    click.echo("  ERROR: psql not found on PATH. Database restore SKIPPED.", err=True)
                except subprocess.TimeoutExpired:
                    click.echo("  psql timed out after 10 minutes.", err=True)

    # Restore API data
    client = get_api_client(server, token)

    try:
        for file in sorted(backup_path.glob("*.json")):
            if file.name == "config.json":
                click.echo(f"  Skipped: config.json (apply manually)")
                continue

            endpoint = file.stem.replace("_", "/")
            try:
                with open(file) as f:
                    data = json.load(f)

                if isinstance(data, list):
                    restored = 0
                    for item in data:
                        response = client.post(f"/api/{endpoint}", json=item)
                        if response.status_code in (200, 201):
                            restored += 1
                        else:
                            logger.debug(
                                "Failed to restore item in %s: %s",
                                endpoint, response.status_code,
                            )
                    click.echo(f"  Restored: {endpoint} ({restored}/{len(data)} items)")
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

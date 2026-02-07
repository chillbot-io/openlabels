"""
CLI utility functions shared across command modules.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

import click
import httpx

logger = logging.getLogger(__name__)


def get_httpx_client() -> httpx.Client:
    """Get httpx client for CLI commands."""
    try:
        return httpx.Client(timeout=30.0)
    except ImportError:
        click.echo("Error: httpx not installed. Run: pip install httpx", err=True)
        sys.exit(1)


def get_server_url() -> str:
    """Get server URL from environment or default."""
    return os.environ.get("OPENLABELS_SERVER", "http://localhost:8000")


def validate_where_filter(ctx, param, value):
    """Validate the --where filter option."""
    if value is None:
        return None
    from openlabels.cli.filter_parser import parse_filter, ParseError, LexerError
    try:
        parse_filter(value)
        return value
    except (ParseError, LexerError) as e:
        raise click.BadParameter(f"Invalid filter: {e}")


def handle_http_error(e: Exception, server: str):
    """Handle common HTTP errors with user-friendly messages."""
    if isinstance(e, httpx.TimeoutException):
        click.echo("Error: Request timed out connecting to server", err=True)
    elif isinstance(e, httpx.ConnectError):
        click.echo(f"Error: Cannot connect to server at {server}: {e}", err=True)
    elif isinstance(e, httpx.HTTPStatusError):
        click.echo(f"Error: HTTP error {e.response.status_code}", err=True)
    else:
        click.echo(f"Error: {e}", err=True)


def collect_files(path, recursive=False):
    """Collect files from a path (file or directory).

    Args:
        path: File or directory path to collect from.
        recursive: If True, recurse into subdirectories.

    Returns:
        List of Path objects for the files found.
    """
    target_path = Path(path)
    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*"))
        else:
            files = list(target_path.glob("*"))
        files = [f for f in files if f.is_file()]
    else:
        files = [target_path]
    return files


def scan_files(files, enable_ml=False, exposure_level="PRIVATE"):
    """Scan files with FileProcessor and return results as dicts.

    Processes each file through the classification pipeline and returns
    a list of result dicts.  Per-file errors (permissions, I/O, encoding)
    are logged at DEBUG level and the file is skipped.

    Args:
        files: List of Path objects to scan.
        enable_ml: Enable ML-based detectors.
        exposure_level: Exposure level for classification.

    Returns:
        List of dicts with keys: file_path, file_name, risk_score,
        risk_tier, entity_counts, total_entities.
    """
    from openlabels.core.processor import FileProcessor

    from openlabels.core.detectors.config import DetectionConfig
    processor = FileProcessor(config=DetectionConfig(enable_ml=enable_ml))

    async def _process_all():
        all_results = []
        for file_path in files:
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                result = await processor.process_file(
                    file_path=str(file_path),
                    content=content,
                    exposure_level=exposure_level,
                )
                all_results.append({
                    "file_path": str(file_path),
                    "file_name": result.file_name,
                    "risk_score": result.risk_score,
                    "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                    "entity_counts": result.entity_counts,
                    "total_entities": sum(result.entity_counts.values()),
                })
            except PermissionError:
                logger.debug("Permission denied: %s", file_path)
            except OSError as e:
                logger.debug("OS error processing %s: %s", file_path, e)
            except UnicodeDecodeError as e:
                logger.debug("Encoding error processing %s: %s", file_path, e)
            except ValueError as e:
                logger.debug("Value error processing %s: %s", file_path, e)
        return all_results

    return asyncio.run(_process_all())

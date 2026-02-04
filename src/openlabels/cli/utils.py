"""
CLI utility functions shared across command modules.
"""

import os
import sys

import click
import httpx


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

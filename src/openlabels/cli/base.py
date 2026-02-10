"""Shared CLI decorators and utilities."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import click
import httpx
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)


def common_options(f: Callable[..., Any]) -> Callable[..., Any]:
    """Add ``--quiet`` flag to any command."""
    @click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return f(*args, **kwargs)
    return wrapper


def server_options(f: Callable[..., Any]) -> Callable[..., Any]:
    """Add ``--server`` and ``--token`` options for API-calling commands.

    Replaces the old ``get_server_url()`` / ``get_httpx_client()`` pattern.
    Commands receive ``server`` and ``token`` keyword arguments.
    """
    @click.option(
        "--server", "-s",
        envvar="OPENLABELS_SERVER_URL",
        default="http://localhost:8000",
        help="Server URL",
    )
    @click.option(
        "--token",
        envvar="OPENLABELS_TOKEN",
        default=None,
        help="Authentication token",
    )
    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return f(*args, **kwargs)
    return wrapper


def format_option(
    choices: list[str] | None = None,
    default: str | None = None,
) -> Callable[..., Any]:
    """Add ``--format`` / ``-f`` option with configurable choices.

    The Python parameter is named ``output_format`` to avoid shadowing the
    built-in ``format``.
    """
    if choices is None:
        choices = ["table", "json", "csv"]
    if default is None:
        default = choices[0]

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @click.option(
            "--format", "-f", "output_format",
            type=click.Choice(choices),
            default=default,
            help="Output format",
        )
        @functools.wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return f(*args, **kwargs)
        return wrapper
    return decorator


def file_progress(total: int, description: str = "Processing") -> Progress:
    """Create a :class:`rich.progress.Progress` bar for file processing.

    Usage::

        with file_progress(len(files), "Scanning") as progress:
            task = progress.add_task("scan", total=len(files))
            for f in files:
                process(f)
                progress.advance(task)
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        transient=True,
    )


def spinner(description: str = "Working...") -> Progress:
    """Create a spinner-style progress indicator for indeterminate operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    )


def get_api_client(server: str, token: str | None = None) -> httpx.Client:
    """Create an httpx client configured with base URL and optional auth token.

    Commands should use relative paths (e.g., ``/api/targets``) instead of
    building full URLs.
    """
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=server, timeout=30.0, headers=headers)

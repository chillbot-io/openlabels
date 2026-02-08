"""Structured output formatting for CLI commands."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

import click


class OutputFormatter:
    """Format command output as table, JSON, or CSV.

    Usage::

        fmt = OutputFormatter(output_format, quiet)
        fmt.print_table(data, columns=["name", "status", "count"])
        fmt.print_success("Operation completed")
    """

    def __init__(self, output_format: str = "table", quiet: bool = False) -> None:
        self.format = output_format
        self.quiet = quiet

    def print_table(
        self,
        data: list[dict[str, Any]],
        columns: list[str] | None = None,
    ) -> None:
        """Print *data* as a formatted table, JSON array, or CSV.

        Always prints the header row even when *data* is empty so callers
        can tell the command succeeded.
        """
        if columns is None:
            columns = list(data[0].keys()) if data else []

        if self.format == "json":
            click.echo(json.dumps(data, indent=2, default=str))
            return

        if self.format == "csv":
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)
            click.echo(buf.getvalue().rstrip())
            return

        if not columns:
            return

        # Table format — compute column widths
        headers = {c: c.replace("_", " ").title() for c in columns}
        widths: dict[str, int] = {c: len(headers[c]) for c in columns}
        for row in data:
            for c in columns:
                widths[c] = max(widths[c], len(str(row.get(c, ""))))
        # Cap widths at 50 chars
        widths = {c: min(w, 50) for c, w in widths.items()}

        # Header
        header = "  ".join(headers[c].ljust(widths[c]) for c in columns)
        click.echo(header)
        click.echo("-" * len(header))

        # Rows
        for row in data:
            parts: list[str] = []
            for c in columns:
                val = str(row.get(c, ""))
                if len(val) > widths[c]:
                    val = val[: widths[c] - 3] + "..."
                parts.append(val.ljust(widths[c]))
            click.echo("  ".join(parts))

    def print_single(self, data: dict[str, Any]) -> None:
        """Print a single key-value record."""
        if self.format == "json":
            click.echo(json.dumps(data, indent=2, default=str))
        else:
            for key, value in data.items():
                click.echo(f"  {key}: {value}")

    def print_success(self, message: str) -> None:
        """Print a success message (suppressed in quiet mode)."""
        if not self.quiet:
            click.echo(f"OK: {message}")

    def print_error(self, message: str) -> None:
        """Print an error message to stderr."""
        click.echo(f"Error: {message}", err=True)

    def print_message(self, message: str) -> None:
        """Print an informational message (suppressed in quiet mode)."""
        if not self.quiet:
            click.echo(message)

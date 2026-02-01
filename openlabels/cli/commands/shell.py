"""
OpenLabels shell command.

Interactive shell for exploring and managing data risk.

Usage:
    openlabels shell <path>
    openlabels shell ./data
    openlabels shell s3://bucket

Commands in shell:
    find <filter>     - Find files matching filter
    scan <path>       - Scan a specific file
    info <path>       - Show detailed info for a file
    stats             - Show statistics for current scope
    top [n]           - Show top N riskiest files
    help              - Show available commands
    exit              - Exit the shell
"""

import readline  # noqa: F401 - imported for side effect (enables command history)
from pathlib import Path
from typing import List

from openlabels import Client
from openlabels.cli import MAX_PREVIEW_RESULTS
from openlabels.cli.commands.find import find_matching
from openlabels.cli.commands.scan import ScanResult
from openlabels.cli.output import echo, error, warn, success, info, dim, console, divider
from openlabels.logging_config import get_logger

logger = get_logger(__name__)


class OpenLabelsShell:
    """Interactive shell for OpenLabels."""

    def __init__(self, base_path: str, exposure: str = "PRIVATE"):
        self.base_path = base_path
        self.exposure = exposure
        self.client = Client(default_exposure=exposure)
        self.results_cache: List[ScanResult] = []
        self.running = True

    def run(self):
        """Run the interactive shell."""
        console.print("[bold blue]OpenLabels Shell[/bold blue]")
        echo(f"Base path: {self.base_path}")
        dim("Type 'help' for available commands, 'exit' to quit")
        echo("")

        logger.info(f"Shell started", extra={"base_path": self.base_path})

        while self.running:
            try:
                line = console.input("[green]openlabels>[/green] ").strip()
                if not line:
                    continue

                self.execute(line)

            except KeyboardInterrupt:
                echo("")
                continue
            except EOFError:
                echo("")
                break

        logger.info("Shell exited")

    def execute(self, line: str):
        """Execute a shell command."""
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        commands = {
            "find": self.cmd_find,
            "scan": self.cmd_scan,
            "info": self.cmd_info,
            "stats": self.cmd_stats,
            "top": self.cmd_top,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
            "ls": self.cmd_ls,
            "cd": self.cmd_cd,
        }

        handler = commands.get(cmd)
        if handler:
            handler(args)
        else:
            error(f"Unknown command: {cmd}")
            dim("Type 'help' for available commands")

    def cmd_find(self, args: str):
        """Find files matching filter."""
        if not args:
            echo("Usage: find <filter>")
            dim("Example: find score > 50 AND has(SSN)")
            return

        try:
            source = Path(self.base_path) if not self.base_path.startswith(('s3://', 'gs://', 'azure://')) else self.base_path

            if isinstance(source, str):
                warn("Cloud storage not yet supported in shell")
                return

            results = list(find_matching(
                source,
                self.client,
                filter_expr=args,
                recursive=True,
                exposure=self.exposure,
            ))

            self.results_cache = results

            if not results:
                echo("No files match the filter")
                return

            echo(f"\nFound [bold]{len(results)}[/bold] files:\n")
            for r in results[:MAX_PREVIEW_RESULTS]:
                entities = ", ".join(f"{k}({v})" for k, v in r.entities.items()) if r.entities else "none"
                console.print(f"  {r.score:3d} {r.tier:8s} {r.path}")
                if r.entities:
                    dim(f"      entities: {entities}")

            if len(results) > MAX_PREVIEW_RESULTS:
                dim(f"\n  ... and {len(results) - MAX_PREVIEW_RESULTS} more")

        except Exception as e:
            error(str(e))
            logger.warning(f"Shell find error: {e}")

    def cmd_scan(self, args: str):
        """Scan a specific file."""
        if not args:
            echo("Usage: scan <path>")
            return

        try:
            path = Path(args)
            if not path.is_absolute():
                base = Path(self.base_path) if not self.base_path.startswith(('s3://',)) else Path('.')
                path = base / args

            if not path.exists():
                error(f"File not found: {path}")
                return

            result = self.client.score_file(str(path), exposure=self.exposure)

            echo(f"\n[bold]File:[/bold] {path}")
            echo(f"[bold]Score:[/bold] {result.score} ({result.tier})")
            echo(f"[bold]Content score:[/bold] {result.content_score}")
            echo(f"[bold]Exposure:[/bold] {result.exposure} (×{result.exposure_multiplier})")

            if result.entities:
                echo(f"\n[bold]Entities:[/bold]")
                for k, v in result.entities.items():
                    echo(f"  {k}: {v}")

            if result.co_occurrence_rules:
                echo(f"\n[bold]Co-occurrence rules:[/bold] {', '.join(result.co_occurrence_rules)}")

        except Exception as e:
            error(str(e))
            logger.warning(f"Shell scan error: {e}")

    def cmd_info(self, args: str):
        """Show detailed info for a file."""
        # Same as scan for now
        self.cmd_scan(args)

    def cmd_stats(self, args: str):
        """Show statistics for the base path."""
        try:
            source = Path(self.base_path)
            if not source.exists():
                error(f"Path not found: {source}")
                return

            # Quick scan
            info(f"Scanning {source}...")

            results = list(find_matching(
                source,
                self.client,
                filter_expr=None,
                recursive=True,
                exposure=self.exposure,
            ))

            self.results_cache = results

            if not results:
                echo("No files found")
                return

            # Calculate statistics
            total = len(results)
            scores = [r.score for r in results]
            avg_score = sum(scores) / total
            max_score = max(scores)
            min_score = min(scores)

            tiers = {}
            for r in results:
                tiers[r.tier] = tiers.get(r.tier, 0) + 1

            entity_counts = {}
            for r in results:
                for k, v in r.entities.items():
                    entity_counts[k] = entity_counts.get(k, 0) + v

            echo("")
            divider()
            echo(f"[bold]Statistics for:[/bold] {source}")
            divider()
            echo(f"Total files:  {total}")
            echo(f"Avg score:    {avg_score:.1f}")
            echo(f"Max score:    {max_score}")
            echo(f"Min score:    {min_score}")
            echo("")
            echo("[bold]By tier:[/bold]")
            for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
                count = tiers.get(tier, 0)
                pct = count / total * 100
                bar = "█" * int(pct / 5)
                echo(f"  {tier:8s}: {count:4d} ({pct:5.1f}%) {bar}")

            if entity_counts:
                echo("")
                echo("[bold]Top entities:[/bold]")
                sorted_entities = sorted(entity_counts.items(), key=lambda x: -x[1])[:10]
                for k, v in sorted_entities:
                    echo(f"  {k}: {v}")

        except Exception as e:
            error(str(e))
            logger.warning(f"Shell stats error: {e}")

    def cmd_top(self, args: str):
        """Show top N riskiest files."""
        try:
            n = int(args) if args else 10
        except ValueError:
            n = 10

        if not self.results_cache:
            # Do a quick scan
            source = Path(self.base_path)
            if source.exists():
                self.results_cache = list(find_matching(
                    source,
                    self.client,
                    filter_expr=None,
                    recursive=True,
                    exposure=self.exposure,
                ))

        if not self.results_cache:
            warn("No files scanned. Run 'stats' or 'find' first.")
            return

        sorted_results = sorted(self.results_cache, key=lambda x: -x.score)[:n]

        echo(f"\n[bold]Top {n} riskiest files:[/bold]\n")
        for i, r in enumerate(sorted_results, 1):
            echo(f"  {i:2d}. [{r.score:3d}] {r.tier:8s} {r.path}")

    def cmd_ls(self, args: str):
        """List files in current scope."""
        try:
            path = Path(args) if args else Path(self.base_path)
            if not path.is_absolute() and args:
                path = Path(self.base_path) / args

            if not path.exists():
                error(f"Path not found: {path}")
                return

            if path.is_file():
                echo(str(path))
                return

            for item in sorted(path.iterdir()):
                prefix = "d" if item.is_dir() else "-"
                echo(f"  {prefix} {item.name}")

        except Exception as e:
            error(str(e))

    def cmd_cd(self, args: str):
        """Change base path."""
        if not args:
            echo(f"Current path: {self.base_path}")
            return

        new_path = Path(args)
        if not new_path.is_absolute():
            new_path = Path(self.base_path) / args

        if new_path.exists():
            self.base_path = str(new_path.resolve())
            self.results_cache = []
            success(f"Changed to: {self.base_path}")
        else:
            error(f"Path not found: {new_path}")

    def cmd_help(self, args: str):
        """Show help."""
        console.print("""
[bold blue]OpenLabels Shell Commands:[/bold blue]

  [bold]find <filter>[/bold]    Find files matching filter expression
                   Example: find score > 50 AND has(SSN)

  [bold]scan <path>[/bold]      Scan and show details for a specific file
  [bold]info <path>[/bold]      Same as scan

  [bold]stats[/bold]            Show statistics for the current scope
  [bold]top [n][/bold]          Show top N riskiest files (default: 10)

  [bold]ls [path][/bold]        List files in path
  [bold]cd <path>[/bold]        Change base path

  [bold]help[/bold]             Show this help message
  [bold]exit / quit[/bold]      Exit the shell

[bold]Filter syntax:[/bold]
  score > 50                     Score greater than 50
  exposure = public              Public exposure
  has(SSN)                       Contains SSN entities
  last_accessed > 1y             Not accessed in 1 year
  score > 75 AND has(CREDIT_CARD)  Combine conditions
""")

    def cmd_exit(self, args: str):
        """Exit the shell."""
        self.running = False
        success("Goodbye!")


def cmd_shell(args) -> int:
    """Execute the shell command."""
    source = args.source

    # Validate path
    if not source.startswith(('s3://', 'gs://', 'azure://')):
        path = Path(source)
        if not path.exists():
            error(f"Path not found: {source}")
            return 1

    shell = OpenLabelsShell(source, exposure=args.exposure)
    shell.run()

    return 0


def add_shell_parser(subparsers, hidden=False):
    """Add the shell subparser."""
    import argparse
    parser = subparsers.add_parser(
        "shell",
        help=argparse.SUPPRESS if hidden else "Interactive shell for exploring data risk",
    )
    parser.add_argument(
        "source",
        help="Base path to explore",
    )
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help="Default exposure level for scoring",
    )
    parser.set_defaults(func=cmd_shell)

    return parser

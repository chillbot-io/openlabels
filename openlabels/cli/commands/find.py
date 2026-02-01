"""
OpenLabels find command.

Find local files matching filter criteria.

Usage:
    openlabels find <path> --where "<filter>"
    openlabels find . --where "score > 75 AND has(SSN)"
    openlabels find ./data --where "exposure = private"
"""

import json
import stat as stat_module
from pathlib import Path
from typing import Iterator, Optional, Dict, Any, List

from openlabels import Client
from openlabels.cli.filter import Filter, parse_filter
from openlabels.cli.commands.scan import scan_file, scan_directory, ScanResult
from openlabels.cli.output import echo, error, dim, progress
from openlabels.logging_config import get_logger

logger = get_logger(__name__)


def result_to_filter_dict(result: ScanResult) -> Dict[str, Any]:
    """Convert ScanResult to dict suitable for filter evaluation."""
    return {
        "path": result.path,
        "score": result.score,
        "tier": result.tier.lower() if result.tier else "",
        "exposure": result.exposure.lower() if result.exposure else "",
        "entities": [
            {"type": etype, "count": count}
            for etype, count in result.entities.items()
        ],
        "entity_count": sum(result.entities.values()) if result.entities else 0,
    }


def find_matching(
    path: Path,
    client: Client,
    filter_expr: Optional[str] = None,
    recursive: bool = True,
    exposure: str = "PRIVATE",
    extensions: Optional[List[str]] = None,
) -> Iterator[ScanResult]:
    """Find files matching the filter criteria."""
    # Parse filter if provided
    filter_obj = parse_filter(filter_expr) if filter_expr else None

    def is_regular_file(p):  # TOCTOU-001: use lstat
        try:
            return stat_module.S_ISREG(p.lstat().st_mode)
        except OSError:
            return False

    # Scan files
    if is_regular_file(path):
        result = scan_file(path, client, exposure)
        if not filter_obj or filter_obj.evaluate(result_to_filter_dict(result)):
            yield result
    else:
        for result in scan_directory(
            path, client,
            recursive=recursive,
            exposure=exposure,
            extensions=extensions,
        ):
            if not filter_obj or filter_obj.evaluate(result_to_filter_dict(result)):
                yield result


def format_find_result(result: ScanResult, format: str = "text") -> str:
    """Format a find result for output."""
    if format == "json":
        return json.dumps(result.to_dict(), indent=2)

    if format == "jsonl":
        return json.dumps(result.to_dict())

    # Text format - concise output
    entities_str = ", ".join(
        f"{k}({v})" for k, v in sorted(result.entities.items())
    ) if result.entities else "-"

    return f"{result.path}\tScore: {result.score}\t{entities_str}"


def cmd_find(args) -> int:
    """Execute the find command."""
    client = Client(default_exposure=args.exposure)
    path = Path(args.path)

    if not path.exists():
        error(f"Path not found: {path}")
        return 1

    logger.info(f"Starting find", extra={
        "path": str(path),
        "filter": args.where,
        "recursive": args.recursive,
    })

    extensions = args.extensions.split(",") if args.extensions else None
    match_count = 0

    try:
        for result in find_matching(
            path,
            client,
            filter_expr=args.where,
            recursive=args.recursive,
            exposure=args.exposure,
            extensions=extensions,
        ):
            match_count += 1
            echo(format_find_result(result, args.format))

            # Limit output
            if args.limit and match_count >= args.limit:
                if args.format == "text":
                    dim(f"\n... (limited to {args.limit} results)")
                break

    except ValueError as e:
        error(f"Filter error: {e}")
        logger.warning(f"Filter error: {e}")
        return 1

    # Print summary
    if args.format == "text" and not args.quiet:
        echo("")
        echo(f"Found {match_count} matching files")

    logger.info(f"Find complete", extra={"matches": match_count})

    # Exit code
    if args.count:
        # Just print count and exit
        echo(str(match_count))

    return 0


def add_find_parser(subparsers):
    """Add the find subparser."""
    parser = subparsers.add_parser(
        "find",
        help="Find files matching filter criteria",
    )
    parser.add_argument(
        "path",
        help="Local path to search (file or directory)",
    )
    parser.add_argument(
        "--where", "-w",
        help="Filter expression (e.g., 'score > 75 AND has(SSN)')",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        default=True,
        help="Search recursively (default: true)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_false",
        dest="recursive",
        help="Do not search recursively",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "jsonl"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help="Exposure level for scoring",
    )
    parser.add_argument(
        "--extensions",
        help="Comma-separated list of file extensions",
    )
    parser.add_argument(
        "--limit", "-n",
        type=int,
        help="Maximum number of results",
    )
    parser.add_argument(
        "--count", "-c",
        action="store_true",
        help="Only print count of matches",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress summary output",
    )
    parser.set_defaults(func=cmd_find)

    return parser

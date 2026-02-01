"""
OpenLabels export command.

Export labeled file results to CSV or JSON.

Usage:
    openlabels export ./data --format csv -o results.csv
    openlabels export ./data --format json -o results.json
"""

import csv
import json
import io
import stat as stat_module
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from openlabels import Client
from openlabels.cli.commands.scan import scan_directory, scan_file
from openlabels.cli.output import echo, error, info, progress, summary_panel
from openlabels.logging_config import get_logger

logger = get_logger(__name__)


def export_to_csv(results: List[Dict[str, Any]]) -> str:
    """Export results to CSV format."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "path",
        "score",
        "tier",
        "exposure",
        "label_id",
        "content_hash",
        "entities",
        "entity_count",
        "labels",
        "scanned_at",
    ])

    for r in results:
        entities = r.get("entities", {})
        entities_str = "|".join(f"{k}:{v}" for k, v in entities.items())
        entity_count = sum(entities.values()) if entities else 0
        labels_str = ",".join(r.get("labels", []))

        writer.writerow([
            r.get("path", ""),
            r.get("score", 0),
            r.get("tier", ""),
            r.get("exposure", ""),
            r.get("label_id", ""),
            r.get("content_hash", ""),
            entities_str,
            entity_count,
            labels_str,
            r.get("scanned_at", ""),
        ])

    return output.getvalue()


def export_to_json(results: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    """Export results to JSON format."""
    export_data = {
        "exported_at": datetime.now().isoformat(),
        "total_files": len(results),
        "summary": summary,
        "files": results,
    }
    return json.dumps(export_data, indent=2)


def compute_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute summary statistics."""
    if not results:
        return {}

    from collections import Counter

    tier_counts = Counter(r.get("tier", "UNKNOWN") for r in results)
    entity_counts: Counter = Counter()
    for r in results:
        for etype, count in r.get("entities", {}).items():
            entity_counts[etype] += count

    scores = [r.get("score", 0) for r in results]

    return {
        "total_files": len(results),
        "files_at_risk": sum(1 for s in scores if s > 0),
        "max_score": max(scores) if scores else 0,
        "avg_score": sum(scores) / len(scores) if scores else 0,
        "by_tier": dict(tier_counts),
        "by_entity": dict(entity_counts.most_common(20)),
    }


def cmd_export(args) -> int:
    """Execute the export command."""
    path = Path(args.path)

    if not path.exists():
        error(f"Path not found: {path}")
        return 1

    if not args.output:
        error("Output file is required. Use -o or --output.")
        return 1

    client = Client(default_exposure=args.exposure)
    extensions = args.extensions.split(",") if args.extensions else None

    info(f"Scanning {path} for export...")

    results = []

    def is_regular_file(p):
        try:
            return stat_module.S_ISREG(p.lstat().st_mode)
        except OSError:
            return False

    if is_regular_file(path):
        result = scan_file(path, client, args.exposure)
        results.append(result.to_dict())
    else:
        # Count files for progress
        if args.recursive:
            all_files = list(path.rglob("*"))
        else:
            all_files = list(path.glob("*"))
        all_files = [f for f in all_files if is_regular_file(f)]
        if extensions:
            exts = {e.lower().lstrip(".") for e in extensions}
            all_files = [f for f in all_files if f.suffix.lower().lstrip(".") in exts]

        with progress("Scanning files", total=len(all_files)) as p:
            for result in scan_directory(
                path, client,
                recursive=args.recursive,
                exposure=args.exposure,
                extensions=extensions,
            ):
                result_dict = result.to_dict()
                result_dict["scanned_at"] = datetime.now().isoformat()
                results.append(result_dict)
                p.advance()

    if not results:
        echo("No files found to export.")
        return 0

    # Compute summary
    summary = compute_summary(results)

    # Generate output
    if args.format == "csv":
        content = export_to_csv(results)
    else:  # json
        content = export_to_json(results, summary)

    # Write to file
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)

        echo("")
        summary_panel(
            "Export Complete",
            {
                "Files": len(results),
                "At Risk": summary.get("files_at_risk", 0),
                "Max Score": summary.get("max_score", 0),
                "Format": args.format.upper(),
            }
        )
        echo(f"\nExported to: {args.output}")

    except IOError as e:
        error(f"Failed to write output file: {e}")
        return 1

    return 0


def add_export_parser(subparsers, hidden=False):
    """Add the export subparser."""
    import argparse
    parser = subparsers.add_parser(
        "export",
        help=argparse.SUPPRESS if hidden else "Export labeled file results to CSV or JSON",
    )
    parser.add_argument(
        "path",
        help="Path to scan and export",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv)",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output file path",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        default=True,
        help="Scan recursively (default: true)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_false",
        dest="recursive",
        help="Do not scan recursively",
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
    parser.set_defaults(func=cmd_export)

    return parser

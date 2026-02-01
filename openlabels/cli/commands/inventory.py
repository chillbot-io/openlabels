"""
OpenLabels inventory command.

Query and filter scan results with Rich output.

Usage:
    openlabels inventory
    openlabels inventory --tier HIGH --entity SSN
    openlabels inventory --min-score 70 --format csv
"""

import json
import csv
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
from collections import Counter

from openlabels.cli.output import (
    echo, error, console, risk_table, summary_panel, tier_distribution
)
from openlabels.logging_config import get_logger

logger = get_logger(__name__)


def load_inventory(index_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Load inventory from the index.

    For now, this loads from a JSON file. In production, this would
    query the actual index backend (SQLite, PostgreSQL, etc.)
    """
    # Default index location
    if index_path is None:
        index_path = Path.home() / ".openlabels" / "inventory.json"

    if not index_path.exists():
        return []

    try:
        with open(index_path) as f:
            data = json.load(f)
            return data.get("files", []) if isinstance(data, dict) else data
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load inventory: {e}")
        return []


def filter_inventory(
    items: List[Dict[str, Any]],
    tier: Optional[str] = None,
    entity: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    path_contains: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter inventory items based on criteria."""
    results = []

    for item in items:
        # Tier filter
        if tier and item.get("tier", "").upper() != tier.upper():
            continue

        # Entity filter
        if entity:
            entities = item.get("entities", {})
            if entity.upper() not in [e.upper() for e in entities.keys()]:
                continue

        # Score filters
        score = item.get("score", 0)
        if min_score is not None and score < min_score:
            continue
        if max_score is not None and score > max_score:
            continue

        # Path filter
        if path_contains:
            path = item.get("path", "")
            if path_contains.lower() not in path.lower():
                continue

        results.append(item)

    return results


def format_inventory_csv(items: List[Dict[str, Any]]) -> str:
    """Format inventory as CSV."""
    import io
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["path", "score", "tier", "entities", "exposure"])

    for item in items:
        entities = item.get("entities", {})
        entities_str = "|".join(f"{k}:{v}" for k, v in entities.items())
        writer.writerow([
            item.get("path", ""),
            item.get("score", 0),
            item.get("tier", ""),
            entities_str,
            item.get("exposure", ""),
        ])

    return output.getvalue()


def format_inventory_json(items: List[Dict[str, Any]]) -> str:
    """Format inventory as JSON."""
    return json.dumps({"count": len(items), "files": items}, indent=2)


def cmd_inventory(args) -> int:
    """Execute the inventory command."""
    # Load inventory
    items = load_inventory()

    if not items:
        echo("No inventory data found.")
        echo("Run 'openlabels scan <path>' to scan files first.")
        return 0

    # Apply filters
    filtered = filter_inventory(
        items,
        tier=args.tier,
        entity=args.entity,
        min_score=args.min_score,
        max_score=args.max_score,
        path_contains=args.path_contains,
    )

    # Output based on format
    if args.format == "csv":
        output = format_inventory_csv(filtered)
        if args.export:
            with open(args.export, "w") as f:
                f.write(output)
            echo(f"Exported to {args.export}")
        else:
            echo(output)

    elif args.format == "json":
        output = format_inventory_json(filtered)
        if args.export:
            with open(args.export, "w") as f:
                f.write(output)
            echo(f"Exported to {args.export}")
        else:
            echo(output)

    else:  # table format
        # Show summary
        if filtered:
            tier_counts = Counter(item.get("tier", "UNKNOWN") for item in filtered)
            scores = [item.get("score", 0) for item in filtered]

            summary_panel(
                "Inventory Summary",
                {
                    "Total": len(filtered),
                    "Max Score": max(scores) if scores else 0,
                    "Avg Score": sum(scores) / len(scores) if scores else 0,
                }
            )

            echo("")
            tier_distribution(tier_counts)
            echo("")

        # Show table
        title = f"Inventory: {len(filtered)} files"
        if args.tier or args.entity or args.min_score or args.max_score:
            filters = []
            if args.tier:
                filters.append(f"tier={args.tier}")
            if args.entity:
                filters.append(f"entity={args.entity}")
            if args.min_score:
                filters.append(f"min_score={args.min_score}")
            if args.max_score:
                filters.append(f"max_score={args.max_score}")
            title += f" (filter: {', '.join(filters)})"

        risk_table(filtered, title=title, max_rows=args.limit)

    return 0


def add_inventory_parser(subparsers, hidden=False):
    """Add the inventory subparser."""
    import argparse
    parser = subparsers.add_parser(
        "inventory",
        help=argparse.SUPPRESS if hidden else "Query and filter scan results",
    )
    parser.add_argument(
        "--tier", "-t",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"],
        help="Filter by risk tier",
    )
    parser.add_argument(
        "--entity", "-e",
        help="Filter by entity type (e.g., SSN, CREDIT_CARD)",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        help="Minimum risk score",
    )
    parser.add_argument(
        "--max-score",
        type=int,
        help="Maximum risk score",
    )
    parser.add_argument(
        "--path-contains",
        help="Filter paths containing string",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--export", "-o",
        help="Export to file",
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=50,
        help="Maximum rows to display (default: 50)",
    )
    parser.set_defaults(func=cmd_inventory)

    return parser

"""
OpenLabels read command.

Read embedded labels from files - proves labels travel with files.

Usage:
    openlabels read <file>
    openlabels read document.pdf --format json
    openlabels read customers.xlsx --verify
"""

import json
from datetime import datetime
from pathlib import Path

from openlabels.output.embed import read_embedded_label, supports_embedded_labels
from openlabels.core.labels import compute_content_hash_file
from openlabels.cli.output import echo, error, success, console
from openlabels.logging_config import get_logger

logger = get_logger(__name__)


# Risk tier colors for display
TIER_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "yellow",
    "MEDIUM": "orange3",
    "LOW": "green",
    "MINIMAL": "dim",
}


def cmd_read(args) -> int:
    """Execute the read command - read embedded label from a file."""
    path = Path(args.path)

    if not path.exists():
        error(f"File not found: {path}")
        return 1

    if not path.is_file():
        error(f"Not a file: {path}")
        return 1

    # Check if file type supports embedded labels
    if not supports_embedded_labels(path):
        if args.format == "json":
            echo(json.dumps({"error": "unsupported_format", "path": str(path)}))
        else:
            error(f"File type '{path.suffix}' does not support embedded labels")
            echo("")
            echo("Supported formats: PDF, DOCX, XLSX, PPTX, JPEG, PNG, TIFF")
        return 1

    # Read the embedded label
    label_set = read_embedded_label(path)

    if label_set is None:
        if args.format == "json":
            echo(json.dumps({"error": "no_label", "path": str(path)}))
        else:
            echo(f"No embedded label found in: {path.name}")
            echo("")
            echo("This file hasn't been labeled yet. Run:")
            echo(f"  openlabels scan {path}")
        return 1

    # Verify content hash if requested
    hash_match = None
    if args.verify:
        try:
            current_hash = compute_content_hash_file(str(path))
            hash_match = current_hash == label_set.content_hash
        except Exception as e:
            logger.warning(f"Could not verify hash: {e}")
            hash_match = None

    # Output based on format
    if args.format == "json":
        output = label_set.to_dict()
        if args.verify and hash_match is not None:
            output["verified"] = hash_match
            output["current_hash"] = current_hash if hash_match is False else label_set.content_hash
        echo(json.dumps(output, indent=2))
    else:
        _print_label_text(path, label_set, hash_match, args.verify)

    return 0


def _print_label_text(path: Path, label_set, hash_match, verify: bool):
    """Print label in human-readable text format."""
    console.print("")
    console.print(f"[bold blue]OpenLabels[/bold blue] - {path.name}")
    console.print("=" * 50)
    console.print("")

    # Label ID and hash
    console.print(f"  Label ID:     [cyan]{label_set.label_id}[/cyan]")
    console.print(f"  Content Hash: [dim]{label_set.content_hash}[/dim]")

    # Verification status
    if verify:
        if hash_match is True:
            console.print(f"  Verified:     [green]Yes - content unchanged[/green]")
        elif hash_match is False:
            console.print(f"  Verified:     [yellow]No - content modified since labeling[/yellow]")
        else:
            console.print(f"  Verified:     [dim]Could not verify[/dim]")

    console.print("")

    # Labels (entities)
    if label_set.labels:
        console.print("  [bold]Detected Entities:[/bold]")
        for label in label_set.labels:
            count_str = f" x{label.count}" if label.count > 1 else ""
            conf_str = f"{label.confidence:.0%}"
            console.print(f"    - {label.type}{count_str} ({conf_str}, {label.detector})")
    else:
        console.print("  [dim]No sensitive entities detected[/dim]")

    console.print("")

    # Metadata
    ts = datetime.fromtimestamp(label_set.timestamp)
    console.print(f"  Source:    {label_set.source}")
    console.print(f"  Labeled:   {ts.strftime('%Y-%m-%d %H:%M:%S')}")
    console.print("")

    # Summary
    total_entities = sum(l.count for l in label_set.labels)
    entity_types = len(label_set.labels)

    if total_entities > 0:
        console.print(f"  [bold]Summary:[/bold] {total_entities} sensitive values across {entity_types} entity types")
    else:
        console.print("  [bold]Summary:[/bold] No sensitive data detected")

    console.print("")


def add_read_parser(subparsers):
    """Add the read subparser."""
    parser = subparsers.add_parser(
        "read",
        help="Read embedded label from a file",
        description="Read and display the OpenLabels label embedded in a file's metadata. "
                    "This proves that labels travel with files across systems.",
    )
    parser.add_argument(
        "path",
        help="File to read label from",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Verify content hash matches (detect if file was modified)",
    )
    parser.set_defaults(func=cmd_read)

    return parser

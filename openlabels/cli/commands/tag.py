"""
OpenLabels tag command.

Apply or update OpenLabels tags on local files matching filter criteria.

Usage:
    openlabels tag <source> --where "<filter>"
    openlabels tag ./data --where "score > 50"
    openlabels tag ./data --where "has(SSN)" --force-rescan
"""

from pathlib import Path

from openlabels import Client
from openlabels.cli import MAX_PREVIEW_RESULTS
from openlabels.cli.commands.find import find_matching
from openlabels.cli.output import echo, error, warn, success, dim, progress, divider
from openlabels.logging_config import get_logger, get_audit_logger
from openlabels.output.virtual import write_virtual_label
from openlabels.output.embed import write_embedded_label
from openlabels.output.index import store_label

logger = get_logger(__name__)
audit = get_audit_logger()


def cmd_tag(args) -> int:
    """Execute the tag command."""
    source = Path(args.source)

    if not source.exists():
        error(f"Source not found: {source}")
        return 1

    logger.info(f"Starting tag operation", extra={
        "source": str(source),
        "filter": args.where,
        "embed": args.embed,
    })

    client = Client(default_exposure=args.exposure)
    extensions = args.extensions.split(",") if args.extensions else None

    # Find matching files (or all files if no filter)
    matches = list(find_matching(
        source,
        client,
        filter_expr=args.where,
        recursive=args.recursive,
        exposure=args.exposure,
        extensions=extensions,
    ))

    if not matches:
        echo("No files match the filter criteria")
        logger.info("No files matched filter criteria")
        return 0

    logger.info(f"Found {len(matches)} files matching filter")

    # Dry run - just show what would be tagged
    if args.dry_run:
        echo(f"Would tag [bold]{len(matches)}[/bold] files:\n")
        for result in matches[:MAX_PREVIEW_RESULTS]:
            dim(f"  {result.path} (score: {result.score})")
        if len(matches) > MAX_PREVIEW_RESULTS:
            dim(f"  ... and {len(matches) - MAX_PREVIEW_RESULTS} more")
        return 0

    # Tag files
    tagged_count = 0
    embedded_count = 0
    virtual_count = 0
    errors = []

    with progress("Tagging files", total=len(matches)) as p:
        for i, result in enumerate(matches):
            try:
                file_path = Path(result.path)

                # Get the label set from the scan result
                label_set = result.label_set if hasattr(result, 'label_set') else None

                if label_set is None:
                    # Re-scan to get label set
                    scan_result = client.score_file(str(file_path), exposure=args.exposure)
                    label_set = scan_result.label_set if hasattr(scan_result, 'label_set') else None

                if label_set is None:
                    if not args.quiet:
                        dim(f"Skipped (no labels): {result.path}")
                    p.advance()
                    continue

                # Try embedded label first (for supported formats)
                embedded = False
                if args.embed:
                    try:
                        write_embedded_label(str(file_path), label_set)
                        embedded = True
                        embedded_count += 1
                    except (OSError, ValueError) as e:
                        logger.debug(f"Could not embed label in {file_path}, falling back to virtual: {e}")

                # Write virtual label if not embedded
                if not embedded:
                    write_virtual_label(str(file_path), label_set.label_id, label_set.content_hash)
                    virtual_count += 1

                # Store in index
                store_label(label_set, str(file_path), result.score, result.tier)

                # Audit log for each tagged file
                audit.file_tag(
                    path=result.path,
                    label_id=label_set.label_id,
                    embedded=embedded,
                    score=result.score,
                )

                tagged_count += 1
                logger.debug(f"Tagged {result.path} ({'embedded' if embedded else 'virtual'})")

                if not args.quiet:
                    p.set_description(f"[{i+1}/{len(matches)}] {file_path.name}")

            except (OSError, ValueError) as e:
                errors.append({"path": result.path, "error": str(e)})
                logger.warning(f"Failed to tag {result.path}: {e}")
                if not args.quiet:
                    warn(f"Error: {result.path} - {e}")

            p.advance()

    # Summary
    echo("")
    divider()
    if errors:
        warn(f"Tagged: {tagged_count} files ({len(errors)} errors)")
    else:
        success(f"Tagged: {tagged_count} files")
    dim(f"  Embedded: {embedded_count}")
    dim(f"  Virtual: {virtual_count}")

    logger.info(f"Tag complete", extra={
        "files_tagged": tagged_count,
        "embedded": embedded_count,
        "virtual": virtual_count,
        "errors": len(errors),
    })

    return 0 if not errors else 1


def add_tag_parser(subparsers, hidden=False):
    """Add the tag subparser."""
    import argparse
    parser = subparsers.add_parser(
        "tag",
        help=argparse.SUPPRESS if hidden else "Apply OpenLabels tags to files",
    )
    parser.add_argument(
        "source",
        help="Local source path to search",
    )
    parser.add_argument(
        "--where", "-w",
        help="Filter expression (optional, tags all files if not specified)",
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
        "--embed",
        action="store_true",
        default=True,
        help="Try to embed labels in file metadata (default: true)",
    )
    parser.add_argument(
        "--no-embed",
        action="store_false",
        dest="embed",
        help="Only use virtual labels (xattr)",
    )
    parser.add_argument(
        "--force-rescan",
        action="store_true",
        help="Re-scan files even if already tagged",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Preview what would be tagged without tagging",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_tag)

    return parser

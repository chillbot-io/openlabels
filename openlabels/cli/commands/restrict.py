"""
OpenLabels restrict command.

Restrict access permissions on files matching filter criteria.

Usage:
    openlabels restrict <source> --where "<filter>" --acl private
    openlabels restrict ./data --where "score > 75 AND exposure = public" --acl private
    openlabels restrict s3://bucket --where "has(SSN)" --acl private
"""

import os
import stat
from pathlib import Path

from openlabels import Client
from openlabels.cli import MAX_PREVIEW_RESULTS
from openlabels.cli.commands.find import find_matching
from openlabels.cli.output import echo, error, warn, success, dim, info, progress, confirm, divider
from openlabels.logging_config import get_logger, get_audit_logger

logger = get_logger(__name__)
audit = get_audit_logger()


def restrict_posix(file_path: Path, mode: str) -> bool:
    """Restrict POSIX file permissions."""
    try:
        if mode == "private":
            # Owner only: rw-------
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        elif mode == "internal":
            # Owner + group: rw-r-----
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        elif mode == "readonly":
            # Read-only for owner: r--------
            os.chmod(file_path, stat.S_IRUSR)
        return True
    except OSError as e:
        logger.warning(f"Could not apply ACL '{mode}' to {file_path}: {e}")
        return False


def cmd_restrict(args) -> int:
    """Execute the restrict command."""
    if not args.where:
        error("--where filter is required for restrict")
        return 1

    if not args.acl:
        error("--acl is required")
        return 1

    source = Path(args.source) if not args.source.startswith(('s3://', 'gs://', 'azure://')) else args.source

    # Check for cloud paths
    if isinstance(source, str):
        if source.startswith('s3://'):
            bucket = source.replace('s3://', '').split('/')[0]
            info("For S3 access restriction, use AWS CLI:")
            if args.acl == "private":
                echo(f"  aws s3api put-object-acl --bucket {bucket} --acl private --key <key>")
                echo(f"  # Or block public access at bucket level:")
                echo(f"  aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
        elif source.startswith('gs://'):
            info("For GCS access restriction, use gsutil:")
            echo(f"  gsutil acl set private {source}")
        elif source.startswith('azure://'):
            info("For Azure Blob, configure private access in portal or use az cli:")
            echo("  az storage container set-permission --name <container> --public-access off")
        return 1

    if not source.exists():
        error(f"Source not found: {source}")
        return 1

    logger.info(f"Starting restrict operation", extra={
        "source": str(source),
        "acl": args.acl,
        "filter": args.where,
    })

    client = Client(default_exposure=args.exposure)
    extensions = args.extensions.split(",") if args.extensions else None

    # Find matching files
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

    # Dry run - just show what would be restricted
    if args.dry_run:
        echo(f"Would restrict [bold]{len(matches)}[/bold] files to '{args.acl}':\n")
        for result in matches[:MAX_PREVIEW_RESULTS]:
            dim(f"  {result.path} (score: {result.score})")
        if len(matches) > MAX_PREVIEW_RESULTS:
            dim(f"  ... and {len(matches) - MAX_PREVIEW_RESULTS} more")
        return 0

    # Confirm if not forced
    if not args.force:
        echo(f"About to restrict [bold]{len(matches)}[/bold] files to '{args.acl}'")
        echo(f"Filter: {args.where}")
        echo("")

        if not confirm("Proceed?"):
            echo("Aborted")
            logger.info("Restrict aborted by user")
            return 1

    # Restrict files
    restricted_count = 0
    errors = []

    with progress("Restricting permissions", total=len(matches)) as p:
        for i, result in enumerate(matches):
            try:
                file_path = Path(result.path)

                if restrict_posix(file_path, args.acl):
                    restricted_count += 1

                    # Audit log for each restricted file
                    audit.access_restrict(
                        path=result.path,
                        mode=args.acl,
                        score=result.score,
                    )

                    logger.debug(f"Restricted {result.path} to {args.acl}")

                    if not args.quiet:
                        p.set_description(f"[{i+1}/{len(matches)}] {file_path.name}")
                else:
                    errors.append({"path": result.path, "error": "Permission change failed"})
                    warn(f"Failed: {result.path}")

            except OSError as e:
                errors.append({"path": result.path, "error": str(e)})
                logger.warning(f"Failed to restrict {result.path}: {e}")
                if not args.quiet:
                    warn(f"Error: {result.path} - {e}")

            p.advance()

    # Summary
    echo("")
    divider()
    if errors:
        warn(f"Restricted: {restricted_count} files ({len(errors)} errors)")
    else:
        success(f"Restricted: {restricted_count} files")

    logger.info(f"Restrict complete", extra={
        "files_restricted": restricted_count,
        "errors": len(errors),
        "acl": args.acl,
    })

    return 0 if not errors else 1


def add_restrict_parser(subparsers, hidden=False):
    """Add the restrict subparser."""
    import argparse
    parser = subparsers.add_parser(
        "restrict",
        help=argparse.SUPPRESS if hidden else "Restrict access permissions on matching files",
    )
    parser.add_argument(
        "source",
        help="Source path to search",
    )
    parser.add_argument(
        "--where", "-w",
        required=True,
        help="Filter expression (required)",
    )
    parser.add_argument(
        "--acl",
        required=True,
        choices=["private", "internal", "readonly"],
        help="Target access level",
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
        "--dry-run", "-n",
        action="store_true",
        help="Preview what would be restricted without changing",
    )
    parser.add_argument(
        "--force", "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_restrict)

    return parser

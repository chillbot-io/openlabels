"""
OpenLabels quarantine command.

Move local files matching filter criteria to a quarantine location.

Usage:
    openlabels quarantine <source> --where "<filter>" --to <dest>
    openlabels quarantine ./data --where "score > 75" --to ./quarantine
"""

import json
import shutil
import os
import stat as stat_module
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from openlabels import Client
from openlabels.cli import MAX_PREVIEW_RESULTS
from openlabels.cli.commands.find import find_matching
from openlabels.cli.output import echo, error, warn, success, dim, progress, confirm, divider
from openlabels.logging_config import get_logger, get_audit_logger

logger = get_logger(__name__)
audit = get_audit_logger()


def move_file(source: Path, dest_dir: Path, preserve_structure: bool = True, base_path: Optional[Path] = None) -> Path:
    """
    Move a file to the destination directory.

    Args:
        source: Source file path
        dest_dir: Destination directory
        preserve_structure: If True, preserve relative path structure
        base_path: Base path for computing relative structure

    Returns:
        New file path

    Raises:
        ValueError: If source is a symlink or not a regular file
        FileNotFoundError: If source doesn't exist
        PermissionError: If source cannot be accessed

    Security: See SECURITY.md for TOCTOU-001.
    """
    try:
        st = source.lstat()  # TOCTOU-001: atomic, no symlink follow
    except FileNotFoundError:
        raise FileNotFoundError(f"Source file not found: {source}")
    except OSError as e:
        raise PermissionError(f"Cannot access source file: {e}")

    if stat_module.S_ISLNK(st.st_mode):  # Reject symlinks
        raise ValueError(f"Refusing to move symlink (security): {source}")

    if not stat_module.S_ISREG(st.st_mode):  # Regular files only
        raise ValueError(f"Not a regular file (security): {source}")

    if preserve_structure and base_path:
        # Compute relative path from base
        try:
            rel_path = source.relative_to(base_path)
        except ValueError:
            rel_path = Path(source.name)
    else:
        rel_path = Path(source.name)

    dest_path = dest_dir / rel_path

    # Create parent directories
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    try:  # Atomic move; cross-fs requires re-verify
        os.rename(str(source), str(dest_path))
    except OSError as rename_error:
        # Cross-filesystem move required - need to copy then delete
        # Re-verify source file type hasn't changed (minimize TOCTOU window)
        try:
            st2 = source.lstat()
            if stat_module.S_ISLNK(st2.st_mode):
                raise ValueError(f"Source became symlink during move (security): {source}")
            if not stat_module.S_ISREG(st2.st_mode):
                raise ValueError(f"Source is no longer a regular file (security): {source}")
            # Verify it's the same file by checking inode
            if st.st_ino != st2.st_ino or st.st_dev != st2.st_dev:
                raise ValueError(f"Source file changed during move (security): {source}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Source file disappeared during move: {source}")

        # Perform copy + delete
        shutil.copy2(str(source), str(dest_path))
        os.unlink(str(source))

    return dest_path


def write_manifest(
    dest_dir: Path,
    moved_files: List[dict],
    filter_expr: str,
) -> Path:
    """Write a manifest file documenting the quarantine operation."""
    manifest = {
        "quarantine_date": datetime.now().isoformat(),
        "filter": filter_expr,
        "file_count": len(moved_files),
        "files": moved_files,
    }

    manifest_path = dest_dir / f"quarantine_manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return manifest_path


def list_quarantined_files(quarantine_dir: Path) -> List[dict]:
    """List all quarantined files with their manifests."""
    files = []

    if not quarantine_dir.exists():
        return files

    # Find manifest files
    manifests = list(quarantine_dir.glob("quarantine_manifest_*.json"))

    for manifest_path in manifests:
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
                for file_info in manifest.get("files", []):
                    file_info["manifest"] = str(manifest_path)
                    file_info["quarantine_date"] = manifest.get("quarantine_date", "")
                    files.append(file_info)
        except (json.JSONDecodeError, IOError):
            continue

    return files


def cmd_quarantine_list(args) -> int:
    """List quarantined files."""
    from openlabels.cli.output import console
    from rich.panel import Panel
    from rich.table import Table

    quarantine_dir = Path(args.quarantine_dir) if args.quarantine_dir else Path.home() / ".openlabels" / "quarantine"

    files = list_quarantined_files(quarantine_dir)

    if not files:
        echo("No quarantined files found.")
        echo(f"Quarantine directory: {quarantine_dir}")
        return 0

    # Show as panel with table
    console.print(Panel(
        f"[bold]{len(files)} files quarantined[/bold]\n\n"
        f"Restore: openlabels quarantine --restore <original-path>\n"
        f"Delete:  openlabels quarantine --delete <original-path>",
        title=f"Quarantine: {quarantine_dir}",
        border_style="yellow",
    ))

    # Show table
    table = Table()
    table.add_column("Original Path", style="cyan")
    table.add_column("Quarantined", style="dim")
    table.add_column("Score", justify="right")
    table.add_column("Tier", justify="center")

    for f in files:
        tier = f.get("tier", "UNKNOWN")
        tier_style = {
            "CRITICAL": "bold red",
            "HIGH": "yellow",
            "MEDIUM": "orange3",
            "LOW": "green",
        }.get(tier, "dim")

        table.add_row(
            f.get("original_path", ""),
            f.get("quarantine_date", "")[:16] if f.get("quarantine_date") else "",
            str(f.get("score", 0)),
            f"[{tier_style}]{tier}[/{tier_style}]",
        )

    console.print(table)
    return 0


def cmd_quarantine_restore(args) -> int:
    """Restore a quarantined file."""
    quarantine_dir = Path(args.quarantine_dir) if args.quarantine_dir else Path.home() / ".openlabels" / "quarantine"
    original_path = args.restore

    files = list_quarantined_files(quarantine_dir)

    # Find the file
    file_info = None
    for f in files:
        if f.get("original_path") == original_path:
            file_info = f
            break

    if not file_info:
        error(f"File not found in quarantine: {original_path}")
        return 1

    new_path = Path(file_info.get("new_path", ""))
    if not new_path.exists():
        error(f"Quarantined file no longer exists: {new_path}")
        return 1

    # Restore the file
    try:
        original = Path(original_path)
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(new_path), str(original))
        success(f"Restored: {original_path}")
        return 0
    except Exception as e:
        error(f"Failed to restore: {e}")
        return 1


def cmd_quarantine_delete(args) -> int:
    """Delete a quarantined file permanently."""
    from openlabels.cli.output import confirm_destructive

    quarantine_dir = Path(args.quarantine_dir) if args.quarantine_dir else Path.home() / ".openlabels" / "quarantine"
    original_path = args.delete

    files = list_quarantined_files(quarantine_dir)

    # Find the file
    file_info = None
    for f in files:
        if f.get("original_path") == original_path:
            file_info = f
            break

    if not file_info:
        error(f"File not found in quarantine: {original_path}")
        return 1

    new_path = Path(file_info.get("new_path", ""))

    if not args.force:
        if not confirm_destructive(
            f"Permanently delete {original_path}?",
            confirmation_word="DELETE"
        ):
            echo("Cancelled")
            return 1

    try:
        if new_path.exists():
            new_path.unlink()
        success(f"Deleted: {original_path}")
        return 0
    except Exception as e:
        error(f"Failed to delete: {e}")
        return 1


def cmd_quarantine(args) -> int:
    """Execute the quarantine command."""
    # Handle subcommands
    if args.list:
        return cmd_quarantine_list(args)
    if args.restore:
        return cmd_quarantine_restore(args)
    if args.delete:
        return cmd_quarantine_delete(args)

    # Original quarantine behavior requires source, where, and to
    if not args.source:
        error("Source path is required for quarantine operation")
        error("Or use --list to view quarantined files")
        return 1

    if not args.where:
        error("--where filter is required for quarantine")
        error("Or use --list to view quarantined files")
        return 1

    if not args.to:
        error("--to destination is required")
        return 1

    source = Path(args.source)
    dest = Path(args.to)

    if not source.exists():
        error(f"Source not found: {source}")
        return 1

    logger.info(f"Starting quarantine operation", extra={
        "source": str(source),
        "destination": str(dest),
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

    # Dry run - just show what would be moved
    if args.dry_run:
        echo(f"Would quarantine [bold]{len(matches)}[/bold] files to {dest}:\n")
        for result in matches[:MAX_PREVIEW_RESULTS]:
            dim(f"  {result.path} (score: {result.score})")
        if len(matches) > MAX_PREVIEW_RESULTS:
            dim(f"  ... and {len(matches) - MAX_PREVIEW_RESULTS} more")
        return 0

    # Confirm if not forced
    if not args.force:
        echo(f"About to quarantine [bold]{len(matches)}[/bold] files to {dest}")
        echo(f"Filter: {args.where}")
        echo("")
        for result in matches[:5]:
            dim(f"  {result.path} (score: {result.score})")
        if len(matches) > 5:
            dim(f"  ... and {len(matches) - 5} more")
        echo("")

        if not confirm("Proceed?"):
            echo("Aborted")
            logger.info("Quarantine aborted by user")
            return 1

    # Create destination directory
    dest.mkdir(parents=True, exist_ok=True)

    # Move files
    moved_files = []
    errors = []
    base_path = source if source.is_dir() else source.parent

    with progress("Quarantining files", total=len(matches)) as p:
        for i, result in enumerate(matches):
            try:
                source_path = Path(result.path)
                new_path = move_file(
                    source_path,
                    dest,
                    preserve_structure=args.preserve_structure,
                    base_path=base_path,
                )

                moved_files.append({
                    "original_path": result.path,
                    "new_path": str(new_path),
                    "score": result.score,
                    "tier": result.tier,
                    "entities": result.entities,
                })

                # Audit log for each quarantined file
                audit.file_quarantine(
                    source=result.path,
                    destination=str(new_path),
                    score=result.score,
                    tier=result.tier,
                )

                logger.debug(f"Moved {result.path} -> {new_path}")

                if not args.quiet:
                    p.set_description(f"[{i+1}/{len(matches)}] {Path(result.path).name}")

            except (OSError, ValueError) as e:
                errors.append({"path": result.path, "error": str(e)})
                logger.warning(f"Failed to quarantine {result.path}: {e}")
                if not args.quiet:
                    warn(f"Failed: {result.path} - {e}")

            p.advance()

    # Write manifest
    if args.manifest and moved_files:
        manifest_path = write_manifest(dest, moved_files, args.where)
        echo(f"\nManifest written to: {manifest_path}")
        logger.info(f"Manifest written to {manifest_path}")

    # Summary
    echo("")
    divider()
    if errors:
        warn(f"Quarantined: {len(moved_files)} files ({len(errors)} errors)")
    else:
        success(f"Quarantined: {len(moved_files)} files")
    echo(f"Destination: {dest}")

    logger.info(f"Quarantine complete", extra={
        "files_moved": len(moved_files),
        "errors": len(errors),
        "destination": str(dest),
    })

    return 0 if not errors else 1


def add_quarantine_parser(subparsers, hidden=False):
    """Add the quarantine subparser."""
    import argparse
    parser = subparsers.add_parser(
        "quarantine",
        help=argparse.SUPPRESS if hidden else "Move matching files to quarantine location",
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Local source path to search (not needed for --list, --restore, --delete)",
    )
    # Management subcommands
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List quarantined files",
    )
    parser.add_argument(
        "--restore",
        metavar="PATH",
        help="Restore a quarantined file by its original path",
    )
    parser.add_argument(
        "--delete",
        metavar="PATH",
        help="Permanently delete a quarantined file by its original path",
    )
    parser.add_argument(
        "--quarantine-dir",
        help="Quarantine directory (default: ~/.openlabels/quarantine)",
    )
    # Original quarantine operation arguments
    parser.add_argument(
        "--where", "-w",
        help="Filter expression (required for quarantine operation)",
    )
    parser.add_argument(
        "--to", "-t",
        help="Local destination quarantine directory",
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
        help="Preview what would be moved without moving",
    )
    parser.add_argument(
        "--force", "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )
    parser.add_argument(
        "--preserve-structure", "-p",
        action="store_true",
        default=True,
        help="Preserve directory structure in destination",
    )
    parser.add_argument(
        "--no-preserve-structure",
        action="store_false",
        dest="preserve_structure",
        help="Flatten directory structure",
    )
    parser.add_argument(
        "--manifest", "-m",
        action="store_true",
        default=True,
        help="Write manifest file (default: true)",
    )
    parser.add_argument(
        "--no-manifest",
        action="store_false",
        dest="manifest",
        help="Skip manifest file",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_quarantine)

    return parser

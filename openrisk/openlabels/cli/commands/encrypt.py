"""
OpenLabels encrypt command.

Encrypt local files matching filter criteria using GPG or age.

Usage:
    openlabels encrypt <source> --where "<filter>" --key <key-id>
    openlabels encrypt ./data --where "score > 75" --key user@example.com
    openlabels encrypt ./secrets --where "has(API_KEY)" --key age1...
"""

import re
import stat as stat_module
import subprocess
from pathlib import Path

from openlabels import Client
from openlabels.cli import MAX_PREVIEW_RESULTS
from openlabels.cli.commands.find import find_matching
from openlabels.cli.output import echo, error, warn, success, dim, progress, confirm, divider
from openlabels.logging_config import get_logger, get_audit_logger

logger = get_logger(__name__)
audit = get_audit_logger()


# Dangerous shell metacharacters that could enable injection
SHELL_METACHARACTERS = frozenset(['`', '$', '|', ';', '&', '>', '<', '\n', '\r', '\x00'])


def validate_recipient(recipient: str, tool: str) -> bool:
    """
    Validate encryption recipient/key to prevent injection attacks.

    Args:
        recipient: The key ID, email, or public key
        tool: Either 'gpg' or 'age'

    Returns:
        True if the recipient appears safe to use
    """
    if not recipient or len(recipient) > 500:
        return False
    if any(c in recipient for c in SHELL_METACHARACTERS):
        return False

    if tool == "gpg":
        # GPG accepts: hex key IDs, email addresses, key fingerprints, names
        gpg_pattern = re.compile(
            r'^([0-9A-Fa-f]{8,40}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[A-Za-z0-9 ._-]+)$'
        )
        return bool(gpg_pattern.match(recipient))
    elif tool == "age":
        # Age accepts: age1... public keys, SSH public keys, file paths
        age_pattern = re.compile(
            r'^(age1[a-z0-9]{58}|ssh-(rsa|ed25519) [A-Za-z0-9+/=]+ ?.*|[A-Za-z0-9._/-]+)$'
        )
        return bool(age_pattern.match(recipient))
    return False


def validate_file_path(file_path: Path) -> bool:
    """
    Validate file path to prevent injection.

    Args:
        file_path: The path to validate

    Returns:
        True if the path is safe to use with subprocess
    """
    path_str = str(file_path)
    if any(c in path_str for c in SHELL_METACHARACTERS):
        return False
    try:
        resolved = file_path.resolve()
        st = resolved.lstat()  # TOCTOU-001: atomic stat
        # Reject symlinks and non-regular files
        if stat_module.S_ISLNK(st.st_mode):
            return False
        return stat_module.S_ISREG(st.st_mode)
    except (OSError, ValueError):
        return False


def encrypt_file_gpg(file_path: Path, recipient: str) -> bool:
    """Encrypt a file using GPG."""
    if not validate_file_path(file_path):
        return False
    if not validate_recipient(recipient, "gpg"):
        return False

    try:
        result = subprocess.run(
            ["gpg", "--encrypt", "--recipient", recipient, str(file_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            file_path.unlink()
            return True
        return False
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return False


def encrypt_file_age(file_path: Path, recipient: str) -> bool:
    """Encrypt a file using age."""
    if not validate_file_path(file_path):
        return False
    if not validate_recipient(recipient, "age"):
        return False

    try:
        output_path = file_path.with_suffix(file_path.suffix + ".age")
        result = subprocess.run(
            ["age", "--encrypt", "--recipient", recipient, "-o", str(output_path), str(file_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            file_path.unlink()
            return True
        return False
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return False


def cmd_encrypt(args) -> int:
    """Execute the encrypt command."""
    if not args.where:
        error("--where filter is required for encrypt")
        return 1

    if not args.key:
        error("--key is required for encryption")
        return 1

    source = Path(args.source)

    if not source.exists():
        error(f"Source not found: {source}")
        return 1

    # Check for encryption tool
    tool = args.tool
    if tool == "auto":
        # Try to detect available tool
        try:
            subprocess.run(["age", "--version"], capture_output=True)
            tool = "age"
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            try:
                subprocess.run(["gpg", "--version"], capture_output=True)
                tool = "gpg"
            except (FileNotFoundError, OSError, subprocess.SubprocessError):
                error("No encryption tool found. Install 'age' or 'gpg'")
                return 1

    # Validate recipient/key early
    if not validate_recipient(args.key, tool):
        error(f"Invalid key format for {tool}. Check key ID or recipient.")
        return 1

    logger.info(f"Starting encrypt operation", extra={
        "source": str(source),
        "tool": tool,
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

    # Dry run - just show what would be encrypted
    if args.dry_run:
        echo(f"Would encrypt [bold]{len(matches)}[/bold] files using {tool}:\n")
        for result in matches[:MAX_PREVIEW_RESULTS]:
            dim(f"  {result.path} (score: {result.score})")
        if len(matches) > MAX_PREVIEW_RESULTS:
            dim(f"  ... and {len(matches) - MAX_PREVIEW_RESULTS} more")
        return 0

    # Confirm if not forced
    if not args.force:
        echo(f"About to encrypt [bold]{len(matches)}[/bold] files using {tool}")
        echo(f"Key/Recipient: {args.key}")
        echo(f"Filter: {args.where}")
        echo("")
        warn("Original files will be replaced with encrypted versions!")
        echo("")

        if not confirm("Proceed?"):
            echo("Aborted")
            logger.info("Encrypt aborted by user")
            return 1

    # Encrypt files
    encrypted_count = 0
    errors = []

    encrypt_func = encrypt_file_age if tool == "age" else encrypt_file_gpg

    with progress("Encrypting files", total=len(matches)) as p:
        for i, result in enumerate(matches):
            try:
                file_path = Path(result.path)

                if encrypt_func(file_path, args.key):
                    encrypted_count += 1

                    # Audit log for each encrypted file
                    audit.file_encrypt(
                        path=result.path,
                        tool=tool,
                        score=result.score,
                    )

                    logger.debug(f"Encrypted {result.path} with {tool}")

                    if not args.quiet:
                        p.set_description(f"[{i+1}/{len(matches)}] {file_path.name}")
                else:
                    errors.append({"path": result.path, "error": "Encryption failed"})
                    warn(f"Failed: {result.path}")

            except (OSError, ValueError) as e:
                errors.append({"path": result.path, "error": str(e)})
                logger.warning(f"Failed to encrypt {result.path}: {e}")
                if not args.quiet:
                    warn(f"Error: {result.path} - {e}")

            p.advance()

    # Summary
    echo("")
    divider()
    if errors:
        warn(f"Encrypted: {encrypted_count} files ({len(errors)} errors)")
    else:
        success(f"Encrypted: {encrypted_count} files")

    logger.info(f"Encrypt complete", extra={
        "files_encrypted": encrypted_count,
        "errors": len(errors),
        "tool": tool,
    })

    return 0 if not errors else 1


def add_encrypt_parser(subparsers, hidden=False):
    """Add the encrypt subparser."""
    import argparse
    parser = subparsers.add_parser(
        "encrypt",
        help=argparse.SUPPRESS if hidden else "Encrypt matching files",
    )
    parser.add_argument(
        "source",
        help="Local source path to search",
    )
    parser.add_argument(
        "--where", "-w",
        required=True,
        help="Filter expression (required)",
    )
    parser.add_argument(
        "--key", "-k",
        required=True,
        help="Encryption key or recipient (GPG key ID, email, or age public key)",
    )
    parser.add_argument(
        "--tool",
        choices=["auto", "gpg", "age"],
        default="auto",
        help="Encryption tool to use (default: auto-detect)",
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
        help="Preview what would be encrypted without encrypting",
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
    parser.set_defaults(func=cmd_encrypt)

    return parser

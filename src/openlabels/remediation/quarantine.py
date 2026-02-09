"""
Quarantine operations for sensitive files.

Moves files to a secure quarantine location while preserving:
- File permissions (ACLs)
- Timestamps
- Attributes
- Audit information

Windows implementation uses robocopy for reliable transfers with
ACL preservation and retry logic.
"""

import hashlib
import logging
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from .base import (
    RemediationResult,
    RemediationAction,
    get_current_user,
)
from openlabels.exceptions import QuarantineError
from openlabels.exceptions import QuarantineError

logger = logging.getLogger(__name__)

# Robocopy exit codes (bitmap)
# 0: No files copied, no errors
# 1: Files copied successfully
# 2: Extra files/dirs detected (not an error for us)
# 4: Mismatched files/dirs detected
# 8: Some files/dirs could not be copied (copy errors)
# 16: Serious error, no files copied
ROBOCOPY_SUCCESS_CODES = {0, 1, 2, 3}  # 3 = 1+2 (copied + extra)
ROBOCOPY_PARTIAL_CODES = {4, 5, 6, 7}  # Some issues but mostly worked
ROBOCOPY_ERROR_CODES = {8, 16}  # Real failures


def _compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def quarantine(
    source: Path,
    destination: Path,
    preserve_acls: bool = True,
    create_audit_log: bool = True,
    dry_run: bool = False,
    retry_count: int = 3,
    retry_wait: int = 5,
) -> RemediationResult:
    """
    Move a file to quarantine location.

    Uses platform-native tools (robocopy on Windows) to ensure reliable
    transfer with ACL preservation.

    Args:
        source: Path to file to quarantine
        destination: Destination directory (file will keep its name)
        preserve_acls: Whether to preserve file permissions (default: True)
        create_audit_log: Whether to log the operation (default: True)
        dry_run: If True, report what would happen without moving
        retry_count: Number of retries on failure (default: 3)
        retry_wait: Seconds to wait between retries (default: 5)

    Returns:
        RemediationResult with success/failure status

    Raises:
        QuarantineError: If quarantine fails, source file doesn't exist,
            or destination is not a directory
    """
    source = Path(source).resolve()
    destination = Path(destination).resolve()

    # Validate inputs
    if not source.exists():
        raise QuarantineError(f"Source file not found: {source}", path=source)

    if not source.is_file():
        raise QuarantineError(f"Source must be a file, not directory: {source}", path=source)

    # Create destination directory if needed
    if not dry_run:
        destination.mkdir(parents=True, exist_ok=True)

    if not destination.is_dir() and not dry_run:
        raise QuarantineError(f"Destination must be a directory: {destination}", path=destination)

    # Compute file hash before move for integrity verification
    pre_hash: str | None = None
    if not dry_run:
        try:
            pre_hash = _compute_file_hash(source)
        except OSError as e:
            logger.warning(f"Could not compute pre-move hash for {source}: {e}")

    # Dispatch to platform-specific implementation
    if platform.system() == "Windows":
        result = _quarantine_windows(
            source=source,
            destination=destination,
            preserve_acls=preserve_acls,
            dry_run=dry_run,
            retry_count=retry_count,
            retry_wait=retry_wait,
        )
    else:
        result = _quarantine_unix(
            source=source,
            destination=destination,
            preserve_acls=preserve_acls,
            dry_run=dry_run,
        )

    # Verify integrity after move
    if result.success and not dry_run and pre_hash and result.dest_path:
        try:
            post_hash = _compute_file_hash(result.dest_path)
            if pre_hash != post_hash:
                logger.error(
                    f"Hash mismatch after quarantine! "
                    f"pre={pre_hash} post={post_hash} file={result.dest_path}"
                )
                result.error = f"Integrity warning: hash mismatch ({pre_hash} != {post_hash})"
        except OSError as e:
            logger.warning(f"Could not compute post-move hash for {result.dest_path}: {e}")

    # Attach the pre-move hash to the result for manifest storage
    if pre_hash:
        result.file_hash = pre_hash

    return result


def _quarantine_windows(
    source: Path,
    destination: Path,
    preserve_acls: bool,
    dry_run: bool,
    retry_count: int,
    retry_wait: int,
) -> RemediationResult:
    """
    Windows quarantine using robocopy.

    Robocopy flags:
    - /MOVE: Move files (delete from source after copy)
    - /COPY:DATSOU: Copy Data, Attributes, Timestamps, Security, Owner, aUditing
    - /R:n: Retry count
    - /W:n: Wait time between retries
    - /NP: No progress (cleaner output)
    - /NDL: No directory list
    - /NJH: No job header
    - /NJS: No job summary
    """
    dest_file = destination / source.name

    # Build robocopy command
    # robocopy works on directories, so we specify the file as a filter
    copy_flags = "DATSOU" if preserve_acls else "DAT"

    cmd = [
        "robocopy",
        str(source.parent),  # Source directory
        str(destination),  # Destination directory
        source.name,  # File filter
        "/MOVE",  # Move (delete after copy)
        f"/COPY:{copy_flags}",
        f"/R:{retry_count}",
        f"/W:{retry_wait}",
        "/NP",  # No progress
        "/NDL",  # No directory list
        "/NJH",  # No job header
        "/NJS",  # No job summary
    ]

    if dry_run:
        cmd.append("/L")  # List only, don't actually move

    logger.info(f"Quarantine command: {' '.join(cmd)}")

    if dry_run:
        logger.info(f"[DRY RUN] Would move {source} to {dest_file}")
        return RemediationResult(
            success=True,
            action=RemediationAction.QUARANTINE,
            source_path=source,
            dest_path=dest_file,
            performed_by=get_current_user(),
        )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        # Check robocopy exit code
        if result.returncode in ROBOCOPY_SUCCESS_CODES:
            logger.info(f"Successfully quarantined {source} to {dest_file}")
            return RemediationResult.success_quarantine(
                source=source,
                dest=dest_file,
                performed_by=get_current_user(),
            )
        elif result.returncode in ROBOCOPY_PARTIAL_CODES:
            # Partial success - file might have been copied but with issues
            logger.warning(f"Partial success quarantining {source}: {result.stdout}")
            return RemediationResult(
                success=True,  # Consider partial success as success
                action=RemediationAction.QUARANTINE,
                source_path=source,
                dest_path=dest_file,
                error=f"Partial success (code {result.returncode}): {result.stdout}",
                error_code=result.returncode,
                performed_by=get_current_user(),
            )
        else:
            # Real failure
            error_msg = result.stderr or result.stdout or f"robocopy failed with code {result.returncode}"
            logger.error(f"Failed to quarantine {source}: {error_msg}")
            return RemediationResult.failure(
                action=RemediationAction.QUARANTINE,
                source=source,
                error=error_msg,
                error_code=result.returncode,
            )

    except subprocess.TimeoutExpired:
        error_msg = "Quarantine operation timed out"
        logger.error(f"{error_msg}: {source}")
        return RemediationResult.failure(
            action=RemediationAction.QUARANTINE,
            source=source,
            error=error_msg,
        )
    except (OSError, PermissionError, RuntimeError) as e:
        # Log unexpected errors with full exception type for debugging
        logger.error(f"Unexpected error quarantining {source}: {type(e).__name__}: {e}")
        return RemediationResult.failure(
            action=RemediationAction.QUARANTINE,
            source=source,
            error=f"{type(e).__name__}: {e}",
        )


def _quarantine_unix(
    source: Path,
    destination: Path,
    preserve_acls: bool,
    dry_run: bool,
) -> RemediationResult:
    """
    Unix quarantine using shutil (fallback) or rsync if available.

    Note: Full ACL preservation on Unix requires rsync with -A flag
    and both source and destination filesystems supporting ACLs.
    """
    dest_file = destination / source.name

    if dry_run:
        logger.info(f"[DRY RUN] Would move {source} to {dest_file}")
        return RemediationResult(
            success=True,
            action=RemediationAction.QUARANTINE,
            source_path=source,
            dest_path=dest_file,
            performed_by=get_current_user(),
        )

    # Try rsync first for better ACL preservation
    if preserve_acls and shutil.which("rsync"):
        try:
            cmd = [
                "rsync",
                "-avX",  # Archive mode, preserve extended attributes
                "--remove-source-files",  # Delete source after copy
                str(source),
                str(destination) + "/",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                logger.info(f"Successfully quarantined {source} to {dest_file}")
                return RemediationResult.success_quarantine(
                    source=source,
                    dest=dest_file,
                    performed_by=get_current_user(),
                )
            else:
                # rsync failed, fall through to shutil
                logger.warning(f"rsync failed, falling back to shutil: {result.stderr}")

        except (OSError, subprocess.SubprocessError) as e:
            # Log rsync failures with exception type - non-critical as we have fallback
            logger.info(f"rsync failed, falling back to shutil: {type(e).__name__}: {e}")

    # Fallback to shutil.move
    try:
        shutil.move(str(source), str(dest_file))
        logger.info(f"Successfully quarantined {source} to {dest_file}")
        return RemediationResult.success_quarantine(
            source=source,
            dest=dest_file,
            performed_by=get_current_user(),
        )
    except Exception as e:
        # Log quarantine failures with full exception type for debugging
        logger.error(f"Failed to quarantine {source}: {type(e).__name__}: {e}")
        return RemediationResult.failure(
            action=RemediationAction.QUARANTINE,
            source=source,
            error=f"{type(e).__name__}: {e}",
        )


def restore_from_quarantine(
    entry_id: str,
    manifest: "QuarantineManifest",
    verify_hash: bool = True,
    dry_run: bool = False,
) -> RemediationResult:
    """Restore a quarantined file to its original location.

    Args:
        entry_id: ID of the quarantine manifest entry.
        manifest: The :class:`QuarantineManifest` that tracks the entry.
        verify_hash: If ``True`` (default), verify the SHA-256 hash of the
            quarantined file matches the hash recorded at quarantine time.
        dry_run: If ``True``, report what would happen without moving.

    Returns:
        RemediationResult with success/failure status.
    """
    from .manifest import QuarantineManifest  # noqa: F811 — runtime import

    entry = manifest.get(entry_id)
    if not entry:
        return RemediationResult.failure(
            action=RemediationAction.RESTORE,
            source=Path(entry_id),
            error="Quarantine entry not found",
        )

    quarantine_path = Path(entry.quarantine_path)
    original_path = Path(entry.original_path)

    if not quarantine_path.exists():
        return RemediationResult.failure(
            action=RemediationAction.RESTORE,
            source=quarantine_path,
            error="Quarantined file no longer exists",
        )

    # Verify integrity before restoring
    if verify_hash and entry.file_hash:
        actual_hash = _compute_file_hash(quarantine_path)
        if actual_hash != entry.file_hash:
            return RemediationResult.failure(
                action=RemediationAction.RESTORE,
                source=quarantine_path,
                error=f"Hash mismatch: expected {entry.file_hash}, got {actual_hash}",
            )

    if dry_run:
        return RemediationResult(
            success=True,
            action=RemediationAction.RESTORE,
            source_path=quarantine_path,
            dest_path=original_path,
            performed_by=get_current_user(),
        )

    # Move file back to original location
    original_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(quarantine_path), str(original_path))
    except (OSError, PermissionError) as e:
        logger.error(f"Failed to restore {quarantine_path} to {original_path}: {e}")
        return RemediationResult.failure(
            action=RemediationAction.RESTORE,
            source=quarantine_path,
            error=str(e),
        )

    manifest.mark_restored(entry_id)
    logger.info(f"Restored {quarantine_path} to {original_path}")

    return RemediationResult(
        success=True,
        action=RemediationAction.RESTORE,
        source_path=quarantine_path,
        dest_path=original_path,
        performed_by=get_current_user(),
    )

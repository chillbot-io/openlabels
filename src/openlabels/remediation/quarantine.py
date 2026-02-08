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
        QuarantineError: If quarantine fails and raise_on_error is True
        FileNotFoundError: If source file doesn't exist
        NotADirectoryError: If destination is not a directory
    """
    source = Path(source).resolve()
    destination = Path(destination).resolve()

    # Validate inputs
    if not source.exists():
        raise FileNotFoundError(f"Source file not found: {source}")

    if not source.is_file():
        raise ValueError(f"Source must be a file, not directory: {source}")

    # Create destination directory if needed
    if not dry_run:
        destination.mkdir(parents=True, exist_ok=True)

    if not destination.is_dir() and not dry_run:
        raise NotADirectoryError(f"Destination must be a directory: {destination}")

    # Dispatch to platform-specific implementation
    if platform.system() == "Windows":
        return _quarantine_windows(
            source=source,
            destination=destination,
            preserve_acls=preserve_acls,
            dry_run=dry_run,
            retry_count=retry_count,
            retry_wait=retry_wait,
        )
    else:
        return _quarantine_unix(
            source=source,
            destination=destination,
            preserve_acls=preserve_acls,
            dry_run=dry_run,
        )


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

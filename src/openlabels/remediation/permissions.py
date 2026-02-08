"""
Permission lockdown operations for sensitive files.

Restricts file access to a specified set of principals (users/groups),
removing all other permissions. This is a remediation action for
sensitive files that should have minimal access.

Windows implementation uses icacls for ACL manipulation.
"""

import base64
import logging
import platform
import subprocess
from pathlib import Path
from typing import List, Optional

from .base import (
    RemediationResult,
    RemediationAction,
    get_current_user,
)
from openlabels.exceptions import RemediationPermissionError

logger = logging.getLogger(__name__)

# Default principals when none specified
DEFAULT_WINDOWS_PRINCIPALS = ["BUILTIN\\Administrators"]
DEFAULT_UNIX_PRINCIPALS = ["root"]


def lock_down(
    path: Path,
    allowed_principals: Optional[List[str]] = None,
    remove_inheritance: bool = True,
    backup_acl: bool = True,
    dry_run: bool = False,
) -> RemediationResult:
    """
    Lock down file permissions to specified principals only.

    Removes all existing discretionary access and grants access only to
    the specified principals. By default, only local Administrators
    can access the file after lockdown.

    Args:
        path: Path to file to lock down
        allowed_principals: List of users/groups to grant access.
                          Default: ["BUILTIN\\Administrators"] on Windows
        remove_inheritance: Whether to remove inherited permissions (default: True)
        backup_acl: Whether to save the previous ACL for audit (default: True)
        dry_run: If True, report what would happen without changing permissions

    Returns:
        RemediationResult with success/failure status and previous ACL

    Raises:
        FileNotFoundError: If file doesn't exist
        RemediationPermissionError: If unable to modify permissions
    """
    path = Path(path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Set default principals based on platform
    if allowed_principals is None:
        if platform.system() == "Windows":
            allowed_principals = DEFAULT_WINDOWS_PRINCIPALS
        else:
            allowed_principals = DEFAULT_UNIX_PRINCIPALS

    # Dispatch to platform-specific implementation
    if platform.system() == "Windows":
        return _lock_down_windows(
            path=path,
            allowed_principals=allowed_principals,
            remove_inheritance=remove_inheritance,
            backup_acl=backup_acl,
            dry_run=dry_run,
        )
    else:
        return _lock_down_unix(
            path=path,
            allowed_principals=allowed_principals,
            backup_acl=backup_acl,
            dry_run=dry_run,
        )


def get_current_acl(path: Path) -> dict:
    """
    Get current ACL/permissions for a file.

    Returns a dictionary with platform-specific permission information.

    Args:
        path: Path to file

    Returns:
        Dictionary with ACL information
    """
    path = Path(path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if platform.system() == "Windows":
        return _get_acl_windows(path)
    else:
        return _get_acl_unix(path)


def _lock_down_windows(
    path: Path,
    allowed_principals: List[str],
    remove_inheritance: bool,
    backup_acl: bool,
    dry_run: bool,
) -> RemediationResult:
    """
    Windows permission lockdown using icacls.

    Steps:
    1. Backup current ACL (if requested)
    2. Disable inheritance (copy inherited to explicit)
    3. Reset permissions (remove all explicit)
    4. Grant full control to specified principals
    """
    previous_acl = None

    # Backup current ACL
    if backup_acl:
        try:
            acl_info = _get_acl_windows(path)
            previous_acl = base64.b64encode(
                acl_info.get("raw", "").encode()
            ).decode()
        except Exception as e:
            logger.warning(f"Failed to backup ACL: {e}")

    if dry_run:
        logger.info(f"[DRY RUN] Would lock down {path}")
        logger.info(f"[DRY RUN] Allowed principals: {allowed_principals}")
        logger.info(f"[DRY RUN] Remove inheritance: {remove_inheritance}")
        return RemediationResult(
            success=True,
            action=RemediationAction.LOCKDOWN,
            source_path=path,
            principals=allowed_principals,
            previous_acl=previous_acl,
            performed_by=get_current_user(),
        )

    try:
        # Step 1: Disable inheritance (copy inherited permissions to explicit)
        if remove_inheritance:
            result = subprocess.run(
                ["icacls", str(path), "/inheritance:d"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning(f"Failed to disable inheritance: {result.stderr}")

        # Step 2: Reset permissions (remove all explicit ACEs)
        result = subprocess.run(
            ["icacls", str(path), "/reset"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RemediationPermissionError(f"Failed to reset permissions: {result.stderr}", path)

        # Step 3: Grant full control to each allowed principal
        for principal in allowed_principals:
            # /grant:r replaces any existing permission for this principal
            # (OI)(CI)F = Object Inherit, Container Inherit, Full control
            result = subprocess.run(
                ["icacls", str(path), "/grant:r", f"{principal}:(OI)(CI)F"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise RemediationPermissionError(
                    f"Failed to grant access to {principal}: {result.stderr}",
                    path,
                )

        # Step 4: Remove common overly-permissive principals
        # These might have been inherited before we disabled inheritance
        principals_to_remove = [
            "Everyone",
            "BUILTIN\\Users",
            "Authenticated Users",
        ]

        for principal in principals_to_remove:
            if principal not in allowed_principals:
                # /remove removes all ACEs for this principal (ignore errors)
                subprocess.run(
                    ["icacls", str(path), "/remove", principal],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

        logger.info(f"Successfully locked down {path} to: {allowed_principals}")
        return RemediationResult.success_lockdown(
            path=path,
            principals=allowed_principals,
            previous_acl=previous_acl,
            performed_by=get_current_user(),
        )

    except RemediationPermissionError:
        raise
    except subprocess.TimeoutExpired:
        error_msg = "Permission lockdown operation timed out"
        logger.error(f"{error_msg}: {path}")
        return RemediationResult.failure(
            action=RemediationAction.LOCKDOWN,
            source=path,
            error=error_msg,
        )
    except Exception as e:
        logger.error(f"Failed to lock down {path}: {e}")
        return RemediationResult.failure(
            action=RemediationAction.LOCKDOWN,
            source=path,
            error=str(e),
        )


def _lock_down_unix(
    path: Path,
    allowed_principals: List[str],
    backup_acl: bool,
    dry_run: bool,
) -> RemediationResult:
    """
    Unix permission lockdown using chmod and setfacl.

    For basic lockdown, sets permissions to owner-only (600 for files).
    If setfacl is available, can grant access to specific users/groups.
    """
    previous_acl = None

    # Backup current permissions
    if backup_acl:
        try:
            acl_info = _get_acl_unix(path)
            previous_acl = base64.b64encode(
                str(acl_info).encode()
            ).decode()
        except Exception as e:
            logger.warning(f"Failed to backup permissions: {e}")

    if dry_run:
        logger.info(f"[DRY RUN] Would lock down {path}")
        logger.info(f"[DRY RUN] Allowed principals: {allowed_principals}")
        return RemediationResult(
            success=True,
            action=RemediationAction.LOCKDOWN,
            source_path=path,
            principals=allowed_principals,
            previous_acl=previous_acl,
            performed_by=get_current_user(),
        )

    try:
        import os
        import stat

        # Step 1: Remove all ACLs if setfacl is available
        if _has_setfacl():
            subprocess.run(
                ["setfacl", "-b", str(path)],  # Remove all ACLs
                capture_output=True,
                timeout=30,
            )

        # Step 2: Set base permissions to owner-only
        if path.is_dir():
            os.chmod(path, stat.S_IRWXU)  # 700
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600

        # Step 3: Add ACL entries for allowed principals (if setfacl available)
        if _has_setfacl() and allowed_principals:
            for principal in allowed_principals:
                if principal == "root":
                    continue  # root already has access via owner
                # Try as user first, then as group
                result = subprocess.run(
                    ["setfacl", "-m", f"u:{principal}:rwx", str(path)],
                    capture_output=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    # Try as group
                    subprocess.run(
                        ["setfacl", "-m", f"g:{principal}:rwx", str(path)],
                        capture_output=True,
                        timeout=30,
                    )

        logger.info(f"Successfully locked down {path} to: {allowed_principals}")
        return RemediationResult.success_lockdown(
            path=path,
            principals=allowed_principals,
            previous_acl=previous_acl,
            performed_by=get_current_user(),
        )

    except Exception as e:
        logger.error(f"Failed to lock down {path}: {e}")
        return RemediationResult.failure(
            action=RemediationAction.LOCKDOWN,
            source=path,
            error=str(e),
        )


def _get_acl_windows(path: Path) -> dict:
    """Get Windows ACL using icacls."""
    result = subprocess.run(
        ["icacls", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
    )

    return {
        "path": str(path),
        "raw": result.stdout,
        "return_code": result.returncode,
    }


def _get_acl_unix(path: Path) -> dict:
    """Get Unix permissions and ACLs."""
    import os
    import stat

    st = os.stat(path)

    result = {
        "path": str(path),
        "mode": oct(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
    }

    # Try to get extended ACLs if getfacl is available
    if _has_getfacl():
        proc = subprocess.run(
            ["getfacl", "-p", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0:
            result["acl"] = proc.stdout

    return result


def _has_setfacl() -> bool:
    """Check if setfacl is available."""
    import shutil

    return shutil.which("setfacl") is not None


def _has_getfacl() -> bool:
    """Check if getfacl is available."""
    import shutil

    return shutil.which("getfacl") is not None

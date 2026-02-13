"""
Permission lockdown operations for sensitive files.

Restricts file access to a specified set of principals (users/groups),
removing all other permissions. This is a remediation action for
sensitive files that should have minimal access.

Windows implementation uses icacls for ACL manipulation.
"""

from __future__ import annotations

import base64
import logging
import platform
import subprocess
from pathlib import Path

from openlabels.core.constants import SUBPROCESS_TIMEOUT
from openlabels.exceptions import RemediationPermissionError

from .base import (
    RemediationAction,
    RemediationResult,
    get_current_user,
)

logger = logging.getLogger(__name__)

# Default principals when none specified
DEFAULT_WINDOWS_PRINCIPALS = ["BUILTIN\\Administrators"]
DEFAULT_UNIX_PRINCIPALS = ["root"]


def lock_down(
    path: Path,
    allowed_principals: list[str] | None = None,
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
        RemediationPermissionError: If file doesn't exist or unable to modify permissions
    """
    path = Path(path).resolve()

    if not path.exists():
        raise RemediationPermissionError(f"File not found: {path}", path=path)

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
        raise RemediationPermissionError(f"File not found: {path}", path=path)

    if platform.system() == "Windows":
        return _get_acl_windows(path)
    else:
        return _get_acl_unix(path)


def _lock_down_windows(
    path: Path,
    allowed_principals: list[str],
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
        except (subprocess.SubprocessError, OSError, ValueError) as e:
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
                timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode != 0:
                logger.warning(f"Failed to disable inheritance: {result.stderr}")

        # Step 2: Reset permissions (remove all explicit ACEs)
        result = subprocess.run(
            ["icacls", str(path), "/reset"],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
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
                timeout=SUBPROCESS_TIMEOUT,
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
                    timeout=SUBPROCESS_TIMEOUT,
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
    except (subprocess.SubprocessError, OSError) as e:
        logger.error(f"Failed to lock down {path}: {e}")
        return RemediationResult.failure(
            action=RemediationAction.LOCKDOWN,
            source=path,
            error=str(e),
        )


def _lock_down_unix(
    path: Path,
    allowed_principals: list[str],
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
            import json as _json
            acl_info = _get_acl_unix(path)
            # Use JSON format for new backups (restore code handles both JSON
            # and legacy Python repr format for backwards compatibility)
            previous_acl = base64.b64encode(
                _json.dumps(acl_info).encode()
            ).decode()
        except (subprocess.SubprocessError, OSError, ValueError) as e:
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
                timeout=SUBPROCESS_TIMEOUT,
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
                    timeout=SUBPROCESS_TIMEOUT,
                )
                if result.returncode != 0:
                    # Try as group
                    subprocess.run(
                        ["setfacl", "-m", f"g:{principal}:rwx", str(path)],
                        capture_output=True,
                        timeout=SUBPROCESS_TIMEOUT,
                    )

        logger.info(f"Successfully locked down {path} to: {allowed_principals}")
        return RemediationResult.success_lockdown(
            path=path,
            principals=allowed_principals,
            previous_acl=previous_acl,
            performed_by=get_current_user(),
        )

    except (subprocess.SubprocessError, OSError) as e:
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
        timeout=SUBPROCESS_TIMEOUT,
    )

    return {
        "path": str(path),
        "raw": result.stdout,
        "return_code": result.returncode,
    }


def _get_acl_unix(path: Path) -> dict:
    """Get Unix permissions and ACLs."""
    import os

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
            timeout=SUBPROCESS_TIMEOUT,
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


def restore_permissions(
    path: Path,
    previous_acl: str,
    dry_run: bool = False,
) -> RemediationResult:
    """
    Restore file permissions from a previously backed-up ACL.

    Reverses a ``lock_down()`` operation by applying the saved ACL state.
    The *previous_acl* string is base64-encoded (the format stored by
    ``lock_down(backup_acl=True)``).

    Args:
        path: Path to file whose permissions should be restored.
        previous_acl: Base64-encoded ACL snapshot produced by ``lock_down()``.
        dry_run: If True, report what would happen without modifying permissions.

    Returns:
        RemediationResult with success/failure status.

    Raises:
        RemediationPermissionError: If the file doesn't exist or permissions cannot be restored.
    """
    path = Path(path).resolve()

    if not path.exists():
        raise RemediationPermissionError(f"File not found: {path}", path=path)

    try:
        acl_data = base64.b64decode(previous_acl).decode()
    except (ValueError, UnicodeDecodeError) as e:
        raise RemediationPermissionError(
            f"Invalid base64-encoded ACL data: {e}", path
        ) from e

    if dry_run:
        logger.info("[DRY RUN] Would restore permissions for %s", path)
        return RemediationResult(
            success=True,
            action=RemediationAction.RESTORE,
            source_path=path,
            performed_by=get_current_user(),
        )

    if platform.system() == "Windows":
        return _restore_permissions_windows(path, acl_data)
    else:
        return _restore_permissions_unix(path, acl_data)


def _restore_permissions_windows(path: Path, acl_data: str) -> RemediationResult:
    """Restore Windows ACL from icacls output.

    Parses backed-up icacls output lines and reapplies each grant
    via ``icacls /grant``.
    """
    try:
        # Reset to clean state first
        result = subprocess.run(
            ["icacls", str(path), "/reset"],
            capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
        )
        if result.returncode != 0:
            raise RemediationPermissionError(
                f"Failed to reset permissions before restore: {result.stderr}", path,
            )

        # Parse original icacls output and re-grant each ACE.
        # icacls output format: "  PRINCIPAL:(PERM)(PERM)..."
        # Use regex to handle principals with spaces (e.g. "DOMAIN\User Name").
        import re
        ace_pattern = re.compile(r"(\S.*?):(\([^)]+\)(?:\([^)]+\))*\S*)")
        restore_failures = []
        for line in acl_data.splitlines():
            line = line.strip()
            if not line:
                continue
            for match in ace_pattern.finditer(line):
                ace_str = match.group(0)  # "PRINCIPAL:(OI)(CI)F"
                grant_result = subprocess.run(
                    ["icacls", str(path), "/grant", ace_str],
                    capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
                )
                if grant_result.returncode != 0:
                    restore_failures.append(ace_str)
                    logger.warning("Failed to restore ACE %s: %s", ace_str, grant_result.stderr)

        if restore_failures:
            logger.warning("Some ACEs could not be restored for %s: %s", path, restore_failures)
            return RemediationResult(
                success=False,
                action=RemediationAction.RESTORE,
                source_path=path,
                performed_by=get_current_user(),
                error=f"Failed to restore {len(restore_failures)} ACE(s)",
            )

        logger.info("Restored permissions for %s from backup", path)
        return RemediationResult(
            success=True,
            action=RemediationAction.RESTORE,
            source_path=path,
            performed_by=get_current_user(),
        )

    except RemediationPermissionError:
        raise
    except subprocess.TimeoutExpired:
        error_msg = "Permission restore operation timed out"
        logger.error("%s: %s", error_msg, path)
        return RemediationResult.failure(
            action=RemediationAction.RESTORE, source=path, error=error_msg,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.error("Failed to restore permissions for %s: %s", path, e)
        return RemediationResult.failure(
            action=RemediationAction.RESTORE, source=path, error=str(e),
        )


def _restore_permissions_unix(path: Path, acl_data: str) -> RemediationResult:
    """Restore Unix permissions from backed-up stat/getfacl data.

    The backup is a ``repr(dict)`` containing ``mode``, ``uid``, ``gid``,
    and optionally ``acl`` (getfacl output).
    """
    import json
    import os

    # SECURITY: Use json.loads instead of ast.literal_eval to avoid parsing
    # arbitrarily complex Python literals from potentially-tampered backup data.
    # Limit input size to prevent memory exhaustion from crafted payloads.
    if len(acl_data) > 1_000_000:
        logger.warning("ACL backup data exceeds 1MB limit, treating as raw ACL")
        acl_dict = {"acl": acl_data}
    else:
        try:
            acl_dict = json.loads(acl_data)
        except (json.JSONDecodeError, ValueError):
            # Fall back: legacy backups may use Python repr() format
            try:
                import ast
                acl_dict = ast.literal_eval(acl_data)
            except (ValueError, SyntaxError):
                acl_dict = {"acl": acl_data}

    # Validate that parsed data is a dict (not a list, string, etc.)
    if not isinstance(acl_dict, dict):
        logger.warning("ACL backup data is not a dict (got %s), treating as raw ACL", type(acl_dict).__name__)
        acl_dict = {"acl": acl_data}

    try:
        # Restore mode
        if "mode" in acl_dict:
            # oct() returns strings like '0o100644'; use base 0 to auto-detect
            # the prefix, rather than base 8 which rejects the '0o' prefix.
            mode = int(acl_dict["mode"], 0) if isinstance(acl_dict["mode"], str) else acl_dict["mode"]
            os.chmod(path, mode)

        # Restore ACLs via setfacl if data available
        setfacl_failed = False
        if "acl" in acl_dict and _has_setfacl():
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".acl", delete=False) as tmp:
                tmp.write(acl_dict["acl"])
                tmp_path = tmp.name
            try:
                result = subprocess.run(
                    ["setfacl", "--restore", tmp_path],
                    capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
                )
                if result.returncode != 0:
                    setfacl_failed = True
                    logger.warning("setfacl --restore failed: %s", result.stderr)
            finally:
                Path(tmp_path).unlink(missing_ok=True)

        if setfacl_failed:
            return RemediationResult(
                success=False,
                action=RemediationAction.RESTORE,
                source_path=path,
                performed_by=get_current_user(),
                error="setfacl --restore failed (mode was restored, ACLs were not)",
            )

        logger.info("Restored permissions for %s from backup", path)
        return RemediationResult(
            success=True,
            action=RemediationAction.RESTORE,
            source_path=path,
            performed_by=get_current_user(),
        )

    except (OSError, subprocess.SubprocessError) as e:
        logger.error("Failed to restore permissions for %s: %s", path, e)
        return RemediationResult.failure(
            action=RemediationAction.RESTORE, source=path, error=str(e),
        )

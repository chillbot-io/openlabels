"""
Monitoring registry - manage which files are being monitored.

This module handles:
- Enabling monitoring on files (adding SACL on Windows, audit rules on Linux)
- Disabling monitoring
- Tracking which files are currently monitored

The actual access events are captured by the OS audit system; we just
configure which files to audit.

Persistence
-----------
The in-memory ``_watched_files`` dict serves as a **process-local cache** for
fast synchronous lookups.  Durable state is persisted to the database via the
async helpers in :mod:`openlabels.monitoring.db`.  Callers that run inside an
async context (e.g. FastAPI routes or startup hooks) should call the
corresponding ``db.upsert_monitored_file`` / ``db.remove_monitored_file``
after a successful enable/disable to keep the database in sync.

On application startup, call :func:`populate_cache_from_db` to pre-populate
the in-memory cache from the database so that the registry reflects previously
persisted state.
"""

import logging
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from uuid import UUID

from .base import (
    WatchedFile,
    MonitoringResult,
)
from openlabels.exceptions import MonitoringError, SACLError, AuditRuleError

logger = logging.getLogger(__name__)

# In-memory registry of watched files.
# Acts as a process-local cache; durable state lives in the database
# (see openlabels.monitoring.db for async persistence helpers).
_watched_files: Dict[str, WatchedFile] = {}


def enable_monitoring(
    path: Path,
    risk_tier: str = "HIGH",
    audit_read: bool = True,
    audit_write: bool = True,
    label_id: Optional[str] = None,
) -> MonitoringResult:
    """
    Enable access monitoring on a file.

    On Windows: Adds a System ACL (SACL) entry to audit file access.
    On Linux: Adds an auditd rule for the file.

    Args:
        path: Path to file to monitor
        risk_tier: Risk tier for prioritization ("CRITICAL", "HIGH", etc.)
        audit_read: Whether to audit read access (default: True)
        audit_write: Whether to audit write access (default: True)
        label_id: Optional OpenLabels label ID to associate

    Returns:
        MonitoringResult with success/failure status
    """
    path = Path(path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Check if already monitored
    if str(path) in _watched_files:
        logger.info(f"File already monitored: {path}")
        return MonitoringResult(
            success=True,
            path=path,
            message="Already monitored",
            sacl_enabled=_watched_files[str(path)].sacl_enabled,
            audit_rule_enabled=_watched_files[str(path)].audit_rule_enabled,
        )

    # Dispatch to platform-specific implementation
    if platform.system() == "Windows":
        result = _enable_monitoring_windows(path, audit_read, audit_write)
    else:
        result = _enable_monitoring_linux(path, audit_read, audit_write)

    # Track in registry if successful
    if result.success:
        _watched_files[str(path)] = WatchedFile(
            path=path,
            risk_tier=risk_tier,
            added_at=datetime.now(),
            sacl_enabled=result.sacl_enabled,
            audit_rule_enabled=result.audit_rule_enabled,
            label_id=label_id,
        )
        # NOTE: The in-memory cache has been updated.  Callers running in
        # an async context should also persist to the database:
        #
        #   from openlabels.monitoring import db as monitoring_db
        #   await monitoring_db.upsert_monitored_file(
        #       session, tenant_id, str(path),
        #       risk_tier=risk_tier,
        #       sacl_enabled=result.sacl_enabled,
        #       audit_rule_enabled=result.audit_rule_enabled,
        #       audit_read=audit_read,
        #       audit_write=audit_write,
        #   )

    return result


def disable_monitoring(path: Path) -> MonitoringResult:
    """
    Disable access monitoring on a file.

    Removes the SACL entry (Windows) or audit rule (Linux).

    Args:
        path: Path to file to stop monitoring

    Returns:
        MonitoringResult with success/failure status
    """
    path = Path(path).resolve()

    # Check if currently monitored
    if str(path) not in _watched_files:
        return MonitoringResult(
            success=True,
            path=path,
            message="Not currently monitored",
        )

    # Dispatch to platform-specific implementation
    if platform.system() == "Windows":
        result = _disable_monitoring_windows(path)
    else:
        result = _disable_monitoring_linux(path)

    # Remove from registry if successful
    if result.success:
        del _watched_files[str(path)]
        # NOTE: The in-memory cache has been updated.  Callers running in
        # an async context should also remove from the database:
        #
        #   from openlabels.monitoring import db as monitoring_db
        #   await monitoring_db.remove_monitored_file(
        #       session, tenant_id, str(path),
        #   )

    return result


def is_monitored(path: Path) -> bool:
    """Check if a file is currently being monitored."""
    return str(Path(path).resolve()) in _watched_files


def get_watched_files() -> List[WatchedFile]:
    """Get list of all currently monitored files."""
    return list(_watched_files.values())


def get_watched_file(path: Path) -> Optional[WatchedFile]:
    """Get monitoring info for a specific file."""
    return _watched_files.get(str(Path(path).resolve()))


# =============================================================================
# DATABASE CACHE MANAGEMENT (async)
# =============================================================================


async def populate_cache_from_db(
    session,  # AsyncSession
    tenant_id: UUID,
) -> int:
    """
    Pre-populate the in-memory ``_watched_files`` cache from the database.

    Call this during application startup so the registry reflects previously
    persisted monitoring state.  Only entries that are not already in the
    cache are added (existing entries are left untouched).

    Args:
        session: An active :class:`~sqlalchemy.ext.asyncio.AsyncSession`.
        tenant_id: The tenant whose monitored files to load.

    Returns:
        The number of entries added to the cache.
    """
    from openlabels.monitoring import db as monitoring_db

    db_entries = await monitoring_db.load_from_db(session, tenant_id)
    added = 0
    for file_path, fields in db_entries.items():
        if file_path not in _watched_files:
            _watched_files[file_path] = WatchedFile(
                path=fields["path"],
                risk_tier=fields["risk_tier"],
                added_at=fields["added_at"],
                sacl_enabled=fields["sacl_enabled"],
                audit_rule_enabled=fields["audit_rule_enabled"],
                last_event_at=fields.get("last_event_at"),
                access_count=fields.get("access_count", 0),
            )
            added += 1

    logger.info(
        "Populated in-memory cache with %d entries from database "
        "(tenant %s, %d already cached)",
        added,
        tenant_id,
        len(db_entries) - added,
    )
    return added


async def sync_cache_to_db(
    session,  # AsyncSession
    tenant_id: UUID,
) -> int:
    """
    Persist the current in-memory ``_watched_files`` cache to the database.

    This is the inverse of :func:`populate_cache_from_db`.  Use it as a
    periodic consistency check or a graceful-shutdown hook to ensure that
    any in-memory-only state is durably persisted.

    Args:
        session: An active :class:`~sqlalchemy.ext.asyncio.AsyncSession`.
        tenant_id: The tenant whose state to sync.

    Returns:
        The number of records written to the database.
    """
    from openlabels.monitoring import db as monitoring_db

    return await monitoring_db.sync_to_db(session, tenant_id, _watched_files)


# =============================================================================
# WINDOWS IMPLEMENTATION
# =============================================================================


def _enable_monitoring_windows(
    path: Path,
    audit_read: bool,
    audit_write: bool,
) -> MonitoringResult:
    """
    Enable Windows SACL auditing on a file.

    Uses PowerShell to add audit rules because icacls doesn't support
    SACL modification directly.

    Prerequisites:
    - "Audit object access" must be enabled in Local Security Policy
      or via: auditpol /set /subcategory:"File System" /success:enable
    """
    # Build the access flags
    rights = []
    if audit_read:
        rights.append("Read")
    if audit_write:
        rights.append("Write")

    if not rights:
        return MonitoringResult(
            success=False,
            path=path,
            error="At least one of audit_read or audit_write must be True",
        )

    rights_str = ", ".join(rights)

    # Validate path to prevent command injection
    resolved_path = str(Path(path).resolve())
    # Reject paths containing characters that could break out of PowerShell strings
    if any(c in resolved_path for c in ['"', "'", '`', '$', '\n', '\r', ';', '&', '|']):
        return MonitoringResult(
            success=False,
            path=path,
            error="Path contains invalid characters",
        )

    # PowerShell script to add audit rule (path is validated above)
    ps_script = f'''
$path = "{resolved_path}"
$acl = Get-Acl -Path $path -Audit
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "{rights_str}",
    "None",
    "None",
    "Success, Failure"
)
$acl.AddAuditRule($rule)
Set-Acl -Path $path -AclObject $acl
'''

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logger.info(f"Enabled SACL monitoring on: {path}")
            return MonitoringResult(
                success=True,
                path=path,
                message="SACL audit rule added",
                sacl_enabled=True,
            )
        else:
            error = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Failed to enable SACL on {path}: {error}")
            return MonitoringResult(
                success=False,
                path=path,
                error=f"Failed to add SACL: {error}",
            )

    except subprocess.TimeoutExpired:
        return MonitoringResult(
            success=False,
            path=path,
            error="Operation timed out",
        )
    except Exception as e:
        logger.error(f"Error enabling monitoring on {path}: {e}")
        return MonitoringResult(
            success=False,
            path=path,
            error=str(e),
        )


def _disable_monitoring_windows(path: Path) -> MonitoringResult:
    """Remove Windows SACL auditing from a file."""

    # Validate path to prevent command injection (same as _enable_monitoring_windows)
    resolved_path = str(Path(path).resolve())
    if any(c in resolved_path for c in ['"', "'", '`', '$', '\n', '\r', ';', '&', '|']):
        return MonitoringResult(
            success=False,
            path=path,
            error="Path contains invalid characters",
        )

    # PowerShell script to remove audit rules
    ps_script = f'''
$path = "{resolved_path}"
$acl = Get-Acl -Path $path -Audit
$acl.Audit | ForEach-Object {{ $acl.RemoveAuditRule($_) }} | Out-Null
Set-Acl -Path $path -AclObject $acl
'''

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logger.info(f"Disabled SACL monitoring on: {path}")
            return MonitoringResult(
                success=True,
                path=path,
                message="SACL audit rules removed",
            )
        else:
            error = result.stderr or result.stdout or "Unknown error"
            return MonitoringResult(
                success=False,
                path=path,
                error=f"Failed to remove SACL: {error}",
            )

    except Exception as e:
        return MonitoringResult(
            success=False,
            path=path,
            error=str(e),
        )


# =============================================================================
# LINUX IMPLEMENTATION
# =============================================================================


def _enable_monitoring_linux(
    path: Path,
    audit_read: bool,
    audit_write: bool,
) -> MonitoringResult:
    """
    Enable Linux auditd monitoring on a file.

    Uses auditctl to add a watch rule. The rule persists until reboot
    or explicit removal. For persistence across reboots, rules should
    be added to /etc/audit/rules.d/.

    Prerequisites:
    - auditd service must be running
    - Requires root or CAP_AUDIT_CONTROL capability
    """
    # Build permission flags
    perms = ""
    if audit_read:
        perms += "r"
    if audit_write:
        perms += "wa"  # write and attribute change

    if not perms:
        return MonitoringResult(
            success=False,
            path=path,
            error="At least one of audit_read or audit_write must be True",
        )

    # Check if auditctl is available
    import shutil

    if not shutil.which("auditctl"):
        return MonitoringResult(
            success=False,
            path=path,
            error="auditctl not found - is auditd installed?",
        )

    try:
        # Add audit rule
        # -w: watch path
        # -p: permissions to audit (r=read, w=write, x=execute, a=attribute)
        # -k: key for searching logs
        result = subprocess.run(
            [
                "auditctl",
                "-w", str(path),
                "-p", perms,
                "-k", "openlabels",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logger.info(f"Enabled auditd monitoring on: {path}")
            return MonitoringResult(
                success=True,
                path=path,
                message="Audit rule added",
                audit_rule_enabled=True,
            )
        else:
            error = result.stderr or result.stdout or "Unknown error"

            # Check for common errors
            if "Permission denied" in error or "Operation not permitted" in error:
                error = "Permission denied - requires root or CAP_AUDIT_CONTROL"
            elif "No audit rules" in error:
                error = "auditd service may not be running"

            logger.error(f"Failed to enable audit rule on {path}: {error}")
            return MonitoringResult(
                success=False,
                path=path,
                error=error,
            )

    except subprocess.TimeoutExpired:
        return MonitoringResult(
            success=False,
            path=path,
            error="Operation timed out",
        )
    except Exception as e:
        logger.error(f"Error enabling monitoring on {path}: {e}")
        return MonitoringResult(
            success=False,
            path=path,
            error=str(e),
        )


def _disable_monitoring_linux(path: Path) -> MonitoringResult:
    """Remove Linux auditd watch rule from a file."""

    import shutil

    if not shutil.which("auditctl"):
        return MonitoringResult(
            success=False,
            path=path,
            error="auditctl not found",
        )

    try:
        # Remove audit rule
        # -W: remove watch (opposite of -w)
        result = subprocess.run(
            [
                "auditctl",
                "-W", str(path),
                "-k", "openlabels",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # auditctl returns 0 even if rule doesn't exist
        logger.info(f"Disabled auditd monitoring on: {path}")
        return MonitoringResult(
            success=True,
            path=path,
            message="Audit rule removed",
        )

    except Exception as e:
        return MonitoringResult(
            success=False,
            path=path,
            error=str(e),
        )

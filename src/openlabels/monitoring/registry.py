"""
Monitoring registry - tracks which files are being monitored.

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

from __future__ import annotations

import asyncio
import logging
import platform
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from uuid import UUID

from openlabels.exceptions import MonitoringError

from .base import (
    MonitoringResult,
    WatchedFile,
)

logger = logging.getLogger(__name__)

# In-memory registry of watched files.
# Acts as a process-local cache; durable state lives in the database
# (see openlabels.monitoring.db for async persistence helpers).
_MAX_WATCHED_FILES = 100_000
_watched_files: dict[str, WatchedFile] = {}
_watched_lock = threading.Lock()


def enable_monitoring(
    path: Path,
    risk_tier: str = "HIGH",
    audit_read: bool = True,
    audit_write: bool = True,
    label_id: str | None = None,
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
    path_str = str(path)

    if not path.exists():
        raise MonitoringError(f"File not found: {path}", path=path)

    # Check if already monitored (lock protects the dict read)
    with _watched_lock:
        if path_str in _watched_files:
            logger.info(f"File already monitored: {path}")
            return MonitoringResult(
                success=True,
                path=path,
                message="Already monitored",
                sacl_enabled=_watched_files[path_str].sacl_enabled,
                audit_rule_enabled=_watched_files[path_str].audit_rule_enabled,
            )

    # Platform-specific setup (outside lock — may be slow)
    if platform.system() == "Windows":
        result = _enable_monitoring_windows(path, audit_read, audit_write)
    else:
        result = _enable_monitoring_linux(path, audit_read, audit_write)

    # Track in registry if successful (lock protects the dict write)
    if result.success:
        with _watched_lock:
            if len(_watched_files) >= _MAX_WATCHED_FILES and path_str not in _watched_files:
                logger.warning("Monitoring cache full (%d entries), skipping cache for %s", _MAX_WATCHED_FILES, path_str)
            else:
                _watched_files[path_str] = WatchedFile(
                    path=path,
                    risk_tier=risk_tier,
                    added_at=datetime.now(),
                    sacl_enabled=result.sacl_enabled,
                    audit_rule_enabled=result.audit_rule_enabled,
                    label_id=label_id,
                )

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
    path_str = str(path)

    # Check if currently monitored
    with _watched_lock:
        if path_str not in _watched_files:
            return MonitoringResult(
                success=True,
                path=path,
                message="Not currently monitored",
            )

    # Platform-specific removal (outside lock — may be slow)
    if platform.system() == "Windows":
        result = _disable_monitoring_windows(path)
    else:
        result = _disable_monitoring_linux(path)

    # Remove from registry if successful
    if result.success:
        with _watched_lock:
            _watched_files.pop(path_str, None)

    return result


def is_monitored(path: Path) -> bool:
    """Check if a file is currently being monitored."""
    with _watched_lock:
        return str(Path(path).resolve()) in _watched_files


def get_watched_files() -> list[WatchedFile]:
    """Get list of all currently monitored files."""
    with _watched_lock:
        return list(_watched_files.values())


def get_watched_file(path: Path) -> WatchedFile | None:
    """Get monitoring info for a specific file."""
    with _watched_lock:
        return _watched_files.get(str(Path(path).resolve()))


# DATABASE CACHE MANAGEMENT (async)
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
    with _watched_lock:
        for file_path, fields in db_entries.items():
            if len(_watched_files) >= _MAX_WATCHED_FILES:
                logger.warning("Monitoring cache full (%d entries), stopping DB populate", _MAX_WATCHED_FILES)
                break
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

    with _watched_lock:
        snapshot = dict(_watched_files)
    return await monitoring_db.sync_to_db(session, tenant_id, snapshot)


async def periodic_cache_sync(
    tenant_id: UUID,
    *,
    interval_seconds: int = 300,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Periodically re-populate the in-memory cache from the database.

    Each application instance runs this independently (no advisory lock)
    so that every instance picks up monitoring changes made by other
    instances via the shared database.

    Parameters
    ----------
    tenant_id:
        The tenant whose monitored files to sync.
    interval_seconds:
        Seconds between sync cycles.
    shutdown_event:
        When set, the loop exits gracefully.
    """
    import asyncio

    from openlabels.server.db import get_session_context

    _stop = shutdown_event or asyncio.Event()

    logger.info(
        "Periodic monitoring cache sync started (interval=%ds, tenant=%s)",
        interval_seconds,
        tenant_id,
    )

    while not _stop.is_set():
        try:
            async with get_session_context() as session:
                added = await populate_cache_from_db(session, tenant_id)
                if added > 0:
                    logger.info(
                        "Periodic cache sync: added %d new entries from DB", added,
                    )
                else:
                    logger.debug("Periodic cache sync: cache up to date")
        except Exception:  # noqa: BLE001
            logger.warning(
                "Periodic monitoring cache sync failed; will retry next cycle",
                exc_info=True,
            )

        try:
            await asyncio.wait_for(_stop.wait(), timeout=interval_seconds)
            break
        except asyncio.TimeoutError:
            pass

    logger.info("Periodic monitoring cache sync stopped")


# ASYNC WRAPPERS WITH DB PERSISTENCE
async def enable_monitoring_async(
    path: Path,
    session,  # AsyncSession
    tenant_id: UUID,
    risk_tier: str = "HIGH",
    **kwargs,
) -> MonitoringResult:
    """Enable monitoring with automatic DB persistence.

    Wraps :func:`enable_monitoring` and, on success, persists the
    monitoring state to the database via :mod:`openlabels.monitoring.db`.
    """
    result = enable_monitoring(path, risk_tier=risk_tier, **kwargs)

    if result.success:
        from openlabels.monitoring import db as monitoring_db

        await monitoring_db.upsert_monitored_file(
            session,
            tenant_id,
            str(Path(path).resolve()),
            risk_tier=risk_tier,
            sacl_enabled=result.sacl_enabled,
            audit_rule_enabled=result.audit_rule_enabled,
        )

    return result


async def disable_monitoring_async(
    path: Path,
    session,  # AsyncSession
    tenant_id: UUID,
) -> MonitoringResult:
    """Disable monitoring with automatic DB removal.

    Wraps :func:`disable_monitoring` and, on success, removes the
    monitoring record from the database.
    """
    result = disable_monitoring(path)

    if result.success:
        from openlabels.monitoring import db as monitoring_db

        await monitoring_db.remove_monitored_file(
            session,
            tenant_id,
            str(Path(path).resolve()),
        )

    return result


# BULK OPERATIONS
def enable_monitoring_batch(
    paths: list[Path],
    risk_tier: str = "HIGH",
) -> list[MonitoringResult]:
    """Enable monitoring on multiple files efficiently.

    On Windows: generates a single PowerShell script for all files.
    On Linux: generates a single auditctl script for all files.
    Falls back to per-file enable_monitoring for individual error handling.
    """
    if not paths:
        return []

    if platform.system() == "Windows":
        return _enable_batch_windows(paths, risk_tier)
    else:
        return _enable_batch_linux(paths, risk_tier)


def _enable_batch_windows(
    paths: list[Path],
    risk_tier: str,
) -> list[MonitoringResult]:
    """Single PowerShell invocation for all files."""
    _INJECTION_CHARS = set('"\'`$\n\r;&|')
    results: list[MonitoringResult] = []
    validated: list[tuple] = []  # (resolved_str, original_path)

    for p in paths:
        resolved = str(Path(p).resolve())
        if any(c in resolved for c in _INJECTION_CHARS):
            results.append(MonitoringResult(
                success=False, path=p, error="Path contains invalid characters",
            ))
        elif not Path(p).exists():
            results.append(MonitoringResult(
                success=False, path=p, error=f"File not found: {p}",
            ))
        else:
            validated.append((resolved, Path(p).resolve()))

    if not validated:
        return results

    path_list = "\n".join(f'    "{v[0]}"' for v in validated)
    ps_script = f'''
$paths = @(
{path_list}
)
foreach ($p in $paths) {{
    try {{
        $acl = Get-Acl -Path $p -Audit
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "Read, Write", "None", "None", "Success, Failure"
        )
        $acl.AddAuditRule($rule)
        Set-Acl -Path $p -AclObject $acl
        Write-Output "OK:$p"
    }} catch {{
        Write-Output "FAIL:$p:$($_.Exception.Message)"
    }}
}}
'''

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=120,
        )
        ok_paths = set()
        for line in proc.stdout.strip().splitlines():
            if line.startswith("OK:"):
                ok_paths.add(line[3:])

        for resolved_str, resolved_path in validated:
            success = resolved_str in ok_paths
            r = MonitoringResult(
                success=success, path=resolved_path,
                sacl_enabled=success,
                error=None if success else "Failed in batch script",
            )
            if success:
                with _watched_lock:
                    if len(_watched_files) < _MAX_WATCHED_FILES or resolved_str in _watched_files:
                        _watched_files[resolved_str] = WatchedFile(
                            path=resolved_path, risk_tier=risk_tier,
                            added_at=datetime.now(), sacl_enabled=True,
                        )
            results.append(r)
    except (subprocess.TimeoutExpired, OSError) as e:
        for _, resolved_path in validated:
            results.append(MonitoringResult(
                success=False, path=resolved_path, error=str(e),
            ))

    return results


def _enable_batch_linux(
    paths: list[Path],
    risk_tier: str,
) -> list[MonitoringResult]:
    """Single auditctl invocation for all files."""
    import shutil

    _INJECTION_CHARS = set('"\'`$\n\r;&|')
    results: list[MonitoringResult] = []
    validated: list[Path] = []

    if not shutil.which("auditctl"):
        return [
            MonitoringResult(success=False, path=p, error="auditctl not found")
            for p in paths
        ]

    for p in paths:
        resolved = Path(p).resolve()
        resolved_str = str(resolved)
        if any(c in resolved_str for c in _INJECTION_CHARS):
            results.append(MonitoringResult(
                success=False, path=resolved, error="Path contains invalid characters",
            ))
        elif not resolved.exists():
            results.append(MonitoringResult(
                success=False, path=resolved, error=f"File not found: {p}",
            ))
        else:
            validated.append(resolved)

    if not validated:
        return results

    # Build a single shell script with one auditctl call per file
    # Paths are validated above to not contain shell metacharacters
    commands = "\n".join(
        f'auditctl -w "{p}" -p rwa -k openlabels && echo "OK:{p}" || echo "FAIL:{p}"'
        for p in validated
    )

    try:
        proc = subprocess.run(
            ["sh", "-c", commands],
            capture_output=True, text=True, timeout=120,
        )
        ok_paths = set()
        for line in proc.stdout.strip().splitlines():
            if line.startswith("OK:"):
                ok_paths.add(line[3:])

        for p in validated:
            success = str(p) in ok_paths
            r = MonitoringResult(
                success=success, path=p,
                audit_rule_enabled=success,
                error=None if success else "Failed in batch script",
            )
            if success:
                with _watched_lock:
                    if len(_watched_files) < _MAX_WATCHED_FILES or str(p) in _watched_files:
                        _watched_files[str(p)] = WatchedFile(
                            path=p, risk_tier=risk_tier,
                            added_at=datetime.now(), audit_rule_enabled=True,
                        )
            results.append(r)
    except (subprocess.TimeoutExpired, OSError) as e:
        for p in validated:
            results.append(MonitoringResult(
                success=False, path=p, error=str(e),
            ))

    return results


# WINDOWS IMPLEMENTATION
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
    except (subprocess.SubprocessError, OSError) as e:
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

    except (subprocess.SubprocessError, OSError) as e:
        return MonitoringResult(
            success=False,
            path=path,
            error=str(e),
        )


# LINUX IMPLEMENTATION
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
    except (subprocess.SubprocessError, OSError) as e:
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

    except (subprocess.SubprocessError, OSError) as e:
        return MonitoringResult(
            success=False,
            path=path,
            error=str(e),
        )

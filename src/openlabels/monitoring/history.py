"""
Access history queries for monitored files.

Queries platform audit logs (Windows Security Event Log, Linux auditd)
to retrieve access history for specific files.

This is on-demand querying, not continuous monitoring - we query the
existing audit logs rather than maintaining our own event stream.
"""

from __future__ import annotations

import logging
import platform
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from .base import (
    AccessAction,
    AccessEvent,
)

logger = logging.getLogger(__name__)


def get_access_history(
    path: Path,
    days: int = 30,
    limit: int = 100,
    include_system: bool = False,
) -> list[AccessEvent]:
    """
    Get access history for a file from platform audit logs.

    On Windows: Queries Security Event Log for events 4663, 4656
    On Linux: Queries auditd logs via ausearch

    Args:
        path: Path to file to query
        days: Number of days of history to retrieve (default: 30)
        limit: Maximum number of events to return (default: 100)
        include_system: Whether to include SYSTEM/root access (default: False)

    Returns:
        List of AccessEvent objects, most recent first
    """
    path = Path(path).resolve()

    if platform.system() == "Windows":
        events = _get_history_windows(path, days, limit)
    else:
        events = _get_history_linux(path, days, limit)

    # Filter out system accounts if requested
    if not include_system:
        events = [
            e for e in events
            if not _is_system_account(e.user_name, e.user_sid)
        ]

    # Sort by timestamp, most recent first
    events.sort(key=lambda e: e.timestamp, reverse=True)

    # Apply limit
    return events[:limit]


def _is_system_account(username: str | None, sid: str | None) -> bool:
    """Check if an account is a system/service account."""
    if not username and not sid:
        return False

    # Windows system accounts
    system_names = {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1",
    }

    if username and username.upper() in system_names:
        return True

    # Windows well-known SIDs
    # S-1-5-18 = Local System
    # S-1-5-19 = Local Service
    # S-1-5-20 = Network Service
    system_sids = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
    if sid and sid in system_sids:
        return True

    # Linux system accounts (UID < 1000 typically)
    if username and username in {"root", "nobody", "daemon", "bin", "sys"}:
        return True

    return False


# WINDOWS IMPLEMENTATION
def _get_history_windows(
    path: Path,
    days: int,
    limit: int,
) -> list[AccessEvent]:
    """
    Query Windows Security Event Log for file access events.

    Uses PowerShell Get-WinEvent to query for events 4663 (object access)
    and 4656 (handle request) that match the file path.
    """
    start_time = datetime.now() - timedelta(days=days)
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")

    # PowerShell script to query events
    # Validate and escape the path for use in the PowerShell filter
    resolved_path = str(path.resolve())
    if any(c in resolved_path for c in ['"', "'", '`', '$', '\n', '\r', ';', '&', '|']):
        logger.warning(f"Path contains invalid characters, refusing to query: {path}")
        return []

    # Escape the filename for use in PowerShell -like pattern.
    # Must escape all wildcard characters: *, ?, [, ]
    escaped_name = (
        path.name
        .replace('`', '``')   # escape backtick first (it's the escape char)
        .replace('[', '`[')
        .replace(']', '`]')
        .replace('*', '`*')
        .replace('?', '`?')
    )

    ps_script = f'''
$events = Get-WinEvent -FilterHashtable @{{
    LogName = 'Security'
    Id = 4663, 4656
    StartTime = '{start_time_str}'
}} -MaxEvents {limit * 2} -ErrorAction SilentlyContinue |
Where-Object {{
    $_.Properties[6].Value -like "*{escaped_name}*"
}} |
Select-Object -First {limit} |
ForEach-Object {{
    $event = $_
    [PSCustomObject]@{{
        TimeCreated = $event.TimeCreated.ToString("o")
        EventId = $event.Id
        UserSid = $event.Properties[0].Value.ToString()
        UserName = $event.Properties[1].Value
        UserDomain = $event.Properties[2].Value
        ObjectName = $event.Properties[6].Value
        AccessMask = $event.Properties[8].Value
        ProcessName = $event.Properties[11].Value
        ProcessId = $event.Properties[12].Value
    }}
}} | ConvertTo-Json -Depth 3
'''

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            logger.warning(f"PowerShell query failed: {result.stderr}")
            return []

        if not result.stdout.strip():
            return []

        # Parse JSON output
        import json

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse PowerShell output: {result.stdout[:200]}")
            return []

        # Handle single result (PowerShell returns object, not array)
        if isinstance(data, dict):
            data = [data]

        events = []
        for item in data:
            # Filter to exact path match
            obj_name = item.get("ObjectName", "")
            if not obj_name or path.name.lower() not in obj_name.lower():
                continue

            # Parse timestamp
            try:
                ts = datetime.fromisoformat(item["TimeCreated"].replace("Z", "+00:00"))
            except (ValueError, KeyError) as e:
                # Skip events with missing/malformed timestamps - common in Windows event logs
                logger.debug(f"Skipping event with invalid timestamp: {type(e).__name__}")
                continue

            # Determine action from access mask
            access_mask = item.get("AccessMask", 0)
            if isinstance(access_mask, str):
                try:
                    access_mask = int(access_mask, 16) if access_mask.startswith("0x") else int(access_mask)
                except ValueError as e:
                    logger.debug(f"Failed to parse access mask '{access_mask}': {e}")
                    access_mask = 0

            action = _parse_windows_access_mask(access_mask)

            events.append(AccessEvent(
                path=Path(obj_name) if obj_name else path,
                timestamp=ts,
                action=action,
                user_sid=item.get("UserSid"),
                user_name=item.get("UserName"),
                user_domain=item.get("UserDomain"),
                process_name=item.get("ProcessName"),
                process_id=item.get("ProcessId"),
                event_id=item.get("EventId"),
            ))

        return events

    except subprocess.TimeoutExpired:
        logger.warning("Event log query timed out")
        return []
    except Exception as e:
        logger.error(f"Error querying Windows event log: {e}")
        return []


def _parse_windows_access_mask(mask: int) -> AccessAction:
    """Convert Windows access mask to AccessAction."""
    # Check for common access types
    if mask & 0x10000:  # DELETE
        return AccessAction.DELETE
    elif mask & 0x40000:  # WRITE_DAC
        return AccessAction.PERMISSION_CHANGE
    elif mask & 0x2 or mask & 0x4:  # WriteData or AppendData
        return AccessAction.WRITE
    elif mask & 0x1:  # ReadData
        return AccessAction.READ
    else:
        return AccessAction.UNKNOWN


# LINUX IMPLEMENTATION
def _get_history_linux(
    path: Path,
    days: int,
    limit: int,
) -> list[AccessEvent]:
    """
    Query Linux audit log for file access events.

    Uses ausearch to query auditd logs for events matching the file path.
    """
    import shutil

    if not shutil.which("ausearch"):
        logger.warning("ausearch not found - is auditd installed?")
        return []

    # Calculate start time
    # ausearch uses relative time like "recent" or absolute timestamps
    start_time = datetime.now() - timedelta(days=days)
    start_str = start_time.strftime("%m/%d/%Y %H:%M:%S")

    try:
        # Query audit log
        # -k: search by key (we use "openlabels" when adding rules)
        # -f: search by file path
        # -ts: start time
        # --format csv: easier to parse
        result = subprocess.run(
            [
                "ausearch",
                "-f", str(path),
                "-ts", start_str,
                "--format", "csv",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            # ausearch returns non-zero if no events found
            if "no matches" in result.stderr.lower():
                return []
            logger.warning(f"ausearch failed: {result.stderr}")
            return []

        if not result.stdout.strip():
            return []

        return _parse_ausearch_csv(result.stdout, path, limit)

    except subprocess.TimeoutExpired:
        logger.warning("Audit log query timed out")
        return []
    except Exception as e:
        logger.error(f"Error querying Linux audit log: {e}")
        return []


def _parse_ausearch_csv(output: str, path: Path, limit: int) -> list[AccessEvent]:
    """Parse ausearch CSV output into AccessEvent objects."""
    events = []
    lines = output.strip().split("\n")

    # Skip header line if present
    if lines and lines[0].startswith("NODE,"):
        lines = lines[1:]

    for line in lines[:limit]:
        try:
            # CSV format varies, but typically:
            # NODE,EVENT_TYPE,EVENT_TIME,AUDIT_ID,UID,AUID,SES,...
            parts = line.split(",")
            if len(parts) < 5:
                continue

            # Parse what we can
            event_time_str = parts[2] if len(parts) > 2 else None
            uid = parts[4] if len(parts) > 4 else None

            # Try to parse timestamp
            ts = datetime.now()  # fallback
            if event_time_str:
                try:
                    ts = datetime.fromisoformat(event_time_str)
                except ValueError as e:
                    logger.debug(f"Failed to parse timestamp '{event_time_str}': {e}")

            # Determine action from event type (parts[1])
            event_type = parts[1] if len(parts) > 1 else ""
            action = _parse_linux_event_type(event_type)

            # Try to resolve username from UID
            username = _resolve_linux_uid(uid) if uid else None

            events.append(AccessEvent(
                path=path,
                timestamp=ts,
                action=action,
                user_sid=uid,
                user_name=username,
            ))

        except Exception as e:
            logger.debug(f"Failed to parse audit line: {e}")
            continue

    return events


def _parse_linux_event_type(event_type: str) -> AccessAction:
    """Convert Linux audit event type to AccessAction."""
    event_type = event_type.upper()

    if "UNLINK" in event_type or "DELETE" in event_type:
        return AccessAction.DELETE
    elif "WRITE" in event_type or "TRUNCATE" in event_type:
        return AccessAction.WRITE
    elif "READ" in event_type or "OPEN" in event_type:
        return AccessAction.READ
    elif "RENAME" in event_type:
        return AccessAction.RENAME
    elif "CHMOD" in event_type or "CHOWN" in event_type:
        return AccessAction.PERMISSION_CHANGE
    else:
        return AccessAction.UNKNOWN


def _resolve_linux_uid(uid: str) -> str | None:
    """Resolve Linux UID to username."""
    try:
        import pwd

        uid_int = int(uid)
        return pwd.getpwuid(uid_int).pw_name
    except ValueError:
        # Invalid UID format - not a number
        logger.debug(f"Cannot resolve non-numeric UID: {uid}")
        return None
    except KeyError:
        # UID not found in passwd database
        logger.debug(f"UID {uid} not found in passwd database")
        return None
    except ImportError:
        # pwd module not available (Windows)
        return None

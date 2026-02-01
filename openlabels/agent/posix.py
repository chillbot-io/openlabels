"""
POSIX Permission Handler.

Handles Linux/macOS file permissions and maps them to OpenLabels exposure levels.

Permission Mapping:
┌────────────────────────────────────────┬─────────────┐
│ POSIX Permission                       │ Exposure    │
├────────────────────────────────────────┼─────────────┤
│ owner-only (700, 600)                  │ PRIVATE     │
│ group-readable (740, 640)              │ INTERNAL    │
│ group-writable (770, 660)              │ INTERNAL    │
│ world-readable (744, 755, 644)         │ ORG_WIDE    │
│ world-writable (777, 666)              │ PUBLIC      │
│ SUID/SGID + world-readable             │ PUBLIC      │
│ sticky bit + world-writable            │ ORG_WIDE    │
└────────────────────────────────────────┴─────────────┘

Extended attributes and ACLs (when available) are also considered.
"""

import os
import stat
import pwd
import grp
import logging
from dataclasses import dataclass
from typing import Optional, List, Tuple
from pathlib import Path

from ..adapters.base import ExposureLevel
from ..adapters.scanner.constants import SUBPROCESS_TIMEOUT
from ..utils.validation import validate_path_for_subprocess

logger = logging.getLogger(__name__)


@dataclass
class PosixPermissions:
    """
    POSIX file permission details.
    """
    mode: int                       # Full mode (e.g., 0o100644)
    owner_uid: int
    owner_name: str
    group_gid: int
    group_name: str

    # Permission bits
    owner_read: bool
    owner_write: bool
    owner_execute: bool
    group_read: bool
    group_write: bool
    group_execute: bool
    world_read: bool
    world_write: bool
    world_execute: bool

    # Special bits
    suid: bool
    sgid: bool
    sticky: bool

    # ACL info (if available)
    has_acl: bool = False
    acl_entries: List[str] = None

    # Calculated exposure
    exposure: ExposureLevel = ExposureLevel.PRIVATE

    def __post_init__(self):
        if self.acl_entries is None:
            self.acl_entries = []

    @property
    def mode_string(self) -> str:
        """Return permission string like 'rwxr-xr-x'."""
        chars = []

        # Owner
        chars.append('r' if self.owner_read else '-')
        chars.append('w' if self.owner_write else '-')
        if self.suid:
            chars.append('s' if self.owner_execute else 'S')
        else:
            chars.append('x' if self.owner_execute else '-')

        # Group
        chars.append('r' if self.group_read else '-')
        chars.append('w' if self.group_write else '-')
        if self.sgid:
            chars.append('s' if self.group_execute else 'S')
        else:
            chars.append('x' if self.group_execute else '-')

        # World
        chars.append('r' if self.world_read else '-')
        chars.append('w' if self.world_write else '-')
        if self.sticky:
            chars.append('t' if self.world_execute else 'T')
        else:
            chars.append('x' if self.world_execute else '-')

        return ''.join(chars)

    @property
    def octal_string(self) -> str:
        """Return octal permission string like '0755'."""
        perms = self.mode & 0o7777
        return f"{perms:04o}"


def get_posix_permissions(path: str) -> PosixPermissions:
    """
    Get POSIX permissions for a file.

    Args:
        path: Path to file

    Returns:
        PosixPermissions with all permission details

    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If can't read file metadata

    Security Note (HIGH-013):
        This function returns a point-in-time snapshot of permissions.
        The returned data may become stale between when it's retrieved and
        when the file is actually accessed (TOCTOU - Time-of-Check to Time-of-Use).

        DO NOT use this for security decisions where the check and use are
        separated in time. For security-critical operations:
        - Use file descriptors and fstat() instead of stat()
        - Open the file first, then check permissions on the open fd
        - Consider using mandatory access control (MAC) systems

        This function is suitable for:
        - Informational/reporting purposes
        - Risk scoring where approximate data is acceptable
        - User interface display
    """
    path = Path(path)

    try:
        st = path.lstat()  # TOCTOU-001: atomic, no symlink follow
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {path}")

    mode = st.st_mode

    # Get owner/group names
    try:
        owner_name = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner_name = str(st.st_uid)

    try:
        group_name = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group_name = str(st.st_gid)

    # Extract permission bits
    perms = PosixPermissions(
        mode=mode,
        owner_uid=st.st_uid,
        owner_name=owner_name,
        group_gid=st.st_gid,
        group_name=group_name,

        # Owner permissions
        owner_read=bool(mode & stat.S_IRUSR),
        owner_write=bool(mode & stat.S_IWUSR),
        owner_execute=bool(mode & stat.S_IXUSR),

        # Group permissions
        group_read=bool(mode & stat.S_IRGRP),
        group_write=bool(mode & stat.S_IWGRP),
        group_execute=bool(mode & stat.S_IXGRP),

        # World permissions
        world_read=bool(mode & stat.S_IROTH),
        world_write=bool(mode & stat.S_IWOTH),
        world_execute=bool(mode & stat.S_IXOTH),

        # Special bits
        suid=bool(mode & stat.S_ISUID),
        sgid=bool(mode & stat.S_ISGID),
        sticky=bool(mode & stat.S_ISVTX),
    )

    # Check for ACLs
    perms.has_acl, perms.acl_entries = _get_acl_entries(str(path))

    # Calculate exposure level
    perms.exposure = posix_mode_to_exposure(perms)

    return perms


def posix_mode_to_exposure(perms: PosixPermissions) -> ExposureLevel:
    """
    Map POSIX permissions to OpenLabels exposure level.

    Follows the most-permissive-wins principle:
    - If world-writable → PUBLIC
    - If world-readable → ORG_WIDE (unless other indicators)
    - If group-readable → INTERNAL
    - Otherwise → PRIVATE

    Args:
        perms: PosixPermissions object

    Returns:
        ExposureLevel
    """
    # Check for PUBLIC indicators
    if perms.world_write:
        return ExposureLevel.PUBLIC

    # SUID/SGID with world-readable is high risk
    if (perms.suid or perms.sgid) and perms.world_read:
        return ExposureLevel.PUBLIC

    # World-readable is ORG_WIDE
    if perms.world_read:
        # Sticky bit with world-writable is still ORG_WIDE (not PUBLIC)
        return ExposureLevel.ORG_WIDE

    # Group permissions
    if perms.group_read or perms.group_write:
        return ExposureLevel.INTERNAL

    # Check ACLs for broader access
    if perms.has_acl and perms.acl_entries:
        for entry in perms.acl_entries:
            entry_lower = entry.lower()
            # Check for "other" or "everyone" ACL entries
            if "other" in entry_lower or "everyone" in entry_lower:
                if "r" in entry_lower:
                    return ExposureLevel.ORG_WIDE
            # Check for group entries
            if "group:" in entry_lower and "r" in entry_lower:
                return ExposureLevel.INTERNAL

    # Default: PRIVATE
    return ExposureLevel.PRIVATE


def _get_acl_entries(path: str) -> Tuple[bool, List[str]]:
    """
    Get ACL entries for a file (if available).

    Uses getfacl command on Linux or file ACL APIs on macOS.

    Returns:
        Tuple of (has_acl, list of ACL entries)
    """
    import subprocess
    import platform

    entries = []
    has_acl = False

    # Validate path before subprocess calls
    if not validate_path_for_subprocess(path):
        logger.debug(f"Invalid path for ACL check: {path!r}")
        return has_acl, entries

    try:
        if platform.system() == "Linux":
            # Use getfacl on Linux
            result = subprocess.run(
                ["getfacl", "-p", path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode == 0:
                # Parse getfacl output
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and ':' in line:
                        entries.append(line)
                        # Check if this is an extended ACL (not just base permissions)
                        if line.startswith(('user:', 'group:', 'mask:', 'default:')):
                            parts = line.split(':')
                            if len(parts) >= 2 and parts[1]:  # Named user/group
                                has_acl = True

        elif platform.system() == "Darwin":
            # Use ls -le on macOS to check for ACLs
            result = subprocess.run(
                ["ls", "-le", path],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            if result.returncode == 0:
                output = result.stdout
                if "+" in output.split()[0]:  # ACL indicator
                    has_acl = True
                    # Get detailed ACL with /bin/chmod
                    acl_result = subprocess.run(
                        ["/bin/chmod", "-vv", "+a", "", path],
                        capture_output=True,
                        text=True,
                        timeout=SUBPROCESS_TIMEOUT,
                    )
                    if "ACL" in (acl_result.stdout + acl_result.stderr):
                        entries = [line for line in acl_result.stderr.splitlines()
                                  if "allow" in line or "deny" in line]

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.debug(f"Could not get ACLs for {path}: {e}")

    return has_acl, entries


def get_owner_info(path: str) -> dict:
    """
    Get owner information for a file.

    Args:
        path: Path to file

    Returns:
        Dict with owner_uid, owner_name, group_gid, group_name
    """
    st = os.stat(path)

    try:
        owner_name = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner_name = str(st.st_uid)

    try:
        group_name = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group_name = str(st.st_gid)

    return {
        "owner_uid": st.st_uid,
        "owner_name": owner_name,
        "group_gid": st.st_gid,
        "group_name": group_name,
    }


def is_world_readable(path: str) -> bool:
    """Check if a file is world-readable."""
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IROTH)
    except OSError:
        return False


def is_world_writable(path: str) -> bool:
    """Check if a file is world-writable."""
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IWOTH)
    except OSError:
        return False


def get_effective_permissions(path: str, uid: Optional[int] = None) -> dict:
    """
    Get effective permissions for a user on a file.

    Args:
        path: Path to file
        uid: User ID to check (default: current user)

    Returns:
        Dict with can_read, can_write, can_execute
    """
    if uid is None:
        uid = os.getuid()

    # Use os.access for effective permission check
    return {
        "can_read": os.access(path, os.R_OK),
        "can_write": os.access(path, os.W_OK),
        "can_execute": os.access(path, os.X_OK),
    }



# --- Convenience Functions ---


def mode_to_exposure(mode: int) -> ExposureLevel:
    """
    Quick conversion from mode int to exposure level.

    Args:
        mode: Permission mode (e.g., 0o644)

    Returns:
        ExposureLevel
    """
    # World-writable
    if mode & stat.S_IWOTH:
        return ExposureLevel.PUBLIC

    # World-readable
    if mode & stat.S_IROTH:
        return ExposureLevel.ORG_WIDE

    # Group-readable
    if mode & stat.S_IRGRP:
        return ExposureLevel.INTERNAL

    return ExposureLevel.PRIVATE


def exposure_to_recommended_mode(
    exposure: ExposureLevel,
    is_directory: bool = False,
    is_executable: bool = False,
) -> int:
    """
    Get recommended permission mode for desired exposure level.

    Args:
        exposure: Desired exposure level
        is_directory: Whether this is a directory
        is_executable: Whether this should be executable

    Returns:
        Recommended mode (e.g., 0o600)
    """
    base_execute = stat.S_IXUSR if is_executable else 0
    dir_execute = stat.S_IXUSR | stat.S_IXGRP if is_directory else 0

    if exposure == ExposureLevel.PRIVATE:
        # Owner only
        if is_directory:
            return stat.S_IRWXU  # 0o700
        return stat.S_IRUSR | stat.S_IWUSR | base_execute  # 0o600 or 0o700

    elif exposure == ExposureLevel.INTERNAL:
        # Owner + group
        if is_directory:
            return stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP  # 0o750
        return stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | base_execute  # 0o640 or 0o750

    elif exposure == ExposureLevel.ORG_WIDE:
        # Owner + group + world-read
        if is_directory:
            return stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH  # 0o755
        return stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH | base_execute  # 0o644 or 0o755

    else:  # PUBLIC - not recommended, but provide something
        if is_directory:
            return stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO  # 0o777
        return stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH  # 0o666

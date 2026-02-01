"""
NTFS Permission Handler.

Handles Windows NTFS ACLs and maps them to OpenLabels exposure levels.

NTFS Permission Mapping:
┌────────────────────────────────────────┬─────────────┐
│ NTFS Permission                        │ Exposure    │
├────────────────────────────────────────┼─────────────┤
│ Owner only                             │ PRIVATE     │
│ Specific user/group ACE                │ PRIVATE     │
│ CREATOR OWNER                          │ PRIVATE     │
│ Domain Admins                          │ INTERNAL    │
│ Domain Users                           │ INTERNAL    │
│ Authenticated Users (domain)           │ INTERNAL    │
│ BUILTIN\\Users                         │ ORG_WIDE    │
│ Everyone (authenticated context)       │ ORG_WIDE    │
│ Anonymous Logon                        │ PUBLIC      │
│ Everyone (+ anonymous enabled)         │ PUBLIC      │
│ NULL SID                               │ PUBLIC      │
│ Network share: Everyone Full Control   │ PUBLIC      │
│ Inherited broad permissions            │ ORG_WIDE    │
└────────────────────────────────────────┴─────────────┘

Note: This module only works fully on Windows. On other platforms,
it provides stub implementations that return PRIVATE exposure.
"""

import logging
import platform
from dataclasses import dataclass, field
from typing import List, Optional

from ..adapters.base import ExposureLevel

logger = logging.getLogger(__name__)

# Check if we're on Windows
_IS_WINDOWS = platform.system() == "Windows"


@dataclass
class NtfsAce:
    """
    A single NTFS Access Control Entry.
    """
    principal: str        # SID or account name
    ace_type: str         # "allow" or "deny"
    permissions: List[str]  # List of permission names
    is_inherited: bool = False
    principal_type: str = "unknown"  # "user", "group", "well_known"


@dataclass
class NtfsPermissions:
    """
    Complete NTFS permission information.
    """
    owner: str
    owner_sid: Optional[str] = None
    group: Optional[str] = None
    group_sid: Optional[str] = None

    # Access Control Entries
    aces: List[NtfsAce] = field(default_factory=list)

    # Calculated exposure
    exposure: ExposureLevel = ExposureLevel.PRIVATE

    # Whether inheritance is enabled
    inheritance_enabled: bool = True

    # Raw security descriptor (for debugging)
    raw_sd: Optional[str] = None


# Well-known SIDs and their exposure mappings
WELL_KNOWN_SIDS = {
    # PRIVATE - specific principals
    "S-1-3-0": ("CREATOR OWNER", ExposureLevel.PRIVATE),
    "S-1-3-1": ("CREATOR GROUP", ExposureLevel.PRIVATE),

    # INTERNAL - domain/authenticated users
    "S-1-5-11": ("Authenticated Users", ExposureLevel.INTERNAL),
    "S-1-5-32-545": ("BUILTIN\\Users", ExposureLevel.ORG_WIDE),  # Local users
    "S-1-5-32-544": ("BUILTIN\\Administrators", ExposureLevel.INTERNAL),
    "S-1-5-18": ("Local System", ExposureLevel.INTERNAL),
    "S-1-5-19": ("Local Service", ExposureLevel.INTERNAL),
    "S-1-5-20": ("Network Service", ExposureLevel.INTERNAL),

    # ORG_WIDE - broad access
    "S-1-1-0": ("Everyone", ExposureLevel.ORG_WIDE),  # Note: depends on settings

    # PUBLIC - anonymous/null
    "S-1-5-7": ("Anonymous Logon", ExposureLevel.PUBLIC),
    "S-1-0-0": ("NULL SID", ExposureLevel.PUBLIC),
}

# Account name patterns that indicate exposure levels
EXPOSURE_PATTERNS = {
    # PRIVATE
    ExposureLevel.PRIVATE: [],

    # INTERNAL
    ExposureLevel.INTERNAL: [
        "domain admins",
        "domain users",
        "enterprise admins",
        "authenticated users",
        "administrators",
    ],

    # ORG_WIDE
    ExposureLevel.ORG_WIDE: [
        "builtin\\users",
        "users",
        "everyone",  # Depends on context
    ],

    # PUBLIC
    ExposureLevel.PUBLIC: [
        "anonymous",
        "anonymous logon",
        "guest",
        "guests",
    ],
}


def get_ntfs_permissions(path: str) -> NtfsPermissions:
    """
    Get NTFS permissions for a file.

    Args:
        path: Path to file

    Returns:
        NtfsPermissions with all ACL information

    Note:
        On non-Windows systems, returns a stub with PRIVATE exposure.

    Security Note (HIGH-013):
        This function returns a point-in-time snapshot of permissions.
        The returned data may become stale between when it's retrieved and
        when the file is actually accessed (TOCTOU - Time-of-Check to Time-of-Use).

        DO NOT use this for security decisions where the check and use are
        separated in time. For security-critical operations:
        - Use file handles and GetSecurityInfo() on the handle
        - Open the file first, then check permissions on the open handle
        - Consider using Windows integrity levels or mandatory labels

        This function is suitable for:
        - Informational/reporting purposes
        - Risk scoring where approximate data is acceptable
        - User interface display
    """
    if not _IS_WINDOWS:
        return _get_stub_permissions(path)

    return _get_windows_permissions(path)


def _get_stub_permissions(path: str) -> NtfsPermissions:
    """Return stub permissions for non-Windows systems."""
    import os
    import pwd

    try:
        st = os.stat(path)
        owner = pwd.getpwuid(st.st_uid).pw_name
    except (OSError, KeyError) as e:
        logger.debug(f"Could not get owner for {path}: {e}")
        owner = "unknown"

    return NtfsPermissions(
        owner=owner,
        exposure=ExposureLevel.PRIVATE,
    )


def _get_windows_permissions(path: str) -> NtfsPermissions:
    """Get actual Windows NTFS permissions."""
    try:
        import win32security
        import ntsecuritycon
    except ImportError:
        logger.warning("pywin32 not installed, using stub permissions")
        return _get_stub_permissions(path)

    try:
        # Get security descriptor
        sd = win32security.GetFileSecurity(
            path,
            win32security.OWNER_SECURITY_INFORMATION |
            win32security.GROUP_SECURITY_INFORMATION |
            win32security.DACL_SECURITY_INFORMATION
        )

        owner_sid = sd.GetSecurityDescriptorOwner()
        try:
            owner_name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            owner = f"{domain}\\{owner_name}" if domain else owner_name
        except Exception as e:
            logger.debug(f"Could not resolve owner SID {owner_sid}: {e}")
            owner = str(owner_sid)

        group_sid = sd.GetSecurityDescriptorGroup()
        group = None
        if group_sid:
            try:
                group_name, domain, _ = win32security.LookupAccountSid(None, group_sid)
                group = f"{domain}\\{group_name}" if domain else group_name
            except Exception as e:
                logger.debug(f"Could not resolve group SID {group_sid}: {e}")
                group = str(group_sid)

        dacl = sd.GetSecurityDescriptorDacl()
        aces = []

        if dacl:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                ace_type = "allow" if ace[0][0] == ntsecuritycon.ACCESS_ALLOWED_ACE_TYPE else "deny"

                principal_sid = ace[2]
                try:
                    principal_name, domain, _ = win32security.LookupAccountSid(None, principal_sid)
                    principal = f"{domain}\\{principal_name}" if domain else principal_name
                except Exception as e:
                    logger.debug(f"Could not resolve principal SID {principal_sid}: {e}")
                    principal = str(principal_sid)

                mask = ace[1]
                permissions = _decode_access_mask(mask)
                is_inherited = bool(ace[0][1] & ntsecuritycon.INHERITED_ACE)

                aces.append(NtfsAce(
                    principal=principal,
                    ace_type=ace_type,
                    permissions=permissions,
                    is_inherited=is_inherited,
                ))

        exposure = _calculate_exposure_from_aces(aces)

        return NtfsPermissions(
            owner=owner,
            owner_sid=str(owner_sid),
            group=group,
            group_sid=str(group_sid) if group_sid else None,
            aces=aces,
            exposure=exposure,
        )

    except Exception as e:
        logger.error(f"Failed to get NTFS permissions: {e}")
        return NtfsPermissions(
            owner="unknown",
            exposure=ExposureLevel.PRIVATE,
        )


def _decode_access_mask(mask: int) -> List[str]:
    """Decode NTFS access mask to permission names."""
    try:
        import ntsecuritycon
    except ImportError:
        return [f"0x{mask:08x}"]

    permissions = []

    permission_map = {
        ntsecuritycon.FILE_READ_DATA: "READ_DATA",
        ntsecuritycon.FILE_WRITE_DATA: "WRITE_DATA",
        ntsecuritycon.FILE_APPEND_DATA: "APPEND_DATA",
        ntsecuritycon.FILE_READ_EA: "READ_EA",
        ntsecuritycon.FILE_WRITE_EA: "WRITE_EA",
        ntsecuritycon.FILE_EXECUTE: "EXECUTE",
        ntsecuritycon.FILE_DELETE_CHILD: "DELETE_CHILD",
        ntsecuritycon.FILE_READ_ATTRIBUTES: "READ_ATTRIBUTES",
        ntsecuritycon.FILE_WRITE_ATTRIBUTES: "WRITE_ATTRIBUTES",
        ntsecuritycon.DELETE: "DELETE",
        ntsecuritycon.READ_CONTROL: "READ_CONTROL",
        ntsecuritycon.WRITE_DAC: "WRITE_DAC",
        ntsecuritycon.WRITE_OWNER: "WRITE_OWNER",
        ntsecuritycon.SYNCHRONIZE: "SYNCHRONIZE",
    }

    for flag, name in permission_map.items():
        if mask & flag:
            permissions.append(name)

    # Check for generic permissions
    if mask & ntsecuritycon.GENERIC_ALL:
        permissions.append("GENERIC_ALL")
    if mask & ntsecuritycon.GENERIC_READ:
        permissions.append("GENERIC_READ")
    if mask & ntsecuritycon.GENERIC_WRITE:
        permissions.append("GENERIC_WRITE")
    if mask & ntsecuritycon.GENERIC_EXECUTE:
        permissions.append("GENERIC_EXECUTE")

    return permissions if permissions else [f"0x{mask:08x}"]


def _calculate_exposure_from_aces(aces: List[NtfsAce]) -> ExposureLevel:
    """
    Calculate exposure level from ACEs.

    Uses most-permissive-wins principle.
    """
    highest_exposure = ExposureLevel.PRIVATE

    for ace in aces:
        if ace.ace_type != "allow":
            continue

        # Check for read permissions
        has_read = any(p in ace.permissions for p in [
            "READ_DATA", "GENERIC_READ", "GENERIC_ALL"
        ])

        if not has_read:
            continue

        principal_lower = ace.principal.lower()

        # Check well-known patterns
        for exposure, patterns in EXPOSURE_PATTERNS.items():
            for pattern in patterns:
                if pattern in principal_lower:
                    if exposure.value > highest_exposure.value:
                        highest_exposure = exposure
                    break

        # Check for "Everyone" specifically
        if "everyone" in principal_lower:
            # Check if anonymous access is enabled (would need registry check)
            # For now, treat Everyone as ORG_WIDE
            if ExposureLevel.ORG_WIDE.value > highest_exposure.value:
                highest_exposure = ExposureLevel.ORG_WIDE

    return highest_exposure


def ntfs_exposure_to_recommended_acl(
    exposure: ExposureLevel,
    owner: str,
) -> List[dict]:
    """
    Get recommended ACL for desired exposure level.

    Args:
        exposure: Desired exposure level
        owner: Owner account name

    Returns:
        List of recommended ACE dictionaries
    """
    aces = [
        {"principal": owner, "type": "allow", "permissions": ["GENERIC_ALL"]},
    ]

    if exposure == ExposureLevel.PRIVATE:
        # Owner only
        pass

    elif exposure == ExposureLevel.INTERNAL:
        # Add Administrators group
        aces.append({
            "principal": "BUILTIN\\Administrators",
            "type": "allow",
            "permissions": ["GENERIC_ALL"],
        })

    elif exposure == ExposureLevel.ORG_WIDE:
        # Add Authenticated Users with read
        aces.extend([
            {
                "principal": "BUILTIN\\Administrators",
                "type": "allow",
                "permissions": ["GENERIC_ALL"],
            },
            {
                "principal": "Authenticated Users",
                "type": "allow",
                "permissions": ["GENERIC_READ"],
            },
        ])

    # Not providing PUBLIC recommendation as it's a security risk

    return aces

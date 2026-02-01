"""
OpenLabels NTFS (Windows) Adapter.

Converts Windows file system permissions (ACLs, ACEs) to normalized exposure levels.

Usage:
    >>> from openlabels.adapters.ntfs import NTFSAdapter
    >>> adapter = NTFSAdapter()
    >>> normalized = adapter.extract(acl_data, file_metadata)

Expected ACL data format:
    {
        "owner": "DOMAIN\\username",
        "aces": [
            {
                "trustee": "DOMAIN\\Users",  # or SID
                "type": "allow",             # allow or deny
                "permissions": ["read", "write", "execute", "full_control", ...],
                "inherited": true
            },
            ...
        ],
        "share_permissions": [  # Optional: SMB share permissions
            {"trustee": "Everyone", "permissions": ["full_control"]}
        ]
    }

Expected file metadata format:
    {
        "path": "\\\\server\\share\\folder\\file.txt",
        "size": 1024,
        "created": "2025-01-15T10:30:00Z",
        "modified": "2025-01-15T10:30:00Z",
        "accessed": "2025-01-15T10:30:00Z",
        "attributes": ["archive", "hidden", ...],
        "owner": "DOMAIN\\username",
        "encryption": "none",  # none, efs, bitlocker
        "zone_identifier": false,  # Mark of the Web
    }
"""

from typing import Dict, Any, List

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, EntityAggregator, calculate_staleness_days, is_archive,
)
from ..core.registry import normalize_type


# Well-known SIDs and their exposure levels
WELL_KNOWN_SIDS: Dict[str, ExposureLevel] = {
    # PUBLIC - Anonymous/unauthenticated access
    "S-1-1-0": ExposureLevel.PUBLIC,        # Everyone (when anonymous enabled)
    "S-1-5-7": ExposureLevel.PUBLIC,        # Anonymous Logon
    "S-1-0-0": ExposureLevel.PUBLIC,        # NULL SID

    # ORG_WIDE - Broad authenticated access
    "S-1-5-11": ExposureLevel.ORG_WIDE,     # Authenticated Users
    "S-1-5-32-545": ExposureLevel.ORG_WIDE, # BUILTIN\Users
    "S-1-5-32-546": ExposureLevel.ORG_WIDE, # BUILTIN\Guests

    # INTERNAL - Domain/org scoped
    "S-1-5-32-544": ExposureLevel.INTERNAL, # BUILTIN\Administrators
    "S-1-5-18": ExposureLevel.INTERNAL,     # Local System
    "S-1-5-19": ExposureLevel.INTERNAL,     # Local Service
    "S-1-5-20": ExposureLevel.INTERNAL,     # Network Service

    # PRIVATE - Owner/creator
    "S-1-3-0": ExposureLevel.PRIVATE,       # Creator Owner
    "S-1-3-1": ExposureLevel.PRIVATE,       # Creator Group
}

# Trustee name patterns and their exposure levels
TRUSTEE_PATTERNS: Dict[str, ExposureLevel] = {
    # PUBLIC
    "anonymous logon": ExposureLevel.PUBLIC,
    "anonymous": ExposureLevel.PUBLIC,
    "null sid": ExposureLevel.PUBLIC,

    # ORG_WIDE
    "everyone": ExposureLevel.ORG_WIDE,     # Everyone in authenticated context
    "authenticated users": ExposureLevel.ORG_WIDE,
    "builtin\\users": ExposureLevel.ORG_WIDE,
    "builtin\\guests": ExposureLevel.ORG_WIDE,
    "users": ExposureLevel.ORG_WIDE,

    # INTERNAL - Domain groups
    "domain users": ExposureLevel.INTERNAL,
    "domain admins": ExposureLevel.INTERNAL,
    "domain computers": ExposureLevel.INTERNAL,
    "enterprise admins": ExposureLevel.INTERNAL,
    "builtin\\administrators": ExposureLevel.INTERNAL,
    "administrators": ExposureLevel.INTERNAL,
    "system": ExposureLevel.INTERNAL,
    "local service": ExposureLevel.INTERNAL,
    "network service": ExposureLevel.INTERNAL,

    # PRIVATE
    "creator owner": ExposureLevel.PRIVATE,
    "creator group": ExposureLevel.PRIVATE,
}


class NTFSAdapter:
    """
    Windows NTFS + SMB share permissions adapter.

    Converts Windows ACLs to normalized entities and file metadata
    to normalized context for risk scoring.

    Uses "most permissive ACE wins" logic - the highest exposure level
    from any ACE determines the final exposure.
    """

    def extract(
        self,
        acl_data: Dict[str, Any],
        file_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert NTFS ACL + file metadata to normalized format.

        Args:
            acl_data: Windows ACL with owner and ACEs
            file_metadata: File system metadata

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(acl_data, file_metadata)
        context = self._normalize_context(acl_data, file_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(
        self,
        acl_data: Dict[str, Any],
        file_metadata: Dict[str, Any],
    ) -> List[Entity]:
        """Extract entities from file content scan results if present."""
        agg = EntityAggregator(source="ntfs")

        scan_results = file_metadata.get("scan_results", {})
        for finding in scan_results.get("findings", []):
            entity_type = normalize_type(finding.get("type", ""), "ntfs")
            agg.add(entity_type, finding.get("count", 1), finding.get("confidence", 0.8))

        return agg.to_entities()

    def _normalize_context(
        self,
        acl_data: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> NormalizedContext:
        """Convert NTFS ACL + metadata to normalized context."""
        # Determine exposure from ACLs (most permissive wins)
        exposure = self._determine_exposure(acl_data)

        # Check for anonymous access indicators
        anonymous_access = self._has_anonymous_access(acl_data)

        # Normalize encryption
        encryption = self._normalize_encryption(meta.get("encryption"))

        # Calculate staleness
        last_modified = meta.get("modified") or meta.get("last_modified")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            exposure=exposure.name,
            cross_account_access=False,  # N/A for NTFS
            anonymous_access=anonymous_access,
            encryption=encryption,
            versioning=meta.get("versioning", False),
            access_logging=meta.get("auditing_enabled", False),
            retention_policy=False,
            last_modified=last_modified,
            last_accessed=meta.get("accessed"),
            staleness_days=staleness,
            has_classification=bool(meta.get("classification")),
            classification_source="ntfs" if meta.get("classification") else "none",
            path=meta.get("path", ""),
            owner=acl_data.get("owner") or meta.get("owner"),
            size_bytes=meta.get("size", 0),
            file_type=meta.get("content_type", ""),
            is_archive=is_archive(meta.get("path", "")),
        )

    def _determine_exposure(self, acl_data: Dict[str, Any]) -> ExposureLevel:
        """
        Determine exposure level from NTFS ACLs.

        Uses "most permissive ACE wins" logic - iterates through all ACEs
        and returns the highest (most permissive) exposure level found.

        See ExposureLevel docstring for full permission mapping.
        """
        max_exposure = ExposureLevel.PRIVATE

        # Check file/folder ACEs
        aces = acl_data.get("aces", [])
        for ace in aces:
            # Only consider Allow ACEs for exposure (Deny ACEs restrict)
            if ace.get("type", "").lower() != "allow":
                continue

            # Skip ACEs with no meaningful permissions
            permissions = ace.get("permissions", [])
            if not self._has_read_permissions(permissions):
                continue

            trustee = ace.get("trustee", "")
            sid = ace.get("sid", "")

            exposure = self._trustee_to_exposure(trustee, sid)
            if exposure.value > max_exposure.value:
                max_exposure = exposure

            # Early exit if PUBLIC found
            if max_exposure == ExposureLevel.PUBLIC:
                return ExposureLevel.PUBLIC

        # Check SMB share permissions (can be more permissive than NTFS)
        share_perms = acl_data.get("share_permissions", [])
        for perm in share_perms:
            trustee = perm.get("trustee", "")
            sid = perm.get("sid", "")

            exposure = self._trustee_to_exposure(trustee, sid)

            # Share with Everyone + Full Control = PUBLIC
            if trustee.lower() == "everyone" and "full_control" in [
                p.lower() for p in perm.get("permissions", [])
            ]:
                return ExposureLevel.PUBLIC

            if exposure.value > max_exposure.value:
                max_exposure = exposure

        return max_exposure

    def _trustee_to_exposure(self, trustee: str, sid: str = "") -> ExposureLevel:
        """Map trustee/SID to exposure level."""
        # Check SID first (more reliable)
        if sid and sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]

        # Check trustee name patterns
        trustee_lower = trustee.lower()

        # Direct match
        if trustee_lower in TRUSTEE_PATTERNS:
            return TRUSTEE_PATTERNS[trustee_lower]

        # Check for domain-qualified names (DOMAIN\name)
        if "\\" in trustee_lower:
            _, name = trustee_lower.rsplit("\\", 1)
            if name in TRUSTEE_PATTERNS:
                return TRUSTEE_PATTERNS[name]

            # Domain Users, Domain Admins patterns
            if "domain users" in trustee_lower:
                return ExposureLevel.INTERNAL
            if "domain admins" in trustee_lower:
                return ExposureLevel.INTERNAL

        # Check partial matches
        for pattern, exposure in TRUSTEE_PATTERNS.items():
            if pattern in trustee_lower:
                return exposure

        # Specific user/group = PRIVATE
        return ExposureLevel.PRIVATE

    def _has_read_permissions(self, permissions: List[str]) -> bool:
        """Check if permission set includes read access."""
        read_perms = {
            "read", "read_data", "read_attributes", "read_ea",
            "list_directory", "traverse", "full_control",
            "modify", "read_and_execute", "generic_read",
        }
        perm_lower = {p.lower() for p in permissions}
        return bool(perm_lower & read_perms)

    def _has_anonymous_access(self, acl_data: Dict[str, Any]) -> bool:
        """Check if anonymous/unauthenticated access is possible."""
        anonymous_trustees = {
            "anonymous logon", "anonymous", "s-1-5-7", "null sid", "s-1-0-0"
        }

        for ace in acl_data.get("aces", []):
            if ace.get("type", "").lower() != "allow":
                continue
            trustee = ace.get("trustee", "").lower()
            sid = ace.get("sid", "").lower()
            if trustee in anonymous_trustees or sid in anonymous_trustees:
                return True

        return False

    def _normalize_encryption(self, encryption: Any) -> str:
        """Normalize encryption type."""
        if not encryption:
            return "none"
        enc_lower = str(encryption).lower()
        if enc_lower in ("efs", "bitlocker", "encrypted"):
            return "platform"
        return "none"

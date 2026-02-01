"""
OpenLabels NFS (Network File System) Adapter.

Converts NFS export configurations and file permissions to normalized exposure levels.

Usage:
    >>> from openlabels.adapters.nfs import NFSAdapter
    >>> adapter = NFSAdapter()
    >>> normalized = adapter.extract(export_config, file_metadata)

Expected export config format:
    {
        "export_path": "/data/shared",
        "clients": [
            {
                "host": "10.0.0.0/24",      # or "*", or "host.domain.com"
                "options": ["rw", "sync", "root_squash", "sec=krb5"]
            },
            ...
        ],
        "global_options": ["fsid=0", "crossmnt"]
    }

Expected file metadata format:
    {
        "path": "/data/shared/file.txt",
        "mode": "0644",                  # or 644, or "-rw-r--r--"
        "uid": 1000,
        "gid": 1000,
        "owner": "username",
        "group": "groupname",
        "size": 1024,
        "mtime": "2025-01-15T10:30:00Z",
        "atime": "2025-01-15T10:30:00Z",
        "ctime": "2025-01-15T10:30:00Z",
        "nfs_version": "4.1",
        "security_flavor": "krb5p",      # sys, krb5, krb5i, krb5p
    }
"""

from typing import Dict, Any, List

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, EntityAggregator, calculate_staleness_days, is_archive,
)
from ..core.registry import normalize_type


# NFS export options and their security implications
INSECURE_OPTIONS = {
    "insecure",         # Allow connections from non-privileged ports
    "no_root_squash",   # Don't map root to anonymous
    "no_all_squash",    # Don't map all users to anonymous (less concerning)
    "no_auth_nlm",      # No auth for NLM (Network Lock Manager)
}

SECURE_OPTIONS = {
    "root_squash",      # Map root to anonymous
    "all_squash",       # Map all users to anonymous
    "sec=krb5",         # Kerberos authentication
    "sec=krb5i",        # Kerberos with integrity
    "sec=krb5p",        # Kerberos with privacy (encryption)
}


class NFSAdapter:
    """
    NFS export configuration adapter.

    Converts NFS exports to normalized exposure levels based on:
    - Client specifications (hosts, subnets, wildcards)
    - Export options (security, squashing, etc.)
    - File permissions (mode bits)

    Uses "most permissive wins" logic - the highest exposure level
    from any client/option determines the final exposure.
    """

    def extract(
        self,
        export_config: Dict[str, Any],
        file_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert NFS export config + file metadata to normalized format.

        Args:
            export_config: NFS export configuration with clients and options
            file_metadata: File system metadata including mode bits

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(file_metadata)
        context = self._normalize_context(export_config, file_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, file_metadata: Dict[str, Any]) -> List[Entity]:
        """Extract entities from file content scan results if present."""
        agg = EntityAggregator(source="nfs")

        scan_results = file_metadata.get("scan_results", {})
        for finding in scan_results.get("findings", []):
            entity_type = normalize_type(finding.get("type", ""), "nfs")
            agg.add(entity_type, finding.get("count", 1), finding.get("confidence", 0.8))

        return agg.to_entities()

    def _normalize_context(
        self,
        export_config: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> NormalizedContext:
        """Convert NFS export + file metadata to normalized context."""
        # Determine exposure (most permissive wins)
        exposure = self._determine_exposure(export_config, meta)

        # Check for anonymous access
        anonymous_access = self._has_anonymous_access(export_config, meta)

        # Calculate staleness
        last_modified = meta.get("mtime") or meta.get("modified")
        staleness = calculate_staleness_days(last_modified)

        # Determine encryption from security flavor
        encryption = self._get_encryption(export_config, meta)

        return NormalizedContext(
            exposure=exposure.name,
            cross_account_access=False,
            anonymous_access=anonymous_access,
            encryption=encryption,
            versioning=False,  # NFS doesn't have built-in versioning
            access_logging=meta.get("audit_enabled", False),
            retention_policy=False,
            last_modified=last_modified,
            last_accessed=meta.get("atime"),
            staleness_days=staleness,
            has_classification=False,
            classification_source="none",
            path=meta.get("path", export_config.get("export_path", "")),
            owner=meta.get("owner"),
            size_bytes=meta.get("size", 0),
            file_type=meta.get("content_type", ""),
            is_archive=is_archive(meta.get("path", "")),
        )

    def _determine_exposure(
        self,
        export_config: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> ExposureLevel:
        """
        Determine exposure level from NFS export configuration.

        Uses "most permissive wins" logic:
        1. Check each client specification for exposure level
        2. Check export options for insecure settings
        3. Consider file mode bits for world-readable
        4. Return the highest (most permissive) exposure found

        See ExposureLevel docstring for full permission mapping.
        """
        max_exposure = ExposureLevel.PRIVATE

        clients = export_config.get("clients", [])

        for client in clients:
            host = client.get("host", "")
            options = [o.lower() for o in client.get("options", [])]

            # Determine base exposure from host specification
            host_exposure = self._host_to_exposure(host)

            # Apply option modifiers (can elevate OR reduce exposure)
            # Kerberos can reduce exposure; insecure options can elevate it
            client_exposure = self._options_to_exposure(options, host_exposure)

            if client_exposure.value > max_exposure.value:
                max_exposure = client_exposure

            # Early exit if PUBLIC
            if max_exposure == ExposureLevel.PUBLIC:
                return ExposureLevel.PUBLIC

        # Check file mode bits for world-readable combined with broad export
        mode = meta.get("mode", "")
        if self._is_world_readable(mode) and max_exposure.value >= ExposureLevel.ORG_WIDE.value:
            # World-readable + broad export = elevate risk
            if self._has_wildcard_export(export_config):
                return ExposureLevel.PUBLIC

        return max_exposure

    def _host_to_exposure(self, host: str) -> ExposureLevel:
        """Map NFS client host specification to exposure level."""
        host = host.strip()

        # PUBLIC: Wildcard exports
        if host == "*" or host == "":
            return ExposureLevel.PUBLIC

        # Check for CIDR notation
        if "/" in host:
            return self._cidr_to_exposure(host)

        # Check for wildcard patterns
        if "*" in host or "?" in host:
            # *.domain.com is INTERNAL (domain-scoped)
            if host.startswith("*."):
                return ExposureLevel.INTERNAL
            # Other wildcards are ORG_WIDE
            return ExposureLevel.ORG_WIDE

        # Single host = PRIVATE
        return ExposureLevel.PRIVATE

    def _cidr_to_exposure(self, cidr: str) -> ExposureLevel:
        """Map CIDR notation to exposure level based on subnet size."""
        try:
            _, prefix = cidr.rsplit("/", 1)
            prefix_len = int(prefix)

            # /32 = single host = PRIVATE
            if prefix_len >= 32:
                return ExposureLevel.PRIVATE

            # /24 or smaller (more hosts) = INTERNAL
            if prefix_len >= 24:
                return ExposureLevel.INTERNAL

            # /16 or smaller = ORG_WIDE (large subnet)
            if prefix_len >= 16:
                return ExposureLevel.ORG_WIDE

            # /8 or broader = PUBLIC (huge range)
            return ExposureLevel.PUBLIC

        except (ValueError, IndexError):
            # Can't parse, assume INTERNAL
            return ExposureLevel.INTERNAL

    def _options_to_exposure(
        self,
        options: List[str],
        base_exposure: ExposureLevel,
    ) -> ExposureLevel:
        """Evaluate export options for security implications."""
        exposure = base_exposure

        # Check for security-elevating options
        has_insecure = "insecure" in options
        has_no_root_squash = "no_root_squash" in options
        has_no_auth_nlm = "no_auth_nlm" in options

        security_flavor = self._get_security_flavor(options)

        # Kerberos authentication provides strong security
        # Can reduce exposure from ORG_WIDE to INTERNAL
        if security_flavor in ("krb5", "krb5i", "krb5p"):
            if exposure == ExposureLevel.ORG_WIDE:
                exposure = ExposureLevel.INTERNAL
            # krb5p provides encryption
            return exposure

        # sec=sys (AUTH_SYS) trusts client UIDs - only risky for broad exports
        # For single hosts or small subnets, it's acceptable
        # Only elevate to ORG_WIDE if already at INTERNAL with broad host spec
        # (this is handled by host_to_exposure returning higher for large subnets)

        # Insecure options elevate risk significantly
        if has_insecure or has_no_auth_nlm:
            if base_exposure.value >= ExposureLevel.ORG_WIDE.value:
                return ExposureLevel.PUBLIC
            if exposure.value < ExposureLevel.ORG_WIDE.value:
                exposure = ExposureLevel.ORG_WIDE

        # no_root_squash allows remote root = elevated risk
        if has_no_root_squash:
            if exposure.value < ExposureLevel.ORG_WIDE.value:
                exposure = ExposureLevel.ORG_WIDE

        return exposure

    def _get_security_flavor(self, options: List[str]) -> str:
        """Extract security flavor from options."""
        for opt in options:
            if opt.startswith("sec="):
                return opt.split("=", 1)[1].lower()
        # Default is sys (AUTH_SYS)
        return "sys"

    def _is_world_readable(self, mode: Any) -> bool:
        """Check if file mode indicates world-readable."""
        if not mode:
            return False

        mode_str = str(mode)

        # Handle symbolic mode (-rw-r--r--)
        if mode_str.startswith("-") or mode_str.startswith("d"):
            # Check "other" read permission (position 7)
            return len(mode_str) >= 8 and mode_str[7] == "r"

        # Handle octal mode (644, 0644, 755)
        try:
            mode_int = int(mode_str, 8) if mode_str.startswith("0") else int(mode_str)
            # Check if "other" has read permission (o+r = 4)
            return (mode_int & 0o004) != 0
        except ValueError:
            return False

    def _has_wildcard_export(self, export_config: Dict[str, Any]) -> bool:
        """Check if any client uses wildcard export."""
        for client in export_config.get("clients", []):
            host = client.get("host", "")
            if host == "*" or host == "":
                return True
        return False

    def _has_anonymous_access(
        self,
        export_config: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> bool:
        """Check if anonymous/unauthenticated access is possible."""
        for client in export_config.get("clients", []):
            options = [o.lower() for o in client.get("options", [])]

            # all_squash maps everyone to anonymous
            if "all_squash" in options:
                return True

            # Wildcard export with sec=sys
            host = client.get("host", "")
            if host == "*" and self._get_security_flavor(options) == "sys":
                return True

        return False

    def _get_encryption(
        self,
        export_config: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> str:
        """Determine encryption from security flavor."""
        # Check file-level encryption hint
        if meta.get("encrypted"):
            return "platform"

        # Check for krb5p (Kerberos with privacy = encryption)
        for client in export_config.get("clients", []):
            options = [o.lower() for o in client.get("options", [])]
            if "sec=krb5p" in options:
                return "platform"

        # Also check metadata security flavor
        if meta.get("security_flavor", "").lower() == "krb5p":
            return "platform"

        return "none"

"""
OpenLabels M365 (SharePoint/OneDrive/Teams) Adapter.

Converts Microsoft 365 sharing and permission settings to normalized exposure levels.

Usage:
    >>> from openlabels.adapters.m365 import M365Adapter
    >>> adapter = M365Adapter()
    >>> normalized = adapter.extract(permissions_data, item_metadata)

Expected permissions data format:
    {
        "direct_permissions": [
            {
                "grantedTo": {"user": {"email": "user@company.com"}},
                "roles": ["read", "write"],
            },
            {
                "grantedTo": {"group": {"displayName": "Marketing Team"}},
                "roles": ["read"],
            },
        ],
        "sharing_links": [
            {
                "type": "view",                    # view, edit
                "scope": "organization",           # anonymous, organization, users
                "hasPassword": false,
                "expirationDateTime": "2025-12-31T00:00:00Z",
                "preventsDownload": false,
            },
        ],
        "inherited_from": "/sites/marketing",     # null if not inherited
        "site_sharing_capability": "ExternalUserAndGuestSharing",
        "sensitivity_label": "Confidential",
    }

Expected item metadata format:
    {
        "id": "01ABC123...",
        "name": "document.docx",
        "path": "/drives/b!abc.../root:/folder/document.docx",
        "webUrl": "https://company.sharepoint.com/sites/...",
        "size": 102400,
        "createdDateTime": "2025-01-01T10:00:00Z",
        "lastModifiedDateTime": "2025-01-15T10:30:00Z",
        "createdBy": {"user": {"email": "creator@company.com"}},
        "lastModifiedBy": {"user": {"email": "editor@company.com"}},
        "parentReference": {"driveType": "documentLibrary"},
        "file": {"mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        "sensitivity_label": "Confidential",
        "retention_label": "3-year-hold",
        "dlp_policy_tips": [...],
    }
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, EntityAggregator, calculate_staleness_days, is_archive,
)
from ..core.registry import normalize_type


# Sharing link scopes and their exposure levels
LINK_SCOPE_EXPOSURE: Dict[str, ExposureLevel] = {
    "anonymous": ExposureLevel.PUBLIC,
    "anyone": ExposureLevel.PUBLIC,

    "organization": ExposureLevel.ORG_WIDE,
    "company": ExposureLevel.ORG_WIDE,

    "existingaccess": ExposureLevel.PRIVATE,
    "users": ExposureLevel.PRIVATE,
    "specificpeople": ExposureLevel.PRIVATE,
}

# Site sharing capability levels
SHARING_CAPABILITY_EXPOSURE: Dict[str, ExposureLevel] = {
    "disabled": ExposureLevel.PRIVATE,
    "existingexternalusersharing": ExposureLevel.ORG_WIDE,
    "externalusersharing": ExposureLevel.ORG_WIDE,
    "externaluserandguestsharing": ExposureLevel.ORG_WIDE,
}


class M365Adapter:
    """
    Microsoft 365 (SharePoint/OneDrive/Teams) adapter.

    Converts M365 sharing permissions and item metadata to normalized
    exposure levels for risk scoring.

    Uses "most permissive wins" logic - the highest exposure level
    from any permission or sharing link determines the final exposure.
    """

    def extract(
        self,
        permissions_data: Dict[str, Any],
        item_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert M365 permissions + item metadata to normalized format.

        Args:
            permissions_data: Sharing permissions, links, and site settings
            item_metadata: SharePoint/OneDrive item metadata

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(permissions_data, item_metadata)
        context = self._normalize_context(permissions_data, item_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(
        self,
        permissions_data: Dict[str, Any],
        item_metadata: Dict[str, Any],
    ) -> List[Entity]:
        """Extract entities from DLP scan results if present."""
        agg = EntityAggregator(source="m365")

        # From DLP policy tips
        for tip in item_metadata.get("dlp_policy_tips", []):
            entity_type = normalize_type(tip.get("type", ""), "m365")
            agg.add(entity_type, tip.get("count", 1), tip.get("confidence", 0.85))

        # From scan results
        scan_results = item_metadata.get("scan_results", {})
        for finding in scan_results.get("findings", []):
            entity_type = normalize_type(finding.get("type", ""), "m365")
            agg.add(entity_type, finding.get("count", 1), finding.get("confidence", 0.8))

        return agg.to_entities()

    def _normalize_context(
        self,
        permissions_data: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> NormalizedContext:
        """Convert M365 permissions + metadata to normalized context."""
        # Determine exposure (most permissive wins)
        exposure = self._determine_exposure(permissions_data)

        # Check for anonymous access
        anonymous_access = self._has_anonymous_access(permissions_data)

        # Check for cross-tenant sharing
        cross_tenant = self._has_external_sharing(permissions_data)

        # Calculate staleness
        last_modified = meta.get("lastModifiedDateTime") or meta.get("modified")
        staleness = calculate_staleness_days(last_modified)

        # Determine path
        path = meta.get("webUrl") or meta.get("path") or ""

        # Check for sensitivity label (indicates classification)
        sensitivity_label = (
            meta.get("sensitivity_label") or
            permissions_data.get("sensitivity_label")
        )

        # Check retention policy
        has_retention = bool(meta.get("retention_label"))

        return NormalizedContext(
            exposure=exposure.name,
            cross_account_access=cross_tenant,
            anonymous_access=anonymous_access,
            encryption="platform",  # M365 always encrypts at rest
            versioning=True,        # SharePoint/OneDrive has versioning
            access_logging=True,    # M365 has audit logging
            retention_policy=has_retention,
            last_modified=last_modified,
            last_accessed=meta.get("lastAccessedDateTime"),
            staleness_days=staleness,
            has_classification=bool(sensitivity_label),
            classification_source="m365" if sensitivity_label else "none",
            path=path,
            owner=self._get_owner(meta),
            size_bytes=meta.get("size", 0),
            file_type=self._get_mime_type(meta),
            is_archive=is_archive(meta.get("name", "")),
        )

    def _determine_exposure(self, permissions_data: Dict[str, Any]) -> ExposureLevel:
        """
        Determine exposure level from M365 permissions.

        Uses "most permissive wins" logic:
        1. Check all sharing links for scope
        2. Check direct permissions for broad access
        3. Consider site-level sharing capability
        4. Return the highest (most permissive) exposure found

        See ExposureLevel docstring for full permission mapping.
        """
        max_exposure = ExposureLevel.PRIVATE

        # Check sharing links (often most permissive)
        sharing_links = permissions_data.get("sharing_links", [])
        for link in sharing_links:
            link_exposure = self._link_to_exposure(link)
            if link_exposure.value > max_exposure.value:
                max_exposure = link_exposure

            if max_exposure == ExposureLevel.PUBLIC:
                return ExposureLevel.PUBLIC

        # Check direct permissions
        direct_perms = permissions_data.get("direct_permissions", [])
        for perm in direct_perms:
            perm_exposure = self._permission_to_exposure(perm)
            if perm_exposure.value > max_exposure.value:
                max_exposure = perm_exposure

        # Check site sharing capability (sets upper bound on what's possible)
        site_capability = permissions_data.get("site_sharing_capability", "").lower()
        if site_capability in SHARING_CAPABILITY_EXPOSURE:
            # Site capability doesn't directly set exposure, but external sharing
            # capability combined with actual sharing links increases risk
            if "external" in site_capability and max_exposure.value >= ExposureLevel.INTERNAL.value:
                if max_exposure.value < ExposureLevel.ORG_WIDE.value:
                    max_exposure = ExposureLevel.ORG_WIDE

        return max_exposure

    def _link_to_exposure(self, link: Dict[str, Any]) -> ExposureLevel:
        """Map sharing link to exposure level."""
        scope = link.get("scope", "").lower()

        # Get base exposure from scope
        exposure = LINK_SCOPE_EXPOSURE.get(scope, ExposureLevel.PRIVATE)

        # Anonymous links without password or with no expiry are more risky
        if scope in ("anonymous", "anyone"):
            has_password = link.get("hasPassword", False)
            expiration = link.get("expirationDateTime")

            # No password and no expiry = definitely PUBLIC
            if not has_password and not expiration:
                return ExposureLevel.PUBLIC

            # Has password but no expiry = still PUBLIC but slightly better
            # Has expiry = still PUBLIC until expired
            return ExposureLevel.PUBLIC

        # Organization link that requires sign-in
        if scope in ("organization", "company"):
            # Check if it requires sign-in
            requires_signin = link.get("requiresSignIn", True)
            if not requires_signin:
                return ExposureLevel.PUBLIC
            return ExposureLevel.ORG_WIDE

        return exposure

    def _permission_to_exposure(self, perm: Dict[str, Any]) -> ExposureLevel:
        """Map direct permission to exposure level."""
        granted_to = perm.get("grantedTo", {}) or perm.get("grantedToV2", {})

        # Check for special principals
        if "siteCollection" in granted_to:
            return ExposureLevel.INTERNAL

        if "group" in granted_to:
            group = granted_to["group"]
            group_name = group.get("displayName", "").lower()

            # Check for broad groups (Everyone, Everyone except external users)
            if "everyone" in group_name:
                return ExposureLevel.ORG_WIDE

            # M365 Group / Team = INTERNAL
            if group.get("groupTypes") or "team" in group_name:
                return ExposureLevel.INTERNAL

            # Security group = INTERNAL (scoped)
            return ExposureLevel.INTERNAL

        if "user" in granted_to:
            user = granted_to["user"]
            email = user.get("email", "").lower()

            # External user (guest)
            if "#ext#" in email or user.get("userType") == "Guest":
                return ExposureLevel.ORG_WIDE

            # Specific internal user = PRIVATE
            return ExposureLevel.PRIVATE

        # Application permission
        if "application" in granted_to:
            return ExposureLevel.INTERNAL

        return ExposureLevel.PRIVATE

    def _has_anonymous_access(self, permissions_data: Dict[str, Any]) -> bool:
        """Check if anonymous/unauthenticated access is possible."""
        for link in permissions_data.get("sharing_links", []):
            scope = link.get("scope", "").lower()
            if scope in ("anonymous", "anyone"):
                # Check if link requires sign-in
                if not link.get("requiresSignIn", False):
                    return True

        return False

    def _has_external_sharing(self, permissions_data: Dict[str, Any]) -> bool:
        """Check if content is shared with external users."""
        # Check direct permissions for guests
        for perm in permissions_data.get("direct_permissions", []):
            granted_to = perm.get("grantedTo", {}) or perm.get("grantedToV2", {})
            if "user" in granted_to:
                user = granted_to["user"]
                email = user.get("email", "").lower()
                if "#ext#" in email or user.get("userType") == "Guest":
                    return True

        # Check for organization links (could include guests)
        site_capability = permissions_data.get("site_sharing_capability", "").lower()
        if "external" in site_capability or "guest" in site_capability:
            # Site allows external sharing
            for link in permissions_data.get("sharing_links", []):
                if link.get("scope", "").lower() in ("organization", "company"):
                    return True

        return False

    def _get_owner(self, meta: Dict[str, Any]) -> Optional[str]:
        """Extract owner from metadata."""
        created_by = meta.get("createdBy", {})
        if "user" in created_by:
            return created_by["user"].get("email") or created_by["user"].get("displayName")
        return meta.get("owner")

    def _get_mime_type(self, meta: Dict[str, Any]) -> str:
        """Extract MIME type from metadata."""
        file_info = meta.get("file", {})
        return file_info.get("mimeType", meta.get("contentType", ""))

"""
GCP DLP + GCS metadata adapter.

Converts GCP DLP inspection results and GCS object metadata to OpenLabels normalized format.

Usage:
    >>> from openlabels.adapters.dlp import DLPAdapter
    >>> adapter = DLPAdapter()
    >>> normalized = adapter.extract(dlp_findings, gcs_metadata)
    >>> result = score(normalized.entities, normalized.context.exposure)
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, EntityAggregator, calculate_staleness_days, is_archive,
)
from ..core.registry import normalize_type


class DLPAdapter:
    """
    GCP DLP + GCS metadata adapter.

    Converts DLP inspection results to normalized entities and GCS bucket/object
    metadata to normalized context for risk scoring.
    """

    def extract(
        self,
        findings: Dict[str, Any],
        gcs_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert DLP findings + GCS metadata to normalized format.

        Args:
            findings: DLP inspection results JSON
                Expected structure:
                {
                    "result": {
                        "findings": [
                            {
                                "infoType": {"name": "US_SOCIAL_SECURITY_NUMBER"},
                                "likelihood": "VERY_LIKELY",
                                "location": {...},
                                "quote": "..."
                            }
                        ]
                    }
                }
            gcs_metadata: GCS object/bucket metadata
                Expected structure:
                {
                    "bucket": "my-bucket",
                    "name": "path/to/file.csv",
                    "size": 1024,
                    "updated": "2024-01-15T10:30:00Z",
                    "contentType": "text/csv",
                    "iam_policy": {
                        "bindings": [
                            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                        ]
                    },
                    "encryption": {"defaultKmsKeyName": "..."},
                    "versioning": {"enabled": true},
                    "logging": {"logBucket": "..."},
                    "retentionPolicy": {...}
                }

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(findings)
        context = self._normalize_gcs_context(gcs_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, findings: Dict[str, Any]) -> List[Entity]:
        """Extract entities from DLP findings."""
        agg = EntityAggregator(source="dlp")

        # Handle both direct findings array and nested result.findings
        findings_list = findings.get("findings", [])
        if not findings_list and "result" in findings:
            findings_list = findings.get("result", {}).get("findings", [])

        for finding in findings_list:
            info_type = finding.get("infoType", {})
            dlp_type = info_type.get("name", "UNKNOWN")
            entity_type = normalize_type(dlp_type, source="dlp")
            confidence = self._likelihood_to_confidence(finding.get("likelihood", "POSSIBLE"))
            agg.add(entity_type, count=1, confidence=confidence)

        return agg.to_entities()

    def _likelihood_to_confidence(self, likelihood: str) -> float:
        """Map DLP likelihood to confidence score."""
        return {
            "VERY_LIKELY": 0.95,
            "LIKELY": 0.85,
            "POSSIBLE": 0.70,
            "UNLIKELY": 0.50,
            "VERY_UNLIKELY": 0.30,
            "LIKELIHOOD_UNSPECIFIED": 0.60,
        }.get(likelihood, 0.70)

    def _normalize_gcs_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert GCS metadata to normalized context."""
        exposure = self._determine_exposure(meta)
        encryption = self._normalize_encryption(meta.get("encryption"))
        last_modified = meta.get("updated") or meta.get("timeCreated")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            # Exposure
            exposure=exposure.name,
            cross_account_access=self._has_cross_project_access(meta),
            anonymous_access=(exposure == ExposureLevel.PUBLIC),

            # Protection
            encryption=encryption,
            versioning=meta.get("versioning", {}).get("enabled", False),
            access_logging=meta.get("logging", {}).get("logBucket") is not None,
            retention_policy=meta.get("retentionPolicy") is not None,

            # Staleness
            last_modified=last_modified,
            last_accessed=None,  # GCS doesn't track this
            staleness_days=staleness,

            # Classification
            has_classification=True,
            classification_source="dlp",

            # File info
            path=f"gs://{meta.get('bucket', '')}/{meta.get('name', '')}",
            owner=meta.get("owner", {}).get("entity") if isinstance(meta.get("owner"), dict) else meta.get("owner"),
            size_bytes=int(meta.get("size", 0)),
            file_type=meta.get("contentType", ""),
            is_archive=is_archive(meta.get("name", "")),
        )

    def _determine_exposure(self, meta: Dict[str, Any]) -> ExposureLevel:
        """
        Determine exposure from GCS IAM policy and ACLs.

        See ExposureLevel docstring for full permission mapping.
        """
        # Check for public access prevention (strongest protection)
        if meta.get("iamConfiguration", {}).get("publicAccessPrevention") == "enforced":
            # Even with prevention, check for cross-project access
            if self._has_cross_project_access(meta):
                return ExposureLevel.ORG_WIDE
            return ExposureLevel.PRIVATE

        # Track the highest exposure level found
        max_exposure = ExposureLevel.PRIVATE

        # Check IAM policy bindings
        iam_policy = meta.get("iam_policy", {})
        bindings = iam_policy.get("bindings", [])

        for binding in bindings:
            members = binding.get("members", [])
            for member in members:
                exposure = self._member_to_exposure(member)
                if exposure.value > max_exposure.value:
                    max_exposure = exposure
                # Early exit if PUBLIC found
                if max_exposure == ExposureLevel.PUBLIC:
                    return ExposureLevel.PUBLIC

        # Check legacy ACL if present
        acl = meta.get("acl", [])
        for entry in acl:
            entity = entry.get("entity", "")
            exposure = self._acl_entity_to_exposure(entity)
            if exposure.value > max_exposure.value:
                max_exposure = exposure
            if max_exposure == ExposureLevel.PUBLIC:
                return ExposureLevel.PUBLIC

        # Check for cross-project access (elevates to at least ORG_WIDE)
        if self._has_cross_project_access(meta) and max_exposure.value < ExposureLevel.ORG_WIDE.value:
            max_exposure = ExposureLevel.ORG_WIDE

        return max_exposure

    def _member_to_exposure(self, member: str) -> ExposureLevel:
        """Map IAM member string to exposure level."""
        # PUBLIC: allUsers
        if member == "allUsers":
            return ExposureLevel.PUBLIC

        # ORG_WIDE: allAuthenticatedUsers
        if member == "allAuthenticatedUsers":
            return ExposureLevel.ORG_WIDE

        # INTERNAL: domain-wide or project-wide access
        if member.startswith("domain:"):
            return ExposureLevel.INTERNAL
        if member.startswith("projectViewer:") or \
           member.startswith("projectEditor:") or \
           member.startswith("projectOwner:"):
            return ExposureLevel.INTERNAL

        # INTERNAL: group access (could be broad)
        if member.startswith("group:"):
            return ExposureLevel.INTERNAL

        # PRIVATE: specific user or service account
        return ExposureLevel.PRIVATE

    def _acl_entity_to_exposure(self, entity: str) -> ExposureLevel:
        """Map ACL entity string to exposure level."""
        if entity == "allUsers":
            return ExposureLevel.PUBLIC
        if entity == "allAuthenticatedUsers":
            return ExposureLevel.ORG_WIDE
        if entity.startswith("project-"):
            return ExposureLevel.INTERNAL
        # user-*, group-* are considered private (specific principals)
        return ExposureLevel.PRIVATE

    def _has_cross_project_access(self, meta: Dict[str, Any]) -> bool:
        """Check if IAM policy grants cross-project access."""
        iam_policy = meta.get("iam_policy", {})
        bindings = iam_policy.get("bindings", [])
        bucket_project = meta.get("projectNumber", "")

        for binding in bindings:
            for member in binding.get("members", []):
                # Check for service accounts from other projects
                if "serviceAccount:" in member and bucket_project:
                    # Extract project from service account
                    if f"@{bucket_project}" not in member:
                        return True
        return False

    def _normalize_encryption(self, encryption: Optional[Dict]) -> str:
        """Normalize GCS encryption."""
        if not encryption:
            return "platform"  # GCS has default encryption
        if encryption.get("defaultKmsKeyName"):
            return "customer_managed"
        return "platform"

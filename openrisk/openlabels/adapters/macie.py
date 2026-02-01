"""
AWS Macie + S3 metadata adapter.

Converts Macie findings and S3 object metadata to OpenLabels normalized format.

Usage:
    >>> from openlabels.adapters.macie import MacieAdapter
    >>> adapter = MacieAdapter()
    >>> normalized = adapter.extract(macie_findings, s3_metadata)
    >>> # Feed to scorer
    >>> result = score(normalized.entities, normalized.context.exposure)
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, EntityAggregator, calculate_staleness_days, is_archive,
)
from ..core.registry import normalize_type


class MacieAdapter:
    """
    AWS Macie + S3 metadata adapter.

    Converts Macie findings to normalized entities and S3 bucket/object
    metadata to normalized context for risk scoring.
    """

    def extract(
        self,
        findings: Dict[str, Any],
        s3_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert Macie findings + S3 metadata to normalized format.

        Args:
            findings: Macie findings JSON (from GetFindings API or S3 event)
                Expected structure:
                {
                    "findings": [
                        {
                            "type": "SensitiveData:S3Object/Personal",
                            "severity": {"score": 3},
                            "classificationDetails": {
                                "result": {
                                    "sensitiveData": [
                                        {
                                            "category": "PERSONAL_INFORMATION",
                                            "detections": [
                                                {"type": "USA_SOCIAL_SECURITY_NUMBER", "count": 5}
                                            ]
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            s3_metadata: S3 object/bucket metadata
                Expected structure:
                {
                    "bucket": "my-bucket",
                    "key": "path/to/file.csv",
                    "size": 1024,
                    "last_modified": "2024-01-15T10:30:00Z",
                    "content_type": "text/csv",
                    "acl": "private",
                    "public_access_block": True,
                    "encryption": "AES256" | "aws:kms" | None,
                    "versioning": "Enabled" | "Suspended" | None,
                    "logging_enabled": True | False,
                    "cross_account": False,
                    "owner": "123456789012"
                }

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(findings)
        context = self._normalize_s3_context(s3_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, findings: Dict[str, Any]) -> List[Entity]:
        """Extract entities from Macie findings."""
        agg = EntityAggregator(source="macie")

        for finding in findings.get("findings", []):
            severity = finding.get("severity", {})
            severity_score = severity.get("score", 2) if isinstance(severity, dict) else 2
            confidence = self._severity_to_confidence(severity_score)

            class_details = finding.get("classificationDetails", {})
            result = class_details.get("result", {})

            for category_data in result.get("sensitiveData", []):
                for detection in category_data.get("detections", []):
                    entity_type = normalize_type(detection.get("type", "UNKNOWN"), source="macie")
                    agg.add(entity_type, detection.get("count", 1), confidence)

        return agg.to_entities()

    def _severity_to_confidence(self, severity_score: int) -> float:
        """
        Map Macie severity score to confidence.

        Macie severity scores: 1 (Low) to 4 (High)
        """
        return {
            1: 0.65,  # Low
            2: 0.75,  # Medium
            3: 0.85,  # High
            4: 0.95,  # Critical
        }.get(severity_score, 0.75)

    def _normalize_s3_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert S3 metadata to normalized context."""
        # Determine exposure level
        exposure = self._determine_exposure(meta)

        # Normalize encryption
        encryption = self._normalize_encryption(meta.get("encryption"))

        # Calculate staleness
        last_modified = meta.get("last_modified")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            # Exposure
            exposure=exposure.name,
            cross_account_access=meta.get("cross_account", False),
            anonymous_access=(exposure == ExposureLevel.PUBLIC),

            # Protection
            encryption=encryption,
            versioning=(meta.get("versioning") == "Enabled"),
            access_logging=meta.get("logging_enabled", False),
            retention_policy=meta.get("object_lock", False),

            # Staleness
            last_modified=last_modified,
            last_accessed=meta.get("last_accessed"),
            staleness_days=staleness,

            # Classification
            has_classification=True,
            classification_source="macie",

            # File info
            path=f"s3://{meta.get('bucket', '')}/{meta.get('key', '')}",
            owner=meta.get("owner"),
            size_bytes=meta.get("size", 0),
            file_type=meta.get("content_type", ""),
            is_archive=is_archive(meta.get("key", "")),
        )

    def _determine_exposure(self, meta: Dict[str, Any]) -> ExposureLevel:
        """
        Determine exposure level from S3 ACL, bucket policy, and access settings.

        See ExposureLevel docstring for full permission mapping.
        """
        # Check if website hosting is enabled (always public)
        if meta.get("website_enabled", False):
            return ExposureLevel.PUBLIC

        # Check public access block - if all four settings enabled, caps exposure
        public_block = meta.get("public_access_block", True)
        public_block_enabled = (
            public_block is True or
            (isinstance(public_block, str) and public_block.lower() == "true")
        )

        # Check bucket policy for public access (Principal: "*" without conditions)
        if meta.get("bucket_policy_public", False):
            if not public_block_enabled:
                return ExposureLevel.PUBLIC

        # Check ACL-based permissions (only apply if public block not enabled)
        acl = meta.get("acl", "private").lower()
        if not public_block_enabled:
            # PUBLIC ACLs
            if "public-read" in acl or "public-read-write" in acl:
                return ExposureLevel.PUBLIC
            # ORG_WIDE ACLs
            if "authenticated-read" in acl:
                return ExposureLevel.ORG_WIDE

        # Check for cross-account access (elevated to ORG_WIDE)
        if meta.get("cross_account", False):
            return ExposureLevel.ORG_WIDE

        # Check for bucket policy with conditions (internal access patterns)
        if meta.get("bucket_policy_conditional", False):
            return ExposureLevel.INTERNAL

        # Map remaining ACLs to exposure levels
        # PRIVATE ACLs
        if acl in ("private", "bucket-owner-full-control", "bucket-owner-read"):
            return ExposureLevel.PRIVATE

        # INTERNAL ACLs (AWS service access)
        if acl in ("aws-exec-read", "log-delivery-write"):
            return ExposureLevel.INTERNAL

        # Default to INTERNAL for unknown ACLs (safer than PRIVATE)
        return ExposureLevel.INTERNAL

    def _normalize_encryption(self, enc: Optional[str]) -> str:
        """Normalize S3 encryption to standard format."""
        if not enc:
            return "none"
        enc_lower = enc.lower()
        if "aws:kms" in enc_lower or "kms" in enc_lower:
            return "customer_managed"
        if "aes256" in enc_lower or "sse-s3" in enc_lower:
            return "platform"
        return "platform"

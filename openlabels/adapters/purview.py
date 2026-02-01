"""
Azure Purview + Blob metadata adapter.

Converts Purview classifications and Azure Blob metadata to OpenLabels normalized format.

Usage:
    >>> from openlabels.adapters.purview import PurviewAdapter
    >>> adapter = PurviewAdapter()
    >>> normalized = adapter.extract(purview_classifications, blob_metadata)
    >>> result = score(normalized.entities, normalized.context.exposure)
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, EntityAggregator, calculate_staleness_days, is_archive,
)
from ..core.registry import normalize_type


class PurviewAdapter:
    """
    Azure Purview + Blob metadata adapter.

    Converts Purview classifications to normalized entities and Azure Blob
    metadata to normalized context for risk scoring.
    """

    def extract(
        self,
        classifications: Dict[str, Any],
        blob_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert Purview classifications + Blob metadata to normalized format.

        Args:
            classifications: Purview classifications JSON
                Expected structure:
                {
                    "classifications": [
                        {
                            "typeName": "MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER",
                            "attributes": {"confidence": 0.95, "count": 5}
                        }
                    ]
                }
                OR
                {
                    "scanResult": {
                        "classifications": [
                            {"classificationName": "Credit Card Number", "count": 3}
                        ]
                    }
                }
            blob_metadata: Azure Blob/container metadata
                Expected structure:
                {
                    "container": "my-container",
                    "name": "path/to/file.csv",
                    "properties": {
                        "content_length": 1024,
                        "last_modified": "2024-01-15T10:30:00Z",
                        "content_type": "text/csv",
                        "blob_tier": "Hot"
                    },
                    "access_level": "private",  # private, blob, container
                    "encryption": {"key_source": "Microsoft.Storage"},
                    "versioning_enabled": true,
                    "soft_delete_enabled": true
                }

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(classifications)
        context = self._normalize_blob_context(blob_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, classifications: Dict[str, Any]) -> List[Entity]:
        """Extract entities from Purview classifications."""
        agg = EntityAggregator(source="purview")

        # Handle multiple classification formats
        class_list = classifications.get("classifications", [])
        if not class_list and "scanResult" in classifications:
            class_list = classifications.get("scanResult", {}).get("classifications", [])

        for classification in class_list:
            # Get classification name (different formats)
            purview_type = (
                classification.get("classificationName") or
                classification.get("typeName", "UNKNOWN")
            )
            purview_type = self._normalize_type_name(purview_type)

            attrs = classification.get("attributes", {})
            count = classification.get("count", attrs.get("count", 1))
            confidence = attrs.get("confidence", 0.85)

            entity_type = normalize_type(purview_type, source="purview")
            agg.add(entity_type, count, confidence)

        return agg.to_entities()

    def _normalize_type_name(self, type_name: str) -> str:
        """Normalize Purview internal type names to display names."""
        # Handle MICROSOFT.PERSONAL.* format
        if type_name.startswith("MICROSOFT."):
            # Convert MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER
            # to "U.S. Social Security Number (SSN)"
            mapping = {
                "MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER": "U.S. Social Security Number (SSN)",
                "MICROSOFT.FINANCIAL.CREDIT_CARD_NUMBER": "Credit Card Number",
                "MICROSOFT.PERSONAL.EMAIL": "Email",
                "MICROSOFT.PERSONAL.PHONE_NUMBER": "Phone Number",
                "MICROSOFT.PERSONAL.NAME": "Person's Name",
                "MICROSOFT.PERSONAL.DATE_OF_BIRTH": "Date of Birth",
                "MICROSOFT.PERSONAL.ADDRESS": "Address",
                "MICROSOFT.PERSONAL.IPADDRESS": "IP Address",
            }
            if type_name in mapping:
                return mapping[type_name]
            # Fallback: extract last component and format it
            # MICROSOFT.PERSONAL.UK.NINO -> NINO_UK (or just NINO if no country)
            parts = type_name.split(".")
            if len(parts) >= 3:
                # Try to extract meaningful name from last parts
                # e.g., MICROSOFT.FINANCIAL.IBAN -> IBAN
                return parts[-1].upper()
        return type_name

    def _normalize_blob_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert Azure Blob metadata to normalized context."""
        # Determine exposure from access level
        exposure = self._determine_exposure(meta)

        # Get properties
        props = meta.get("properties", {})

        # Normalize encryption
        encryption = self._normalize_encryption(meta.get("encryption"))

        # Calculate staleness
        last_modified = props.get("last_modified")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            # Exposure
            exposure=exposure.name,
            cross_account_access=meta.get("cross_tenant_access", False),
            anonymous_access=(exposure == ExposureLevel.PUBLIC),

            # Protection
            encryption=encryption,
            versioning=meta.get("versioning_enabled", False),
            access_logging=meta.get("analytics_logging", {}).get("read", False),
            retention_policy=meta.get("soft_delete_enabled", False),

            # Staleness
            last_modified=last_modified,
            last_accessed=props.get("last_accessed"),
            staleness_days=staleness,

            # Classification
            has_classification=True,
            classification_source="purview",

            # File info
            path=f"azure://{meta.get('container', '')}/{meta.get('name', '')}",
            owner=meta.get("owner"),
            size_bytes=props.get("content_length", 0),
            file_type=props.get("content_type", ""),
            is_archive=is_archive(meta.get("name", "")),
        )

    def _determine_exposure(self, meta: Dict[str, Any]) -> ExposureLevel:
        """
        Determine exposure from Azure Blob access level, network rules, and SAS tokens.

        See ExposureLevel docstring for full permission mapping.
        """
        # Check for private endpoint only (strongest protection)
        if meta.get("private_endpoint_only", False):
            # Even with private endpoint, check for cross-tenant
            if meta.get("cross_tenant_access", False):
                return ExposureLevel.ORG_WIDE
            return ExposureLevel.PRIVATE

        # Check container access level
        access_level = meta.get("access_level", "private").lower()

        # PUBLIC: container-level anonymous access
        if access_level == "container":
            return ExposureLevel.PUBLIC

        # Check for SAS tokens
        sas_exposure = self._evaluate_sas_exposure(meta)
        if sas_exposure == ExposureLevel.PUBLIC:
            return ExposureLevel.PUBLIC

        # ORG_WIDE: blob-level anonymous access (need URL to access)
        if access_level == "blob":
            return ExposureLevel.ORG_WIDE

        # Check network rules
        network_rules = meta.get("network_rules", {})
        default_action = network_rules.get("default_action", "Deny")

        # If default is Allow with no VNet rules, it's broadly accessible
        if default_action == "Allow":
            virtual_network_rules = network_rules.get("virtual_network_rules", [])
            ip_rules = network_rules.get("ip_rules", [])
            if not virtual_network_rules and not ip_rules:
                return ExposureLevel.ORG_WIDE

        # INTERNAL: VNet rules or IP rules configured
        if network_rules.get("virtual_network_rules") or network_rules.get("ip_rules"):
            return ExposureLevel.INTERNAL

        # Check for cross-tenant access
        if meta.get("cross_tenant_access", False):
            return ExposureLevel.ORG_WIDE

        # Check SAS token exposure (may return INTERNAL or ORG_WIDE)
        if sas_exposure.value > ExposureLevel.PRIVATE.value:
            return sas_exposure

        return ExposureLevel.PRIVATE

    def _evaluate_sas_exposure(self, meta: Dict[str, Any]) -> ExposureLevel:
        """Evaluate exposure level based on SAS token configuration."""
        # Publicly shared SAS = PUBLIC
        if meta.get("has_public_sas", False):
            return ExposureLevel.PUBLIC

        sas_config = meta.get("sas_policy", {})
        if not sas_config:
            return ExposureLevel.PRIVATE

        # Check for overly permissive SAS
        # No expiry or very long expiry = ORG_WIDE
        if sas_config.get("no_expiry", False):
            return ExposureLevel.ORG_WIDE

        # Broad permissions (full access) = ORG_WIDE
        permissions = sas_config.get("permissions", "")
        if "d" in permissions and "w" in permissions and "r" in permissions:
            # Delete + Write + Read = very broad
            return ExposureLevel.ORG_WIDE

        # Limited scope SAS with expiry = INTERNAL
        if sas_config.get("has_expiry", True):
            return ExposureLevel.INTERNAL

        return ExposureLevel.PRIVATE

    def _normalize_encryption(self, encryption: Optional[Dict]) -> str:
        """Normalize Azure Blob encryption."""
        if not encryption:
            return "platform"  # Azure has default encryption

        key_source = encryption.get("key_source", "")
        if "keyvault" in key_source.lower() or key_source == "Microsoft.KeyVault":
            return "customer_managed"

        return "platform"

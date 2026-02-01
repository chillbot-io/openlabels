"""
Microsoft Presidio adapter.

Converts Presidio analyzer results to OpenLabels normalized format.

Presidio is an open-source data protection and anonymization SDK that provides
fast identification of PII using NLP, regex, and checksum validations.

Usage:
    >>> from openlabels.adapters.presidio import PresidioAdapter
    >>> adapter = PresidioAdapter()
    >>> normalized = adapter.extract(presidio_results, file_metadata)
    >>> # Feed to scorer
    >>> result = score(normalized.entities, normalized.context.exposure)

Requirements:
    pip install presidio-analyzer presidio-anonymizer
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, calculate_staleness_days, is_archive,
)
from ..core.registry import normalize_type


class PresidioAdapter:
    """
    Microsoft Presidio adapter.

    Converts Presidio analyzer results to normalized entities and
    file metadata to normalized context for risk scoring.
    """

    # Presidio entity type to OpenLabels canonical type mapping
    ENTITY_MAP = {
        # Direct identifiers
        "US_SSN": "SSN",
        "US_PASSPORT": "PASSPORT",
        "US_DRIVER_LICENSE": "DRIVERS_LICENSE",
        "UK_NHS": "NHS_NUMBER",
        "US_ITIN": "TAX_ID",
        "US_BANK_NUMBER": "BANK_ACCOUNT",
        "IBAN_CODE": "IBAN",
        "SG_NRIC_FIN": "MY_NRIC",
        "AU_ABN": "TAX_ID",
        "AU_ACN": "TAX_ID",
        "AU_TFN": "TFN_AU",
        "AU_MEDICARE": "MEDICARE_ID",
        "IN_AADHAAR": "AADHAAR_IN",
        "IN_PAN": "PAN_IN",

        # Financial
        "CREDIT_CARD": "CREDIT_CARD",
        "CRYPTO": "BITCOIN_ADDRESS",  # Generic crypto maps to most common
        "MEDICAL_LICENSE": "MEDICAL_LICENSE",

        # Contact
        "EMAIL_ADDRESS": "EMAIL",
        "PHONE_NUMBER": "PHONE",
        "IP_ADDRESS": "IP_ADDRESS",
        "URL": "URL",

        # Personal
        "PERSON": "NAME",
        "DATE_TIME": "DATE",
        "NRP": "RELIGION",  # Nationality, religion, political group - map to closest
        "LOCATION": "ADDRESS",

        # Credentials (if detected via custom recognizers)
        "AWS_ACCESS_KEY": "AWS_ACCESS_KEY",
        "AZURE_AUTH_TOKEN": "BEARER_TOKEN",  # Map to generic token type
        "GITHUB_TOKEN": "GITHUB_TOKEN",
    }

    def extract(
        self,
        results: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedInput:
        """
        Convert Presidio analyzer results to normalized format.

        Args:
            results: List of Presidio RecognizerResult dicts
                Expected structure (from analyzer.analyze()):
                [
                    {
                        "entity_type": "US_SSN",
                        "start": 10,
                        "end": 21,
                        "score": 0.85,
                        "analysis_explanation": {...}
                    },
                    ...
                ]
                Or as RecognizerResult objects directly.

            metadata: Optional file/object metadata
                Expected structure:
                {
                    "path": "/path/to/file.txt",
                    "size": 1024,
                    "last_modified": "2024-01-15T10:30:00Z",
                    "file_type": "text/plain",
                    "exposure": "PRIVATE",  # Optional
                    "encryption": "none",    # Optional
                    "owner": "user@example.com"
                }

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(results)
        context = self._normalize_context(metadata or {})
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, results: List[Any]) -> List[Entity]:
        """Extract entities from Presidio results."""
        seen_types: Dict[str, Entity] = {}

        for result in results:
            # Handle both dict and RecognizerResult objects
            if hasattr(result, 'entity_type'):
                presidio_type = result.entity_type
                confidence = result.score
                start = result.start
                end = result.end
            else:
                presidio_type = result.get("entity_type", "UNKNOWN")
                confidence = result.get("score", 0.5)
                start = result.get("start", 0)
                end = result.get("end", 0)

            # Map to canonical type
            entity_type = self.ENTITY_MAP.get(presidio_type)
            if not entity_type:
                # Try normalizing via registry
                entity_type = normalize_type(presidio_type, source="presidio")

            # Aggregate by type
            if entity_type in seen_types:
                existing = seen_types[entity_type]
                new_positions = existing.positions + [(start, end)]
                seen_types[entity_type] = Entity(
                    type=entity_type,
                    count=existing.count + 1,
                    confidence=max(existing.confidence, confidence),
                    source="presidio",
                    positions=new_positions,
                )
            else:
                seen_types[entity_type] = Entity(
                    type=entity_type,
                    count=1,
                    confidence=confidence,
                    source="presidio",
                    positions=[(start, end)],
                )

        return list(seen_types.values())

    def _normalize_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert file metadata to normalized context."""
        # Determine exposure level
        exposure_str = meta.get("exposure", "PRIVATE").upper()
        try:
            exposure = ExposureLevel[exposure_str]
        except KeyError:
            exposure = ExposureLevel.PRIVATE

        # Calculate staleness
        last_modified = meta.get("last_modified")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            # Exposure
            exposure=exposure.name,
            cross_account_access=meta.get("cross_account", False),
            anonymous_access=(exposure == ExposureLevel.PUBLIC),

            # Protection
            encryption=meta.get("encryption", "none"),
            versioning=meta.get("versioning", False),
            access_logging=meta.get("access_logging", False),
            retention_policy=meta.get("retention_policy", False),

            # Staleness
            last_modified=last_modified,
            last_accessed=meta.get("last_accessed"),
            staleness_days=staleness,

            # Classification
            has_classification=True,
            classification_source="presidio",

            # File info
            path=meta.get("path", ""),
            owner=meta.get("owner"),
            size_bytes=meta.get("size", 0),
            file_type=meta.get("file_type", ""),
            is_archive=is_archive(meta.get("path", "")),
        )

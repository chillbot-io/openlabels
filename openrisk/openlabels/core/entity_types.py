"""
OpenLabels Entity Type Normalization.

Provides centralized entity type normalization to ensure consistency
across all components. Entity types are ALWAYS normalized to UPPERCASE.

Usage:
    from openlabels.core.entity_types import normalize_entity_type

    entity_type = normalize_entity_type("ssn")  # Returns "SSN"
    entity_type = normalize_entity_type("  Email ")  # Returns "EMAIL"
"""

from typing import Dict


def normalize_entity_type(entity_type: str) -> str:
    """
    Canonical normalization for entity types.

    ALWAYS returns UPPERCASE. This is the single source of truth for
    entity type normalization across all OpenLabels components.

    Args:
        entity_type: Raw entity type string from any source

    Returns:
        Normalized UPPERCASE entity type

    Examples:
        >>> normalize_entity_type("ssn")
        'SSN'
        >>> normalize_entity_type("  Credit_Card  ")
        'CREDIT_CARD'
        >>> normalize_entity_type("PHONE")
        'PHONE'
    """
    return entity_type.strip().upper()


def normalize_entity_counts(entity_counts: Dict[str, int]) -> Dict[str, int]:
    """
    Normalize all entity types in a counts dictionary.

    Merges counts for entity types that normalize to the same value.

    Args:
        entity_counts: Dict of {entity_type: count}

    Returns:
        Dict with normalized UPPERCASE keys, merged counts

    Examples:
        >>> normalize_entity_counts({"ssn": 2, "SSN": 3, "email": 1})
        {'SSN': 5, 'EMAIL': 1}
    """
    normalized: Dict[str, int] = {}
    for entity_type, count in entity_counts.items():
        canonical = normalize_entity_type(entity_type)
        normalized[canonical] = normalized.get(canonical, 0) + count
    return normalized

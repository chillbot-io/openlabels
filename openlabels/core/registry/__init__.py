"""
OpenLabels Entity Registry.

Canonical entity types with weights, categories, and vendor mappings.
This is the single source of truth for entity classification.

Adapters MUST use normalize_type() to convert vendor-specific types.
Scorer MUST use get_weight() to look up entity weights.

Entity count: ~303 types per openlabels-entity-registry-v1.md

This module provides backward-compatible imports while organizing
the registry into logical submodules:
- weights.py: Entity weights by category (risk scoring)
- categories.py: Entity categories (for co-occurrence rules)
- vendor_aliases.py: Vendor-specific type mappings
"""

from typing import Optional

# Import from submodules for organization
from .weights import (
    ENTITY_WEIGHTS,
    DEFAULT_WEIGHT,
    # Override mechanism
    get_effective_weights,
    reload_overrides,
    # Category-specific exports for advanced use
    DIRECT_IDENTIFIER_WEIGHTS,
    HEALTHCARE_WEIGHTS,
    PERSONAL_INFO_WEIGHTS,
    CONTACT_INFO_WEIGHTS,
    FINANCIAL_WEIGHTS,
    DIGITAL_IDENTIFIER_WEIGHTS,
    CREDENTIAL_WEIGHTS,
    GOVERNMENT_WEIGHTS,
    EDUCATION_WEIGHTS,
    LEGAL_WEIGHTS,
    VEHICLE_WEIGHTS,
    IMMIGRATION_WEIGHTS,
    INSURANCE_WEIGHTS,
    REAL_ESTATE_WEIGHTS,
    TELECOM_WEIGHTS,
    BIOMETRIC_WEIGHTS,
    MILITARY_WEIGHTS,
    SENSITIVE_FILE_WEIGHTS,
    INTERNATIONAL_ID_WEIGHTS,
)

from .categories import ENTITY_CATEGORIES

from .vendor_aliases import VENDOR_ALIASES



# --- Public Api ---


def get_weight(entity_type: str) -> int:
    """
    Get weight for an entity type.

    Uses effective weights (standard + local overrides) to support
    organization-specific risk scoring. Override weights by creating
    a weights.yaml file at:
    - /etc/openlabels/weights.yaml (system-wide)
    - ~/.openlabels/weights.yaml (user-specific)
    - OPENLABELS_WEIGHTS_FILE environment variable

    Args:
        entity_type: Canonical entity type (e.g., "SSN", "CREDIT_CARD")

    Returns:
        Weight from 1-10, or DEFAULT_WEIGHT if unknown
    """
    return get_effective_weights().get(entity_type, DEFAULT_WEIGHT)


def get_category(entity_type: str) -> str:
    """
    Get category for an entity type.

    Args:
        entity_type: Canonical entity type

    Returns:
        Category string, or "unknown" if not categorized
    """
    return ENTITY_CATEGORIES.get(entity_type, "unknown")


def normalize_type(vendor_type: str, source: Optional[str] = None) -> str:
    """
    Normalize a vendor-specific entity type to canonical OpenLabels type.

    Args:
        vendor_type: Entity type from Macie, DLP, Purview, or scanner
        source: Optional source hint (unused, for logging)

    Returns:
        Canonical OpenLabels entity type
    """
    # Already canonical?
    if vendor_type in ENTITY_WEIGHTS:
        return vendor_type

    # Check vendor aliases
    if vendor_type in VENDOR_ALIASES:
        return VENDOR_ALIASES[vendor_type]

    # Unknown - pass through as-is
    return vendor_type


def is_known_type(entity_type: str) -> bool:
    """Check if an entity type is in the registry."""
    return entity_type in ENTITY_WEIGHTS or entity_type in VENDOR_ALIASES



# --- Additional Utilities ---


def get_types_by_category(category: str) -> list:
    """
    Get all entity types in a category.

    Args:
        category: Category name (e.g., "health_info", "credential")

    Returns:
        List of entity types in that category
    """
    return [
        entity_type
        for entity_type, cat in ENTITY_CATEGORIES.items()
        if cat == category
    ]


def get_high_risk_types(min_weight: int = 8) -> list:
    """
    Get entity types with weight >= min_weight.

    Args:
        min_weight: Minimum weight threshold (default 8)

    Returns:
        List of high-risk entity types
    """
    return [
        entity_type
        for entity_type, weight in ENTITY_WEIGHTS.items()
        if weight >= min_weight
    ]


def get_all_categories() -> set:
    """Get all unique category names."""
    return set(ENTITY_CATEGORIES.values())


# Backward compatibility: export everything at package level
__all__ = [
    # Main data structures
    "ENTITY_WEIGHTS",
    "ENTITY_CATEGORIES",
    "VENDOR_ALIASES",
    "DEFAULT_WEIGHT",
    # API functions
    "get_weight",
    "get_category",
    "normalize_type",
    "is_known_type",
    # Override mechanism
    "get_effective_weights",
    "reload_overrides",
    # Additional utilities
    "get_types_by_category",
    "get_high_risk_types",
    "get_all_categories",
    # Category-specific weights (for advanced use)
    "DIRECT_IDENTIFIER_WEIGHTS",
    "HEALTHCARE_WEIGHTS",
    "PERSONAL_INFO_WEIGHTS",
    "CONTACT_INFO_WEIGHTS",
    "FINANCIAL_WEIGHTS",
    "DIGITAL_IDENTIFIER_WEIGHTS",
    "CREDENTIAL_WEIGHTS",
    "GOVERNMENT_WEIGHTS",
    "EDUCATION_WEIGHTS",
    "LEGAL_WEIGHTS",
    "VEHICLE_WEIGHTS",
    "IMMIGRATION_WEIGHTS",
    "INSURANCE_WEIGHTS",
    "REAL_ESTATE_WEIGHTS",
    "TELECOM_WEIGHTS",
    "BIOMETRIC_WEIGHTS",
    "MILITARY_WEIGHTS",
    "SENSITIVE_FILE_WEIGHTS",
    "INTERNATIONAL_ID_WEIGHTS",
]

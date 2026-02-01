"""
Core constants for OpenLabels detection engine.

All magic numbers, timeouts, and limits defined here.
Import from this module rather than hardcoding values.
"""

__all__ = [
    # Detection
    "BERT_MAX_LENGTH",
    "NON_NAME_WORDS",
    "NAME_CONNECTORS",
    "NAME_ENTITY_TYPES",
    "is_name_entity_type",
    "PRODUCT_CODE_PREFIXES",
    # Processing
    "MAX_DETECTOR_WORKERS",
    "DETECTOR_TIMEOUT",
]

# --- DETECTION ---
BERT_MAX_LENGTH = 512  # BERT tokenizer sequence length limit

# NAME span boundary validation - common words that should never end a name
NON_NAME_WORDS = frozenset({
    'appears', 'is', 'was', 'were', 'has', 'have', 'had', 'does', 'did',
    'said', 'says', 'went', 'came', 'will', 'would', 'could', 'should',
    'being', 'been', 'are', 'am', 'the', 'a', 'an', 'this', 'that',
    'these', 'those', 'to', 'of', 'in', 'on', 'at', 'for', 'with',
    'by', 'from', 'about', 'he', 'she', 'it', 'they', 'we', 'you',
    'his', 'her', 'their', 'its', 'and', 'or', 'but', 'if', 'then', 'because',
})

# Name connectors (van, von, de, etc.) that ARE valid in names
NAME_CONNECTORS = frozenset({
    'van', 'von', 'de', 'del', 'della', 'la', 'le', 'du', 'dos', 'das',
    'ben', 'ibn', 'bin', 'al', 'el', 'y', 'di', 'da', 'der', 'den', 'ter',
})

# Entity types that represent person names
NAME_ENTITY_TYPES = frozenset({
    "NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE",
    "PERSON", "PER",
})


def is_name_entity_type(entity_type: str) -> bool:
    """
    Check if entity type represents a person name.

    Used for entity resolution, gender inference, and coreference linking.
    Handles both base types (NAME) and role-qualified types (NAME_PATIENT).

    Args:
        entity_type: The entity type string to check

    Returns:
        True if the type represents a person name
    """
    if entity_type in NAME_ENTITY_TYPES:
        return True
    # Also check base type for role-qualified names
    for suffix in ("_PATIENT", "_PROVIDER", "_RELATIVE"):
        if entity_type.endswith(suffix):
            base = entity_type[:-len(suffix)]
            return base in NAME_ENTITY_TYPES
    return False


# Product/inventory code prefixes - NOT medical record numbers
# ML models mistake "SKU-123-45-6789" for MRN because numeric part looks like ID
PRODUCT_CODE_PREFIXES = frozenset({
    'sku', 'item', 'part', 'model', 'ref', 'cat', 'inv', 'po', 'so',
    'lot', 'batch', 'ser', 'prod', 'art', 'stock', 'upc', 'ean',
    'asin', 'isbn', 'gtin', 'mpn', 'oem', 'ndc', 'abc', 'xyz',
})

# --- PROCESSING ---
MAX_DETECTOR_WORKERS = 8
DETECTOR_TIMEOUT = 120.0  # seconds

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
    # File processing & security
    "MAX_DOCUMENT_PAGES",
    "MAX_SPREADSHEET_ROWS",
    "MIN_NATIVE_TEXT_LENGTH",
    "MAX_FILE_SIZE_BYTES",
    "MAX_DECOMPRESSED_SIZE",
    "MAX_EXTRACTION_RATIO",
    "DEFAULT_MAX_READ_BYTES",
    # Subprocess & query limits
    "SUBPROCESS_TIMEOUT",
    "DEFAULT_QUERY_LIMIT",
    # OCR / Models
    "MODEL_LOAD_TIMEOUT",
    "OCR_READY_TIMEOUT",
    # Data directories
    "PROJECT_ROOT",
    "DATA_DIR",
    "DEFAULT_MODELS_DIR",
    "DEFAULT_DICTIONARIES_DIR",
    # Risk tier ordering & priority
    "RISK_TIER_PRIORITY",
    "RISK_TIER_ORDER",
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

# --- FILE PROCESSING & SECURITY ---
MAX_DOCUMENT_PAGES = 50  # Maximum pages to process per document (prevents DoS)
MAX_SPREADSHEET_ROWS = 100000  # Per-sheet row limit (increased for CSV processing)
MIN_NATIVE_TEXT_LENGTH = 20  # Below this, assume scanned/image-based
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50MB file upload limit

# Decompression bomb protection
# DOCX/XLSX are ZIP files - malicious files could decompress to gigabytes
MAX_DECOMPRESSED_SIZE = 200 * 1024 * 1024  # 200MB - reasonable for large documents
MAX_EXTRACTION_RATIO = 100  # Max ratio of decompressed:compressed size

# Adapter read_file default limit (prevents memory exhaustion)
DEFAULT_MAX_READ_BYTES = 100 * 1024 * 1024  # 100MB

# --- SUBPROCESS & QUERY LIMITS ---
SUBPROCESS_TIMEOUT = 30  # seconds - timeout for icacls/setfacl/getfacl calls
DEFAULT_QUERY_LIMIT = 500  # Safety limit for unbounded SELECT queries

# --- RISK TIER ORDERING & PRIORITY ---
# Canonical ascending order of risk tiers (index = severity rank)
RISK_TIER_ORDER = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# Numeric priority for comparisons (higher = more severe)
RISK_TIER_PRIORITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1}

# --- OCR / MODELS ---
MODEL_LOAD_TIMEOUT = 60.0  # seconds - timeout for loading ML models
OCR_READY_TIMEOUT = 30.0  # seconds - timeout for OCR engine readiness

# --- DATA DIRECTORIES ---
# Project-relative paths under .openlabels/
# Structure:
#   <project_root>/.openlabels/
#     models/
#       phi_bert_int8.onnx, phi_bert.tokenizer.json, phi_bert_tokenizer/
#       pii_bert_int8.onnx, pii_bert.tokenizer.json, pii_bert_tokenizer/
#       fastcoref.onnx, fastcoref.tokenizer.json, fastcoref_tokenizer/
#       rapidocr/ (det.onnx, rec.onnx, cls.onnx)
#     dictionaries/
#       diagnoses.txt, drugs.txt, facilities.txt, etc.

from pathlib import Path


def _find_project_root() -> Path:
    """Find the project root by looking for pyproject.toml."""
    # Start from this file's location and walk up
    current = Path(__file__).resolve().parent
    for _ in range(10):  # Max 10 levels up
        if (current / "pyproject.toml").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    # Fallback to home directory if not found
    return Path.home() / "openlabels"


PROJECT_ROOT = _find_project_root()
DATA_DIR = PROJECT_ROOT / ".openlabels"
DEFAULT_MODELS_DIR = DATA_DIR / "models"
DEFAULT_DICTIONARIES_DIR = DATA_DIR / "dictionaries"

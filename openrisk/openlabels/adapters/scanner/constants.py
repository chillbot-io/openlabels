"""
Central constants for the OpenLabels Scanner.

All magic numbers, timeouts, and limits defined here.
Import from this module rather than hardcoding values.
"""

__all__ = [
    # Timeouts
    "MODEL_LOAD_TIMEOUT",
    "DETECTOR_TIMEOUT",
    "OCR_READY_TIMEOUT",
    "THREAD_JOIN_TIMEOUT",
    "SUBPROCESS_TIMEOUT",
    "DATABASE_LOCK_TIMEOUT",
    # Retry/resilience
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_RETRY_BASE_DELAY",
    "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
    "CIRCUIT_BREAKER_RECOVERY_TIMEOUT",
    # Size limits
    "MAX_TEXT_LENGTH",
    "MAX_PATH_LENGTH",
    "MAX_XATTR_VALUE_SIZE",
    # Chunk sizes for file I/O
    "FILE_READ_CHUNK_SIZE",
    "PARTIAL_HASH_SIZE",
    "MAGIC_BYTES_HEADER_SIZE",
    # File processing
    "MAX_DOCUMENT_PAGES",
    "MAX_PAGE_WORKERS",
    "MIN_NATIVE_TEXT_LENGTH",
    "MAX_FILE_SIZE_BYTES",
    "MAX_SPREADSHEET_ROWS",
    "MAX_DECOMPRESSED_SIZE",
    "MAX_EXTRACTION_RATIO",
    "MAX_FILENAME_LENGTH",
    # Detection
    "MAX_DETECTOR_WORKERS",
    "MIN_NAME_LENGTH",
    "MAX_STRUCTURED_VALUE_LENGTH",
    "BERT_MAX_LENGTH",
    "NON_NAME_WORDS",
    "NAME_CONNECTORS",
    "NAME_ENTITY_TYPES",
    "is_name_entity_type",
    "PRODUCT_CODE_PREFIXES",
    # Span merging
    "WORD_BOUNDARY_EXPANSION_LIMIT",
    "NAME_CONTEXT_WINDOW",
    "ADDRESS_GAP_THRESHOLD",
    "TRACKING_CONTEXT_WINDOW",
    "INTERVALTREE_THRESHOLD",
    # Context analysis
    "CONTEXT_WINDOW_DEFAULT",
    # Queue/batch processing
    "DEFAULT_BATCH_SIZE",
    "DEFAULT_QUERY_LIMIT",
    "MAX_QUEUE_SIZE",
    # Regex safety
    "REGEX_TIMEOUT_MS",
    # Extended attributes (collector)
    "MAX_XATTR_NAME_LENGTH",
    "MAX_XATTR_COUNT",
]

# --- TIMEOUTS (seconds) ---
MODEL_LOAD_TIMEOUT = 60.0
DETECTOR_TIMEOUT = 120.0
OCR_READY_TIMEOUT = 30.0
THREAD_JOIN_TIMEOUT = 5.0  # For thread.join() calls
SUBPROCESS_TIMEOUT = 5.0  # For subprocess calls
DATABASE_LOCK_TIMEOUT = 30.0  # SQLite lock wait timeout

# --- RETRY/RESILIENCE ---
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_DELAY = 1.0  # seconds
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 60.0  # seconds

# --- SIZE LIMITS ---
MAX_TEXT_LENGTH = 1_000_000  # 1MB text input
MAX_PATH_LENGTH = 4096  # Filesystem path length limit
MAX_XATTR_VALUE_SIZE = 65536  # Extended attribute value size limit

# --- CHUNK SIZES FOR FILE I/O ---
FILE_READ_CHUNK_SIZE = 8192  # Standard chunk size for reading files (8KB)
PARTIAL_HASH_SIZE = 65536  # Bytes to read for partial hash (64KB)
MAGIC_BYTES_HEADER_SIZE = 64  # Bytes to read for MIME type detection

# --- FILE PROCESSING ---
MAX_DOCUMENT_PAGES = 100  # Max pages to process per document
MAX_PAGE_WORKERS = 4  # Parallel page processing
MIN_NATIVE_TEXT_LENGTH = 20  # Below this, assume scanned/image
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB file limit
MAX_SPREADSHEET_ROWS = 50000  # Per-sheet row limit

# Decompression bomb protection
MAX_DECOMPRESSED_SIZE = 500 * 1024 * 1024  # 500MB max decompressed
MAX_EXTRACTION_RATIO = 100  # Max ratio of decompressed:compressed size

# Maximum filename length (filesystem safe)
MAX_FILENAME_LENGTH = 255

# --- DETECTION ---
MAX_DETECTOR_WORKERS = 8
MIN_NAME_LENGTH = 3  # "Al" valid, "K." not
MAX_STRUCTURED_VALUE_LENGTH = 80
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
    """Check if entity type represents a person name."""
    if entity_type in NAME_ENTITY_TYPES:
        return True
    for suffix in ("_PATIENT", "_PROVIDER", "_RELATIVE"):
        if entity_type.endswith(suffix):
            base = entity_type[:-len(suffix)]
            return base in NAME_ENTITY_TYPES
    return False


# Product/inventory code prefixes - NOT identifiers
PRODUCT_CODE_PREFIXES = frozenset({
    'sku', 'item', 'part', 'model', 'ref', 'cat', 'inv', 'po', 'so',
    'lot', 'batch', 'ser', 'prod', 'art', 'stock', 'upc', 'ean',
    'asin', 'isbn', 'gtin', 'mpn', 'oem', 'ndc', 'abc', 'xyz',
})

# --- SPAN MERGING ---
WORD_BOUNDARY_EXPANSION_LIMIT = 10
NAME_CONTEXT_WINDOW = 50
ADDRESS_GAP_THRESHOLD = 20
TRACKING_CONTEXT_WINDOW = 30
INTERVALTREE_THRESHOLD = 100

# --- CONTEXT ANALYSIS ---
CONTEXT_WINDOW_DEFAULT = 30  # Characters to look before/after entity

# --- QUEUE/BATCH PROCESSING ---
DEFAULT_BATCH_SIZE = 1000  # Batch size for bulk operations
DEFAULT_QUERY_LIMIT = 100  # Default limit for database queries
MAX_QUEUE_SIZE = 10000  # Maximum size for job queues

# --- REGEX SAFETY ---
REGEX_TIMEOUT_MS = 100  # Timeout for regex operations in milliseconds

# --- EXTENDED ATTRIBUTES (COLLECTOR) ---
MAX_XATTR_NAME_LENGTH = 256  # Linux limit is 255, macOS is similar
MAX_XATTR_COUNT = 100  # Prevent collecting excessive attributes

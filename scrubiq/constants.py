"""
Central constants for ScrubIQ.

All magic numbers, timeouts, and limits defined here.
Import from this module rather than hardcoding values.
"""

__all__ = [
    # Rate limiting
    "REDACT_RATE_LIMIT",
    "UPLOAD_RATE_LIMIT",
    "CHAT_RATE_LIMIT",
    "API_RATE_WINDOW_SECONDS",
    # Timeouts
    "DATABASE_LOCK_TIMEOUT",
    "MODEL_LOAD_TIMEOUT",
    "DETECTOR_TIMEOUT",
    "PRELOAD_WAIT_TIMEOUT",
    "OCR_READY_TIMEOUT",
    "LLM_REQUEST_TIMEOUT",
    # Retry
    "DB_MAX_RETRIES",
    "DB_RETRY_BASE_DELAY",
    "DB_RETRY_MAX_DELAY",
    # Size limits
    "MAX_TEXT_LENGTH",
    "MAX_REQUEST_SIZE_MB",
    "MAX_TOKEN_COUNT",
    # Context limits
    "MAX_CONTEXT_TOKENS",
    "CHARS_PER_TOKEN",
    "RESPONSE_TOKEN_RESERVE",
    "LLM_MAX_OUTPUT_TOKENS",
    # Security
    "MIN_RESPONSE_TIME_MS",
    # File processing
    "MAX_DOCUMENT_PAGES",
    "MAX_PAGE_WORKERS",
    "MIN_NATIVE_TEXT_LENGTH",
    "MAX_FILE_SIZE_BYTES",
    "MAX_SPREADSHEET_ROWS",
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
    # Pagination
    "DEFAULT_CONVERSATION_LIMIT",
    "DEFAULT_AUDIT_LIMIT",
    "MAX_PAGINATION_LIMIT",
    "MAX_PAGINATION_OFFSET",
    # Memory system
    "CROSS_CONVERSATION_CONTEXT_COUNT",
    "MEMORY_CONTEXT_LIMIT",
    "MEMORY_MIN_CONFIDENCE",
    "MEMORY_EXTRACTION_ENABLED",
    # LLM model defaults
    "DEFAULT_ANTHROPIC_MODEL",
    "DEFAULT_ANTHROPIC_FAST_MODEL",
    "DEFAULT_OPENAI_MODEL",
    # Chat / LLM context
    "MAX_TITLE_LENGTH",
    "CONTEXT_PREVIEW_LENGTH",
    "TITLE_CONTEXT_USER_LENGTH",
    "TITLE_CONTEXT_ASSISTANT_LENGTH",
    "TITLE_CONTEXT_SOLO_LENGTH",
    "CONTEXT_CONVERSATIONS_LIMIT",
    # File validation
    "MAX_FILENAME_LENGTH",
]

# --- RATE LIMITING ---
# Rate limits for resource-intensive endpoints (per API key)
REDACT_RATE_LIMIT = 30  # Max redact requests per window
UPLOAD_RATE_LIMIT = 10  # Max file uploads per window
CHAT_RATE_LIMIT = 20    # Max chat requests per window
API_RATE_WINDOW_SECONDS = 60  # Window for API rate limits

# --- TIMEOUTS (seconds) ---
DATABASE_LOCK_TIMEOUT = 30.0
MODEL_LOAD_TIMEOUT = 60.0
DETECTOR_TIMEOUT = 120.0
PRELOAD_WAIT_TIMEOUT = 10.0
OCR_READY_TIMEOUT = 30.0
LLM_REQUEST_TIMEOUT = 60.0

# --- RETRY CONFIGURATION ---
DB_MAX_RETRIES = 5
DB_RETRY_BASE_DELAY = 0.1  # seconds
DB_RETRY_MAX_DELAY = 2.0  # seconds

# --- SIZE LIMITS ---
MAX_TEXT_LENGTH = 1_000_000  # 1MB text input
MAX_REQUEST_SIZE_MB = 10  # HTTP request body
MAX_TOKEN_COUNT = 999_999  # Per type per conversation

# --- CONTEXT LIMITS (LLM) ---
MAX_CONTEXT_TOKENS = 100_000  # Reserve room from 200k limit
CHARS_PER_TOKEN = 4  # Rough estimate
RESPONSE_TOKEN_RESERVE = 4000
LLM_MAX_OUTPUT_TOKENS = 4096  # Max tokens for LLM response generation

# --- SECURITY ---
MIN_RESPONSE_TIME_MS = 500  # Timing attack mitigation

# --- FILE PROCESSING ---
MAX_DOCUMENT_PAGES = 50
MAX_PAGE_WORKERS = 4
MIN_NATIVE_TEXT_LENGTH = 20  # Below this, assume scanned/image
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50MB file upload limit
MAX_SPREADSHEET_ROWS = 10000  # Per-sheet row limit (prevents DoS via large spreadsheets)

# SECURITY: Decompression bomb protection
# Maximum decompressed/extracted content size (prevents zip bombs in DOCX/XLSX)
# A 25MB DOCX could theoretically decompress to gigabytes if malicious
MAX_DECOMPRESSED_SIZE = 200 * 1024 * 1024  # 200MB - reasonable for large documents
MAX_EXTRACTION_RATIO = 100  # Max ratio of decompressed:compressed size

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
# Used for entity resolution, gender inference, and coreference
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

# --- SPAN MERGING (merger.py) ---
# Maximum characters to expand when snapping to word boundaries
WORD_BOUNDARY_EXPANSION_LIMIT = 10

# Characters before/after span to check for context (provider/patient patterns)
NAME_CONTEXT_WINDOW = 50

# Maximum gap (chars) between ADDRESS spans to merge them
ADDRESS_GAP_THRESHOLD = 20

# Characters before span to check for tracking number context
TRACKING_CONTEXT_WINDOW = 30

# Span count threshold for using IntervalTree (O(n log n)) vs O(n²)
INTERVALTREE_THRESHOLD = 100

# --- PAGINATION DEFAULTS ---
DEFAULT_CONVERSATION_LIMIT = 50
DEFAULT_AUDIT_LIMIT = 100
MAX_PAGINATION_LIMIT = 500  # Maximum items per page to prevent DoS
MAX_PAGINATION_OFFSET = 100_000  # Maximum offset to prevent resource exhaustion

# --- MEMORY SYSTEM (Claude-like recall) ---
# Number of recent messages from other conversations to include in context
CROSS_CONVERSATION_CONTEXT_COUNT = 5

# Maximum number of extracted memories to inject into system prompt
MEMORY_CONTEXT_LIMIT = 10

# Minimum confidence threshold for memories to be included in context
MEMORY_MIN_CONFIDENCE = 0.8

# Enable automatic memory extraction after conversations
# Set to False to disable LLM-based memory extraction (saves tokens)
MEMORY_EXTRACTION_ENABLED = True

# --- LLM MODEL DEFAULTS ---
# Default model for chat/completion requests (best balance of speed/quality)
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
# Fast model for lightweight tasks (title generation, memory extraction)
DEFAULT_ANTHROPIC_FAST_MODEL = "claude-haiku-4"
# Default OpenAI model
DEFAULT_OPENAI_MODEL = "gpt-4o"

# --- CHAT / LLM CONTEXT ---
# Maximum length for conversation title generation
MAX_TITLE_LENGTH = 50

# Preview length for context messages (truncation point)
CONTEXT_PREVIEW_LENGTH = 200

# Max characters for title generation context
TITLE_CONTEXT_USER_LENGTH = 300
TITLE_CONTEXT_ASSISTANT_LENGTH = 300
TITLE_CONTEXT_SOLO_LENGTH = 500

# Conversations to scan for cross-conversation context
CONTEXT_CONVERSATIONS_LIMIT = 10

# --- FILE VALIDATION ---
# Maximum filename length (filesystem safe)
MAX_FILENAME_LENGTH = 200

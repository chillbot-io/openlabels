"""Tests for central constants module.

Tests configuration constants, limits, and helper functions.
"""

import pytest

from scrubiq.constants import (
    # Rate limiting
    REDACT_RATE_LIMIT,
    UPLOAD_RATE_LIMIT,
    CHAT_RATE_LIMIT,
    API_RATE_WINDOW_SECONDS,
    # Timeouts
    DATABASE_LOCK_TIMEOUT,
    MODEL_LOAD_TIMEOUT,
    DETECTOR_TIMEOUT,
    PRELOAD_WAIT_TIMEOUT,
    OCR_READY_TIMEOUT,
    LLM_REQUEST_TIMEOUT,
    # Retry
    DB_MAX_RETRIES,
    DB_RETRY_BASE_DELAY,
    DB_RETRY_MAX_DELAY,
    # Size limits
    MAX_TEXT_LENGTH,
    MAX_REQUEST_SIZE_MB,
    MAX_TOKEN_COUNT,
    # Context limits
    MAX_CONTEXT_TOKENS,
    CHARS_PER_TOKEN,
    RESPONSE_TOKEN_RESERVE,
    LLM_MAX_OUTPUT_TOKENS,
    # Security
    MIN_RESPONSE_TIME_MS,
    # File processing
    MAX_DOCUMENT_PAGES,
    MAX_PAGE_WORKERS,
    MIN_NATIVE_TEXT_LENGTH,
    MAX_FILE_SIZE_BYTES,
    MAX_SPREADSHEET_ROWS,
    # Detection
    MAX_DETECTOR_WORKERS,
    MIN_NAME_LENGTH,
    MAX_STRUCTURED_VALUE_LENGTH,
    BERT_MAX_LENGTH,
    NON_NAME_WORDS,
    NAME_CONNECTORS,
    NAME_ENTITY_TYPES,
    is_name_entity_type,
    PRODUCT_CODE_PREFIXES,
    # Span merging
    WORD_BOUNDARY_EXPANSION_LIMIT,
    NAME_CONTEXT_WINDOW,
    ADDRESS_GAP_THRESHOLD,
    TRACKING_CONTEXT_WINDOW,
    INTERVALTREE_THRESHOLD,
    # Pagination
    DEFAULT_CONVERSATION_LIMIT,
    DEFAULT_AUDIT_LIMIT,
    MAX_PAGINATION_LIMIT,
    MAX_PAGINATION_OFFSET,
    # Memory system
    CROSS_CONVERSATION_CONTEXT_COUNT,
    MEMORY_CONTEXT_LIMIT,
    MEMORY_MIN_CONFIDENCE,
    MEMORY_EXTRACTION_ENABLED,
    # LLM defaults
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_ANTHROPIC_FAST_MODEL,
    DEFAULT_OPENAI_MODEL,
    # Chat context
    MAX_TITLE_LENGTH,
    CONTEXT_PREVIEW_LENGTH,
    TITLE_CONTEXT_USER_LENGTH,
    TITLE_CONTEXT_ASSISTANT_LENGTH,
    TITLE_CONTEXT_SOLO_LENGTH,
    CONTEXT_CONVERSATIONS_LIMIT,
    # File validation
    MAX_FILENAME_LENGTH,
)


# =============================================================================
# RATE LIMITING CONSTANTS TESTS
# =============================================================================

class TestRateLimitingConstants:
    """Tests for rate limiting constants."""

    def test_redact_rate_limit_positive(self):
        """REDACT_RATE_LIMIT is positive."""
        assert REDACT_RATE_LIMIT > 0

    def test_upload_rate_limit_positive(self):
        """UPLOAD_RATE_LIMIT is positive."""
        assert UPLOAD_RATE_LIMIT > 0

    def test_chat_rate_limit_positive(self):
        """CHAT_RATE_LIMIT is positive."""
        assert CHAT_RATE_LIMIT > 0

    def test_api_rate_window_seconds_positive(self):
        """API_RATE_WINDOW_SECONDS is positive."""
        assert API_RATE_WINDOW_SECONDS > 0

    def test_upload_most_restrictive(self):
        """Upload is most restrictive rate limit."""
        assert UPLOAD_RATE_LIMIT <= CHAT_RATE_LIMIT
        assert UPLOAD_RATE_LIMIT <= REDACT_RATE_LIMIT


# =============================================================================
# TIMEOUT CONSTANTS TESTS
# =============================================================================

class TestTimeoutConstants:
    """Tests for timeout constants."""

    def test_database_lock_timeout_positive(self):
        """DATABASE_LOCK_TIMEOUT is positive."""
        assert DATABASE_LOCK_TIMEOUT > 0

    def test_model_load_timeout_positive(self):
        """MODEL_LOAD_TIMEOUT is positive."""
        assert MODEL_LOAD_TIMEOUT > 0

    def test_detector_timeout_positive(self):
        """DETECTOR_TIMEOUT is positive."""
        assert DETECTOR_TIMEOUT > 0

    def test_preload_wait_timeout_positive(self):
        """PRELOAD_WAIT_TIMEOUT is positive."""
        assert PRELOAD_WAIT_TIMEOUT > 0

    def test_ocr_ready_timeout_positive(self):
        """OCR_READY_TIMEOUT is positive."""
        assert OCR_READY_TIMEOUT > 0

    def test_llm_request_timeout_positive(self):
        """LLM_REQUEST_TIMEOUT is positive."""
        assert LLM_REQUEST_TIMEOUT > 0

    def test_model_timeout_longer_than_preload(self):
        """Model load timeout > preload wait."""
        assert MODEL_LOAD_TIMEOUT > PRELOAD_WAIT_TIMEOUT


# =============================================================================
# RETRY CONSTANTS TESTS
# =============================================================================

class TestRetryConstants:
    """Tests for retry configuration constants."""

    def test_db_max_retries_positive(self):
        """DB_MAX_RETRIES is positive."""
        assert DB_MAX_RETRIES > 0

    def test_db_retry_base_delay_positive(self):
        """DB_RETRY_BASE_DELAY is positive."""
        assert DB_RETRY_BASE_DELAY > 0

    def test_db_retry_max_delay_positive(self):
        """DB_RETRY_MAX_DELAY is positive."""
        assert DB_RETRY_MAX_DELAY > 0

    def test_max_delay_greater_than_base(self):
        """Max delay >= base delay."""
        assert DB_RETRY_MAX_DELAY >= DB_RETRY_BASE_DELAY


# =============================================================================
# SIZE LIMITS TESTS
# =============================================================================

class TestSizeLimits:
    """Tests for size limit constants."""

    def test_max_text_length_reasonable(self):
        """MAX_TEXT_LENGTH is reasonable (>= 10KB)."""
        assert MAX_TEXT_LENGTH >= 10_000

    def test_max_request_size_mb_positive(self):
        """MAX_REQUEST_SIZE_MB is positive."""
        assert MAX_REQUEST_SIZE_MB > 0

    def test_max_token_count_large(self):
        """MAX_TOKEN_COUNT is large enough."""
        assert MAX_TOKEN_COUNT >= 1000


# =============================================================================
# CONTEXT LIMITS TESTS
# =============================================================================

class TestContextLimits:
    """Tests for LLM context limit constants."""

    def test_max_context_tokens_positive(self):
        """MAX_CONTEXT_TOKENS is positive."""
        assert MAX_CONTEXT_TOKENS > 0

    def test_chars_per_token_positive(self):
        """CHARS_PER_TOKEN is positive."""
        assert CHARS_PER_TOKEN > 0

    def test_response_token_reserve_positive(self):
        """RESPONSE_TOKEN_RESERVE is positive."""
        assert RESPONSE_TOKEN_RESERVE > 0

    def test_llm_max_output_tokens_positive(self):
        """LLM_MAX_OUTPUT_TOKENS is positive."""
        assert LLM_MAX_OUTPUT_TOKENS > 0

    def test_reserve_less_than_max_context(self):
        """Response reserve < max context."""
        assert RESPONSE_TOKEN_RESERVE < MAX_CONTEXT_TOKENS


# =============================================================================
# SECURITY CONSTANTS TESTS
# =============================================================================

class TestSecurityConstants:
    """Tests for security constants."""

    def test_min_response_time_ms_positive(self):
        """MIN_RESPONSE_TIME_MS is positive (timing attack mitigation)."""
        assert MIN_RESPONSE_TIME_MS > 0


# =============================================================================
# FILE PROCESSING CONSTANTS TESTS
# =============================================================================

class TestFileProcessingConstants:
    """Tests for file processing constants."""

    def test_max_document_pages_positive(self):
        """MAX_DOCUMENT_PAGES is positive."""
        assert MAX_DOCUMENT_PAGES > 0

    def test_max_page_workers_positive(self):
        """MAX_PAGE_WORKERS is positive."""
        assert MAX_PAGE_WORKERS > 0

    def test_min_native_text_length_positive(self):
        """MIN_NATIVE_TEXT_LENGTH is positive."""
        assert MIN_NATIVE_TEXT_LENGTH > 0

    def test_max_file_size_bytes_positive(self):
        """MAX_FILE_SIZE_BYTES is positive."""
        assert MAX_FILE_SIZE_BYTES > 0

    def test_max_spreadsheet_rows_positive(self):
        """MAX_SPREADSHEET_ROWS is positive (DoS protection)."""
        assert MAX_SPREADSHEET_ROWS > 0


# =============================================================================
# DETECTION CONSTANTS TESTS
# =============================================================================

class TestDetectionConstants:
    """Tests for detection constants."""

    def test_max_detector_workers_positive(self):
        """MAX_DETECTOR_WORKERS is positive."""
        assert MAX_DETECTOR_WORKERS > 0

    def test_min_name_length_positive(self):
        """MIN_NAME_LENGTH is positive."""
        assert MIN_NAME_LENGTH > 0

    def test_max_structured_value_length_positive(self):
        """MAX_STRUCTURED_VALUE_LENGTH is positive."""
        assert MAX_STRUCTURED_VALUE_LENGTH > 0

    def test_bert_max_length_positive(self):
        """BERT_MAX_LENGTH is positive."""
        assert BERT_MAX_LENGTH > 0


# =============================================================================
# NAME SETS TESTS
# =============================================================================

class TestNameSets:
    """Tests for name-related frozensets."""

    def test_non_name_words_is_frozenset(self):
        """NON_NAME_WORDS is a frozenset."""
        assert isinstance(NON_NAME_WORDS, frozenset)

    def test_non_name_words_not_empty(self):
        """NON_NAME_WORDS is not empty."""
        assert len(NON_NAME_WORDS) > 0

    def test_non_name_words_contains_common(self):
        """NON_NAME_WORDS contains common words."""
        assert "is" in NON_NAME_WORDS
        assert "was" in NON_NAME_WORDS
        assert "the" in NON_NAME_WORDS

    def test_name_connectors_is_frozenset(self):
        """NAME_CONNECTORS is a frozenset."""
        assert isinstance(NAME_CONNECTORS, frozenset)

    def test_name_connectors_not_empty(self):
        """NAME_CONNECTORS is not empty."""
        assert len(NAME_CONNECTORS) > 0

    def test_name_connectors_contains_expected(self):
        """NAME_CONNECTORS contains expected connectors."""
        assert "van" in NAME_CONNECTORS
        assert "von" in NAME_CONNECTORS
        assert "de" in NAME_CONNECTORS

    def test_name_entity_types_is_frozenset(self):
        """NAME_ENTITY_TYPES is a frozenset."""
        assert isinstance(NAME_ENTITY_TYPES, frozenset)

    def test_name_entity_types_contains_expected(self):
        """NAME_ENTITY_TYPES contains expected types."""
        assert "NAME" in NAME_ENTITY_TYPES
        assert "PERSON" in NAME_ENTITY_TYPES

    def test_product_code_prefixes_is_frozenset(self):
        """PRODUCT_CODE_PREFIXES is a frozenset."""
        assert isinstance(PRODUCT_CODE_PREFIXES, frozenset)

    def test_product_code_prefixes_contains_expected(self):
        """PRODUCT_CODE_PREFIXES contains expected prefixes."""
        assert "sku" in PRODUCT_CODE_PREFIXES
        assert "item" in PRODUCT_CODE_PREFIXES


# =============================================================================
# IS_NAME_ENTITY_TYPE FUNCTION TESTS
# =============================================================================

class TestIsNameEntityType:
    """Tests for is_name_entity_type function."""

    def test_name_returns_true(self):
        """NAME returns True."""
        assert is_name_entity_type("NAME") is True

    def test_person_returns_true(self):
        """PERSON returns True."""
        assert is_name_entity_type("PERSON") is True

    def test_name_patient_returns_true(self):
        """NAME_PATIENT returns True."""
        assert is_name_entity_type("NAME_PATIENT") is True

    def test_name_provider_returns_true(self):
        """NAME_PROVIDER returns True."""
        assert is_name_entity_type("NAME_PROVIDER") is True

    def test_name_relative_returns_true(self):
        """NAME_RELATIVE returns True."""
        assert is_name_entity_type("NAME_RELATIVE") is True

    def test_non_name_returns_false(self):
        """Non-name types return False."""
        assert is_name_entity_type("SSN") is False
        assert is_name_entity_type("PHONE") is False
        assert is_name_entity_type("DATE") is False

    def test_per_returns_true(self):
        """PER (shorthand) returns True."""
        assert is_name_entity_type("PER") is True

    def test_unknown_type_returns_false(self):
        """Unknown types return False."""
        assert is_name_entity_type("UNKNOWN_TYPE") is False
        assert is_name_entity_type("") is False


# =============================================================================
# SPAN MERGING CONSTANTS TESTS
# =============================================================================

class TestSpanMergingConstants:
    """Tests for span merging constants."""

    def test_word_boundary_expansion_limit_positive(self):
        """WORD_BOUNDARY_EXPANSION_LIMIT is positive."""
        assert WORD_BOUNDARY_EXPANSION_LIMIT > 0

    def test_name_context_window_positive(self):
        """NAME_CONTEXT_WINDOW is positive."""
        assert NAME_CONTEXT_WINDOW > 0

    def test_address_gap_threshold_positive(self):
        """ADDRESS_GAP_THRESHOLD is positive."""
        assert ADDRESS_GAP_THRESHOLD > 0

    def test_tracking_context_window_positive(self):
        """TRACKING_CONTEXT_WINDOW is positive."""
        assert TRACKING_CONTEXT_WINDOW > 0

    def test_intervaltree_threshold_positive(self):
        """INTERVALTREE_THRESHOLD is positive."""
        assert INTERVALTREE_THRESHOLD > 0


# =============================================================================
# PAGINATION CONSTANTS TESTS
# =============================================================================

class TestPaginationConstants:
    """Tests for pagination constants."""

    def test_default_conversation_limit_positive(self):
        """DEFAULT_CONVERSATION_LIMIT is positive."""
        assert DEFAULT_CONVERSATION_LIMIT > 0

    def test_default_audit_limit_positive(self):
        """DEFAULT_AUDIT_LIMIT is positive."""
        assert DEFAULT_AUDIT_LIMIT > 0

    def test_max_pagination_limit_positive(self):
        """MAX_PAGINATION_LIMIT is positive (DoS protection)."""
        assert MAX_PAGINATION_LIMIT > 0

    def test_max_pagination_offset_positive(self):
        """MAX_PAGINATION_OFFSET is positive."""
        assert MAX_PAGINATION_OFFSET > 0

    def test_defaults_within_max(self):
        """Default limits within max."""
        assert DEFAULT_CONVERSATION_LIMIT <= MAX_PAGINATION_LIMIT
        assert DEFAULT_AUDIT_LIMIT <= MAX_PAGINATION_LIMIT


# =============================================================================
# MEMORY SYSTEM CONSTANTS TESTS
# =============================================================================

class TestMemorySystemConstants:
    """Tests for memory system constants."""

    def test_cross_conversation_context_count_positive(self):
        """CROSS_CONVERSATION_CONTEXT_COUNT is positive."""
        assert CROSS_CONVERSATION_CONTEXT_COUNT > 0

    def test_memory_context_limit_positive(self):
        """MEMORY_CONTEXT_LIMIT is positive."""
        assert MEMORY_CONTEXT_LIMIT > 0

    def test_memory_min_confidence_valid(self):
        """MEMORY_MIN_CONFIDENCE is between 0 and 1."""
        assert 0 <= MEMORY_MIN_CONFIDENCE <= 1

    def test_memory_extraction_enabled_is_bool(self):
        """MEMORY_EXTRACTION_ENABLED is a boolean."""
        assert isinstance(MEMORY_EXTRACTION_ENABLED, bool)


# =============================================================================
# LLM MODEL CONSTANTS TESTS
# =============================================================================

class TestLLMModelConstants:
    """Tests for LLM model constants."""

    def test_default_anthropic_model_not_empty(self):
        """DEFAULT_ANTHROPIC_MODEL is not empty."""
        assert len(DEFAULT_ANTHROPIC_MODEL) > 0

    def test_default_anthropic_fast_model_not_empty(self):
        """DEFAULT_ANTHROPIC_FAST_MODEL is not empty."""
        assert len(DEFAULT_ANTHROPIC_FAST_MODEL) > 0

    def test_default_openai_model_not_empty(self):
        """DEFAULT_OPENAI_MODEL is not empty."""
        assert len(DEFAULT_OPENAI_MODEL) > 0


# =============================================================================
# CHAT CONTEXT CONSTANTS TESTS
# =============================================================================

class TestChatContextConstants:
    """Tests for chat context constants."""

    def test_max_title_length_positive(self):
        """MAX_TITLE_LENGTH is positive."""
        assert MAX_TITLE_LENGTH > 0

    def test_context_preview_length_positive(self):
        """CONTEXT_PREVIEW_LENGTH is positive."""
        assert CONTEXT_PREVIEW_LENGTH > 0

    def test_title_context_lengths_positive(self):
        """Title context lengths are positive."""
        assert TITLE_CONTEXT_USER_LENGTH > 0
        assert TITLE_CONTEXT_ASSISTANT_LENGTH > 0
        assert TITLE_CONTEXT_SOLO_LENGTH > 0

    def test_context_conversations_limit_positive(self):
        """CONTEXT_CONVERSATIONS_LIMIT is positive."""
        assert CONTEXT_CONVERSATIONS_LIMIT > 0


# =============================================================================
# FILE VALIDATION CONSTANTS TESTS
# =============================================================================

class TestFileValidationConstants:
    """Tests for file validation constants."""

    def test_max_filename_length_positive(self):
        """MAX_FILENAME_LENGTH is positive."""
        assert MAX_FILENAME_LENGTH > 0

    def test_max_filename_length_reasonable(self):
        """MAX_FILENAME_LENGTH is reasonable (< 256)."""
        assert MAX_FILENAME_LENGTH < 256

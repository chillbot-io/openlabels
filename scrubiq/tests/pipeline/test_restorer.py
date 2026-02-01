"""Tests for token restoration in restorer.py.

Tests replacing tokens with PHI values or Safe Harbor values.
"""

import sys
import pytest
from unittest.mock import MagicMock

# Mock the storage module before importing restorer to avoid SQLCipher dependency
mock_token_store = MagicMock()
sys.modules['scrubiq.storage'] = MagicMock()
sys.modules['scrubiq.storage.tokens'] = MagicMock()
sys.modules['scrubiq.storage.tokens'].TokenStore = mock_token_store

from scrubiq.pipeline.restorer import (
    restore,
    restore_tokens,
    RestoreResult,
    TOKEN_PATTERN,
)


def make_mock_store(token_map: dict):
    """Create a mock TokenStore with given token mappings."""
    store = MagicMock()

    def mock_get(token, use_safe_harbor=False):
        if token in token_map:
            value = token_map[token]
            if use_safe_harbor and isinstance(value, tuple):
                return value[1]  # safe harbor value
            elif isinstance(value, tuple):
                return value[0]  # original value
            return value
        return None

    store.get = mock_get
    return store


# =============================================================================
# TOKEN_PATTERN TESTS
# =============================================================================

class TestTokenPattern:
    """Tests for TOKEN_PATTERN regex."""

    def test_matches_simple_token(self):
        """Matches basic token format [TYPE_N]."""
        match = TOKEN_PATTERN.search("[NAME_1]")
        assert match is not None
        assert match.group(1) == "NAME_1"

    def test_matches_multi_digit_token(self):
        """Matches tokens with multiple digit numbers."""
        match = TOKEN_PATTERN.search("[SSN_123]")
        assert match is not None
        assert match.group(1) == "SSN_123"

    def test_matches_underscored_type(self):
        """Matches types with underscores."""
        match = TOKEN_PATTERN.search("[NAME_PATIENT_1]")
        assert match is not None
        assert match.group(1) == "NAME_PATIENT_1"

    def test_matches_alphanumeric_type(self):
        """Matches types with numbers."""
        match = TOKEN_PATTERN.search("[ID2_1]")
        assert match is not None
        assert match.group(1) == "ID2_1"

    def test_no_match_lowercase(self):
        """Does not match lowercase types."""
        match = TOKEN_PATTERN.search("[name_1]")
        assert match is None

    def test_no_match_without_number(self):
        """Does not match tokens without numbers."""
        match = TOKEN_PATTERN.search("[NAME]")
        assert match is None

    def test_no_match_without_underscore(self):
        """Does not match without underscore before number."""
        match = TOKEN_PATTERN.search("[NAME1]")
        assert match is None

    def test_finds_multiple_tokens(self):
        """Finds multiple tokens in text."""
        text = "Patient [NAME_1] has SSN [SSN_1] and phone [PHONE_1]"
        matches = TOKEN_PATTERN.findall(text)
        assert len(matches) == 3
        assert "NAME_1" in matches
        assert "SSN_1" in matches
        assert "PHONE_1" in matches

    def test_token_at_start(self):
        """Matches token at start of string."""
        match = TOKEN_PATTERN.search("[NAME_1] is here")
        assert match is not None

    def test_token_at_end(self):
        """Matches token at end of string."""
        match = TOKEN_PATTERN.search("Patient is [NAME_1]")
        assert match is not None

    def test_adjacent_tokens(self):
        """Matches adjacent tokens."""
        text = "[NAME_1][NAME_2]"
        matches = TOKEN_PATTERN.findall(text)
        assert len(matches) == 2


# =============================================================================
# RESTORE TESTS
# =============================================================================

class TestRestore:
    """Tests for restore() function."""

    def test_no_tokens_unchanged(self):
        """Text without tokens is unchanged."""
        store = make_mock_store({})
        text = "This is plain text"
        restored, found, unknown = restore(text, store)

        assert restored == "This is plain text"
        assert found == []
        assert unknown == []

    def test_restores_single_token(self):
        """Restores a single token."""
        store = make_mock_store({"[NAME_1]": "John Smith"})
        text = "Patient [NAME_1] arrived"
        restored, found, unknown = restore(text, store)

        assert restored == "Patient John Smith arrived"
        assert found == ["[NAME_1]"]
        assert unknown == []

    def test_restores_multiple_tokens(self):
        """Restores multiple different tokens."""
        store = make_mock_store({
            "[NAME_1]": "John Smith",
            "[SSN_1]": "123-45-6789",
            "[PHONE_1]": "555-1234",
        })
        text = "[NAME_1] SSN: [SSN_1] Phone: [PHONE_1]"
        restored, found, unknown = restore(text, store)

        assert restored == "John Smith SSN: 123-45-6789 Phone: 555-1234"
        assert len(found) == 3
        assert "[NAME_1]" in found
        assert "[SSN_1]" in found
        assert "[PHONE_1]" in found

    def test_unknown_token_becomes_redacted(self):
        """Unknown tokens become [REDACTED]."""
        store = make_mock_store({"[NAME_1]": "John Smith"})
        text = "Patient [NAME_1] has [UNKNOWN_999]"
        restored, found, unknown = restore(text, store)

        assert restored == "Patient John Smith has [REDACTED]"
        assert found == ["[NAME_1]"]
        assert unknown == ["[UNKNOWN_999]"]

    def test_all_unknown_tokens(self):
        """All unknown tokens become [REDACTED]."""
        store = make_mock_store({})
        text = "[NAME_1] and [SSN_1]"
        restored, found, unknown = restore(text, store)

        assert restored == "[REDACTED] and [REDACTED]"
        assert found == []
        assert "[NAME_1]" in unknown
        assert "[SSN_1]" in unknown

    def test_same_token_multiple_times(self):
        """Same token appearing multiple times is restored."""
        store = make_mock_store({"[NAME_1]": "John Smith"})
        text = "[NAME_1] met with [NAME_1]"
        restored, found, unknown = restore(text, store)

        assert restored == "John Smith met with John Smith"
        assert found == ["[NAME_1]", "[NAME_1]"]

    def test_empty_string(self):
        """Empty string returns empty."""
        store = make_mock_store({})
        restored, found, unknown = restore("", store)

        assert restored == ""
        assert found == []
        assert unknown == []

    def test_preserves_formatting(self):
        """Preserves whitespace and formatting."""
        store = make_mock_store({"[NAME_1]": "John"})
        text = "  [NAME_1]  \n  has arrived  "
        restored, found, unknown = restore(text, store)

        assert restored == "  John  \n  has arrived  "

    def test_adjacent_tokens_restored(self):
        """Adjacent tokens are both restored."""
        store = make_mock_store({
            "[NAME_1]": "John",
            "[NAME_2]": "Smith",
        })
        text = "[NAME_1][NAME_2]"
        restored, found, unknown = restore(text, store)

        assert restored == "JohnSmith"
        assert len(found) == 2


# =============================================================================
# RESTORE WITH SAFE HARBOR TESTS
# =============================================================================

class TestRestoreSafeHarbor:
    """Tests for restore() with use_safe_harbor=True."""

    def test_uses_safe_harbor_value(self):
        """Uses Safe Harbor value when requested."""
        store = make_mock_store({
            "[DATE_1]": ("03/15/1985", "1985"),  # (original, safe_harbor)
        })
        text = "DOB: [DATE_1]"
        restored, found, unknown = restore(text, store, use_safe_harbor=True)

        assert restored == "DOB: 1985"
        assert found == ["[DATE_1]"]

    def test_uses_original_by_default(self):
        """Uses original value by default."""
        store = make_mock_store({
            "[DATE_1]": ("03/15/1985", "1985"),
        })
        text = "DOB: [DATE_1]"
        restored, found, unknown = restore(text, store, use_safe_harbor=False)

        assert restored == "DOB: 03/15/1985"

    def test_multiple_tokens_safe_harbor(self):
        """Multiple tokens all use Safe Harbor."""
        store = make_mock_store({
            "[DATE_1]": ("03/15/1985", "1985"),
            "[AGE_1]": ("95", "90+"),
            "[ZIP_1]": ("12345", "123"),
        })
        text = "DOB: [DATE_1], Age: [AGE_1], ZIP: [ZIP_1]"
        restored, found, unknown = restore(text, store, use_safe_harbor=True)

        assert restored == "DOB: 1985, Age: 90+, ZIP: 123"


# =============================================================================
# RESTORE_TOKENS TESTS
# =============================================================================

class TestRestoreTokens:
    """Tests for restore_tokens() convenience function."""

    def test_returns_restore_result(self):
        """Returns RestoreResult object."""
        store = make_mock_store({"[NAME_1]": "John"})
        result = restore_tokens("[NAME_1]", store)

        assert isinstance(result, RestoreResult)

    def test_result_has_restored_text(self):
        """RestoreResult has restored text."""
        store = make_mock_store({"[NAME_1]": "John"})
        result = restore_tokens("[NAME_1] is here", store)

        assert result.restored == "John is here"

    def test_result_has_tokens_found(self):
        """RestoreResult has tokens_found list."""
        store = make_mock_store({"[NAME_1]": "John"})
        result = restore_tokens("[NAME_1]", store)

        assert result.tokens_found == ["[NAME_1]"]

    def test_result_has_tokens_unknown(self):
        """RestoreResult has tokens_unknown list."""
        store = make_mock_store({})
        result = restore_tokens("[NAME_1]", store)

        assert result.tokens_unknown == ["[NAME_1]"]

    def test_safe_harbor_mode(self):
        """Supports use_safe_harbor parameter."""
        store = make_mock_store({
            "[DATE_1]": ("03/15/1985", "1985"),
        })
        result = restore_tokens("[DATE_1]", store, use_safe_harbor=True)

        assert result.restored == "1985"


# =============================================================================
# RESTORE_RESULT TESTS
# =============================================================================

class TestRestoreResult:
    """Tests for RestoreResult dataclass."""

    def test_is_dataclass(self):
        """RestoreResult is a dataclass."""
        from dataclasses import is_dataclass
        assert is_dataclass(RestoreResult)

    def test_has_required_fields(self):
        """RestoreResult has required fields."""
        result = RestoreResult(
            restored="text",
            tokens_found=["[NAME_1]"],
            tokens_unknown=["[SSN_1]"],
        )

        assert result.restored == "text"
        assert result.tokens_found == ["[NAME_1]"]
        assert result.tokens_unknown == ["[SSN_1]"]


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for token restoration."""

    def test_token_inside_word(self):
        """Token pattern requires brackets, not inside words."""
        store = make_mock_store({"[NAME_1]": "John"})
        text = "prefix[NAME_1]suffix"
        restored, found, unknown = restore(text, store)

        assert restored == "prefixJohnsuffix"

    def test_malformed_token_ignored(self):
        """Malformed tokens are left unchanged."""
        store = make_mock_store({})
        text = "[NAME_] and [_1] and NAME_1]"
        restored, found, unknown = restore(text, store)

        assert restored == text
        assert found == []
        assert unknown == []

    def test_nested_brackets_handled(self):
        """Nested brackets handled correctly."""
        store = make_mock_store({"[NAME_1]": "John"})
        text = "[[NAME_1]]"
        restored, found, unknown = restore(text, store)

        # Should match [NAME_1] inside
        assert restored == "[John]"

    def test_special_characters_in_value(self):
        """Values with special chars are inserted correctly."""
        store = make_mock_store({"[EMAIL_1]": "user@example.com"})
        text = "Email: [EMAIL_1]"
        restored, found, unknown = restore(text, store)

        assert restored == "Email: user@example.com"

    def test_multiline_text(self):
        """Handles multiline text."""
        store = make_mock_store({
            "[NAME_1]": "John",
            "[NAME_2]": "Jane",
        })
        text = "Line 1: [NAME_1]\nLine 2: [NAME_2]"
        restored, found, unknown = restore(text, store)

        assert restored == "Line 1: John\nLine 2: Jane"
        assert len(found) == 2

    def test_very_large_token_number(self):
        """Handles large token numbers."""
        store = make_mock_store({"[NAME_999999]": "John"})
        text = "[NAME_999999]"
        restored, found, unknown = restore(text, store)

        assert restored == "John"

    def test_value_contains_token_pattern(self):
        """Value containing token pattern is inserted literally."""
        # Edge case: restored value looks like a token
        store = make_mock_store({"[NAME_1]": "[SSN_99]"})
        text = "[NAME_1]"
        restored, found, unknown = restore(text, store)

        # The literal string "[SSN_99]" is inserted
        # It should NOT be re-processed (only one pass)
        assert restored == "[SSN_99]"


# =============================================================================
# SECURITY TESTS
# =============================================================================

class TestSecurity:
    """Security-related tests for token restoration."""

    def test_unknown_token_masked(self):
        """Unknown tokens don't reveal type information."""
        store = make_mock_store({})
        text = "[SSN_1] and [CREDIT_CARD_2]"
        restored, found, unknown = restore(text, store)

        # Types are not revealed in output
        assert "SSN" not in restored
        assert "CREDIT_CARD" not in restored
        assert restored == "[REDACTED] and [REDACTED]"

    def test_partial_store_masks_unknown(self):
        """Known and unknown tokens handled correctly."""
        store = make_mock_store({"[NAME_1]": "John"})
        text = "[NAME_1] SSN: [SSN_1]"
        restored, found, unknown = restore(text, store)

        assert "John" in restored
        assert "[REDACTED]" in restored
        assert "SSN_1" not in restored

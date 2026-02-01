"""Tests for pattern-based PHI detection.

Tests pattern matching for phone numbers, emails, names, addresses, etc.
Also tests false positive filtering.
"""

import re
import pytest

from scrubiq.detectors.patterns import (
    PATTERNS,
    FALSE_POSITIVE_NAMES,
    _is_false_positive_name,
    add_pattern,
)


# =============================================================================
# FALSE POSITIVE NAME TESTS
# =============================================================================

class TestFalsePositiveNames:
    """Tests for false positive name detection."""

    def test_document_headers_rejected(self):
        """Document headers are rejected as names."""
        assert _is_false_positive_name("LABORATORY") is True
        assert _is_false_positive_name("REPORT") is True
        assert _is_false_positive_name("CERTIFICATE") is True
        assert _is_false_positive_name("INSURANCE") is True

    def test_field_labels_rejected(self):
        """Field labels are rejected as names."""
        assert _is_false_positive_name("MRN") is True
        assert _is_false_positive_name("DOB") is True
        assert _is_false_positive_name("SSN") is True
        assert _is_false_positive_name("PATIENT") is True

    def test_state_abbreviations_rejected(self):
        """State abbreviations are rejected as names."""
        assert _is_false_positive_name("PA") is True
        assert _is_false_positive_name("MD") is True
        assert _is_false_positive_name("NY") is True
        assert _is_false_positive_name("CA") is True

    def test_medical_terms_rejected(self):
        """Medical terms are rejected as names."""
        assert _is_false_positive_name("DIAGNOSIS") is True
        assert _is_false_positive_name("PROCEDURE") is True
        assert _is_false_positive_name("MEDICATION") is True

    def test_insurance_companies_rejected(self):
        """Insurance company fragments are rejected."""
        assert _is_false_positive_name("BLUECROSS") is True
        assert _is_false_positive_name("AETNA") is True
        assert _is_false_positive_name("MEDICARE") is True

    def test_single_character_rejected(self):
        """Single character 'names' are rejected."""
        assert _is_false_positive_name("A") is True
        assert _is_false_positive_name("X") is True

    def test_very_short_rejected(self):
        """Very short values (< 3 chars) are rejected."""
        assert _is_false_positive_name("AB") is True
        assert _is_false_positive_name("Jo") is True

    def test_all_words_false_positive(self):
        """All words being false positives is rejected."""
        assert _is_false_positive_name("LABORATORY REPORT") is True
        assert _is_false_positive_name("INSURANCE DOCUMENT") is True

    def test_document_fragment_y_report(self):
        """Document fragments like 'Y REPORT' are rejected."""
        assert _is_false_positive_name("Y REPORT") is True
        assert _is_false_positive_name("RY REPORT") is True

    def test_city_state_pattern(self):
        """City, STATE patterns are rejected (addresses, not names)."""
        assert _is_false_positive_name("Baltimore, MD") is True
        assert _is_false_positive_name("Boston, MA") is True
        assert _is_false_positive_name("Denver, CO") is True

    def test_multi_word_city(self):
        """Multi-word cities with state are rejected."""
        assert _is_false_positive_name("New York, NY") is True
        assert _is_false_positive_name("San Francisco, CA") is True
        assert _is_false_positive_name("Las Vegas, NV") is True

    def test_valid_names_pass(self):
        """Valid names are not rejected."""
        assert _is_false_positive_name("John Smith") is False
        assert _is_false_positive_name("Mary Johnson") is False
        assert _is_false_positive_name("Robert Williams") is False

    def test_names_with_credentials_pass(self):
        """Names with credentials are not rejected."""
        # "John Smith, MD" should pass (valid provider name)
        assert _is_false_positive_name("John Smith, MD") is False
        assert _is_false_positive_name("Jane Doe, RN") is False

    def test_mixed_case_handled(self):
        """Mixed case is handled correctly."""
        assert _is_false_positive_name("laboratory") is True
        assert _is_false_positive_name("Laboratory") is True
        assert _is_false_positive_name("LABORATORY") is True

    def test_ends_with_report(self):
        """Names ending with REPORT are rejected."""
        assert _is_false_positive_name("Something REPORT") is True
        assert _is_false_positive_name("X RESULTS") is True

    def test_honorifics_rejected(self):
        """International honorifics are rejected."""
        assert _is_false_positive_name("HERR") is True  # German
        assert _is_false_positive_name("MADAME") is True  # French
        assert _is_false_positive_name("SEÑOR") is True  # Spanish

    def test_greeting_words_rejected(self):
        """Greeting words are rejected."""
        assert _is_false_positive_name("HELLO") is True
        assert _is_false_positive_name("DEAR") is True
        assert _is_false_positive_name("REGARDS") is True


# =============================================================================
# FALSE POSITIVE NAMES SET TESTS
# =============================================================================

class TestFalsePositiveNamesSet:
    """Tests for the FALSE_POSITIVE_NAMES constant."""

    def test_contains_document_types(self):
        """Contains common document types."""
        assert "LABORATORY" in FALSE_POSITIVE_NAMES
        assert "REPORT" in FALSE_POSITIVE_NAMES
        assert "CERTIFICATE" in FALSE_POSITIVE_NAMES

    def test_contains_field_labels(self):
        """Contains common field labels."""
        assert "MRN" in FALSE_POSITIVE_NAMES
        assert "DOB" in FALSE_POSITIVE_NAMES
        assert "SSN" in FALSE_POSITIVE_NAMES

    def test_contains_state_abbreviations(self):
        """Contains US state abbreviations."""
        assert "PA" in FALSE_POSITIVE_NAMES
        assert "MD" in FALSE_POSITIVE_NAMES
        assert "NY" in FALSE_POSITIVE_NAMES

    def test_set_is_not_empty(self):
        """Set is populated."""
        assert len(FALSE_POSITIVE_NAMES) > 100

    def test_all_uppercase(self):
        """All entries are uppercase."""
        for name in FALSE_POSITIVE_NAMES:
            assert name == name.upper(), f"{name} is not uppercase"


# =============================================================================
# PATTERNS LIST TESTS
# =============================================================================

class TestPatternsList:
    """Tests for the PATTERNS constant."""

    def test_patterns_not_empty(self):
        """PATTERNS list is populated."""
        assert len(PATTERNS) > 10

    def test_patterns_are_tuples(self):
        """Each pattern is a tuple of (regex, type, confidence, group)."""
        for pattern in PATTERNS:
            assert isinstance(pattern, tuple)
            assert len(pattern) == 4

    def test_patterns_have_compiled_regex(self):
        """First element is compiled regex."""
        for pattern in PATTERNS:
            assert hasattr(pattern[0], 'pattern')  # Compiled regex has pattern attr

    def test_patterns_have_entity_type(self):
        """Second element is entity type string."""
        for pattern in PATTERNS:
            assert isinstance(pattern[1], str)
            assert len(pattern[1]) > 0

    def test_patterns_have_confidence(self):
        """Third element is confidence float."""
        for pattern in PATTERNS:
            assert isinstance(pattern[2], float)
            assert 0.0 <= pattern[2] <= 1.0

    def test_patterns_have_group_index(self):
        """Fourth element is group index int."""
        for pattern in PATTERNS:
            assert isinstance(pattern[3], int)
            assert pattern[3] >= 0


# =============================================================================
# PHONE PATTERN TESTS
# =============================================================================

class TestPhonePatterns:
    """Tests for phone number pattern matching."""

    def test_phone_parentheses_format(self):
        """Matches (XXX) XXX-XXXX format."""
        phone_patterns = [p for p in PATTERNS if p[1] == 'PHONE']
        text = "(555) 123-4567"

        matched = False
        for pattern, entity_type, conf, group in phone_patterns:
            if pattern.search(text):
                matched = True
                break
        assert matched, f"Failed to match {text}"

    def test_phone_dash_format(self):
        """Matches XXX-XXX-XXXX format."""
        phone_patterns = [p for p in PATTERNS if p[1] == 'PHONE']
        text = "555-123-4567"

        matched = False
        for pattern, entity_type, conf, group in phone_patterns:
            if pattern.search(text):
                matched = True
                break
        assert matched, f"Failed to match {text}"

    def test_phone_dot_format(self):
        """Matches XXX.XXX.XXXX format."""
        phone_patterns = [p for p in PATTERNS if p[1] == 'PHONE']
        text = "555.123.4567"

        matched = False
        for pattern, entity_type, conf, group in phone_patterns:
            if pattern.search(text):
                matched = True
                break
        assert matched, f"Failed to match {text}"

    def test_labeled_phone(self):
        """Matches labeled phone: 'phone: XXX-XXX-XXXX'."""
        phone_patterns = [p for p in PATTERNS if p[1] == 'PHONE']
        text = "phone: 555-123-4567"

        matched = False
        for pattern, entity_type, conf, group in phone_patterns:
            if pattern.search(text):
                matched = True
                break
        assert matched, f"Failed to match {text}"


# =============================================================================
# EMAIL PATTERN TESTS
# =============================================================================

class TestEmailPatterns:
    """Tests for email pattern matching."""

    def test_simple_email(self):
        """Matches simple email format."""
        email_patterns = [p for p in PATTERNS if p[1] == 'EMAIL']
        if not email_patterns:
            pytest.skip("No EMAIL patterns defined")

        text = "john.doe@example.com"

        matched = False
        for pattern, entity_type, conf, group in email_patterns:
            if pattern.search(text):
                matched = True
                break
        assert matched, f"Failed to match {text}"


# =============================================================================
# ADD PATTERN FUNCTION TESTS
# =============================================================================

class TestAddPattern:
    """Tests for add_pattern helper function."""

    def test_adds_to_patterns_list(self):
        """add_pattern adds to PATTERNS list."""
        initial_count = len(PATTERNS)

        add_pattern(r'TEST_PATTERN_\d+', 'TEST_TYPE', 0.75)

        assert len(PATTERNS) == initial_count + 1

    def test_pattern_is_compiled(self):
        """Added pattern is compiled regex."""
        add_pattern(r'UNIQUE_TEST_\d+', 'UNIQUE_TEST', 0.80)

        # Find the pattern we just added
        found = None
        for p in PATTERNS:
            if p[1] == 'UNIQUE_TEST':
                found = p
                break

        assert found is not None
        assert hasattr(found[0], 'pattern')

    def test_default_group_is_zero(self):
        """Default group index is 0."""
        add_pattern(r'DEFAULT_GROUP_\d+', 'DEFAULT_GROUP_TEST', 0.85)

        found = None
        for p in PATTERNS:
            if p[1] == 'DEFAULT_GROUP_TEST':
                found = p
                break

        assert found is not None
        assert found[3] == 0  # Group index

    def test_custom_group(self):
        """Can specify custom group index."""
        add_pattern(r'CUSTOM_GROUP_(\d+)', 'CUSTOM_GROUP_TEST', 0.85, group=1)

        found = None
        for p in PATTERNS:
            if p[1] == 'CUSTOM_GROUP_TEST':
                found = p
                break

        assert found is not None
        assert found[3] == 1

    def test_regex_flags(self):
        """Can specify regex flags."""
        add_pattern(r'case_insensitive', 'FLAG_TEST', 0.85, flags=re.IGNORECASE)

        found = None
        for p in PATTERNS:
            if p[1] == 'FLAG_TEST':
                found = p
                break

        assert found is not None
        # Should match regardless of case
        assert found[0].search("CASE_INSENSITIVE") is not None
        assert found[0].search("case_insensitive") is not None


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for pattern detection."""

    def test_empty_string_not_false_positive(self):
        """Empty string is handled gracefully."""
        result = _is_false_positive_name("")
        assert result is True  # Empty/short strings are rejected

    def test_whitespace_only_is_false_positive(self):
        """Whitespace-only is rejected."""
        assert _is_false_positive_name("   ") is True

    def test_numbers_only_not_checked_as_name(self):
        """Numbers-only string is not in false positive set."""
        # Numbers aren't in FALSE_POSITIVE_NAMES and are 5 chars (>= 3)
        # So they pass the false positive check (would be filtered elsewhere)
        result = _is_false_positive_name("12345")
        assert result is False  # Not in false positive names

    def test_unicode_names_handled(self):
        """Unicode names are handled."""
        # José is a valid name
        result = _is_false_positive_name("José García")
        assert result is False  # Valid name

    def test_long_false_positive_phrase(self):
        """Long phrase of false positives is rejected."""
        result = _is_false_positive_name("LABORATORY REPORT DOCUMENT FORM")
        assert result is True

    def test_real_provider_name_with_md(self):
        """Real provider name with MD credential passes."""
        result = _is_false_positive_name("Dr. John Smith, MD")
        # This is a valid provider name
        assert result is False

"""Tests for span cleanup functions in merger.py.

Tests trimming, boundary snapping, and filtering functions.
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.merger import (
    trim_span_whitespace,
    trim_trailing_punctuation,
    trim_names_at_newlines,
    trim_name_at_non_name_words,
    snap_to_word_boundaries,
    filter_short_names,
    filter_city_as_name,
    fix_misclassified_emails,
    merge_adjacent_addresses,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test", tier=2):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
    )


class TestTrimSpanWhitespace:
    """Tests for trim_span_whitespace()."""

    def test_leading_whitespace_trimmed(self):
        """Leading whitespace is removed from span."""
        text = "  John Smith is here"
        span = make_span("  John Smith", start=0)
        result = trim_span_whitespace([span], text)

        assert len(result) == 1
        assert result[0].start == 2
        assert result[0].end == 12
        assert result[0].text == "John Smith"

    def test_trailing_whitespace_trimmed(self):
        """Trailing whitespace is removed from span."""
        text = "John Smith   is here"
        span = make_span("John Smith   ", start=0)
        result = trim_span_whitespace([span], text)

        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 10
        assert result[0].text == "John Smith"

    def test_both_sides_trimmed(self):
        """Whitespace on both sides is trimmed."""
        text = "  John Smith  "
        span = make_span("  John Smith  ", start=0)
        result = trim_span_whitespace([span], text)

        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_no_whitespace_unchanged(self):
        """Spans without surrounding whitespace are unchanged."""
        text = "John Smith is here"
        span = make_span("John Smith", start=0)
        result = trim_span_whitespace([span], text)

        assert len(result) == 1
        assert result[0].start == 0
        assert result[0].end == 10
        assert result[0].text == "John Smith"

    def test_all_whitespace_discarded(self):
        """Span that is only whitespace is discarded."""
        text = "   "
        span = make_span("   ", start=0)
        result = trim_span_whitespace([span], text)

        assert len(result) == 0

    def test_preserves_span_metadata(self):
        """Non-position metadata is preserved after trimming."""
        text = "  John Smith  "
        span = make_span("  John Smith  ", start=0, confidence=0.85, detector="ml", tier=1)
        result = trim_span_whitespace([span], text)

        assert result[0].confidence == 0.85
        assert result[0].detector == "ml"
        assert result[0].tier == Tier.ML


class TestTrimTrailingPunctuation:
    """Tests for trim_trailing_punctuation()."""

    def test_email_punctuation_trimmed(self):
        """Trailing punctuation on EMAIL spans is trimmed."""
        text = "Contact: john@example.com."
        span = make_span("john@example.com.", start=9, entity_type="EMAIL")
        result = trim_trailing_punctuation([span], text)

        assert result[0].text == "john@example.com"
        assert result[0].end == 25

    def test_phone_punctuation_trimmed(self):
        """Trailing punctuation on PHONE spans is trimmed."""
        text = "Call 555-123-4567!"
        span = make_span("555-123-4567!", start=5, entity_type="PHONE")
        result = trim_trailing_punctuation([span], text)

        assert result[0].text == "555-123-4567"

    def test_ssn_punctuation_trimmed(self):
        """Trailing punctuation on SSN spans is trimmed."""
        text = "SSN: 123-45-6789."
        span = make_span("123-45-6789.", start=5, entity_type="SSN")
        result = trim_trailing_punctuation([span], text)

        assert result[0].text == "123-45-6789"

    def test_name_punctuation_not_trimmed(self):
        """NAME spans keep trailing punctuation (could be Jr., Sr., etc.)."""
        text = "Dr. John Smith, Jr."
        span = make_span("John Smith, Jr.", start=4, entity_type="NAME")
        result = trim_trailing_punctuation([span], text)

        # Should be unchanged
        assert result[0].text == "John Smith, Jr."

    def test_multiple_punctuation_marks_trimmed(self):
        """Multiple trailing punctuation marks are all trimmed."""
        text = "MRN: 123456789..."
        span = make_span("123456789...", start=5, entity_type="MRN")
        result = trim_trailing_punctuation([span], text)

        assert result[0].text == "123456789"


class TestTrimNamesAtNewlines:
    """Tests for trim_names_at_newlines()."""

    def test_name_trimmed_at_newline(self):
        """NAME spans are trimmed at newline characters."""
        text = "Dr. John Smith\nDepartment of Medicine"
        span = make_span("Dr. John Smith\nDepartment", start=0, entity_type="NAME")
        result = trim_names_at_newlines([span], text)

        assert len(result) == 1
        assert result[0].text == "Dr. John Smith"
        assert result[0].end == 14

    def test_name_without_newline_unchanged(self):
        """NAME spans without newlines are unchanged."""
        text = "Dr. John Smith is here"
        span = make_span("Dr. John Smith", start=0, entity_type="NAME")
        result = trim_names_at_newlines([span], text)

        assert result[0].text == "Dr. John Smith"

    def test_non_name_types_unchanged(self):
        """Non-NAME spans are not trimmed at newlines."""
        text = "Address: 123 Main St\nSpringfield"
        span = make_span("123 Main St\nSpringfield", start=9, entity_type="ADDRESS")
        result = trim_names_at_newlines([span], text)

        # ADDRESS should be unchanged
        assert result[0].text == "123 Main St\nSpringfield"

    def test_very_short_result_discarded(self):
        """If trimming leaves < 2 chars, span is discarded."""
        text = "A\nBIG HEADER"
        span = make_span("A\nBIG", start=0, entity_type="NAME")
        result = trim_names_at_newlines([span], text)

        # "A" is only 1 char, should be discarded
        assert len(result) == 0


class TestTrimNameAtNonNameWords:
    """Tests for trim_name_at_non_name_words()."""

    def test_non_name_word_trimmed(self):
        """Trailing non-name words are trimmed."""
        text = "John Smith appears to be healthy"
        span = make_span("John Smith appears", start=0, entity_type="NAME")
        result = trim_name_at_non_name_words([span], text)

        # "appears" is in NON_NAME_WORDS
        assert result[0].text == "John Smith"

    def test_lowercase_long_word_trimmed(self):
        """Lowercase words > 5 chars (not connectors) are trimmed."""
        text = "John Smith treatment was successful"
        span = make_span("John Smith treatment", start=0, entity_type="NAME")
        result = trim_name_at_non_name_words([span], text)

        # "treatment" is lowercase and > 5 chars
        assert result[0].text == "John Smith"

    def test_name_connectors_preserved(self):
        """Name connectors (van, von, de) are not trimmed."""
        text = "Ludwig van Beethoven composed music"
        span = make_span("Ludwig van Beethoven", start=0, entity_type="NAME")
        result = trim_name_at_non_name_words([span], text)

        # "van" is a connector, should be preserved
        assert result[0].text == "Ludwig van Beethoven"

    def test_single_word_name_unchanged(self):
        """Single-word names are not trimmed."""
        text = "Madonna performed yesterday"
        span = make_span("Madonna", start=0, entity_type="NAME")
        result = trim_name_at_non_name_words([span], text)

        assert result[0].text == "Madonna"

    def test_multiple_non_name_words_trimmed(self):
        """Multiple trailing non-name words are all trimmed."""
        # Use words that are ALL in NON_NAME_WORDS (e.g., "was", "the")
        text = "Dr. Smith was the one"
        span = make_span("Dr. Smith was the", start=0, entity_type="NAME")
        result = trim_name_at_non_name_words([span], text)

        # "was" and "the" are both in NON_NAME_WORDS, should be trimmed
        assert result[0].text == "Dr. Smith"


class TestSnapToWordBoundaries:
    """Tests for snap_to_word_boundaries()."""

    def test_mid_word_start_expanded(self):
        """Span starting mid-word expands left to word start."""
        text = "Hello John Smith"
        # Span starts at "ohn" (missing the J)
        span = Span(start=7, end=11, text="ohn ", entity_type="NAME",
                    confidence=0.9, detector="test", tier=Tier.PATTERN)
        result = snap_to_word_boundaries([span], text)

        assert result[0].start == 6  # Expanded to include "J"
        assert "John" in result[0].text

    def test_mid_word_end_expanded(self):
        """Span ending mid-word expands right to word end."""
        text = "Hello John Smith"
        # Span ends at "Smi" (missing "th")
        span = Span(start=11, end=14, text="Smi", entity_type="NAME",
                    confidence=0.9, detector="test", tier=Tier.PATTERN)
        result = snap_to_word_boundaries([span], text)

        assert result[0].end == 16  # Expanded to include "th"
        assert result[0].text == "Smith"

    def test_word_boundary_span_unchanged(self):
        """Span already on word boundaries is unchanged."""
        text = "Hello John Smith"
        span = make_span("John", start=6, entity_type="NAME")
        result = snap_to_word_boundaries([span], text)

        assert result[0].start == 6
        assert result[0].end == 10
        assert result[0].text == "John"

    def test_expansion_limit_enforced(self):
        """Expansion is limited to prevent runaway."""
        text = "Supercalifragilisticexpialidocious name"
        # Start mid-word in the long word - expansion would be > 10 chars
        span = Span(start=20, end=25, text="xpial", entity_type="NAME",
                    confidence=0.9, detector="test", tier=Tier.PATTERN)
        result = snap_to_word_boundaries([span], text)

        # Should keep original due to expansion limit
        assert result[0].text == "xpial"

    def test_confidence_reduced_on_expansion(self):
        """Confidence is slightly reduced when boundaries are adjusted."""
        text = "Hello John Smith"
        span = Span(start=7, end=10, text="ohn", entity_type="NAME",
                    confidence=0.9, detector="test", tier=Tier.PATTERN)
        result = snap_to_word_boundaries([span], text)

        assert result[0].confidence == pytest.approx(0.9 * 0.95)

    def test_invalid_span_filtered(self):
        """Invalid spans are filtered out with warning."""
        text = "Short"
        span = Span(start=0, end=100, text="x" * 100, entity_type="NAME",
                    confidence=0.9, detector="test", tier=Tier.PATTERN)
        result = snap_to_word_boundaries([span], text)

        assert len(result) == 0


class TestFilterShortNames:
    """Tests for filter_short_names()."""

    def test_single_initial_filtered(self):
        """Single initials like 'K.' are filtered."""
        span = make_span("K.", entity_type="NAME")
        result = filter_short_names([span])

        assert len(result) == 0

    def test_two_char_name_filtered(self):
        """Two-character 'names' are filtered."""
        span = make_span("Jo", entity_type="NAME")
        result = filter_short_names([span])

        assert len(result) == 0

    def test_three_char_name_kept(self):
        """Three-character names (minimum) are kept."""
        span = make_span("Joe", entity_type="NAME")
        result = filter_short_names([span])

        assert len(result) == 1
        assert result[0].text == "Joe"

    def test_non_name_types_not_filtered(self):
        """Short non-NAME spans are not filtered."""
        span = make_span("TX", entity_type="ADDRESS")  # State abbreviation
        result = filter_short_names([span])

        assert len(result) == 1

    def test_name_variants_filtered(self):
        """NAME_PATIENT, NAME_PROVIDER etc. are also filtered if short."""
        spans = [
            make_span("K.", entity_type="NAME_PATIENT"),
            make_span("R.", entity_type="NAME_PROVIDER"),
        ]
        result = filter_short_names(spans)

        assert len(result) == 0


class TestFilterCityAsName:
    """Tests for filter_city_as_name()."""

    def test_city_state_pattern_reclassified(self):
        """'CITY, ST' pattern is reclassified from NAME to ADDRESS."""
        span = make_span("HARRISBURG, PA", entity_type="NAME_PROVIDER")
        result = filter_city_as_name([span])

        assert len(result) == 1
        assert result[0].entity_type == "ADDRESS"

    def test_city_suffix_reclassified(self):
        """Names ending in city suffixes (-burg, -ville) are reclassified."""
        test_cases = [
            ("Pittsburgh", "ADDRESS"),
            ("Springfield", "ADDRESS"),
            ("Nashville", "ADDRESS"),
            ("Harrisburg", "ADDRESS"),
        ]
        for city_name, expected_type in test_cases:
            span = make_span(city_name, entity_type="NAME")
            result = filter_city_as_name([span])
            assert result[0].entity_type == expected_type, f"{city_name} should be {expected_type}"

    def test_real_names_not_reclassified(self):
        """Actual names are not reclassified."""
        test_cases = ["John Smith", "Mary Johnson", "Robert Williams"]
        for name in test_cases:
            span = make_span(name, entity_type="NAME")
            result = filter_city_as_name([span])
            assert result[0].entity_type == "NAME", f"{name} should stay NAME"

    def test_confidence_reduced_for_suffix_match(self):
        """Confidence is reduced when reclassifying based on suffix."""
        span = make_span("Springfield", entity_type="NAME", confidence=0.9)
        result = filter_city_as_name([span])

        assert result[0].confidence == pytest.approx(0.9 * 0.9)


class TestFixMisclassifiedEmails:
    """Tests for fix_misclassified_emails()."""

    def test_email_reclassified_from_name(self):
        """NAME span that looks like email is reclassified to EMAIL."""
        span = make_span("john.smith@example.com", entity_type="NAME")
        result = fix_misclassified_emails([span])

        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"

    def test_email_with_trailing_punctuation(self):
        """Email with trailing punctuation is handled."""
        span = make_span("john@example.com.", entity_type="NAME")
        result = fix_misclassified_emails([span])

        assert result[0].entity_type == "EMAIL"
        assert result[0].text == "john@example.com"  # Punctuation removed

    def test_non_email_name_unchanged(self):
        """Regular NAME spans are unchanged."""
        span = make_span("John Smith", entity_type="NAME")
        result = fix_misclassified_emails([span])

        assert result[0].entity_type == "NAME"

    def test_name_variants_checked(self):
        """NAME_PATIENT, NAME_PROVIDER etc. are also checked."""
        span = make_span("patient@hospital.org", entity_type="NAME_PATIENT")
        result = fix_misclassified_emails([span])

        assert result[0].entity_type == "EMAIL"


class TestMergeAdjacentAddresses:
    """Tests for merge_adjacent_addresses()."""

    def test_adjacent_addresses_merged(self):
        """Adjacent ADDRESS spans are merged."""
        text = "Address: 123 Main St, Springfield, IL 62701"
        spans = [
            make_span("123 Main St", start=9, entity_type="ADDRESS"),
            make_span("Springfield, IL 62701", start=22, entity_type="ADDRESS"),
        ]
        result = merge_adjacent_addresses(spans, text)

        # Should merge into one span
        address_spans = [s for s in result if s.entity_type == "ADDRESS"]
        assert len(address_spans) == 1
        assert "123 Main St" in address_spans[0].text
        assert "62701" in address_spans[0].text

    def test_non_adjacent_addresses_not_merged(self):
        """Non-adjacent ADDRESS spans stay separate."""
        text = "From 123 Main St in the city of Springfield IL 62701"
        spans = [
            make_span("123 Main St", start=5, entity_type="ADDRESS"),
            make_span("62701", start=47, entity_type="ADDRESS"),
        ]
        result = merge_adjacent_addresses(spans, text)

        address_spans = [s for s in result if s.entity_type == "ADDRESS"]
        assert len(address_spans) == 2

    def test_other_types_not_merged(self):
        """Non-ADDRESS types are not affected."""
        text = "John Smith and Jane Doe"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Jane Doe", start=15, entity_type="NAME"),
        ]
        result = merge_adjacent_addresses(spans, text)

        assert len(result) == 2

    def test_merged_span_takes_highest_tier(self):
        """Merged span gets the highest tier from components."""
        text = "123 Main St, Springfield"
        spans = [
            make_span("123 Main St", start=0, entity_type="ADDRESS", tier=1),
            make_span("Springfield", start=13, entity_type="ADDRESS", tier=3),
        ]
        result = merge_adjacent_addresses(spans, text)

        address_spans = [s for s in result if s.entity_type == "ADDRESS"]
        assert address_spans[0].tier == Tier.STRUCTURED  # tier 3

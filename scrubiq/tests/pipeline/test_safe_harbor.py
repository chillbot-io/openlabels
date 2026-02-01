"""Tests for HIPAA Safe Harbor transformations in safe_harbor.py.

Tests date year extraction, age generalization (>89 → 90+),
and ZIP code truncation per 45 CFR §164.514(b)(2).
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.safe_harbor import (
    extract_year,
    generalize_age,
    truncate_zip,
    apply_safe_harbor,
    HIPAA_ZERO_PREFIXES,
    DATE_PATTERNS,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test",
              tier=2, safe_harbor_value=None):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
        safe_harbor_value=safe_harbor_value,
    )


# =============================================================================
# HIPAA ZERO PREFIXES TESTS
# =============================================================================

class TestHipaaZeroPrefixes:
    """Tests for HIPAA_ZERO_PREFIXES constant."""

    def test_contains_known_low_population_prefixes(self):
        """Contains known low-population ZIP prefixes."""
        # These are documented low-population prefixes
        assert "036" in HIPAA_ZERO_PREFIXES  # Wyoming
        assert "102" in HIPAA_ZERO_PREFIXES  # New York
        assert "893" in HIPAA_ZERO_PREFIXES  # Nevada

    def test_does_not_contain_high_population_prefixes(self):
        """Does not contain high-population prefixes."""
        # NYC (100xx), LA (900xx), Chicago (606xx) are high population
        assert "100" not in HIPAA_ZERO_PREFIXES
        assert "900" not in HIPAA_ZERO_PREFIXES
        assert "606" not in HIPAA_ZERO_PREFIXES

    def test_is_frozenset(self):
        """HIPAA_ZERO_PREFIXES is immutable."""
        assert isinstance(HIPAA_ZERO_PREFIXES, frozenset)


# =============================================================================
# EXTRACT YEAR TESTS
# =============================================================================

class TestExtractYear:
    """Tests for extract_year()."""

    def test_bare_year(self):
        """Extracts bare 4-digit year."""
        assert extract_year("1980") == "1980"
        assert extract_year("2023") == "2023"

    def test_mm_dd_yyyy_slash(self):
        """Extracts year from MM/DD/YYYY format."""
        assert extract_year("03/15/1985") == "1985"
        assert extract_year("12/31/2000") == "2000"

    def test_mm_dd_yyyy_dash(self):
        """Extracts year from MM-DD-YYYY format."""
        assert extract_year("03-15-1985") == "1985"
        assert extract_year("12-31-2000") == "2000"

    def test_iso_format(self):
        """Extracts year from ISO YYYY-MM-DD format."""
        assert extract_year("1985-03-15") == "1985"
        assert extract_year("2023-01-01") == "2023"

    def test_month_name_format(self):
        """Extracts year from 'Month DD, YYYY' format."""
        assert extract_year("March 15, 1985") == "1985"
        assert extract_year("December 31 2000") == "2000"

    def test_dd_month_yyyy_format(self):
        """Extracts year from 'DD Month YYYY' format."""
        assert extract_year("15 March 1985") == "1985"
        assert extract_year("31 December 2000") == "2000"

    def test_no_year_returns_none(self):
        """Returns None when no year found."""
        assert extract_year("March 15") is None
        assert extract_year("03/15") is None
        assert extract_year("no date here") is None

    def test_embedded_in_text(self):
        """Extracts year even when embedded in text."""
        assert extract_year("DOB: 03/15/1985") == "1985"
        assert extract_year("Born on March 15, 1985 in NYC") == "1985"


# =============================================================================
# GENERALIZE AGE TESTS
# =============================================================================

class TestGeneralizeAge:
    """Tests for generalize_age()."""

    def test_age_under_90_unchanged(self):
        """Ages under 90 are unchanged."""
        assert generalize_age("25") == "25"
        assert generalize_age("89") == "89"
        assert generalize_age("0") == "0"

    def test_age_90_becomes_90_plus(self):
        """Age 90 becomes '90+' per HIPAA."""
        assert generalize_age("90") == "90+"

    def test_age_over_90_becomes_90_plus(self):
        """Ages over 90 become '90+'."""
        assert generalize_age("95") == "90+"
        assert generalize_age("100") == "90+"
        assert generalize_age("105") == "90+"

    def test_invalid_age_unchanged(self):
        """Non-numeric ages are unchanged."""
        assert generalize_age("unknown") == "unknown"
        assert generalize_age("N/A") == "N/A"
        assert generalize_age("") == ""

    def test_age_with_text_unchanged(self):
        """Ages with text units are returned unchanged (non-numeric)."""
        assert generalize_age("25 years") == "25 years"


# =============================================================================
# TRUNCATE ZIP TESTS
# =============================================================================

class TestTruncateZip:
    """Tests for truncate_zip()."""

    def test_5_digit_zip_truncated_to_3(self):
        """5-digit ZIP truncated to first 3 digits."""
        assert truncate_zip("12345") == "123"
        assert truncate_zip("90210") == "902"

    def test_9_digit_zip_truncated_to_3(self):
        """9-digit ZIP+4 truncated to first 3 digits."""
        assert truncate_zip("12345-6789") == "123"
        assert truncate_zip("902101234") == "902"

    def test_low_population_prefix_becomes_000(self):
        """Low-population prefixes become '000'."""
        # Test some known HIPAA zero prefixes
        assert truncate_zip("03601") == "000"  # 036xx
        assert truncate_zip("10201") == "000"  # 102xx
        assert truncate_zip("89301") == "000"  # 893xx

    def test_high_population_prefix_preserved(self):
        """High-population prefixes keep first 3 digits."""
        assert truncate_zip("10001") == "100"  # NYC
        assert truncate_zip("90210") == "902"  # Beverly Hills
        assert truncate_zip("60601") == "606"  # Chicago

    def test_short_zip_unchanged(self):
        """ZIP codes with fewer than 3 digits are unchanged."""
        assert truncate_zip("12") == "12"
        assert truncate_zip("1") == "1"
        assert truncate_zip("") == ""

    def test_zip_with_spaces(self):
        """ZIP with spaces is handled."""
        assert truncate_zip("123 45") == "123"

    def test_formatted_zip(self):
        """Formatted ZIP (with dash) is handled."""
        assert truncate_zip("12345-6789") == "123"


# =============================================================================
# APPLY SAFE HARBOR TESTS
# =============================================================================

class TestApplySafeHarbor:
    """Tests for apply_safe_harbor()."""

    def test_date_gets_year_only(self):
        """DATE type gets year-only safe harbor value."""
        spans = [make_span("03/15/1985", entity_type="DATE")]
        result = apply_safe_harbor(spans, "session-123")

        assert len(result) == 1
        assert result[0].safe_harbor_value == "1985"

    def test_date_dob_gets_year_only(self):
        """DATE_DOB type gets year-only safe harbor value."""
        spans = [make_span("March 15, 1985", entity_type="DATE_DOB")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "1985"

    def test_date_range_gets_year(self):
        """DATE_RANGE type gets year-only safe harbor value."""
        spans = [make_span("2020-01-01", entity_type="DATE_RANGE")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "2020"

    def test_birth_year_gets_year(self):
        """BIRTH_YEAR type gets year-only safe harbor value."""
        spans = [make_span("1985", entity_type="BIRTH_YEAR")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "1985"

    def test_age_over_89_gets_90_plus(self):
        """AGE over 89 gets '90+' safe harbor value."""
        spans = [make_span("95", entity_type="AGE")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "90+"

    def test_age_under_90_unchanged(self):
        """AGE under 90 keeps original value."""
        spans = [make_span("65", entity_type="AGE")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "65"

    def test_zip_truncated_to_3_digits(self):
        """ZIP gets truncated to 3 digits."""
        spans = [make_span("12345", entity_type="ZIP")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "123"

    def test_zip_low_population_becomes_000(self):
        """ZIP in low-population area becomes '000'."""
        spans = [make_span("03601", entity_type="ZIP")]  # 036 is low-population
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "000"

    def test_other_types_get_none(self):
        """Other entity types get None (token becomes safe harbor value later)."""
        spans = [
            make_span("John Smith", entity_type="NAME"),
            make_span("123-45-6789", entity_type="SSN"),
            make_span("555-123-4567", entity_type="PHONE"),
        ]
        result = apply_safe_harbor(spans, "session-123")

        for span in result:
            assert span.safe_harbor_value is None

    def test_preserves_span_metadata(self):
        """All span metadata is preserved."""
        span = Span(
            start=10,
            end=20,
            text="03/15/1985",
            entity_type="DATE",
            confidence=0.95,
            detector="patterns",
            tier=Tier.PATTERN,
            needs_review=True,
            review_reason="Check date",
        )
        result = apply_safe_harbor([span], "session-123")

        assert result[0].start == 10
        assert result[0].end == 20
        assert result[0].text == "03/15/1985"
        assert result[0].confidence == 0.95
        assert result[0].detector == "patterns"
        assert result[0].tier == Tier.PATTERN
        assert result[0].needs_review is True
        assert result[0].review_reason == "Check date"
        assert result[0].safe_harbor_value == "1985"

    def test_immutable_pattern(self):
        """Original spans are not modified."""
        original = make_span("03/15/1985", entity_type="DATE")
        original_shv = original.safe_harbor_value

        apply_safe_harbor([original], "session-123")

        # Original span unchanged
        assert original.safe_harbor_value == original_shv

    def test_empty_list_returns_empty(self):
        """Empty span list returns empty list."""
        result = apply_safe_harbor([], "session-123")
        assert result == []

    def test_multiple_spans_mixed_types(self):
        """Multiple spans with different types are all processed."""
        spans = [
            make_span("03/15/1985", entity_type="DATE"),
            make_span("95", entity_type="AGE"),
            make_span("12345", entity_type="ZIP"),
            make_span("John Smith", entity_type="NAME"),
        ]
        result = apply_safe_harbor(spans, "session-123")

        assert len(result) == 4
        assert result[0].safe_harbor_value == "1985"  # DATE → year
        assert result[1].safe_harbor_value == "90+"   # AGE > 89
        assert result[2].safe_harbor_value == "123"   # ZIP → 3 digits
        assert result[3].safe_harbor_value is None    # NAME → None


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for safe harbor transformations."""

    def test_date_without_year(self):
        """Date without extractable year gets None."""
        spans = [make_span("March 15", entity_type="DATE")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value is None

    def test_already_has_safe_harbor_value(self):
        """Span with existing safe_harbor_value gets updated."""
        span = make_span("03/15/1985", entity_type="DATE", safe_harbor_value="old_value")
        result = apply_safe_harbor([span], "session-123")

        assert result[0].safe_harbor_value == "1985"

    def test_same_safe_harbor_value_returns_same_span(self):
        """If new value matches existing, same span is returned."""
        span = make_span("03/15/1985", entity_type="DATE", safe_harbor_value="1985")
        result = apply_safe_harbor([span], "session-123")

        assert result[0] is span  # Same object

    def test_age_89_not_generalized(self):
        """Age 89 is NOT generalized (only >89)."""
        spans = [make_span("89", entity_type="AGE")]
        result = apply_safe_harbor(spans, "session-123")

        assert result[0].safe_harbor_value == "89"

    def test_various_zip_formats(self):
        """Various ZIP formats are handled correctly."""
        test_cases = [
            ("12345", "123"),
            ("12345-6789", "123"),
            ("123456789", "123"),
            ("123 45", "123"),
        ]
        for zip_input, expected in test_cases:
            spans = [make_span(zip_input, entity_type="ZIP")]
            result = apply_safe_harbor(spans, "session-123")
            assert result[0].safe_harbor_value == expected, f"Failed for {zip_input}"


# =============================================================================
# DATE PATTERNS CONSTANT
# =============================================================================

class TestDatePatterns:
    """Tests for DATE_PATTERNS constant."""

    def test_has_multiple_patterns(self):
        """DATE_PATTERNS has multiple patterns for different formats."""
        assert len(DATE_PATTERNS) >= 4

    def test_patterns_are_compiled(self):
        """All patterns are pre-compiled regex objects."""
        import re
        for pattern in DATE_PATTERNS:
            assert isinstance(pattern, re.Pattern)

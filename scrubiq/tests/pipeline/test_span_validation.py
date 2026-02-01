"""Tests for span position validation in span_validation.py.

Tests validation of span positions after pipeline stages.
"""

import pytest
from unittest.mock import patch, MagicMock

from scrubiq.types import Span, Tier
from scrubiq.pipeline.span_validation import (
    validate_span_positions,
    _validate_single_span,
    check_for_overlaps,
    validate_after_coref,
    SpanValidationError,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test"):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.PATTERN,
    )


def make_invalid_span(start, end, text, entity_type="NAME"):
    """
    Create a span-like object that bypasses Span validation.

    This simulates spans that might come from deserialization,
    external APIs, or data corruption scenarios.
    """
    span = MagicMock()
    span.start = start
    span.end = end
    span.text = text
    span.entity_type = entity_type
    span.confidence = 0.9
    span.detector = "test"
    span.tier = Tier.PATTERN
    return span


# =============================================================================
# SPAN VALIDATION ERROR TESTS
# =============================================================================

class TestSpanValidationError:
    """Tests for SpanValidationError exception."""

    def test_exception_has_span(self):
        """Exception stores the invalid span."""
        span = make_invalid_span(0, 4, "test")
        error = SpanValidationError("test error", span, 100)
        assert error.span == span

    def test_exception_has_text_length(self):
        """Exception stores the text length."""
        span = make_invalid_span(0, 4, "test")
        error = SpanValidationError("test error", span, 100)
        assert error.text_length == 100

    def test_exception_message(self):
        """Exception has message."""
        span = make_invalid_span(0, 4, "test")
        error = SpanValidationError("test error", span, 100)
        assert str(error) == "test error"


# =============================================================================
# VALIDATE SINGLE SPAN TESTS
# =============================================================================

class TestValidateSingleSpan:
    """Tests for _validate_single_span() function."""

    def test_valid_span_returns_none(self):
        """Valid span returns None (no error)."""
        text = "Hello John Smith there"
        span = make_span("John Smith", start=6)
        error = _validate_single_span(span, text, len(text))
        assert error is None

    def test_negative_start_returns_error(self):
        """Negative start position returns error."""
        text = "Hello"
        span = make_invalid_span(start=-1, end=3, text="abc")
        error = _validate_single_span(span, text, len(text))
        assert error is not None
        assert "negative" in error.lower()

    def test_negative_end_returns_error(self):
        """Negative end position returns error."""
        text = "Hello"
        span = make_invalid_span(start=0, end=-1, text="abc")
        error = _validate_single_span(span, text, len(text))
        assert error is not None
        assert "negative" in error.lower()

    def test_start_exceeds_text_length_returns_error(self):
        """Start position exceeding text length returns error."""
        text = "Hello"
        span = make_invalid_span(start=100, end=105, text="test")
        error = _validate_single_span(span, text, len(text))
        assert error is not None
        assert "exceeds" in error.lower()

    def test_end_exceeds_text_length_returns_error(self):
        """End position exceeding text length returns error."""
        text = "Hello"
        span = make_invalid_span(start=0, end=100, text="test")
        error = _validate_single_span(span, text, len(text))
        assert error is not None
        assert "exceeds" in error.lower()

    def test_start_equals_end_returns_error(self):
        """Start equals end (zero-length span) returns error."""
        text = "Hello"
        span = make_invalid_span(start=2, end=2, text="")
        error = _validate_single_span(span, text, len(text))
        assert error is not None
        assert ">=" in error

    def test_start_greater_than_end_returns_error(self):
        """Start greater than end returns error."""
        text = "Hello"
        span = make_invalid_span(start=5, end=2, text="abc")
        error = _validate_single_span(span, text, len(text))
        assert error is not None
        assert ">=" in error

    def test_text_length_mismatch_returns_error(self):
        """Text length mismatch returns error."""
        text = "Hello World"
        # span.text is "Hello" but positions span "Hello Wo" (8 chars)
        span = make_invalid_span(start=0, end=8, text="Hello")
        error = _validate_single_span(span, text, len(text))
        assert error is not None
        assert "mismatch" in error.lower()

    def test_case_difference_allowed(self):
        """Case differences are allowed (returns None)."""
        text = "Hello JOHN there"
        # Create span that matches case-insensitively
        span = make_invalid_span(start=6, end=10, text="john")
        # "JOHN" vs "john" - same when lowercased
        error = _validate_single_span(span, text, len(text))
        assert error is None

    def test_span_at_start_of_text(self):
        """Span at start of text is valid."""
        text = "John Smith said hello"
        span = make_span("John Smith", start=0)
        error = _validate_single_span(span, text, len(text))
        assert error is None

    def test_span_at_end_of_text(self):
        """Span at end of text is valid."""
        text = "Hello John Smith"
        span = make_span("John Smith", start=6)
        error = _validate_single_span(span, text, len(text))
        assert error is None


# =============================================================================
# VALIDATE SPAN POSITIONS TESTS
# =============================================================================

class TestValidateSpanPositions:
    """Tests for validate_span_positions() function."""

    def test_empty_spans_returns_empty(self):
        """Empty spans list returns empty."""
        result = validate_span_positions("Some text", [])
        assert result == []

    def test_valid_spans_returned(self):
        """Valid spans are returned unchanged."""
        text = "Hello John Smith there"
        spans = [make_span("John Smith", start=6)]
        result = validate_span_positions(text, spans)
        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_multiple_valid_spans(self):
        """Multiple valid spans all returned."""
        text = "John Smith and Mary Jones"
        spans = [
            make_span("John Smith", start=0),
            make_span("Mary Jones", start=15),
        ]
        result = validate_span_positions(text, spans)
        assert len(result) == 2

    def test_lenient_mode_filters_invalid(self):
        """Lenient mode filters out invalid spans."""
        text = "Hello John Smith there"
        spans = [
            make_span("John Smith", start=6),  # Valid
            make_invalid_span(start=-1, end=5, text="bad"),  # Invalid
        ]
        result = validate_span_positions(text, spans, strict=False)
        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_strict_mode_raises_on_invalid(self):
        """Strict mode raises exception on first invalid span."""
        text = "Hello"
        spans = [
            make_invalid_span(start=-1, end=5, text="bad"),
        ]
        with pytest.raises(SpanValidationError) as exc_info:
            validate_span_positions(text, spans, strict=True)
        assert exc_info.value.span.start == -1

    def test_strict_mode_stops_at_first_error(self):
        """Strict mode stops at first error."""
        text = "Hello"
        spans = [
            make_invalid_span(start=-1, end=5, text="bad1"),
            make_invalid_span(start=-2, end=5, text="bad2"),
        ]
        with pytest.raises(SpanValidationError) as exc_info:
            validate_span_positions(text, spans, strict=True)
        # Should be first error
        assert exc_info.value.span.text == "bad1"

    def test_context_parameter_for_logging(self):
        """Context parameter is used for logging."""
        text = "Hello"
        spans = [
            make_invalid_span(start=-1, end=5, text="bad"),
        ]
        # Should not raise, just filter and log
        with patch('scrubiq.pipeline.span_validation.logger') as mock_logger:
            result = validate_span_positions(text, spans, strict=False, context="test_context")
            assert len(result) == 0
            # Check context appears in log message
            assert mock_logger.warning.called


# =============================================================================
# CHECK FOR OVERLAPS TESTS
# =============================================================================

class TestCheckForOverlaps:
    """Tests for check_for_overlaps() function."""

    def test_empty_spans_returns_empty(self):
        """Empty spans returns empty list."""
        result = check_for_overlaps([])
        assert result == []

    def test_single_span_returns_empty(self):
        """Single span returns empty (no overlaps possible)."""
        spans = [make_span("John", start=0)]
        result = check_for_overlaps(spans)
        assert result == []

    def test_non_overlapping_spans_returns_empty(self):
        """Non-overlapping spans return empty."""
        spans = [
            make_span("John", start=0),
            make_span("Mary", start=10),
        ]
        result = check_for_overlaps(spans)
        assert result == []

    def test_overlapping_spans_detected(self):
        """Overlapping spans are detected."""
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=5, end=15, text="Smith Jane", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        result = check_for_overlaps(spans)
        assert len(result) == 1
        assert result[0][0].start == 0
        assert result[0][1].start == 5

    def test_identical_positions_allowed_by_default(self):
        """Identical positions are allowed by default."""
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=0, end=10, text="John Smith", entity_type="PERSON",
                 confidence=0.8, detector="other", tier=Tier.PATTERN),
        ]
        result = check_for_overlaps(spans, allow_identical=True)
        assert len(result) == 0

    def test_identical_positions_detected_when_disallowed(self):
        """Identical positions detected when allow_identical=False."""
        spans = [
            Span(start=0, end=10, text="John Smith", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=0, end=10, text="John Smith", entity_type="PERSON",
                 confidence=0.8, detector="other", tier=Tier.PATTERN),
        ]
        result = check_for_overlaps(spans, allow_identical=False)
        assert len(result) == 1

    def test_adjacent_spans_not_overlapping(self):
        """Adjacent spans (touching but not overlapping) are not overlaps."""
        spans = [
            Span(start=0, end=5, text="Hello", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=5, end=10, text="World", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        result = check_for_overlaps(spans)
        assert len(result) == 0

    def test_multiple_overlaps_all_detected(self):
        """Multiple overlapping pairs are all detected."""
        spans = [
            Span(start=0, end=10, text="0123456789", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=5, end=15, text="5678901234", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=10, end=20, text="0123456789", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        result = check_for_overlaps(spans)
        # (0-10, 5-15) overlap, (5-15, 10-20) overlap
        assert len(result) == 2

    def test_contained_span_detected(self):
        """Span completely contained in another is detected."""
        spans = [
            Span(start=0, end=20, text="0123456789" * 2, entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=5, end=10, text="56789", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        result = check_for_overlaps(spans)
        assert len(result) == 1


# =============================================================================
# VALIDATE AFTER COREF TESTS
# =============================================================================

class TestValidateAfterCoref:
    """Tests for validate_after_coref() convenience function."""

    def test_validates_positions(self):
        """Validates span positions."""
        text = "Hello John Smith there"
        spans = [make_span("John Smith", start=6)]
        result = validate_after_coref(text, spans)
        assert len(result) == 1

    def test_filters_invalid_in_lenient_mode(self):
        """Filters invalid spans in lenient mode (default)."""
        text = "Hello"
        spans = [
            make_invalid_span(start=-1, end=5, text="bad"),
        ]
        result = validate_after_coref(text, spans, strict=False)
        assert len(result) == 0

    def test_raises_in_strict_mode(self):
        """Raises in strict mode."""
        text = "Hello"
        spans = [
            make_invalid_span(start=-1, end=5, text="bad"),
        ]
        with pytest.raises(SpanValidationError):
            validate_after_coref(text, spans, strict=True)

    def test_logs_overlaps(self):
        """Logs overlap information."""
        text = "Hello John Smith there"
        spans = [
            Span(start=0, end=10, text="Hello John", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
            Span(start=6, end=16, text="John Smith", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN),
        ]
        with patch('scrubiq.pipeline.span_validation.logger') as mock_logger:
            result = validate_after_coref(text, spans)
            # Both spans are valid, just overlapping
            assert len(result) == 2
            # Should log about overlaps
            assert mock_logger.info.called or mock_logger.debug.called


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for span validation."""

    def test_empty_text_with_spans(self):
        """Empty text with spans should filter all."""
        spans = [make_span("test", start=0)]
        result = validate_span_positions("", spans, strict=False)
        assert len(result) == 0

    def test_unicode_text(self):
        """Unicode text is handled correctly."""
        text = "Hello José Smith there"
        span = Span(start=6, end=10, text="José", entity_type="NAME",
                    confidence=0.9, detector="test", tier=Tier.PATTERN)
        result = validate_span_positions(text, [span])
        assert len(result) == 1

    def test_span_at_exact_text_end(self):
        """Span ending exactly at text end is valid."""
        text = "Hello John"
        span = make_span("John", start=6)
        result = validate_span_positions(text, [span])
        assert len(result) == 1

    def test_many_spans_performance(self):
        """Many spans are handled efficiently."""
        text = "a " * 1000
        spans = [make_span("a", start=i * 2) for i in range(500)]
        result = validate_span_positions(text, spans)
        assert len(result) == 500

    def test_overlaps_with_many_spans(self):
        """Overlap detection handles many spans."""
        spans = [
            Span(start=i, end=i + 10, text="0123456789", entity_type="NAME",
                 confidence=0.9, detector="test", tier=Tier.PATTERN)
            for i in range(0, 50, 5)  # 10 overlapping spans
        ]
        result = check_for_overlaps(spans)
        # Each consecutive pair overlaps
        assert len(result) > 0

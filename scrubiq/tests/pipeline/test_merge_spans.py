"""Integration tests for merge_spans() in merger.py.

Tests the complete span merging pipeline with realistic inputs.
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.merger import merge_spans


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


class TestMergeSpansBasics:
    """Basic merge_spans functionality tests."""

    def test_empty_input_returns_empty(self):
        """Empty span list returns empty list."""
        result = merge_spans([], min_confidence=0.5)
        assert result == []

    def test_single_span_returned(self):
        """Single valid span is returned unchanged."""
        text = "John Smith"
        spans = [make_span("John Smith", start=0)]
        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_low_confidence_filtered(self):
        """Spans below confidence threshold are filtered."""
        text = "John Smith is here"
        spans = [
            make_span("John Smith", start=0, confidence=0.3),
        ]
        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 0

    def test_confidence_at_threshold_kept(self):
        """Spans at exactly the threshold are kept."""
        text = "John Smith"
        spans = [
            make_span("John Smith", start=0, confidence=0.5),
        ]
        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1


class TestClinicalContextFiltering:
    """Tests for clinical context type filtering."""

    def test_lab_test_filtered(self):
        """LAB_TEST spans are filtered."""
        text = "CBC results are normal"
        spans = [make_span("CBC", start=0, entity_type="LAB_TEST")]
        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 0

    def test_diagnosis_filtered(self):
        """DIAGNOSIS spans are filtered."""
        text = "Diagnosis: Hypertension"
        spans = [make_span("Hypertension", start=11, entity_type="DIAGNOSIS")]
        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 0

    def test_medication_filtered(self):
        """MEDICATION spans are filtered."""
        text = "Taking Lisinopril daily"
        spans = [make_span("Lisinopril", start=7, entity_type="MEDICATION")]
        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 0

    def test_name_with_diagnosis_kept(self):
        """NAME spans alongside DIAGNOSIS are kept."""
        text = "Dr. Smith diagnosed hypertension"
        spans = [
            make_span("Dr. Smith", start=0, entity_type="NAME"),
            make_span("hypertension", start=20, entity_type="DIAGNOSIS"),
        ]
        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].entity_type == "NAME"


class TestInputValidation:
    """Tests for input validation in merge_spans."""

    def test_invalid_span_position_filtered(self):
        """Spans with positions exceeding text length are filtered."""
        text = "Short"
        spans = [
            make_span("Valid", start=0),  # This span text doesn't match but position is valid
        ]
        # Create a span that exceeds text bounds
        bad_span = Span(
            start=0, end=100, text="x" * 100,
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.PATTERN
        )

        result = merge_spans([bad_span], min_confidence=0.5, text=text)
        assert len(result) == 0

    def test_valid_spans_kept_invalid_filtered(self):
        """Valid spans are kept while invalid ones are filtered."""
        text = "John Smith is here"
        good_span = make_span("John Smith", start=0)
        bad_span = Span(
            start=0, end=100, text="x" * 100,
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.PATTERN
        )

        result = merge_spans([good_span, bad_span], min_confidence=0.5, text=text)
        assert len(result) == 1
        assert result[0].text == "John Smith"


class TestComplexScenarios:
    """Complex real-world scenario tests."""

    def test_clinical_note_extraction(self):
        """Extract PHI from a realistic clinical note."""
        text = """
Patient: John Smith
DOB: 01/15/1980
MRN: 123456789

Dr. Sarah Johnson, MD reviewed the case.
Contact: 555-123-4567
Email: john.smith@email.com
""".strip()

        spans = [
            make_span("John Smith", start=9, entity_type="NAME_PATIENT"),
            make_span("01/15/1980", start=25, entity_type="DATE_DOB"),
            make_span("123456789", start=41, entity_type="MRN"),
            make_span("Sarah Johnson", start=56, entity_type="NAME_PROVIDER"),
            make_span("555-123-4567", start=100, entity_type="PHONE"),
            make_span("john.smith@email.com", start=120, entity_type="EMAIL"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        # All PHI types should be kept
        types_found = {s.entity_type for s in result}
        assert "NAME_PATIENT" in types_found or "NAME" in types_found
        assert "MRN" in types_found
        assert "PHONE" in types_found
        assert "EMAIL" in types_found

    def test_overlapping_detections_resolved(self):
        """Multiple overlapping detections are resolved by authority."""
        text = "Dr. John Smith, MD is the attending"

        # Simulating multiple detectors finding overlapping spans
        spans = [
            # ML detector finds just "John"
            make_span("John", start=4, entity_type="NAME", tier=1, confidence=0.7),
            # Pattern detector finds "John Smith"
            make_span("John Smith", start=4, entity_type="NAME", tier=2, confidence=0.85),
            # Another ML detector finds full "Dr. John Smith, MD"
            make_span("Dr. John Smith, MD", start=0, entity_type="NAME", tier=1, confidence=0.9),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        # Should resolve to one span - pattern tier beats ML for "John Smith"
        # but the larger span might win due to containment logic
        assert len(result) == 1

    def test_multiple_entities_same_type(self):
        """Multiple non-overlapping entities of same type are kept."""
        text = "John Smith and Jane Doe met at the cafe"

        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Jane Doe", start=15, entity_type="NAME"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 2
        names = [s.text for s in result]
        assert "John Smith" in names
        assert "Jane Doe" in names

    def test_mixed_entity_types(self):
        """Different entity types at various positions are handled."""
        text = "Call John Smith at 555-1234 about MRN 12345"

        spans = [
            make_span("John Smith", start=5, entity_type="NAME"),
            make_span("555-1234", start=19, entity_type="PHONE"),
            make_span("12345", start=38, entity_type="MRN"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 3
        types = {s.entity_type for s in result}
        assert types == {"NAME", "PHONE", "MRN"}


class TestBoundaryNormalization:
    """Tests for boundary normalization during merge."""

    def test_whitespace_trimmed(self):
        """Whitespace is trimmed from span boundaries."""
        text = "  John Smith  is here"
        spans = [make_span("  John Smith  ", start=0)]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].text == "John Smith"
        assert result[0].start == 2
        assert result[0].end == 12

    def test_names_trimmed_at_newlines(self):
        """NAME spans are trimmed at newline characters."""
        text = "John Smith\nDepartment Head"
        spans = [make_span("John Smith\nDepartment", start=0, entity_type="NAME")]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_trailing_punctuation_trimmed_from_ids(self):
        """Trailing punctuation is trimmed from ID-type spans."""
        text = "SSN: 123-45-6789."
        spans = [make_span("123-45-6789.", start=5, entity_type="SSN")]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].text == "123-45-6789"


class TestOutputProperties:
    """Tests for output span properties."""

    def test_output_sorted_by_position(self):
        """Output spans are sorted by start position."""
        text = "End John then Start Alice"
        spans = [
            make_span("Alice", start=20, entity_type="NAME"),
            make_span("John", start=4, entity_type="NAME"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 2
        assert result[0].start < result[1].start

    def test_non_overlapping_output(self):
        """Output spans do not overlap."""
        text = "John Smith Jr. is here"
        # Create overlapping input spans
        spans = [
            make_span("John Smith Jr.", start=0, entity_type="NAME", tier=2),
            make_span("Smith Jr.", start=5, entity_type="NAME", tier=1),
            make_span("John Smith", start=0, entity_type="NAME", tier=1),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        # Verify no overlaps
        for i in range(len(result) - 1):
            assert result[i].end <= result[i + 1].start, "Output spans should not overlap"

    def test_metadata_preserved(self):
        """Span metadata is preserved through merge."""
        text = "John Smith"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME",
                     confidence=0.95, detector="custom_detector", tier=3),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert result[0].confidence == 0.95
        assert result[0].detector == "custom_detector"
        assert result[0].tier == Tier.STRUCTURED


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_text_none_still_works(self):
        """merge_spans works without text parameter (no boundary normalization)."""
        spans = [make_span("John Smith", start=0)]

        result = merge_spans(spans, min_confidence=0.5, text=None)

        assert len(result) == 1

    def test_all_spans_filtered(self):
        """Returns empty when all spans are filtered."""
        text = "CBC LAB_TEST"
        spans = [
            make_span("CBC", start=0, entity_type="LAB_TEST"),
            make_span("LAB_TEST", start=4, entity_type="DIAGNOSIS"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)
        assert len(result) == 0

    def test_adjacent_spans_not_merged(self):
        """Adjacent but non-overlapping spans of different types stay separate."""
        # Use a space between them so word boundary snapping doesn't merge them
        text = "John 123456"
        spans = [
            make_span("John", start=0, entity_type="NAME"),
            make_span("123456", start=5, entity_type="MRN"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 2

    def test_unicode_text_handled(self):
        """Unicode characters in text are handled correctly."""
        text = "José García lives here"
        spans = [make_span("José García", start=0, entity_type="NAME")]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].text == "José García"


class TestPerformance:
    """Performance-related tests."""

    def test_many_spans_handled(self):
        """Large numbers of spans are handled efficiently."""
        # Create 1000 non-overlapping spans
        text = " ".join([f"Name{i}" for i in range(1000)])
        spans = []
        pos = 0
        for i in range(1000):
            name = f"Name{i}"
            spans.append(make_span(name, start=pos, entity_type="NAME"))
            pos += len(name) + 1  # +1 for space

        import time
        start = time.time()
        result = merge_spans(spans, min_confidence=0.5, text=text)
        elapsed = time.time() - start

        assert len(result) == 1000
        assert elapsed < 5.0, f"merge_spans too slow: {elapsed:.2f}s for 1000 spans"

    def test_many_overlapping_spans(self):
        """Many overlapping spans are resolved efficiently."""
        text = "A" * 1000
        # Create many overlapping spans
        spans = [
            make_span("A" * 100, start=i * 10, entity_type="NAME", tier=1)
            for i in range(90)
        ]
        # Add one high-authority span covering everything
        spans.append(make_span("A" * 1000, start=0, entity_type="NAME", tier=3))

        import time
        start = time.time()
        result = merge_spans(spans, min_confidence=0.5, text=text)
        elapsed = time.time() - start

        # Should resolve to the one high-authority span
        assert len(result) == 1
        assert elapsed < 2.0, f"Overlapping span resolution too slow: {elapsed:.2f}s"


class TestRegressions:
    """Regression tests for previously-fixed bugs."""

    def test_short_name_filtered(self):
        """Short names like 'K.' are filtered."""
        text = "K. Smith, MD"
        spans = [
            make_span("K.", start=0, entity_type="NAME"),
            make_span("K. Smith, MD", start=0, entity_type="NAME"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        # "K." should be filtered, "K. Smith, MD" should remain
        assert len(result) == 1
        assert result[0].text == "K. Smith, MD"

    def test_city_name_reclassified(self):
        """City names detected as NAME are reclassified to ADDRESS."""
        text = "From HARRISBURG, PA"
        spans = [make_span("HARRISBURG, PA", start=5, entity_type="NAME")]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].entity_type == "ADDRESS"

    def test_email_reclassified_from_name(self):
        """Email detected as NAME is reclassified to EMAIL."""
        text = "Contact: john@example.com"
        spans = [make_span("john@example.com", start=9, entity_type="NAME")]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"

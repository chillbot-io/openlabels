"""Tests for core types module.

Tests cover:
- Span creation and properties
- Tier enum
- DetectionResult
- Entity and Mention
- Type normalization
"""

import pytest
from openlabels.core.types import (
    Span,
    Tier,
    DetectionResult,
    normalize_entity_type,
    RiskTier,
)
from openlabels.core.pipeline.entity_resolver import Entity, Mention


# =============================================================================
# SPAN TESTS
# =============================================================================

class TestSpan:
    """Tests for Span dataclass."""

    def test_length_property(self):
        """Span has correct length."""
        span = Span(
            start=5,
            end=15,
            text="John Smith",
            entity_type="NAME",
            confidence=0.9,
            detector="test",
            tier=Tier.ML,
        )

        assert len(span.text) == 10

    def test_overlaps_detection(self):
        """Span detects overlapping spans."""
        span1 = Span(
            start=0, end=10, text="John Smith",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )
        span2 = Span(
            start=5, end=15, text="Smith Jane",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )
        span3 = Span(
            start=20, end=30, text="Other Name",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )

        assert span1.overlaps(span2) is True
        assert span1.overlaps(span3) is False

    def test_contains_detection(self):
        """Span detects contained spans."""
        outer = Span(
            start=0, end=19, text="Mr. John Smith here",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )
        inner = Span(
            start=4, end=14, text="John Smith",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )

        assert outer.contains(inner) is True
        assert inner.contains(outer) is False

    def test_optional_fields(self):
        """Span has optional fields with defaults."""
        span = Span(
            start=0, end=10, text="John Smith",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )

        assert span.coref_anchor_value is None
        assert span.needs_review is False

    def test_coref_anchor_value(self):
        """Span can have coref_anchor_value set."""
        span = Span(
            start=0, end=2, text="He",
            entity_type="NAME", confidence=0.8, detector="coref", tier=Tier.ML,
            coref_anchor_value="John Smith"
        )

        assert span.coref_anchor_value == "John Smith"


# =============================================================================
# TIER TESTS
# =============================================================================

class TestTier:
    """Tests for Tier enum."""

    def test_tier_values(self):
        """Tier has expected values."""
        assert Tier.CHECKSUM.value == 4
        assert Tier.STRUCTURED.value == 3
        assert Tier.PATTERN.value == 2
        assert Tier.ML.value == 1

    def test_tier_ordering(self):
        """Tier values are ordered correctly."""
        assert Tier.CHECKSUM.value > Tier.STRUCTURED.value
        assert Tier.STRUCTURED.value > Tier.PATTERN.value
        assert Tier.PATTERN.value > Tier.ML.value

    def test_from_value(self):
        """Tier.from_value creates tier from int."""
        assert Tier.from_value(4) == Tier.CHECKSUM
        assert Tier.from_value(3) == Tier.STRUCTURED
        assert Tier.from_value(2) == Tier.PATTERN
        assert Tier.from_value(1) == Tier.ML

    def test_from_value_raises_on_invalid(self):
        """Tier.from_value raises on invalid values."""
        with pytest.raises(ValueError):
            Tier.from_value(99)
        with pytest.raises(ValueError):
            Tier.from_value(0)


# =============================================================================
# DETECTION RESULT TESTS
# =============================================================================

class TestDetectionResult:
    """Tests for DetectionResult dataclass."""

    def test_with_spans(self):
        """DetectionResult holds spans correctly."""
        span = Span(
            start=0, end=10, text="John Smith",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )
        result = DetectionResult(
            spans=[span],
            entity_counts={"NAME": 1},
            processing_time_ms=50.0,
            detectors_used=["test"],
            text_length=20,
        )

        assert len(result.spans) == 1
        assert result.entity_counts["NAME"] == 1


# =============================================================================
# ENTITY AND MENTION TESTS
# =============================================================================

class TestEntity:
    """Tests for Entity dataclass."""

    def test_count_property(self):
        """Entity count property works."""
        span = Span(
            start=0, end=10, text="John Smith",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )
        mention = Mention(span=span, normalized_text="john smith", words={"john", "smith"})

        entity = Entity(
            id="abc123",
            canonical_value="John Smith",
            entity_type="NAME",
            mentions=[mention],
        )

        assert entity.count == 1

    def test_optional_fields(self):
        """Entity has optional fields."""
        entity = Entity(
            id="abc123",
            canonical_value="John Smith",
            entity_type="NAME",
            mentions=[],
            semantic_role="patient",
        )

        assert entity.semantic_role == "patient"

    def test_to_dict(self):
        """Entity to_dict works."""
        entity = Entity(
            id="abc123",
            canonical_value="John Smith",
            entity_type="NAME",
            mentions=[],
        )

        result = entity.to_dict()
        assert result["id"] == "abc123"
        assert result["canonical_value"] == "John Smith"
        assert result["entity_type"] == "NAME"
        assert result["count"] == 0


# =============================================================================
# NORMALIZE ENTITY TYPE TESTS
# =============================================================================

class TestNormalizeEntityType:
    """Tests for normalize_entity_type function."""

    def test_basic_normalization(self):
        """Basic types are normalized correctly."""
        assert normalize_entity_type("NAME") == "NAME"
        assert normalize_entity_type("name") == "NAME"
        assert normalize_entity_type("SSN") == "SSN"

    def test_synonyms(self):
        """Type synonyms are normalized."""
        # PER -> NAME
        assert normalize_entity_type("PER") == "NAME"
        assert normalize_entity_type("PERSON") == "NAME"

    def test_role_suffixes_preserved(self):
        """Role suffixes are preserved."""
        assert normalize_entity_type("NAME_PATIENT") == "NAME_PATIENT"
        assert normalize_entity_type("NAME_PROVIDER") == "NAME_PROVIDER"

    def test_unknown_types_preserved(self):
        """Unknown types are preserved as-is."""
        assert normalize_entity_type("CUSTOM_TYPE") == "CUSTOM_TYPE"


# =============================================================================
# RISK TIER TESTS
# =============================================================================

class TestRiskTier:
    """Tests for RiskTier enum."""

    def test_risk_tier_values(self):
        """RiskTier has expected string values."""
        assert RiskTier.CRITICAL.value == "CRITICAL"
        assert RiskTier.HIGH.value == "HIGH"
        assert RiskTier.MEDIUM.value == "MEDIUM"
        assert RiskTier.LOW.value == "LOW"
        assert RiskTier.MINIMAL.value == "MINIMAL"



# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge case tests for types."""

    def test_span_requires_valid_range(self):
        """Span validates that start < end."""
        with pytest.raises(ValueError):
            Span(
                start=0, end=0, text="",
                entity_type="NAME", confidence=0.5, detector="test", tier=Tier.ML
            )

    def test_span_unicode(self):
        """Span handles unicode correctly."""
        span = Span(
            start=0, end=11, text="José García",
            entity_type="NAME", confidence=0.9, detector="test", tier=Tier.ML
        )

        assert span.text == "José García"


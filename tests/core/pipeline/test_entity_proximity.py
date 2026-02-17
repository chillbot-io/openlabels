"""Tests for entity proximity analysis and confidence boosting.

Tests cover:
- Cluster formation based on proximity window
- Confidence boosting with high-confidence anchors
- Boost cap at MAX_CONFIDENCE_BOOST
- No boost when anchors are below threshold
- Backward compatibility (boosting disabled)
- Empty input handling
"""

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.pipeline.entity_proximity import (
    DEFAULT_PROXIMITY_CHARS,
    MAX_CONFIDENCE_BOOST,
    MIN_ANCHOR_CONFIDENCE,
    EntityCluster,
    ProximityResult,
    analyze_proximity,
)


def _make_span(
    start: int,
    end: int,
    entity_type: str = "NAME",
    confidence: float = 0.90,
    text: str | None = None,
) -> Span:
    """Helper to create a Span for testing."""
    return Span(
        start=start,
        end=end,
        text=text or ("x" * (end - start)),
        entity_type=entity_type,
        confidence=confidence,
        detector="test",
        tier=Tier.ML,
    )


class TestClusterFormation:
    """Test that spans are grouped into clusters based on proximity."""

    def test_nearby_spans_form_one_cluster(self):
        spans = [
            _make_span(0, 10, "NAME"),
            _make_span(20, 31, "SSN"),
        ]
        result = analyze_proximity(spans, proximity_chars=500, enable_boosting=False)
        assert len(result.clusters) == 1
        assert len(result.clusters[0].spans) == 2

    def test_distant_spans_form_separate_clusters(self):
        spans = [
            _make_span(0, 10, "NAME"),
            _make_span(1000, 1011, "SSN"),
        ]
        result = analyze_proximity(spans, proximity_chars=500, enable_boosting=False)
        assert len(result.clusters) == 2

    def test_chain_of_nearby_spans(self):
        # A-B close, B-C close, but A-C would be far if measured directly.
        # They should still form one cluster (transitive proximity).
        spans = [
            _make_span(0, 10, "NAME"),
            _make_span(100, 110, "EMAIL"),
            _make_span(200, 210, "SSN"),
        ]
        result = analyze_proximity(spans, proximity_chars=200, enable_boosting=False)
        assert len(result.clusters) == 1
        assert len(result.clusters[0].spans) == 3

    def test_single_span_forms_cluster(self):
        spans = [_make_span(0, 10, "NAME")]
        result = analyze_proximity(spans, enable_boosting=False)
        assert len(result.clusters) == 1

    def test_empty_input(self):
        result = analyze_proximity([], enable_boosting=False)
        assert len(result.clusters) == 0
        assert result.boosted_spans == []
        assert result.boost_count == 0

    def test_cluster_entity_types_tracked(self):
        spans = [
            _make_span(0, 10, "NAME"),
            _make_span(20, 31, "SSN"),
            _make_span(40, 50, "EMAIL"),
        ]
        result = analyze_proximity(spans, enable_boosting=False)
        assert result.clusters[0].entity_types == {"NAME", "SSN", "EMAIL"}


class TestClusterProperties:
    """Test EntityCluster helper properties."""

    def test_has_identifier(self):
        cluster = EntityCluster(id=0, entity_types={"SSN", "NAME"})
        assert cluster.has_identifier is True

    def test_no_identifier(self):
        cluster = EntityCluster(id=0, entity_types={"NAME", "EMAIL"})
        assert cluster.has_identifier is False

    def test_has_name(self):
        cluster = EntityCluster(id=0, entity_types={"NAME", "SSN"})
        assert cluster.has_name is True

    def test_no_name(self):
        cluster = EntityCluster(id=0, entity_types={"SSN", "EMAIL"})
        assert cluster.has_name is False


class TestConfidenceBoosting:
    """Test confidence boosting logic."""

    def test_name_boosted_near_high_confidence_ssn(self):
        spans = [
            _make_span(0, 10, "NAME", confidence=0.55),
            _make_span(20, 31, "SSN", confidence=0.95),
        ]
        result = analyze_proximity(spans, enable_boosting=True)
        assert result.boost_count >= 1

        # Find the NAME span — it should be boosted
        name_span = [s for s in result.boosted_spans if s.entity_type == "NAME"][0]
        assert name_span.confidence > 0.55

    def test_boost_capped_at_max(self):
        spans = [
            _make_span(0, 10, "NAME", confidence=0.85),
            _make_span(20, 31, "SSN", confidence=0.99),
        ]
        result = analyze_proximity(spans, enable_boosting=True)

        name_span = [s for s in result.boosted_spans if s.entity_type == "NAME"][0]
        boost = name_span.confidence - 0.85
        assert boost <= MAX_CONFIDENCE_BOOST + 1e-9

    def test_no_boost_when_anchor_low_confidence(self):
        spans = [
            _make_span(0, 10, "NAME", confidence=0.55),
            _make_span(20, 31, "SSN", confidence=0.50),  # Below MIN_ANCHOR_CONFIDENCE
        ]
        result = analyze_proximity(spans, enable_boosting=True)
        assert result.boost_count == 0

    def test_no_boost_when_target_already_high(self):
        spans = [
            _make_span(0, 10, "NAME", confidence=0.95),  # Already >= 0.90
            _make_span(20, 31, "SSN", confidence=0.99),
        ]
        result = analyze_proximity(spans, enable_boosting=True)

        name_span = [s for s in result.boosted_spans if s.entity_type == "NAME"][0]
        # Should not be boosted since confidence >= 0.90
        assert name_span.confidence == 0.95

    def test_no_boost_for_unrelated_types(self):
        spans = [
            _make_span(0, 10, "CITY", confidence=0.55),
            _make_span(20, 31, "DATE", confidence=0.95),
        ]
        result = analyze_proximity(spans, enable_boosting=True)
        # CITY has no boost relationship with DATE
        assert result.boost_count == 0

    def test_boosting_disabled_returns_original_confidence(self):
        spans = [
            _make_span(0, 10, "NAME", confidence=0.55),
            _make_span(20, 31, "SSN", confidence=0.95),
        ]
        result = analyze_proximity(spans, enable_boosting=False)
        assert result.boost_count == 0

        name_span = [s for s in result.boosted_spans if s.entity_type == "NAME"][0]
        assert name_span.confidence == 0.55

    def test_single_span_cluster_no_boost(self):
        spans = [_make_span(0, 10, "NAME", confidence=0.55)]
        result = analyze_proximity(spans, enable_boosting=True)
        assert result.boost_count == 0

    def test_bidirectional_boosting(self):
        # Both NAME and SSN can boost each other
        spans = [
            _make_span(0, 10, "NAME", confidence=0.80),
            _make_span(20, 31, "SSN", confidence=0.75),
        ]
        result = analyze_proximity(spans, enable_boosting=True)

        name_span = [s for s in result.boosted_spans if s.entity_type == "NAME"][0]
        ssn_span = [s for s in result.boosted_spans if s.entity_type == "SSN"][0]

        # Both should be boosted (NAME by SSN anchor, SSN by NAME anchor)
        assert name_span.confidence > 0.80
        assert ssn_span.confidence > 0.75


class TestProximityResult:
    """Test ProximityResult metadata."""

    def test_original_span_count(self):
        spans = [
            _make_span(0, 10, "NAME"),
            _make_span(20, 31, "SSN"),
        ]
        result = analyze_proximity(spans, enable_boosting=False)
        assert result.original_span_count == 2

    def test_boosted_spans_same_length(self):
        spans = [
            _make_span(0, 10, "NAME", confidence=0.55),
            _make_span(20, 31, "SSN", confidence=0.95),
        ]
        result = analyze_proximity(spans, enable_boosting=True)
        assert len(result.boosted_spans) == len(spans)

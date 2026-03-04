"""Tests for tier-based confidence calibration."""

import pytest

from openlabels.core.pipeline.confidence import (
    _TIER_FLOORS,
    _next_ceiling,
    calibrate_confidence,
    calibrate_spans,
)
from openlabels.core.types import Span, Tier


def _make_span(
    confidence: float,
    tier: Tier = Tier.ML,
    entity_type: str = "NAME",
) -> Span:
    return Span(
        start=0, end=4, text="test",
        entity_type=entity_type,
        confidence=confidence,
        detector="test",
        tier=tier,
    )


class TestTierFloors:
    """Verify tier floor values are ordered and non-overlapping."""

    def test_ml_floor(self):
        assert _TIER_FLOORS[Tier.ML] == 0.20

    def test_pattern_floor(self):
        assert _TIER_FLOORS[Tier.PATTERN] == 0.65

    def test_structured_floor(self):
        assert _TIER_FLOORS[Tier.STRUCTURED] == 0.80

    def test_checksum_floor(self):
        assert _TIER_FLOORS[Tier.CHECKSUM] == 0.90

    def test_floors_ascending(self):
        """Each tier's floor is higher than the previous tier's."""
        ordered = [Tier.ML, Tier.PATTERN, Tier.STRUCTURED, Tier.CHECKSUM]
        for i in range(len(ordered) - 1):
            assert _TIER_FLOORS[ordered[i]] < _TIER_FLOORS[ordered[i + 1]]


class TestNextCeiling:
    """Test ceiling computation for each tier."""

    def test_ml_ceiling_is_pattern_floor(self):
        assert _next_ceiling(Tier.ML) == _TIER_FLOORS[Tier.PATTERN]

    def test_pattern_ceiling_is_structured_floor(self):
        assert _next_ceiling(Tier.PATTERN) == _TIER_FLOORS[Tier.STRUCTURED]

    def test_structured_ceiling_is_checksum_floor(self):
        assert _next_ceiling(Tier.STRUCTURED) == _TIER_FLOORS[Tier.CHECKSUM]

    def test_checksum_ceiling_is_1(self):
        assert _next_ceiling(Tier.CHECKSUM) == 1.0


class TestMLCalibration:
    """ML tier calibration: [0.20, 0.65] band."""

    def test_ml_raw_0_gives_floor(self):
        """Raw 0.0 → floor (0.20)."""
        span = _make_span(0.0, Tier.ML)
        assert calibrate_confidence(span) == pytest.approx(0.20)

    def test_ml_raw_1_gives_ceiling(self):
        """Raw 1.0 → ceiling (0.65)."""
        span = _make_span(1.0, Tier.ML)
        assert calibrate_confidence(span) == pytest.approx(0.65)

    def test_ml_raw_095_competitive(self):
        """Raw 0.95 → 0.6275, competitive with low-confidence patterns."""
        span = _make_span(0.95, Tier.ML)
        result = calibrate_confidence(span)
        # 0.20 + 0.95 * (0.65 - 0.20) = 0.20 + 0.4275 = 0.6275
        assert result == pytest.approx(0.6275)
        assert result > 0.60

    def test_ml_raw_050_below_pattern(self):
        """Raw 0.50 → 0.425, safely below pattern floor."""
        span = _make_span(0.50, Tier.ML)
        result = calibrate_confidence(span)
        # 0.20 + 0.50 * 0.45 = 0.425
        assert result == pytest.approx(0.425)
        assert result < _TIER_FLOORS[Tier.PATTERN]


class TestPatternCalibration:
    """PATTERN tier calibration: [0.65, 0.80] band."""

    def test_pattern_raw_0_gives_floor(self):
        span = _make_span(0.0, Tier.PATTERN)
        assert calibrate_confidence(span) == pytest.approx(0.65)

    def test_pattern_raw_1_gives_ceiling(self):
        span = _make_span(1.0, Tier.PATTERN)
        assert calibrate_confidence(span) == pytest.approx(0.80)

    def test_pattern_raw_085(self):
        span = _make_span(0.85, Tier.PATTERN)
        # 0.65 + 0.85 * (0.80 - 0.65) = 0.65 + 0.1275 = 0.7775
        assert calibrate_confidence(span) == pytest.approx(0.7775)


class TestChecksumCalibration:
    """CHECKSUM tier calibration: [0.90, 1.0] band."""

    def test_checksum_raw_0_gives_floor(self):
        span = _make_span(0.0, Tier.CHECKSUM)
        assert calibrate_confidence(span) == pytest.approx(0.90)

    def test_checksum_raw_1_gives_ceiling(self):
        span = _make_span(1.0, Tier.CHECKSUM)
        assert calibrate_confidence(span) == pytest.approx(1.0)

    def test_checksum_always_beats_ml(self):
        """Even a low-confidence checksum beats a perfect ML score."""
        checksum = calibrate_confidence(_make_span(0.5, Tier.CHECKSUM))
        ml_perfect = calibrate_confidence(_make_span(1.0, Tier.ML))
        assert checksum > ml_perfect


class TestCalibrateSpans:
    """Test batch calibration."""

    def test_empty_list(self):
        assert calibrate_spans([]) == []

    def test_preserves_span_count(self):
        spans = [_make_span(0.5, Tier.ML), _make_span(0.8, Tier.PATTERN)]
        result = calibrate_spans(spans)
        assert len(result) == 2

    def test_preserves_metadata(self):
        span = _make_span(0.5, Tier.ML)
        result = calibrate_spans([span])[0]
        assert result.start == span.start
        assert result.end == span.end
        assert result.text == span.text
        assert result.entity_type == span.entity_type
        assert result.detector == span.detector
        assert result.tier == span.tier

    def test_confidence_updated(self):
        span = _make_span(0.5, Tier.ML)
        result = calibrate_spans([span])[0]
        assert result.confidence != span.confidence
        # 0.20 + 0.50 * (0.65 - 0.20) = 0.425
        assert result.confidence == pytest.approx(0.425)


class TestTierHierarchy:
    """Cross-tier comparisons — higher tiers always dominate."""

    def test_pattern_beats_best_ml(self):
        """Any pattern score beats the best possible ML score."""
        pattern_worst = calibrate_confidence(_make_span(0.0, Tier.PATTERN))
        ml_best = calibrate_confidence(_make_span(1.0, Tier.ML))
        assert pattern_worst >= ml_best

    def test_structured_beats_best_pattern(self):
        """Any structured score beats the best possible pattern score."""
        structured_worst = calibrate_confidence(_make_span(0.0, Tier.STRUCTURED))
        pattern_best = calibrate_confidence(_make_span(1.0, Tier.PATTERN))
        assert structured_worst >= pattern_best

    def test_checksum_beats_best_structured(self):
        """Any checksum score beats the best possible structured score."""
        checksum_worst = calibrate_confidence(_make_span(0.0, Tier.CHECKSUM))
        structured_best = calibrate_confidence(_make_span(1.0, Tier.STRUCTURED))
        assert checksum_worst >= structured_best

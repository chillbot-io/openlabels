"""Tests for per-entity-type confidence thresholds in the orchestrator."""

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.detectors.config import DetectionConfig
from openlabels.core.detectors.orchestrator import DetectorOrchestrator


def _make_span(
    entity_type: str,
    confidence: float,
    tier: Tier = Tier.ML,
    start: int = 0,
    text: str = "test",
) -> Span:
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector="test",
        tier=tier,
    )


class TestPerEntityThresholds:
    """Test that per-entity thresholds override global thresholds."""

    def test_name_below_global_passes_entity_threshold(self):
        """NAME at 0.56 passes entity threshold (0.55) even below global (0.70)."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False,
        )
        orch = DetectorOrchestrator(config=config)
        span = _make_span("NAME", 0.56, Tier.ML)
        result = orch._passes_threshold(span)
        assert result is True

    def test_name_below_entity_threshold_filtered(self):
        """NAME at 0.40 is below entity threshold (0.45) and filtered."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False,
        )
        orch = DetectorOrchestrator(config=config)
        span = _make_span("NAME", 0.40, Tier.ML)
        result = orch._passes_threshold(span)
        assert result is False

    def test_age_below_entity_threshold_filtered(self):
        """AGE at 0.75 is below entity threshold (0.82) and filtered."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False,
        )
        orch = DetectorOrchestrator(config=config)
        span = _make_span("AGE", 0.75, Tier.ML)
        result = orch._passes_threshold(span)
        assert result is False

    def test_age_above_entity_threshold_passes(self):
        """AGE at 0.85 is above entity threshold (0.82) and passes."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False,
        )
        orch = DetectorOrchestrator(config=config)
        span = _make_span("AGE", 0.85, Tier.ML)
        result = orch._passes_threshold(span)
        assert result is True

    def test_unknown_entity_uses_ml_threshold(self):
        """Entity type without per-entity threshold uses ML threshold for ML tier."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False,
            ml_confidence_threshold=0.50,
        )
        orch = DetectorOrchestrator(config=config)
        span = _make_span("BITCOIN_ADDRESS", 0.55, Tier.ML)
        result = orch._passes_threshold(span)
        assert result is True

    def test_unknown_entity_uses_global_threshold_for_pattern(self):
        """Entity type without per-entity threshold uses global for PATTERN tier."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False,
            confidence_threshold=0.70,
        )
        orch = DetectorOrchestrator(config=config)
        span = _make_span("BITCOIN_ADDRESS", 0.65, Tier.PATTERN)
        result = orch._passes_threshold(span)
        assert result is False

    def test_email_lower_threshold(self):
        """EMAIL has a lower threshold (0.60) — passes at 0.62."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False,
        )
        orch = DetectorOrchestrator(config=config)
        span = _make_span("EMAIL", 0.62, Tier.PATTERN)
        result = orch._passes_threshold(span)
        assert result is True


class TestEntityThresholdsInPostProcess:
    """Test that _post_process uses per-entity thresholds for filtering."""

    def test_post_process_filters_by_entity_threshold(self):
        """NAME at 0.40 and EMAIL at 0.62 — NAME filtered, EMAIL kept."""
        config = DetectionConfig(
            enable_ml=False, enable_checksum=False, enable_secrets=False,
            enable_financial=False, enable_government=False, enable_patterns=False,
            enable_context_keywords=False, enable_proximity_boost=False,
        )
        orch = DetectorOrchestrator(config=config)

        spans = [
            _make_span("NAME", 0.40, Tier.ML, start=0, text="John"),
            _make_span("EMAIL", 0.62, Tier.PATTERN, start=10, text="a@b.com"),
        ]
        result = orch._post_process(spans)
        entity_types = {s.entity_type for s in result}
        assert "EMAIL" in entity_types
        assert "NAME" not in entity_types


class TestEntityThresholdsConfig:
    """Test entity_thresholds field in DetectionConfig."""

    def test_default_has_name_threshold(self):
        config = DetectionConfig()
        thresholds = dict(config.entity_thresholds)
        assert thresholds["NAME"] == 0.50

    def test_default_has_age_threshold(self):
        config = DetectionConfig()
        thresholds = dict(config.entity_thresholds)
        assert thresholds["AGE"] == 0.82

    def test_custom_entity_thresholds(self):
        """Custom entity_thresholds can be passed."""
        config = DetectionConfig(
            entity_thresholds=(("NAME", 0.40), ("AGE", 0.90)),
        )
        thresholds = dict(config.entity_thresholds)
        assert thresholds["NAME"] == 0.40
        assert thresholds["AGE"] == 0.90

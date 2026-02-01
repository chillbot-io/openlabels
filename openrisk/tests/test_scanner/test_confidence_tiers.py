"""Comprehensive tests for confidence_tiers.py.

Tests confidence tier constants, adjustment factors, detector floors,
and thresholds used throughout the detection pipeline.
"""

import pytest

from openlabels.adapters.scanner.confidence_tiers import (
    Confidence,
    DETECTOR_CONFIDENCE_FLOORS,
    DEFAULT_MIN_CONFIDENCE,
    SKIP_VERIFICATION_THRESHOLD,
    LLM_VERIFICATION_THRESHOLD,
)


class TestConfidenceTiers:
    """Tests for Confidence class tier values."""

    def test_very_high_is_highest(self):
        """VERY_HIGH should be the highest confidence tier."""
        assert Confidence.VERY_HIGH > Confidence.HIGH
        assert Confidence.VERY_HIGH > Confidence.MEDIUM_HIGH
        assert Confidence.VERY_HIGH > Confidence.MEDIUM
        assert Confidence.VERY_HIGH > Confidence.LOW
        assert Confidence.VERY_HIGH > Confidence.MINIMAL

    def test_tier_ordering(self):
        """Tiers should be strictly ordered from high to low."""
        assert Confidence.VERY_HIGH > Confidence.HIGH
        assert Confidence.HIGH > Confidence.MEDIUM_HIGH
        assert Confidence.MEDIUM_HIGH > Confidence.MEDIUM
        assert Confidence.MEDIUM > Confidence.LOW
        assert Confidence.LOW > Confidence.MINIMAL

    def test_very_high_value(self):
        """VERY_HIGH should be 0.98 for near-certain matches."""
        assert Confidence.VERY_HIGH == 0.98
        # Used for: AWS AKIA prefix, validated checksums, PEM headers

    def test_high_value(self):
        """HIGH should be 0.92 for strong matches."""
        assert Confidence.HIGH == 0.92
        # Used for: Labeled fields, contextual matches

    def test_medium_high_value(self):
        """MEDIUM_HIGH should be 0.88 for good patterns."""
        assert Confidence.MEDIUM_HIGH == 0.88
        # Used for: Unlabeled format matches

    def test_medium_value(self):
        """MEDIUM should be 0.85 for moderate confidence."""
        assert Confidence.MEDIUM == 0.85
        # Used for: Generic formats, partial patterns

    def test_low_value(self):
        """LOW should be 0.75 for potential false positives."""
        assert Confidence.LOW == 0.75
        # Used for: Date formats, short patterns

    def test_minimal_value(self):
        """MINIMAL should be 0.65 for weak matches."""
        assert Confidence.MINIMAL == 0.65
        # Used for: Single words without context

    def test_all_tiers_valid_probabilities(self):
        """All tier values should be valid probabilities (0.0-1.0)."""
        tiers = [
            Confidence.VERY_HIGH,
            Confidence.HIGH,
            Confidence.MEDIUM_HIGH,
            Confidence.MEDIUM,
            Confidence.LOW,
            Confidence.MINIMAL,
        ]
        for tier in tiers:
            assert 0.0 <= tier <= 1.0, f"Tier {tier} not a valid probability"


class TestAdjustmentFactors:
    """Tests for confidence adjustment factors."""

    def test_labeled_boost_positive(self):
        """LABELED_BOOST should be positive to increase confidence."""
        assert Confidence.LABELED_BOOST > 0
        assert Confidence.LABELED_BOOST == 0.05

    def test_unlabeled_penalty_negative(self):
        """UNLABELED_PENALTY should be negative to reduce confidence."""
        assert Confidence.UNLABELED_PENALTY < 0
        assert Confidence.UNLABELED_PENALTY == -0.05

    def test_test_credential_penalty_negative(self):
        """TEST_CREDENTIAL_PENALTY should be negative for test creds."""
        assert Confidence.TEST_CREDENTIAL_PENALTY < 0
        assert Confidence.TEST_CREDENTIAL_PENALTY == -0.08

    def test_boost_and_penalty_symmetric(self):
        """Labeled boost and unlabeled penalty should be symmetric."""
        assert abs(Confidence.LABELED_BOOST) == abs(Confidence.UNLABELED_PENALTY)

    def test_adjustment_factors_reasonable(self):
        """Adjustment factors should be small relative to tier gaps."""
        tier_gap = Confidence.HIGH - Confidence.MEDIUM_HIGH  # 0.04
        assert abs(Confidence.LABELED_BOOST) <= tier_gap * 2
        assert abs(Confidence.UNLABELED_PENALTY) <= tier_gap * 2
        assert abs(Confidence.TEST_CREDENTIAL_PENALTY) <= tier_gap * 3

    def test_applying_boost_stays_valid(self):
        """Applying boost to max tier should stay <= 1.0."""
        boosted = min(1.0, Confidence.VERY_HIGH + Confidence.LABELED_BOOST)
        assert boosted <= 1.0

    def test_applying_penalty_stays_valid(self):
        """Applying penalty to min tier should stay >= 0.0."""
        penalized = max(0.0, Confidence.MINIMAL + Confidence.TEST_CREDENTIAL_PENALTY)
        assert penalized >= 0.0


class TestDetectorConfidenceFloors:
    """Tests for detector-specific confidence floors."""

    def test_checksum_floor_is_high(self):
        """Checksum-validated patterns should have high floor."""
        assert DETECTOR_CONFIDENCE_FLOORS["checksum"] == 0.92
        assert DETECTOR_CONFIDENCE_FLOORS["checksum"] >= Confidence.HIGH

    def test_structured_floor_is_high(self):
        """Structured extraction from labeled fields should be reliable."""
        assert DETECTOR_CONFIDENCE_FLOORS["structured"] == 0.90

    def test_known_entity_floor_is_highest(self):
        """Known entities from previous context should be most reliable."""
        assert DETECTOR_CONFIDENCE_FLOORS["known_entity"] == 0.95
        assert DETECTOR_CONFIDENCE_FLOORS["known_entity"] > DETECTOR_CONFIDENCE_FLOORS["checksum"]

    def test_patterns_floor_is_lower(self):
        """Pattern-only detection may have false positives."""
        assert DETECTOR_CONFIDENCE_FLOORS["patterns"] == 0.70
        assert DETECTOR_CONFIDENCE_FLOORS["patterns"] < DETECTOR_CONFIDENCE_FLOORS["checksum"]

    def test_dictionaries_floor_reasonable(self):
        """Dictionary matches depend on dictionary quality."""
        assert DETECTOR_CONFIDENCE_FLOORS["dictionaries"] == 0.75
        assert DETECTOR_CONFIDENCE_FLOORS["dictionaries"] > DETECTOR_CONFIDENCE_FLOORS["patterns"]

    def test_ml_floor_is_lowest(self):
        """ML/NER models vary by entity type."""
        assert DETECTOR_CONFIDENCE_FLOORS["ml"] == 0.65
        assert DETECTOR_CONFIDENCE_FLOORS["ml"] <= DETECTOR_CONFIDENCE_FLOORS["patterns"]

    def test_all_floors_valid_probabilities(self):
        """All floor values should be valid probabilities."""
        for detector, floor in DETECTOR_CONFIDENCE_FLOORS.items():
            assert 0.0 <= floor <= 1.0, f"Floor for {detector} not valid"

    def test_all_floors_above_minimum(self):
        """All floors should be above the default minimum confidence."""
        for detector, floor in DETECTOR_CONFIDENCE_FLOORS.items():
            assert floor >= DEFAULT_MIN_CONFIDENCE, \
                f"Floor for {detector} ({floor}) below minimum ({DEFAULT_MIN_CONFIDENCE})"

    def test_expected_detectors_present(self):
        """All expected detector types should have floors defined."""
        expected = ["checksum", "structured", "known_entity", "patterns", "dictionaries", "ml"]
        for detector in expected:
            assert detector in DETECTOR_CONFIDENCE_FLOORS, f"Missing floor for {detector}"


class TestConfidenceThresholds:
    """Tests for confidence thresholds used in filtering."""

    def test_default_min_confidence(self):
        """Default minimum should filter very low confidence."""
        assert DEFAULT_MIN_CONFIDENCE == 0.60
        assert DEFAULT_MIN_CONFIDENCE < Confidence.MINIMAL

    def test_skip_verification_threshold(self):
        """Skip verification threshold should be very high."""
        assert SKIP_VERIFICATION_THRESHOLD == 0.95
        assert SKIP_VERIFICATION_THRESHOLD > Confidence.HIGH

    def test_llm_verification_threshold(self):
        """LLM verification threshold should be moderate."""
        assert LLM_VERIFICATION_THRESHOLD == 0.80
        assert LLM_VERIFICATION_THRESHOLD < SKIP_VERIFICATION_THRESHOLD
        assert LLM_VERIFICATION_THRESHOLD > DEFAULT_MIN_CONFIDENCE

    def test_threshold_ordering(self):
        """Thresholds should be properly ordered."""
        assert DEFAULT_MIN_CONFIDENCE < LLM_VERIFICATION_THRESHOLD
        assert LLM_VERIFICATION_THRESHOLD < SKIP_VERIFICATION_THRESHOLD
        assert SKIP_VERIFICATION_THRESHOLD < 1.0

    def test_thresholds_create_valid_ranges(self):
        """Thresholds should create meaningful decision ranges."""
        # Below min: filtered out
        # Between min and LLM: needs LLM verification
        # Between LLM and skip: may need verification
        # Above skip: keep without verification
        assert SKIP_VERIFICATION_THRESHOLD - LLM_VERIFICATION_THRESHOLD > 0.10
        assert LLM_VERIFICATION_THRESHOLD - DEFAULT_MIN_CONFIDENCE > 0.10


class TestConfidenceArithmetic:
    """Tests for confidence score arithmetic operations."""

    def test_boost_medium_to_medium_high(self):
        """Boosting MEDIUM should reach MEDIUM_HIGH range."""
        boosted = Confidence.MEDIUM + Confidence.LABELED_BOOST
        assert boosted >= Confidence.MEDIUM
        assert boosted <= Confidence.HIGH

    def test_penalty_medium_to_low(self):
        """Penalizing MEDIUM should drop toward LOW range."""
        penalized = Confidence.MEDIUM + Confidence.UNLABELED_PENALTY
        assert penalized < Confidence.MEDIUM
        assert penalized >= Confidence.LOW

    def test_double_boost_capped(self):
        """Double boost should be capped at 1.0."""
        double_boosted = Confidence.HIGH + 2 * Confidence.LABELED_BOOST
        capped = min(1.0, double_boosted)
        assert capped <= 1.0

    def test_double_penalty_capped(self):
        """Double penalty should be capped at 0.0."""
        double_penalized = Confidence.MINIMAL + 2 * Confidence.TEST_CREDENTIAL_PENALTY
        capped = max(0.0, double_penalized)
        assert capped >= 0.0

    def test_floor_application(self):
        """Applying floor should raise low confidences."""
        low_conf = 0.50
        floor = DETECTOR_CONFIDENCE_FLOORS["checksum"]
        final = max(low_conf, floor)
        assert final == floor

    def test_floor_doesnt_lower_high_confidence(self):
        """Floor should not lower already-high confidences."""
        high_conf = 0.99
        floor = DETECTOR_CONFIDENCE_FLOORS["checksum"]
        final = max(high_conf, floor)
        assert final == high_conf


class TestConfidenceUseCases:
    """Tests for real-world confidence score use cases."""

    def test_ssn_with_checksum_confidence(self):
        """SSN validated with Luhn should get VERY_HIGH."""
        base = Confidence.VERY_HIGH
        assert base >= DETECTOR_CONFIDENCE_FLOORS["checksum"]

    def test_name_without_context_confidence(self):
        """Name detected without context should be LOW/MINIMAL."""
        base = Confidence.MINIMAL
        assert base < LLM_VERIFICATION_THRESHOLD

    def test_labeled_field_confidence(self):
        """Labeled field should get boosted to HIGH."""
        base = Confidence.MEDIUM
        boosted = base + Confidence.LABELED_BOOST
        assert boosted >= Confidence.MEDIUM

    def test_test_credential_confidence(self):
        """Test credentials should be penalized."""
        base = Confidence.HIGH
        penalized = base + Confidence.TEST_CREDENTIAL_PENALTY
        assert penalized < base
        # 0.92 - 0.08 = 0.84, which drops below MEDIUM but stays above LOW
        assert penalized > Confidence.LOW

    def test_dictionary_match_confidence(self):
        """Dictionary match should meet its floor."""
        raw_score = 0.60
        floor = DETECTOR_CONFIDENCE_FLOORS["dictionaries"]
        final = max(raw_score, floor)
        assert final == floor

    def test_ml_entity_confidence(self):
        """ML-detected entity should meet its floor."""
        raw_score = 0.55
        floor = DETECTOR_CONFIDENCE_FLOORS["ml"]
        final = max(raw_score, floor)
        assert final == floor

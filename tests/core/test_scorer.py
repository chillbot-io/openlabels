"""Tests for the risk scoring engine.

Tests cover:
- Entity weight lookups
- Category lookups
- Co-occurrence multipliers
- Content score calculation
- Tier mapping
- Full score function
"""

import pytest
from openlabels.core.types import RiskTier
from openlabels.core.scoring.scorer import (
    get_weight,
    get_category,
    get_categories,
    get_co_occurrence_multiplier,
    calculate_content_score,
    score_to_tier,
    score,
    ENTITY_WEIGHTS,
    ENTITY_CATEGORIES,
    CO_OCCURRENCE_RULES,
    TIER_THRESHOLDS,
    EXPOSURE_MULTIPLIERS,
    WEIGHT_SCALE,
    DEFAULT_WEIGHT,
)


# =============================================================================
# GET WEIGHT TESTS
# =============================================================================

class TestGetWeight:
    """Tests for get_weight function."""

    def test_critical_entities_weight_10(self):
        """Critical entities have weight 10."""
        assert get_weight("SSN") == 10
        assert get_weight("PASSPORT") == 10
        assert get_weight("CREDIT_CARD") == 10
        assert get_weight("PASSWORD") == 10

    def test_high_entities_weight_8_9(self):
        """High-risk entities have weight 8-9."""
        assert get_weight("MRN") == 9
        assert get_weight("DRIVER_LICENSE") == 8
        assert get_weight("NPI") == 8

    def test_moderate_entities_weight_4_5(self):
        """Moderate entities have weight 4-5."""
        assert get_weight("NAME") == 5
        assert get_weight("ADDRESS") == 5
        assert get_weight("AGE") == 4

    def test_low_entities_weight_2_3(self):
        """Low-risk entities have weight 2-3."""
        assert get_weight("DATE") == 3
        assert get_weight("CITY") == 2
        assert get_weight("STATE") == 2

    def test_unknown_entity_gets_default_weight(self):
        """Unknown entity types get DEFAULT_WEIGHT."""
        assert get_weight("UNKNOWN_TYPE") == DEFAULT_WEIGHT

    def test_weight_normalization(self):
        """Entity types are normalized (case-insensitive)."""
        assert get_weight("ssn") == get_weight("SSN")
        assert get_weight("Ssn") == get_weight("SSN")


# =============================================================================
# GET CATEGORY TESTS
# =============================================================================

class TestGetCategory:
    """Tests for get_category function."""

    def test_direct_identifiers(self):
        """Direct identifiers are categorized correctly."""
        assert get_category("SSN") == "direct_identifier"
        assert get_category("PASSPORT") == "direct_identifier"
        assert get_category("DRIVER_LICENSE") == "direct_identifier"
        assert get_category("MRN") == "direct_identifier"

    def test_health_info(self):
        """Health info entities are categorized correctly."""
        assert get_category("DIAGNOSIS") == "health_info"
        assert get_category("MEDICATION") == "health_info"
        assert get_category("NPI") == "health_info"

    def test_financial(self):
        """Financial entities are categorized correctly."""
        assert get_category("CREDIT_CARD") == "financial"
        assert get_category("IBAN") == "financial"
        assert get_category("BITCOIN_ADDRESS") == "financial"

    def test_credentials(self):
        """Credential entities are categorized correctly."""
        assert get_category("PASSWORD") == "credential"
        assert get_category("API_KEY") == "credential"
        assert get_category("JWT") == "credential"
        assert get_category("AWS_ACCESS_KEY") == "credential"

    def test_contact_info(self):
        """Contact entities are categorized correctly."""
        assert get_category("EMAIL") == "contact"
        assert get_category("PHONE") == "contact"
        assert get_category("ADDRESS") == "contact"

    def test_quasi_identifiers(self):
        """Quasi-identifiers are categorized correctly."""
        assert get_category("NAME") == "quasi_identifier"
        assert get_category("DATE_DOB") == "quasi_identifier"
        assert get_category("AGE") == "quasi_identifier"

    def test_unknown_category(self):
        """Unknown entities return 'unknown' category."""
        assert get_category("UNKNOWN_TYPE") == "unknown"


# =============================================================================
# GET CATEGORIES TESTS
# =============================================================================

class TestGetCategories:
    """Tests for get_categories function."""

    def test_empty_entities(self):
        """Empty entities returns empty set."""
        assert get_categories({}) == set()

    def test_single_category(self):
        """Single entity type returns its category."""
        result = get_categories({"SSN": 1})
        assert result == {"direct_identifier"}

    def test_multiple_categories(self):
        """Multiple entity types return their categories."""
        result = get_categories({
            "SSN": 1,
            "DIAGNOSIS": 1,
            "EMAIL": 1,
        })
        assert "direct_identifier" in result
        assert "health_info" in result
        assert "contact" in result

    def test_excludes_unknown(self):
        """Unknown categories are excluded."""
        result = get_categories({
            "SSN": 1,
            "UNKNOWN_TYPE": 1,
        })
        assert "unknown" not in result
        assert "direct_identifier" in result


# =============================================================================
# CO-OCCURRENCE MULTIPLIER TESTS
# =============================================================================

class TestGetCoOccurrenceMultiplier:
    """Tests for get_co_occurrence_multiplier function."""

    def test_empty_entities(self):
        """Empty entities returns multiplier 1.0."""
        mult, rules = get_co_occurrence_multiplier({})
        assert mult == 1.0
        assert rules == []

    def test_hipaa_phi_rule(self):
        """Direct ID + Health data triggers HIPAA PHI rule."""
        entities = {"SSN": 1, "DIAGNOSIS": 1}
        mult, rules = get_co_occurrence_multiplier(entities)
        assert mult == 2.0
        assert "hipaa_phi" in rules

    def test_identity_theft_rule(self):
        """Direct ID + Financial triggers identity theft rule."""
        entities = {"SSN": 1, "CREDIT_CARD": 1}
        mult, rules = get_co_occurrence_multiplier(entities)
        assert mult == 1.8
        assert "identity_theft" in rules

    def test_credential_exposure_rule(self):
        """Credentials alone trigger exposure rule."""
        entities = {"PASSWORD": 1}
        mult, rules = get_co_occurrence_multiplier(entities)
        assert mult == 1.5
        assert "credential_exposure" in rules

    def test_classified_data_rule(self):
        """Classification markings trigger classified rule."""
        entities = {"CLASSIFICATION_LEVEL": 1}
        mult, rules = get_co_occurrence_multiplier(entities)
        assert mult == 2.5
        assert "classified_data" in rules

    def test_highest_multiplier_wins(self):
        """Highest applicable multiplier is used."""
        # Classified (2.5) should win over HIPAA PHI (2.0)
        entities = {"SSN": 1, "DIAGNOSIS": 1, "CLASSIFICATION_LEVEL": 1}
        mult, rules = get_co_occurrence_multiplier(entities)
        assert mult == 2.5

    def test_no_matching_rule(self):
        """No matching rule returns multiplier 1.0."""
        entities = {"DATE": 1, "CITY": 1}
        mult, rules = get_co_occurrence_multiplier(entities)
        assert mult == 1.0
        assert rules == []


# =============================================================================
# CONTENT SCORE CALCULATION TESTS
# =============================================================================

class TestCalculateContentScore:
    """Tests for calculate_content_score function."""

    def test_empty_entities(self):
        """Empty entities returns 0.0."""
        assert calculate_content_score({}) == 0.0

    def test_single_ssn(self):
        """Single SSN has expected score."""
        score = calculate_content_score({"SSN": 1})
        # SSN weight=10, scale=4.0, aggregation=1+ln(1)=1
        # Expected: 10 * 4 * 1 * 0.85 = 34
        assert score > 30
        assert score < 50

    def test_count_aggregation(self):
        """Multiple instances have diminishing returns."""
        score_1 = calculate_content_score({"SSN": 1})
        score_2 = calculate_content_score({"SSN": 2})
        score_5 = calculate_content_score({"SSN": 5})

        # Scores increase but not linearly
        assert score_2 > score_1
        assert score_5 > score_2
        assert score_5 < score_1 * 5  # Not 5x the single score

    def test_multiple_entity_types(self):
        """Multiple entity types combine scores."""
        score_ssn = calculate_content_score({"SSN": 1})
        score_name = calculate_content_score({"NAME": 1})
        score_both = calculate_content_score({"SSN": 1, "NAME": 1})

        # Combined score should be higher
        assert score_both > score_ssn
        assert score_both > score_name

    def test_co_occurrence_boost(self):
        """Co-occurrence multiplier boosts score."""
        # SSN + DIAGNOSIS triggers HIPAA PHI (2.0x)
        score_separate = calculate_content_score({"SSN": 1}) + calculate_content_score({"DIAGNOSIS": 1})
        score_together = calculate_content_score({"SSN": 1, "DIAGNOSIS": 1})

        # Together should be roughly 2x the separate sum
        assert score_together > score_separate

    def test_max_score_100(self):
        """Score is capped at 100."""
        # Lots of high-risk entities
        entities = {
            "SSN": 10,
            "PASSPORT": 10,
            "CREDIT_CARD": 10,
            "CLASSIFICATION_LEVEL": 10,
        }
        assert calculate_content_score(entities) <= 100.0

    def test_confidence_affects_score(self):
        """Lower confidence reduces score."""
        high_conf = calculate_content_score({"SSN": 1}, confidence=0.95)
        low_conf = calculate_content_score({"SSN": 1}, confidence=0.50)

        assert high_conf > low_conf


# =============================================================================
# SCORE TO TIER TESTS
# =============================================================================

class TestScoreToTier:
    """Tests for score_to_tier function."""

    def test_critical_tier(self):
        """Score >= 80 is CRITICAL."""
        assert score_to_tier(80) == RiskTier.CRITICAL
        assert score_to_tier(100) == RiskTier.CRITICAL

    def test_high_tier(self):
        """Score 55-79 is HIGH."""
        assert score_to_tier(55) == RiskTier.HIGH
        assert score_to_tier(79) == RiskTier.HIGH

    def test_medium_tier(self):
        """Score 31-54 is MEDIUM."""
        assert score_to_tier(31) == RiskTier.MEDIUM
        assert score_to_tier(54) == RiskTier.MEDIUM

    def test_low_tier(self):
        """Score 11-30 is LOW."""
        assert score_to_tier(11) == RiskTier.LOW
        assert score_to_tier(30) == RiskTier.LOW

    def test_minimal_tier(self):
        """Score 0-10 is MINIMAL."""
        assert score_to_tier(0) == RiskTier.MINIMAL
        assert score_to_tier(10) == RiskTier.MINIMAL


# =============================================================================
# FULL SCORE FUNCTION TESTS
# =============================================================================

class TestScore:
    """Tests for the main score function."""

    def test_empty_entities(self):
        """Empty entities returns minimal score."""
        result = score({})
        assert result.score == 0
        assert result.tier == RiskTier.MINIMAL

    def test_single_ssn_private(self):
        """Single SSN at PRIVATE exposure."""
        result = score({"SSN": 1}, exposure="PRIVATE")
        assert result.score > 0
        assert result.tier in (RiskTier.MEDIUM, RiskTier.LOW)
        assert result.exposure == "PRIVATE"
        assert result.exposure_multiplier == 1.0

    def test_single_ssn_public(self):
        """Single SSN at PUBLIC exposure has higher score."""
        private_result = score({"SSN": 1}, exposure="PRIVATE")
        public_result = score({"SSN": 1}, exposure="PUBLIC")

        assert public_result.score > private_result.score
        assert public_result.exposure_multiplier == 2.5

    def test_exposure_multipliers(self):
        """Different exposures have correct multipliers."""
        private = score({"SSN": 1}, exposure="PRIVATE")
        internal = score({"SSN": 1}, exposure="INTERNAL")
        org_wide = score({"SSN": 1}, exposure="ORG_WIDE")
        public = score({"SSN": 1}, exposure="PUBLIC")

        assert private.exposure_multiplier == 1.0
        assert internal.exposure_multiplier == 1.2
        assert org_wide.exposure_multiplier == 1.8
        assert public.exposure_multiplier == 2.5

    def test_co_occurrence_in_result(self):
        """Co-occurrence info is in result."""
        result = score({"SSN": 1, "DIAGNOSIS": 1})

        assert result.co_occurrence_multiplier >= 2.0
        assert "hipaa_phi" in result.co_occurrence_rules

    def test_categories_in_result(self):
        """Categories are included in result."""
        result = score({"SSN": 1, "EMAIL": 1})

        assert "direct_identifier" in result.categories
        assert "contact" in result.categories

    def test_content_score_in_result(self):
        """Content score is included in result."""
        result = score({"SSN": 1})

        assert result.content_score > 0
        assert result.content_score <= 100

    def test_score_capped_at_100(self):
        """Final score is capped at 100."""
        # Lots of entities at PUBLIC exposure
        result = score(
            {"SSN": 10, "PASSPORT": 10, "CLASSIFICATION_LEVEL": 5},
            exposure="PUBLIC"
        )
        assert result.score <= 100

    def test_case_insensitive_exposure(self):
        """Exposure is case-insensitive."""
        lower = score({"SSN": 1}, exposure="private")
        upper = score({"SSN": 1}, exposure="PRIVATE")
        mixed = score({"SSN": 1}, exposure="Private")

        assert lower.exposure == "PRIVATE"
        assert upper.exposure == "PRIVATE"
        assert mixed.exposure == "PRIVATE"


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for module constants."""

    def test_weight_scale_positive(self):
        """WEIGHT_SCALE is positive."""
        assert WEIGHT_SCALE > 0

    def test_tier_thresholds_ordered(self):
        """Tier thresholds are in order."""
        assert TIER_THRESHOLDS['critical'] > TIER_THRESHOLDS['high']
        assert TIER_THRESHOLDS['high'] > TIER_THRESHOLDS['medium']
        assert TIER_THRESHOLDS['medium'] > TIER_THRESHOLDS['low']

    def test_exposure_multipliers_ordered(self):
        """Exposure multipliers increase with exposure."""
        assert EXPOSURE_MULTIPLIERS['PRIVATE'] < EXPOSURE_MULTIPLIERS['INTERNAL']
        assert EXPOSURE_MULTIPLIERS['INTERNAL'] < EXPOSURE_MULTIPLIERS['ORG_WIDE']
        assert EXPOSURE_MULTIPLIERS['ORG_WIDE'] < EXPOSURE_MULTIPLIERS['PUBLIC']

    def test_entity_weights_range(self):
        """All entity weights are in 1-10 range."""
        for weight in ENTITY_WEIGHTS.values():
            assert 1 <= weight <= 10

    def test_default_weight_in_range(self):
        """DEFAULT_WEIGHT is in 1-10 range."""
        assert 1 <= DEFAULT_WEIGHT <= 10

    def test_co_occurrence_multipliers_positive(self):
        """Co-occurrence multipliers are all >= 1.0."""
        for _, mult, _ in CO_OCCURRENCE_RULES:
            assert mult >= 1.0

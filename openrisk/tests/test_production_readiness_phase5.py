"""
Production Readiness Phase 5 Tests: Contract Consistency & Type Safety.

Tests for all Phase 5 remediation items:
- Issue 5.1: Centralized entity type normalization
- Issue 5.2: ExposureLevel enum enforcement
- Issue 5.3: Optional vs required fields clarification
- Issue 5.4: Unknown filter field warnings
- Issue 5.5: Config schema versioning
- Issue 5.6: Confidence threshold constants
"""

import warnings
import unittest
from unittest.mock import patch


class TestEntityTypeNormalization(unittest.TestCase):
    """Test Issue 5.1: Centralized entity type normalization."""

    def test_normalize_entity_type_lowercase(self):
        """Entity types are normalized to UPPERCASE."""
        from openlabels.core.entity_types import normalize_entity_type

        self.assertEqual(normalize_entity_type("ssn"), "SSN")
        self.assertEqual(normalize_entity_type("email"), "EMAIL")
        self.assertEqual(normalize_entity_type("credit_card"), "CREDIT_CARD")

    def test_normalize_entity_type_uppercase(self):
        """Already uppercase types remain unchanged."""
        from openlabels.core.entity_types import normalize_entity_type

        self.assertEqual(normalize_entity_type("SSN"), "SSN")
        self.assertEqual(normalize_entity_type("EMAIL"), "EMAIL")

    def test_normalize_entity_type_strips_whitespace(self):
        """Whitespace is stripped from entity types."""
        from openlabels.core.entity_types import normalize_entity_type

        self.assertEqual(normalize_entity_type("  ssn  "), "SSN")
        self.assertEqual(normalize_entity_type("\temail\n"), "EMAIL")

    def test_normalize_entity_counts_merges_duplicates(self):
        """Counts for same entity type (different case) are merged."""
        from openlabels.core.entity_types import normalize_entity_counts

        counts = {"ssn": 2, "SSN": 3, "Ssn": 1}
        normalized = normalize_entity_counts(counts)

        self.assertEqual(normalized, {"SSN": 6})

    def test_scorer_handles_any_case(self):
        """Scorer produces same result regardless of entity type case."""
        from openlabels.core.scorer import score

        result1 = score({"ssn": 1}, "PRIVATE")
        result2 = score({"SSN": 1}, "PRIVATE")
        result3 = score({"Ssn": 1}, "PRIVATE")

        self.assertEqual(result1.score, result2.score)
        self.assertEqual(result2.score, result3.score)

    def test_components_scorer_uses_uppercase(self):
        """Components scorer normalizes to uppercase."""
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context

        ctx = Context()
        scorer = Scorer(ctx)

        # Test _normalize_entity_counts
        normalized = scorer._normalize_entity_counts({"ssn": 1, "email": 2})
        self.assertIn("SSN", normalized)
        self.assertIn("EMAIL", normalized)
        self.assertNotIn("ssn", normalized)

        ctx.close()


class TestExposureLevelEnforcement(unittest.TestCase):
    """Test Issue 5.2: ExposureLevel enum enforcement."""

    def test_normalize_exposure_from_string(self):
        """Strings are normalized to uppercase."""
        from openlabels.adapters.base import normalize_exposure_level

        self.assertEqual(normalize_exposure_level("private"), "PRIVATE")
        self.assertEqual(normalize_exposure_level("PUBLIC"), "PUBLIC")
        self.assertEqual(normalize_exposure_level("  org_wide  "), "ORG_WIDE")

    def test_normalize_exposure_from_enum(self):
        """Enum members return their name."""
        from openlabels.adapters.base import normalize_exposure_level, ExposureLevel

        self.assertEqual(normalize_exposure_level(ExposureLevel.PRIVATE), "PRIVATE")
        self.assertEqual(normalize_exposure_level(ExposureLevel.PUBLIC), "PUBLIC")

    def test_invalid_exposure_raises_error(self):
        """Invalid exposure level raises ValueError."""
        from openlabels.adapters.base import normalize_exposure_level

        with self.assertRaises(ValueError) as ctx:
            normalize_exposure_level("invalid")

        self.assertIn("Invalid exposure level", str(ctx.exception))

    def test_invalid_exposure_type_raises_error(self):
        """Non-string/enum types raise TypeError."""
        from openlabels.adapters.base import normalize_exposure_level

        with self.assertRaises(TypeError):
            normalize_exposure_level(123)

    def test_normalized_context_validates_exposure(self):
        """NormalizedContext validates and normalizes exposure."""
        from openlabels.adapters.base import NormalizedContext, ExposureLevel

        # String input
        ctx1 = NormalizedContext(exposure="public")
        self.assertEqual(ctx1.exposure, "PUBLIC")

        # Enum input
        ctx2 = NormalizedContext(exposure=ExposureLevel.ORG_WIDE)
        self.assertEqual(ctx2.exposure, "ORG_WIDE")

        # Invalid raises error
        with self.assertRaises(ValueError):
            NormalizedContext(exposure="invalid_level")

    def test_context_validates_default_exposure(self):
        """Context validates and normalizes default_exposure."""
        from openlabels.context import Context
        from openlabels.adapters.base import ExposureLevel

        # String input
        ctx1 = Context(default_exposure="internal")
        self.assertEqual(ctx1.default_exposure, "INTERNAL")
        ctx1.close()

        # Enum input
        ctx2 = Context(default_exposure=ExposureLevel.PUBLIC)
        self.assertEqual(ctx2.default_exposure, "PUBLIC")
        ctx2.close()

        # Invalid raises error
        with self.assertRaises(ValueError):
            Context(default_exposure="bad_value")


class TestOptionalFields(unittest.TestCase):
    """Test Issue 5.3: Optional vs required fields clarification."""

    def test_scan_result_score_is_optional(self):
        """ScanResult score defaults to None (not scanned)."""
        from openlabels.core.types import ScanResult

        result = ScanResult(path="/test/file.txt")
        self.assertIsNone(result.score)
        self.assertIsNone(result.tier)

    def test_was_scanned_false_when_score_none(self):
        """was_scanned returns False when score is None."""
        from openlabels.core.types import ScanResult

        result = ScanResult(path="/test/file.txt")
        self.assertFalse(result.was_scanned)

    def test_was_scanned_true_when_score_zero(self):
        """was_scanned returns True even when score is 0 (minimal risk)."""
        from openlabels.core.types import ScanResult

        result = ScanResult(path="/test/file.txt", score=0, tier="MINIMAL")
        self.assertTrue(result.was_scanned)

    def test_was_scanned_true_when_score_positive(self):
        """was_scanned returns True when score is positive."""
        from openlabels.core.types import ScanResult

        result = ScanResult(path="/test/data.csv", score=75, tier="HIGH")
        self.assertTrue(result.was_scanned)

    def test_was_scanned_false_when_error(self):
        """was_scanned returns False when there's an error."""
        from openlabels.core.types import ScanResult

        result = ScanResult(path="/test/file.txt", error="Permission denied")
        self.assertFalse(result.was_scanned)

    def test_has_error_property(self):
        """has_error correctly indicates error state."""
        from openlabels.core.types import ScanResult

        # No error
        result1 = ScanResult(path="/test/file.txt", score=50)
        self.assertFalse(result1.has_error)

        # With error
        result2 = ScanResult(path="/test/file.txt", error="Failed")
        self.assertTrue(result2.has_error)


class TestUnknownFilterFieldWarnings(unittest.TestCase):
    """Test Issue 5.4: Unknown filter field warnings."""

    def setUp(self):
        """Reset warning state before each test."""
        from openlabels.cli import filter as filter_module
        filter_module._unknown_field_warnings_issued.clear()

    def test_valid_field_no_warning(self):
        """Valid filter fields don't produce warnings."""
        from openlabels.cli.filter import FilterParser

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            FilterParser("score > 50").parse()
            self.assertEqual(len(w), 0)

    def test_unknown_field_warns(self):
        """Unknown filter fields produce warnings."""
        from openlabels.cli.filter import FilterParser

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            FilterParser("scroe > 50").parse()  # typo!

            self.assertEqual(len(w), 1)
            self.assertIn("Unknown filter field", str(w[0].message))
            self.assertIn("scroe", str(w[0].message))

    def test_unknown_field_warns_once_per_field(self):
        """Same unknown field only warns once."""
        from openlabels.cli.filter import FilterParser

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            FilterParser("scroe > 50").parse()
            FilterParser("scroe < 10").parse()  # Same typo

            self.assertEqual(len(w), 1)

    def test_different_unknown_fields_warn_separately(self):
        """Different unknown fields warn independently."""
        from openlabels.cli.filter import FilterParser

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            FilterParser("scroe > 50").parse()
            FilterParser("expozure = public").parse()

            self.assertEqual(len(w), 2)


class TestConfigSchemaVersioning(unittest.TestCase):
    """Test Issue 5.5: Config schema versioning."""

    def test_current_version_no_warning(self):
        """Current schema version doesn't produce warnings."""
        from openlabels.adapters.scanner.config import Config, CURRENT_SCHEMA_VERSION

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            config = Config()
            self.assertEqual(config.schema_version, CURRENT_SCHEMA_VERSION)
            self.assertEqual(len(w), 0)

    def test_old_version_warns_and_migrates(self):
        """Old schema version warns and migrates to current."""
        from openlabels.adapters.scanner.config import Config, CURRENT_SCHEMA_VERSION

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            config = Config(schema_version=0)

            # Should be migrated to current
            self.assertEqual(config.schema_version, CURRENT_SCHEMA_VERSION)
            # Should have warned
            self.assertEqual(len(w), 1)
            self.assertIn("older than current", str(w[0].message))

    def test_future_version_warns_and_normalizes(self):
        """Future schema version warns but continues."""
        from openlabels.adapters.scanner.config import Config, CURRENT_SCHEMA_VERSION

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            config = Config(schema_version=999)

            # Should be set to current
            self.assertEqual(config.schema_version, CURRENT_SCHEMA_VERSION)
            # Should have warned
            self.assertEqual(len(w), 1)
            self.assertIn("newer than current", str(w[0].message))


class TestConfidenceThresholdConstants(unittest.TestCase):
    """Test Issue 5.6: Confidence threshold constants."""

    def test_constants_defined(self):
        """Confidence constants are defined with expected values."""
        from openlabels.core.constants import (
            DEFAULT_CONFIDENCE_THRESHOLD,
            CONFIDENCE_WHEN_NO_SPANS,
            MIN_CONFIDENCE,
            MAX_CONFIDENCE,
        )

        self.assertEqual(DEFAULT_CONFIDENCE_THRESHOLD, 0.90)
        self.assertEqual(CONFIDENCE_WHEN_NO_SPANS, 0.90)
        self.assertEqual(MIN_CONFIDENCE, 0.0)
        self.assertEqual(MAX_CONFIDENCE, 1.0)

    def test_scorer_uses_default_constant(self):
        """score() function uses DEFAULT_CONFIDENCE_THRESHOLD."""
        import inspect
        from openlabels.core.scorer import score
        from openlabels.core.constants import DEFAULT_CONFIDENCE_THRESHOLD

        sig = inspect.signature(score)
        default = sig.parameters["confidence"].default

        self.assertEqual(default, DEFAULT_CONFIDENCE_THRESHOLD)

    def test_calculate_content_score_uses_constant(self):
        """calculate_content_score() uses DEFAULT_CONFIDENCE_THRESHOLD."""
        import inspect
        from openlabels.core.scorer import calculate_content_score
        from openlabels.core.constants import DEFAULT_CONFIDENCE_THRESHOLD

        sig = inspect.signature(calculate_content_score)
        default = sig.parameters["confidence"].default

        self.assertEqual(default, DEFAULT_CONFIDENCE_THRESHOLD)

    def test_scorer_component_uses_constant_for_no_spans(self):
        """Scorer component uses CONFIDENCE_WHEN_NO_SPANS for empty spans."""
        from openlabels.components.scorer import Scorer
        from openlabels.context import Context
        from openlabels.core.constants import CONFIDENCE_WHEN_NO_SPANS

        ctx = Context()
        scorer = Scorer(ctx)

        confidence = scorer._calculate_average_confidence([])
        self.assertEqual(confidence, CONFIDENCE_WHEN_NO_SPANS)

        ctx.close()


class TestPhase5Integration(unittest.TestCase):
    """Integration tests for Phase 5 features working together."""

    def test_full_scoring_pipeline_with_phase5_features(self):
        """Test full scoring pipeline with all Phase 5 features."""
        from openlabels.context import Context
        from openlabels.components.scorer import Scorer
        from openlabels.adapters.base import NormalizedContext, NormalizedInput, Entity, ExposureLevel
        from openlabels.core.types import ScanResult

        # Create context with enum exposure
        ctx = Context(default_exposure=ExposureLevel.INTERNAL)

        # Create scorer
        scorer = Scorer(ctx)

        # Create input with mixed case entity types and enum exposure
        context = NormalizedContext(exposure=ExposureLevel.PUBLIC)
        entities = [
            Entity(type="ssn", count=2, confidence=0.95, source="test"),  # lowercase
            Entity(type="EMAIL", count=1, confidence=0.80, source="test"),  # uppercase
        ]
        normalized_input = NormalizedInput(entities=entities, context=context)

        # Score
        result = scorer.score_from_adapters([normalized_input])

        # Verify result
        self.assertIsNotNone(result)
        self.assertGreater(result.score, 0)
        self.assertEqual(result.exposure, "PUBLIC")

        ctx.close()

    def test_scan_result_with_all_phase5_properties(self):
        """Test ScanResult with Phase 5 optional field semantics."""
        from openlabels.core.types import ScanResult

        # Not scanned
        result1 = ScanResult(path="/test/file1.txt")
        self.assertFalse(result1.was_scanned)
        self.assertFalse(result1.has_error)
        self.assertIsNone(result1.score)

        # Scanned with minimal risk
        result2 = ScanResult(path="/test/file2.txt", score=0, tier="MINIMAL")
        self.assertTrue(result2.was_scanned)
        self.assertFalse(result2.has_error)
        self.assertEqual(result2.score, 0)

        # Scanned with high risk
        result3 = ScanResult(path="/test/file3.txt", score=85, tier="CRITICAL")
        self.assertTrue(result3.was_scanned)
        self.assertEqual(result3.tier, "CRITICAL")

        # Error case
        result4 = ScanResult(path="/test/file4.txt", error="Access denied")
        self.assertFalse(result4.was_scanned)
        self.assertTrue(result4.has_error)


if __name__ == "__main__":
    unittest.main()

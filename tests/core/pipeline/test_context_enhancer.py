"""Tests for the expanded ContextEnhancer.

Verifies that context-aware enhancement works for all enabled entity
types (NAME, ADDRESS, USERNAME, MRN, MEDICATION) — not just MRN.

The expansion was motivated by Singh & Narayanan 2025 which found
contextual disambiguation is the #1 failure mode for NER-based PII.
"""

import pytest

from openlabels.core.pipeline.context_enhancer import (
    ContextEnhancer,
    create_enhancer,
)
from openlabels.core.types import Span, Tier


def _span(text, entity_type, start=0, confidence=0.6, tier=Tier.ML):
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector="test",
        tier=tier,
    )


class TestEnhancedTypes:
    """Test that all configured entity types are enhanced."""

    def test_mrn_still_enhanced(self):
        enhancer = ContextEnhancer()
        assert "MRN" in enhancer.enhanced_types

    def test_name_enhanced(self):
        enhancer = ContextEnhancer()
        assert "NAME" in enhancer.enhanced_types
        assert "PERSON" in enhancer.enhanced_types

    def test_address_enhanced(self):
        enhancer = ContextEnhancer()
        assert "ADDRESS" in enhancer.enhanced_types

    def test_username_enhanced(self):
        enhancer = ContextEnhancer()
        assert "USERNAME" in enhancer.enhanced_types

    def test_medication_enhanced(self):
        enhancer = ContextEnhancer()
        assert "MEDICATION" in enhancer.enhanced_types

    def test_non_enhanced_type_passes_through(self):
        enhancer = ContextEnhancer()
        span = _span("test@example.com", "EMAIL")
        result = enhancer.enhance_span("Send to test@example.com", span)
        assert result.action == "keep"
        assert "non_enhanced_type" in result.reasons


class TestNameDenyList:
    """Test deny list filtering for NAME entities."""

    def test_common_word_rejected(self):
        enhancer = ContextEnhancer()
        span = _span("will", "NAME")
        result = enhancer.enhance_span("We will proceed", span)
        assert result.action == "reject"

    def test_title_alone_rejected(self):
        enhancer = ContextEnhancer()
        span = _span("mr", "NAME")
        result = enhancer.enhance_span("Ask mr about this", span)
        assert result.action == "reject"

    def test_real_name_not_rejected(self):
        enhancer = ContextEnhancer()
        span = _span("Sarah", "NAME", confidence=0.9)
        result = enhancer.enhance_span("Patient name: Sarah", span)
        # Should not be rejected by deny list (Sarah is not in the list)
        assert result.action != "reject" or "deny_list" not in str(result.reasons)


class TestUsernameDenyList:
    """Test deny list filtering for USERNAME entities."""

    def test_common_word_rejected(self):
        enhancer = ContextEnhancer()
        span = _span("admin", "USERNAME")
        result = enhancer.enhance_span("Login as admin", span)
        assert result.action == "reject"


class TestAddressDenyList:
    """Test deny list filtering for ADDRESS entities."""

    def test_generic_location_rejected(self):
        enhancer = ContextEnhancer()
        span = _span("headquarters", "ADDRESS")
        result = enhancer.enhance_span("Visit headquarters", span)
        assert result.action == "reject"


class TestMedicationDenyList:
    """Test deny list filtering for MEDICATION entities."""

    def test_generic_health_word_rejected(self):
        enhancer = ContextEnhancer()
        span = _span("health", "MEDICATION")
        result = enhancer.enhance_span("Focus on health", span)
        assert result.action == "reject"


class TestNameHotwords:
    """Test hotword-based confidence adjustment for NAME entities."""

    def test_title_boosts_confidence(self):
        enhancer = ContextEnhancer()
        span = _span("Johnson", "NAME", start=4, confidence=0.6)
        result = enhancer.enhance_span("Dr. Johnson is here", span)
        assert result.confidence > 0.6

    def test_company_suffix_reduces_confidence(self):
        enhancer = ContextEnhancer()
        text = "Contact Johnson Inc. for details"
        span = _span("Johnson", "NAME", start=8, confidence=0.6)
        result = enhancer.enhance_span(text, span)
        assert result.confidence < 0.6


class TestAddressHotwords:
    """Test hotword-based confidence adjustment for ADDRESS entities."""

    def test_address_label_boosts_confidence(self):
        enhancer = ContextEnhancer()
        text = "Shipping address: 123 Main St"
        span = _span("123 Main St", "ADDRESS", start=18, confidence=0.6)
        result = enhancer.enhance_span(text, span)
        assert result.confidence > 0.6

    def test_digital_context_reduces_confidence(self):
        enhancer = ContextEnhancer()
        text = "Website: 123 Main St"
        span = _span("123 Main St", "ADDRESS", start=9, confidence=0.6)
        result = enhancer.enhance_span(text, span)
        assert result.confidence < 0.6


class TestUsernameHotwords:
    """Test hotword-based confidence adjustment for USERNAME entities."""

    def test_username_label_boosts_confidence(self):
        enhancer = ContextEnhancer()
        text = "Username: jdoe42"
        span = _span("jdoe42", "USERNAME", start=10, confidence=0.6)
        result = enhancer.enhance_span(text, span)
        assert result.confidence > 0.6

    def test_code_context_reduces_confidence(self):
        enhancer = ContextEnhancer()
        text = "import jdoe42"
        span = _span("jdoe42", "USERNAME", start=7, confidence=0.6)
        result = enhancer.enhance_span(text, span)
        assert result.confidence < 0.6


class TestHighTierBypass:
    """Test that high-tier detections bypass pattern/hotword stages."""

    def test_structured_tier_bypasses_patterns(self):
        enhancer = ContextEnhancer()
        span = _span("John", "NAME", confidence=0.8, tier=Tier.STRUCTURED)
        result = enhancer.enhance_span("Name: John", span)
        assert result.action == "keep"
        assert "high_tier" in result.reasons

    def test_checksum_tier_bypasses_patterns(self):
        enhancer = ContextEnhancer()
        span = _span("MED123456", "MRN", confidence=0.95, tier=Tier.CHECKSUM)
        result = enhancer.enhance_span("MRN: MED123456", span)
        assert result.action == "keep"


class TestEnhanceBatch:
    """Test the batch enhance() method."""

    def test_mixed_types_processed(self):
        enhancer = ContextEnhancer()
        text = "Name: will, Address: headquarters, Email: test@example.com"
        spans = [
            _span("will", "NAME", start=6),
            _span("headquarters", "ADDRESS", start=21),
            _span("test@example.com", "EMAIL", start=43),
        ]
        kept = enhancer.enhance(text, spans)
        # "will" and "headquarters" should be rejected, email should pass through
        types_kept = {s.entity_type for s in kept}
        assert "EMAIL" in types_kept
        assert "NAME" not in types_kept
        assert "ADDRESS" not in types_kept

    def test_empty_spans_returns_empty(self):
        enhancer = ContextEnhancer()
        assert enhancer.enhance("some text", []) == []


class TestCreateEnhancer:
    """Test the factory function."""

    def test_default_creation(self):
        enhancer = create_enhancer()
        assert isinstance(enhancer, ContextEnhancer)
        assert enhancer.high_threshold == 0.85

    def test_custom_thresholds(self):
        enhancer = create_enhancer(
            high_confidence_threshold=0.9,
            low_confidence_threshold=0.2,
        )
        assert enhancer.high_threshold == 0.9
        assert enhancer.low_threshold == 0.2

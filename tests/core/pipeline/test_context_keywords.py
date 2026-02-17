"""Tests for context keyword verification pipeline stage."""

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.pipeline.context_keywords import (
    CONTEXT_RULES,
    ContextRule,
    apply_context_keywords,
)


def _make_span(
    text: str,
    start: int = 0,
    entity_type: str = "PHONE",
    confidence: float = 0.70,
    tier: Tier = Tier.PATTERN,
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


class TestContextKeywordBoosting:
    """Test that confirming keywords boost confidence."""

    def test_phone_boosted_by_keyword(self):
        """'Phone: 555-1234' should boost PHONE confidence."""
        text = "Phone: 555-1234 is the number"
        span = _make_span("555-1234", start=7, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert len(result) == 1
        assert result[0].confidence > 0.70

    def test_ssn_boosted_by_keyword(self):
        """'SSN: 123-45-6789' should boost SSN confidence."""
        text = "SSN: 123-45-6789"
        span = _make_span("123-45-6789", start=5, entity_type="SSN", confidence=0.65)
        result = apply_context_keywords([span], text)
        assert result[0].confidence > 0.65

    def test_dob_boosted_by_keyword(self):
        """'Date of Birth: 01/15/1990' should boost DATE_DOB."""
        text = "Patient Date of Birth: 01/15/1990 recorded"
        span = _make_span("01/15/1990", start=23, entity_type="DATE_DOB", confidence=0.60)
        result = apply_context_keywords([span], text)
        assert result[0].confidence > 0.60

    def test_name_boosted_by_patient(self):
        """'Patient: John Smith' should boost NAME."""
        text = "Patient: John Smith was seen today"
        span = _make_span("John Smith", start=9, entity_type="NAME", confidence=0.60)
        result = apply_context_keywords([span], text)
        assert result[0].confidence > 0.60

    def test_email_boosted_by_keyword(self):
        """'Email: user@example.com' should boost EMAIL."""
        text = "Email: user@example.com"
        span = _make_span("user@example.com", start=7, entity_type="EMAIL", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert result[0].confidence > 0.70

    def test_boost_amount_matches_rule(self):
        """Boost should match the rule's boost_amount."""
        text = "Phone: 555-1234 number"
        span = _make_span("555-1234", start=7, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        expected = 0.70 + CONTEXT_RULES["PHONE"].boost_amount
        assert result[0].confidence == pytest.approx(expected)


class TestContextKeywordDemotion:
    """Test that contradicting keywords demote confidence."""

    def test_phone_demoted_by_order_keyword(self):
        """'Order #5551234567' should demote PHONE."""
        text = "Order #5551234567 confirmed"
        span = _make_span("5551234567", start=7, entity_type="PHONE", confidence=0.80)
        result = apply_context_keywords([span], text)
        assert result[0].confidence < 0.80

    def test_ssn_demoted_by_invoice_keyword(self):
        """'Invoice 123-45-6789' should demote SSN."""
        text = "Invoice 123-45-6789 paid"
        span = _make_span("123-45-6789", start=8, entity_type="SSN", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert result[0].confidence < 0.70

    def test_age_demoted_by_page_keyword(self):
        """'Page 42' should demote AGE."""
        text = "See page 42 for details"
        span = _make_span("42", start=9, entity_type="AGE", confidence=0.75)
        result = apply_context_keywords([span], text)
        assert result[0].confidence < 0.75

    def test_demote_amount_matches_rule(self):
        """Demote should match the rule's demote_amount."""
        text = "Order #5551234567 confirmed"
        span = _make_span("5551234567", start=7, entity_type="PHONE", confidence=0.80)
        result = apply_context_keywords([span], text)
        expected = 0.80 - CONTEXT_RULES["PHONE"].demote_amount
        assert result[0].confidence == pytest.approx(expected)


class TestContextKeywordNeutrality:
    """Test cases where no adjustment should occur."""

    def test_no_keywords_no_change(self):
        """No context keywords means no adjustment."""
        text = "The value is 555-1234 found here"
        span = _make_span("555-1234", start=13, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert result[0].confidence == 0.70

    def test_both_boost_and_demote_cancel(self):
        """Presence of both boost and demote keywords cancels out."""
        text = "Phone order tracking 555-1234"
        span = _make_span("555-1234", start=21, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        # "phone" boosts, "order" + "tracking" demotes → cancel
        assert result[0].confidence == 0.70

    def test_unknown_entity_type_unchanged(self):
        """Entity types not in CONTEXT_RULES pass through unchanged."""
        text = "Some bitcoin address bc1abc123 here"
        span = _make_span("bc1abc123", start=21, entity_type="BITCOIN_ADDRESS", confidence=0.80)
        result = apply_context_keywords([span], text)
        assert result[0].confidence == 0.80

    def test_empty_spans_returns_empty(self):
        """Empty input returns empty output."""
        result = apply_context_keywords([], "some text")
        assert result == []

    def test_empty_text_returns_original(self):
        """Empty text returns original spans unchanged."""
        span = _make_span("test", entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], "")
        assert result[0].confidence == 0.70


class TestContextKeywordEdgeCases:
    """Edge cases for context keyword verification."""

    def test_span_at_start_of_text(self):
        """Span at position 0 doesn't crash (no before-context)."""
        text = "5551234567 is a number"
        span = _make_span("5551234567", start=0, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert len(result) == 1

    def test_span_at_end_of_text(self):
        """Span at end of text doesn't crash (no after-context)."""
        text = "Call 5551234567"
        span = _make_span("5551234567", start=5, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert len(result) == 1

    def test_confidence_capped_at_1(self):
        """Boosting cannot exceed 1.0."""
        text = "Phone: 555-1234"
        span = _make_span("555-1234", start=7, entity_type="PHONE", confidence=0.98)
        result = apply_context_keywords([span], text)
        assert result[0].confidence <= 1.0

    def test_confidence_floored_at_0(self):
        """Demotion cannot go below 0.0."""
        text = "Order serial tracking 555-1234"
        span = _make_span("555-1234", start=22, entity_type="PHONE", confidence=0.05)
        result = apply_context_keywords([span], text)
        assert result[0].confidence >= 0.0

    def test_multiple_spans_processed(self):
        """Multiple spans in the same text are each processed."""
        text = "Phone: 555-1234, SSN: 123-45-6789"
        spans = [
            _make_span("555-1234", start=7, entity_type="PHONE", confidence=0.70),
            _make_span("123-45-6789", start=22, entity_type="SSN", confidence=0.65),
        ]
        result = apply_context_keywords(spans, text)
        assert len(result) == 2
        assert result[0].confidence > 0.70  # PHONE boosted
        assert result[1].confidence > 0.65  # SSN boosted

    def test_case_insensitive_keyword_matching(self):
        """Keywords are matched case-insensitively."""
        text = "PHONE: 555-1234 number"
        span = _make_span("555-1234", start=7, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert result[0].confidence > 0.70

    def test_span_metadata_preserved(self):
        """Non-confidence fields are preserved after adjustment."""
        text = "Phone: 555-1234"
        span = _make_span("555-1234", start=7, entity_type="PHONE", confidence=0.70)
        result = apply_context_keywords([span], text)
        assert result[0].start == 7
        assert result[0].end == 15
        assert result[0].text == "555-1234"
        assert result[0].entity_type == "PHONE"
        assert result[0].detector == "test"
        assert result[0].tier == Tier.PATTERN


class TestContextRulesCompleteness:
    """Verify all rules are well-formed."""

    @pytest.mark.parametrize("entity_type", list(CONTEXT_RULES.keys()))
    def test_rule_has_positive_window(self, entity_type):
        rule = CONTEXT_RULES[entity_type]
        assert rule.window_chars > 0

    @pytest.mark.parametrize("entity_type", list(CONTEXT_RULES.keys()))
    def test_rule_has_non_negative_amounts(self, entity_type):
        rule = CONTEXT_RULES[entity_type]
        assert rule.boost_amount >= 0
        assert rule.demote_amount >= 0

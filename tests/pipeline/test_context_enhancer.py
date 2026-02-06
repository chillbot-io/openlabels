"""Tests for context_enhancer.py - Context-aware PII detection enhancement.

Tests cover:
- Deny list filtering (NAME, USERNAME, ADDRESS, MEDICATION, MRN)
- Pattern-based exclusions (HTML, reference codes, company patterns)
- Hotword-based confidence adjustment (positive and negative)
- Confidence routing (keep, reject, verify)
- ContextEnhancer class methods
- EnhancementResult dataclass

Tests context-aware PII detection enhancement.
"""

import re
import pytest

from openlabels.core.types import Span, Tier


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def make_span():
    """Factory for creating test spans."""
    def _make_span(
        text: str,
        start: int = 0,
        entity_type: str = "NAME",
        confidence: float = 0.7,
        detector: str = "ml",
        tier: Tier = Tier.ML,
    ) -> Span:
        return Span(
            start=start,
            end=start + len(text),
            text=text,
            entity_type=entity_type,
            confidence=confidence,
            detector=detector,
            tier=tier,
        )
    return _make_span


@pytest.fixture
def enhancer():
    """Create default ContextEnhancer."""
    from openlabels.core.pipeline.context_enhancer import ContextEnhancer
    return ContextEnhancer()


# =============================================================================
# DENY LIST TESTS
# =============================================================================

class TestNameDenyList:
    """Tests for NAME deny list filtering."""

    def test_common_verbs_denied(self):
        """Common verbs are in NAME deny list."""
        from openlabels.core.pipeline.context_enhancer import NAME_DENY_LIST

        # Verify common false positives are in deny list
        assert "will" in NAME_DENY_LIST
        assert "may" in NAME_DENY_LIST
        assert "can" in NAME_DENY_LIST

    def test_document_words_denied(self):
        """Document-related words are denied."""
        from openlabels.core.pipeline.context_enhancer import NAME_DENY_LIST

        assert "signature" in NAME_DENY_LIST
        assert "signed" in NAME_DENY_LIST
        assert "reports" in NAME_DENY_LIST

    def test_generic_roles_denied(self):
        """Generic role terms are denied."""
        from openlabels.core.pipeline.context_enhancer import NAME_DENY_LIST

        assert "admin" in NAME_DENY_LIST
        assert "user" in NAME_DENY_LIST
        assert "customer" in NAME_DENY_LIST
        assert "patient" in NAME_DENY_LIST

    def test_tech_terms_denied(self):
        """Tech/product terms are denied."""
        from openlabels.core.pipeline.context_enhancer import NAME_DENY_LIST

        assert "null" in NAME_DENY_LIST
        assert "undefined" in NAME_DENY_LIST
        assert "none" in NAME_DENY_LIST

    def test_html_artifacts_denied(self):
        """HTML artifacts are denied."""
        from openlabels.core.pipeline.context_enhancer import NAME_DENY_LIST

        assert "input" in NAME_DENY_LIST
        assert "label" in NAME_DENY_LIST
        assert "div" in NAME_DENY_LIST
        assert "span" in NAME_DENY_LIST

    def test_titles_alone_denied(self):
        """Standalone titles are denied."""
        from openlabels.core.pipeline.context_enhancer import NAME_DENY_LIST

        assert "mr" in NAME_DENY_LIST
        assert "mrs" in NAME_DENY_LIST
        assert "dr" in NAME_DENY_LIST

    def test_currency_names_denied(self):
        """Currency names are denied."""
        from openlabels.core.pipeline.context_enhancer import NAME_DENY_LIST

        assert "dollar" in NAME_DENY_LIST
        assert "euro" in NAME_DENY_LIST
        assert "pound" in NAME_DENY_LIST


class TestUsernameDenyList:
    """Tests for USERNAME deny list."""

    def test_common_words_denied(self):
        """Common words falsely detected as usernames are denied."""
        from openlabels.core.pipeline.context_enhancer import USERNAME_DENY_LIST

        assert "has" in USERNAME_DENY_LIST
        assert "number" in USERNAME_DENY_LIST
        assert "agent" in USERNAME_DENY_LIST
        assert "details" in USERNAME_DENY_LIST

    def test_generic_roles_denied(self):
        """Generic role terms are denied as usernames."""
        from openlabels.core.pipeline.context_enhancer import USERNAME_DENY_LIST

        assert "admin" in USERNAME_DENY_LIST
        assert "user" in USERNAME_DENY_LIST
        assert "system" in USERNAME_DENY_LIST
        assert "root" in USERNAME_DENY_LIST


class TestAddressDenyList:
    """Tests for ADDRESS deny list."""

    def test_building_types_denied(self):
        """Building types are denied as addresses."""
        from openlabels.core.pipeline.context_enhancer import ADDRESS_DENY_LIST

        assert "maisonette" in ADDRESS_DENY_LIST
        assert "apartment" in ADDRESS_DENY_LIST
        assert "flat" in ADDRESS_DENY_LIST

    def test_department_terms_denied(self):
        """Department/organizational terms are denied."""
        from openlabels.core.pipeline.context_enhancer import ADDRESS_DENY_LIST

        assert "operations" in ADDRESS_DENY_LIST
        assert "department" in ADDRESS_DENY_LIST
        assert "headquarters" in ADDRESS_DENY_LIST


class TestMedicationDenyList:
    """Tests for MEDICATION deny list."""

    def test_generic_health_words_denied(self):
        """Generic health words are denied as medications."""
        from openlabels.core.pipeline.context_enhancer import MEDICATION_DENY_LIST

        assert "health" in MEDICATION_DENY_LIST
        assert "stress" in MEDICATION_DENY_LIST
        assert "care" in MEDICATION_DENY_LIST
        assert "treatment" in MEDICATION_DENY_LIST


class TestMRNExcludePatterns:
    """Tests for MRN exclusion patterns."""

    def test_dollar_amounts_excluded(self):
        """Dollar amounts are excluded from MRN."""
        from openlabels.core.pipeline.context_enhancer import MRN_EXCLUDE_PATTERNS

        # Dollar amounts look like MRN but shouldn't match
        test_cases = ["440060.24", "512717.39", "100.00"]
        for value in test_cases:
            matched = any(p.search(value) for p in MRN_EXCLUDE_PATTERNS)
            assert matched, f"{value} should be excluded as dollar amount"

    def test_currency_symbols_excluded(self):
        """Currency with symbols excluded from MRN."""
        from openlabels.core.pipeline.context_enhancer import MRN_EXCLUDE_PATTERNS

        test_cases = ["$850", "€100", "£50"]
        for value in test_cases:
            matched = any(p.search(value) for p in MRN_EXCLUDE_PATTERNS)
            assert matched, f"{value} should be excluded as currency"


# =============================================================================
# COMPANY AND LOCATION SUFFIXES TESTS
# =============================================================================

class TestCompanySuffixes:
    """Tests for company suffix detection."""

    def test_common_suffixes_present(self):
        """Common company suffixes are defined."""
        from openlabels.core.pipeline.context_enhancer import COMPANY_SUFFIXES

        assert "inc" in COMPANY_SUFFIXES
        assert "llc" in COMPANY_SUFFIXES
        assert "ltd" in COMPANY_SUFFIXES
        assert "corp" in COMPANY_SUFFIXES
        assert "company" in COMPANY_SUFFIXES




# =============================================================================
# HOTWORD RULE TESTS
# =============================================================================

class TestHotwordRules:
    """Tests for hotword rules."""

    def test_positive_name_hotwords_defined(self):
        """Positive NAME hotwords are defined with expected structure."""
        from openlabels.core.pipeline.context_enhancer import NAME_POSITIVE_HOTWORDS, HotwordRule

        assert len(NAME_POSITIVE_HOTWORDS) >= 1, "Should have at least one positive hotword"
        # Verify structure of first hotword
        first_rule = NAME_POSITIVE_HOTWORDS[0]
        assert isinstance(first_rule, HotwordRule), "Hotwords should be HotwordRule instances"
        assert first_rule.confidence_delta > 0, "Positive hotwords should have positive delta"

    def test_negative_name_hotwords_defined(self):
        """Negative NAME hotwords are defined with expected structure."""
        from openlabels.core.pipeline.context_enhancer import NAME_NEGATIVE_HOTWORDS, HotwordRule

        assert len(NAME_NEGATIVE_HOTWORDS) >= 1, "Should have at least one negative hotword"
        # Verify structure of first hotword
        first_rule = NAME_NEGATIVE_HOTWORDS[0]
        assert isinstance(first_rule, HotwordRule), "Hotwords should be HotwordRule instances"
        assert first_rule.confidence_delta < 0, "Negative hotwords should have negative delta"



# =============================================================================
# PATTERN TESTS
# =============================================================================

class TestPatterns:
    """Tests for exclusion patterns."""

    def test_company_pattern(self):
        """COMPANY_PATTERN matches law firm style names."""
        from openlabels.core.pipeline.context_enhancer import COMPANY_PATTERN

        assert COMPANY_PATTERN.match("Smith, Jones and Brown")
        assert COMPANY_PATTERN.match("Walker and Associates")
        assert not COMPANY_PATTERN.match("John Smith")

    def test_greeting_pattern(self):
        """GREETING_PATTERN matches common greetings."""
        from openlabels.core.pipeline.context_enhancer import GREETING_PATTERN

        assert GREETING_PATTERN.match("Hi John")
        assert GREETING_PATTERN.match("hello World")
        assert GREETING_PATTERN.match("Dear Customer")
        assert not GREETING_PATTERN.match("John Smith")

    def test_html_pattern(self):
        """HTML_PATTERN matches HTML content."""
        from openlabels.core.pipeline.context_enhancer import HTML_PATTERN

        assert HTML_PATTERN.search("<div>")
        assert HTML_PATTERN.search("</span>")
        assert HTML_PATTERN.search("&nbsp;")
        assert not HTML_PATTERN.search("plain text")

    def test_reference_code_pattern(self):
        """REFERENCE_CODE_PATTERN matches document codes."""
        from openlabels.core.pipeline.context_enhancer import REFERENCE_CODE_PATTERN

        assert REFERENCE_CODE_PATTERN.match("REF-123")
        assert REFERENCE_CODE_PATTERN.match("INV-456")
        assert REFERENCE_CODE_PATTERN.match("DOC123")
        assert not REFERENCE_CODE_PATTERN.match("John")

    def test_all_caps_pattern(self):
        """ALL_CAPS_PATTERN matches all-caps strings."""
        from openlabels.core.pipeline.context_enhancer import ALL_CAPS_PATTERN

        assert ALL_CAPS_PATTERN.match("ABC")
        assert ALL_CAPS_PATTERN.match("USA")
        assert not ALL_CAPS_PATTERN.match("Abc")


# =============================================================================
# CONTEXT ENHANCER INITIALIZATION TESTS
# =============================================================================

class TestContextEnhancerInit:
    """Tests for ContextEnhancer initialization."""

    def test_default_thresholds(self):
        """ContextEnhancer has default thresholds."""
        from openlabels.core.pipeline.context_enhancer import ContextEnhancer

        enhancer = ContextEnhancer()

        assert enhancer.high_threshold == 0.85
        assert enhancer.low_threshold == 0.35

    def test_custom_thresholds(self):
        """ContextEnhancer accepts custom thresholds."""
        from openlabels.core.pipeline.context_enhancer import ContextEnhancer

        enhancer = ContextEnhancer(
            high_confidence_threshold=0.9,
            low_confidence_threshold=0.4
        )

        assert enhancer.high_threshold == 0.9
        assert enhancer.low_threshold == 0.4

    def test_feature_flags(self):
        """ContextEnhancer accepts feature flags."""
        from openlabels.core.pipeline.context_enhancer import ContextEnhancer

        enhancer = ContextEnhancer(
            enable_deny_list=False,
            enable_hotwords=False,
            enable_patterns=False
        )

        assert enhancer.enable_deny_list is False
        assert enhancer.enable_hotwords is False
        assert enhancer.enable_patterns is False


# =============================================================================
# CONTEXT ENHANCER METHOD TESTS
# =============================================================================

class TestContextEnhancerGetContextWindow:
    """Tests for _get_context_window method."""

    def test_get_context_basic(self, enhancer, make_span):
        """Gets context around span."""
        text = "Hello John Smith how are you"
        span = make_span("John Smith", start=6)

        before, after = enhancer._get_context_window(text, span, 10, 10)

        assert "Hello" in before
        assert "how" in after

    def test_get_context_at_start(self, enhancer, make_span):
        """Handles span at start of text."""
        text = "John Smith how are you"
        span = make_span("John Smith", start=0)

        before, after = enhancer._get_context_window(text, span, 10, 10)

        assert before == ""
        assert "how" in after

    def test_get_context_at_end(self, enhancer, make_span):
        """Handles span at end of text."""
        text = "Hello John Smith"
        span = make_span("John Smith", start=6)

        before, after = enhancer._get_context_window(text, span, 10, 10)

        assert "Hello" in before
        assert after == ""


class TestContextEnhancerCheckDenyList:
    """Tests for _check_deny_list method."""

    def test_denies_name_in_list(self, enhancer, make_span):
        """Denies NAME in deny list."""
        span = make_span("will", entity_type="NAME")

        reason = enhancer._check_deny_list(span)

        # Verify the reason indicates deny_list rejection
        assert isinstance(reason, str), f"Expected string reason, got {type(reason)}"
        assert "deny_list" in reason, f"Reason should mention deny_list: {reason}"

    def test_allows_valid_name(self, enhancer, make_span):
        """Allows valid NAME not in deny list."""
        span = make_span("John", entity_type="NAME")

        reason = enhancer._check_deny_list(span)

        assert reason is None

    def test_denies_username_in_list(self, enhancer, make_span):
        """Denies USERNAME in deny list."""
        span = make_span("admin", entity_type="USERNAME")

        reason = enhancer._check_deny_list(span)

        assert isinstance(reason, str), "admin should be denied as username"
        assert "deny_list" in reason or "admin" in reason.lower()

    def test_denies_address_in_list(self, enhancer, make_span):
        """Denies ADDRESS in deny list."""
        span = make_span("maisonette", entity_type="ADDRESS")

        reason = enhancer._check_deny_list(span)

        assert isinstance(reason, str), "maisonette should be denied as address"

    def test_denies_medication_in_list(self, enhancer, make_span):
        """Denies MEDICATION in deny list."""
        span = make_span("health", entity_type="MEDICATION")

        reason = enhancer._check_deny_list(span)

        assert isinstance(reason, str), "health should be denied as medication"

    def test_mrn_uses_pattern_exclusion(self, enhancer, make_span):
        """MRN uses pattern-based exclusion."""
        span = make_span("440060.24", entity_type="MRN")

        reason = enhancer._check_deny_list(span)

        assert isinstance(reason, str), "Dollar amount should be excluded from MRN"
        assert "mrn_exclude" in reason, f"Reason should mention mrn_exclude: {reason}"


class TestContextEnhancerEnhanceSpan:
    """Tests for enhance_span method."""

    def test_non_enhanced_type_passes(self, enhancer, make_span):
        """Non-enhanced types pass through with 'keep'."""
        span = make_span("John Smith", entity_type="NAME", confidence=0.7)

        result = enhancer.enhance_span("Hello John Smith", span)

        # NAME is not in enhanced_types (only MRN is)
        assert result.action == "keep"
        assert "non_enhanced_type" in result.reasons

    def test_deny_list_rejects(self, enhancer, make_span):
        """Deny list rejection returns 'reject'."""
        # MRN is in enhanced_types
        span = make_span("440060.24", entity_type="MRN", confidence=0.7)

        result = enhancer.enhance_span("Amount: 440060.24", span)

        assert result.action == "reject"
        assert result.confidence == 0.0


class TestContextEnhancerEnhance:
    """Tests for enhance method (batch processing)."""

    def test_empty_spans_returns_empty(self, enhancer):
        """Empty span list returns empty."""
        result = enhancer.enhance("Hello world", [])

        assert result == []

    def test_processes_multiple_spans(self, enhancer, make_span):
        """Processes multiple spans."""
        spans = [
            make_span("John", start=0, entity_type="NAME"),
            make_span("Smith", start=5, entity_type="NAME"),
        ]

        result = enhancer.enhance("John Smith", spans)

        # Both should pass (NAME not in enhanced_types)
        assert len(result) == 2


# =============================================================================
# CREATE ENHANCER FUNCTION TESTS
# =============================================================================

class TestCreateEnhancer:
    """Tests for create_enhancer function."""

    def test_creates_default_enhancer(self):
        """Creates enhancer with defaults."""
        from openlabels.core.pipeline.context_enhancer import create_enhancer

        enhancer = create_enhancer()

        assert enhancer.high_threshold == 0.85
        assert enhancer.low_threshold == 0.35

    def test_creates_custom_enhancer(self):
        """Creates enhancer with custom settings."""
        from openlabels.core.pipeline.context_enhancer import create_enhancer

        enhancer = create_enhancer(
            high_confidence_threshold=0.9,
            enable_hotwords=False
        )

        assert enhancer.high_threshold == 0.9
        assert enhancer.enable_hotwords is False


# =============================================================================
# EDGE CASES AND INTEGRATION TESTS
# =============================================================================

class TestContextEnhancerEdgeCases:
    """Edge case tests for ContextEnhancer."""

    def test_unicode_text(self, enhancer, make_span):
        """Handles Unicode text without errors."""
        span = make_span("José García", entity_type="NAME")

        result = enhancer.enhance_span("Hello José García!", span)

        # Should return valid result with an action
        assert result.action in ("keep", "reject", "verify"), \
            f"Expected valid action, got: {result.action}"

    def test_span_at_text_boundary(self, enhancer, make_span):
        """Handles span at text boundaries."""
        text = "John"
        span = make_span("John", start=0, entity_type="NAME")

        result = enhancer.enhance_span(text, span)

        # Should return valid result with an action
        assert result.action in ("keep", "reject", "verify"), \
            f"Expected valid action, got: {result.action}"

    def test_case_insensitive_deny_list(self, enhancer, make_span):
        """Deny list check is case insensitive."""
        span1 = make_span("WILL", entity_type="NAME")
        span2 = make_span("Will", entity_type="NAME")

        reason1 = enhancer._check_deny_list(span1)
        reason2 = enhancer._check_deny_list(span2)

        # Both should be denied regardless of case
        assert isinstance(reason1, str), "WILL (uppercase) should be denied"
        assert isinstance(reason2, str), "Will (titlecase) should be denied"

    def test_preserves_span_attributes(self, enhancer, make_span):
        """Preserves non-modified span attributes."""
        span = make_span("John", entity_type="NAME", detector="custom_detector")

        result = enhancer.enhance("Hello John", [span])

        if result:
            assert result[0].detector == "custom_detector"


class TestContextEnhancerPerformance:
    """Tests for performance characteristics."""

    def test_handles_long_text(self, enhancer, make_span):
        """Handles long text efficiently."""
        long_text = "Word " * 10000
        span = make_span("John", start=50, entity_type="NAME")

        # Should not timeout and return valid result
        result = enhancer.enhance_span(long_text, span)

        assert result.action in ("keep", "reject", "verify"), \
            f"Expected valid action for long text, got: {result.action}"

    def test_handles_many_spans(self, enhancer, make_span):
        """Handles many spans efficiently."""
        spans = [
            make_span(f"Name{i}", start=i*10, entity_type="NAME")
            for i in range(100)
        ]
        text = " ".join(f"Name{i}" for i in range(100))

        # Should not timeout
        result = enhancer.enhance(text, spans)

        assert len(result) == 100

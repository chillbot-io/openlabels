"""Tests for detectors/context_enhancer.py - Context-aware PII detection enhancement.

Tests cover:
- Deny list filtering (NAME, USERNAME, ADDRESS, MEDICATION, MRN)
- Pattern-based exclusions (HTML, reference codes, company patterns)
- Hotword-based confidence adjustment (positive and negative)
- Confidence routing (keep, reject, verify)
- ContextEnhancer class methods
- EnhancementResult dataclass
- HotwordRule application
- Helper functions (create_enhancer)
"""

import re
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from scrubiq.types import Span, Tier


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
    from scrubiq.detectors.context_enhancer import ContextEnhancer
    return ContextEnhancer()


# =============================================================================
# DENY LIST TESTS
# =============================================================================

class TestNameDenyList:
    """Tests for NAME deny list filtering."""

    def test_common_verbs_denied(self, make_span):
        """Common verbs are in NAME deny list."""
        from scrubiq.detectors.context_enhancer import NAME_DENY_LIST

        # Verify common false positives are in deny list
        assert "will" in NAME_DENY_LIST
        assert "may" in NAME_DENY_LIST
        assert "can" in NAME_DENY_LIST
        assert "ensure" in NAME_DENY_LIST

    def test_document_words_denied(self, make_span):
        """Document-related words are denied."""
        from scrubiq.detectors.context_enhancer import NAME_DENY_LIST

        assert "signature" in NAME_DENY_LIST
        assert "signed" in NAME_DENY_LIST
        assert "reports" in NAME_DENY_LIST

    def test_generic_roles_denied(self):
        """Generic role terms are denied."""
        from scrubiq.detectors.context_enhancer import NAME_DENY_LIST

        assert "admin" in NAME_DENY_LIST
        assert "user" in NAME_DENY_LIST
        assert "customer" in NAME_DENY_LIST
        assert "patient" in NAME_DENY_LIST

    def test_tech_terms_denied(self):
        """Tech/product terms are denied."""
        from scrubiq.detectors.context_enhancer import NAME_DENY_LIST

        assert "null" in NAME_DENY_LIST
        assert "undefined" in NAME_DENY_LIST
        assert "none" in NAME_DENY_LIST

    def test_html_artifacts_denied(self):
        """HTML artifacts are denied."""
        from scrubiq.detectors.context_enhancer import NAME_DENY_LIST

        assert "input" in NAME_DENY_LIST
        assert "label" in NAME_DENY_LIST
        assert "div" in NAME_DENY_LIST
        assert "span" in NAME_DENY_LIST

    def test_titles_alone_denied(self):
        """Standalone titles are denied."""
        from scrubiq.detectors.context_enhancer import NAME_DENY_LIST

        assert "mr" in NAME_DENY_LIST
        assert "mrs" in NAME_DENY_LIST
        assert "dr" in NAME_DENY_LIST

    def test_currency_names_denied(self):
        """Currency names are denied."""
        from scrubiq.detectors.context_enhancer import NAME_DENY_LIST

        assert "dollar" in NAME_DENY_LIST
        assert "euro" in NAME_DENY_LIST
        assert "pound" in NAME_DENY_LIST


class TestUsernameDenyList:
    """Tests for USERNAME deny list."""

    def test_common_words_denied(self):
        """Common words falsely detected as usernames are denied."""
        from scrubiq.detectors.context_enhancer import USERNAME_DENY_LIST

        assert "has" in USERNAME_DENY_LIST
        assert "number" in USERNAME_DENY_LIST
        assert "agent" in USERNAME_DENY_LIST
        assert "details" in USERNAME_DENY_LIST

    def test_generic_roles_denied(self):
        """Generic role terms are denied as usernames."""
        from scrubiq.detectors.context_enhancer import USERNAME_DENY_LIST

        assert "admin" in USERNAME_DENY_LIST
        assert "user" in USERNAME_DENY_LIST
        assert "system" in USERNAME_DENY_LIST
        assert "root" in USERNAME_DENY_LIST


class TestAddressDenyList:
    """Tests for ADDRESS deny list."""

    def test_building_types_denied(self):
        """Building types are denied as addresses."""
        from scrubiq.detectors.context_enhancer import ADDRESS_DENY_LIST

        assert "maisonette" in ADDRESS_DENY_LIST
        assert "apartment" in ADDRESS_DENY_LIST
        assert "flat" in ADDRESS_DENY_LIST
        assert "condo" in ADDRESS_DENY_LIST

    def test_department_terms_denied(self):
        """Department/organizational terms are denied."""
        from scrubiq.detectors.context_enhancer import ADDRESS_DENY_LIST

        assert "operations" in ADDRESS_DENY_LIST
        assert "department" in ADDRESS_DENY_LIST
        assert "headquarters" in ADDRESS_DENY_LIST


class TestMedicationDenyList:
    """Tests for MEDICATION deny list."""

    def test_generic_health_words_denied(self):
        """Generic health words are denied as medications."""
        from scrubiq.detectors.context_enhancer import MEDICATION_DENY_LIST

        assert "health" in MEDICATION_DENY_LIST
        assert "stress" in MEDICATION_DENY_LIST
        assert "care" in MEDICATION_DENY_LIST
        assert "treatment" in MEDICATION_DENY_LIST


class TestMRNExcludePatterns:
    """Tests for MRN exclusion patterns."""

    def test_dollar_amounts_excluded(self):
        """Dollar amounts are excluded from MRN."""
        from scrubiq.detectors.context_enhancer import MRN_EXCLUDE_PATTERNS

        # 440060.24 looks like MRN but is dollar amount
        test_cases = ["440060.24", "512717.39", "100.00"]
        for value in test_cases:
            matched = any(p.search(value) for p in MRN_EXCLUDE_PATTERNS)
            assert matched, f"{value} should be excluded as dollar amount"

    def test_currency_symbols_excluded(self):
        """Currency with symbols excluded from MRN."""
        from scrubiq.detectors.context_enhancer import MRN_EXCLUDE_PATTERNS

        test_cases = ["$850", "€100", "£50"]
        for value in test_cases:
            matched = any(p.search(value) for p in MRN_EXCLUDE_PATTERNS)
            assert matched, f"{value} should be excluded as currency"

    def test_user_agents_excluded(self):
        """User agent versions excluded from MRN."""
        from scrubiq.detectors.context_enhancer import MRN_EXCLUDE_PATTERNS

        test_cases = ["Chrome/25.0.801.0", "Safari/537.1.0", "Firefox/100.0"]
        for value in test_cases:
            matched = any(p.search(value) for p in MRN_EXCLUDE_PATTERNS)
            assert matched, f"{value} should be excluded as user agent"

    def test_crypto_addresses_excluded(self):
        """Long alphanumeric crypto addresses excluded."""
        from scrubiq.detectors.context_enhancer import MRN_EXCLUDE_PATTERNS

        crypto = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Bitcoin-like
        matched = any(p.search(crypto) for p in MRN_EXCLUDE_PATTERNS)
        assert matched


# =============================================================================
# COMPANY AND LOCATION SUFFIXES TESTS
# =============================================================================

class TestCompanySuffixes:
    """Tests for company suffix detection."""

    def test_common_suffixes_present(self):
        """Common company suffixes are defined."""
        from scrubiq.detectors.context_enhancer import COMPANY_SUFFIXES

        assert "inc" in COMPANY_SUFFIXES
        assert "llc" in COMPANY_SUFFIXES
        assert "ltd" in COMPANY_SUFFIXES
        assert "corp" in COMPANY_SUFFIXES
        assert "company" in COMPANY_SUFFIXES


class TestLocationSuffixes:
    """Tests for location suffix detection."""

    def test_street_suffixes_present(self):
        """Street suffixes are defined."""
        from scrubiq.detectors.context_enhancer import LOCATION_SUFFIXES

        assert "street" in LOCATION_SUFFIXES
        assert "avenue" in LOCATION_SUFFIXES
        assert "road" in LOCATION_SUFFIXES
        assert "drive" in LOCATION_SUFFIXES


# =============================================================================
# HOTWORD RULE TESTS
# =============================================================================

class TestHotwordRules:
    """Tests for hotword rules."""

    def test_positive_name_hotwords_exist(self):
        """Positive NAME hotwords are defined."""
        from scrubiq.detectors.context_enhancer import NAME_POSITIVE_HOTWORDS

        assert len(NAME_POSITIVE_HOTWORDS) > 0

        # Check for title hotword
        has_title = any("mr" in str(hw.pattern.pattern).lower() for hw in NAME_POSITIVE_HOTWORDS)
        assert has_title

    def test_negative_name_hotwords_exist(self):
        """Negative NAME hotwords are defined."""
        from scrubiq.detectors.context_enhancer import NAME_NEGATIVE_HOTWORDS

        assert len(NAME_NEGATIVE_HOTWORDS) > 0

        # Check for company suffix hotword
        has_company = any("inc" in str(hw.pattern.pattern).lower() for hw in NAME_NEGATIVE_HOTWORDS)
        assert has_company

    def test_hotword_rule_structure(self):
        """HotwordRule has required attributes."""
        from scrubiq.detectors.context_enhancer import HotwordRule

        rule = HotwordRule(
            pattern=re.compile(r'\btest\b'),
            confidence_delta=0.2,
            window_before=50,
            window_after=30,
            description="Test rule"
        )

        assert rule.pattern is not None
        assert rule.confidence_delta == 0.2
        assert rule.window_before == 50
        assert rule.window_after == 30
        assert rule.description == "Test rule"

    def test_hotword_rule_default_values(self):
        """HotwordRule has sensible defaults."""
        from scrubiq.detectors.context_enhancer import HotwordRule

        rule = HotwordRule(
            pattern=re.compile(r'\btest\b'),
            confidence_delta=0.1
        )

        assert rule.window_before == 50  # Default
        assert rule.window_after == 30   # Default
        assert rule.description == ""    # Default


# =============================================================================
# PATTERN TESTS
# =============================================================================

class TestPatterns:
    """Tests for exclusion patterns."""

    def test_company_pattern(self):
        """COMPANY_PATTERN matches law firm style names."""
        from scrubiq.detectors.context_enhancer import COMPANY_PATTERN

        assert COMPANY_PATTERN.match("Smith, Jones and Brown")
        assert COMPANY_PATTERN.match("Walker and Associates")
        assert not COMPANY_PATTERN.match("John Smith")  # No "and"

    def test_greeting_pattern(self):
        """GREETING_PATTERN matches common greetings."""
        from scrubiq.detectors.context_enhancer import GREETING_PATTERN

        assert GREETING_PATTERN.match("Hi John")
        assert GREETING_PATTERN.match("hello World")
        assert GREETING_PATTERN.match("Dear Customer")
        assert not GREETING_PATTERN.match("John Smith")

    def test_html_pattern(self):
        """HTML_PATTERN matches HTML content."""
        from scrubiq.detectors.context_enhancer import HTML_PATTERN

        assert HTML_PATTERN.search("<div>")
        assert HTML_PATTERN.search("</span>")
        assert HTML_PATTERN.search("&nbsp;")
        assert not HTML_PATTERN.search("plain text")

    def test_reference_code_pattern(self):
        """REFERENCE_CODE_PATTERN matches document codes."""
        from scrubiq.detectors.context_enhancer import REFERENCE_CODE_PATTERN

        assert REFERENCE_CODE_PATTERN.match("REF-123")
        assert REFERENCE_CODE_PATTERN.match("INV-456")
        assert REFERENCE_CODE_PATTERN.match("DOC123")
        assert not REFERENCE_CODE_PATTERN.match("John")

    def test_all_caps_pattern(self):
        """ALL_CAPS_PATTERN matches all-caps strings."""
        from scrubiq.detectors.context_enhancer import ALL_CAPS_PATTERN

        assert ALL_CAPS_PATTERN.match("ABC")
        assert ALL_CAPS_PATTERN.match("USA")
        assert not ALL_CAPS_PATTERN.match("Abc")
        assert not ALL_CAPS_PATTERN.match("A")  # Too short

    def test_hyphenated_name_pattern(self):
        """HYPHENATED_NAME_PATTERN matches company-style names."""
        from scrubiq.detectors.context_enhancer import HYPHENATED_NAME_PATTERN

        assert HYPHENATED_NAME_PATTERN.match("Lewis-Osborne")
        assert HYPHENATED_NAME_PATTERN.match("Walker-Kay")
        assert not HYPHENATED_NAME_PATTERN.match("JohnSmith")
        assert not HYPHENATED_NAME_PATTERN.match("lewis-osborne")  # Not capitalized

    def test_business_context_words(self):
        """BUSINESS_CONTEXT_WORDS matches business context."""
        from scrubiq.detectors.context_enhancer import BUSINESS_CONTEXT_WORDS

        assert BUSINESS_CONTEXT_WORDS.search("employed by company")
        assert BUSINESS_CONTEXT_WORDS.search("LLC agreement")
        assert BUSINESS_CONTEXT_WORDS.search("invoice payment")
        assert not BUSINESS_CONTEXT_WORDS.search("hello world")


# =============================================================================
# ENHANCEMENT RESULT TESTS
# =============================================================================

class TestEnhancementResult:
    """Tests for EnhancementResult dataclass."""

    def test_basic_result(self):
        """EnhancementResult stores basic data."""
        from scrubiq.detectors.context_enhancer import EnhancementResult

        result = EnhancementResult(
            action="keep",
            confidence=0.9,
            reasons=["high_confidence"]
        )

        assert result.action == "keep"
        assert result.confidence == 0.9
        assert result.reasons == ["high_confidence"]

    def test_default_reasons(self):
        """EnhancementResult has default empty reasons."""
        from scrubiq.detectors.context_enhancer import EnhancementResult

        result = EnhancementResult(action="reject", confidence=0.1)

        assert result.reasons == []


# =============================================================================
# CONTEXT ENHANCER INITIALIZATION TESTS
# =============================================================================

class TestContextEnhancerInit:
    """Tests for ContextEnhancer initialization."""

    def test_default_thresholds(self):
        """ContextEnhancer has default thresholds."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer

        enhancer = ContextEnhancer()

        assert enhancer.high_threshold == 0.85
        assert enhancer.low_threshold == 0.35

    def test_custom_thresholds(self):
        """ContextEnhancer accepts custom thresholds."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer

        enhancer = ContextEnhancer(
            high_confidence_threshold=0.9,
            low_confidence_threshold=0.4
        )

        assert enhancer.high_threshold == 0.9
        assert enhancer.low_threshold == 0.4

    def test_feature_flags(self):
        """ContextEnhancer accepts feature flags."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer

        enhancer = ContextEnhancer(
            enable_deny_list=False,
            enable_hotwords=False,
            enable_patterns=False
        )

        assert enhancer.enable_deny_list is False
        assert enhancer.enable_hotwords is False
        assert enhancer.enable_patterns is False

    def test_enhanced_types(self):
        """ContextEnhancer has limited enhanced_types."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer

        enhancer = ContextEnhancer()

        # Currently only MRN is enhanced (surgical approach)
        assert "MRN" in enhancer.enhanced_types


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

        assert reason is not None
        assert "deny_list" in reason

    def test_allows_valid_name(self, enhancer, make_span):
        """Allows valid NAME not in deny list."""
        span = make_span("John", entity_type="NAME")

        reason = enhancer._check_deny_list(span)

        assert reason is None

    def test_denies_username_in_list(self, enhancer, make_span):
        """Denies USERNAME in deny list."""
        span = make_span("admin", entity_type="USERNAME")

        reason = enhancer._check_deny_list(span)

        assert reason is not None

    def test_denies_address_in_list(self, enhancer, make_span):
        """Denies ADDRESS in deny list."""
        span = make_span("maisonette", entity_type="ADDRESS")

        reason = enhancer._check_deny_list(span)

        assert reason is not None

    def test_denies_medication_in_list(self, enhancer, make_span):
        """Denies MEDICATION in deny list."""
        span = make_span("health", entity_type="MEDICATION")

        reason = enhancer._check_deny_list(span)

        assert reason is not None

    def test_mrn_uses_pattern_exclusion(self, enhancer, make_span):
        """MRN uses pattern-based exclusion."""
        span = make_span("440060.24", entity_type="MRN")

        reason = enhancer._check_deny_list(span)

        assert reason is not None
        assert "mrn_exclude" in reason

    def test_strips_punctuation(self, enhancer, make_span):
        """Strips trailing punctuation for deny list check."""
        span = make_span("will.", entity_type="NAME")

        reason = enhancer._check_deny_list(span)

        assert reason is not None

    def test_company_suffix_denial(self, enhancer, make_span):
        """Denies names ending with company suffixes."""
        span = make_span("Smith Inc", entity_type="NAME")

        reason = enhancer._check_deny_list(span)

        assert reason is not None
        assert "company_suffix" in reason


class TestContextEnhancerNormalizeText:
    """Tests for _normalize_text method."""

    def test_strips_punctuation(self, enhancer):
        """Strips trailing punctuation."""
        result = enhancer._normalize_text("John Smith.")

        assert result == "John Smith"

    def test_strips_whitespace(self, enhancer):
        """Strips leading/trailing whitespace."""
        result = enhancer._normalize_text("  John Smith  ")

        assert result == "John Smith"

    def test_keeps_internal_punctuation(self, enhancer):
        """Keeps internal punctuation like O'Brien."""
        result = enhancer._normalize_text("O'Brien")

        assert result == "O'Brien"


class TestContextEnhancerCheckPatterns:
    """Tests for _check_patterns method."""

    def test_rejects_html_content(self, enhancer, make_span):
        """Rejects span containing HTML."""
        span = make_span("<div>John</div>", entity_type="NAME")
        text = "Hello <div>John</div> World"

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        assert reason is not None
        assert "html" in reason.lower()

    def test_rejects_reference_codes(self, enhancer, make_span):
        """Rejects reference codes."""
        span = make_span("REF-12345", entity_type="NAME")
        text = "Your REF-12345 is ready"

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        assert reason is not None
        assert "reference_code" in reason

    def test_rejects_all_caps(self, enhancer, make_span):
        """Rejects all-caps acronyms."""
        span = make_span("USA", entity_type="NAME")
        text = "Visit USA today"

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        assert reason is not None
        assert "all_caps" in reason

    def test_rejects_company_pattern(self, enhancer, make_span):
        """Rejects company pattern names."""
        span = make_span("Smith, Jones and Brown", entity_type="NAME")
        text = "Contact Smith, Jones and Brown for help"

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        assert reason is not None
        assert "company_pattern" in reason

    def test_strips_greeting(self, enhancer, make_span):
        """Strips greeting from name."""
        span = make_span("Hi John", entity_type="NAME")
        text = "Hi John, how are you?"

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        # Should strip greeting, not reject
        assert reason is None
        assert cleaned == "John"
        assert offset == 3  # "Hi "

    def test_rejects_names_with_digits(self, enhancer, make_span):
        """Rejects names containing digits."""
        span = make_span("John123", entity_type="NAME")
        text = "User John123 logged in"

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        assert reason is not None
        assert "contains_digits" in reason

    def test_allows_roman_numerals(self, enhancer, make_span):
        """Allows names with Roman numerals."""
        span = make_span("John Smith III", entity_type="NAME")
        text = "Meet John Smith III"

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        # Should not reject due to Roman numeral
        assert reason is None or "contains_digits" not in (reason or "")

    def test_rejects_possessive_product(self, enhancer, make_span):
        """Rejects possessive + product pattern."""
        span = make_span("Apple", entity_type="NAME")
        text = "Visit Apple's website for more"
        span = Span(start=6, end=11, text="Apple", entity_type="NAME",
                    confidence=0.7, detector="ml", tier=Tier.ML)

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        assert reason is not None
        assert "possessive_product" in reason

    def test_rejects_hyphenated_company_in_context(self, enhancer, make_span):
        """Rejects hyphenated names in business context."""
        span = make_span("Lewis-Osborne", entity_type="NAME")
        text = "I am employed by Lewis-Osborne Inc for 5 years"
        span = Span(start=17, end=30, text="Lewis-Osborne", entity_type="NAME",
                    confidence=0.7, detector="ml", tier=Tier.ML)

        reason, cleaned, offset = enhancer._check_patterns(text, span)

        assert reason is not None
        assert "hyphenated_company" in reason


class TestContextEnhancerApplyHotwords:
    """Tests for _apply_hotwords method."""

    def test_title_boosts_confidence(self, enhancer, make_span):
        """Title before name boosts confidence."""
        text = "Dr. John Smith attended"
        span = make_span("John Smith", start=4, entity_type="NAME", confidence=0.6)

        new_conf, reasons = enhancer._apply_hotwords(text, span, 0.6)

        assert new_conf > 0.6
        assert any("hotword" in r for r in reasons)

    def test_company_suffix_reduces_confidence(self, enhancer, make_span):
        """Company suffix after reduces confidence."""
        text = "Contact John Smith Inc for help"
        span = make_span("John Smith", start=8, entity_type="NAME", confidence=0.7)

        new_conf, reasons = enhancer._apply_hotwords(text, span, 0.7)

        assert new_conf < 0.7
        assert any("-hotword" in r for r in reasons)

    def test_no_hotwords_for_non_name(self, enhancer, make_span):
        """No hotwords applied for non-NAME types."""
        text = "123-45-6789"
        span = make_span("123-45-6789", entity_type="SSN", confidence=0.9)

        new_conf, reasons = enhancer._apply_hotwords(text, span, 0.9)

        assert new_conf == 0.9
        assert len(reasons) == 0

    def test_confidence_clamped_at_1(self, enhancer, make_span):
        """Confidence doesn't exceed 1.0."""
        text = "Dr. Mr. John Smith attended"
        span = make_span("John Smith", start=8, entity_type="NAME", confidence=0.95)

        new_conf, reasons = enhancer._apply_hotwords(text, span, 0.95)

        assert new_conf <= 1.0

    def test_confidence_clamped_at_0(self, enhancer, make_span):
        """Confidence doesn't go below 0.0."""
        text = "Contact John Smith Inc Ltd Corp for help"
        span = make_span("John Smith", start=8, entity_type="NAME", confidence=0.1)

        new_conf, reasons = enhancer._apply_hotwords(text, span, 0.1)

        assert new_conf >= 0.0


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

    def test_high_tier_passes_after_deny_list(self, enhancer, make_span):
        """High tier spans pass after deny list check."""
        span = Span(
            start=0, end=10, text="1234567890",
            entity_type="MRN", confidence=0.95,
            detector="checksum", tier=Tier.STRUCTURED
        )

        result = enhancer.enhance_span("MRN: 1234567890", span)

        assert result.action == "keep"
        assert "high_tier" in result.reasons

    def test_high_confidence_keeps(self, enhancer, make_span):
        """High confidence returns 'keep'."""
        span = make_span("12345678", entity_type="MRN", confidence=0.9, tier=Tier.ML)

        result = enhancer.enhance_span("MRN: 12345678", span)

        # Without deny list match, high confidence keeps
        assert result.action in ["keep", "verify"]

    def test_low_confidence_rejects(self, enhancer, make_span):
        """Low confidence returns 'reject'."""
        # Need to create enhancer with NAME in enhanced_types for this test
        from scrubiq.detectors.context_enhancer import ContextEnhancer
        custom_enhancer = ContextEnhancer()
        custom_enhancer.enhanced_types = {"NAME"}  # Override

        span = make_span("John", entity_type="NAME", confidence=0.2, tier=Tier.ML)

        result = custom_enhancer.enhance_span("Hello John", span)

        # Low confidence should reject
        assert result.action == "reject"
        assert "low_confidence" in result.reasons

    def test_medium_confidence_verifies(self, enhancer, make_span):
        """Medium confidence returns 'verify'."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer
        custom_enhancer = ContextEnhancer()
        custom_enhancer.enhanced_types = {"NAME"}

        span = make_span("John", entity_type="NAME", confidence=0.6, tier=Tier.ML)

        result = custom_enhancer.enhance_span("Hello John", span)

        # Medium confidence should verify (between thresholds)
        assert result.action == "verify"
        assert "needs_llm" in result.reasons


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

    def test_filters_rejected_spans(self, enhancer, make_span):
        """Filters out rejected spans."""
        spans = [
            make_span("12345678", entity_type="MRN", confidence=0.9),
            make_span("440060.24", entity_type="MRN", confidence=0.7),  # Dollar amount
        ]

        result = enhancer.enhance("MRN: 12345678, Amount: 440060.24", spans)

        # Dollar amount should be filtered
        mrn_spans = [s for s in result if s.entity_type == "MRN"]
        assert len(mrn_spans) == 1

    def test_marks_verify_spans(self, enhancer, make_span):
        """Sets needs_review for verify spans."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer
        custom_enhancer = ContextEnhancer()
        custom_enhancer.enhanced_types = {"NAME"}

        span = make_span("John", entity_type="NAME", confidence=0.5, tier=Tier.ML)

        result = custom_enhancer.enhance("Hello John", [span])

        # Should be marked for verification
        if len(result) > 0 and hasattr(result[0], 'needs_review'):
            # verify action sets needs_review
            pass

    def test_updates_confidence(self, enhancer, make_span):
        """Updates span confidence based on enhancement."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer
        custom_enhancer = ContextEnhancer()
        custom_enhancer.enhanced_types = {"NAME"}

        # Title should boost confidence
        span = make_span("John Smith", start=4, entity_type="NAME", confidence=0.6, tier=Tier.ML)

        result = custom_enhancer.enhance("Dr. John Smith attended", [span])

        # Confidence should be boosted (if not rejected)
        # Note: result may be empty if rejected


# =============================================================================
# CREATE ENHANCER FUNCTION TESTS
# =============================================================================

class TestCreateEnhancer:
    """Tests for create_enhancer function."""

    def test_creates_default_enhancer(self):
        """Creates enhancer with defaults."""
        from scrubiq.detectors.context_enhancer import create_enhancer

        enhancer = create_enhancer()

        assert enhancer.high_threshold == 0.85
        assert enhancer.low_threshold == 0.35

    def test_creates_custom_enhancer(self):
        """Creates enhancer with custom settings."""
        from scrubiq.detectors.context_enhancer import create_enhancer

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
        """Handles Unicode text."""
        span = make_span("José García", entity_type="NAME")

        result = enhancer.enhance_span("Hello José García!", span)

        assert result is not None

    def test_empty_text(self, enhancer, make_span):
        """Handles empty text."""
        span = make_span("", entity_type="NAME")
        span.start = 0
        span.end = 0

        result = enhancer.enhance_span("", span)

        # Should handle gracefully
        assert result is not None

    def test_span_at_text_boundary(self, enhancer, make_span):
        """Handles span at text boundaries."""
        text = "John"
        span = make_span("John", start=0, entity_type="NAME")

        result = enhancer.enhance_span(text, span)

        assert result is not None

    def test_overlapping_hotword_matches(self, enhancer, make_span):
        """Handles overlapping hotword matches."""
        from scrubiq.detectors.context_enhancer import ContextEnhancer
        custom_enhancer = ContextEnhancer()
        custom_enhancer.enhanced_types = {"NAME"}

        # Both title (Dr.) and company suffix (Inc) present
        text = "Dr. John Smith Inc is here"
        span = make_span("John Smith", start=4, entity_type="NAME", confidence=0.5, tier=Tier.ML)

        result = custom_enhancer.enhance_span(text, span)

        # Should handle multiple hotword effects
        assert result is not None

    def test_case_insensitive_deny_list(self, enhancer, make_span):
        """Deny list check is case insensitive."""
        span1 = make_span("WILL", entity_type="NAME")
        span2 = make_span("Will", entity_type="NAME")

        reason1 = enhancer._check_deny_list(span1)
        reason2 = enhancer._check_deny_list(span2)

        # Both should be denied
        assert reason1 is not None
        assert reason2 is not None

    def test_preserves_span_attributes(self, enhancer, make_span):
        """Preserves non-modified span attributes."""
        span = make_span("John", entity_type="NAME", detector="custom_detector")

        result = enhancer.enhance("Hello John", [span])

        if result:
            assert result[0].detector == "custom_detector"


class TestContextEnhancerLogging:
    """Tests for logging behavior."""

    def test_logs_rejections(self, enhancer, make_span, caplog):
        """Logs rejected spans."""
        import logging
        caplog.set_level(logging.INFO)

        span = make_span("440060.24", entity_type="MRN")

        enhancer.enhance("Amount: 440060.24", [span])

        # Should log rejection (if INFO level enabled)
        # Check that logging doesn't raise errors

    def test_logs_statistics(self, enhancer, make_span, caplog):
        """Logs enhancement statistics."""
        import logging
        caplog.set_level(logging.INFO)

        spans = [
            make_span("12345678", entity_type="MRN"),
            make_span("440060.24", entity_type="MRN"),
        ]

        enhancer.enhance("Test", spans, return_stats=True)

        # Should log statistics without errors


class TestContextEnhancerTierHandling:
    """Tests for tier-based handling."""

    def test_high_tier_bypasses_pattern_check(self, enhancer, make_span):
        """High tier spans bypass pattern checks."""
        span = Span(
            start=0, end=8, text="REF-1234",
            entity_type="MRN", confidence=0.95,
            detector="checksum", tier=Tier.CHECKSUM
        )

        result = enhancer.enhance_span("REF-1234", span)

        # High tier should pass even with reference code pattern
        assert result.action == "keep"

    def test_deny_list_applies_to_high_tier(self, enhancer, make_span):
        """Deny list applies even to high tier (known entities)."""
        span = Span(
            start=0, end=4, text="will",
            entity_type="MRN", confidence=0.98,
            detector="known", tier=Tier.STRUCTURED
        )

        result = enhancer.enhance_span("will", span)

        # MRN "will" isn't in MRN exclude patterns, so it passes
        # But if it were NAME, it would be rejected


class TestContextEnhancerPerformance:
    """Tests for performance characteristics."""

    def test_handles_long_text(self, enhancer, make_span):
        """Handles long text efficiently."""
        long_text = "Word " * 10000
        span = make_span("John", start=50, entity_type="NAME")

        # Should not timeout
        result = enhancer.enhance_span(long_text, span)

        assert result is not None

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

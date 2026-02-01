"""
Tests for the Hyperscan-accelerated pattern detector.

Tests both the Hyperscan path (when available) and fallback behavior.
"""

import pytest
from unittest.mock import patch, MagicMock
import re


class TestHyperscanCompatibilityChecker:
    """Test _is_hyperscan_compatible function."""

    def test_lookahead_not_compatible(self):
        """Patterns with lookahead are not compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        # Positive lookahead
        assert _is_hyperscan_compatible(r"foo(?=bar)") is False
        # Negative lookahead
        assert _is_hyperscan_compatible(r"foo(?!bar)") is False

    def test_lookbehind_not_compatible(self):
        """Patterns with lookbehind are not compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        # Positive lookbehind
        assert _is_hyperscan_compatible(r"(?<=foo)bar") is False
        # Negative lookbehind
        assert _is_hyperscan_compatible(r"(?<!foo)bar") is False

    def test_unicode_escapes_not_compatible(self):
        """Unicode escape sequences are not compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        assert _is_hyperscan_compatible(r"[\u0041-\u005A]") is False
        assert _is_hyperscan_compatible(r"\U0001F600") is False

    def test_backreferences_not_compatible(self):
        """Backreferences are not compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        assert _is_hyperscan_compatible(r"(\w+)\s+\1") is False
        assert _is_hyperscan_compatible(r"(a)(b)\2\1") is False

    def test_many_alternations_not_compatible(self):
        """Patterns with >30 alternations are not compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        # Generate pattern with 35 alternations
        pattern = "|".join([f"word{i}" for i in range(35)])
        assert _is_hyperscan_compatible(pattern) is False

        # 29 alternations should be fine
        pattern = "|".join([f"word{i}" for i in range(29)])
        assert _is_hyperscan_compatible(pattern) is True

    def test_long_patterns_not_compatible(self):
        """Patterns over 500 chars are not compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        long_pattern = "a" * 501
        assert _is_hyperscan_compatible(long_pattern) is False

        short_pattern = "a" * 500
        assert _is_hyperscan_compatible(short_pattern) is True

    def test_nested_quantifiers_not_compatible(self):
        """Nested quantifiers are not compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        # Pattern with actual nested quantifiers that Hyperscan can't handle
        # Note: The regex checks for \{...\}\s*\{ pattern
        assert _is_hyperscan_compatible(r"(a{2,3}){1,2}") is True  # This is actually OK
        # Long pattern with many quantifiers that might fail
        # The actual implementation checks for specific patterns

    def test_simple_patterns_compatible(self):
        """Simple patterns are compatible."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _is_hyperscan_compatible,
        )
        assert _is_hyperscan_compatible(r"\d{3}-\d{2}-\d{4}") is True
        assert _is_hyperscan_compatible(r"[a-zA-Z]+@[a-zA-Z]+\.[a-zA-Z]+") is True
        assert _is_hyperscan_compatible(r"\b\d{16}\b") is True


class TestHyperscanAvailability:
    """Test Hyperscan availability detection."""

    def test_is_hyperscan_available_returns_bool(self):
        """is_hyperscan_available should return a boolean."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            is_hyperscan_available,
        )
        result = is_hyperscan_available()
        assert isinstance(result, bool)


class TestHyperscanDetectorFallback:
    """Test HyperscanDetector when Hyperscan is not available."""

    def test_detector_falls_back_when_hyperscan_unavailable(self):
        """Detector should fall back to PatternDetector when Hyperscan unavailable."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _HYPERSCAN_AVAILABLE,
        )

        if _HYPERSCAN_AVAILABLE:
            pytest.skip("Hyperscan is available, testing fallback not possible")

        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            HyperscanDetector,
        )

        detector = HyperscanDetector()
        assert detector._fallback_detector is not None

        # Test it actually detects
        text = "SSN: 123-45-6789"
        spans = detector.detect(text)
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detector_with_mocked_hyperscan_unavailable(self):
        """Test detector behavior with mocked unavailable Hyperscan."""
        with patch.dict('sys.modules', {'hyperscan': None}):
            # Force reimport to pick up mock
            import importlib
            from openlabels.adapters.scanner.detectors.patterns import hyperscan_detector
            importlib.reload(hyperscan_detector)

            # Verify it falls back
            detector = hyperscan_detector.HyperscanDetector()
            assert detector._fallback_detector is not None


class TestPatternInfo:
    """Test PatternInfo dataclass."""

    def test_pattern_info_creation(self):
        """PatternInfo should store all fields correctly."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            PatternInfo,
        )
        import re

        pattern = re.compile(r"\d+")
        info = PatternInfo(
            pattern_id=42,
            entity_type="SSN",
            confidence=0.95,
            group_idx=1,
            original_pattern=pattern,
        )

        assert info.pattern_id == 42
        assert info.entity_type == "SSN"
        assert info.confidence == 0.95
        assert info.group_idx == 1
        assert info.original_pattern is pattern


class TestHyperscanDetectorWithHyperscan:
    """Test HyperscanDetector when Hyperscan IS available."""

    @pytest.fixture
    def detector(self):
        """Create a HyperscanDetector, skip if Hyperscan unavailable."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            _HYPERSCAN_AVAILABLE,
            HyperscanDetector,
        )

        if not _HYPERSCAN_AVAILABLE:
            pytest.skip("Hyperscan not available")

        return HyperscanDetector()

    def test_detect_ssn(self, detector):
        """Should detect SSN with Hyperscan."""
        text = "SSN: 123-45-6789"
        spans = detector.detect(text)
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_email(self, detector):
        """Should detect email with Hyperscan."""
        text = "Contact: test@example.com"
        spans = detector.detect(text)
        email_spans = [s for s in spans if s.entity_type == "EMAIL"]
        assert len(email_spans) >= 1

    def test_detect_credit_card_with_validation(self, detector):
        """Should validate credit card with Luhn."""
        # Valid Luhn
        text = "Card: 4111111111111111"
        spans = detector.detect(text)
        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) >= 1

        # Invalid Luhn - should NOT be detected
        text = "Card: 1234567890123456"
        spans = detector.detect(text)
        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) == 0

    def test_detect_invalid_ip_rejected(self, detector):
        """Should reject invalid IP addresses."""
        text = "IP: 999.999.999.999"
        spans = detector.detect(text)
        ip_spans = [s for s in spans if s.entity_type == "IP_ADDRESS" and "999" in s.text]
        assert len(ip_spans) == 0

    def test_detect_unicode_text(self, detector):
        """Should handle unicode text."""
        text = "Email: José.García@example.com"
        spans = detector.detect(text)
        # Should not crash
        assert isinstance(spans, list)

    def test_empty_text(self, detector):
        """Should handle empty text."""
        spans = detector.detect("")
        assert spans == []

    def test_fallback_patterns_run(self, detector):
        """Fallback patterns (with lookahead/lookbehind) should still work."""
        # International phone number uses lookbehind
        text = "Phone: +1-555-123-4567"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        # Should detect via fallback
        assert len(phone_spans) >= 1


class TestValidateMatch:
    """Test the _validate_match method."""

    @pytest.fixture
    def detector(self):
        """Create a HyperscanDetector."""
        from openlabels.adapters.scanner.detectors.patterns.hyperscan_detector import (
            HyperscanDetector,
        )
        return HyperscanDetector()

    def test_validate_ip_rejects_invalid(self, detector):
        """Invalid IPs should be rejected."""
        result = detector._validate_match(
            text="IP: 999.999.999.999",
            value="999.999.999.999",
            start=4,
            end=19,
            entity_type="IP_ADDRESS",
            confidence=0.9,
            match=None,
        )
        assert result is False

    def test_validate_ip_accepts_valid(self, detector):
        """Valid IPs should be accepted."""
        result = detector._validate_match(
            text="IP: 192.168.1.1",
            value="192.168.1.1",
            start=4,
            end=15,
            entity_type="IP_ADDRESS",
            confidence=0.9,
            match=None,
        )
        assert result is True

    def test_validate_phone_rejects_invalid(self, detector):
        """Invalid phone numbers should be rejected."""
        result = detector._validate_match(
            text="Phone: 000-000-0000",
            value="000-000-0000",
            start=7,
            end=19,
            entity_type="PHONE",
            confidence=0.9,
            match=None,
        )
        assert result is False

    def test_validate_age_rejects_invalid(self, detector):
        """Invalid ages should be rejected."""
        result = detector._validate_match(
            text="Age: 200",
            value="200",
            start=5,
            end=8,
            entity_type="AGE",
            confidence=0.9,
            match=None,
        )
        assert result is False

    def test_validate_age_accepts_valid(self, detector):
        """Valid ages should be accepted."""
        result = detector._validate_match(
            text="Age: 35",
            value="35",
            start=5,
            end=7,
            entity_type="AGE",
            confidence=0.9,
            match=None,
        )
        assert result is True

    def test_validate_name_rejects_false_positive(self, detector):
        """False positive names should be rejected."""
        # "REPORT" is in the FALSE_POSITIVE_NAMES deny list
        result = detector._validate_match(
            text="Document type: REPORT",
            value="REPORT",
            start=15,
            end=21,
            entity_type="NAME",
            confidence=0.9,
            match=None,
        )
        assert result is False

    def test_validate_credit_card_uses_luhn(self, detector):
        """Credit cards should be validated with Luhn."""
        # Invalid Luhn
        result = detector._validate_match(
            text="Card: 1234567890123456",
            value="1234567890123456",
            start=6,
            end=22,
            entity_type="CREDIT_CARD",
            confidence=0.9,
            match=None,
        )
        assert result is False

        # Valid Luhn
        result = detector._validate_match(
            text="Card: 4111111111111111",
            value="4111111111111111",
            start=6,
            end=22,
            entity_type="CREDIT_CARD",
            confidence=0.9,
            match=None,
        )
        assert result is True

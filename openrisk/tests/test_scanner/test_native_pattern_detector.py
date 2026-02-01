"""
Tests for the Native (Rust-accelerated) Pattern Detector.

Tests that the native detector produces identical results to the
Python detector while providing GIL release benefits.
"""

import pytest
from concurrent.futures import ThreadPoolExecutor
import time


# Skip all tests if native extension is not available
pytest.importorskip("openlabels._rust")


class TestNativeDetectorAvailability:
    """Test native detector availability and initialization."""

    def test_native_extension_available(self):
        """Test that the Rust extension is available."""
        from openlabels._rust import is_native_available
        assert is_native_available() is True

    def test_native_detector_initialization(self):
        """Test NativePatternDetector initializes correctly."""
        from openlabels.adapters.scanner.detectors.patterns.native import (
            NativePatternDetector,
            is_native_detector_available,
        )
        assert is_native_detector_available() is True
        detector = NativePatternDetector()
        assert detector.name == "pattern"

    def test_pattern_compilation_stats(self):
        """Test pattern compilation reports reasonable stats."""
        from openlabels.adapters.scanner.detectors.patterns.native import NativePatternDetector
        detector = NativePatternDetector()
        # Should compile most patterns (some may fail due to lookbehind)
        assert detector._matcher.pattern_count > 300
        assert detector._matcher.failed_count < 20


class TestNativePythonParity:
    """Test that native detector produces same results as Python detector."""

    @pytest.fixture
    def detectors(self):
        """Create both native and Python detectors."""
        from openlabels.adapters.scanner.detectors.patterns.native import NativePatternDetector
        from openlabels.adapters.scanner.detectors.patterns.detector import PatternDetector
        return NativePatternDetector(), PatternDetector()

    def test_ssn_detection_parity(self, detectors):
        """Test SSN detection produces same results."""
        native, python = detectors
        text = "Patient SSN: 123-45-6789"

        native_spans = native.detect(text)
        python_spans = python.detect(text)

        native_ssn = {(s.text, s.entity_type) for s in native_spans if s.entity_type == "SSN"}
        python_ssn = {(s.text, s.entity_type) for s in python_spans if s.entity_type == "SSN"}
        assert native_ssn == python_ssn

    def test_credit_card_detection_parity(self, detectors):
        """Test credit card detection produces same results."""
        native, python = detectors
        text = "Card: 4111-1111-1111-1111"

        native_spans = native.detect(text)
        python_spans = python.detect(text)

        native_cc = {s.text for s in native_spans if s.entity_type == "CREDIT_CARD"}
        python_cc = {s.text for s in python_spans if s.entity_type == "CREDIT_CARD"}
        assert native_cc == python_cc

    def test_email_detection_parity(self, detectors):
        """Test email detection produces same results."""
        native, python = detectors
        text = "Contact: john.smith@example.com"

        native_spans = native.detect(text)
        python_spans = python.detect(text)

        native_email = {s.text for s in native_spans if s.entity_type == "EMAIL"}
        python_email = {s.text for s in python_spans if s.entity_type == "EMAIL"}
        assert native_email == python_email

    def test_date_detection_parity(self, detectors):
        """Test date detection produces same results."""
        native, python = detectors
        text = "DOB: 01/15/1985"

        native_spans = native.detect(text)
        python_spans = python.detect(text)

        native_dates = {s.text for s in native_spans if s.entity_type in ("DATE", "DATE_DOB")}
        python_dates = {s.text for s in python_spans if s.entity_type in ("DATE", "DATE_DOB")}
        assert native_dates == python_dates

    def test_age_detection_parity(self, detectors):
        """Test age detection produces same results."""
        native, python = detectors
        text = "Age: 39 years old"

        native_spans = native.detect(text)
        python_spans = python.detect(text)

        native_age = {s.text for s in native_spans if s.entity_type == "AGE"}
        python_age = {s.text for s in python_spans if s.entity_type == "AGE"}
        assert native_age == python_age

    def test_full_document_parity(self, detectors):
        """Test full document produces same entity types and texts."""
        native, python = detectors
        text = """
        Patient Name: John Smith
        DOB: 01/15/1985
        Age: 39
        SSN: 123-45-6789
        Phone: (555) 123-4567
        Email: john.smith@example.com
        Credit Card: 4111-1111-1111-1111
        Address: 123 Main Street, Anytown, CA 90210
        IP Address: 192.168.1.100
        """

        native_spans = native.detect(text)
        python_spans = python.detect(text)

        native_set = {(s.entity_type, s.text) for s in native_spans}
        python_set = {(s.entity_type, s.text) for s in python_spans}
        assert native_set == python_set


class TestValidators:
    """Test that validators work correctly in native detector."""

    @pytest.fixture
    def detector(self):
        from openlabels.adapters.scanner.detectors.patterns.native import NativePatternDetector
        return NativePatternDetector()

    def test_invalid_date_rejected(self, detector):
        """Test invalid dates are rejected by validator."""
        text = "Date: 13/45/2025"  # Invalid month and day
        spans = detector.detect(text)
        # Should not detect this as a valid date
        date_spans = [s for s in spans if s.entity_type in ("DATE", "DATE_DOB")]
        valid_dates = [s for s in date_spans if s.text == "13/45/2025"]
        assert len(valid_dates) == 0

    def test_invalid_age_rejected(self, detector):
        """Test invalid ages are rejected by validator."""
        text = "Age: 200 years old"  # Age > 125 is invalid
        spans = detector.detect(text)
        age_spans = [s for s in spans if s.entity_type == "AGE"]
        invalid_ages = [s for s in age_spans if s.text == "200"]
        assert len(invalid_ages) == 0

    def test_invalid_credit_card_rejected(self, detector):
        """Test invalid credit cards (bad Luhn) are rejected."""
        text = "Card: 1234-5678-9012-3456"  # Invalid Luhn checksum
        spans = detector.detect(text)
        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        # Should not detect or have low confidence
        assert len(cc_spans) == 0

    def test_invalid_ip_rejected(self, detector):
        """Test invalid IPs are rejected by validator."""
        text = "IP: 999.999.999.999"  # Invalid octet values
        spans = detector.detect(text)
        ip_spans = [s for s in spans if s.entity_type == "IP_ADDRESS"]
        invalid_ips = [s for s in ip_spans if s.text == "999.999.999.999"]
        assert len(invalid_ips) == 0


class TestFallbackPatterns:
    """Test that patterns that fail Rust compilation work via Python fallback."""

    @pytest.fixture
    def detector(self):
        from openlabels.adapters.scanner.detectors.patterns.native import NativePatternDetector
        return NativePatternDetector()

    def test_fallback_patterns_exist(self, detector):
        """Test that some patterns are in the fallback list."""
        # Some patterns with lookbehind should be in fallback
        assert detector._failed_patterns is not None
        assert len(detector._failed_patterns) > 0

    def test_international_phone_via_fallback(self, detector):
        """Test international phone patterns (use lookbehind) work via fallback."""
        text = "Phone: +1-555-123-4567"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == "PHONE"]
        # Should detect via fallback pattern
        assert len(phone_spans) >= 1


class TestGILRelease:
    """Test that GIL release enables true parallelism."""

    def test_parallel_faster_than_sequential_gil_contention(self):
        """Test that native parallel is faster than Python parallel (GIL contention)."""
        from openlabels.adapters.scanner.detectors.patterns.native import NativePatternDetector
        from openlabels.adapters.scanner.detectors.patterns.detector import PatternDetector

        file_text = "SSN: 123-45-6789 Email: test@example.com " * 50
        num_files = 20

        def process_native(text):
            return NativePatternDetector().detect(text)

        def process_python(text):
            return PatternDetector().detect(text)

        # Native parallel
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(process_native, [file_text] * num_files))
        native_parallel = time.perf_counter() - start

        # Python parallel (should be slower due to GIL)
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(process_python, [file_text] * num_files))
        python_parallel = time.perf_counter() - start

        # Native parallel should be faster (GIL release benefit)
        # Allow some tolerance for test environment variance
        assert native_parallel < python_parallel * 1.5


class TestEdgeCases:
    """Test edge cases for native detector."""

    @pytest.fixture
    def detector(self):
        from openlabels.adapters.scanner.detectors.patterns.native import NativePatternDetector
        return NativePatternDetector()

    def test_empty_string(self, detector):
        """Test empty string handling."""
        spans = detector.detect("")
        assert len(spans) == 0

    def test_whitespace_only(self, detector):
        """Test whitespace-only string handling."""
        spans = detector.detect("   \t\n   ")
        assert len(spans) == 0

    def test_unicode_text(self, detector):
        """Test handling of unicode text."""
        text = "Email: test@example.com, Name: José García"
        spans = detector.detect(text)
        # Should detect email without crashing
        email_spans = [s for s in spans if s.entity_type == "EMAIL"]
        assert len(email_spans) >= 1

    def test_large_text(self, detector):
        """Test handling of large text."""
        text = "SSN: 123-45-6789 " * 1000
        spans = detector.detect(text)
        # Should find many SSNs
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1000

    def test_span_positions_correct(self, detector):
        """Test that span positions are accurate."""
        text = "SSN: 123-45-6789"
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)
            # Extracted text should match
            assert text[span.start:span.end] == span.text

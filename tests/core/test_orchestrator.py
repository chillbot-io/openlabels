"""
Tests for DetectorOrchestrator.

Tests the detection coordination, parallel execution, and result merging.

Adapted from openrisk/tests/test_detector_orchestrator.py
"""

import pytest
from openlabels.core.detectors.orchestrator import DetectorOrchestrator, detect


# =============================================================================
# Initialization Tests
# =============================================================================

class TestOrchestratorInit:
    """Tests for orchestrator initialization."""

    def test_creates_with_defaults(self):
        """Test orchestrator creates with default settings."""
        orchestrator = DetectorOrchestrator()

        assert orchestrator.confidence_threshold > 0
        assert len(orchestrator.detectors) > 0

    def test_secrets_detector_can_be_disabled(self):
        """Test secrets detector can be disabled."""
        orchestrator = DetectorOrchestrator(enable_secrets=False)

        detector_names = orchestrator.detector_names
        assert "secrets" not in detector_names

    def test_financial_detector_can_be_disabled(self):
        """Test financial detector can be disabled."""
        orchestrator = DetectorOrchestrator(enable_financial=False)

        detector_names = orchestrator.detector_names
        assert "financial" not in detector_names

    def test_government_detector_can_be_disabled(self):
        """Test government detector can be disabled."""
        orchestrator = DetectorOrchestrator(enable_government=False)

        detector_names = orchestrator.detector_names
        assert "government" not in detector_names

    def test_checksum_detector_can_be_disabled(self):
        """Test checksum detector can be disabled."""
        orchestrator = DetectorOrchestrator(enable_checksum=False)

        detector_names = orchestrator.detector_names
        assert "checksum" not in detector_names

    def test_has_core_detectors(self):
        """Test orchestrator has core detectors by default."""
        orchestrator = DetectorOrchestrator()

        detector_names = orchestrator.detector_names
        assert "checksum" in detector_names
        assert "secrets" in detector_names
        assert "financial" in detector_names
        assert "government" in detector_names

    def test_custom_confidence_threshold(self):
        """Test custom confidence threshold is respected."""
        orchestrator = DetectorOrchestrator(confidence_threshold=0.95)

        assert orchestrator.confidence_threshold == 0.95


# =============================================================================
# Detection Tests
# =============================================================================

class TestOrchestratorDetect:
    """Tests for the detect method."""

    def test_detect_ssn(self):
        """Test detection of SSN."""
        orchestrator = DetectorOrchestrator()
        text = "Patient SSN: 123-45-6789"

        result = orchestrator.detect(text)

        # Should find at least one SSN span
        ssn_spans = [s for s in result.spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_credit_card(self):
        """Test detection of credit card."""
        orchestrator = DetectorOrchestrator()
        text = "Card: 4111-1111-1111-1111"

        result = orchestrator.detect(text)

        # Should find credit card
        cc_spans = [s for s in result.spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) >= 1

    def test_detect_multiple_entities(self):
        """Test detection of multiple entity types."""
        orchestrator = DetectorOrchestrator()
        text = """
        Patient SSN: 123-45-6789
        Card: 4111-1111-1111-1111
        """

        result = orchestrator.detect(text)

        # Should find multiple entity types
        entity_types = set(s.entity_type for s in result.spans)
        assert len(entity_types) >= 2

    def test_detect_empty_text(self):
        """Test detection on empty text."""
        orchestrator = DetectorOrchestrator()

        result = orchestrator.detect("")

        assert result.spans == []

    def test_detect_no_pii(self):
        """Test detection on text without PII."""
        orchestrator = DetectorOrchestrator()
        text = "The quick brown fox jumps over the lazy dog."

        result = orchestrator.detect(text)

        # Should find no or very few spans
        assert len(result.spans) <= 3


# =============================================================================
# Secrets Detection Tests
# =============================================================================

class TestSecretsDetection:
    """Tests for secrets detection."""

    def test_detect_aws_access_key(self):
        """Test detection of AWS access key."""
        orchestrator = DetectorOrchestrator(enable_secrets=True)
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

        result = orchestrator.detect(text)

        aws_spans = [s for s in result.spans if "AWS" in s.entity_type]
        assert len(aws_spans) >= 1

    def test_detect_github_token(self):
        """Test detection of GitHub token."""
        orchestrator = DetectorOrchestrator(enable_secrets=True)
        text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"

        result = orchestrator.detect(text)

        gh_spans = [s for s in result.spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1


# =============================================================================
# Confidence Filtering Tests
# =============================================================================

class TestConfidenceFiltering:
    """Tests for confidence-based filtering."""

    def test_min_confidence_filters_low_confidence(self):
        """Test that confidence threshold filters low confidence spans."""
        orchestrator = DetectorOrchestrator(confidence_threshold=0.95)

        text = "SSN: 123-45-6789"
        result = orchestrator.detect(text)

        for span in result.spans:
            assert span.confidence >= 0.95


# =============================================================================
# Detection Result Tests
# =============================================================================

class TestDetectionResult:
    """Tests for DetectionResult structure."""

    def test_result_has_required_fields(self):
        """Test that result has all required fields with correct types."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        result = orchestrator.detect(text)

        # Verify fields exist and have correct types
        assert isinstance(result.spans, list)
        assert isinstance(result.entity_counts, dict)
        assert isinstance(result.processing_time_ms, (int, float))
        assert isinstance(result.detectors_used, list)
        assert isinstance(result.text_length, int)

    def test_entity_counts_populated(self):
        """Test that entity counts are populated."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        result = orchestrator.detect(text)

        assert isinstance(result.entity_counts, dict)
        if result.spans:
            assert sum(result.entity_counts.values()) >= 1

    def test_processing_time_recorded(self):
        """Test that processing time is recorded."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        result = orchestrator.detect(text)

        assert result.processing_time_ms >= 0

    def test_text_length_recorded(self):
        """Test that text length is recorded."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        result = orchestrator.detect(text)

        assert result.text_length == len(text)


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling and graceful degradation."""

    def test_handles_unicode_text(self):
        """Test that orchestrator handles unicode text."""
        orchestrator = DetectorOrchestrator()
        text = "Patient: José García, SSN: 123-45-6789"

        result = orchestrator.detect(text)

        assert isinstance(result.spans, list)

    def test_handles_very_long_text(self):
        """Test that orchestrator handles very long text."""
        orchestrator = DetectorOrchestrator()
        text = ("Lorem ipsum " * 500) + "SSN: 123-45-6789" + (" dolor sit" * 500)

        result = orchestrator.detect(text)

        ssn_spans = [s for s in result.spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1


# =============================================================================
# Span Properties Tests
# =============================================================================

class TestSpanProperties:
    """Tests for span properties."""

    def test_spans_have_required_properties(self):
        """Test that spans have all required properties with correct types."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        result = orchestrator.detect(text)

        assert len(result.spans) > 0, "Should detect at least one span for SSN"

        for span in result.spans:
            # Verify fields exist with correct types
            assert isinstance(span.start, int), f"start should be int, got {type(span.start)}"
            assert isinstance(span.end, int), f"end should be int, got {type(span.end)}"
            assert isinstance(span.text, str), f"text should be str, got {type(span.text)}"
            assert isinstance(span.entity_type, str), f"entity_type should be str, got {type(span.entity_type)}"
            assert isinstance(span.confidence, (int, float)), f"confidence should be numeric"
            assert isinstance(span.detector, str), f"detector should be str"
            # tier can be an enum, so just check it exists
            assert span.tier is not None, "tier should not be None"

    def test_span_positions_are_valid(self):
        """Test that span positions are valid."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        result = orchestrator.detect(text)

        for span in result.spans:
            assert 0 <= span.start < len(text)
            assert span.start < span.end <= len(text)

    def test_span_text_matches_position(self):
        """Test that span text matches its position in source."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        result = orchestrator.detect(text)

        for span in result.spans:
            assert span.text == text[span.start:span.end]


# =============================================================================
# Detector Management Tests
# =============================================================================

class TestDetectorManagement:
    """Tests for adding/removing detectors."""

    def test_add_detector(self):
        """Test adding a custom detector."""
        from openlabels.core.detectors.base import BaseDetector
        from openlabels.core.types import Span, Tier

        class CustomDetector(BaseDetector):
            name = "custom"
            tier = Tier.PATTERN

            def detect(self, text):
                return []

        orchestrator = DetectorOrchestrator()
        initial_count = len(orchestrator.detectors)

        orchestrator.add_detector(CustomDetector())

        assert len(orchestrator.detectors) == initial_count + 1
        assert "custom" in orchestrator.detector_names

    def test_remove_detector(self):
        """Test removing a detector by name."""
        orchestrator = DetectorOrchestrator()

        assert "secrets" in orchestrator.detector_names

        removed = orchestrator.remove_detector("secrets")

        assert removed is True
        assert "secrets" not in orchestrator.detector_names

    def test_remove_nonexistent_detector(self):
        """Test removing a detector that doesn't exist."""
        orchestrator = DetectorOrchestrator()

        removed = orchestrator.remove_detector("nonexistent")

        assert removed is False


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunction:
    """Tests for the detect() convenience function."""

    def test_detect_function_works(self):
        """Test that the convenience function works."""
        text = "SSN: 123-45-6789"

        result = detect(text)

        assert isinstance(result.spans, list)
        ssn_spans = [s for s in result.spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_function_accepts_options(self):
        """Test that the convenience function accepts options."""
        text = "SSN: 123-45-6789"

        result = detect(text, confidence_threshold=0.99)

        # All returned spans should meet threshold
        for span in result.spans:
            assert span.confidence >= 0.99


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for full detection pipeline."""

    def test_clinical_note_detection(self):
        """Test detection on clinical note-like text."""
        orchestrator = DetectorOrchestrator()
        text = """
        PATIENT: John Smith
        SSN: 123-45-6789
        Card: 4111-1111-1111-1111
        """

        result = orchestrator.detect(text)

        entity_types = set(s.entity_type for s in result.spans)
        assert "SSN" in entity_types or "CREDIT_CARD" in entity_types

    def test_financial_document_detection(self):
        """Test detection on financial document-like text."""
        orchestrator = DetectorOrchestrator(enable_financial=True)
        text = """
        Card: 4111-1111-1111-1111
        IBAN: DE89370400440532013000
        """

        result = orchestrator.detect(text)

        entity_types = set(s.entity_type for s in result.spans)
        assert "CREDIT_CARD" in entity_types or "IBAN" in entity_types

    def test_secrets_document_detection(self):
        """Test detection on document with secrets."""
        orchestrator = DetectorOrchestrator(enable_secrets=True)
        text = """
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        """

        result = orchestrator.detect(text)

        aws_spans = [s for s in result.spans if "AWS" in s.entity_type]
        assert len(aws_spans) >= 1

    def test_government_document_detection(self):
        """Test detection on document with government markings."""
        orchestrator = DetectorOrchestrator(enable_government=True)
        text = "Classification: TOP SECRET//SCI//NOFORN"

        result = orchestrator.detect(text)

        # Should find classification markings
        assert len(result.spans) >= 1

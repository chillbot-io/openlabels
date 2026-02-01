"""
Tests for DetectorOrchestrator.

Tests the detection coordination, parallel execution, and result merging.
"""

import pytest
from unittest.mock import MagicMock, patch

from openlabels.adapters.scanner.detectors.orchestrator import DetectorOrchestrator
from openlabels.adapters.scanner.config import Config
from openlabels.adapters.scanner.types import Span


# =============================================================================
# Initialization Tests
# =============================================================================

class TestOrchestratorInit:
    """Tests for orchestrator initialization."""

    def test_creates_with_defaults(self):
        """Test orchestrator creates with default config."""
        orchestrator = DetectorOrchestrator()

        assert orchestrator.config is not None
        assert orchestrator.parallel is True
        assert len(orchestrator._detectors) > 0

    def test_creates_with_custom_config(self):
        """Test orchestrator creates with custom config."""
        config = Config(min_confidence=0.9)
        orchestrator = DetectorOrchestrator(config=config)

        assert orchestrator.config.min_confidence == 0.9

    def test_parallel_mode_configurable(self):
        """Test parallel mode can be disabled."""
        orchestrator = DetectorOrchestrator(parallel=False)

        assert orchestrator.parallel is False

    def test_secrets_detector_can_be_disabled(self):
        """Test secrets detector can be disabled."""
        orchestrator = DetectorOrchestrator(enable_secrets=False)

        detector_names = [d.name for d in orchestrator._detectors]
        assert "secrets" not in detector_names

    def test_financial_detector_can_be_disabled(self):
        """Test financial detector can be disabled."""
        orchestrator = DetectorOrchestrator(enable_financial=False)

        detector_names = [d.name for d in orchestrator._detectors]
        assert "financial" not in detector_names

    def test_government_detector_can_be_disabled(self):
        """Test government detector can be disabled."""
        orchestrator = DetectorOrchestrator(enable_government=False)

        detector_names = [d.name for d in orchestrator._detectors]
        assert "government" not in detector_names

    def test_has_core_detectors(self):
        """Test orchestrator has core detectors by default."""
        orchestrator = DetectorOrchestrator()

        detector_names = [d.name for d in orchestrator._detectors]
        assert "checksum" in detector_names
        assert "pattern" in detector_names  # PatternDetector.name = "pattern" (singular)


# =============================================================================
# Detection Tests
# =============================================================================

class TestOrchestratorDetect:
    """Tests for the detect method."""

    def test_detect_ssn(self):
        """Test detection of SSN."""
        orchestrator = DetectorOrchestrator()
        text = "Patient SSN: 123-45-6789"

        spans = orchestrator.detect(text)

        # Should find at least one SSN span
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_credit_card(self):
        """Test detection of credit card."""
        orchestrator = DetectorOrchestrator()
        text = "Card: 4111-1111-1111-1111"

        spans = orchestrator.detect(text)

        # Should find credit card
        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) >= 1

    def test_detect_email(self):
        """Test detection of email address."""
        orchestrator = DetectorOrchestrator()
        text = "Contact: john.doe@example.com"

        spans = orchestrator.detect(text)

        email_spans = [s for s in spans if s.entity_type == "EMAIL"]
        assert len(email_spans) >= 1

    def test_detect_multiple_entities(self):
        """Test detection of multiple entity types."""
        orchestrator = DetectorOrchestrator()
        text = """
        Patient SSN: 123-45-6789
        Email: john.smith@hospital.org
        """

        spans = orchestrator.detect(text)

        # Should find multiple entity types
        entity_types = set(s.entity_type for s in spans)
        assert len(entity_types) >= 2

    def test_detect_empty_text(self):
        """Test detection on empty text."""
        orchestrator = DetectorOrchestrator()

        spans = orchestrator.detect("")

        assert spans == []

    def test_detect_no_pii(self):
        """Test detection on text without PII."""
        orchestrator = DetectorOrchestrator()
        text = "The quick brown fox jumps over the lazy dog."

        spans = orchestrator.detect(text)

        # Should find no or very few spans
        assert len(spans) <= 3


# =============================================================================
# Secrets Detection Tests
# =============================================================================

class TestSecretsDetection:
    """Tests for secrets detection."""

    def test_detect_aws_access_key(self):
        """Test detection of AWS access key."""
        orchestrator = DetectorOrchestrator(enable_secrets=True)
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

        spans = orchestrator.detect(text)

        aws_spans = [s for s in spans if "AWS" in s.entity_type or "ACCESS_KEY" in s.entity_type]
        assert len(aws_spans) >= 1


# =============================================================================
# Parallel Execution Tests
# =============================================================================

class TestParallelExecution:
    """Tests for parallel execution behavior."""

    def test_parallel_mode_produces_results(self):
        """Test parallel mode produces detection results."""
        orchestrator = DetectorOrchestrator(parallel=True)
        text = "SSN: 123-45-6789, Email: test@example.com"

        spans = orchestrator.detect(text)

        assert len(spans) >= 1

    def test_serial_mode_produces_results(self):
        """Test serial mode produces detection results."""
        orchestrator = DetectorOrchestrator(parallel=False)
        text = "SSN: 123-45-6789, Email: test@example.com"

        spans = orchestrator.detect(text)

        assert len(spans) >= 1


# =============================================================================
# Confidence Filtering Tests
# =============================================================================

class TestConfidenceFiltering:
    """Tests for confidence-based filtering."""

    def test_min_confidence_filters_low_confidence(self):
        """Test that min_confidence filters low confidence spans."""
        config = Config(min_confidence=0.95)
        orchestrator = DetectorOrchestrator(config=config)

        text = "SSN: 123-45-6789"
        spans = orchestrator.detect(text)

        for span in spans:
            assert span.confidence >= config.min_confidence


# =============================================================================
# Disabled Detectors Tests
# =============================================================================

class TestDisabledDetectors:
    """Tests for disabling detectors via config."""

    def test_disable_checksum_detector(self):
        """Test disabling checksum detector."""
        config = Config()
        config.disabled_detectors = {"checksum"}
        orchestrator = DetectorOrchestrator(config=config)

        detector_names = [d.name for d in orchestrator._detectors]
        assert "checksum" not in detector_names

    def test_disable_multiple_detectors(self):
        """Test disabling multiple detectors."""
        config = Config()
        config.disabled_detectors = {"checksum", "patterns"}
        orchestrator = DetectorOrchestrator(config=config)

        detector_names = [d.name for d in orchestrator._detectors]
        assert "checksum" not in detector_names
        assert "patterns" not in detector_names


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling and graceful degradation."""

    def test_handles_unicode_text(self):
        """Test that orchestrator handles unicode text."""
        orchestrator = DetectorOrchestrator()
        text = "Patient: José García, SSN: 123-45-6789"

        spans = orchestrator.detect(text)

        assert isinstance(spans, list)

    def test_handles_very_long_text(self):
        """Test that orchestrator handles very long text."""
        orchestrator = DetectorOrchestrator()
        text = ("Lorem ipsum " * 500) + "SSN: 123-45-6789" + (" dolor sit" * 500)

        spans = orchestrator.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1


# =============================================================================
# Span Properties Tests
# =============================================================================

class TestSpanProperties:
    """Tests for span properties."""

    def test_spans_have_required_properties(self):
        """Test that spans have all required properties."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        spans = orchestrator.detect(text)

        for span in spans:
            assert hasattr(span, 'start')
            assert hasattr(span, 'end')
            assert hasattr(span, 'text')
            assert hasattr(span, 'entity_type')
            assert hasattr(span, 'confidence')
            assert hasattr(span, 'detector')

    def test_span_positions_are_valid(self):
        """Test that span positions are valid."""
        orchestrator = DetectorOrchestrator()
        text = "SSN: 123-45-6789"

        spans = orchestrator.detect(text)

        for span in spans:
            assert 0 <= span.start < len(text)
            assert span.start < span.end <= len(text)


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
        Email: john.smith@email.com
        """

        spans = orchestrator.detect(text)

        entity_types = set(s.entity_type for s in spans)
        assert "SSN" in entity_types or "EMAIL" in entity_types

    def test_financial_document_detection(self):
        """Test detection on financial document-like text."""
        orchestrator = DetectorOrchestrator(enable_financial=True)
        text = """
        Card: 4111-1111-1111-1111
        """

        spans = orchestrator.detect(text)

        entity_types = set(s.entity_type for s in spans)
        assert "CREDIT_CARD" in entity_types

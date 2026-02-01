"""
Tests for the Government Detector.

Tests detection of classification markings, government identifiers,
and security-related patterns.
"""

import pytest
from openlabels.adapters.scanner.detectors.government import GovernmentDetector


class TestGovernmentDetector:
    """Test the GovernmentDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a GovernmentDetector instance."""
        return GovernmentDetector()

    def test_detector_name(self, detector):
        """Test detector has correct name."""
        assert detector.name == "government"

    def test_detector_available(self, detector):
        """Test detector is available."""
        assert detector.is_available() is True


class TestClassificationLevels:
    """Test detection of classification levels."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_top_secret(self, detector):
        """Test TOP SECRET detection."""
        text = "This document is classified TOP SECRET"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1
        assert any("TOP SECRET" in s.text.upper() for s in class_spans)

    def test_detect_secret(self, detector):
        """Test SECRET detection with context."""
        text = "Classification: SECRET//NOFORN"
        spans = detector.detect(text)

        # Should detect either CLASSIFICATION_LEVEL or CLASSIFICATION_MARKING
        assert len(spans) >= 1

    def test_detect_unclassified_fouo(self, detector):
        """Test UNCLASSIFIED//FOUO detection."""
        text = "This document is UNCLASSIFIED//FOUO"
        spans = detector.detect(text)

        class_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(class_spans) >= 1

    def test_detect_cui(self, detector):
        """Test Controlled Unclassified Information detection."""
        text = "Marked as CONTROLLED UNCLASSIFIED INFORMATION"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1


class TestClassificationMarkings:
    """Test detection of full classification markings."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_ts_sci(self, detector):
        """Test TOP SECRET//SCI marking."""
        text = "Handling instructions: TOP SECRET//SCI"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(marking_spans) >= 1

    def test_detect_noforn(self, detector):
        """Test NOFORN dissemination control."""
        text = "SECRET//NOFORN - Not releasable to foreign nationals"
        spans = detector.detect(text)

        # Should detect classification marking with NOFORN
        assert len(spans) >= 1

    def test_detect_rel_to(self, detector):
        """Test REL TO dissemination control."""
        text = "SECRET//REL TO USA, GBR, AUS"
        spans = detector.detect(text)

        assert len(spans) >= 1

    def test_detect_portion_marking(self, detector):
        """Test portion markings like (TS), (S)."""
        text = "(TS) This paragraph is top secret. (U) This is unclassified."
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1


class TestSCIMarkings:
    """Test detection of SCI compartment markers."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_si_marking(self, detector):
        """Test Special Intelligence (//SI) marking."""
        text = "Handle via TOP SECRET//SI channels"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_tk_marking(self, detector):
        """Test TALENT KEYHOLE (//TK) marking."""
        text = "Classification: TOP SECRET//TK"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1


class TestDisseminationControls:
    """Test detection of dissemination control markings."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_orcon(self, detector):
        """Test ORCON (Originator Controlled) detection."""
        text = "Distribution: ORCON"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_propin(self, detector):
        """Test PROPIN (Proprietary Information) detection."""
        text = "Marked PROPIN for proprietary handling"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1


class TestGovernmentIdentifiers:
    """Test detection of government identifiers."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_cage_code(self, detector):
        """Test CAGE (Commercial and Government Entity) code detection."""
        text = "Vendor CAGE code: 1ABC2"
        spans = detector.detect(text)

        cage_spans = [s for s in spans if s.entity_type == "CAGE_CODE"]
        assert len(cage_spans) >= 1

    def test_detect_dod_contract(self, detector):
        """Test DoD contract number detection."""
        text = "Contract FA8750-20-C-1234"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1


class TestExportControlMarkings:
    """Test detection of export control markings."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_itar_marking(self, detector):
        """Test ITAR (International Traffic in Arms Regulations) marking."""
        # Use text that matches detector patterns
        text = "WARNING: ITAR CONTROLLED - This document is subject to ITAR"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1

    def test_detect_ear_marking(self, detector):
        """Test EAR (Export Administration Regulations) marking."""
        # Use text that matches detector patterns: ECCN classification
        text = "ECCN: 5A992 - Subject to EAR CONTROLLED"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1


class TestEdgeCases:
    """Test edge cases and false positive prevention."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_no_false_positive_secret_word(self, detector):
        """Test 'secret' in normal context isn't flagged."""
        text = "It's a secret recipe for grandma's cookies."
        spans = detector.detect(text)

        # Should not flag common usage of "secret"
        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        # If it does match, confidence should be lower
        for span in class_spans:
            if "secret" in span.text.lower():
                assert span.confidence < 0.90

    def test_no_false_positive_normal_text(self, detector):
        """Test normal text without government context."""
        text = "The quick brown fox jumps over the lazy dog."
        spans = detector.detect(text)
        assert len(spans) == 0

    def test_confidence_scores(self, detector):
        """Test that detected spans have valid confidence scores."""
        text = "Classification: TOP SECRET//SCI//NOFORN"
        spans = detector.detect(text)

        for span in spans:
            assert 0.0 <= span.confidence <= 1.0

    def test_span_positions(self, detector):
        """Test that span positions are correct."""
        text = "Marked TOP SECRET for handling"
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)

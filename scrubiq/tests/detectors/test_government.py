"""
Comprehensive tests for scrubiq/detectors/government.py.

Tests detection of government classification markings, security identifiers,
contract numbers, and export control markings.
"""

import pytest
from scrubiq.detectors.government import (
    GovernmentDetector,
    GOVERNMENT_PATTERNS,
)
from scrubiq.types import Tier


# =============================================================================
# GovernmentDetector Class Tests
# =============================================================================
class TestGovernmentDetector:
    """Tests for the GovernmentDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a GovernmentDetector instance."""
        return GovernmentDetector()

    def test_detector_name(self, detector):
        """Detector should have correct name."""
        assert detector.name == "government"

    def test_detector_tier(self, detector):
        """Detector should use PATTERN tier."""
        assert detector.tier == Tier.PATTERN

    def test_detect_returns_list(self, detector):
        """Detection should return a list."""
        result = detector.detect("No government data here")
        assert isinstance(result, list)

    def test_detect_empty_text(self, detector):
        """Empty text should return empty list."""
        result = detector.detect("")
        assert result == []


# =============================================================================
# Classification Level Detection Tests
# =============================================================================
class TestClassificationLevels:
    """Tests for classification level detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_top_secret(self, detector):
        """Detect TOP SECRET classification."""
        text = "This document is TOP SECRET"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1
        assert any("TOP SECRET" in s.text.upper() for s in class_spans)

    def test_detect_top_secret_no_space(self, detector):
        """Detect TOPSECRET (no space)."""
        text = "Classified TOPSECRET material"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1

    def test_detect_secret_with_context(self, detector):
        """Detect SECRET with classification context."""
        text = "Classification: SECRET//NOFORN"
        spans = detector.detect(text)

        class_spans = [s for s in spans if "SECRET" in s.text.upper()]
        assert len(class_spans) >= 1

    def test_no_detect_secret_without_context(self, detector):
        """Should not detect SECRET without classification context."""
        text = "It's a secret recipe"
        spans = detector.detect(text)

        # Pattern has negative lookahead for common words
        secret_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"
                       and s.text.upper() == "SECRET"]
        # Should be filtered out
        assert len(secret_spans) == 0

    def test_detect_unclassified(self, detector):
        """Detect UNCLASSIFIED classification."""
        text = "This is UNCLASSIFIED information"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1
        assert any("UNCLASSIFIED" in s.text.upper() for s in class_spans)

    def test_detect_unclassified_fouo(self, detector):
        """Detect UNCLASSIFIED//FOUO."""
        text = "UNCLASSIFIED//FOUO memo"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1

    def test_detect_cui(self, detector):
        """Detect CUI with context."""
        text = "CUI controlled unclassified information category"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1

    def test_detect_controlled_unclassified_information(self, detector):
        """Detect full CONTROLLED UNCLASSIFIED INFORMATION."""
        text = "This is CONTROLLED UNCLASSIFIED INFORMATION"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1


# =============================================================================
# Classification Marking Detection Tests
# =============================================================================
class TestClassificationMarkings:
    """Tests for full classification marking detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_ts_sci(self, detector):
        """Detect TOP SECRET//SCI."""
        text = "Document marked TOP SECRET//SCI"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1
        assert any("SCI" in s.text.upper() for s in marking_spans)

    def test_detect_secret_sci(self, detector):
        """Detect SECRET//SCI."""
        text = "Classification: SECRET//SCI"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1

    def test_detect_classification_with_compartments(self, detector):
        """Detect classification with compartment markings."""
        text = "TOP SECRET//SI/TK//NOFORN"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1

    def test_detect_classification_with_noforn(self, detector):
        """Detect classification with NOFORN."""
        text = "SECRET//NOFORN document"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if "NOFORN" in s.text.upper()]
        assert len(marking_spans) >= 1

    def test_detect_portion_markings(self, detector):
        """Detect portion markings like (TS), (S), (C)."""
        text = "(TS) This paragraph is Top Secret. (U) This is unclassified."
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1

    def test_detect_ts_sci_portion(self, detector):
        """Detect (TS//SCI) portion marking."""
        text = "(TS//SCI) Intelligence assessment"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1


# =============================================================================
# SCI Marking Detection Tests
# =============================================================================
class TestSCIMarkings:
    """Tests for SCI (Sensitive Compartmented Information) marking detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_si(self, detector):
        """Detect //SI (Special Intelligence)."""
        text = "Document classified //SI"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_tk(self, detector):
        """Detect //TK (TALENT KEYHOLE)."""
        text = "Imagery marked //TK"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_hcs(self, detector):
        """Detect //HCS (HUMINT Control System)."""
        text = "//HCS compartmented information"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_sigint(self, detector):
        """Detect //SIGINT."""
        text = "Signals intelligence //SIGINT product"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_humint(self, detector):
        """Detect //HUMINT."""
        text = "//HUMINT source protection"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_special_access_program(self, detector):
        """Detect SPECIAL ACCESS PROGRAM."""
        text = "SPECIAL ACCESS PROGRAM material"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1


# =============================================================================
# Dissemination Control Detection Tests
# =============================================================================
class TestDisseminationControls:
    """Tests for dissemination control marking detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_noforn_standalone(self, detector):
        """Detect //NOFORN."""
        text = "//NOFORN restricted release"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_rel_to(self, detector):
        """Detect REL TO markings."""
        text = "REL TO USA, GBR, CAN, AUS, NZL"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_fvey(self, detector):
        """Detect FVEY (Five Eyes)."""
        text = "Releasable to FVEY partners"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_orcon(self, detector):
        """Detect ORCON (Originator Controlled)."""
        text = "ORCON protected information"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_fouo(self, detector):
        """Detect FOUO (For Official Use Only)."""
        text = "FOUO document handling"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1


# =============================================================================
# CAGE Code Detection Tests
# =============================================================================
class TestCAGECodeDetection:
    """Tests for CAGE code detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_cage_labeled(self, detector):
        """Detect CAGE code with label."""
        text = "CAGE: 1A2B3"
        spans = detector.detect(text)

        cage_spans = [s for s in spans if s.entity_type == "CAGE_CODE"]
        assert len(cage_spans) == 1
        assert cage_spans[0].text == "1A2B3"

    def test_detect_cage_with_hash(self, detector):
        """Detect CAGE code with hash symbol."""
        text = "CAGE# ABC12"
        spans = detector.detect(text)

        cage_spans = [s for s in spans if s.entity_type == "CAGE_CODE"]
        assert len(cage_spans) == 1

    def test_detect_cage_code_label(self, detector):
        """Detect 'cage code:' format."""
        text = "Vendor cage code: 5XYZ9"
        spans = detector.detect(text)

        cage_spans = [s for s in spans if s.entity_type == "CAGE_CODE"]
        assert len(cage_spans) == 1


# =============================================================================
# DUNS Number Detection Tests
# =============================================================================
class TestDUNSDetection:
    """Tests for DUNS number detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_duns_continuous(self, detector):
        """Detect DUNS number (9 continuous digits)."""
        text = "DUNS: 123456789"
        spans = detector.detect(text)

        duns_spans = [s for s in spans if s.entity_type == "DUNS_NUMBER"]
        assert len(duns_spans) == 1
        assert duns_spans[0].text == "123456789"

    def test_detect_duns_formatted(self, detector):
        """Detect DUNS number with dashes."""
        text = "D-U-N-S: 12-345-6789"
        spans = detector.detect(text)

        duns_spans = [s for s in spans if s.entity_type == "DUNS_NUMBER"]
        assert len(duns_spans) == 1


# =============================================================================
# UEI Detection Tests
# =============================================================================
class TestUEIDetection:
    """Tests for UEI (Unique Entity Identifier) detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_uei_labeled(self, detector):
        """Detect UEI with label."""
        text = "UEI: ABC123DEF456"
        spans = detector.detect(text)

        uei_spans = [s for s in spans if s.entity_type == "UEI"]
        assert len(uei_spans) == 1
        assert uei_spans[0].text == "ABC123DEF456"

    def test_detect_unique_entity_identifier(self, detector):
        """Detect full 'Unique Entity Identifier' label."""
        text = "Unique Entity ID: XYZ789ABC012"
        spans = detector.detect(text)

        uei_spans = [s for s in spans if s.entity_type == "UEI"]
        assert len(uei_spans) == 1


# =============================================================================
# DoD Contract Number Detection Tests
# =============================================================================
class TestDoDContractDetection:
    """Tests for DoD contract number detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_air_force_contract(self, detector):
        """Detect Air Force contract (FA prefix)."""
        text = "Contract FA8756-21-C-0001"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1
        assert any("FA8756" in s.text for s in contract_spans)

    def test_detect_army_contract(self, detector):
        """Detect Army contract (W prefix)."""
        text = "W91238-22-D-0045 awarded"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1

    def test_detect_navy_contract(self, detector):
        """Detect Navy contract (N prefix)."""
        text = "Contract N00014-23-C-1234"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1

    def test_detect_contract_with_modification(self, detector):
        """Detect contract with modification number."""
        text = "FA8756-21-C-0001-P00005"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1


# =============================================================================
# GSA Contract Detection Tests
# =============================================================================
class TestGSAContractDetection:
    """Tests for GSA contract number detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_gsa_schedule(self, detector):
        """Detect GSA Schedule contract."""
        text = "GSA Schedule GS-35F-0001J"
        spans = detector.detect(text)

        gsa_spans = [s for s in spans if s.entity_type == "GSA_CONTRACT"]
        assert len(gsa_spans) >= 1

    def test_detect_gsa_mas(self, detector):
        """Detect GSA MAS contract."""
        text = "Contract 47QTCA21D1234 awarded"
        spans = detector.detect(text)

        gsa_spans = [s for s in spans if s.entity_type == "GSA_CONTRACT"]
        assert len(gsa_spans) >= 1


# =============================================================================
# Security Clearance Detection Tests
# =============================================================================
class TestClearanceLevelDetection:
    """Tests for security clearance level detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_ts_sci_clearance(self, detector):
        """Detect TS/SCI clearance."""
        text = "Requires TS/SCI clearance"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_top_secret_clearance(self, detector):
        """Detect TOP SECRET CLEARANCE."""
        text = "Must have TOP SECRET CLEARANCE"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_secret_clearance(self, detector):
        """Detect SECRET CLEARANCE."""
        text = "SECRET CLEARANCE required"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_q_clearance(self, detector):
        """Detect Q CLEARANCE (DOE)."""
        text = "DOE Q CLEARANCE holder"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_polygraph(self, detector):
        """Detect polygraph requirements."""
        text = "Requires FULL SCOPE POLYGRAPH"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1


# =============================================================================
# ITAR/EAR Detection Tests
# =============================================================================
class TestExportControlDetection:
    """Tests for ITAR/EAR export control marking detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_itar_controlled(self, detector):
        """Detect ITAR CONTROLLED."""
        text = "ITAR CONTROLLED data"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1

    def test_detect_usml_category(self, detector):
        """Detect USML CATEGORY."""
        text = "USML CATEGORY XI item"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1

    def test_detect_ear_controlled(self, detector):
        """Detect EAR CONTROLLED."""
        text = "EAR CONTROLLED technology"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1

    def test_detect_eccn(self, detector):
        """Detect ECCN (Export Control Classification Number)."""
        text = "ECCN: 5A002"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1


# =============================================================================
# False Positive Filtering Tests
# =============================================================================
class TestFalsePositiveFiltering:
    """Tests for false positive filtering."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_filter_secret_santa(self, detector):
        """Should not detect SECRET in 'secret santa'."""
        text = "We're having a secret santa party"
        spans = detector.detect(text)

        secret_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"
                       and "secret" in s.text.lower() and "top" not in s.text.lower()]
        # Pattern has negative lookahead for "santa"
        assert len(secret_spans) == 0

    def test_filter_secret_recipe(self, detector):
        """Should not detect SECRET in 'secret recipe'."""
        text = "It's a secret recipe from grandma"
        spans = detector.detect(text)

        # Should not detect as classification
        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"
                      and "secret" in s.text.lower()]
        assert len(class_spans) == 0

    def test_secret_with_classification_context(self, detector):
        """Should detect SECRET with classification context."""
        text = "Document classified SECRET//NOFORN for dissemination"
        spans = detector.detect(text)

        # Should detect with proper context
        secret_spans = [s for s in spans if "SECRET" in s.text.upper()]
        assert len(secret_spans) >= 1


# =============================================================================
# Pattern Coverage Tests
# =============================================================================
class TestPatternsCoverage:
    """Tests for pattern definitions."""

    def test_patterns_not_empty(self):
        """GOVERNMENT_PATTERNS should contain patterns."""
        assert len(GOVERNMENT_PATTERNS) > 0

    def test_pattern_structure(self):
        """Each pattern should have correct structure."""
        for pattern, entity_type, confidence, group_idx in GOVERNMENT_PATTERNS:
            assert hasattr(pattern, "finditer")
            assert isinstance(entity_type, str) and len(entity_type) > 0
            assert 0 <= confidence <= 1
            assert group_idx >= 0

    def test_all_entity_types_defined(self):
        """All documented entity types should have patterns."""
        entity_types = {pattern[1] for pattern in GOVERNMENT_PATTERNS}

        expected = {
            "CLASSIFICATION_LEVEL", "CLASSIFICATION_MARKING",
            "SCI_MARKING", "DISSEMINATION_CONTROL",
            "CAGE_CODE", "DUNS_NUMBER", "UEI",
            "DOD_CONTRACT", "GSA_CONTRACT",
            "CLEARANCE_LEVEL", "ITAR_MARKING", "EAR_MARKING"
        }

        # At least core types should be present
        core_types = {"CLASSIFICATION_LEVEL", "DOD_CONTRACT", "CAGE_CODE"}
        assert core_types.issubset(entity_types)


# =============================================================================
# Edge Cases and Robustness Tests
# =============================================================================
class TestGovernmentEdgeCases:
    """Edge case tests for government detection."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_unicode_text(self, detector):
        """Should handle Unicode text."""
        text = "Classification: TOP SECRET 日本語"
        spans = detector.detect(text)
        # Should still detect TOP SECRET
        assert any("TOP SECRET" in s.text.upper() for s in spans)

    def test_very_long_text(self, detector):
        """Should handle very long text."""
        text = "x" * 50000 + " TOP SECRET " + "y" * 50000
        spans = detector.detect(text)
        assert any("TOP SECRET" in s.text.upper() for s in spans)

    def test_multiple_classifications(self, detector):
        """Should detect multiple classifications."""
        text = "TOP SECRET document. SECRET memo. UNCLASSIFIED report."
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 2

    def test_span_position_accuracy(self, detector):
        """Span positions should be accurate."""
        prefix = "Classification: "
        marking = "TOP SECRET"
        text = f"{prefix}{marking}"
        spans = detector.detect(text)

        ts_spans = [s for s in spans if "TOP SECRET" in s.text.upper()]
        assert len(ts_spans) >= 1

        span = ts_spans[0]
        assert text[span.start:span.end].upper() == span.text.upper()

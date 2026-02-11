"""
Comprehensive tests for the Government Detector.

Tests detection of security classification markings, government identifiers,
and defense/intelligence related patterns.

Entity Types tested:
- CLASSIFICATION_LEVEL: Classification levels (TOP SECRET, SECRET, etc.)
- CLASSIFICATION_MARKING: Full classification lines with caveats
- SCI_MARKING: Sensitive Compartmented Information markers
- DISSEMINATION_CONTROL: NOFORN, REL TO, ORCON, etc.
- CAGE_CODE: Commercial and Government Entity Code (5 chars)
- DUNS_NUMBER: Data Universal Numbering System (9 digits)
- UEI: Unique Entity Identifier (12 chars)
- DOD_CONTRACT: DoD contract numbers
- GSA_CONTRACT: GSA schedule contract numbers
- CLEARANCE_LEVEL: Security clearance references
- ITAR_MARKING: International Traffic in Arms Regulations
- EAR_MARKING: Export Administration Regulations
"""

import pytest
from openlabels.core.detectors.government import GovernmentDetector
from openlabels.core.types import Tier


# =============================================================================
# DETECTOR INITIALIZATION TESTS
# =============================================================================

# =============================================================================
# CLASSIFICATION LEVEL TESTS
# =============================================================================

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

    def test_detect_top_secret_space_variation(self, detector):
        """Test TOP SECRET with space variations (TOP\\s*SECRET pattern)."""
        text = "Classified as TOPSECRET and TOP  SECRET"
        spans = detector.detect(text)

        class_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(class_spans) >= 1
        # At least one should contain "TOP" and "SECRET"
        assert any("TOP" in s.text.upper() and "SECRET" in s.text.upper() for s in class_spans)

    def test_detect_secret_with_context(self, detector):
        """Test SECRET detection with classification context."""
        text = "Classification: SECRET//NOFORN"
        spans = detector.detect(text)

        # Should detect classification marking and/or dissemination control
        assert len(spans) >= 1
        entity_types = {s.entity_type for s in spans}
        # At least one classification-related entity should be found
        assert entity_types & {"CLASSIFICATION_LEVEL", "CLASSIFICATION_MARKING", "DISSEMINATION_CONTROL"}

    def test_detect_confidential(self, detector):
        """Test CONFIDENTIAL detection with classification context."""
        text = "This portion is CONFIDENTIAL classification with clearance required"
        spans = detector.detect(text)

        class_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(class_spans) >= 1
        assert any("CONFIDENTIAL" in s.text.upper() for s in class_spans)

    def test_detect_unclassified(self, detector):
        """Test UNCLASSIFIED detection."""
        text = "This document is UNCLASSIFIED"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1
        assert any(s.text == "UNCLASSIFIED" for s in class_spans)
        assert all(s.confidence >= 0.90 for s in class_spans)

    def test_detect_unclassified_fouo(self, detector):
        """Test UNCLASSIFIED//FOUO detection."""
        text = "This document is UNCLASSIFIED//FOUO"
        spans = detector.detect(text)

        class_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(class_spans) >= 1

    def test_detect_cui(self, detector):
        """Test CUI (Controlled Unclassified Information) detection."""
        text = "Marked as CONTROLLED UNCLASSIFIED INFORMATION"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1
        assert any("CONTROLLED UNCLASSIFIED INFORMATION" in s.text.upper() for s in class_spans)

    def test_detect_cui_abbreviation(self, detector):
        """Test CUI abbreviation with context."""
        text = "This is CUI controlled unclassified information category"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1

    def test_detect_sensitive_but_unclassified(self, detector):
        """Test SENSITIVE BUT UNCLASSIFIED detection."""
        text = "Marked as SENSITIVE BUT UNCLASSIFIED"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1

    def test_detect_official_use_only(self, detector):
        """Test OFFICIAL USE ONLY detection."""
        text = "This is OFFICIAL USE ONLY material"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1

    def test_detect_limited_official_use(self, detector):
        """Test LIMITED OFFICIAL USE detection."""
        text = "Marked as LIMITED OFFICIAL USE"
        spans = detector.detect(text)

        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) >= 1


# =============================================================================
# FULL CLASSIFICATION MARKING TESTS
# =============================================================================

class TestClassificationMarkings:
    """Test detection of full classification markings with caveats."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_ts_sci(self, detector):
        """Test TOP SECRET//SCI marking."""
        text = "Handling instructions: TOP SECRET//SCI"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(marking_spans) >= 1

    def test_detect_secret_sci(self, detector):
        """Test SECRET//SCI marking."""
        text = "Classification: SECRET//SCI"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(marking_spans) >= 1

    def test_detect_ts_noforn(self, detector):
        """Test TOP SECRET//NOFORN marking."""
        text = "TOP SECRET//NOFORN - Not releasable"
        spans = detector.detect(text)

        assert len(spans) >= 1

    def test_detect_secret_noforn(self, detector):
        """Test SECRET//NOFORN marking."""
        text = "SECRET//NOFORN - Limited distribution"
        spans = detector.detect(text)

        assert len(spans) >= 1

    def test_detect_confidential_noforn(self, detector):
        """Test CONFIDENTIAL//NOFORN marking."""
        text = "CONFIDENTIAL//NOFORN document"
        spans = detector.detect(text)

        marking_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(marking_spans) >= 1

    def test_detect_ts_rel_to(self, detector):
        """Test TOP SECRET//REL TO marking."""
        text = "TOP SECRET//REL TO USA, GBR, AUS"
        spans = detector.detect(text)

        assert len(spans) >= 1

    def test_detect_secret_rel_to(self, detector):
        """Test SECRET//REL TO marking."""
        text = "SECRET//REL TO USA, GBR, AUS"
        spans = detector.detect(text)

        assert len(spans) >= 1

    def test_detect_portion_marking_ts(self, detector):
        """Test (TS) portion marking."""
        text = "(TS) This paragraph contains top secret information."
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1

    def test_detect_portion_marking_s(self, detector):
        """Test (S) portion marking."""
        text = "(S) This section is secret classified."
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1

    def test_detect_portion_marking_c(self, detector):
        """Test (C) portion marking."""
        text = "(C) Confidential information follows."
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1

    def test_detect_ts_sci_portion_marking(self, detector):
        """Test (TS//SCI) portion marking."""
        text = "(TS//SCI) Highly sensitive compartmented information."
        spans = detector.detect(text)

        marking_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_MARKING"]
        assert len(marking_spans) >= 1

    def test_detect_complex_marking(self, detector):
        """Test complex classification marking with multiple caveats."""
        text = "TOP SECRET//SI//TK//NOFORN"
        spans = detector.detect(text)

        assert len(spans) >= 1


# =============================================================================
# SCI MARKING TESTS
# =============================================================================

class TestSCIMarkings:
    """Test detection of SCI (Sensitive Compartmented Information) markers."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_si_marking(self, detector):
        """Test Special Intelligence (//SI) marking."""
        text = "Handle via TOP SECRET//SI channels"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1
        assert any(s.text == "//SI" for s in sci_spans)

    def test_detect_tk_marking(self, detector):
        """Test TALENT KEYHOLE (//TK) marking."""
        text = "Classification: TOP SECRET//TK"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1
        assert any(s.text == "//TK" for s in sci_spans)

    def test_detect_hcs_marking(self, detector):
        """Test HUMINT Control System (//HCS) marking."""
        # SCI markers need word boundary - attach to classification level
        text = "Classification: SECRET//HCS document"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_comint_marking(self, detector):
        """Test Communications Intelligence (//COMINT) marking."""
        text = "Handling: TOP SECRET//COMINT material"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_sigint_marking(self, detector):
        """Test Signals Intelligence (//SIGINT) marking."""
        text = "Classification: SECRET//SIGINT data"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_humint_marking(self, detector):
        """Test Human Intelligence (//HUMINT) marking."""
        text = "Marked as TOP SECRET//HUMINT sources"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_imint_marking(self, detector):
        """Test Imagery Intelligence (//IMINT) marking."""
        text = "Satellite imagery SECRET//IMINT restricted"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_geoint_marking(self, detector):
        """Test Geospatial Intelligence (//GEOINT) marking."""
        text = "Mapping data SECRET//GEOINT classified"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_masint_marking(self, detector):
        """Test Measurement and Signature Intelligence (//MASINT) marking."""
        text = "Technical data SECRET//MASINT collection"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1

    def test_detect_sap_marking(self, detector):
        """Test Special Access Program marking."""
        text = "SPECIAL ACCESS PROGRAM required for access"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1
        assert any("SPECIAL ACCESS PROGRAM" in s.text.upper() for s in sci_spans)

    def test_detect_sar_marking(self, detector):
        """Test Special Access Required marking."""
        text = "SPECIAL ACCESS REQUIRED for this material"
        spans = detector.detect(text)

        sci_spans = [s for s in spans if s.entity_type == "SCI_MARKING"]
        assert len(sci_spans) >= 1
        assert any("SPECIAL ACCESS REQUIRED" in s.text.upper() for s in sci_spans)


# =============================================================================
# DISSEMINATION CONTROL TESTS
# =============================================================================

class TestDisseminationControls:
    """Test detection of dissemination control markings."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_noforn_inline(self, detector):
        """Test //NOFORN inline marking."""
        # //NOFORN needs word boundary - attach to classification level
        text = "Classification: SECRET//NOFORN"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_noforn_contextual(self, detector):
        """Test NOFORN with classification context."""
        text = "SECRET classified NOFORN material for dissemination control"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_rel_to_countries(self, detector):
        """Test REL TO with country codes."""
        text = "REL TO USA, FVEY, AUS, GBR, CAN"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_fvey(self, detector):
        """Test Five Eyes (FVEY) marking."""
        text = "Shared with FVEY partners only"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_five_eyes_spelled_out(self, detector):
        """Test FIVE EYES spelled out."""
        text = "FIVE EYES sharing agreement applies"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_orcon(self, detector):
        """Test ORCON (Originator Controlled) marking."""
        text = "Distribution: ORCON required"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_imcon(self, detector):
        """Test IMCON (Imagery Control) marking."""
        text = "Handling instructions: IMCON"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_propin(self, detector):
        """Test PROPIN (Proprietary Information) marking."""
        text = "Marked PROPIN for proprietary handling"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_fouo(self, detector):
        """Test FOUO (For Official Use Only) marking."""
        text = "Distribution limited: FOUO"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1

    def test_detect_les(self, detector):
        """Test Law Enforcement Sensitive marking."""
        text = "LAW ENFORCEMENT SENSITIVE material"
        spans = detector.detect(text)

        dissem_spans = [s for s in spans if s.entity_type == "DISSEMINATION_CONTROL"]
        assert len(dissem_spans) >= 1


# =============================================================================
# GOVERNMENT ENTITY CODE TESTS
# =============================================================================

class TestGovernmentEntityCodes:
    """Test detection of government entity identifiers."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_cage_code_labeled(self, detector):
        """Test CAGE code with label."""
        text = "Vendor CAGE: 1ABC2"
        spans = detector.detect(text)

        cage_spans = [s for s in spans if s.entity_type == "CAGE_CODE"]
        assert len(cage_spans) >= 1
        assert any(s.text == "1ABC2" for s in cage_spans)

    def test_detect_cage_code_lowercase_label(self, detector):
        """Test CAGE code with lowercase label."""
        text = "cage: 1ABC2"
        spans = detector.detect(text)

        cage_spans = [s for s in spans if s.entity_type == "CAGE_CODE"]
        assert len(cage_spans) >= 1

    def test_detect_cage_code_numeric(self, detector):
        """Test CAGE code with all numeric."""
        text = "CAGE: 12345"
        spans = detector.detect(text)

        cage_spans = [s for s in spans if s.entity_type == "CAGE_CODE"]
        assert len(cage_spans) >= 1

    def test_detect_duns_number(self, detector):
        """Test DUNS number detection."""
        text = "DUNS: 123456789"
        spans = detector.detect(text)

        duns_spans = [s for s in spans if s.entity_type == "DUNS_NUMBER"]
        assert len(duns_spans) >= 1
        assert any(s.text == "123456789" for s in duns_spans)

    def test_detect_duns_with_dashes(self, detector):
        """Test DUNS number with dashes."""
        text = "D-U-N-S: 12-345-6789"
        spans = detector.detect(text)

        duns_spans = [s for s in spans if s.entity_type == "DUNS_NUMBER"]
        assert len(duns_spans) >= 1
        assert any(s.text == "12-345-6789" for s in duns_spans)

    def test_detect_uei(self, detector):
        """Test Unique Entity Identifier (UEI) detection."""
        text = "UEI: ABCD12345678"
        spans = detector.detect(text)

        uei_spans = [s for s in spans if s.entity_type == "UEI"]
        assert len(uei_spans) >= 1
        assert any(s.text == "ABCD12345678" for s in uei_spans)

    def test_detect_uei_sam_context(self, detector):
        """Test UEI with SAM.gov context."""
        # Pattern: SAM + (registration|ID|#) + 12 alphanumeric
        text = "SAM.gov registration: ABCD12345678"
        spans = detector.detect(text)

        uei_spans = [s for s in spans if s.entity_type == "UEI"]
        assert len(uei_spans) >= 1


# =============================================================================
# CONTRACT NUMBER TESTS
# =============================================================================

class TestContractNumbers:
    """Test detection of government contract numbers."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_dod_contract_fa(self, detector):
        """Test DoD contract number with FA prefix (Air Force)."""
        text = "Contract FA8750-20-C-1234"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1

    def test_detect_dod_contract_w(self, detector):
        """Test DoD contract number with W prefix (Army)."""
        text = "Contract W912HN-20-C-0042"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1

    def test_detect_dod_contract_n(self, detector):
        """Test DoD contract number with N prefix (Navy)."""
        text = "Contract N00024-20-C-5301"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1

    def test_detect_dod_contract_with_mod(self, detector):
        """Test DoD contract with modification number."""
        text = "Contract FA8750-20-C-1234-P00001"
        spans = detector.detect(text)

        contract_spans = [s for s in spans if s.entity_type == "DOD_CONTRACT"]
        assert len(contract_spans) >= 1

    def test_detect_gsa_contract_gs_format(self, detector):
        """Test GSA contract with GS- format."""
        text = "GSA Schedule GS-35F-0119Y"
        spans = detector.detect(text)

        gsa_spans = [s for s in spans if s.entity_type == "GSA_CONTRACT"]
        assert len(gsa_spans) >= 1

    def test_detect_gsa_contract_47_format(self, detector):
        """Test GSA contract with 47 prefix format."""
        # Pattern: 47 + 2 letters + 2 alnum + 2 digits + 1 letter + 4 digits
        text = "Contract 47QTCA20D0012"
        spans = detector.detect(text)

        gsa_spans = [s for s in spans if s.entity_type == "GSA_CONTRACT"]
        assert len(gsa_spans) >= 1


# =============================================================================
# SECURITY CLEARANCE TESTS
# =============================================================================

class TestSecurityClearance:
    """Test detection of security clearance references."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_ts_sci_clearance(self, detector):
        """Test TS/SCI clearance reference."""
        text = "Applicant must have TS/SCI clearance"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_top_secret_clearance(self, detector):
        """Test TOP SECRET CLEARANCE reference."""
        text = "Requires TOP SECRET CLEARANCE"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_top_secret_sci_clearance(self, detector):
        """Test TOP SECRET SCI CLEARANCE reference."""
        text = "Must hold TOP SECRET SCI CLEARANCE"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_secret_clearance(self, detector):
        """Test SECRET CLEARANCE reference."""
        text = "SECRET CLEARANCE required"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_q_clearance(self, detector):
        """Test Q CLEARANCE (DOE) reference."""
        text = "Requires Q CLEARANCE for nuclear access"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_l_clearance(self, detector):
        """Test L CLEARANCE (DOE) reference."""
        text = "L CLEARANCE sufficient for this role"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_yankee_white(self, detector):
        """Test YANKEE WHITE clearance reference."""
        text = "Requires YANKEE WHITE for White House access"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1

    def test_detect_active_clearance(self, detector):
        """Test ACTIVE clearance reference."""
        text = "Must have ACTIVE SECRET SECURITY CLEARANCE"
        spans = detector.detect(text)

        clearance_spans = [s for s in spans if s.entity_type == "CLEARANCE_LEVEL"]
        assert len(clearance_spans) >= 1


# =============================================================================
# EXPORT CONTROL MARKING TESTS
# =============================================================================

class TestExportControlMarkings:
    """Test detection of ITAR and EAR export control markings."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_detect_itar_controlled(self, detector):
        """Test ITAR CONTROLLED marking."""
        text = "WARNING: ITAR CONTROLLED - Export restricted"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1
        assert any("ITAR CONTROLLED" in s.text.upper() for s in itar_spans)

    def test_detect_itar_restricted(self, detector):
        """Test ITAR RESTRICTED marking."""
        text = "ITAR RESTRICTED technical data"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1

    def test_detect_itar_data(self, detector):
        """Test ITAR DATA marking."""
        text = "Contains ITAR DATA"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1

    def test_detect_usml_category(self, detector):
        """Test USML CATEGORY marking."""
        text = "Classified under USML CATEGORY XI"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1

    def test_detect_22_cfr(self, detector):
        """Test 22 CFR (ITAR regulation) reference."""
        text = "Subject to 22 CFR 120-130 regulations"
        spans = detector.detect(text)

        itar_spans = [s for s in spans if s.entity_type == "ITAR_MARKING"]
        assert len(itar_spans) >= 1

    def test_detect_ear_controlled(self, detector):
        """Test EAR CONTROLLED marking."""
        text = "Export subject to EAR CONTROLLED"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1

    def test_detect_eccn(self, detector):
        """Test ECCN (Export Control Classification Number) marking."""
        text = "ECCN: 5A992 classification"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1
        assert any("ECCN" in s.text and "5A992" in s.text for s in ear_spans)

    def test_detect_ear_99(self, detector):
        """Test EAR 99 classification."""
        text = "Classified as EAR 99"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1

    def test_detect_15_cfr(self, detector):
        """Test 15 CFR (EAR regulation) reference."""
        text = "Subject to 15 CFR 730-774"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1

    def test_detect_export_controlled(self, detector):
        """Test EXPORT CONTROLLED marking."""
        text = "This item is EXPORT CONTROLLED"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1

    def test_detect_export_restricted(self, detector):
        """Test EXPORT RESTRICTED marking."""
        text = "EXPORT RESTRICTED material"
        spans = detector.detect(text)

        ear_spans = [s for s in spans if s.entity_type == "EAR_MARKING"]
        assert len(ear_spans) >= 1


# =============================================================================
# FALSE POSITIVE TESTS
# =============================================================================

class TestGovernmentFalsePositives:
    """Test false positive prevention."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_no_false_positive_secret_recipe(self, detector):
        """Test 'secret' in recipe context is not flagged."""
        text = "It's a secret recipe for grandma's cookies."
        spans = detector.detect(text)

        # _is_false_positive_classification should filter out "secret" without
        # classification context (no //, classified, clearance, etc.)
        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) == 0, (
            f"'secret recipe' should not be flagged as CLASSIFICATION_LEVEL, got: {class_spans}"
        )

    def test_no_false_positive_secret_santa(self, detector):
        """Test 'secret' in Santa context is not flagged."""
        text = "We're doing a secret santa gift exchange."
        spans = detector.detect(text)

        # The pattern excludes "secret" followed by "santa" via negative lookahead
        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) == 0, (
            f"'secret santa' should not be flagged as CLASSIFICATION_LEVEL, got: {class_spans}"
        )

    def test_no_false_positive_normal_text(self, detector):
        """Test normal text without government context."""
        text = "The quick brown fox jumps over the lazy dog."
        spans = detector.detect(text)
        assert len(spans) == 0

    def test_no_false_positive_secret_ingredient(self, detector):
        """Test 'secret ingredient' is not flagged."""
        text = "The secret ingredient is love."
        spans = detector.detect(text)

        # The pattern excludes "secret" followed by "ingredient" via negative lookahead
        class_spans = [s for s in spans if s.entity_type == "CLASSIFICATION_LEVEL"]
        assert len(class_spans) == 0, (
            f"'secret ingredient' should not be flagged as CLASSIFICATION_LEVEL, got: {class_spans}"
        )


# =============================================================================
# EDGE CASES
# =============================================================================

class TestGovernmentEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_empty_string(self, detector):
        """Test empty string input."""
        spans = detector.detect("")
        assert spans == []

    def test_whitespace_only(self, detector):
        """Test whitespace-only input."""
        spans = detector.detect("   \n\t  ")
        assert spans == []

    def test_multiple_markings_in_text(self, detector):
        """Test detecting multiple markings in one text."""
        text = """
        Classification: TOP SECRET//SCI//NOFORN
        Contract: FA8750-20-C-1234
        CAGE Code: 1ABC2
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        # Should detect at least classification + contract + CAGE code
        assert "DOD_CONTRACT" in entity_types or "CAGE_CODE" in entity_types, (
            f"Expected contract/CAGE entity types, got: {entity_types}"
        )
        # Should detect classification-related types
        assert entity_types & {"CLASSIFICATION_LEVEL", "CLASSIFICATION_MARKING",
                               "SCI_MARKING", "DISSEMINATION_CONTROL"}, (
            f"Expected classification entity types, got: {entity_types}"
        )
        # Should have found multiple distinct entity types
        assert len(entity_types) >= 3, (
            f"Expected >= 3 entity types in multi-marking text, got {len(entity_types)}: {entity_types}"
        )

    def test_span_positions_valid(self, detector):
        """Test that span positions are correct."""
        text = "Marked TOP SECRET for handling"
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)
            assert text[span.start:span.end] == span.text

    def test_classification_at_document_start(self, detector):
        """Test classification at document start."""
        text = "TOP SECRET\n\nDocument content here."
        spans = detector.detect(text)

        class_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(class_spans) >= 1

    def test_classification_at_document_end(self, detector):
        """Test classification at document end."""
        text = "Document content here.\n\nTOP SECRET"
        spans = detector.detect(text)

        class_spans = [s for s in spans if "CLASSIFICATION" in s.entity_type]
        assert len(class_spans) >= 1


# =============================================================================
# SPAN VALIDATION TESTS
# =============================================================================

class TestGovernmentSpanValidation:
    """Test span properties and validation."""

    @pytest.fixture
    def detector(self):
        return GovernmentDetector()

    def test_span_has_correct_detector_name(self, detector):
        """Test spans have correct detector name."""
        text = "TOP SECRET document"
        spans = detector.detect(text)

        for span in spans:
            assert span.detector == "government"

    def test_span_has_correct_tier(self, detector):
        """Test spans have correct tier."""
        text = "TOP SECRET document"
        spans = detector.detect(text)

        for span in spans:
            assert span.tier == Tier.PATTERN

    def test_span_text_matches_position(self, detector):
        """Test span text matches extracted position."""
        text = "prefix TOP SECRET suffix"
        spans = detector.detect(text)

        for span in spans:
            extracted = text[span.start:span.end]
            assert extracted == span.text

    def test_high_confidence_for_distinctive_markings(self, detector):
        """Test high confidence for distinctive markings."""
        distinctive_texts = [
            "TOP SECRET//SCI",
            "Document marked //NOFORN for distribution",
            "CAGE: 1ABC2",
        ]

        for text in distinctive_texts:
            spans = detector.detect(text)
            assert len(spans) >= 1, f"Expected at least one detection for: {text!r}"
            assert any(s.confidence >= 0.90 for s in spans), (
                f"Low confidence for: {text!r}, got: {[(s.entity_type, s.confidence) for s in spans]}"
            )

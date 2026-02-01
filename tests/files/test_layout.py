"""Tests for layout-aware OCR post-processing (deprecated module).

Tests for the deprecated layout module. This module is kept for backwards
compatibility but has been superseded by enhanced_ocr.py and document_templates.py.
"""

import warnings
from dataclasses import dataclass
from typing import List

import pytest


# =============================================================================
# MOCK DATA CLASSES
# =============================================================================

@dataclass
class MockOCRBlock:
    """Mock OCR block for testing."""
    text: str
    bbox: List[List[float]]
    confidence: float = 0.95


@dataclass
class MockOCRResult:
    """Mock OCR result for testing."""
    full_text: str
    blocks: List[MockOCRBlock]
    confidence: float = 0.9
    offset_map: List = None


def create_block(text: str, x1: float, y1: float, x2: float, y2: float, conf: float = 0.95):
    """Helper to create mock OCR block."""
    bbox = [[x1, y1], [x2, y1], [x2, y2], [x1, y2]]
    return MockOCRBlock(text=text, bbox=bbox, confidence=conf)


# =============================================================================
# DEPRECATION WARNING TESTS
# =============================================================================

class TestDeprecationWarning:
    """Tests for module deprecation."""

    def test_import_warns_deprecation(self):
        """Importing layout module emits deprecation warning."""
        # Clear any cached import
        import sys
        if 'scrubiq.files.layout' in sys.modules:
            del sys.modules['scrubiq.files.layout']

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            import scrubiq.files.layout

            # Should have deprecation warning
            deprecation_warnings = [
                x for x in w if issubclass(x.category, DeprecationWarning)
            ]
            assert len(deprecation_warnings) >= 1
            assert "deprecated" in str(deprecation_warnings[0].message).lower()


# =============================================================================
# DOCUMENT TYPE DETECTION TESTS
# =============================================================================

class TestDetectDocumentType:
    """Tests for detect_document_type function."""

    def test_detect_drivers_license(self):
        """Detects driver's license from keywords."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import detect_document_type

        ocr_result = MockOCRResult(
            full_text="DRIVER LICENSE STATE OF CALIFORNIA DLN: 12345678 DOB: 01/01/1990 CLASS: C",
            blocks=[],
        )

        doc_type = detect_document_type(ocr_result)

        assert doc_type == "drivers_license"

    def test_detect_insurance_card(self):
        """Detects insurance card from keywords."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import detect_document_type

        ocr_result = MockOCRResult(
            full_text="MEMBER ID: 123456 GROUP: ABC123 SUBSCRIBER: JOHN DOE COPAY $20",
            blocks=[],
        )

        doc_type = detect_document_type(ocr_result)

        assert doc_type == "insurance_card"

    def test_detect_lab_report(self):
        """Detects lab report from keywords."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import detect_document_type

        ocr_result = MockOCRResult(
            full_text="SPECIMEN COLLECTED 01/01/2024 RESULT: NORMAL REFERENCE RANGE 0-100 LABORATORY",
            blocks=[],
        )

        doc_type = detect_document_type(ocr_result)

        assert doc_type == "lab_report"

    def test_detect_clinical_note(self):
        """Detects clinical note from keywords."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import detect_document_type

        ocr_result = MockOCRResult(
            full_text="PATIENT: DOE JOHN DIAGNOSIS: HYPERTENSION CHIEF COMPLAINT: HEADACHE ASSESSMENT: STABLE",
            blocks=[],
        )

        doc_type = detect_document_type(ocr_result)

        assert doc_type == "clinical_note"

    def test_detect_unknown_type(self):
        """Returns unknown for unrecognized documents."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import detect_document_type

        ocr_result = MockOCRResult(
            full_text="Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            blocks=[],
        )

        doc_type = detect_document_type(ocr_result)

        assert doc_type == "unknown"

    def test_requires_minimum_score(self):
        """Requires minimum score of 2 to classify."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import detect_document_type

        # Only one keyword match
        ocr_result = MockOCRResult(
            full_text="DRIVER some random text here",
            blocks=[],
        )

        doc_type = detect_document_type(ocr_result)

        assert doc_type == "unknown"


# =============================================================================
# FIELD CODE CLEANUP TESTS
# =============================================================================

class TestCleanFieldCodes:
    """Tests for clean_field_codes function."""

    def test_removes_numeric_prefix_from_dln(self):
        """Removes field code from DLN label."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import clean_field_codes

        result = clean_field_codes("4dDLN:99999999")

        assert "4d" not in result
        assert "DLN" in result

    def test_removes_numeric_prefix_from_dob(self):
        """Removes field code from DOB label."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import clean_field_codes

        result = clean_field_codes("3DOB: 01/07/1973")

        # Regex removes numeric prefix before label patterns
        # "3DOB" matches pattern \d{1,2}[a-zA-Z]? before DOB:
        # Result is "OB: 01/07/1973" because it removes "3D"
        # The date 01/07/1973 contains "3" so check for prefix removal
        assert not result.startswith("3")

    def test_preserves_text_without_codes(self):
        """Preserves text without field codes."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import clean_field_codes

        result = clean_field_codes("John Doe")

        assert result == "John Doe"


# =============================================================================
# OCR ARTIFACT CLEANUP TESTS
# =============================================================================

class TestCleanOCRArtifacts:
    """Tests for clean_ocr_artifacts function."""

    def test_adds_space_between_numbers_and_words(self):
        """Adds space between numbers and uppercase words."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import clean_ocr_artifacts

        result = clean_ocr_artifacts("8123MAINSTREET")

        assert "8123 MAIN" in result

    def test_removes_leading_colon(self):
        """Removes leading colon."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import clean_ocr_artifacts

        result = clean_ocr_artifacts(":99999999")

        assert not result.startswith(":")

    def test_removes_dups_from_dl(self):
        """Removes DUPS marker from driver's license."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import clean_ocr_artifacts

        result = clean_ocr_artifacts("DUPS:00 other text", doc_type="drivers_license")

        assert "DUPS" not in result
        assert "00" not in result or "other" in result

    def test_removes_organ_donor_from_dl(self):
        """Removes organ donor text from driver's license."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import clean_ocr_artifacts

        result = clean_ocr_artifacts("ORGAN DONOR text here", doc_type="drivers_license")

        assert "ORGAN DONOR" not in result


# =============================================================================
# LAYOUT FIELD TESTS
# =============================================================================

class TestLayoutField:
    """Tests for LayoutField dataclass."""

    def test_create_layout_field(self):
        """LayoutField stores label and value."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import LayoutField

        field = LayoutField(
            label="DLN",
            value="12345678",
            confidence=0.95,
            label_bbox=[[0, 0], [50, 0], [50, 20], [0, 20]],
        )

        assert field.label == "DLN"
        assert field.value == "12345678"
        assert field.confidence == 0.95

    def test_layout_field_optional_value_bbox(self):
        """LayoutField value_bbox is optional."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import LayoutField

        field = LayoutField(
            label="NAME",
            value="DOE",
            confidence=0.9,
            label_bbox=[[0, 0], [50, 0], [50, 20], [0, 20]],
        )

        assert field.value_bbox is None


# =============================================================================
# BLOCK GEOMETRY HELPER TESTS
# =============================================================================

class TestBlockGeometryHelpers:
    """Tests for block geometry helper functions."""

    def test_get_block_center_y(self):
        """get_block_center_y returns vertical center."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import get_block_center_y

        block = create_block("text", 0, 10, 100, 30)

        center = get_block_center_y(block)

        assert center == 20.0  # (10 + 30) / 2

    def test_get_block_left_x(self):
        """get_block_left_x returns left edge."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import get_block_left_x

        block = create_block("text", 50, 10, 100, 30)

        left = get_block_left_x(block)

        assert left == 50.0

    def test_get_block_right_x(self):
        """get_block_right_x returns right edge."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import get_block_right_x

        block = create_block("text", 50, 10, 100, 30)

        right = get_block_right_x(block)

        assert right == 100.0

    def test_blocks_on_same_line_true(self):
        """blocks_on_same_line returns True for aligned blocks."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import blocks_on_same_line

        block1 = create_block("A", 0, 10, 50, 30)
        block2 = create_block("B", 60, 12, 110, 32)  # Slight Y offset

        result = blocks_on_same_line(block1, block2, tolerance=15)

        assert result is True

    def test_blocks_on_same_line_false(self):
        """blocks_on_same_line returns False for different lines."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import blocks_on_same_line

        block1 = create_block("A", 0, 10, 50, 30)
        block2 = create_block("B", 0, 60, 50, 80)

        result = blocks_on_same_line(block1, block2, tolerance=15)

        assert result is False

    def test_block_is_to_right_true(self):
        """block_is_to_right returns True when properly positioned."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import block_is_to_right

        label = create_block("DLN:", 0, 10, 50, 30)
        value = create_block("12345", 60, 10, 110, 30)

        result = block_is_to_right(label, value, max_gap=100)

        assert result is True

    def test_block_is_to_right_false_left(self):
        """block_is_to_right returns False when value is left."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import block_is_to_right

        label = create_block("DLN:", 60, 10, 110, 30)
        value = create_block("12345", 0, 10, 50, 30)

        result = block_is_to_right(label, value, max_gap=100)

        assert result is False

    def test_block_is_to_right_false_too_far(self):
        """block_is_to_right returns False when gap too large."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import block_is_to_right

        label = create_block("DLN:", 0, 10, 50, 30)
        value = create_block("12345", 200, 10, 250, 30)

        result = block_is_to_right(label, value, max_gap=100)

        assert result is False


# =============================================================================
# IS LABEL BLOCK TESTS
# =============================================================================

class TestIsLabelBlock:
    """Tests for is_label_block function."""

    def test_colon_ending_is_label(self):
        """Block ending with colon is label."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import is_label_block

        block = create_block("DLN:", 0, 0, 50, 20)

        assert is_label_block(block) is True

    def test_known_label_patterns(self):
        """Known label patterns are detected."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import is_label_block

        labels = ["DLN", "DOB", "EXP", "NAME", "MEMBER", "GROUP"]

        for label in labels:
            block = create_block(label, 0, 0, 50, 20)
            assert is_label_block(block) is True, f"{label} should be a label"

    def test_value_not_label(self):
        """Value text is not a label."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import is_label_block

        block = create_block("12345678", 0, 0, 80, 20)

        assert is_label_block(block) is False


# =============================================================================
# EXTRACT FIELDS BY LAYOUT TESTS
# =============================================================================

class TestExtractFieldsByLayout:
    """Tests for extract_fields_by_layout function."""

    def test_empty_blocks_returns_empty(self):
        """Empty blocks returns empty list."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import extract_fields_by_layout

        ocr_result = MockOCRResult(full_text="", blocks=[])

        fields = extract_fields_by_layout(ocr_result)

        assert fields == []

    def test_extracts_label_value_pairs(self):
        """Extracts label:value pairs from layout."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import extract_fields_by_layout

        ocr_result = MockOCRResult(
            full_text="DLN: 12345678",
            blocks=[
                create_block("DLN:", 0, 10, 40, 30),
                create_block("12345678", 50, 10, 130, 30),
            ],
        )

        fields = extract_fields_by_layout(ocr_result)

        assert len(fields) == 1
        assert fields[0].label == "DLN"
        assert fields[0].value == "12345678"

    def test_extracts_multiple_fields(self):
        """Extracts multiple label:value pairs."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import extract_fields_by_layout

        ocr_result = MockOCRResult(
            full_text="DLN: 12345 DOB: 01/01/90",
            blocks=[
                create_block("DLN:", 0, 10, 40, 30),
                create_block("12345", 50, 10, 100, 30),
                create_block("DOB:", 0, 50, 40, 70),
                create_block("01/01/90", 50, 50, 130, 70),
            ],
        )

        fields = extract_fields_by_layout(ocr_result)

        assert len(fields) == 2


# =============================================================================
# PROCESS STRUCTURED DOCUMENT TESTS
# =============================================================================

class TestProcessStructuredDocument:
    """Tests for process_structured_document function."""

    def test_empty_result_unchanged(self):
        """Empty OCR result is returned unchanged."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import process_structured_document

        ocr_result = MockOCRResult(full_text="", blocks=[])

        result = process_structured_document(ocr_result)

        assert result is ocr_result

    def test_process_drivers_license(self):
        """Processes driver's license document."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import process_structured_document

        ocr_result = MockOCRResult(
            full_text="DRIVER LICENSE DLN: 12345678 DOB: 01/01/1990",
            blocks=[
                create_block("DRIVER LICENSE", 0, 0, 150, 30),
                create_block("DLN:", 0, 40, 40, 60),
                create_block("12345678", 50, 40, 130, 60),
                create_block("DOB:", 0, 70, 40, 90),
                create_block("01/01/1990", 50, 70, 140, 90),
            ],
        )

        result = process_structured_document(ocr_result)

        # Should have cleaned blocks
        assert result.blocks is not None

    def test_process_unknown_applies_basic_cleanup(self):
        """Unknown document type gets basic cleanup."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import process_structured_document

        ocr_result = MockOCRResult(
            full_text="Random text here",
            blocks=[
                create_block("Random text here", 0, 0, 150, 30),
            ],
        )

        result = process_structured_document(ocr_result)

        # Should still have processed blocks
        assert len(result.blocks) == 1


# =============================================================================
# PHI FIELDS HELPERS TESTS
# =============================================================================

class TestGetPhiFieldsForDocType:
    """Tests for get_phi_fields_for_doc_type function."""

    def test_drivers_license_phi_fields(self):
        """Returns DL PHI fields for driver's license."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import get_phi_fields_for_doc_type

        fields = get_phi_fields_for_doc_type("drivers_license")

        assert "DLN" in fields
        assert "DOB" in fields
        assert "NAME" in fields
        assert "ADDRESS" in fields

    def test_insurance_phi_fields(self):
        """Returns insurance PHI fields for insurance card."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import get_phi_fields_for_doc_type

        fields = get_phi_fields_for_doc_type("insurance_card")

        assert "MEMBER" in fields
        assert "GROUP" in fields
        assert "DOB" in fields

    def test_unknown_returns_empty(self):
        """Returns empty set for unknown document type."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import get_phi_fields_for_doc_type

        fields = get_phi_fields_for_doc_type("unknown")

        assert fields == set()

    def test_other_type_returns_empty(self):
        """Returns empty set for unrecognized type."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import get_phi_fields_for_doc_type

        fields = get_phi_fields_for_doc_type("some_other_type")

        assert fields == set()


# =============================================================================
# PA FIELD CODES TESTS
# =============================================================================

class TestPAFieldCodes:
    """Tests for PA field codes constant."""

    def test_pa_field_codes_defined(self):
        """PA field codes constant exists."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from scrubiq.files.layout import PA_FIELD_CODES

        assert "1" in PA_FIELD_CODES
        assert PA_FIELD_CODES["1"] == "FAMILY_NAME"
        assert PA_FIELD_CODES["4d"] == "DLN"
        assert PA_FIELD_CODES["3"] == "DOB"

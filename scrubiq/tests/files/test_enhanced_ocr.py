"""Tests for enhanced OCR post-processing.

Tests for layout-aware OCR enhancement and document processing.
"""

from dataclasses import dataclass
from typing import List, Optional
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from scrubiq.files.document_templates import DocumentType


# =============================================================================
# MOCK DATA CLASSES
# =============================================================================

@dataclass
class MockOCRBlock:
    """Mock OCR block for testing."""
    text: str
    bounding_rect: tuple  # (x1, y1, x2, y2)
    confidence: float = 0.95
    bbox: List[List[float]] = None

    def __post_init__(self):
        if self.bbox is None:
            x1, y1, x2, y2 = self.bounding_rect
            self.bbox = [[x1, y1], [x2, y1], [x2, y2], [x1, y2]]


@dataclass
class MockOCRResult:
    """Mock OCR result for testing."""
    full_text: str
    blocks: List[MockOCRBlock]
    confidence: float = 0.9
    offset_map: List = None


@dataclass
class MockLayoutRegion:
    """Mock layout region for testing."""
    x: int
    y: int
    x2: int
    y2: int
    layout_class: "MockLayoutClass"


class MockLayoutClass:
    """Mock layout class enum."""
    def __init__(self, value):
        self.value = value


@dataclass
class MockLayoutResult:
    """Mock layout analysis result."""
    regions: List[MockLayoutRegion]


# =============================================================================
# ENHANCEDOCRRESULT TESTS
# =============================================================================

class TestEnhancedOCRResult:
    """Tests for EnhancedOCRResult dataclass."""

    def test_create_result(self):
        """EnhancedOCRResult stores all fields."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRResult

        result = EnhancedOCRResult(
            raw_text="Hello World",
            enhanced_text="Hello World",
            document_type=DocumentType.UNKNOWN,
            is_id_card=False,
            layout_regions=0,
            enhancements_applied=["basic_spacing"],
        )

        assert result.raw_text == "Hello World"
        assert result.enhanced_text == "Hello World"
        assert result.document_type == DocumentType.UNKNOWN
        assert result.is_id_card is False
        assert result.layout_regions == 0
        assert result.enhancements_applied == ["basic_spacing"]

    def test_create_result_with_phi_fields(self):
        """EnhancedOCRResult can store PHI fields."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRResult

        phi_fields = {
            "name": {"value": "John Doe", "phi_category": "name", "confidence": 0.9},
            "dob": {"value": "01/01/1990", "phi_category": "date", "confidence": 0.85},
        }

        result = EnhancedOCRResult(
            raw_text="John Doe DOB 01/01/1990",
            enhanced_text="John Doe DOB 01/01/1990",
            document_type=DocumentType.DRIVERS_LICENSE,
            is_id_card=True,
            layout_regions=2,
            enhancements_applied=["type(DRIVERS_LICENSE)", "phi(2)"],
            phi_fields=phi_fields,
        )

        assert result.phi_fields == phi_fields
        assert len(result.phi_fields) == 2


# =============================================================================
# BASIC SPATIAL GROUPING TESTS
# =============================================================================

class TestBasicSpatialGrouping:
    """Tests for _basic_spatial_grouping function."""

    def test_empty_blocks(self):
        """Returns empty string for empty blocks."""
        from scrubiq.files.enhanced_ocr import _basic_spatial_grouping

        result = _basic_spatial_grouping([])

        assert result == ""

    def test_single_block(self):
        """Returns text from single block."""
        from scrubiq.files.enhanced_ocr import _basic_spatial_grouping

        blocks = [MockOCRBlock("Hello", (0, 0, 50, 20))]

        result = _basic_spatial_grouping(blocks)

        assert "Hello" in result

    def test_blocks_same_line(self):
        """Blocks on same line are joined."""
        from scrubiq.files.enhanced_ocr import _basic_spatial_grouping

        blocks = [
            MockOCRBlock("Hello", (0, 10, 50, 30)),
            MockOCRBlock("World", (60, 10, 110, 30)),
        ]

        result = _basic_spatial_grouping(blocks, line_threshold=20)

        # Both should be on same line
        lines = result.strip().split('\n')
        assert len(lines) == 1
        assert "Hello" in lines[0]
        assert "World" in lines[0]

    def test_blocks_different_lines(self):
        """Blocks on different lines create separate lines."""
        from scrubiq.files.enhanced_ocr import _basic_spatial_grouping

        blocks = [
            MockOCRBlock("Line 1", (0, 0, 50, 20)),
            MockOCRBlock("Line 2", (0, 50, 50, 70)),
        ]

        result = _basic_spatial_grouping(blocks, line_threshold=20)

        lines = [l.strip() for l in result.strip().split('\n') if l.strip()]
        assert len(lines) == 2

    def test_blocks_sorted_top_to_bottom(self):
        """Blocks are sorted top to bottom."""
        from scrubiq.files.enhanced_ocr import _basic_spatial_grouping

        # Create blocks out of order
        blocks = [
            MockOCRBlock("Second", (0, 50, 50, 70)),
            MockOCRBlock("First", (0, 0, 50, 20)),
        ]

        result = _basic_spatial_grouping(blocks, line_threshold=20)

        lines = [l.strip() for l in result.strip().split('\n') if l.strip()]
        assert "First" in lines[0]
        assert "Second" in lines[1]

    def test_blocks_sorted_left_to_right_on_same_line(self):
        """Blocks on same line are sorted left to right."""
        from scrubiq.files.enhanced_ocr import _basic_spatial_grouping

        # Create blocks out of order horizontally
        blocks = [
            MockOCRBlock("Second", (100, 10, 150, 30)),
            MockOCRBlock("First", (0, 10, 50, 30)),
        ]

        result = _basic_spatial_grouping(blocks, line_threshold=20)

        # Should be "First Second" or similar
        assert result.index("First") < result.index("Second")


# =============================================================================
# ASSEMBLE LINE WITH GAPS TESTS
# =============================================================================

class TestAssembleLineWithGaps:
    """Tests for _assemble_line_with_gaps function."""

    def test_empty_blocks(self):
        """Returns empty string for empty blocks."""
        from scrubiq.files.enhanced_ocr import _assemble_line_with_gaps

        result = _assemble_line_with_gaps([])

        assert result == ""

    def test_single_block(self):
        """Returns text from single block."""
        from scrubiq.files.enhanced_ocr import _assemble_line_with_gaps

        blocks = [MockOCRBlock("Hello", (0, 0, 50, 20))]

        result = _assemble_line_with_gaps(blocks)

        assert result == "Hello"

    def test_adjacent_blocks_no_gap(self):
        """Adjacent blocks without gap are joined."""
        from scrubiq.files.enhanced_ocr import _assemble_line_with_gaps

        blocks = [
            MockOCRBlock("ab", (0, 0, 20, 20)),  # 10 pixels per char
            MockOCRBlock("cd", (22, 0, 42, 20)),  # 2 pixel gap
        ]

        result = _assemble_line_with_gaps(blocks)

        # Small gap shouldn't add space
        assert result == "abcd"

    def test_blocks_with_gap_get_space(self):
        """Blocks with gap get space inserted."""
        from scrubiq.files.enhanced_ocr import _assemble_line_with_gaps

        blocks = [
            MockOCRBlock("ab", (0, 0, 20, 20)),  # 10 pixels per char
            MockOCRBlock("cd", (50, 0, 70, 20)),  # 30 pixel gap
        ]

        result = _assemble_line_with_gaps(blocks)

        # Large gap should add space
        assert " " in result


# =============================================================================
# IMPROVE SPACING WITH LAYOUT TESTS
# =============================================================================

class TestImproveSpacingWithLayout:
    """Tests for improve_spacing_with_layout function."""

    def test_empty_blocks_returns_empty(self):
        """Empty blocks returns empty string."""
        from scrubiq.files.enhanced_ocr import improve_spacing_with_layout

        result = improve_spacing_with_layout([], [])

        assert result == ""

    def test_no_layout_falls_back(self):
        """Falls back to basic grouping without layout."""
        from scrubiq.files.enhanced_ocr import improve_spacing_with_layout

        blocks = [MockOCRBlock("Hello", (0, 0, 50, 20))]

        result = improve_spacing_with_layout(blocks, [])

        assert "Hello" in result

    def test_blocks_assigned_to_regions(self):
        """Blocks are assigned to containing regions."""
        from scrubiq.files.enhanced_ocr import improve_spacing_with_layout

        blocks = [
            MockOCRBlock("Header", (10, 10, 90, 40)),
            MockOCRBlock("Body", (10, 60, 90, 90)),
        ]

        regions = [
            MockLayoutRegion(0, 0, 100, 50, MockLayoutClass("header")),
            MockLayoutRegion(0, 50, 100, 100, MockLayoutClass("body")),
        ]

        result = improve_spacing_with_layout(blocks, regions)

        # Both should be in result
        assert "Header" in result
        assert "Body" in result

    def test_unassigned_blocks_included(self):
        """Blocks not in any region are still included."""
        from scrubiq.files.enhanced_ocr import improve_spacing_with_layout

        blocks = [
            MockOCRBlock("Inside", (10, 10, 40, 40)),
            MockOCRBlock("Outside", (200, 200, 250, 230)),  # Outside region
        ]

        regions = [
            MockLayoutRegion(0, 0, 100, 100, MockLayoutClass("content")),
        ]

        result = improve_spacing_with_layout(blocks, regions)

        assert "Inside" in result
        assert "Outside" in result


# =============================================================================
# ASSEMBLE BLOCKS TESTS
# =============================================================================

class TestAssembleBlocks:
    """Tests for _assemble_blocks function."""

    def test_empty_blocks(self):
        """Empty blocks returns empty string."""
        from scrubiq.files.enhanced_ocr import _assemble_blocks

        result = _assemble_blocks([], line_threshold=20)

        assert result == ""

    def test_assembles_with_line_threshold(self):
        """Blocks are assembled respecting line threshold."""
        from scrubiq.files.enhanced_ocr import _assemble_blocks

        blocks_with_idx = [
            (MockOCRBlock("First", (0, 0, 50, 20)), 0),
            (MockOCRBlock("Second", (0, 50, 50, 70)), 1),
        ]

        result = _assemble_blocks(blocks_with_idx, line_threshold=20)

        assert "First" in result
        assert "Second" in result


# =============================================================================
# ID CARD TYPE CLASSIFICATION TESTS
# =============================================================================

class TestIDCardTypes:
    """Tests for ID card type classification."""

    def test_drivers_license_is_id(self):
        """Driver's license is classified as ID card."""
        from scrubiq.files.enhanced_ocr import ID_CARD_TYPES

        assert DocumentType.DRIVERS_LICENSE in ID_CARD_TYPES

    def test_passport_is_id(self):
        """Passport is classified as ID card."""
        from scrubiq.files.enhanced_ocr import ID_CARD_TYPES

        assert DocumentType.PASSPORT in ID_CARD_TYPES

    def test_insurance_types_are_id(self):
        """Insurance cards are classified as ID cards."""
        from scrubiq.files.enhanced_ocr import ID_CARD_TYPES

        assert DocumentType.INSURANCE_COMMERCIAL in ID_CARD_TYPES
        assert DocumentType.INSURANCE_MEDICARE in ID_CARD_TYPES
        assert DocumentType.INSURANCE_MEDICAID in ID_CARD_TYPES

    def test_state_id_is_id(self):
        """State ID is classified as ID card."""
        from scrubiq.files.enhanced_ocr import ID_CARD_TYPES

        assert DocumentType.STATE_ID in ID_CARD_TYPES


# =============================================================================
# ENHANCEDOCRPROCESSOR TESTS
# =============================================================================

class TestEnhancedOCRProcessor:
    """Tests for EnhancedOCRProcessor class."""

    def test_init_without_layout_detector(self):
        """Processor can be created without layout detector."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        processor = EnhancedOCRProcessor()

        assert processor.layout_detector is None

    def test_init_with_layout_detector(self):
        """Processor can be created with layout detector."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detector = MagicMock()
        processor = EnhancedOCRProcessor(layout_detector=mock_detector)

        assert processor.layout_detector is mock_detector

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    @patch("scrubiq.files.enhanced_ocr.parse_document")
    @patch("scrubiq.files.enhanced_ocr.get_parser")
    def test_process_basic(self, mock_get_parser, mock_parse, mock_detect):
        """process() returns EnhancedOCRResult."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor, EnhancedOCRResult

        mock_detect.return_value = (DocumentType.UNKNOWN, 0.5)
        mock_parse.return_value = MagicMock(get_phi_fields=lambda: {})
        mock_get_parser.return_value = None

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="Hello World",
            blocks=[MockOCRBlock("Hello World", (0, 0, 100, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        result = processor.process(image, ocr_result)

        assert isinstance(result, EnhancedOCRResult)
        assert result.raw_text == "Hello World"

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    @patch("scrubiq.files.enhanced_ocr.parse_document")
    @patch("scrubiq.files.enhanced_ocr.get_parser")
    def test_process_detects_document_type(self, mock_get_parser, mock_parse, mock_detect):
        """process() detects and stores document type."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detect.return_value = (DocumentType.DRIVERS_LICENSE, 0.8)
        mock_parse.return_value = MagicMock(get_phi_fields=lambda: {})
        mock_get_parser.return_value = None

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="DRIVER LICENSE",
            blocks=[MockOCRBlock("DRIVER LICENSE", (0, 0, 100, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        result = processor.process(image, ocr_result)

        assert result.document_type == DocumentType.DRIVERS_LICENSE

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    @patch("scrubiq.files.enhanced_ocr.parse_document")
    @patch("scrubiq.files.enhanced_ocr.get_parser")
    def test_process_marks_id_card(self, mock_get_parser, mock_parse, mock_detect):
        """process() marks ID cards correctly."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detect.return_value = (DocumentType.PASSPORT, 0.9)
        mock_parse.return_value = MagicMock(get_phi_fields=lambda: {})
        mock_get_parser.return_value = None

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="PASSPORT",
            blocks=[MockOCRBlock("PASSPORT", (0, 0, 100, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        result = processor.process(image, ocr_result)

        assert result.is_id_card is True

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    @patch("scrubiq.files.enhanced_ocr.parse_document")
    @patch("scrubiq.files.enhanced_ocr.get_parser")
    def test_process_extracts_phi_fields(self, mock_get_parser, mock_parse, mock_detect):
        """process() extracts PHI fields from document."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detect.return_value = (DocumentType.DRIVERS_LICENSE, 0.8)

        mock_field = MagicMock()
        mock_field.value = "John Doe"
        mock_field.phi_category = MagicMock(value="name")
        mock_field.confidence = 0.95
        mock_field.validated = True

        mock_parse.return_value = MagicMock(
            get_phi_fields=lambda: {"name": mock_field}
        )
        mock_get_parser.return_value = None

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="John Doe",
            blocks=[MockOCRBlock("John Doe", (0, 0, 100, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        result = processor.process(image, ocr_result)

        assert result.phi_fields is not None
        assert "name" in result.phi_fields
        assert result.phi_fields["name"]["value"] == "John Doe"

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    @patch("scrubiq.files.enhanced_ocr.parse_document")
    @patch("scrubiq.files.enhanced_ocr.get_parser")
    def test_process_applies_text_cleaning(self, mock_get_parser, mock_parse, mock_detect):
        """process() applies document-specific text cleaning."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detect.return_value = (DocumentType.DRIVERS_LICENSE, 0.8)
        mock_parse.return_value = MagicMock(get_phi_fields=lambda: {})

        mock_parser = MagicMock()
        mock_parser.clean_text.return_value = "CLEANED TEXT"
        mock_get_parser.return_value = mock_parser

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="RAW TEXT",
            blocks=[MockOCRBlock("RAW TEXT", (0, 0, 100, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        result = processor.process(image, ocr_result)

        mock_parser.clean_text.assert_called()
        assert result.enhanced_text == "CLEANED TEXT"

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    def test_process_without_document_cleaning(self, mock_detect):
        """process() can skip document cleaning."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detect.return_value = (DocumentType.UNKNOWN, 0.2)

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="Plain text",
            blocks=[MockOCRBlock("Plain text", (0, 0, 100, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        result = processor.process(image, ocr_result, apply_document_cleaning=False)

        # Should still work but not apply document-specific cleaning
        assert result is not None
        assert result.document_type == DocumentType.UNKNOWN

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    def test_process_calculates_aspect_ratio(self, mock_detect):
        """process() calculates image aspect ratio."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detect.return_value = (DocumentType.UNKNOWN, 0.2)

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="Text",
            blocks=[MockOCRBlock("Text", (0, 0, 50, 20))],
        )
        # 200 width, 100 height = 2.0 aspect ratio
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        processor.process(image, ocr_result, apply_document_cleaning=False)

        # detect_document_type should be called with aspect ratio
        call_args = mock_detect.call_args
        assert call_args[0][1] == 2.0  # aspect ratio

    @patch("scrubiq.files.enhanced_ocr.detect_document_type")
    def test_process_tracks_enhancements(self, mock_detect):
        """process() tracks applied enhancements."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detect.return_value = (DocumentType.UNKNOWN, 0.2)

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="Text",
            blocks=[MockOCRBlock("Text", (0, 0, 50, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        result = processor.process(image, ocr_result, apply_document_cleaning=False)

        assert len(result.enhancements_applied) > 0
        # Should include type detection
        assert any("type" in e for e in result.enhancements_applied)

    def test_process_with_layout_detector(self):
        """process() uses layout detector when available."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detector = MagicMock()
        mock_detector.is_initialized = True
        mock_layout_result = MockLayoutResult(regions=[
            MockLayoutRegion(0, 0, 100, 50, MockLayoutClass("header")),
        ])
        mock_detector.analyze.return_value = mock_layout_result

        processor = EnhancedOCRProcessor(layout_detector=mock_detector)

        ocr_result = MockOCRResult(
            full_text="Header text",
            blocks=[MockOCRBlock("Header text", (10, 10, 90, 40))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        with patch("scrubiq.files.enhanced_ocr.detect_document_type") as mock_detect:
            mock_detect.return_value = (DocumentType.UNKNOWN, 0.2)
            result = processor.process(image, ocr_result, apply_document_cleaning=False)

        mock_detector.analyze.assert_called_once()
        assert result.layout_regions == 1
        assert any("layout" in e for e in result.enhancements_applied)

    def test_process_handles_layout_failure(self):
        """process() handles layout analysis failure gracefully."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        mock_detector = MagicMock()
        mock_detector.is_initialized = True
        mock_detector.analyze.side_effect = RuntimeError("Layout failed")

        processor = EnhancedOCRProcessor(layout_detector=mock_detector)

        ocr_result = MockOCRResult(
            full_text="Text",
            blocks=[MockOCRBlock("Text", (0, 0, 50, 20))],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        with patch("scrubiq.files.enhanced_ocr.detect_document_type") as mock_detect:
            mock_detect.return_value = (DocumentType.UNKNOWN, 0.2)
            # Should not raise
            result = processor.process(image, ocr_result, apply_document_cleaning=False)

        assert result is not None
        assert result.layout_regions == 0


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_ocr_result(self):
        """Handles empty OCR result."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="",
            blocks=[],
        )
        image = np.zeros((100, 200, 3), dtype=np.uint8)

        with patch("scrubiq.files.enhanced_ocr.detect_document_type") as mock_detect:
            mock_detect.return_value = (DocumentType.UNKNOWN, 0.0)
            result = processor.process(image, ocr_result, apply_document_cleaning=False)

        assert result.raw_text == ""
        assert result.enhanced_text == ""

    def test_none_image_handled(self):
        """Handles None image."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="Text",
            blocks=[MockOCRBlock("Text", (0, 0, 50, 20))],
        )

        with patch("scrubiq.files.enhanced_ocr.detect_document_type") as mock_detect:
            mock_detect.return_value = (DocumentType.UNKNOWN, 0.0)
            result = processor.process(None, ocr_result, apply_document_cleaning=False)

        assert result is not None

    def test_grayscale_image(self):
        """Handles grayscale image."""
        from scrubiq.files.enhanced_ocr import EnhancedOCRProcessor

        processor = EnhancedOCRProcessor()

        ocr_result = MockOCRResult(
            full_text="Text",
            blocks=[MockOCRBlock("Text", (0, 0, 50, 20))],
        )
        # Grayscale image has only 2 dimensions
        image = np.zeros((100, 200), dtype=np.uint8)

        with patch("scrubiq.files.enhanced_ocr.detect_document_type") as mock_detect:
            mock_detect.return_value = (DocumentType.UNKNOWN, 0.0)
            result = processor.process(image, ocr_result, apply_document_cleaning=False)

        assert result is not None

    def test_very_small_line_threshold(self):
        """Handles very small line threshold."""
        from scrubiq.files.enhanced_ocr import _basic_spatial_grouping

        blocks = [
            MockOCRBlock("A", (0, 0, 10, 10)),
            MockOCRBlock("B", (0, 5, 10, 15)),  # Overlapping Y
        ]

        # Should not crash with very small threshold
        result = _basic_spatial_grouping(blocks, line_threshold=1)

        assert "A" in result or "B" in result

    def test_single_character_blocks(self):
        """Handles single character blocks."""
        from scrubiq.files.enhanced_ocr import _assemble_line_with_gaps

        blocks = [
            MockOCRBlock("A", (0, 0, 10, 20)),
            MockOCRBlock("B", (15, 0, 25, 20)),
            MockOCRBlock("C", (30, 0, 40, 20)),
        ]

        result = _assemble_line_with_gaps(blocks)

        assert "A" in result
        assert "B" in result
        assert "C" in result

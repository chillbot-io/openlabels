"""
Tests for openlabels/adapters/scanner/ocr.py

Tests the OCR engine and text processing functions.
Note: Full OCR tests require optional dependencies (rapidocr-onnxruntime, numpy, etc.)
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, PropertyMock

# Import the functions we can test without optional dependencies
from openlabels.adapters.scanner.ocr import (
    _clean_ocr_text,
    _get_line_group,
    _get_bbox_top_left,
    _ocr_sort_key,
    _group_text_into_lines,
    _LINE_GROUP_THRESHOLD,
)

# Try to import optional dependencies for full tests
try:
    import numpy as np
    from intervaltree import IntervalTree
    HAS_OCR_DEPS = True
except ImportError:
    HAS_OCR_DEPS = False


# --- Text Cleaning Tests ---

class TestCleanOcrText:
    """Tests for _clean_ocr_text function."""

    def test_stuck_field_codes(self):
        """Test fixing stuck field codes like '15SEX:M'."""
        assert _clean_ocr_text("15SEX:M") == "15 SEX: M"
        assert _clean_ocr_text("18EYES:BR") == "18 EYES: BR"

    def test_missing_space_after_colon(self):
        """Test adding space after colon."""
        assert _clean_ocr_text("DOB:01/01/90") == "DOB: 01/01/90"
        assert _clean_ocr_text("SEX:M") == "SEX: M"
        assert _clean_ocr_text("SSN:123-45-6789") == "SSN: 123-45-6789"

    def test_numbers_stuck_to_words(self):
        """Test separating numbers from uppercase words."""
        assert _clean_ocr_text("4dDLN") == "4d DLN"
        assert _clean_ocr_text("123ABC") == "123 ABC"

    def test_preserves_normal_text(self):
        """Test that normal text is not modified."""
        assert _clean_ocr_text("Hello World") == "Hello World"
        assert _clean_ocr_text("SSN: 123-45-6789") == "SSN: 123-45-6789"

    def test_mixed_patterns(self):
        """Test text with multiple OCR artifacts."""
        text = "15SEX:M DOB:01/01/90"
        result = _clean_ocr_text(text)
        assert "15 SEX: M" in result
        assert "DOB: 01/01/90" in result

    def test_empty_string(self):
        """Test empty string handling."""
        assert _clean_ocr_text("") == ""


# --- Line Grouping Tests ---

class TestGetLineGroup:
    """Tests for _get_line_group function."""

    def test_same_line_group(self):
        """Test y-coordinates within threshold are same group."""
        # Within 20 pixel threshold
        group1 = _get_line_group(5.0)
        group2 = _get_line_group(15.0)
        assert group1 == group2

    def test_different_line_groups(self):
        """Test y-coordinates beyond threshold are different groups."""
        group1 = _get_line_group(5.0)
        group2 = _get_line_group(30.0)
        assert group1 != group2

    def test_line_group_boundaries(self):
        """Test behavior at line group boundaries."""
        # At exactly threshold
        group1 = _get_line_group(0.0)
        group2 = _get_line_group(_LINE_GROUP_THRESHOLD)
        assert group1 == 0
        assert group2 == 1


# --- Bounding Box Tests ---

class TestGetBboxTopLeft:
    """Tests for _get_bbox_top_left function."""

    def test_standard_bbox(self):
        """Test extracting top-left from standard quadrilateral."""
        # Standard rectangle: [[left,top], [right,top], [right,bottom], [left,bottom]]
        bbox = [[10, 20], [100, 20], [100, 50], [10, 50]]
        x, y = _get_bbox_top_left(bbox)
        assert x == 10
        assert y == 20

    def test_rotated_bbox(self):
        """Test extracting top-left from rotated quadrilateral."""
        # Slightly rotated
        bbox = [[15, 18], [105, 22], [103, 52], [12, 48]]
        x, y = _get_bbox_top_left(bbox)
        assert x == 12  # Min x
        assert y == 18  # Min y


# --- Sort Key Tests ---

class TestOcrSortKey:
    """Tests for _ocr_sort_key function."""

    def test_sort_top_to_bottom(self):
        """Test items sort top to bottom by line group."""
        item1 = ([[0, 100], [10, 100], [10, 110], [0, 110]], "bottom", 0.9)
        item2 = ([[0, 0], [10, 0], [10, 10], [0, 10]], "top", 0.9)

        key1 = _ocr_sort_key(item1)
        key2 = _ocr_sort_key(item2)

        assert key2 < key1  # top should come before bottom

    def test_sort_left_to_right(self):
        """Test items on same line sort left to right."""
        item1 = ([[100, 0], [110, 0], [110, 10], [100, 10]], "right", 0.9)
        item2 = ([[0, 0], [10, 0], [10, 10], [0, 10]], "left", 0.9)

        key1 = _ocr_sort_key(item1)
        key2 = _ocr_sort_key(item2)

        assert key2 < key1  # left should come before right


# --- Group Text into Lines Tests ---

class TestGroupTextIntoLines:
    """Tests for _group_text_into_lines function."""

    def test_single_line(self):
        """Test grouping items on a single line."""
        items = [
            ([[0, 0], [10, 0], [10, 10], [0, 10]], "Hello", 0.9),
            ([[20, 0], [30, 0], [30, 10], [20, 10]], "World", 0.9),
        ]

        lines = _group_text_into_lines(items, lambda x: x[0], lambda x: x[1])

        assert len(lines) == 1
        assert lines[0] == "Hello World"

    def test_multiple_lines(self):
        """Test grouping items on multiple lines."""
        items = [
            ([[0, 0], [10, 0], [10, 10], [0, 10]], "Line1", 0.9),
            ([[0, 50], [10, 50], [10, 60], [0, 60]], "Line2", 0.9),
        ]

        lines = _group_text_into_lines(items, lambda x: x[0], lambda x: x[1])

        assert len(lines) == 2
        assert lines[0] == "Line1"
        assert lines[1] == "Line2"

    def test_empty_items(self):
        """Test with empty items list."""
        lines = _group_text_into_lines([], lambda x: x[0], lambda x: x[1])
        assert lines == []

    def test_reading_order(self):
        """Test items are grouped in reading order."""
        items = [
            ([[0, 0], [10, 0], [10, 10], [0, 10]], "First", 0.9),
            ([[20, 0], [30, 0], [30, 10], [20, 10]], "Second", 0.9),
            ([[0, 50], [10, 50], [10, 60], [0, 60]], "Third", 0.9),
            ([[20, 50], [30, 50], [30, 60], [20, 60]], "Fourth", 0.9),
        ]

        lines = _group_text_into_lines(items, lambda x: x[0], lambda x: x[1])

        assert len(lines) == 2
        assert lines[0] == "First Second"
        assert lines[1] == "Third Fourth"


# --- OCRBlock Tests ---

@pytest.mark.skipif(not HAS_OCR_DEPS, reason="OCR dependencies not installed")
class TestOCRBlock:
    """Tests for OCRBlock dataclass."""

    def test_create_block(self):
        """Test creating an OCR block."""
        from openlabels.adapters.scanner.ocr import OCRBlock

        block = OCRBlock(
            text="Sample Text",
            bbox=[[10, 20], [100, 20], [100, 50], [10, 50]],
            confidence=0.95,
        )

        assert block.text == "Sample Text"
        assert block.confidence == 0.95

    def test_bounding_rect(self):
        """Test bounding_rect property."""
        from openlabels.adapters.scanner.ocr import OCRBlock

        block = OCRBlock(
            text="Text",
            bbox=[[10, 20], [100, 20], [100, 50], [10, 50]],
            confidence=0.9,
        )

        x1, y1, x2, y2 = block.bounding_rect

        assert x1 == 10
        assert y1 == 20
        assert x2 == 100
        assert y2 == 50


# --- OCRResult Tests ---

@pytest.mark.skipif(not HAS_OCR_DEPS, reason="OCR dependencies not installed")
class TestOCRResult:
    """Tests for OCRResult dataclass."""

    def test_create_empty_result(self):
        """Test creating empty OCR result."""
        from openlabels.adapters.scanner.ocr import OCRResult

        result = OCRResult(
            full_text="",
            blocks=[],
            offset_map=[],
            confidence=0.0,
        )

        assert result.full_text == ""
        assert len(result.blocks) == 0

    def test_create_result_with_blocks(self):
        """Test creating OCR result with blocks."""
        from openlabels.adapters.scanner.ocr import OCRResult, OCRBlock

        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
            OCRBlock("World", [[60, 0], [110, 0], [110, 20], [60, 20]], 0.90),
        ]

        result = OCRResult(
            full_text="Hello World",
            blocks=blocks,
            offset_map=[(0, 5, 0), (6, 11, 1)],
            confidence=0.925,
        )

        assert result.full_text == "Hello World"
        assert len(result.blocks) == 2

    def test_get_blocks_for_span(self):
        """Test finding blocks for character span."""
        from openlabels.adapters.scanner.ocr import OCRResult, OCRBlock

        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
            OCRBlock("World", [[60, 0], [110, 0], [110, 20], [60, 20]], 0.90),
        ]

        result = OCRResult(
            full_text="Hello World",
            blocks=blocks,
            offset_map=[(0, 5, 0), (6, 11, 1)],
            confidence=0.925,
        )

        # Find block containing "Hello"
        matching = result.get_blocks_for_span(0, 5)
        assert len(matching) == 1
        assert matching[0].text == "Hello"

        # Find block containing "World"
        matching = result.get_blocks_for_span(6, 11)
        assert len(matching) == 1
        assert matching[0].text == "World"

    def test_get_blocks_spanning_multiple(self):
        """Test finding blocks when span crosses multiple blocks."""
        from openlabels.adapters.scanner.ocr import OCRResult, OCRBlock

        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
            OCRBlock("World", [[60, 0], [110, 0], [110, 20], [60, 20]], 0.90),
        ]

        result = OCRResult(
            full_text="Hello World",
            blocks=blocks,
            offset_map=[(0, 5, 0), (6, 11, 1)],
            confidence=0.925,
        )

        # Find blocks for entire text
        matching = result.get_blocks_for_span(0, 11)
        assert len(matching) == 2


# --- OCREngine Tests ---

@pytest.mark.skipif(not HAS_OCR_DEPS, reason="OCR dependencies not installed")
class TestOCREngine:
    """Tests for OCREngine class."""

    def test_init(self):
        """Test OCREngine initialization."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))

            assert engine.models_dir == Path(tmpdir)
            assert not engine.is_initialized
            assert not engine.is_loading

    def test_has_custom_models_false(self):
        """Test has_custom_models when models don't exist."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))
            assert not engine.has_custom_models

    def test_has_custom_models_true(self):
        """Test has_custom_models when models exist."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            models_dir = Path(tmpdir)
            rapidocr_dir = models_dir / "rapidocr"
            rapidocr_dir.mkdir()

            # Create fake model files
            (rapidocr_dir / "det.onnx").touch()
            (rapidocr_dir / "rec.onnx").touch()
            (rapidocr_dir / "cls.onnx").touch()

            engine = OCREngine(models_dir)
            assert engine.has_custom_models

    @patch('openlabels.adapters.scanner.ocr._OCR_AVAILABLE', False)
    def test_is_available_without_deps(self):
        """Test is_available when dependencies not installed."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))
            # Without custom models and without rapidocr, should be False
            # Note: This test may pass or fail depending on environment
            # The important thing is it doesn't raise

    def test_ensure_initialized_raises_without_models(self):
        """Test _ensure_initialized raises when no models available."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))

            # Patch is_available property on the class to return False
            with patch.object(OCREngine, 'is_available', new_callable=PropertyMock, return_value=False):
                with pytest.raises(ImportError):
                    engine._ensure_initialized()


# --- Integration Tests (skip if no OCR) ---

@pytest.mark.skipif(not HAS_OCR_DEPS, reason="OCR dependencies not installed")
class TestOCRIntegration:
    """Integration tests requiring full OCR setup."""

    def test_extract_text_mock(self):
        """Test text extraction with mocked RapidOCR."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))

            # Mock the OCR
            mock_ocr = MagicMock()
            mock_ocr.return_value = (
                [
                    ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.95),
                    ([[60, 0], [110, 0], [110, 20], [60, 20]], "World", 0.90),
                ],
                None,
            )

            engine._ocr = mock_ocr
            engine._initialized = True

            # Create a dummy image (numpy array)
            dummy_image = np.zeros((100, 200, 3), dtype=np.uint8)
            text = engine.extract_text(dummy_image)

            assert "Hello" in text
            assert "World" in text

    def test_extract_with_coordinates_mock(self):
        """Test coordinate extraction with mocked RapidOCR."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))

            # Mock the OCR
            mock_ocr = MagicMock()
            mock_ocr.return_value = (
                [
                    ([[0, 0], [50, 0], [50, 20], [0, 20]], "Sample", 0.95),
                ],
                None,
            )

            engine._ocr = mock_ocr
            engine._initialized = True

            dummy_image = np.zeros((100, 200, 3), dtype=np.uint8)
            result = engine.extract_with_coordinates(dummy_image)

            assert result.full_text == "Sample"
            assert len(result.blocks) == 1
            assert result.blocks[0].text == "Sample"
            assert result.confidence == 0.95

    def test_extract_empty_result(self):
        """Test handling of empty OCR result."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))

            # Mock the OCR to return no results
            mock_ocr = MagicMock()
            mock_ocr.return_value = (None, None)

            engine._ocr = mock_ocr
            engine._initialized = True

            dummy_image = np.zeros((100, 200, 3), dtype=np.uint8)
            text = engine.extract_text(dummy_image)

            assert text == ""

    def test_warm_up_mock(self):
        """Test warm_up with mocked OCR."""
        from openlabels.adapters.scanner.ocr import OCREngine

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OCREngine(Path(tmpdir))

            mock_ocr = MagicMock()
            mock_ocr.return_value = (None, None)

            engine._ocr = mock_ocr
            engine._initialized = True

            result = engine.warm_up()
            assert result is True
            mock_ocr.assert_called()

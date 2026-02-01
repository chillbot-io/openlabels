"""Tests for the OCR module.

Tests cover:
- clean_ocr_text function (OCR artifact cleanup)
- OCRBlock dataclass (bounding boxes)
- OCRResult dataclass (text-to-coordinate mapping)
- OCREngine initialization and availability checks
"""

import pytest
from pathlib import Path

from openlabels.core.ocr import (
    clean_ocr_text,
    OCRBlock,
    OCRResult,
    OCREngine,
)
from openlabels.core.constants import DEFAULT_MODELS_DIR


# =============================================================================
# CLEAN OCR TEXT TESTS
# =============================================================================

class TestCleanOcrText:
    """Tests for clean_ocr_text function."""

    def test_empty_string(self):
        """Empty string returns empty."""
        assert clean_ocr_text("") == ""

    def test_normal_text_unchanged(self):
        """Normal text is unchanged."""
        text = "Hello World"
        assert clean_ocr_text(text) == "Hello World"

    def test_stuck_field_code_number_uppercase(self):
        """15SEX becomes 15 SEX."""
        assert clean_ocr_text("15SEX") == "15 SEX"

    def test_stuck_field_code_with_lowercase(self):
        """4dDLN becomes 4d DLN."""
        assert clean_ocr_text("4dDLN") == "4d DLN"

    def test_number_stuck_to_uppercase_word(self):
        """18EYES becomes 18 EYES."""
        assert clean_ocr_text("18EYES") == "18 EYES"

    def test_colon_missing_space(self):
        """DOB:01/01/90 becomes DOB: 01/01/90."""
        assert clean_ocr_text("DOB:01/01/90") == "DOB: 01/01/90"

    def test_colon_missing_space_letter(self):
        """SEX:M becomes SEX: M."""
        assert clean_ocr_text("SEX:M") == "SEX: M"

    def test_colon_with_existing_space(self):
        """DOB: 01/01/90 stays unchanged."""
        assert clean_ocr_text("DOB: 01/01/90") == "DOB: 01/01/90"

    def test_multiple_issues(self):
        """Multiple OCR issues in one string are all fixed."""
        text = "15SEX:M DOB:01/01/90 4dDLN"
        expected = "15 SEX: M DOB: 01/01/90 4d DLN"
        assert clean_ocr_text(text) == expected

    def test_single_uppercase_not_matched(self):
        """Single uppercase letter after digit doesn't add space (e.g., 5A)."""
        # Pattern requires 2+ uppercase letters
        assert clean_ocr_text("5A") == "5A"

    def test_preserves_normal_colons(self):
        """Colons with spaces are preserved."""
        text = "Name: John Smith"
        assert clean_ocr_text(text) == "Name: John Smith"

    def test_url_handling(self):
        """URLs with colons get spaces (may be undesirable but consistent)."""
        # Note: This is current behavior, may need refinement
        text = "http:example.com"
        result = clean_ocr_text(text)
        assert ": " in result  # Colon gets space


# =============================================================================
# OCR BLOCK TESTS
# =============================================================================

class TestOCRBlock:
    """Tests for OCRBlock dataclass."""

    def test_create_block(self):
        """Block can be created with required fields."""
        block = OCRBlock(
            text="Hello",
            bbox=[[0, 0], [100, 0], [100, 20], [0, 20]],
            confidence=0.95,
        )
        assert block.text == "Hello"
        assert block.confidence == 0.95
        assert len(block.bbox) == 4

    def test_bounding_rect_simple(self):
        """bounding_rect returns axis-aligned rectangle."""
        block = OCRBlock(
            text="Test",
            bbox=[[10, 5], [110, 5], [110, 25], [10, 25]],
            confidence=0.90,
        )
        # (x1, y1, x2, y2) = (min_x, min_y, max_x, max_y)
        assert block.bounding_rect == (10, 5, 110, 25)

    def test_bounding_rect_rotated(self):
        """bounding_rect handles rotated quadrilaterals."""
        # Slightly rotated box
        block = OCRBlock(
            text="Rotated",
            bbox=[[5, 10], [105, 5], [110, 25], [10, 30]],
            confidence=0.85,
        )
        rect = block.bounding_rect
        # min_x=5, min_y=5, max_x=110, max_y=30
        assert rect == (5, 5, 110, 30)

    def test_bounding_rect_returns_integers(self):
        """bounding_rect returns integer coordinates."""
        block = OCRBlock(
            text="Float",
            bbox=[[10.5, 5.3], [100.7, 5.8], [100.2, 25.1], [10.9, 24.6]],
            confidence=0.88,
        )
        rect = block.bounding_rect
        assert all(isinstance(v, int) for v in rect)


# =============================================================================
# OCR RESULT TESTS
# =============================================================================

class TestOCRResult:
    """Tests for OCRResult dataclass."""

    def test_empty_result(self):
        """Empty result can be created."""
        result = OCRResult(
            full_text="",
            blocks=[],
            offset_map=[],
            confidence=0.0,
        )
        assert result.full_text == ""
        assert result.blocks == []
        assert result.confidence == 0.0

    def test_single_block_result(self):
        """Result with single block."""
        block = OCRBlock(
            text="Hello",
            bbox=[[0, 0], [50, 0], [50, 20], [0, 20]],
            confidence=0.95,
        )
        result = OCRResult(
            full_text="Hello",
            blocks=[block],
            offset_map=[(0, 5, 0)],
            confidence=0.95,
        )
        assert len(result.blocks) == 1
        assert result.full_text == "Hello"

    def test_multi_block_result(self):
        """Result with multiple blocks."""
        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
            OCRBlock("World", [[60, 0], [110, 0], [110, 20], [60, 20]], 0.92),
        ]
        result = OCRResult(
            full_text="Hello World",
            blocks=blocks,
            offset_map=[(0, 5, 0), (6, 11, 1)],
            confidence=0.935,
        )
        assert len(result.blocks) == 2

    def test_get_blocks_for_span_single(self):
        """get_blocks_for_span finds overlapping block."""
        block = OCRBlock("123-45-6789", [[0, 0], [100, 0], [100, 20], [0, 20]], 0.90)
        result = OCRResult(
            full_text="SSN: 123-45-6789",
            blocks=[block],
            offset_map=[(5, 16, 0)],  # "123-45-6789" starts at char 5
            confidence=0.90,
        )

        # Find blocks for the SSN span
        found = result.get_blocks_for_span(5, 16)
        assert len(found) == 1
        assert found[0].text == "123-45-6789"

    def test_get_blocks_for_span_partial_overlap(self):
        """get_blocks_for_span handles partial overlaps."""
        blocks = [
            OCRBlock("John", [[0, 0], [40, 0], [40, 20], [0, 20]], 0.95),
            OCRBlock("Smith", [[50, 0], [100, 0], [100, 20], [50, 20]], 0.93),
        ]
        result = OCRResult(
            full_text="John Smith",
            blocks=blocks,
            offset_map=[(0, 4, 0), (5, 10, 1)],
            confidence=0.94,
        )

        # Find blocks for "n Sm" (partial overlap with both)
        found = result.get_blocks_for_span(3, 7)
        assert len(found) == 2

    def test_get_blocks_for_span_no_overlap(self):
        """get_blocks_for_span returns empty for non-overlapping span."""
        block = OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95)
        result = OCRResult(
            full_text="Hello",
            blocks=[block],
            offset_map=[(0, 5, 0)],
            confidence=0.95,
        )

        # Find blocks for span after the text
        found = result.get_blocks_for_span(10, 15)
        assert len(found) == 0

    def test_get_blocks_for_span_empty_result(self):
        """get_blocks_for_span on empty result returns empty."""
        result = OCRResult(
            full_text="",
            blocks=[],
            offset_map=[],
            confidence=0.0,
        )
        found = result.get_blocks_for_span(0, 5)
        assert found == []


# =============================================================================
# OCR ENGINE TESTS
# =============================================================================

class TestOCREngine:
    """Tests for OCREngine class."""

    def test_default_models_dir(self):
        """Engine uses default models directory."""
        engine = OCREngine()
        assert engine.models_dir == DEFAULT_MODELS_DIR

    def test_custom_models_dir(self):
        """Engine accepts custom models directory."""
        custom_dir = Path("/custom/models")
        engine = OCREngine(models_dir=custom_dir)
        assert engine.models_dir == custom_dir
        assert engine.rapidocr_dir == custom_dir / "rapidocr"

    def test_has_custom_models_false(self):
        """has_custom_models returns False when models don't exist."""
        # Use a non-existent directory
        engine = OCREngine(models_dir=Path("/nonexistent/path"))
        assert engine.has_custom_models is False

    def test_initial_state(self):
        """Engine starts uninitialized."""
        engine = OCREngine()
        assert engine.is_initialized is False
        assert engine.is_loading is False

    def test_is_available_checks_package(self):
        """is_available checks for rapidocr-onnxruntime package."""
        engine = OCREngine(models_dir=Path("/nonexistent/path"))
        # Will be True if rapidocr-onnxruntime is installed, False otherwise
        # We just check it returns a boolean
        assert isinstance(engine.is_available, bool)

    def test_start_loading_idempotent(self):
        """start_loading can be called multiple times safely."""
        engine = OCREngine()
        engine.start_loading()
        engine.start_loading()  # Should not raise
        # Loading state should be set
        # (actual loading may fail if package not installed, but that's OK)

    def test_extract_text_requires_initialization(self):
        """extract_text raises if rapidocr not available."""
        engine = OCREngine(models_dir=Path("/nonexistent/models"))

        if not engine.is_available:
            with pytest.raises(ImportError):
                engine.extract_text("dummy")


# =============================================================================
# INTEGRATION TESTS (require rapidocr-onnxruntime)
# =============================================================================

class TestOCREngineIntegration:
    """Integration tests that require rapidocr-onnxruntime installed."""

    @pytest.fixture
    def ocr_engine(self):
        """Create OCR engine for testing."""
        engine = OCREngine()
        if not engine.is_available:
            pytest.skip("rapidocr-onnxruntime not installed")
        return engine

    def test_extract_empty_image(self, ocr_engine):
        """Extracting from blank image returns empty string."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")

        # Create blank white image
        blank = np.ones((100, 100, 3), dtype=np.uint8) * 255

        result = ocr_engine.extract_text(blank)
        assert result == ""

    def test_extract_with_confidence(self, ocr_engine):
        """extract_text_with_confidence returns tuple."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")

        # Create blank image
        blank = np.ones((100, 100, 3), dtype=np.uint8) * 255

        text, confidence = ocr_engine.extract_text_with_confidence(blank)
        assert isinstance(text, str)
        assert isinstance(confidence, float)

    def test_extract_with_coordinates_empty(self, ocr_engine):
        """extract_with_coordinates returns OCRResult."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")

        # Create blank image
        blank = np.ones((100, 100, 3), dtype=np.uint8) * 255

        result = ocr_engine.extract_with_coordinates(blank)
        assert isinstance(result, OCRResult)
        assert result.full_text == ""
        assert result.blocks == []

    def test_warm_up(self, ocr_engine):
        """warm_up runs without error."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")

        result = ocr_engine.warm_up()
        assert isinstance(result, bool)

    def test_await_ready_timeout(self):
        """await_ready respects timeout."""
        engine = OCREngine()
        if not engine.is_available:
            pytest.skip("rapidocr-onnxruntime not installed")

        # Should complete or timeout (both are valid behaviors)
        result = engine.await_ready(timeout=5.0)
        assert isinstance(result, bool)


# =============================================================================
# PROCESSOR INTEGRATION TESTS
# =============================================================================

class TestProcessorOCRIntegration:
    """Tests for OCR integration in FileProcessor."""

    def test_processor_creates_ocr_engine(self):
        """FileProcessor creates OCR engine when enabled."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ocr=True)
        # OCR engine is created if rapidocr is available
        # Either _ocr_engine is set or it's None (if not available)
        assert hasattr(processor, '_ocr_engine')

    def test_processor_disables_ocr(self):
        """FileProcessor doesn't create OCR engine when disabled."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ocr=False)
        assert processor._ocr_engine is None

    def test_can_process_images(self):
        """FileProcessor can process image files."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor()

        # Should recognize image extensions
        assert processor.can_process("test.png", 1000)
        assert processor.can_process("test.jpg", 1000)
        assert processor.can_process("test.jpeg", 1000)
        assert processor.can_process("test.tiff", 1000)

    def test_can_process_respects_size_limit(self):
        """FileProcessor respects max file size for images."""
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(max_file_size=1000)

        # Small image: OK
        assert processor.can_process("test.png", 500)

        # Large image: rejected
        assert not processor.can_process("test.png", 2000)

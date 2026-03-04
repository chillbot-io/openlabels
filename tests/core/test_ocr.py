"""Tests for the OCR module.

Tests cover:
- clean_ocr_text function (OCR artifact cleanup)
- OCRBlock dataclass (bounding boxes)
- OCRResult dataclass (text-to-coordinate mapping)
- OCREngine initialization, warm-up, background loading
- OCREngine extract_text / extract_text_with_confidence / extract_with_coordinates (mocked)
- IntervalTree fallback in OCRResult
- Fallback behavior when OCR libraries unavailable
"""

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from openlabels.core.constants import DEFAULT_MODELS_DIR
from openlabels.core.ocr import (
    OCRBlock,
    OCREngine,
    OCRResult,
    clean_ocr_text,
)

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

    def test_extract_with_confidence_blank_image(self, ocr_engine):
        """extract_text_with_confidence on blank image returns empty text and valid confidence."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")

        # Create blank image
        blank = np.ones((100, 100, 3), dtype=np.uint8) * 255

        text, confidence = ocr_engine.extract_text_with_confidence(blank)
        # Blank image should produce empty or whitespace-only text
        assert text.strip() == ""
        # Confidence should be between 0.0 and 1.0
        assert 0.0 <= confidence <= 1.0

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



# =============================================================================
# PROCESSOR INTEGRATION TESTS
# =============================================================================

class TestProcessorOCRIntegration:
    """Tests for OCR integration in FileProcessor."""

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


# =============================================================================
# OCR RESULT INTERVAL TREE FALLBACK TESTS
# =============================================================================

class TestOCRResultLinearFallback:
    """Tests for OCRResult.get_blocks_for_span linear fallback (no IntervalTree)."""

    def test_linear_fallback_when_no_interval_tree(self):
        """When IntervalTree is None, linear search is used."""
        block = OCRBlock("hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.90)
        result = OCRResult(
            full_text="hello",
            blocks=[block],
            offset_map=[(0, 5, 0)],
            confidence=0.90,
        )
        # Force linear fallback
        result._interval_tree = None

        found = result.get_blocks_for_span(0, 5)
        assert len(found) == 1
        assert found[0].text == "hello"

    def test_linear_fallback_no_overlap(self):
        """Linear fallback returns empty when no overlap."""
        block = OCRBlock("hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.90)
        result = OCRResult(
            full_text="hello",
            blocks=[block],
            offset_map=[(0, 5, 0)],
            confidence=0.90,
        )
        result._interval_tree = None

        found = result.get_blocks_for_span(10, 15)
        assert len(found) == 0

    def test_linear_fallback_partial_overlap(self):
        """Linear fallback correctly handles partial overlaps."""
        blocks = [
            OCRBlock("AAA", [[0, 0], [30, 0], [30, 20], [0, 20]], 0.90),
            OCRBlock("BBB", [[40, 0], [70, 0], [70, 20], [40, 20]], 0.90),
            OCRBlock("CCC", [[80, 0], [110, 0], [110, 20], [80, 20]], 0.90),
        ]
        result = OCRResult(
            full_text="AAA BBB CCC",
            blocks=blocks,
            offset_map=[(0, 3, 0), (4, 7, 1), (8, 11, 2)],
            confidence=0.90,
        )
        result._interval_tree = None

        # Overlap with second and third block
        found = result.get_blocks_for_span(5, 10)
        assert len(found) == 2
        texts = {b.text for b in found}
        assert texts == {"BBB", "CCC"}

    def test_interval_tree_built_on_construction(self):
        """IntervalTree is built during __post_init__ when available."""
        block = OCRBlock("test", [[0, 0], [40, 0], [40, 20], [0, 20]], 0.90)
        result = OCRResult(
            full_text="test",
            blocks=[block],
            offset_map=[(0, 4, 0)],
            confidence=0.90,
        )
        # IntervalTree should be set if the library is available
        try:
            from intervaltree import IntervalTree  # noqa: F401
            assert result._interval_tree is not None
        except ImportError:
            assert result._interval_tree is None


# =============================================================================
# OCR ENGINE MOCKED TESTS
# =============================================================================

class TestOCREngineMocked:
    """Tests for OCREngine using mocked RapidOCR."""

    def _make_engine_with_mock_ocr(self):
        """Create an OCREngine with a mocked RapidOCR instance."""
        engine = OCREngine(models_dir=Path("/fake/models"))
        mock_ocr = MagicMock()
        engine._ocr = mock_ocr
        engine._initialized = True
        return engine, mock_ocr

    def test_extract_text_no_result(self):
        """extract_text returns empty string when OCR finds nothing."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (None, None)

        result = engine.extract_text("fake_image")
        assert result == ""

    def test_extract_text_single_block(self):
        """extract_text returns text from a single OCR block."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        # RapidOCR returns: [(bbox, text, confidence), ...]
        mock_ocr.return_value = (
            [([[0, 0], [100, 0], [100, 20], [0, 20]], "Hello World", 0.95)],
            None,
        )

        result = engine.extract_text("fake_image")
        assert "Hello World" in result

    def test_extract_text_multiple_blocks_same_line(self):
        """Blocks on the same line are joined by spaces."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (
            [
                ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.95),
                ([[60, 0], [120, 0], [120, 20], [60, 20]], "World", 0.93),
            ],
            None,
        )

        result = engine.extract_text("fake_image")
        assert "Hello" in result
        assert "World" in result

    def test_extract_text_multiple_lines(self):
        """Blocks on different lines are joined by newlines."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (
            [
                ([[0, 0], [100, 0], [100, 20], [0, 20]], "Line One", 0.95),
                ([[0, 100], [100, 100], [100, 120], [0, 120]], "Line Two", 0.90),
            ],
            None,
        )

        result = engine.extract_text("fake_image")
        assert "Line One" in result
        assert "Line Two" in result
        assert "\n" in result

    def test_extract_text_applies_clean_ocr_text(self):
        """extract_text applies clean_ocr_text to the output."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (
            [([[0, 0], [100, 0], [100, 20], [0, 20]], "15SEX:M", 0.90)],
            None,
        )

        result = engine.extract_text("fake_image")
        # clean_ocr_text should fix "15SEX:M" -> "15 SEX: M"
        assert "15 SEX: M" in result

    def test_extract_text_path_converted_to_string(self):
        """Path objects are converted to strings before passing to RapidOCR."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (None, None)

        engine.extract_text(Path("/some/image.png"))
        # Verify it was called with a string, not a Path
        call_args = mock_ocr.call_args[0][0]
        assert isinstance(call_args, str)

    def test_extract_text_with_confidence_no_result(self):
        """extract_text_with_confidence returns empty text and 0.0 confidence for no results."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (None, None)

        text, confidence = engine.extract_text_with_confidence("fake_image")
        assert text == ""
        assert confidence == 0.0

    def test_extract_text_with_confidence_returns_average(self):
        """extract_text_with_confidence returns average of block confidences."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (
            [
                ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.80),
                ([[60, 0], [120, 0], [120, 20], [60, 20]], "World", 0.90),
            ],
            None,
        )

        text, confidence = engine.extract_text_with_confidence("fake_image")
        assert "Hello" in text
        assert "World" in text
        assert abs(confidence - 0.85) < 0.01  # Average of 0.80 and 0.90

    def test_extract_with_coordinates_no_result(self):
        """extract_with_coordinates returns empty OCRResult for no results."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (None, None)

        result = engine.extract_with_coordinates("fake_image")
        assert isinstance(result, OCRResult)
        assert result.full_text == ""
        assert result.blocks == []
        assert result.offset_map == []
        assert result.confidence == 0.0

    def test_extract_with_coordinates_builds_offset_map(self):
        """extract_with_coordinates builds a correct offset map."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (
            [
                ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.95),
                ([[60, 0], [120, 0], [120, 20], [60, 20]], "World", 0.93),
            ],
            None,
        )

        result = engine.extract_with_coordinates("fake_image")
        assert isinstance(result, OCRResult)
        assert len(result.blocks) == 2
        assert result.blocks[0].text == "Hello"
        assert result.blocks[1].text == "World"
        # Offset map should have 2 entries
        assert len(result.offset_map) == 2
        # First block starts at 0
        assert result.offset_map[0][0] == 0
        assert result.offset_map[0][1] == 5  # len("Hello")
        # Average confidence
        assert abs(result.confidence - 0.94) < 0.01

    def test_extract_with_coordinates_multiline(self):
        """extract_with_coordinates handles multi-line text."""
        engine, mock_ocr = self._make_engine_with_mock_ocr()
        mock_ocr.return_value = (
            [
                ([[0, 0], [50, 0], [50, 20], [0, 20]], "Line1", 0.95),
                ([[0, 100], [50, 100], [50, 120], [0, 120]], "Line2", 0.90),
            ],
            None,
        )

        result = engine.extract_with_coordinates("fake_image")
        assert "\n" in result.full_text
        assert "Line1" in result.full_text
        assert "Line2" in result.full_text


class TestOCREngineWarmUp:
    """Tests for OCR engine warm-up behavior."""

    def test_warm_up_no_numpy(self):
        """warm_up returns False when numpy not available."""
        engine = OCREngine(models_dir=Path("/fake"))
        with patch("openlabels.core.ocr.np", None):
            result = engine.warm_up()
        assert result is False

    def test_warm_up_success(self):
        """warm_up returns True when engine initializes and runs dummy inference."""
        engine = OCREngine(models_dir=Path("/fake"))
        mock_ocr = MagicMock()
        engine._ocr = mock_ocr
        engine._initialized = True
        mock_ocr.return_value = (None, None)

        result = engine.warm_up()
        assert result is True
        # Should have been called with a tiny numpy array
        mock_ocr.assert_called_once()

    def test_warm_up_failure_returns_false(self):
        """warm_up returns False if inference fails."""
        engine = OCREngine(models_dir=Path("/fake"))
        mock_ocr = MagicMock()
        mock_ocr.side_effect = RuntimeError("inference failed")
        engine._ocr = mock_ocr
        engine._initialized = True

        result = engine.warm_up()
        assert result is False


class TestOCREngineBackgroundLoading:
    """Tests for OCR engine background loading."""

    def test_start_loading_sets_loading_flag(self):
        """start_loading sets _loading flag and starts background thread."""
        engine = OCREngine(models_dir=Path("/fake"))

        # Mock _ensure_initialized to avoid actual initialization
        # and warm_up to be a no-op
        with patch.object(engine, '_ensure_initialized'), \
             patch.object(engine, 'warm_up'):
            engine.start_loading()
            # Wait for the thread to complete
            engine._ready_event.wait(timeout=5)

        assert engine._loading is True

    def test_start_loading_idempotent(self):
        """Calling start_loading twice doesn't start two threads."""
        engine = OCREngine(models_dir=Path("/fake"))
        engine._initialized = True  # Prevent actual loading

        with patch.object(engine, '_ensure_initialized'), \
             patch.object(engine, 'warm_up'):
            engine.start_loading()
            engine._ready_event.wait(timeout=5)
            engine.start_loading()  # Should be a no-op

    def test_await_ready_when_already_initialized(self):
        """await_ready returns True immediately when already initialized."""
        engine = OCREngine(models_dir=Path("/fake"))
        engine._initialized = True

        result = engine.await_ready(timeout=1.0)
        assert result is True

    def test_await_ready_starts_loading_if_not_started(self):
        """await_ready starts loading if not already started."""
        engine = OCREngine(models_dir=Path("/fake"))

        with patch.object(engine, '_ensure_initialized'), \
             patch.object(engine, 'warm_up'):
            result = engine.await_ready(timeout=5.0)

        assert result is True

    def test_await_ready_propagates_load_error(self):
        """await_ready re-raises errors from background loading."""
        engine = OCREngine(models_dir=Path("/fake"))
        engine._load_error = ImportError("rapidocr not found")
        engine._ready_event.set()
        engine._loading = True

        with pytest.raises(ImportError, match="rapidocr not found"):
            engine.await_ready(timeout=1.0)

    def test_is_loading_property(self):
        """is_loading is True while loading and False after."""
        engine = OCREngine(models_dir=Path("/fake"))
        engine._loading = True
        engine._initialized = False
        assert engine.is_loading is True

        engine._initialized = True
        assert engine.is_loading is False


class TestOCREngineAvailability:
    """Tests for OCR engine availability checks."""

    def test_is_available_with_custom_models(self, tmp_path):
        """is_available returns True when custom model files exist."""
        rapidocr_dir = tmp_path / "rapidocr"
        rapidocr_dir.mkdir()
        (rapidocr_dir / "det.onnx").write_bytes(b"fake")
        (rapidocr_dir / "rec.onnx").write_bytes(b"fake")
        (rapidocr_dir / "cls.onnx").write_bytes(b"fake")

        engine = OCREngine(models_dir=tmp_path)
        assert engine.has_custom_models is True
        assert engine.is_available is True

    def test_has_custom_models_partial(self, tmp_path):
        """has_custom_models returns False when only some models present."""
        rapidocr_dir = tmp_path / "rapidocr"
        rapidocr_dir.mkdir()
        (rapidocr_dir / "det.onnx").write_bytes(b"fake")
        # Missing rec.onnx and cls.onnx

        engine = OCREngine(models_dir=tmp_path)
        assert engine.has_custom_models is False

    def test_ensure_initialized_raises_when_not_available(self):
        """_ensure_initialized raises ImportError when OCR not available."""
        engine = OCREngine(models_dir=Path("/nonexistent"))

        with patch.object(type(engine), 'is_available', new_callable=PropertyMock, return_value=False):
            with pytest.raises(ImportError, match="OCR engine not available"):
                engine._ensure_initialized()

    def test_ensure_initialized_skips_when_already_loaded(self):
        """_ensure_initialized does nothing if _ocr already set."""
        engine = OCREngine(models_dir=Path("/fake"))
        engine._ocr = MagicMock()

        # Should not raise even though models don't exist
        engine._ensure_initialized()

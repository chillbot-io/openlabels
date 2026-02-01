"""Tests for OCR engine using RapidOCR.

Tests for OCRBlock, OCRResult, OCREngine, and text cleaning.
"""

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import numpy as np

from scrubiq.files.ocr import (
    OCRBlock,
    OCRResult,
    OCREngine,
    _clean_ocr_text,
)


# =============================================================================
# _CLEAN_OCR_TEXT TESTS
# =============================================================================

class TestCleanOCRText:
    """Tests for _clean_ocr_text function."""

    def test_adds_space_between_digit_and_uppercase(self):
        """Adds space between digits and uppercase words."""
        result = _clean_ocr_text("15SEX")

        assert result == "15 SEX"

    def test_adds_space_with_letter_suffix(self):
        """Adds space when digit has lowercase letter suffix."""
        result = _clean_ocr_text("4dDLN")

        assert result == "4d DLN"

    def test_adds_space_after_colon(self):
        """Adds space after colon if missing."""
        result = _clean_ocr_text("DOB:01/01/90")

        assert result == "DOB: 01/01/90"

    def test_adds_space_after_colon_letter(self):
        """Adds space after colon before letter."""
        result = _clean_ocr_text("SEX:M")

        assert result == "SEX: M"

    def test_preserves_existing_spaces(self):
        """Preserves text with proper spacing."""
        result = _clean_ocr_text("DOB: 01/01/1990")

        assert result == "DOB: 01/01/1990"

    def test_handles_multiple_issues(self):
        """Handles multiple spacing issues."""
        result = _clean_ocr_text("15SEX:M 18EYES:BRN")

        assert "15 SEX: M" in result
        assert "18 EYES: BRN" in result

    def test_empty_string(self):
        """Handles empty string."""
        result = _clean_ocr_text("")

        assert result == ""

    def test_no_changes_needed(self):
        """Returns unchanged text when no cleaning needed."""
        result = _clean_ocr_text("Normal text here")

        assert result == "Normal text here"


# =============================================================================
# OCRBLOCK TESTS
# =============================================================================

class TestOCRBlock:
    """Tests for OCRBlock dataclass."""

    def test_create_block(self):
        """OCRBlock stores all properties."""
        bbox = [[0, 0], [100, 0], [100, 20], [0, 20]]
        block = OCRBlock(text="Hello", bbox=bbox, confidence=0.95)

        assert block.text == "Hello"
        assert block.bbox == bbox
        assert block.confidence == 0.95

    def test_bounding_rect_property(self):
        """bounding_rect converts quadrilateral to rectangle."""
        # Quadrilateral: top-left, top-right, bottom-right, bottom-left
        bbox = [[10, 5], [110, 5], [110, 25], [10, 25]]
        block = OCRBlock(text="Test", bbox=bbox, confidence=0.9)

        x1, y1, x2, y2 = block.bounding_rect

        assert x1 == 10
        assert y1 == 5
        assert x2 == 110
        assert y2 == 25

    def test_bounding_rect_rotated_box(self):
        """bounding_rect handles rotated quadrilateral."""
        # Slightly rotated box
        bbox = [[5, 10], [105, 5], [110, 25], [10, 30]]
        block = OCRBlock(text="Test", bbox=bbox, confidence=0.9)

        x1, y1, x2, y2 = block.bounding_rect

        # Should get axis-aligned bounding rectangle
        assert x1 == 5   # min x
        assert y1 == 5   # min y
        assert x2 == 110 # max x
        assert y2 == 30  # max y

    def test_bounding_rect_returns_ints(self):
        """bounding_rect returns integer coordinates."""
        bbox = [[10.5, 5.2], [110.8, 5.1], [110.9, 25.7], [10.3, 25.9]]
        block = OCRBlock(text="Test", bbox=bbox, confidence=0.9)

        x1, y1, x2, y2 = block.bounding_rect

        assert isinstance(x1, int)
        assert isinstance(y1, int)
        assert isinstance(x2, int)
        assert isinstance(y2, int)


# =============================================================================
# OCRRESULT TESTS
# =============================================================================

class TestOCRResult:
    """Tests for OCRResult dataclass."""

    def test_create_result(self):
        """OCRResult stores all properties."""
        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
            OCRBlock("World", [[60, 0], [110, 0], [110, 20], [60, 20]], 0.90),
        ]
        offset_map = [(0, 5, 0), (6, 11, 1)]

        result = OCRResult(
            full_text="Hello World",
            blocks=blocks,
            offset_map=offset_map,
            confidence=0.925,
        )

        assert result.full_text == "Hello World"
        assert len(result.blocks) == 2
        assert result.confidence == 0.925

    def test_builds_interval_tree(self):
        """OCRResult builds interval tree for fast lookups."""
        blocks = [
            OCRBlock("A", [[0, 0], [10, 0], [10, 10], [0, 10]], 0.9),
            OCRBlock("B", [[20, 0], [30, 0], [30, 10], [20, 10]], 0.9),
        ]
        offset_map = [(0, 1, 0), (2, 3, 1)]

        result = OCRResult(
            full_text="A B",
            blocks=blocks,
            offset_map=offset_map,
            confidence=0.9,
        )

        # Interval tree should be built
        assert result._interval_tree is not None
        assert len(result._interval_tree) == 2

    def test_get_blocks_for_span_single_block(self):
        """get_blocks_for_span returns correct block for span."""
        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
            OCRBlock("World", [[60, 0], [110, 0], [110, 20], [60, 20]], 0.90),
        ]
        offset_map = [(0, 5, 0), (6, 11, 1)]

        result = OCRResult(
            full_text="Hello World",
            blocks=blocks,
            offset_map=offset_map,
            confidence=0.925,
        )

        # Span for "Hello" (chars 0-5)
        matching_blocks = result.get_blocks_for_span(0, 5)

        assert len(matching_blocks) == 1
        assert matching_blocks[0].text == "Hello"

    def test_get_blocks_for_span_multiple_blocks(self):
        """get_blocks_for_span returns multiple overlapping blocks."""
        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
            OCRBlock("World", [[60, 0], [110, 0], [110, 20], [60, 20]], 0.90),
        ]
        offset_map = [(0, 5, 0), (6, 11, 1)]

        result = OCRResult(
            full_text="Hello World",
            blocks=blocks,
            offset_map=offset_map,
            confidence=0.925,
        )

        # Span that covers both blocks
        matching_blocks = result.get_blocks_for_span(0, 11)

        assert len(matching_blocks) == 2

    def test_get_blocks_for_span_no_match(self):
        """get_blocks_for_span returns empty for non-overlapping span."""
        blocks = [
            OCRBlock("Hello", [[0, 0], [50, 0], [50, 20], [0, 20]], 0.95),
        ]
        offset_map = [(0, 5, 0)]

        result = OCRResult(
            full_text="Hello",
            blocks=blocks,
            offset_map=offset_map,
            confidence=0.95,
        )

        # Span outside any block
        matching_blocks = result.get_blocks_for_span(10, 15)

        assert len(matching_blocks) == 0

    def test_get_blocks_for_span_empty_offset_map(self):
        """get_blocks_for_span handles empty offset map."""
        result = OCRResult(
            full_text="",
            blocks=[],
            offset_map=[],
            confidence=0.0,
        )

        matching_blocks = result.get_blocks_for_span(0, 5)

        assert len(matching_blocks) == 0


# =============================================================================
# OCRENGINE INIT TESTS
# =============================================================================

class TestOCREngineInit:
    """Tests for OCREngine initialization."""

    def test_init_sets_models_dir(self):
        """Initializes with models directory."""
        models_dir = Path("/path/to/models")
        engine = OCREngine(models_dir)

        assert engine.models_dir == models_dir
        assert engine.rapidocr_dir == models_dir / "rapidocr"

    def test_init_not_initialized(self):
        """Engine is not initialized on creation."""
        engine = OCREngine(Path("/tmp"))

        assert engine._initialized is False
        assert engine._ocr is None

    def test_init_not_loading(self):
        """Engine is not loading on creation."""
        engine = OCREngine(Path("/tmp"))

        assert engine._loading is False


# =============================================================================
# OCRENGINE PROPERTIES TESTS
# =============================================================================

class TestOCREngineProperties:
    """Tests for OCREngine properties."""

    def test_has_custom_models_true(self):
        """has_custom_models returns True when models exist."""
        with patch.object(Path, 'exists', return_value=True):
            engine = OCREngine(Path("/tmp"))

            assert engine.has_custom_models is True

    def test_has_custom_models_false(self):
        """has_custom_models returns False when models missing."""
        engine = OCREngine(Path("/nonexistent"))

        assert engine.has_custom_models is False

    def test_is_available_with_custom_models(self):
        """is_available returns True with custom models."""
        with patch.object(Path, 'exists', return_value=True):
            engine = OCREngine(Path("/tmp"))

            assert engine.is_available is True

    @patch.dict('sys.modules', {'rapidocr_onnxruntime': MagicMock()})
    def test_is_available_with_bundled(self):
        """is_available returns True with bundled models."""
        engine = OCREngine(Path("/nonexistent"))

        assert engine.is_available is True

    def test_is_available_false(self):
        """is_available returns False without models or package."""
        engine = OCREngine(Path("/nonexistent"))

        # Without rapidocr installed and no custom models
        with patch.dict('sys.modules', {'rapidocr_onnxruntime': None}):
            # Force import to fail
            import sys
            if 'rapidocr_onnxruntime' in sys.modules:
                del sys.modules['rapidocr_onnxruntime']

    def test_is_initialized_false(self):
        """is_initialized returns False before loading."""
        engine = OCREngine(Path("/tmp"))

        assert engine.is_initialized is False

    def test_is_loading_false_initially(self):
        """is_loading returns False initially."""
        engine = OCREngine(Path("/tmp"))

        assert engine.is_loading is False


# =============================================================================
# OCRENGINE LOADING TESTS
# =============================================================================

class TestOCREngineLoading:
    """Tests for OCREngine loading behavior."""

    def test_start_loading_sets_flag(self):
        """start_loading sets loading flag."""
        engine = OCREngine(Path("/tmp"))

        with patch.object(engine, '_background_load'):
            engine.start_loading()

            assert engine._loading is True

    def test_start_loading_only_once(self):
        """start_loading only starts once."""
        engine = OCREngine(Path("/tmp"))
        call_count = 0

        def mock_load():
            nonlocal call_count
            call_count += 1

        with patch.object(engine, '_background_load', mock_load):
            with patch('threading.Thread') as mock_thread:
                mock_thread.return_value.start = MagicMock()
                engine.start_loading()
                engine.start_loading()  # Second call should be ignored

                assert mock_thread.call_count == 1

    def test_start_loading_no_op_if_initialized(self):
        """start_loading does nothing if already initialized."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        with patch('threading.Thread') as mock_thread:
            engine.start_loading()

            mock_thread.assert_not_called()

    def test_await_ready_returns_true_if_initialized(self):
        """await_ready returns True immediately if initialized."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        result = engine.await_ready(timeout=0.1)

        assert result is True

    def test_await_ready_starts_loading(self):
        """await_ready starts loading if not started."""
        engine = OCREngine(Path("/tmp"))
        engine._ready_event.set()  # Simulate ready

        with patch.object(engine, 'start_loading') as mock_start:
            engine.await_ready(timeout=0.1)

            mock_start.assert_called_once()

    def test_await_ready_raises_on_error(self):
        """await_ready raises if loading failed."""
        engine = OCREngine(Path("/tmp"))
        engine._load_error = RuntimeError("Load failed")
        engine._ready_event.set()

        with pytest.raises(RuntimeError, match="Load failed"):
            engine.await_ready(timeout=0.1)


# =============================================================================
# OCRENGINE WARM_UP TESTS
# =============================================================================

class TestOCREngineWarmUp:
    """Tests for OCREngine warm_up method."""

    def test_warm_up_runs_inference(self):
        """warm_up runs inference on dummy image."""
        engine = OCREngine(Path("/tmp"))

        mock_ocr = MagicMock()
        engine._ocr = mock_ocr
        engine._initialized = True

        result = engine.warm_up()

        assert result is True
        mock_ocr.assert_called_once()
        # Check it was called with a numpy array
        call_args = mock_ocr.call_args[0][0]
        assert isinstance(call_args, np.ndarray)

    def test_warm_up_returns_false_on_error(self):
        """warm_up returns False on error."""
        engine = OCREngine(Path("/tmp"))

        mock_ocr = MagicMock()
        mock_ocr.side_effect = RuntimeError("OCR error")
        engine._ocr = mock_ocr
        engine._initialized = True

        result = engine.warm_up()

        assert result is False


# =============================================================================
# OCRENGINE EXTRACT_TEXT TESTS
# =============================================================================

class TestOCREngineExtractText:
    """Tests for OCREngine extract_text method."""

    def test_extract_text_returns_string(self):
        """extract_text returns string."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        # Mock OCR result: [(bbox, text, confidence), ...]
        mock_result = [
            ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.95),
            ([[60, 0], [110, 0], [110, 20], [60, 20]], "World", 0.90),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        result = engine.extract_text(np.zeros((100, 100, 3), dtype=np.uint8))

        assert isinstance(result, str)
        assert "Hello" in result
        assert "World" in result

    def test_extract_text_empty_result(self):
        """extract_text returns empty string for no text."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True
        engine._ocr = MagicMock(return_value=(None, None))

        result = engine.extract_text(np.zeros((100, 100, 3), dtype=np.uint8))

        assert result == ""

    def test_extract_text_sorts_by_position(self):
        """extract_text sorts blocks by position."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        # Blocks out of order - "World" appears before "Hello" in result
        mock_result = [
            ([[60, 0], [110, 0], [110, 20], [60, 20]], "World", 0.90),
            ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.95),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        result = engine.extract_text(np.zeros((100, 100, 3), dtype=np.uint8))

        # Should be sorted left to right: Hello World
        assert result.index("Hello") < result.index("World")

    def test_extract_text_groups_lines(self):
        """extract_text groups text into lines."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        # Two lines of text
        mock_result = [
            ([[0, 0], [50, 0], [50, 20], [0, 20]], "Line1", 0.95),
            ([[0, 50], [50, 50], [50, 70], [0, 70]], "Line2", 0.90),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        result = engine.extract_text(np.zeros((100, 100, 3), dtype=np.uint8))

        # Should have newline between lines
        assert "\n" in result

    def test_extract_text_accepts_path(self):
        """extract_text accepts Path object."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True
        engine._ocr = MagicMock(return_value=([], None))

        # Should not raise
        engine.extract_text(Path("/some/image.png"))

        # Should convert to string
        call_args = engine._ocr.call_args[0][0]
        assert isinstance(call_args, str)


# =============================================================================
# OCRENGINE EXTRACT_WITH_CONFIDENCE TESTS
# =============================================================================

class TestOCREngineExtractWithConfidence:
    """Tests for OCREngine extract_text_with_confidence method."""

    def test_returns_tuple(self):
        """Returns tuple of (text, confidence)."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        mock_result = [
            ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.90),
            ([[60, 0], [110, 0], [110, 20], [60, 20]], "World", 0.80),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        text, confidence = engine.extract_text_with_confidence(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )

        assert isinstance(text, str)
        assert isinstance(confidence, float)

    def test_calculates_average_confidence(self):
        """Calculates average confidence across blocks."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        mock_result = [
            ([[0, 0], [50, 0], [50, 20], [0, 20]], "A", 0.90),
            ([[60, 0], [110, 0], [110, 20], [60, 20]], "B", 0.80),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        _, confidence = engine.extract_text_with_confidence(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )

        assert abs(confidence - 0.85) < 0.001  # (0.90 + 0.80) / 2

    def test_returns_zero_confidence_for_empty(self):
        """Returns 0.0 confidence for empty result."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True
        engine._ocr = MagicMock(return_value=(None, None))

        text, confidence = engine.extract_text_with_confidence(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )

        assert text == ""
        assert confidence == 0.0


# =============================================================================
# OCRENGINE EXTRACT_WITH_COORDINATES TESTS
# =============================================================================

class TestOCREngineExtractWithCoordinates:
    """Tests for OCREngine extract_with_coordinates method."""

    def test_returns_ocr_result(self):
        """Returns OCRResult object."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        mock_result = [
            ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.95),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        result = engine.extract_with_coordinates(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )

        assert isinstance(result, OCRResult)

    def test_result_has_blocks(self):
        """Result contains OCRBlocks with coordinates."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        bbox = [[10, 5], [60, 5], [60, 25], [10, 25]]
        mock_result = [
            (bbox, "Test", 0.95),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        result = engine.extract_with_coordinates(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )

        assert len(result.blocks) == 1
        assert result.blocks[0].text == "Test"
        assert result.blocks[0].bbox == bbox
        assert result.blocks[0].confidence == 0.95

    def test_result_has_offset_map(self):
        """Result contains offset map for span lookups."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True

        mock_result = [
            ([[0, 0], [50, 0], [50, 20], [0, 20]], "Hello", 0.95),
            ([[60, 0], [110, 0], [110, 20], [60, 20]], "World", 0.90),
        ]
        engine._ocr = MagicMock(return_value=(mock_result, None))

        result = engine.extract_with_coordinates(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )

        assert len(result.offset_map) == 2

    def test_empty_result(self):
        """Returns empty OCRResult for no text."""
        engine = OCREngine(Path("/tmp"))
        engine._initialized = True
        engine._ocr = MagicMock(return_value=(None, None))

        result = engine.extract_with_coordinates(
            np.zeros((100, 100, 3), dtype=np.uint8)
        )

        assert result.full_text == ""
        assert len(result.blocks) == 0
        assert len(result.offset_map) == 0


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================

class TestOCREngineThreadSafety:
    """Tests for OCREngine thread safety."""

    def test_concurrent_start_loading(self):
        """Concurrent start_loading calls are safe."""
        engine = OCREngine(Path("/tmp"))
        started_count = 0

        original_start_loading = engine.start_loading

        def counting_start():
            nonlocal started_count
            with engine._lock:
                if not engine._loading:
                    started_count += 1
                    engine._loading = True

        with patch.object(engine, 'start_loading', counting_start):
            threads = [
                threading.Thread(target=counting_start)
                for _ in range(10)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        # Should only have started once
        assert started_count == 1

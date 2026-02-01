"""Tests for document layout detection (image_protection/document_layout.py).

Tests cover:
- LayoutClass enum
- LayoutRegion dataclass
- LayoutAnalysisResult dataclass
- DocumentLayoutDetector class
  - Initialization
  - Model loading (lazy and background)
  - analyze() method
  - Preprocessing (resize, pad, normalize)
  - Postprocessing (NMS, scaling)
  - IOU calculation
  - Error handling (missing model)
"""

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import numpy as np
import pytest


# --- LayoutClass Tests ---

class TestLayoutClass:
    """Tests for LayoutClass enum."""

    def test_layout_class_values(self):
        """LayoutClass should have expected values."""
        from scrubiq.image_protection.document_layout import LayoutClass

        assert LayoutClass.TITLE.value == 0
        assert LayoutClass.TEXT.value == 1
        assert LayoutClass.ABANDON.value == 2
        assert LayoutClass.FIGURE.value == 3
        assert LayoutClass.TABLE.value == 5
        assert LayoutClass.HEADER.value == 7
        assert LayoutClass.FOOTER.value == 8
        assert LayoutClass.EQUATION.value == 10

    def test_layout_class_count(self):
        """Should have 11 classes."""
        from scrubiq.image_protection.document_layout import LayoutClass

        assert len(LayoutClass) == 11


# --- LAYOUT_CLASS_NAMES Tests ---

class TestLayoutClassNames:
    """Tests for LAYOUT_CLASS_NAMES mapping."""

    def test_all_classes_have_names(self):
        """All LayoutClass values should have names."""
        from scrubiq.image_protection.document_layout import LayoutClass, LAYOUT_CLASS_NAMES

        for cls in LayoutClass:
            assert cls in LAYOUT_CLASS_NAMES
            assert isinstance(LAYOUT_CLASS_NAMES[cls], str)


# --- LayoutRegion Tests ---

class TestLayoutRegion:
    """Tests for LayoutRegion dataclass."""

    def test_layout_region_properties(self):
        """LayoutRegion should calculate properties correctly."""
        from scrubiq.image_protection.document_layout import LayoutRegion, LayoutClass

        region = LayoutRegion(
            x=10, y=20, width=100, height=50,
            confidence=0.95,
            layout_class=LayoutClass.TEXT,
        )

        assert region.x2 == 110
        assert region.y2 == 70
        assert region.area == 5000
        assert region.bbox == (10, 20, 110, 70)
        assert region.center == (60, 45)

    def test_class_name_property(self):
        """class_name should return human-readable name."""
        from scrubiq.image_protection.document_layout import LayoutRegion, LayoutClass

        region = LayoutRegion(
            x=0, y=0, width=100, height=50,
            confidence=0.9,
            layout_class=LayoutClass.TABLE,
        )

        assert region.class_name == "table"

    def test_to_dict(self):
        """to_dict should return serializable dict."""
        from scrubiq.image_protection.document_layout import LayoutRegion, LayoutClass

        region = LayoutRegion(
            x=10, y=20, width=100, height=50,
            confidence=0.95123,
            layout_class=LayoutClass.FIGURE,
        )

        d = region.to_dict()

        assert d["x"] == 10
        assert d["y"] == 20
        assert d["width"] == 100
        assert d["height"] == 50
        assert d["confidence"] == 0.951  # Rounded
        assert d["class"] == "figure"


# --- LayoutAnalysisResult Tests ---

class TestLayoutAnalysisResult:
    """Tests for LayoutAnalysisResult dataclass."""

    def test_get_regions_by_class(self):
        """get_regions_by_class should filter regions."""
        from scrubiq.image_protection.document_layout import (
            LayoutAnalysisResult, LayoutRegion, LayoutClass
        )

        regions = [
            LayoutRegion(0, 0, 100, 50, 0.9, LayoutClass.TEXT),
            LayoutRegion(0, 60, 100, 50, 0.8, LayoutClass.TABLE),
            LayoutRegion(0, 120, 100, 50, 0.85, LayoutClass.TEXT),
        ]

        result = LayoutAnalysisResult(
            regions=regions,
            processing_time_ms=10.0,
            image_width=640,
            image_height=480,
        )

        text_regions = result.get_regions_by_class(LayoutClass.TEXT)

        assert len(text_regions) == 2
        assert all(r.layout_class == LayoutClass.TEXT for r in text_regions)

    def test_has_tables_property(self):
        """has_tables should detect table presence."""
        from scrubiq.image_protection.document_layout import (
            LayoutAnalysisResult, LayoutRegion, LayoutClass
        )

        # Without tables
        result1 = LayoutAnalysisResult(
            regions=[LayoutRegion(0, 0, 100, 50, 0.9, LayoutClass.TEXT)],
            processing_time_ms=10.0,
            image_width=640,
            image_height=480,
        )
        assert result1.has_tables is False

        # With tables
        result2 = LayoutAnalysisResult(
            regions=[LayoutRegion(0, 0, 100, 50, 0.9, LayoutClass.TABLE)],
            processing_time_ms=10.0,
            image_width=640,
            image_height=480,
        )
        assert result2.has_tables is True

    def test_has_figures_property(self):
        """has_figures should detect figure presence."""
        from scrubiq.image_protection.document_layout import (
            LayoutAnalysisResult, LayoutRegion, LayoutClass
        )

        # Without figures
        result1 = LayoutAnalysisResult(
            regions=[LayoutRegion(0, 0, 100, 50, 0.9, LayoutClass.TEXT)],
            processing_time_ms=10.0,
            image_width=640,
            image_height=480,
        )
        assert result1.has_figures is False

        # With figures
        result2 = LayoutAnalysisResult(
            regions=[LayoutRegion(0, 0, 100, 50, 0.9, LayoutClass.FIGURE)],
            processing_time_ms=10.0,
            image_width=640,
            image_height=480,
        )
        assert result2.has_figures is True

    def test_to_dict(self):
        """to_dict should return summary info."""
        from scrubiq.image_protection.document_layout import (
            LayoutAnalysisResult, LayoutRegion, LayoutClass
        )

        result = LayoutAnalysisResult(
            regions=[
                LayoutRegion(0, 0, 100, 50, 0.9, LayoutClass.TEXT),
                LayoutRegion(0, 60, 100, 50, 0.8, LayoutClass.TABLE),
            ],
            processing_time_ms=15.5,
            image_width=640,
            image_height=480,
        )

        d = result.to_dict()

        assert d["num_regions"] == 2
        assert d["processing_time_ms"] == 15.5
        assert d["image_size"] == [640, 480]
        assert "text" in d["classes_found"]
        assert "table" in d["classes_found"]


# --- DocumentLayoutDetector Tests ---

class TestDocumentLayoutDetector:
    """Tests for DocumentLayoutDetector class."""

    @pytest.fixture
    def mock_models_dir(self, tmp_path):
        """Create a mock models directory."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        return models_dir

    @pytest.fixture
    def mock_onnx_runtime(self):
        """Mock ONNX runtime."""
        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [MagicMock(name="input")]
        mock_session.run.return_value = [np.zeros((1, 15, 8400), dtype=np.float32)]

        mock_ort = MagicMock()
        mock_ort.InferenceSession.return_value = mock_session
        mock_ort.get_available_providers.return_value = ["CPUExecutionProvider"]

        yield mock_ort, mock_session

    def test_init_sets_models_dir(self, mock_models_dir):
        """Should store models directory."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)

        assert detector.models_dir == mock_models_dir

    def test_init_sets_default_confidence(self, mock_models_dir):
        """Should use default confidence threshold."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)

        assert detector.confidence_threshold == 0.35

    def test_init_sets_custom_confidence(self, mock_models_dir):
        """Should allow custom confidence threshold."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir, confidence_threshold=0.5)

        assert detector.confidence_threshold == 0.5

    def test_is_available_false_without_model(self, mock_models_dir):
        """is_available should be False if model file missing."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)

        assert detector.is_available is False

    def test_is_available_true_with_model(self, mock_models_dir):
        """is_available should be True if model file exists."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        # Create model file
        model_file = mock_models_dir / "yolo_doclayout.onnx"
        model_file.touch()

        detector = DocumentLayoutDetector(mock_models_dir)

        assert detector.is_available is True

    def test_is_initialized_false_initially(self, mock_models_dir):
        """is_initialized should be False before loading."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)

        assert detector.is_initialized is False

    def test_load_model_raises_if_not_available(self, mock_models_dir):
        """_load_model should raise FileNotFoundError if model missing."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)

        with pytest.raises(FileNotFoundError, match="not found"):
            detector._load_model()

    def test_load_model_creates_session(self, mock_models_dir, mock_onnx_runtime):
        """_load_model should create ONNX session."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        mock_ort, mock_session = mock_onnx_runtime

        # Create model file
        model_file = mock_models_dir / "yolo_doclayout.onnx"
        model_file.touch()

        detector = DocumentLayoutDetector(mock_models_dir)

        with patch("onnxruntime.InferenceSession", return_value=mock_session):
            with patch("onnxruntime.get_available_providers", return_value=["CPUExecutionProvider"]):
                detector._load_model()

                assert detector._initialized is True

    def test_start_loading_background_thread(self, mock_models_dir, mock_onnx_runtime):
        """start_loading should start background loading thread."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        mock_ort, mock_session = mock_onnx_runtime

        model_file = mock_models_dir / "yolo_doclayout.onnx"
        model_file.touch()

        detector = DocumentLayoutDetector(mock_models_dir)

        with patch.object(detector, "_background_load"):
            detector.start_loading()

            assert detector._loading is True

    def test_start_loading_idempotent(self, mock_models_dir):
        """start_loading should be idempotent."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)
        detector._loading = True

        # Should not start another thread
        detector.start_loading()

        assert detector._loading is True

    def test_await_ready_returns_true_if_initialized(self, mock_models_dir):
        """await_ready should return True immediately if initialized."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)
        detector._initialized = True

        assert detector.await_ready(timeout=0.1) is True

    def test_await_ready_raises_on_load_error(self, mock_models_dir):
        """await_ready should raise if loading failed."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(mock_models_dir)
        detector._load_error = FileNotFoundError("Model not found")
        detector._ready_event.set()

        with pytest.raises(FileNotFoundError):
            detector.await_ready(timeout=0.1)


# --- Analysis Tests ---

class TestAnalyze:
    """Tests for analyze method."""

    @pytest.fixture
    def initialized_detector(self, tmp_path):
        """Create an initialized detector with mocked session."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        models_dir = tmp_path / "models"
        models_dir.mkdir()
        (models_dir / "yolo_doclayout.onnx").touch()

        detector = DocumentLayoutDetector(models_dir)

        # Mock the session
        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [MagicMock(name="input")]
        # Return output with detections: [batch, 4+11 classes, num_boxes]
        mock_session.run.return_value = [np.zeros((1, 15, 100), dtype=np.float32)]

        detector._session = mock_session
        detector._initialized = True

        return detector

    def test_analyze_grayscale_image(self, initialized_detector):
        """Should handle grayscale images."""
        image = np.zeros((480, 640), dtype=np.uint8)

        result = initialized_detector.analyze(image)

        assert result.image_width == 640
        assert result.image_height == 480

    def test_analyze_rgba_image(self, initialized_detector):
        """Should handle RGBA images (drop alpha)."""
        image = np.zeros((480, 640, 4), dtype=np.uint8)

        result = initialized_detector.analyze(image)

        assert result.image_width == 640
        assert result.image_height == 480

    def test_analyze_rgb_image(self, initialized_detector):
        """Should handle RGB images."""
        image = np.zeros((480, 640, 3), dtype=np.uint8)

        result = initialized_detector.analyze(image)

        assert result.image_width == 640
        assert result.image_height == 480

    def test_analyze_returns_regions(self, initialized_detector):
        """Should return detected regions."""
        from scrubiq.image_protection.document_layout import LayoutClass

        # Mock detection output with one high-confidence detection
        # Format: [batch, 4+11, num_boxes] -> x, y, w, h, class_scores
        output = np.zeros((1, 15, 100), dtype=np.float32)
        # Set one detection at index 0
        output[0, 0, 0] = 512  # x_center
        output[0, 1, 0] = 512  # y_center
        output[0, 2, 0] = 200  # width
        output[0, 3, 0] = 100  # height
        output[0, 5, 0] = 0.9  # TEXT class confidence (class 1, but offset by 4)

        initialized_detector._session.run.return_value = [output]

        image = np.zeros((1024, 1024, 3), dtype=np.uint8)
        result = initialized_detector.analyze(image)

        assert result.processing_time_ms > 0

    def test_analyze_filters_low_confidence(self, initialized_detector):
        """Should filter detections below threshold."""
        # All detections below threshold
        output = np.zeros((1, 15, 100), dtype=np.float32)
        output[0, 0, :] = 512  # x
        output[0, 1, :] = 512  # y
        output[0, 2, :] = 100  # w
        output[0, 3, :] = 100  # h
        output[0, 4:, :] = 0.1  # Low confidence for all classes

        initialized_detector._session.run.return_value = [output]
        initialized_detector.confidence_threshold = 0.5

        image = np.zeros((1024, 1024, 3), dtype=np.uint8)
        result = initialized_detector.analyze(image)

        assert len(result.regions) == 0

    def test_analyze_custom_threshold(self, initialized_detector):
        """Should allow custom confidence threshold per call."""
        image = np.zeros((480, 640, 3), dtype=np.uint8)

        # Call with custom threshold
        result = initialized_detector.analyze(image, conf_threshold=0.9)

        # Should complete without error
        assert result is not None


# --- Preprocessing Tests ---

class TestPreprocessing:
    """Tests for image preprocessing."""

    @pytest.fixture
    def detector(self, tmp_path):
        """Create detector for testing."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        return DocumentLayoutDetector(tmp_path)

    def test_preprocess_scales_to_input_size(self, detector):
        """Should scale image to INPUT_SIZE maintaining aspect ratio."""
        image = np.zeros((480, 640, 3), dtype=np.uint8)

        with patch("cv2.resize", return_value=np.zeros((768, 1024, 3), dtype=np.uint8)) as mock_resize:
            blob, scale, pad_w, pad_h = detector._preprocess(image)

            # Output should be 1024x1024 (with batch and channel dims)
            assert blob.shape == (1, 3, 1024, 1024)

    def test_preprocess_normalizes_to_0_1(self, detector):
        """Should normalize pixel values to [0, 1]."""
        image = np.ones((100, 100, 3), dtype=np.uint8) * 255

        # Mock resize to return model input size (1024x1024)
        resized = np.ones((1024, 1024, 3), dtype=np.uint8) * 255
        with patch("cv2.resize", return_value=resized):
            blob, _, _, _ = detector._preprocess(image)

            assert blob.max() <= 1.0
            assert blob.min() >= 0.0

    def test_preprocess_returns_scale_and_padding(self, detector):
        """Should return scale factor and padding."""
        image = np.zeros((480, 640, 3), dtype=np.uint8)

        with patch("cv2.resize", return_value=np.zeros((768, 1024, 3), dtype=np.uint8)):
            blob, scale, pad_w, pad_h = detector._preprocess(image)

            # Scale and padding should be returned
            assert scale > 0
            assert isinstance(pad_w, int)
            assert isinstance(pad_h, int)


# --- NMS Tests ---

class TestNMS:
    """Tests for non-maximum suppression."""

    @pytest.fixture
    def detector(self, tmp_path):
        """Create detector for testing."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        return DocumentLayoutDetector(tmp_path)

    def test_nms_empty_list(self, detector):
        """NMS on empty list should return empty list."""
        result = detector._nms([])

        assert result == []

    def test_nms_single_region(self, detector):
        """NMS on single region should return it."""
        from scrubiq.image_protection.document_layout import LayoutRegion, LayoutClass

        regions = [LayoutRegion(0, 0, 100, 100, 0.9, LayoutClass.TEXT)]

        result = detector._nms(regions)

        assert len(result) == 1

    def test_nms_removes_overlapping(self, detector):
        """NMS should remove highly overlapping regions."""
        from scrubiq.image_protection.document_layout import LayoutRegion, LayoutClass

        regions = [
            LayoutRegion(0, 0, 100, 100, 0.9, LayoutClass.TEXT),
            LayoutRegion(10, 10, 100, 100, 0.8, LayoutClass.TEXT),  # Overlaps
        ]

        result = detector._nms(regions)

        # Only highest confidence should remain
        assert len(result) == 1
        assert result[0].confidence == 0.9

    def test_nms_keeps_non_overlapping(self, detector):
        """NMS should keep non-overlapping regions."""
        from scrubiq.image_protection.document_layout import LayoutRegion, LayoutClass

        regions = [
            LayoutRegion(0, 0, 100, 100, 0.9, LayoutClass.TEXT),
            LayoutRegion(200, 200, 100, 100, 0.8, LayoutClass.TEXT),  # No overlap
        ]

        result = detector._nms(regions)

        assert len(result) == 2


# --- IOU Tests ---

class TestIOU:
    """Tests for IOU calculation."""

    def test_iou_no_overlap(self):
        """IOU of non-overlapping boxes should be 0."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        box1 = (0, 0, 100, 100)
        box2 = (200, 200, 300, 300)

        iou = DocumentLayoutDetector._iou(box1, box2)

        assert iou == 0.0

    def test_iou_full_overlap(self):
        """IOU of identical boxes should be 1."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        box1 = (0, 0, 100, 100)
        box2 = (0, 0, 100, 100)

        iou = DocumentLayoutDetector._iou(box1, box2)

        assert iou == 1.0

    def test_iou_partial_overlap(self):
        """IOU of partially overlapping boxes should be between 0 and 1."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        box1 = (0, 0, 100, 100)
        box2 = (50, 50, 150, 150)

        iou = DocumentLayoutDetector._iou(box1, box2)

        assert 0 < iou < 1

    def test_iou_touching_edges(self):
        """IOU of boxes touching at edge should be 0."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        box1 = (0, 0, 100, 100)
        box2 = (100, 0, 200, 100)  # Touching at x=100

        iou = DocumentLayoutDetector._iou(box1, box2)

        assert iou == 0.0


# --- Warm Up Tests ---

class TestWarmUp:
    """Tests for model warm-up."""

    def test_warm_up_skips_if_not_initialized(self, tmp_path):
        """warm_up should skip if not initialized."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(tmp_path)

        # Should not raise
        detector.warm_up()

    def test_warm_up_runs_dummy_inference(self, tmp_path):
        """warm_up should run dummy inference."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(tmp_path)
        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [MagicMock(name="input")]
        mock_session.run.return_value = [np.zeros((1, 15, 100))]

        detector._session = mock_session
        detector._initialized = True

        detector.warm_up()

        mock_session.run.assert_called()


# --- Background Loading Tests ---

class TestBackgroundLoading:
    """Tests for background model loading."""

    def test_background_load_sets_ready_event(self, tmp_path):
        """_background_load should set ready event on completion."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(tmp_path)

        with patch.object(detector, "_load_model"):
            with patch.object(detector, "warm_up"):
                detector._background_load()

                assert detector._ready_event.is_set()

    def test_background_load_stores_error(self, tmp_path):
        """_background_load should store errors."""
        from scrubiq.image_protection.document_layout import DocumentLayoutDetector

        detector = DocumentLayoutDetector(tmp_path)

        with patch.object(detector, "_load_model", side_effect=FileNotFoundError("Model not found")):
            detector._background_load()

            assert detector._load_error is not None
            assert detector._ready_event.is_set()

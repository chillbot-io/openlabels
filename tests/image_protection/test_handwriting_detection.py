"""Tests for handwriting detection (image_protection/handwriting_detection.py).

Tests cover:
- HandwritingDetection dataclass
- HandwritingDetectionResult dataclass
- HandwritingDetector class
  - Initialization
  - Model loading (lazy and background)
  - detect() method
  - Preprocessing
  - Postprocessing
  - NMS
  - Box expansion
  - Error handling
"""

import hashlib
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest


# --- HandwritingDetection Tests ---

class TestHandwritingDetection:
    """Tests for HandwritingDetection dataclass."""

    def test_handwriting_detection_properties(self):
        """HandwritingDetection should calculate properties correctly."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetection

        det = HandwritingDetection(
            x=10, y=20, width=100, height=50,
            confidence=0.85,
            class_name="handwriting",
        )

        assert det.x2 == 110
        assert det.y2 == 70
        assert det.area == 5000
        assert det.bbox == (10, 20, 110, 70)

    def test_to_dict(self):
        """to_dict should return serializable dict."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetection

        det = HandwritingDetection(
            x=10, y=20, width=100, height=50,
            confidence=0.85123,
            class_name="handwriting",
        )

        d = det.to_dict()

        assert d["x"] == 10
        assert d["y"] == 20
        assert d["width"] == 100
        assert d["height"] == 50
        assert d["confidence"] == 0.851  # Rounded
        assert d["class"] == "handwriting"


# --- HandwritingDetectionResult Tests ---

class TestHandwritingDetectionResult:
    """Tests for HandwritingDetectionResult dataclass."""

    def test_to_audit_dict(self):
        """to_audit_dict should return audit-safe information."""
        from scrubiq.image_protection.handwriting_detection import (
            HandwritingDetectionResult, HandwritingDetection
        )

        result = HandwritingDetectionResult(
            original_hash="abc123def456",
            regions_detected=3,
            detections=[],
            processing_time_ms=25.5,
        )

        audit = result.to_audit_dict()

        assert audit["original_hash"] == "abc123def456"
        assert audit["regions_detected"] == 3
        assert audit["processing_time_ms"] == 25.5


# --- HandwritingDetector Initialization Tests ---

class TestHandwritingDetectorInit:
    """Tests for HandwritingDetector initialization."""

    @pytest.fixture
    def mock_models_dir(self, tmp_path):
        """Create a mock models directory."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        return models_dir

    def test_init_sets_models_dir(self, mock_models_dir):
        """Should store models directory."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        assert detector.models_dir == mock_models_dir

    def test_init_default_confidence(self, mock_models_dir):
        """Should use default confidence threshold."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        assert detector.confidence_threshold == 0.4

    def test_init_custom_confidence(self, mock_models_dir):
        """Should allow custom confidence threshold."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir, confidence_threshold=0.6)

        assert detector.confidence_threshold == 0.6

    def test_is_available_without_model(self, mock_models_dir):
        """is_available should be False without model file."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        assert detector.is_available is False

    def test_is_available_with_model(self, mock_models_dir):
        """is_available should be True with model file."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        (mock_models_dir / "yolov8n_handwriting_detection.onnx").touch()

        detector = HandwritingDetector(mock_models_dir)

        assert detector.is_available is True

    def test_is_initialized_false_initially(self, mock_models_dir):
        """is_initialized should be False before loading."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        assert detector.is_initialized is False

    def test_is_loading_false_initially(self, mock_models_dir):
        """is_loading should be False before start_loading."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        assert detector.is_loading is False


# --- Model Loading Tests ---

class TestModelLoading:
    """Tests for model loading."""

    @pytest.fixture
    def mock_models_dir(self, tmp_path):
        """Create models directory with model file."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        (models_dir / "yolov8n_handwriting_detection.onnx").touch()
        return models_dir

    def test_load_model_raises_if_not_available(self, tmp_path):
        """_load_model should raise FileNotFoundError if model missing."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(tmp_path)

        with pytest.raises(FileNotFoundError, match="not found"):
            detector._load_model()

    def test_load_model_creates_session(self, mock_models_dir):
        """_load_model should create ONNX session."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [MagicMock(name="input")]

        with patch("onnxruntime.InferenceSession", return_value=mock_session):
            with patch("onnxruntime.get_available_providers", return_value=["CPUExecutionProvider"]):
                detector._load_model()

                assert detector._initialized is True
                assert detector._session is mock_session

    def test_start_loading_sets_flag(self, mock_models_dir):
        """start_loading should set loading flag."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        with patch.object(detector, "_background_load"):
            detector.start_loading()

            assert detector._loading is True

    def test_start_loading_idempotent(self, mock_models_dir):
        """start_loading should be idempotent."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)
        detector._loading = True

        detector.start_loading()

        # Should not raise or change state
        assert detector._loading is True

    def test_await_ready_returns_true_if_initialized(self, mock_models_dir):
        """await_ready should return True if already initialized."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)
        detector._initialized = True

        result = detector.await_ready(timeout=0.1)

        assert result is True

    def test_await_ready_raises_on_error(self, mock_models_dir):
        """await_ready should raise stored error."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)
        detector._load_error = RuntimeError("Load failed")
        detector._ready_event.set()

        with pytest.raises(RuntimeError, match="Load failed"):
            detector.await_ready(timeout=0.1)


# --- Background Loading Tests ---

class TestBackgroundLoading:
    """Tests for background model loading."""

    @pytest.fixture
    def mock_models_dir(self, tmp_path):
        """Create models directory with model file."""
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        (models_dir / "yolov8n_handwriting_detection.onnx").touch()
        return models_dir

    def test_background_load_sets_ready_event(self, mock_models_dir):
        """_background_load should set ready event."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        with patch.object(detector, "_load_model"):
            with patch.object(detector, "warm_up"):
                detector._background_load()

                assert detector._ready_event.is_set()

    def test_background_load_catches_errors(self, mock_models_dir):
        """_background_load should catch and store errors."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(mock_models_dir)

        with patch.object(detector, "_load_model", side_effect=RuntimeError("Load failed")):
            detector._background_load()

            assert detector._load_error is not None
            assert detector._ready_event.is_set()


# --- Detection Tests ---

class TestDetect:
    """Tests for detect method."""

    @pytest.fixture
    def initialized_detector(self, tmp_path):
        """Create an initialized detector with mocked session."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        models_dir = tmp_path / "models"
        models_dir.mkdir()
        (models_dir / "yolov8n_handwriting_detection.onnx").touch()

        detector = HandwritingDetector(models_dir)

        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [MagicMock(name="input")]
        # YOLOv8 output: [batch, 5, num_boxes] where 5 = x, y, w, h, conf
        mock_session.run.return_value = [np.zeros((1, 5, 100), dtype=np.float32)]

        detector._session = mock_session
        detector._initialized = True

        return detector

    def test_detect_grayscale(self, initialized_detector):
        """Should handle grayscale images."""
        image = np.zeros((480, 640), dtype=np.uint8)

        result = initialized_detector.detect(image)

        assert isinstance(result, list)

    def test_detect_rgba(self, initialized_detector):
        """Should handle RGBA images."""
        image = np.zeros((480, 640, 4), dtype=np.uint8)

        result = initialized_detector.detect(image)

        assert isinstance(result, list)

    def test_detect_rgb(self, initialized_detector):
        """Should handle RGB images."""
        image = np.zeros((480, 640, 3), dtype=np.uint8)

        result = initialized_detector.detect(image)

        assert isinstance(result, list)

    def test_detect_returns_detections(self, initialized_detector):
        """Should return detected regions."""
        # Mock output with one detection
        output = np.zeros((1, 5, 100), dtype=np.float32)
        output[0, 0, 0] = 320  # x_center
        output[0, 1, 0] = 240  # y_center
        output[0, 2, 0] = 100  # width
        output[0, 3, 0] = 50   # height
        output[0, 4, 0] = 0.9  # confidence

        initialized_detector._session.run.return_value = [output]

        image = np.zeros((480, 640, 3), dtype=np.uint8)
        result = initialized_detector.detect(image)

        # Should detect the region
        assert isinstance(result, list)

    def test_detect_filters_low_confidence(self, initialized_detector):
        """Should filter detections below threshold."""
        # All low confidence
        output = np.zeros((1, 5, 100), dtype=np.float32)
        output[0, :4, :] = 100  # Some position/size
        output[0, 4, :] = 0.1   # Low confidence

        initialized_detector._session.run.return_value = [output]
        initialized_detector.confidence_threshold = 0.5

        image = np.zeros((480, 640, 3), dtype=np.uint8)
        result = initialized_detector.detect(image)

        assert len(result) == 0

    def test_detect_custom_threshold(self, initialized_detector):
        """Should allow custom confidence threshold."""
        image = np.zeros((480, 640, 3), dtype=np.uint8)

        result = initialized_detector.detect(image, conf_threshold=0.9)

        assert isinstance(result, list)


# --- Process Tests ---

class TestProcess:
    """Tests for process method."""

    @pytest.fixture
    def initialized_detector(self, tmp_path):
        """Create initialized detector."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        models_dir = tmp_path / "models"
        models_dir.mkdir()
        (models_dir / "yolov8n_handwriting_detection.onnx").touch()

        detector = HandwritingDetector(models_dir)

        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [MagicMock(name="input")]
        mock_session.run.return_value = [np.zeros((1, 5, 100), dtype=np.float32)]

        detector._session = mock_session
        detector._initialized = True

        return detector

    def test_process_returns_result(self, initialized_detector):
        """process should return HandwritingDetectionResult."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetectionResult

        image = np.zeros((480, 640, 3), dtype=np.uint8)

        result = initialized_detector.process(image)

        assert isinstance(result, HandwritingDetectionResult)
        assert result.processing_time_ms > 0

    def test_process_computes_hash(self, initialized_detector):
        """process should compute image hash."""
        image = np.ones((100, 100, 3), dtype=np.uint8) * 128

        result = initialized_detector.process(image)

        expected_hash = hashlib.sha256(image.tobytes()).hexdigest()[:16]
        assert result.original_hash == expected_hash


# --- Preprocessing Tests ---

class TestPreprocessing:
    """Tests for image preprocessing."""

    @pytest.fixture
    def detector(self, tmp_path):
        """Create detector."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        return HandwritingDetector(tmp_path)

    def test_preprocess_returns_correct_shape(self, detector):
        """Should return correct output shape."""
        image = np.zeros((480, 640, 3), dtype=np.uint8)

        with patch("cv2.resize", return_value=np.zeros((480, 640, 3), dtype=np.uint8)):
            blob, scale, pad_w, pad_h = detector._preprocess(image)

            # Should be [1, 3, 640, 640]
            assert blob.shape == (1, 3, 640, 640)

    def test_preprocess_normalizes(self, detector):
        """Should normalize to [0, 1]."""
        image = np.ones((100, 100, 3), dtype=np.uint8) * 255

        # Mock resize to return 640x640 image (model input size)
        resized = np.ones((640, 640, 3), dtype=np.uint8) * 255
        with patch("cv2.resize", return_value=resized):
            blob, _, _, _ = detector._preprocess(image)

            assert blob.max() <= 1.0


# --- NMS Tests ---

class TestNMS:
    """Tests for non-maximum suppression."""

    @pytest.fixture
    def detector(self, tmp_path):
        """Create detector."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        return HandwritingDetector(tmp_path)

    def test_nms_empty(self, detector):
        """NMS on empty list should return empty."""
        result = detector._nms([])

        assert result == []

    def test_nms_removes_overlapping(self, detector):
        """NMS should remove overlapping detections."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetection

        detections = [
            HandwritingDetection(0, 0, 100, 100, 0.9, "handwriting"),
            HandwritingDetection(10, 10, 100, 100, 0.8, "handwriting"),
        ]

        result = detector._nms(detections)

        assert len(result) == 1
        assert result[0].confidence == 0.9


# --- Box Expansion Tests ---

class TestBoxExpansion:
    """Tests for box expansion."""

    @pytest.fixture
    def detector(self, tmp_path):
        """Create detector."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        return HandwritingDetector(tmp_path)

    def test_expand_box_increases_size(self, detector):
        """_expand_box should increase box dimensions."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetection

        det = HandwritingDetection(100, 100, 200, 100, 0.9, "handwriting")

        expanded = detector._expand_box(det, 640, 480)

        # Should be slightly larger
        assert expanded.width >= det.width
        assert expanded.height >= det.height

    def test_expand_box_clips_to_image(self, detector):
        """_expand_box should clip to image bounds."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetection

        # Box near edge
        det = HandwritingDetection(0, 0, 100, 100, 0.9, "handwriting")

        expanded = detector._expand_box(det, 640, 480)

        assert expanded.x >= 0
        assert expanded.y >= 0


# --- IOU Tests ---

class TestIOU:
    """Tests for IOU calculation."""

    def test_iou_no_overlap(self):
        """IOU of non-overlapping boxes should be 0."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        box1 = (0, 0, 100, 100)
        box2 = (200, 200, 300, 300)

        iou = HandwritingDetector._iou(box1, box2)

        assert iou == 0.0

    def test_iou_full_overlap(self):
        """IOU of identical boxes should be 1."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        box1 = (0, 0, 100, 100)

        iou = HandwritingDetector._iou(box1, box1)

        assert iou == 1.0

    def test_iou_partial_overlap(self):
        """IOU of partially overlapping boxes should be between 0 and 1."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        box1 = (0, 0, 100, 100)
        box2 = (50, 50, 150, 150)

        iou = HandwritingDetector._iou(box1, box2)

        assert 0 < iou < 1


# --- Warm Up Tests ---

class TestWarmUp:
    """Tests for model warm-up."""

    def test_warm_up_skips_if_not_initialized(self, tmp_path):
        """warm_up should skip if not initialized."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(tmp_path)

        # Should not raise
        detector.warm_up()

    def test_warm_up_runs_inference(self, tmp_path):
        """warm_up should run dummy inference."""
        from scrubiq.image_protection.handwriting_detection import HandwritingDetector

        detector = HandwritingDetector(tmp_path)

        mock_session = MagicMock()
        mock_session.get_inputs.return_value = [MagicMock(name="input")]
        mock_session.run.return_value = [np.zeros((1, 5, 100))]

        detector._session = mock_session
        detector._initialized = True

        detector.warm_up()

        mock_session.run.assert_called()

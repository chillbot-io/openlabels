"""Tests for image_protection/face_detection.py - YuNet face detection.

Tests cover:
- FaceDetection dataclass
- FaceDetectionResult dataclass
- FaceDetector initialization
- Face detection functionality
- Edge cases (tiny images, grayscale, empty images)
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import numpy as np


# =============================================================================
# FACE DETECTION DATACLASS TESTS
# =============================================================================

class TestFaceDetection:
    """Tests for FaceDetection dataclass."""

    def test_creation(self):
        """FaceDetection can be created."""
        from scrubiq.image_protection.face_detection import FaceDetection

        face = FaceDetection(
            x=10,
            y=20,
            width=100,
            height=100,
            confidence=0.95,
        )

        assert face.x == 10
        assert face.y == 20
        assert face.width == 100
        assert face.height == 100
        assert face.confidence == 0.95
        assert face.landmarks is None

    def test_with_landmarks(self):
        """FaceDetection can include landmarks."""
        from scrubiq.image_protection.face_detection import FaceDetection

        landmarks = [
            (15, 30), (35, 30),  # Eyes
            (25, 45),            # Nose
            (15, 60), (35, 60),  # Mouth corners
        ]

        face = FaceDetection(
            x=10,
            y=20,
            width=100,
            height=100,
            confidence=0.95,
            landmarks=landmarks,
        )

        assert face.landmarks is not None
        assert len(face.landmarks) == 5

    def test_x2_property(self):
        """x2 returns x + width."""
        from scrubiq.image_protection.face_detection import FaceDetection

        face = FaceDetection(x=10, y=20, width=100, height=80, confidence=0.9)

        assert face.x2 == 110

    def test_y2_property(self):
        """y2 returns y + height."""
        from scrubiq.image_protection.face_detection import FaceDetection

        face = FaceDetection(x=10, y=20, width=100, height=80, confidence=0.9)

        assert face.y2 == 100

    def test_area_property(self):
        """area returns width * height."""
        from scrubiq.image_protection.face_detection import FaceDetection

        face = FaceDetection(x=10, y=20, width=100, height=80, confidence=0.9)

        assert face.area == 8000

    def test_bbox_property(self):
        """bbox returns (x1, y1, x2, y2) tuple."""
        from scrubiq.image_protection.face_detection import FaceDetection

        face = FaceDetection(x=10, y=20, width=100, height=80, confidence=0.9)

        assert face.bbox == (10, 20, 110, 100)

    def test_to_dict(self):
        """to_dict returns serializable dict."""
        from scrubiq.image_protection.face_detection import FaceDetection

        face = FaceDetection(
            x=10,
            y=20,
            width=100,
            height=80,
            confidence=0.9567,
            landmarks=[(15, 30)],
        )

        d = face.to_dict()

        assert d["x"] == 10
        assert d["y"] == 20
        assert d["width"] == 100
        assert d["height"] == 80
        assert d["confidence"] == 0.957  # Rounded to 3 places
        assert d["has_landmarks"] is True

    def test_to_dict_no_landmarks(self):
        """to_dict handles None landmarks."""
        from scrubiq.image_protection.face_detection import FaceDetection

        face = FaceDetection(x=10, y=20, width=100, height=80, confidence=0.9)

        d = face.to_dict()
        assert d["has_landmarks"] is False


# =============================================================================
# FACE DETECTION RESULT TESTS
# =============================================================================

class TestFaceDetectionResult:
    """Tests for FaceDetectionResult dataclass."""

    def test_creation(self):
        """FaceDetectionResult can be created."""
        from scrubiq.image_protection.face_detection import (
            FaceDetection, FaceDetectionResult
        )

        detections = [
            FaceDetection(x=10, y=20, width=100, height=100, confidence=0.9),
            FaceDetection(x=200, y=50, width=80, height=80, confidence=0.85),
        ]

        result = FaceDetectionResult(
            faces_detected=2,
            detections=detections,
            processing_time_ms=15.5,
            image_width=640,
            image_height=480,
        )

        assert result.faces_detected == 2
        assert len(result.detections) == 2
        assert result.processing_time_ms == 15.5
        assert result.image_width == 640
        assert result.image_height == 480

    def test_to_audit_dict(self):
        """to_audit_dict returns audit-safe dict."""
        from scrubiq.image_protection.face_detection import (
            FaceDetection, FaceDetectionResult
        )

        result = FaceDetectionResult(
            faces_detected=1,
            detections=[FaceDetection(x=0, y=0, width=10, height=10, confidence=0.9)],
            processing_time_ms=12.567,
            image_width=640,
            image_height=480,
        )

        audit = result.to_audit_dict()

        assert audit["faces_detected"] == 1
        assert audit["processing_time_ms"] == 12.6  # Rounded
        assert audit["image_size"] == "640x480"

    def test_empty_result(self):
        """Empty result has zero faces."""
        from scrubiq.image_protection.face_detection import FaceDetectionResult

        result = FaceDetectionResult(
            faces_detected=0,
            detections=[],
            processing_time_ms=5.0,
            image_width=100,
            image_height=100,
        )

        assert result.faces_detected == 0
        assert len(result.detections) == 0


# =============================================================================
# FACE DETECTOR INITIALIZATION TESTS
# =============================================================================

class TestFaceDetectorInit:
    """Tests for FaceDetector initialization."""

    def test_init_default_params(self):
        """FaceDetector initializes with defaults."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        assert detector.score_threshold == 0.7
        assert detector.nms_threshold == 0.3
        assert detector.top_k == 5000
        assert detector._detector is None

    def test_init_custom_params(self):
        """FaceDetector accepts custom parameters."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector(
            model_path=Path("/custom/model.onnx"),
            score_threshold=0.5,
            nms_threshold=0.4,
            top_k=1000,
        )

        assert detector.score_threshold == 0.5
        assert detector.nms_threshold == 0.4
        assert detector.top_k == 1000
        assert detector.model_path == Path("/custom/model.onnx")

    def test_init_with_tilde_path(self):
        """FaceDetector expands ~ in path."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector(model_path=Path("~/models/face.onnx"))

        assert "~" not in str(detector.model_path)


# =============================================================================
# FACE DETECTOR DETECTION TESTS
# =============================================================================

class TestFaceDetectorDetect:
    """Tests for FaceDetector.detect method."""

    def test_detect_empty_image(self):
        """Handles empty image gracefully."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        result = detector.detect(np.array([]))

        assert result.faces_detected == 0
        assert result.detections == []
        assert result.image_width == 0
        assert result.image_height == 0

    def test_detect_none_image(self):
        """Handles None image gracefully."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        result = detector.detect(None)

        assert result.faces_detected == 0
        assert result.detections == []

    def test_detect_tiny_image(self):
        """Handles very small images."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        # 10x10 image - too small for face detection
        tiny_image = np.zeros((10, 10, 3), dtype=np.uint8)

        result = detector.detect(tiny_image)

        assert result.faces_detected == 0
        assert result.image_width == 10
        assert result.image_height == 10

    def test_detect_grayscale_image(self):
        """Handles grayscale images (converts to BGR)."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        # 2D grayscale image
        gray_image = np.zeros((100, 100), dtype=np.uint8)

        # Should not raise - converts to BGR internally
        with patch.object(detector, '_ensure_loaded'):
            with patch.object(detector, '_detector') as mock_det:
                mock_det.detect.return_value = (None, None)
                detector._detector = mock_det

                result = detector.detect(gray_image)

                assert result is not None

    def test_detect_single_channel_3d(self):
        """Handles single-channel 3D array."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        # 3D but single channel
        image = np.zeros((100, 100, 1), dtype=np.uint8)

        with patch.object(detector, '_ensure_loaded'):
            with patch.object(detector, '_detector') as mock_det:
                mock_det.detect.return_value = (None, None)
                detector._detector = mock_det

                result = detector.detect(image)

                assert result is not None


# =============================================================================
# ENSURE LOADED TESTS
# =============================================================================

class TestEnsureLoaded:
    """Tests for _ensure_loaded method."""

    def test_raises_if_model_not_found(self):
        """Raises FileNotFoundError if model doesn't exist."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector(model_path=Path("/nonexistent/model.onnx"))

        with pytest.raises(FileNotFoundError) as exc_info:
            detector._ensure_loaded(640, 480)

        assert "YuNet model not found" in str(exc_info.value)

    def test_loads_model_on_first_call(self):
        """Loads model on first call."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        with patch('scrubiq.image_protection.face_detection.cv2.FaceDetectorYN') as mock_yd:
            with patch.object(Path, 'exists', return_value=True):
                mock_yd.create.return_value = MagicMock()

                detector._ensure_loaded(640, 480)

                mock_yd.create.assert_called_once()
                assert detector._current_input_size == (640, 480)

    def test_updates_input_size_when_changed(self):
        """Updates input size when image dimensions change."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()
        mock_det = MagicMock()
        detector._detector = mock_det
        detector._current_input_size = (640, 480)

        # Different size - should update
        with patch.object(Path, 'exists', return_value=True):
            detector._ensure_loaded(800, 600)

            mock_det.setInputSize.assert_called_once_with((800, 600))
            assert detector._current_input_size == (800, 600)


# =============================================================================
# DEFAULT MODEL PATH TESTS
# =============================================================================

class TestDefaultModelPath:
    """Tests for default model path."""

    def test_default_path_is_valid_path(self):
        """DEFAULT_MODEL_PATH is a valid Path."""
        from scrubiq.image_protection.face_detection import DEFAULT_MODEL_PATH

        assert isinstance(DEFAULT_MODEL_PATH, Path)
        assert DEFAULT_MODEL_PATH.name == "face_detection_yunet_2023mar.onnx"

    def test_default_path_in_scrubiq_models(self):
        """DEFAULT_MODEL_PATH is in .scrubiq/models."""
        from scrubiq.image_protection.face_detection import DEFAULT_MODEL_PATH

        assert ".scrubiq" in str(DEFAULT_MODEL_PATH)
        assert "models" in str(DEFAULT_MODEL_PATH)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests for face detection."""

    def test_detect_returns_valid_result_structure(self):
        """detect() returns properly structured result."""
        from scrubiq.image_protection.face_detection import (
            FaceDetector, FaceDetectionResult
        )

        detector = FaceDetector()

        # Create a valid BGR image
        image = np.zeros((200, 200, 3), dtype=np.uint8)

        with patch.object(detector, '_ensure_loaded'):
            # Mock detector that returns some faces
            mock_det = MagicMock()
            # YuNet returns (_, array) where array is Nx15 for N faces
            # Columns: x, y, w, h, x_re, y_re, x_le, y_le, x_nt, y_nt, x_rcm, y_rcm, x_lcm, y_lcm, confidence
            fake_faces = np.array([
                [10, 20, 50, 60, 15, 30, 45, 30, 30, 45, 20, 55, 40, 55, 0.95]
            ])
            mock_det.detect.return_value = (None, fake_faces)
            detector._detector = mock_det

            result = detector.detect(image)

            assert isinstance(result, FaceDetectionResult)
            assert result.image_width == 200
            assert result.image_height == 200


# =============================================================================
# DETECT FROM PATH/BYTES TESTS
# =============================================================================

class TestDetectFromPath:
    """Tests for detect_from_path method."""

    def test_invalid_path_raises(self):
        """Invalid path raises ValueError."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        with pytest.raises(ValueError, match="Could not load image"):
            detector.detect_from_path("/nonexistent/image.jpg")

    def test_valid_path_processes(self, tmp_path):
        """Valid path processes image."""
        from scrubiq.image_protection.face_detection import FaceDetector
        import cv2

        detector = FaceDetector()

        # Create test image file
        image = np.zeros((100, 100, 3), dtype=np.uint8)
        image_path = tmp_path / "test_face.png"
        cv2.imwrite(str(image_path), image)

        with patch.object(detector, '_ensure_loaded'):
            mock_det = MagicMock()
            mock_det.detect.return_value = (None, None)
            detector._detector = mock_det

            result = detector.detect_from_path(str(image_path))

            assert result.image_width == 100
            assert result.image_height == 100


class TestDetectFromBytes:
    """Tests for detect_from_bytes method."""

    def test_invalid_bytes_raises(self):
        """Invalid bytes raises ValueError."""
        from scrubiq.image_protection.face_detection import FaceDetector

        detector = FaceDetector()

        with pytest.raises(ValueError, match="Could not decode image"):
            detector.detect_from_bytes(b"not an image")

    def test_valid_bytes_processes(self):
        """Valid image bytes are processed."""
        from scrubiq.image_protection.face_detection import FaceDetector
        import cv2

        detector = FaceDetector()

        image = np.zeros((80, 80, 3), dtype=np.uint8)
        _, img_bytes = cv2.imencode('.png', image)

        with patch.object(detector, '_ensure_loaded'):
            mock_det = MagicMock()
            mock_det.detect.return_value = (None, None)
            detector._detector = mock_det

            result = detector.detect_from_bytes(img_bytes.tobytes())

            assert result.image_width == 80
            assert result.image_height == 80


# =============================================================================
# REDACT FACES TESTS
# =============================================================================

class TestRedactFaces:
    """Tests for redact_faces function."""

    def test_black_method(self):
        """Black method blacks out face regions."""
        from scrubiq.image_protection.face_detection import redact_faces, FaceDetection

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        detections = [FaceDetection(x=20, y=20, width=30, height=30, confidence=0.9)]

        result = redact_faces(image, detections, method="black", padding=0)

        assert np.all(result[20:50, 20:50] == 0)

    def test_blur_method(self):
        """Blur method blurs face regions."""
        from scrubiq.image_protection.face_detection import redact_faces, FaceDetection

        image = np.ones((100, 100, 3), dtype=np.uint8) * 128
        image[35:45, 35:45] = 255
        detections = [FaceDetection(x=30, y=30, width=20, height=20, confidence=0.9)]

        result = redact_faces(image, detections, method="blur", padding=0)

        # Blurred region should differ from original
        assert not np.array_equal(result[30:50, 30:50], image[30:50, 30:50])

    def test_pixelate_method(self):
        """Pixelate method pixelates face regions."""
        from scrubiq.image_protection.face_detection import redact_faces, FaceDetection

        image = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        detections = [FaceDetection(x=20, y=20, width=40, height=40, confidence=0.9)]

        result = redact_faces(image, detections, method="pixelate", padding=0)

        # Pixelated region should differ
        assert not np.array_equal(result[20:60, 20:60], image[20:60, 20:60])

    def test_padding_applies(self):
        """Padding expands redaction area."""
        from scrubiq.image_protection.face_detection import redact_faces, FaceDetection

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        detections = [FaceDetection(x=40, y=40, width=20, height=20, confidence=0.9)]

        result = redact_faces(image, detections, method="black", padding=0.5)

        # With 50% padding, should expand by 10 pixels
        assert np.all(result[30:70, 30:70] == 0)

    def test_empty_detections(self):
        """Empty detections returns copy of original."""
        from scrubiq.image_protection.face_detection import redact_faces

        image = np.ones((50, 50, 3), dtype=np.uint8) * 128

        result = redact_faces(image, [], method="black", padding=0)

        assert np.array_equal(result, image)

    def test_boundary_clamping(self):
        """Regions extending past boundaries are clamped."""
        from scrubiq.image_protection.face_detection import redact_faces, FaceDetection

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        detections = [FaceDetection(x=80, y=80, width=50, height=50, confidence=0.9)]

        # Should not raise
        result = redact_faces(image, detections, method="black", padding=0.2)
        assert result.shape == image.shape


# =============================================================================
# REDACTION METHOD ENUM TESTS
# =============================================================================

class TestRedactionMethodEnum:
    """Tests for RedactionMethod enum."""

    def test_black_value(self):
        """BLACK value should be 'black'."""
        from scrubiq.image_protection.face_detection import RedactionMethod

        assert RedactionMethod.BLACK.value == "black"

    def test_blur_value(self):
        """BLUR value should be 'blur'."""
        from scrubiq.image_protection.face_detection import RedactionMethod

        assert RedactionMethod.BLUR.value == "blur"

    def test_pixelate_value(self):
        """PIXELATE value should be 'pixelate'."""
        from scrubiq.image_protection.face_detection import RedactionMethod

        assert RedactionMethod.PIXELATE.value == "pixelate"


# =============================================================================
# FACE REDACTION RESULT TESTS
# =============================================================================

class TestFaceRedactionResult:
    """Tests for FaceRedactionResult dataclass."""

    def test_creation(self):
        """FaceRedactionResult can be created."""
        from scrubiq.image_protection.face_detection import FaceRedactionResult

        result = FaceRedactionResult(
            faces_detected=2,
            faces_redacted=2,
            detections=[],
            processing_time_ms=25.0,
            redaction_method="blur",
            image_width=640,
            image_height=480,
        )

        assert result.faces_detected == 2
        assert result.faces_redacted == 2
        assert result.redaction_method == "blur"

    def test_redaction_applied_true(self):
        """redaction_applied returns True when faces redacted."""
        from scrubiq.image_protection.face_detection import FaceRedactionResult

        result = FaceRedactionResult(
            faces_detected=1, faces_redacted=1, detections=[],
            processing_time_ms=10, redaction_method="blur",
            image_width=100, image_height=100
        )

        assert result.redaction_applied is True

    def test_redaction_applied_false(self):
        """redaction_applied returns False when no faces redacted."""
        from scrubiq.image_protection.face_detection import FaceRedactionResult

        result = FaceRedactionResult(
            faces_detected=0, faces_redacted=0, detections=[],
            processing_time_ms=10, redaction_method="blur",
            image_width=100, image_height=100
        )

        assert result.redaction_applied is False

    def test_to_audit_dict(self):
        """to_audit_dict returns audit-safe dict."""
        from scrubiq.image_protection.face_detection import FaceRedactionResult

        result = FaceRedactionResult(
            faces_detected=3, faces_redacted=3, detections=[],
            processing_time_ms=45.678, redaction_method="pixelate",
            image_width=1920, image_height=1080
        )

        audit = result.to_audit_dict()

        assert audit["faces_detected"] == 3
        assert audit["faces_redacted"] == 3
        assert audit["redaction_method"] == "pixelate"
        assert audit["processing_time_ms"] == 45.7
        assert audit["image_size"] == "1920x1080"


# =============================================================================
# FACE REDACTOR TESTS
# =============================================================================

class TestFaceRedactor:
    """Tests for FaceRedactor class."""

    def test_initialization_defaults(self):
        """FaceRedactor initializes with defaults."""
        from scrubiq.image_protection.face_detection import FaceRedactor, RedactionMethod

        redactor = FaceRedactor()

        assert redactor.method == RedactionMethod.BLUR
        assert redactor.padding == 0.1

    def test_initialization_custom(self):
        """FaceRedactor accepts custom parameters."""
        from scrubiq.image_protection.face_detection import FaceRedactor, RedactionMethod

        redactor = FaceRedactor(
            method=RedactionMethod.PIXELATE,
            padding=0.2,
        )

        assert redactor.method == RedactionMethod.PIXELATE
        assert redactor.padding == 0.2

    def test_redact_with_no_faces(self):
        """Redact handles no faces gracefully."""
        from scrubiq.image_protection.face_detection import FaceRedactor, FaceDetector

        mock_detector = MagicMock(spec=FaceDetector)
        mock_detector.detect.return_value = MagicMock(
            faces_detected=0,
            detections=[],
            image_width=100,
            image_height=100,
        )

        redactor = FaceRedactor(detector=mock_detector)

        image = np.ones((100, 100, 3), dtype=np.uint8) * 128
        result, redacted_image = redactor.redact(image)

        assert result.faces_detected == 0
        assert result.faces_redacted == 0

    def test_redact_with_faces(self):
        """Redact processes detected faces."""
        from scrubiq.image_protection.face_detection import (
            FaceRedactor, FaceDetector, FaceDetection
        )

        mock_detector = MagicMock(spec=FaceDetector)
        mock_detector.detect.return_value = MagicMock(
            faces_detected=1,
            detections=[FaceDetection(x=20, y=20, width=30, height=30, confidence=0.9)],
            image_width=100,
            image_height=100,
        )

        redactor = FaceRedactor(detector=mock_detector)

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        result, redacted_image = redactor.redact(image)

        assert result.faces_detected == 1
        assert result.faces_redacted == 1


# =============================================================================
# FACE PROTECTOR TESTS
# =============================================================================

class TestFaceProtector:
    """Tests for FaceProtector class."""

    def test_initialization(self):
        """FaceProtector initializes correctly."""
        from scrubiq.image_protection.face_detection import FaceProtector

        protector = FaceProtector()

        assert protector._initialized is False
        assert protector._loading is False
        assert protector._detector is None

    def test_is_available_false_when_no_model(self):
        """is_available returns False when model missing."""
        from scrubiq.image_protection.face_detection import FaceProtector

        with patch.object(Path, 'exists', return_value=False):
            protector = FaceProtector()
            assert protector.is_available is False

    def test_is_initialized_property(self):
        """is_initialized reflects initialization state."""
        from scrubiq.image_protection.face_detection import FaceProtector

        protector = FaceProtector()
        assert protector.is_initialized is False

        protector._initialized = True
        assert protector.is_initialized is True

    def test_is_loading_property(self):
        """is_loading reflects loading state."""
        from scrubiq.image_protection.face_detection import FaceProtector

        protector = FaceProtector()
        assert protector.is_loading is False

        protector._loading = True
        assert protector.is_loading is True

    def test_warm_up_when_not_available(self):
        """warm_up handles missing model gracefully."""
        from scrubiq.image_protection.face_detection import FaceProtector

        protector = FaceProtector()

        with patch.object(protector, '_ensure_initialized', side_effect=FileNotFoundError("Model not found")):
            result = protector.warm_up()
            assert result is False


# =============================================================================
# MODULE LEVEL FUNCTIONS TESTS
# =============================================================================

class TestModuleFunctions:
    """Tests for module-level functions."""

    def test_get_detector_returns_singleton(self):
        """get_detector returns singleton."""
        from scrubiq.image_protection.face_detection import get_detector
        import scrubiq.image_protection.face_detection as module

        # Reset singleton
        module._default_detector = None

        d1 = get_detector()
        d2 = get_detector()

        assert d1 is d2

    def test_detect_faces_uses_default_detector(self):
        """detect_faces uses default detector."""
        from scrubiq.image_protection.face_detection import detect_faces

        image = np.zeros((100, 100, 3), dtype=np.uint8)

        with patch('scrubiq.image_protection.face_detection.get_detector') as mock_get:
            mock_detector = MagicMock()
            mock_detector.detect.return_value = MagicMock(faces_detected=0, detections=[])
            mock_get.return_value = mock_detector

            detect_faces(image)

            mock_detector.detect.assert_called_once()

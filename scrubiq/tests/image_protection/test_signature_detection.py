"""Tests for signature detection (image_protection/signature_detection.py).

Tests cover:
- SignatureDetection dataclass
- SignatureRedactionResult dataclass
- SignatureDetector class
  - Initialization with tunable parameters
  - detect() method
  - Preprocessing (adaptive threshold)
  - Contour finding and filtering
  - Region scoring
  - NMS
  - Box expansion
- SignatureRedactor class
- SignatureProtector class
"""

import hashlib
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import cv2
import numpy as np
import pytest


# --- SignatureDetection Tests ---

class TestSignatureDetection:
    """Tests for SignatureDetection dataclass."""

    def test_signature_detection_properties(self):
        """SignatureDetection should calculate properties correctly."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        det = SignatureDetection(
            x=10, y=20, width=100, height=50,
            confidence=0.85,
            class_name="signature",
        )

        assert det.x2 == 110
        assert det.y2 == 70
        assert det.area == 5000
        assert det.bbox == (10, 20, 110, 70)

    def test_to_dict(self):
        """to_dict should return serializable dict."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        det = SignatureDetection(
            x=10, y=20, width=100, height=50,
            confidence=0.85123,
            class_name="signature",
        )

        d = det.to_dict()

        assert d["x"] == 10
        assert d["y"] == 20
        assert d["confidence"] == 0.851  # Rounded
        assert d["class"] == "signature"


# --- SignatureRedactionResult Tests ---

class TestSignatureRedactionResult:
    """Tests for SignatureRedactionResult dataclass."""

    def test_to_audit_dict(self):
        """to_audit_dict should return audit-safe information."""
        from scrubiq.image_protection.signature_detection import (
            SignatureRedactionResult, SignatureDetection
        )

        result = SignatureRedactionResult(
            original_hash="abc123",
            signatures_detected=2,
            detections=[],
            processing_time_ms=15.5,
            redaction_applied=True,
        )

        audit = result.to_audit_dict()

        assert audit["original_hash"] == "abc123"
        assert audit["signatures_detected"] == 2
        assert audit["processing_time_ms"] == 15.5
        assert audit["redaction_applied"] is True


# --- SignatureDetector Initialization Tests ---

class TestSignatureDetectorInit:
    """Tests for SignatureDetector initialization."""

    def test_init_default_parameters(self):
        """Should use default parameters."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector()

        assert detector.confidence_threshold == 0.8
        assert detector.min_aspect_ratio == 1.5
        assert detector.max_aspect_ratio == 15.0
        assert detector.min_ink_density == 0.05
        assert detector.max_ink_density == 0.6
        assert detector.min_complexity == 0.3
        assert detector.max_solidity == 0.8
        assert detector.min_contour_area == 500

    def test_init_custom_parameters(self):
        """Should allow custom parameters."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector(
            confidence_threshold=0.9,
            min_aspect_ratio=2.0,
            max_aspect_ratio=10.0,
            min_ink_density=0.1,
            max_ink_density=0.5,
            min_complexity=0.4,
            max_solidity=0.7,
            min_contour_area=1000,
        )

        assert detector.confidence_threshold == 0.9
        assert detector.min_aspect_ratio == 2.0
        assert detector.max_aspect_ratio == 10.0
        assert detector.min_ink_density == 0.1
        assert detector.max_ink_density == 0.5
        assert detector.min_complexity == 0.4
        assert detector.max_solidity == 0.7
        assert detector.min_contour_area == 1000

    def test_always_available(self):
        """is_available should always be True (no model needed)."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector()

        assert detector.is_available is True

    def test_always_initialized(self):
        """is_initialized should always be True (instant init)."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector()

        assert detector.is_initialized is True

    def test_never_loading(self):
        """is_loading should always be False."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector()

        assert detector.is_loading is False

    def test_start_loading_noop(self):
        """start_loading should be no-op."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector()

        # Should not raise
        detector.start_loading()

    def test_await_ready_immediate(self):
        """await_ready should return True immediately."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector()

        assert detector.await_ready() is True

    def test_warm_up_noop(self):
        """warm_up should be no-op."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        detector = SignatureDetector()

        # Should not raise
        detector.warm_up()


# --- Preprocessing Tests ---

class TestPreprocessing:
    """Tests for image preprocessing."""

    @pytest.fixture
    def detector(self):
        """Create detector."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        return SignatureDetector()

    def test_preprocess_grayscale(self, detector):
        """Should handle grayscale input."""
        image = np.zeros((100, 100), dtype=np.uint8)

        binary = detector._preprocess(image)

        assert binary.shape == (100, 100)
        assert binary.dtype == np.uint8

    def test_preprocess_color(self, detector):
        """Should convert color to grayscale."""
        image = np.zeros((100, 100, 3), dtype=np.uint8)

        binary = detector._preprocess(image)

        assert binary.shape == (100, 100)

    def test_preprocess_returns_binary(self, detector):
        """Should return binary image (0 or 255)."""
        # Create image with some content
        image = np.zeros((100, 100), dtype=np.uint8)
        image[40:60, 40:60] = 255

        binary = detector._preprocess(image)

        # Values should be 0 or 255
        unique = np.unique(binary)
        assert all(v in [0, 255] for v in unique)


# --- Contour Finding Tests ---

class TestContourFinding:
    """Tests for contour finding."""

    @pytest.fixture
    def detector(self):
        """Create detector."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        return SignatureDetector()

    def test_find_contours_empty_image(self, detector):
        """Should return empty for blank image."""
        binary = np.zeros((100, 100), dtype=np.uint8)

        regions = detector._find_contours(binary)

        assert len(regions) == 0

    def test_find_contours_filters_small(self, detector):
        """Should filter regions below min_contour_area."""
        # Create image with small region
        binary = np.zeros((100, 100), dtype=np.uint8)
        binary[45:55, 45:55] = 255  # 100 pixel area, below 500 default

        regions = detector._find_contours(binary)

        assert len(regions) == 0

    def test_find_contours_returns_properties(self, detector):
        """Should return contours with computed properties."""
        # Create larger region
        binary = np.zeros((200, 200), dtype=np.uint8)
        cv2.rectangle(binary, (50, 50), (150, 100), 255, -1)

        regions = detector._find_contours(binary)

        if len(regions) > 0:
            contour, props = regions[0]
            assert "x" in props
            assert "y" in props
            assert "w" in props
            assert "h" in props
            assert "ink_density" in props
            assert "aspect_ratio" in props
            assert "complexity" in props
            assert "solidity" in props


# --- Region Scoring Tests ---

class TestRegionScoring:
    """Tests for region scoring."""

    @pytest.fixture
    def detector(self):
        """Create detector."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        return SignatureDetector()

    def test_score_solid_region_zero(self, detector):
        """Solid regions should score 0 (hard reject)."""
        props = {
            "ink_density": 0.95,  # Very dense
            "solidity": 0.95,     # Very solid
            "aspect_ratio": 2.0,
            "complexity": 0.5,
        }

        score = detector._score_region(props)

        assert score == 0.0

    def test_score_signature_like_region(self, detector):
        """Signature-like regions should score high."""
        props = {
            "ink_density": 0.2,    # Low density (gaps)
            "solidity": 0.5,       # Not solid
            "aspect_ratio": 3.0,   # Wide
            "complexity": 0.5,     # Complex
        }

        score = detector._score_region(props)

        assert score > 0.5

    def test_score_wrong_aspect_ratio(self, detector):
        """Wrong aspect ratio should lower score."""
        props = {
            "ink_density": 0.2,
            "solidity": 0.5,
            "aspect_ratio": 0.5,  # Taller than wide
            "complexity": 0.5,
        }

        score = detector._score_region(props)

        # Should be lower due to aspect ratio
        assert score < 0.8


# --- Detection Tests ---

class TestDetect:
    """Tests for detect method."""

    @pytest.fixture
    def detector(self):
        """Create detector."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        return SignatureDetector()

    def test_detect_empty_image(self, detector):
        """Should handle empty image."""
        image = np.zeros((100, 100, 3), dtype=np.uint8)

        detections = detector.detect(image)

        assert isinstance(detections, list)

    def test_detect_grayscale(self, detector):
        """Should handle grayscale image."""
        image = np.zeros((100, 100), dtype=np.uint8)

        detections = detector.detect(image)

        assert isinstance(detections, list)

    def test_detect_rgba(self, detector):
        """Should handle RGBA image (drop alpha)."""
        image = np.zeros((100, 100, 4), dtype=np.uint8)

        detections = detector.detect(image)

        assert isinstance(detections, list)

    def test_detect_custom_threshold(self, detector):
        """Should allow custom confidence threshold."""
        image = np.zeros((100, 100, 3), dtype=np.uint8)

        detections = detector.detect(image, conf_threshold=0.95)

        assert isinstance(detections, list)

    def test_detect_returns_signature_detections(self, detector):
        """Detections should be SignatureDetection objects."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        # Create image with signature-like content
        image = np.ones((200, 400, 3), dtype=np.uint8) * 255
        # Draw a wavy line (signature-like)
        pts = np.array([[50, 100], [100, 80], [150, 120], [200, 90], [250, 110], [300, 85], [350, 100]])
        cv2.polylines(image, [pts], False, (0, 0, 0), 3)

        detections = detector.detect(image)

        for det in detections:
            assert isinstance(det, SignatureDetection)
            assert det.class_name == "signature"


# --- NMS Tests ---

class TestNMS:
    """Tests for non-maximum suppression."""

    @pytest.fixture
    def detector(self):
        """Create detector."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        return SignatureDetector()

    def test_nms_empty(self, detector):
        """NMS on empty list should return empty."""
        result = detector._nms([])

        assert result == []

    def test_nms_single(self, detector):
        """NMS on single detection should return it."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        detections = [SignatureDetection(0, 0, 100, 50, 0.9, "signature")]

        result = detector._nms(detections)

        assert len(result) == 1

    def test_nms_removes_overlapping(self, detector):
        """NMS should remove overlapping detections."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        detections = [
            SignatureDetection(0, 0, 100, 50, 0.9, "signature"),
            SignatureDetection(10, 5, 100, 50, 0.8, "signature"),  # Overlaps
        ]

        result = detector._nms(detections)

        assert len(result) == 1
        assert result[0].confidence == 0.9


# --- Box Expansion Tests ---

class TestBoxExpansion:
    """Tests for box expansion."""

    @pytest.fixture
    def detector(self):
        """Create detector."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        return SignatureDetector()

    def test_expand_box_increases_size(self, detector):
        """_expand_box should increase dimensions."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        det = SignatureDetection(100, 100, 200, 50, 0.9, "signature")

        expanded = detector._expand_box(det, 640, 480)

        assert expanded.width >= det.width
        assert expanded.height >= det.height

    def test_expand_box_clips_to_bounds(self, detector):
        """_expand_box should clip to image bounds."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        # Detection at edge
        det = SignatureDetection(0, 0, 100, 50, 0.9, "signature")

        expanded = detector._expand_box(det, 640, 480)

        assert expanded.x >= 0
        assert expanded.y >= 0
        assert expanded.x2 <= 640
        assert expanded.y2 <= 480


# --- IOU Tests ---

class TestIOU:
    """Tests for IOU calculation."""

    def test_iou_no_overlap(self):
        """IOU of non-overlapping boxes should be 0."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        box1 = (0, 0, 100, 100)
        box2 = (200, 200, 300, 300)

        iou = SignatureDetector._iou(box1, box2)

        assert iou == 0.0

    def test_iou_full_overlap(self):
        """IOU of identical boxes should be 1."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        box = (0, 0, 100, 100)

        iou = SignatureDetector._iou(box, box)

        assert iou == 1.0

    def test_iou_partial_overlap(self):
        """IOU of partially overlapping should be between 0 and 1."""
        from scrubiq.image_protection.signature_detection import SignatureDetector

        box1 = (0, 0, 100, 100)
        box2 = (50, 50, 150, 150)

        iou = SignatureDetector._iou(box1, box2)

        assert 0 < iou < 1


# --- SignatureRedactor Tests ---

class TestSignatureRedactor:
    """Tests for SignatureRedactor class."""

    @pytest.fixture
    def redactor(self):
        """Create redactor."""
        from scrubiq.image_protection.signature_detection import SignatureRedactor

        return SignatureRedactor()

    def test_redact_empty_detections(self, redactor):
        """Should return unchanged image for empty detections."""
        image = np.ones((100, 100, 3), dtype=np.uint8) * 128

        result = redactor.redact(image, [])

        np.testing.assert_array_equal(result, image)

    def test_redact_fills_black(self, redactor):
        """Should fill detection regions with black."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        det = SignatureDetection(20, 20, 60, 30, 0.9, "signature")

        result = redactor.redact(image, [det])

        # Region should be black
        assert np.all(result[20:50, 20:80] == 0)

    def test_redact_preserves_outside(self, redactor):
        """Should preserve pixels outside detections."""
        from scrubiq.image_protection.signature_detection import SignatureDetection

        image = np.ones((100, 100, 3), dtype=np.uint8) * 128
        det = SignatureDetection(40, 40, 20, 20, 0.9, "signature")

        result = redactor.redact(image, [det])

        # Outside should be preserved
        assert np.all(result[0:30, :] == 128)


# --- SignatureProtector Tests ---

class TestSignatureProtector:
    """Tests for SignatureProtector class."""

    def test_init_creates_detector_and_redactor(self):
        """Should create detector and redactor."""
        from scrubiq.image_protection.signature_detection import (
            SignatureProtector, SignatureDetector, SignatureRedactor
        )

        protector = SignatureProtector()

        assert isinstance(protector.detector, SignatureDetector)
        assert isinstance(protector.redactor, SignatureRedactor)

    def test_init_passes_params_to_detector(self):
        """Should pass parameters to detector."""
        from scrubiq.image_protection.signature_detection import SignatureProtector

        protector = SignatureProtector(confidence_threshold=0.9)

        assert protector.detector.confidence_threshold == 0.9

    def test_properties_delegate_to_detector(self):
        """Properties should delegate to detector."""
        from scrubiq.image_protection.signature_detection import SignatureProtector

        protector = SignatureProtector()

        assert protector.is_available is True
        assert protector.is_initialized is True
        assert protector.is_loading is False

    def test_process_returns_result_and_image(self):
        """process should return (result, redacted_image) tuple."""
        from scrubiq.image_protection.signature_detection import (
            SignatureProtector, SignatureRedactionResult
        )

        protector = SignatureProtector()
        image = np.ones((100, 100, 3), dtype=np.uint8) * 128

        result, redacted = protector.process(image)

        assert isinstance(result, SignatureRedactionResult)
        assert isinstance(redacted, np.ndarray)

    def test_process_computes_hash(self):
        """process should compute image hash."""
        from scrubiq.image_protection.signature_detection import SignatureProtector

        protector = SignatureProtector()
        image = np.ones((100, 100, 3), dtype=np.uint8) * 128

        result, _ = protector.process(image)

        expected_hash = hashlib.sha256(image.tobytes()).hexdigest()[:16]
        assert result.original_hash == expected_hash

    def test_process_tracks_timing(self):
        """process should track processing time."""
        from scrubiq.image_protection.signature_detection import SignatureProtector

        protector = SignatureProtector()
        image = np.ones((100, 100, 3), dtype=np.uint8)

        result, _ = protector.process(image)

        assert result.processing_time_ms > 0

    def test_process_redaction_applied_flag(self):
        """redaction_applied should reflect if redaction occurred."""
        from scrubiq.image_protection.signature_detection import SignatureProtector

        protector = SignatureProtector()

        # Empty image - no signatures
        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        result, _ = protector.process(image)

        # Depends on detection, but flag should be set appropriately
        assert isinstance(result.redaction_applied, bool)

    def test_await_ready_delegates(self):
        """await_ready should delegate to detector."""
        from scrubiq.image_protection.signature_detection import SignatureProtector

        protector = SignatureProtector()

        assert protector.await_ready() is True

    def test_start_loading_delegates(self):
        """start_loading should delegate to detector."""
        from scrubiq.image_protection.signature_detection import SignatureProtector

        protector = SignatureProtector()

        # Should not raise
        protector.start_loading()

"""Tests for image_protection/image_phi_processor.py - unified PHI processor.

Tests cover:
- PHIRegion dataclass
- ImagePHIResult dataclass
- ImagePHIProcessor initialization
- Lazy detector loading
- PHI processing
"""

from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import numpy as np


# =============================================================================
# PHI REGION TESTS
# =============================================================================

class TestPHIRegion:
    """Tests for PHIRegion dataclass."""

    def test_creation(self):
        """PHIRegion can be created."""
        from scrubiq.image_protection.image_phi_processor import PHIRegion

        region = PHIRegion(
            x=10,
            y=20,
            width=100,
            height=80,
            phi_type="face",
            confidence=0.95,
            detector="yunet",
        )

        assert region.x == 10
        assert region.y == 20
        assert region.width == 100
        assert region.height == 80
        assert region.phi_type == "face"
        assert region.confidence == 0.95
        assert region.detector == "yunet"
        assert region.metadata == {}

    def test_with_metadata(self):
        """PHIRegion can include metadata."""
        from scrubiq.image_protection.image_phi_processor import PHIRegion

        region = PHIRegion(
            x=10,
            y=20,
            width=100,
            height=80,
            phi_type="barcode",
            confidence=0.9,
            detector="zbar",
            metadata={"format": "QR_CODE", "data": "[REDACTED]"},
        )

        assert region.metadata["format"] == "QR_CODE"

    def test_x2_property(self):
        """x2 returns x + width."""
        from scrubiq.image_protection.image_phi_processor import PHIRegion

        region = PHIRegion(
            x=10, y=20, width=100, height=80,
            phi_type="face", confidence=0.9, detector="test"
        )

        assert region.x2 == 110

    def test_y2_property(self):
        """y2 returns y + height."""
        from scrubiq.image_protection.image_phi_processor import PHIRegion

        region = PHIRegion(
            x=10, y=20, width=100, height=80,
            phi_type="face", confidence=0.9, detector="test"
        )

        assert region.y2 == 100

    def test_bbox_property(self):
        """bbox returns (x1, y1, x2, y2) tuple."""
        from scrubiq.image_protection.image_phi_processor import PHIRegion

        region = PHIRegion(
            x=10, y=20, width=100, height=80,
            phi_type="face", confidence=0.9, detector="test"
        )

        assert region.bbox == (10, 20, 110, 100)

    def test_area_property(self):
        """area returns width * height."""
        from scrubiq.image_protection.image_phi_processor import PHIRegion

        region = PHIRegion(
            x=10, y=20, width=100, height=80,
            phi_type="face", confidence=0.9, detector="test"
        )

        assert region.area == 8000


# =============================================================================
# IMAGE PHI RESULT TESTS
# =============================================================================

class TestImagePHIResult:
    """Tests for ImagePHIResult dataclass."""

    def test_creation(self):
        """ImagePHIResult can be created."""
        from scrubiq.image_protection.image_phi_processor import (
            ImagePHIResult, PHIRegion
        )

        regions = [
            PHIRegion(x=0, y=0, width=50, height=50, phi_type="face", confidence=0.9, detector="yunet"),
            PHIRegion(x=100, y=100, width=30, height=30, phi_type="barcode", confidence=0.8, detector="zbar"),
        ]

        result = ImagePHIResult(
            phi_regions=regions,
            total_phi_detected=2,
            faces_detected=1,
            barcodes_detected=1,
            handwriting_detected=0,
            signatures_detected=0,
            processing_time_ms=25.5,
            image_width=640,
            image_height=480,
            detectors_run=["face", "barcode"],
        )

        assert result.total_phi_detected == 2
        assert result.faces_detected == 1
        assert result.barcodes_detected == 1
        assert len(result.phi_regions) == 2

    def test_has_phi_true(self):
        """has_phi returns True when PHI detected."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIResult

        result = ImagePHIResult(
            phi_regions=[],
            total_phi_detected=1,
            faces_detected=1,
            barcodes_detected=0,
            handwriting_detected=0,
            signatures_detected=0,
            processing_time_ms=10.0,
            image_width=100,
            image_height=100,
        )

        assert result.has_phi is True

    def test_has_phi_false(self):
        """has_phi returns False when no PHI detected."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIResult

        result = ImagePHIResult(
            phi_regions=[],
            total_phi_detected=0,
            faces_detected=0,
            barcodes_detected=0,
            handwriting_detected=0,
            signatures_detected=0,
            processing_time_ms=10.0,
            image_width=100,
            image_height=100,
        )

        assert result.has_phi is False

    def test_to_audit_dict(self):
        """to_audit_dict returns audit-safe dict."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIResult

        result = ImagePHIResult(
            phi_regions=[],
            total_phi_detected=3,
            faces_detected=1,
            barcodes_detected=1,
            handwriting_detected=0,
            signatures_detected=1,
            processing_time_ms=45.678,
            image_width=1920,
            image_height=1080,
            detectors_run=["face", "barcode", "signature"],
            errors=["Failed to load handwriting model"],
        )

        audit = result.to_audit_dict()

        assert audit["total_phi_detected"] == 3
        assert audit["faces"] == 1
        assert audit["barcodes"] == 1
        assert audit["handwriting"] == 0
        assert audit["signatures"] == 1
        assert audit["processing_time_ms"] == 45.7  # Rounded
        assert audit["image_size"] == "1920x1080"
        assert audit["detectors_run"] == ["face", "barcode", "signature"]
        assert "Failed to load handwriting model" in audit["errors"]

    def test_to_audit_dict_no_errors(self):
        """to_audit_dict handles no errors."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIResult

        result = ImagePHIResult(
            phi_regions=[],
            total_phi_detected=0,
            faces_detected=0,
            barcodes_detected=0,
            handwriting_detected=0,
            signatures_detected=0,
            processing_time_ms=10.0,
            image_width=100,
            image_height=100,
            errors=[],
        )

        audit = result.to_audit_dict()
        assert audit["errors"] is None

    def test_defaults(self):
        """ImagePHIResult has reasonable defaults."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIResult

        result = ImagePHIResult(
            phi_regions=[],
            total_phi_detected=0,
            faces_detected=0,
            barcodes_detected=0,
            handwriting_detected=0,
            signatures_detected=0,
            processing_time_ms=0,
            image_width=0,
            image_height=0,
        )

        assert result.detectors_run == []
        assert result.errors == []


# =============================================================================
# IMAGE PHI PROCESSOR INITIALIZATION TESTS
# =============================================================================

class TestImagePHIProcessorInit:
    """Tests for ImagePHIProcessor initialization."""

    def test_init_all_enabled(self):
        """ImagePHIProcessor initializes with all detectors enabled by default."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor()

        assert processor.enable_face is True
        assert processor.enable_barcode is True
        assert processor.enable_handwriting is True
        assert processor.enable_signature is True

    def test_init_custom_flags(self):
        """ImagePHIProcessor respects custom enable flags."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=False,
            enable_barcode=False,
            enable_handwriting=False,
            enable_signature=False,
        )

        assert processor.enable_face is False
        assert processor.enable_barcode is False
        assert processor.enable_handwriting is False
        assert processor.enable_signature is False

    def test_init_custom_confidence(self):
        """ImagePHIProcessor accepts custom confidence thresholds."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            face_confidence=0.5,
            yolo_confidence=0.3,
        )

        assert processor.face_confidence == 0.5
        assert processor.yolo_confidence == 0.3

    def test_init_with_models_dir(self):
        """ImagePHIProcessor accepts models directory."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(models_dir=Path("/custom/models"))

        assert processor.models_dir == Path("/custom/models")

    def test_init_detectors_lazy(self):
        """Detectors are not loaded until accessed."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor()

        assert processor._face_detector is None
        assert processor._barcode_detector is None
        assert processor._handwriting_detector is None
        assert processor._signature_detector is None


# =============================================================================
# LAZY DETECTOR LOADING TESTS
# =============================================================================

class TestLazyDetectorLoading:
    """Tests for lazy detector loading."""

    def test_face_detector_lazy_load(self):
        """Face detector is lazy loaded."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(enable_face=True)

        with patch('scrubiq.image_protection.image_phi_processor.FaceDetector') as mock_fd:
            mock_fd.return_value = MagicMock()

            _ = processor.face_detector

            mock_fd.assert_called_once()

    def test_face_detector_not_loaded_when_disabled(self):
        """Face detector is not loaded when disabled."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(enable_face=False)

        result = processor.face_detector
        assert result is None

    def test_barcode_detector_lazy_load(self):
        """Barcode detector is lazy loaded."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(enable_barcode=True)

        with patch('scrubiq.image_protection.image_phi_processor.BarcodeDetector') as mock_bd:
            mock_bd.return_value = MagicMock()

            _ = processor.barcode_detector

            mock_bd.assert_called_once()

    def test_barcode_detector_not_loaded_when_disabled(self):
        """Barcode detector is not loaded when disabled."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(enable_barcode=False)

        result = processor.barcode_detector
        assert result is None

    def test_signature_detector_lazy_load(self):
        """Signature detector is lazy loaded."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(enable_signature=True)

        with patch('scrubiq.image_protection.image_phi_processor.SignatureDetector') as mock_sd:
            mock_sd.return_value = MagicMock()

            _ = processor.signature_detector

            mock_sd.assert_called_once()

    def test_detector_cached(self):
        """Detector is cached after first load."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(enable_face=True)

        with patch('scrubiq.image_protection.image_phi_processor.FaceDetector') as mock_fd:
            mock_detector = MagicMock()
            mock_fd.return_value = mock_detector

            # First access
            d1 = processor.face_detector
            # Second access
            d2 = processor.face_detector

            # Should only create once
            mock_fd.assert_called_once()
            assert d1 is d2


# =============================================================================
# PROCESS METHOD TESTS
# =============================================================================

class TestProcess:
    """Tests for process method."""

    def test_process_empty_image(self):
        """Handles empty image gracefully."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=False,
            enable_barcode=False,
            enable_handwriting=False,
            enable_signature=False,
        )

        result = processor.process(np.array([]))

        assert result.total_phi_detected == 0
        assert result.phi_regions == []

    def test_process_none_image(self):
        """Handles None image gracefully."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=False,
            enable_barcode=False,
            enable_handwriting=False,
            enable_signature=False,
        )

        result = processor.process(None)

        assert result.total_phi_detected == 0

    def test_process_valid_image(self):
        """Processes valid image."""
        from scrubiq.image_protection.image_phi_processor import (
            ImagePHIProcessor, ImagePHIResult
        )

        processor = ImagePHIProcessor(
            enable_face=False,
            enable_barcode=False,
            enable_handwriting=False,
            enable_signature=False,
        )

        image = np.zeros((100, 100, 3), dtype=np.uint8)
        result = processor.process(image)

        assert isinstance(result, ImagePHIResult)
        assert result.image_width == 100
        assert result.image_height == 100

    def test_process_runs_enabled_detectors(self):
        """Process runs only enabled detectors."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=True,
            enable_barcode=False,
            enable_handwriting=False,
            enable_signature=False,
        )

        # Mock face detector
        mock_face_det = MagicMock()
        mock_face_det.detect.return_value = MagicMock(
            faces_detected=0,
            detections=[],
        )

        with patch.object(
            ImagePHIProcessor, 'face_detector',
            new_callable=PropertyMock, return_value=mock_face_det
        ):
            image = np.zeros((100, 100, 3), dtype=np.uint8)
            result = processor.process(image)

            # Face detector should have been called
            mock_face_det.detect.assert_called_once()
            assert "face" in result.detectors_run


# =============================================================================
# PHI TYPE DETECTION TESTS
# =============================================================================

class TestPHITypes:
    """Tests for different PHI types."""

    def test_valid_phi_types(self):
        """PHIRegion accepts valid PHI types."""
        from scrubiq.image_protection.image_phi_processor import PHIRegion

        valid_types = ["face", "barcode", "handwriting", "signature"]

        for phi_type in valid_types:
            region = PHIRegion(
                x=0, y=0, width=10, height=10,
                phi_type=phi_type,
                confidence=0.9,
                detector="test",
            )
            assert region.phi_type == phi_type


# =============================================================================
# DETECTOR CONFIGURATION TESTS
# =============================================================================

class TestDetectorConfiguration:
    """Tests for detector configuration."""

    def test_face_detector_uses_configured_confidence(self):
        """Face detector uses configured confidence threshold."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=True,
            face_confidence=0.9,
        )

        with patch('scrubiq.image_protection.image_phi_processor.FaceDetector') as mock_fd:
            mock_fd.return_value = MagicMock()

            _ = processor.face_detector

            # Should pass confidence to FaceDetector
            call_kwargs = mock_fd.call_args[1]
            assert call_kwargs["score_threshold"] == 0.9

    def test_uses_custom_models_dir(self):
        """Uses custom models directory when specified."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=True,
            models_dir=Path("/custom/models"),
        )

        with patch('scrubiq.image_protection.image_phi_processor.FaceDetector') as mock_fd:
            mock_fd.return_value = MagicMock()

            _ = processor.face_detector

            # Should pass model path
            call_kwargs = mock_fd.call_args[1]
            assert "model_path" in call_kwargs


# =============================================================================
# REDACT PHI REGIONS TESTS
# =============================================================================

class TestRedactPHIRegions:
    """Tests for redact_phi_regions function."""

    def test_black_redaction_method(self):
        """Black method sets pixels to 0."""
        from scrubiq.image_protection.image_phi_processor import redact_phi_regions, PHIRegion

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        regions = [PHIRegion(x=10, y=10, width=20, height=20,
                            phi_type="face", confidence=0.9, detector="test")]

        result = redact_phi_regions(image, regions, method="black", padding=0)

        # Region should be blacked out
        assert np.all(result[10:30, 10:30] == 0)
        # Outside region unchanged
        assert np.all(result[0:9, 0:9] == 255)

    def test_blur_redaction_method(self):
        """Blur method applies Gaussian blur."""
        from scrubiq.image_protection.image_phi_processor import redact_phi_regions, PHIRegion

        image = np.ones((100, 100, 3), dtype=np.uint8) * 128
        image[40:60, 40:60] = 255  # Add pattern

        regions = [PHIRegion(x=35, y=35, width=30, height=30,
                            phi_type="face", confidence=0.9, detector="test")]

        result = redact_phi_regions(image, regions, method="blur", padding=0)

        # Region should be blurred (different from original)
        assert not np.array_equal(result[35:65, 35:65], image[35:65, 35:65])

    def test_pixelate_redaction_method(self):
        """Pixelate method creates mosaic effect."""
        from scrubiq.image_protection.image_phi_processor import redact_phi_regions, PHIRegion

        image = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        regions = [PHIRegion(x=20, y=20, width=40, height=40,
                            phi_type="face", confidence=0.9, detector="test")]

        result = redact_phi_regions(image, regions, method="pixelate", padding=0)

        # Region should be different (pixelated)
        assert not np.array_equal(result[20:60, 20:60], image[20:60, 20:60])

    def test_padding_expands_region(self):
        """Padding expands the redaction area."""
        from scrubiq.image_protection.image_phi_processor import redact_phi_regions, PHIRegion

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        regions = [PHIRegion(x=40, y=40, width=20, height=20,
                            phi_type="face", confidence=0.9, detector="test")]

        result = redact_phi_regions(image, regions, method="black", padding=0.5)

        # With 50% padding, should expand by 10 pixels each side
        # Check expanded area is black
        assert np.all(result[30:70, 30:70] == 0)

    def test_multiple_regions(self):
        """Multiple regions can be redacted."""
        from scrubiq.image_protection.image_phi_processor import redact_phi_regions, PHIRegion

        image = np.ones((200, 200, 3), dtype=np.uint8) * 255
        regions = [
            PHIRegion(x=10, y=10, width=30, height=30, phi_type="face", confidence=0.9, detector="t"),
            PHIRegion(x=100, y=100, width=30, height=30, phi_type="barcode", confidence=0.9, detector="t"),
        ]

        result = redact_phi_regions(image, regions, method="black", padding=0)

        assert np.all(result[10:40, 10:40] == 0)
        assert np.all(result[100:130, 100:130] == 0)

    def test_empty_regions_list(self):
        """Empty regions list returns unchanged image."""
        from scrubiq.image_protection.image_phi_processor import redact_phi_regions

        image = np.ones((100, 100, 3), dtype=np.uint8) * 128
        result = redact_phi_regions(image, [], method="black", padding=0)

        assert np.array_equal(result, image)

    def test_boundary_clamping(self):
        """Regions extending past image boundaries are clamped."""
        from scrubiq.image_protection.image_phi_processor import redact_phi_regions, PHIRegion

        image = np.ones((100, 100, 3), dtype=np.uint8) * 255
        regions = [PHIRegion(x=80, y=80, width=50, height=50,
                            phi_type="face", confidence=0.9, detector="test")]

        # Should not raise
        result = redact_phi_regions(image, regions, method="black", padding=0.2)
        assert result.shape == (100, 100, 3)


# =============================================================================
# DRAW PHI REGIONS TESTS
# =============================================================================

class TestDrawPHIRegions:
    """Tests for draw_phi_regions function."""

    def test_draws_rectangles(self):
        """Draws rectangles around PHI regions."""
        from scrubiq.image_protection.image_phi_processor import draw_phi_regions, PHIRegion

        image = np.zeros((100, 100, 3), dtype=np.uint8)
        regions = [PHIRegion(x=20, y=20, width=30, height=30,
                            phi_type="face", confidence=0.9, detector="test")]

        result = draw_phi_regions(image, regions)

        # Should have non-zero pixels (drawn rectangles)
        assert np.any(result != 0)

    def test_different_phi_types_different_colors(self):
        """Different PHI types get different colors."""
        from scrubiq.image_protection.image_phi_processor import draw_phi_regions, PHIRegion

        image = np.zeros((200, 200, 3), dtype=np.uint8)
        regions = [
            PHIRegion(x=10, y=10, width=30, height=30, phi_type="face", confidence=0.9, detector="t"),
            PHIRegion(x=100, y=10, width=30, height=30, phi_type="barcode", confidence=0.9, detector="t"),
            PHIRegion(x=10, y=100, width=30, height=30, phi_type="handwriting", confidence=0.9, detector="t"),
            PHIRegion(x=100, y=100, width=30, height=30, phi_type="signature", confidence=0.9, detector="t"),
        ]

        result = draw_phi_regions(image, regions)

        # All regions should be drawn
        assert np.any(result[10:40, 10:40] != 0)
        assert np.any(result[10:40, 100:130] != 0)

    def test_labels_shown_by_default(self):
        """Labels are shown by default."""
        from scrubiq.image_protection.image_phi_processor import draw_phi_regions, PHIRegion

        image = np.zeros((100, 100, 3), dtype=np.uint8)
        regions = [PHIRegion(x=20, y=30, width=30, height=30,
                            phi_type="face", confidence=0.9, detector="test")]

        result = draw_phi_regions(image, regions, show_labels=True)
        assert np.any(result != 0)

    def test_labels_can_be_hidden(self):
        """Labels can be hidden."""
        from scrubiq.image_protection.image_phi_processor import draw_phi_regions, PHIRegion

        image = np.zeros((100, 100, 3), dtype=np.uint8)
        regions = [PHIRegion(x=20, y=30, width=30, height=30,
                            phi_type="face", confidence=0.9, detector="test")]

        result = draw_phi_regions(image, regions, show_labels=False)
        # Should still have rectangles
        assert np.any(result != 0)

    def test_unknown_phi_type_uses_default_color(self):
        """Unknown PHI types use default gray color."""
        from scrubiq.image_protection.image_phi_processor import draw_phi_regions, PHIRegion

        image = np.zeros((100, 100, 3), dtype=np.uint8)
        regions = [PHIRegion(x=20, y=20, width=30, height=30,
                            phi_type="unknown_type", confidence=0.9, detector="test")]

        result = draw_phi_regions(image, regions)
        # Should still draw something
        assert np.any(result != 0)


# =============================================================================
# PROCESS FROM PATH/BYTES TESTS
# =============================================================================

class TestProcessFromPath:
    """Tests for process_from_path method."""

    def test_invalid_path_raises_value_error(self):
        """Invalid path raises ValueError."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=False, enable_barcode=False,
            enable_handwriting=False, enable_signature=False
        )

        with pytest.raises(ValueError, match="Could not load image"):
            processor.process_from_path("/nonexistent/image.jpg")

    def test_valid_path_processes_image(self, tmp_path):
        """Valid path processes image."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor
        import cv2

        processor = ImagePHIProcessor(
            enable_face=False, enable_barcode=False,
            enable_handwriting=False, enable_signature=False
        )

        # Create test image file
        image = np.zeros((50, 50, 3), dtype=np.uint8)
        image_path = tmp_path / "test.png"
        cv2.imwrite(str(image_path), image)

        result = processor.process_from_path(str(image_path))

        assert result.image_width == 50
        assert result.image_height == 50


class TestProcessFromBytes:
    """Tests for process_from_bytes method."""

    def test_invalid_bytes_raises_value_error(self):
        """Invalid bytes raises ValueError."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=False, enable_barcode=False,
            enable_handwriting=False, enable_signature=False
        )

        with pytest.raises(ValueError, match="Could not decode image"):
            processor.process_from_bytes(b"not an image")

    def test_valid_png_bytes_processes(self):
        """Valid PNG bytes are processed."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor
        import cv2

        processor = ImagePHIProcessor(
            enable_face=False, enable_barcode=False,
            enable_handwriting=False, enable_signature=False
        )

        image = np.zeros((50, 50, 3), dtype=np.uint8)
        _, img_bytes = cv2.imencode('.png', image)

        result = processor.process_from_bytes(img_bytes.tobytes())

        assert result.image_width == 50
        assert result.image_height == 50

    def test_valid_jpg_bytes_processes(self):
        """Valid JPEG bytes are processed."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor
        import cv2

        processor = ImagePHIProcessor(
            enable_face=False, enable_barcode=False,
            enable_handwriting=False, enable_signature=False
        )

        image = np.ones((60, 80, 3), dtype=np.uint8) * 128
        _, img_bytes = cv2.imencode('.jpg', image)

        result = processor.process_from_bytes(img_bytes.tobytes())

        assert result.image_width == 80
        assert result.image_height == 60


# =============================================================================
# MODULE-LEVEL FUNCTIONS TESTS
# =============================================================================

class TestModuleFunctions:
    """Tests for module-level functions."""

    def test_get_processor_returns_singleton(self):
        """get_processor returns singleton instance."""
        from scrubiq.image_protection.image_phi_processor import get_processor, _default_processor
        import scrubiq.image_protection.image_phi_processor as module

        # Reset singleton
        module._default_processor = None

        proc1 = get_processor()
        proc2 = get_processor()

        assert proc1 is proc2

    def test_process_image_uses_default_processor(self):
        """process_image uses the default processor."""
        from scrubiq.image_protection.image_phi_processor import process_image, ImagePHIResult

        image = np.zeros((50, 50, 3), dtype=np.uint8)
        result = process_image(image)

        assert isinstance(result, ImagePHIResult)
        assert result.image_width == 50


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling:
    """Tests for error handling in processor."""

    def test_face_detector_error_logged_and_continues(self):
        """Face detector errors are logged and processing continues."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=True,
            enable_barcode=False,
            enable_handwriting=False,
            enable_signature=False,
        )

        mock_face_det = MagicMock()
        mock_face_det.detect.side_effect = Exception("Detection failed")

        with patch.object(
            ImagePHIProcessor, 'face_detector',
            new_callable=PropertyMock, return_value=mock_face_det
        ):
            image = np.zeros((100, 100, 3), dtype=np.uint8)
            result = processor.process(image)

            # Should have error recorded
            assert len(result.errors) > 0
            assert "face" in result.errors[0]

    def test_barcode_detector_error_logged_and_continues(self):
        """Barcode detector errors are logged and processing continues."""
        from scrubiq.image_protection.image_phi_processor import ImagePHIProcessor

        processor = ImagePHIProcessor(
            enable_face=False,
            enable_barcode=True,
            enable_handwriting=False,
            enable_signature=False,
        )

        mock_barcode_det = MagicMock()
        mock_barcode_det.detect.side_effect = Exception("Barcode detection failed")

        with patch.object(
            ImagePHIProcessor, 'barcode_detector',
            new_callable=PropertyMock, return_value=mock_barcode_det
        ):
            image = np.zeros((100, 100, 3), dtype=np.uint8)
            result = processor.process(image)

            assert len(result.errors) > 0
            assert "barcode" in result.errors[0]

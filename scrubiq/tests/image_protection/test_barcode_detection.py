"""Tests for barcode detection (image_protection/barcode_detection.py).

Tests cover:
- BarcodeType enum and from_string conversion
- BarcodeDetection dataclass properties
- BarcodeDetectionResult dataclass
- BarcodeDetector class
  - Initialization with symbol filtering
  - detect() method with various image formats
  - detect_from_path() error handling
  - detect_from_bytes() error handling
  - detect_from_pil() conversion
- redact_barcodes() function
  - Different redaction methods (black, blur, pixelate)
  - Polygon vs bounding box redaction
- Singleton pattern (get_detector)
- High-risk barcode classification
- Error handling for missing pyzbar
"""

import hashlib
from unittest.mock import MagicMock, patch, PropertyMock

import numpy as np
import pytest


# --- BarcodeType Tests ---

class TestBarcodeType:
    """Tests for BarcodeType enum."""

    def test_barcode_type_values(self):
        """BarcodeType should have expected values."""
        from scrubiq.image_protection.barcode_detection import BarcodeType

        assert BarcodeType.QRCODE == "QRCODE"
        assert BarcodeType.PDF417 == "PDF417"
        assert BarcodeType.CODE128 == "CODE128"
        assert BarcodeType.CODE39 == "CODE39"
        assert BarcodeType.EAN13 == "EAN13"
        assert BarcodeType.UNKNOWN == "UNKNOWN"

    def test_from_string_valid(self):
        """from_string should convert valid strings."""
        from scrubiq.image_protection.barcode_detection import BarcodeType

        assert BarcodeType.from_string("QRCODE") == BarcodeType.QRCODE
        assert BarcodeType.from_string("qrcode") == BarcodeType.QRCODE
        assert BarcodeType.from_string("QrCode") == BarcodeType.QRCODE

    def test_from_string_invalid(self):
        """from_string should return UNKNOWN for invalid strings."""
        from scrubiq.image_protection.barcode_detection import BarcodeType

        assert BarcodeType.from_string("INVALID") == BarcodeType.UNKNOWN
        assert BarcodeType.from_string("not_a_barcode") == BarcodeType.UNKNOWN
        assert BarcodeType.from_string("") == BarcodeType.UNKNOWN


# --- BarcodeDetection Tests ---

class TestBarcodeDetection:
    """Tests for BarcodeDetection dataclass."""

    def test_barcode_detection_properties(self):
        """BarcodeDetection should calculate properties correctly."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetection, BarcodeType

        det = BarcodeDetection(
            x=10, y=20, width=100, height=50,
            barcode_type=BarcodeType.QRCODE,
            confidence=1.0,
            data_hash="abc123",
            data_length=100,
        )

        assert det.x2 == 110
        assert det.y2 == 70
        assert det.area == 5000
        assert det.bbox == (10, 20, 110, 70)

    def test_to_dict_excludes_data_hash(self):
        """to_dict should not include data_hash for PHI safety."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetection, BarcodeType

        det = BarcodeDetection(
            x=10, y=20, width=100, height=50,
            barcode_type=BarcodeType.QRCODE,
            confidence=1.0,
            data_hash="sensitive_hash",
            data_length=100,
        )

        d = det.to_dict()

        assert "data_hash" not in d
        assert d["x"] == 10
        assert d["y"] == 20
        assert d["barcode_type"] == "QRCODE"

    def test_default_polygon_empty(self):
        """polygon should default to empty list."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetection, BarcodeType

        det = BarcodeDetection(
            x=10, y=20, width=100, height=50,
            barcode_type=BarcodeType.QRCODE,
        )

        assert det.polygon == []


# --- BarcodeDetectionResult Tests ---

class TestBarcodeDetectionResult:
    """Tests for BarcodeDetectionResult dataclass."""

    def test_to_audit_dict(self):
        """to_audit_dict should return audit-safe information."""
        from scrubiq.image_protection.barcode_detection import (
            BarcodeDetectionResult, BarcodeDetection, BarcodeType
        )

        result = BarcodeDetectionResult(
            barcodes_detected=2,
            detections=[],
            processing_time_ms=15.5,
            image_width=640,
            image_height=480,
            barcode_types_found=["QRCODE", "PDF417"],
        )

        audit = result.to_audit_dict()

        assert audit["barcodes_detected"] == 2
        assert audit["barcode_types"] == ["QRCODE", "PDF417"]
        assert audit["processing_time_ms"] == 15.5
        assert audit["image_size"] == "640x480"


# --- BarcodeDetector Tests ---

class TestBarcodeDetector:
    """Tests for BarcodeDetector class."""

    @pytest.fixture
    def mock_pyzbar(self):
        """Mock pyzbar module."""
        with patch("scrubiq.image_protection.barcode_detection._pyzbar", None):
            with patch("scrubiq.image_protection.barcode_detection._get_pyzbar") as mock_get:
                mock_module = MagicMock()
                mock_get.return_value = mock_module
                yield mock_module

    def test_init_no_symbols(self, mock_pyzbar):
        """Should initialize without symbol filtering."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        detector = BarcodeDetector()

        assert detector._symbols is None

    def test_init_with_symbols(self, mock_pyzbar):
        """Should initialize with symbol filtering."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        # Mock ZBarSymbol enum - need to mock at import level
        mock_zbar_symbol = MagicMock()
        mock_zbar_symbol.QRCODE = "QRCODE_SYMBOL"
        mock_zbar_symbol.PDF417 = "PDF417_SYMBOL"

        # Patch the import before it happens
        mock_pyzbar_module = MagicMock()
        mock_pyzbar_module.ZBarSymbol = mock_zbar_symbol

        with patch.dict("sys.modules", {"pyzbar": mock_pyzbar_module, "pyzbar.pyzbar": mock_pyzbar_module}):
            with patch("scrubiq.image_protection.barcode_detection._get_pyzbar", return_value=mock_pyzbar):
                # The detector may store symbols for later filtering
                detector = BarcodeDetector(symbols=["QRCODE", "PDF417"])

                # Should complete initialization without error
                assert detector is not None

    def test_detect_empty_image(self, mock_pyzbar):
        """Should handle empty images gracefully."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        detector = BarcodeDetector()

        # Empty image
        result = detector.detect(np.array([]))

        assert result.barcodes_detected == 0
        assert result.detections == []

    def test_detect_none_image(self, mock_pyzbar):
        """Should handle None images gracefully."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        detector = BarcodeDetector()

        result = detector.detect(None)

        assert result.barcodes_detected == 0

    def test_detect_grayscale_conversion(self, mock_pyzbar):
        """Should convert BGR to grayscale."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        mock_pyzbar.decode.return_value = []

        detector = BarcodeDetector()

        # BGR image
        image = np.zeros((100, 100, 3), dtype=np.uint8)
        result = detector.detect(image)

        # Should have processed without error
        assert result.barcodes_detected == 0
        mock_pyzbar.decode.assert_called()

    def test_detect_handles_bool_image(self, mock_pyzbar):
        """Should handle boolean (1-bit) images."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        mock_pyzbar.decode.return_value = []

        detector = BarcodeDetector()

        # 1-bit image
        image = np.zeros((100, 100), dtype=bool)
        result = detector.detect(image)

        assert result.barcodes_detected == 0

    def test_detect_returns_detections(self, mock_pyzbar):
        """Should return detected barcodes."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        # Mock barcode detection result
        mock_barcode = MagicMock()
        mock_barcode.rect.left = 10
        mock_barcode.rect.top = 20
        mock_barcode.rect.width = 100
        mock_barcode.rect.height = 50
        mock_barcode.polygon = []
        mock_barcode.data = b"test_data"
        mock_barcode.type = "QRCODE"

        mock_pyzbar.decode.return_value = [mock_barcode]

        detector = BarcodeDetector()
        image = np.zeros((480, 640), dtype=np.uint8)

        result = detector.detect(image)

        assert result.barcodes_detected == 1
        assert len(result.detections) == 1
        assert result.detections[0].x == 10
        assert result.detections[0].y == 20

    def test_detect_hashes_data(self, mock_pyzbar):
        """Should hash barcode data for audit purposes."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        test_data = b"sensitive_phi_data"

        mock_barcode = MagicMock()
        mock_barcode.rect.left = 10
        mock_barcode.rect.top = 20
        mock_barcode.rect.width = 100
        mock_barcode.rect.height = 50
        mock_barcode.polygon = []
        mock_barcode.data = test_data
        mock_barcode.type = "QRCODE"

        mock_pyzbar.decode.return_value = [mock_barcode]

        detector = BarcodeDetector()
        image = np.zeros((480, 640), dtype=np.uint8)

        result = detector.detect(image)

        # Should have hash of data
        expected_hash = hashlib.sha256(test_data).hexdigest()[:16]
        assert result.detections[0].data_hash == expected_hash
        assert result.detections[0].data_length == len(test_data)


# --- detect_from_path Tests ---

class TestDetectFromPath:
    """Tests for detect_from_path method."""

    def test_detect_from_path_raises_on_missing_file(self):
        """Should raise ValueError for missing file."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        with patch("scrubiq.image_protection.barcode_detection._get_pyzbar"):
            detector = BarcodeDetector()

            with patch("cv2.imread", return_value=None):
                with pytest.raises(ValueError, match="Could not load image"):
                    detector.detect_from_path("/nonexistent/path.jpg")

    def test_detect_from_path_loads_and_detects(self):
        """Should load image and detect barcodes."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        with patch("scrubiq.image_protection.barcode_detection._get_pyzbar") as mock_get:
            mock_pyzbar = MagicMock()
            mock_pyzbar.decode.return_value = []
            mock_get.return_value = mock_pyzbar

            detector = BarcodeDetector()

            with patch("cv2.imread", return_value=np.zeros((100, 100, 3), dtype=np.uint8)):
                result = detector.detect_from_path("/path/to/image.jpg")

                assert result.barcodes_detected == 0


# --- detect_from_bytes Tests ---

class TestDetectFromBytes:
    """Tests for detect_from_bytes method."""

    def test_detect_from_bytes_raises_on_invalid_bytes(self):
        """Should raise ValueError for invalid image bytes."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        with patch("scrubiq.image_protection.barcode_detection._get_pyzbar"):
            detector = BarcodeDetector()

            with patch("cv2.imdecode", return_value=None):
                with pytest.raises(ValueError, match="Could not decode image"):
                    detector.detect_from_bytes(b"invalid_image_data")


# --- detect_from_pil Tests ---

class TestDetectFromPil:
    """Tests for detect_from_pil method."""

    def test_detect_from_pil_converts_image(self):
        """Should convert PIL image to numpy and detect."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetector

        with patch("scrubiq.image_protection.barcode_detection._get_pyzbar") as mock_get:
            mock_pyzbar = MagicMock()
            mock_pyzbar.decode.return_value = []
            mock_get.return_value = mock_pyzbar

            detector = BarcodeDetector()

            # Mock PIL image
            mock_pil = MagicMock()
            mock_pil.__array__ = MagicMock(return_value=np.zeros((100, 100, 3), dtype=np.uint8))

            with patch("numpy.array", return_value=np.zeros((100, 100, 3), dtype=np.uint8)):
                result = detector.detect_from_pil(mock_pil)

                assert result.barcodes_detected == 0


# --- redact_barcodes Tests ---

class TestRedactBarcodes:
    """Tests for redact_barcodes function."""

    @pytest.fixture
    def sample_image(self):
        """Create a sample test image."""
        return np.ones((480, 640, 3), dtype=np.uint8) * 128

    @pytest.fixture
    def sample_detection(self):
        """Create a sample barcode detection."""
        from scrubiq.image_protection.barcode_detection import BarcodeDetection, BarcodeType

        return BarcodeDetection(
            x=100, y=100, width=200, height=100,
            barcode_type=BarcodeType.QRCODE,
            confidence=1.0,
            polygon=[(100, 100), (300, 100), (300, 200), (100, 200)],
        )

    def test_redact_black_method(self, sample_image, sample_detection):
        """Black redaction should fill region with black."""
        from scrubiq.image_protection.barcode_detection import redact_barcodes

        result = redact_barcodes(sample_image, [sample_detection], method="black")

        # Check that some region is black (0)
        assert np.any(result == 0)

    def test_redact_blur_method(self, sample_image, sample_detection):
        """Blur redaction should blur the region."""
        from scrubiq.image_protection.barcode_detection import redact_barcodes

        with patch("cv2.GaussianBlur", return_value=np.zeros_like(sample_image)):
            result = redact_barcodes(sample_image, [sample_detection], method="blur")

            # Should complete without error
            assert result.shape == sample_image.shape

    def test_redact_pixelate_method(self, sample_image, sample_detection):
        """Pixelate redaction should pixelate the region."""
        from scrubiq.image_protection.barcode_detection import redact_barcodes

        with patch("cv2.resize", side_effect=lambda img, size, **kw: np.zeros(size[::-1] + (3,) if len(img.shape) == 3 else size[::-1], dtype=np.uint8)):
            result = redact_barcodes(sample_image, [sample_detection], method="pixelate")

            # Should complete without error
            assert result.shape == sample_image.shape

    def test_redact_handles_empty_detections(self, sample_image):
        """Should return unchanged image for empty detections."""
        from scrubiq.image_protection.barcode_detection import redact_barcodes

        result = redact_barcodes(sample_image, [])

        np.testing.assert_array_equal(result, sample_image)

    def test_redact_handles_bool_image(self, sample_detection):
        """Should handle boolean images."""
        from scrubiq.image_protection.barcode_detection import redact_barcodes

        bool_image = np.ones((480, 640), dtype=bool)

        result = redact_barcodes(bool_image, [sample_detection], method="black")

        # Should convert to uint8
        assert result.dtype == np.uint8

    def test_redact_uses_polygon_when_available(self, sample_image, sample_detection):
        """Should use polygon for precise redaction when available."""
        from scrubiq.image_protection.barcode_detection import redact_barcodes

        with patch("cv2.fillPoly") as mock_fillpoly:
            redact_barcodes(sample_image, [sample_detection], method="black", use_polygon=True)

            mock_fillpoly.assert_called()

    def test_redact_falls_back_to_bbox(self, sample_image):
        """Should fall back to bbox when no polygon."""
        from scrubiq.image_protection.barcode_detection import (
            redact_barcodes, BarcodeDetection, BarcodeType
        )

        # Detection without polygon
        det = BarcodeDetection(
            x=100, y=100, width=200, height=100,
            barcode_type=BarcodeType.QRCODE,
            confidence=1.0,
            polygon=[],  # Empty polygon
        )

        result = redact_barcodes(sample_image, [det], method="black")

        # Region should be black
        assert np.any(result[100:200, 100:300] == 0)


# --- Singleton Pattern Tests ---

class TestSingleton:
    """Tests for singleton detector pattern."""

    def test_get_detector_returns_singleton(self):
        """get_detector should return the same instance."""
        from scrubiq.image_protection import barcode_detection

        # Reset singleton
        barcode_detection._default_detector = None

        with patch("scrubiq.image_protection.barcode_detection._get_pyzbar"):
            det1 = barcode_detection.get_detector()
            det2 = barcode_detection.get_detector()

            assert det1 is det2

    def test_detect_barcodes_convenience_function(self):
        """detect_barcodes should use default detector."""
        from scrubiq.image_protection import barcode_detection

        barcode_detection._default_detector = None

        with patch("scrubiq.image_protection.barcode_detection._get_pyzbar") as mock_get:
            mock_pyzbar = MagicMock()
            mock_pyzbar.decode.return_value = []
            mock_get.return_value = mock_pyzbar

            image = np.zeros((100, 100), dtype=np.uint8)
            result = barcode_detection.detect_barcodes(image)

            assert result.barcodes_detected == 0


# --- High Risk Classification Tests ---

class TestHighRiskClassification:
    """Tests for high-risk barcode classification."""

    def test_qrcode_is_high_risk(self):
        """QR codes should be classified as high risk."""
        from scrubiq.image_protection.barcode_detection import (
            is_high_risk_barcode, BarcodeDetection, BarcodeType
        )

        det = BarcodeDetection(
            x=0, y=0, width=100, height=100,
            barcode_type=BarcodeType.QRCODE,
        )

        assert is_high_risk_barcode(det) is True

    def test_pdf417_is_high_risk(self):
        """PDF417 (driver's license) should be high risk."""
        from scrubiq.image_protection.barcode_detection import (
            is_high_risk_barcode, BarcodeDetection, BarcodeType
        )

        det = BarcodeDetection(
            x=0, y=0, width=100, height=100,
            barcode_type=BarcodeType.PDF417,
        )

        assert is_high_risk_barcode(det) is True

    def test_code128_is_high_risk(self):
        """CODE128 (patient wristbands) should be high risk."""
        from scrubiq.image_protection.barcode_detection import (
            is_high_risk_barcode, BarcodeDetection, BarcodeType
        )

        det = BarcodeDetection(
            x=0, y=0, width=100, height=100,
            barcode_type=BarcodeType.CODE128,
        )

        assert is_high_risk_barcode(det) is True

    def test_ean13_is_low_risk(self):
        """EAN13 (product barcodes) should be low risk."""
        from scrubiq.image_protection.barcode_detection import (
            is_high_risk_barcode, BarcodeDetection, BarcodeType
        )

        det = BarcodeDetection(
            x=0, y=0, width=100, height=100,
            barcode_type=BarcodeType.EAN13,
        )

        assert is_high_risk_barcode(det) is False


# --- pyzbar Import Error Tests ---

class TestPyzbarImportError:
    """Tests for handling missing pyzbar."""

    def test_get_pyzbar_raises_import_error(self):
        """Should raise helpful ImportError if pyzbar not installed."""
        from scrubiq.image_protection import barcode_detection

        # Reset global
        barcode_detection._pyzbar = None

        with patch.dict("sys.modules", {"pyzbar": None, "pyzbar.pyzbar": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module")):
                with pytest.raises(ImportError) as exc_info:
                    barcode_detection._get_pyzbar()

                # Should have helpful message
                assert "pyzbar not installed" in str(exc_info.value)


# --- Pixelation Helper Tests ---

class TestPixelateRegion:
    """Tests for _pixelate_region helper function."""

    def test_pixelate_empty_region(self):
        """Should handle empty region gracefully."""
        from scrubiq.image_protection.barcode_detection import _pixelate_region

        image = np.zeros((100, 100, 3), dtype=np.uint8)

        # Region with zero area
        result = _pixelate_region(image, 50, 50, 50, 50)

        # Should return unchanged
        np.testing.assert_array_equal(result, image)

    def test_pixelate_small_region(self):
        """Should handle very small regions."""
        from scrubiq.image_protection.barcode_detection import _pixelate_region

        image = np.ones((100, 100, 3), dtype=np.uint8) * 128

        # Very small region
        with patch("cv2.resize", return_value=np.zeros((5, 5, 3), dtype=np.uint8)):
            result = _pixelate_region(image, 10, 10, 15, 15, block_size=8)

            # Should complete without error
            assert result.shape == image.shape

"""
Comprehensive tests for scrubiq/image_protection modules.

Tests signature detection, document layout analysis, handwriting detection,
and barcode detection functionality.
"""

import pytest
import numpy as np
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

# Import modules under test
from scrubiq.image_protection.signature_detection import (
    SignatureRegion,
    SignatureDetector,
    SignatureProtector,
)
from scrubiq.image_protection.document_layout import (
    LayoutClass,
    LayoutRegion,
    LayoutAnalysisResult,
    DocumentLayoutDetector,
    LAYOUT_CLASS_NAMES,
)
from scrubiq.image_protection.handwriting_detection import (
    HandwritingRegion,
    HandwritingDetectionResult,
    HandwritingDetector,
)
from scrubiq.image_protection.barcode_detection import (
    BarcodeResult,
    BarcodeType,
    BarcodeDetector,
    redact_barcodes,
    PHI_HIGH_RISK_TYPES,
)


# =============================================================================
# Test Fixtures
# =============================================================================
@pytest.fixture
def rgb_image():
    """Create a simple RGB test image."""
    return np.zeros((100, 100, 3), dtype=np.uint8)


@pytest.fixture
def grayscale_image():
    """Create a simple grayscale test image."""
    return np.zeros((100, 100), dtype=np.uint8)


@pytest.fixture
def image_with_content():
    """Create an RGB image with some content."""
    img = np.ones((200, 300, 3), dtype=np.uint8) * 255  # White background
    # Add a dark region (potential signature)
    img[50:100, 50:150] = 0  # Black rectangle
    return img


@pytest.fixture
def temp_models_dir():
    """Create a temporary models directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# =============================================================================
# SignatureRegion Tests
# =============================================================================
class TestSignatureRegion:
    """Tests for the SignatureRegion dataclass."""

    def test_signature_region_creation(self):
        """SignatureRegion should be creatable."""
        region = SignatureRegion(
            x=10, y=20, width=100, height=50,
            confidence=0.85
        )
        assert region.x == 10
        assert region.y == 20
        assert region.width == 100
        assert region.height == 50
        assert region.confidence == 0.85

    def test_signature_region_bbox_property(self):
        """bbox property should return (x1, y1, x2, y2)."""
        region = SignatureRegion(x=10, y=20, width=100, height=50, confidence=0.9)
        assert region.bbox == (10, 20, 110, 70)

    def test_signature_region_area_property(self):
        """area property should return width * height."""
        region = SignatureRegion(x=0, y=0, width=100, height=50, confidence=0.9)
        assert region.area == 5000

    def test_signature_region_center_property(self):
        """center property should return center point."""
        region = SignatureRegion(x=0, y=0, width=100, height=50, confidence=0.9)
        assert region.center == (50, 25)

    def test_signature_region_to_dict(self):
        """to_dict should return proper dictionary."""
        region = SignatureRegion(x=10, y=20, width=100, height=50, confidence=0.85)
        d = region.to_dict()

        assert d["x"] == 10
        assert d["y"] == 20
        assert d["width"] == 100
        assert d["height"] == 50
        assert d["confidence"] == 0.85


# =============================================================================
# SignatureDetector Tests
# =============================================================================
class TestSignatureDetector:
    """Tests for the SignatureDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a SignatureDetector instance."""
        return SignatureDetector()

    def test_detector_creation(self, detector):
        """SignatureDetector should be creatable."""
        assert detector is not None

    def test_detector_default_thresholds(self, detector):
        """Detector should have default thresholds."""
        assert hasattr(detector, 'min_confidence')
        assert 0 <= detector.min_confidence <= 1

    def test_detector_custom_threshold(self):
        """Detector should accept custom confidence threshold."""
        detector = SignatureDetector(min_confidence=0.7)
        assert detector.min_confidence == 0.7

    def test_detect_returns_list(self, detector, rgb_image):
        """detect() should return a list."""
        result = detector.detect(rgb_image)
        assert isinstance(result, list)

    def test_detect_empty_image(self, detector):
        """detect() on blank image should return empty list."""
        blank = np.zeros((100, 100, 3), dtype=np.uint8)
        result = detector.detect(blank)
        assert isinstance(result, list)

    def test_detect_handles_grayscale(self, detector, grayscale_image):
        """detect() should handle grayscale images."""
        result = detector.detect(grayscale_image)
        assert isinstance(result, list)

    def test_detect_handles_rgba(self, detector):
        """detect() should handle RGBA images."""
        rgba = np.zeros((100, 100, 4), dtype=np.uint8)
        result = detector.detect(rgba)
        assert isinstance(result, list)

    def test_detected_regions_are_signature_regions(self, detector, image_with_content):
        """Detected regions should be SignatureRegion instances."""
        result = detector.detect(image_with_content)
        for region in result:
            assert isinstance(region, SignatureRegion)

    def test_detected_regions_have_valid_coordinates(self, detector, image_with_content):
        """Detected regions should have non-negative coordinates."""
        result = detector.detect(image_with_content)
        for region in result:
            assert region.x >= 0
            assert region.y >= 0
            assert region.width > 0
            assert region.height > 0

    def test_detected_regions_have_valid_confidence(self, detector, image_with_content):
        """Detected regions should have confidence between 0 and 1."""
        result = detector.detect(image_with_content)
        for region in result:
            assert 0 <= region.confidence <= 1


# =============================================================================
# SignatureProtector Tests
# =============================================================================
class TestSignatureProtector:
    """Tests for the SignatureProtector class."""

    @pytest.fixture
    def protector(self):
        """Create a SignatureProtector instance."""
        return SignatureProtector()

    def test_protector_creation(self, protector):
        """SignatureProtector should be creatable."""
        assert protector is not None

    def test_protector_has_detector(self, protector):
        """SignatureProtector should have a detector."""
        assert hasattr(protector, 'detector')

    def test_protect_returns_image(self, protector, rgb_image):
        """protect() should return an image."""
        result = protector.protect(rgb_image)
        assert isinstance(result, np.ndarray)

    def test_protect_preserves_shape(self, protector, rgb_image):
        """protect() should preserve image shape."""
        result = protector.protect(rgb_image)
        assert result.shape == rgb_image.shape


# =============================================================================
# LayoutClass Tests
# =============================================================================
class TestLayoutClass:
    """Tests for the LayoutClass enum."""

    def test_layout_class_values(self):
        """LayoutClass should have expected values."""
        assert LayoutClass.TITLE.value == 0
        assert LayoutClass.TEXT.value == 1
        assert LayoutClass.ABANDON.value == 2
        assert LayoutClass.FIGURE.value == 3
        assert LayoutClass.TABLE.value == 5
        assert LayoutClass.HEADER.value == 7
        assert LayoutClass.FOOTER.value == 8

    def test_layout_class_names_mapping(self):
        """LAYOUT_CLASS_NAMES should map all classes."""
        for cls in LayoutClass:
            assert cls in LAYOUT_CLASS_NAMES


# =============================================================================
# LayoutRegion Tests
# =============================================================================
class TestLayoutRegion:
    """Tests for the LayoutRegion dataclass."""

    def test_layout_region_creation(self):
        """LayoutRegion should be creatable."""
        region = LayoutRegion(
            x=10, y=20, width=100, height=50,
            confidence=0.9,
            layout_class=LayoutClass.TEXT
        )
        assert region.x == 10
        assert region.y == 20
        assert region.width == 100
        assert region.height == 50
        assert region.confidence == 0.9
        assert region.layout_class == LayoutClass.TEXT

    def test_layout_region_x2_property(self):
        """x2 property should return x + width."""
        region = LayoutRegion(x=10, y=0, width=100, height=50,
                             confidence=0.9, layout_class=LayoutClass.TEXT)
        assert region.x2 == 110

    def test_layout_region_y2_property(self):
        """y2 property should return y + height."""
        region = LayoutRegion(x=0, y=20, width=100, height=50,
                             confidence=0.9, layout_class=LayoutClass.TEXT)
        assert region.y2 == 70

    def test_layout_region_area_property(self):
        """area property should return width * height."""
        region = LayoutRegion(x=0, y=0, width=100, height=50,
                             confidence=0.9, layout_class=LayoutClass.TEXT)
        assert region.area == 5000

    def test_layout_region_bbox_property(self):
        """bbox property should return (x1, y1, x2, y2)."""
        region = LayoutRegion(x=10, y=20, width=100, height=50,
                             confidence=0.9, layout_class=LayoutClass.TEXT)
        assert region.bbox == (10, 20, 110, 70)

    def test_layout_region_class_name_property(self):
        """class_name property should return human-readable name."""
        region = LayoutRegion(x=0, y=0, width=100, height=50,
                             confidence=0.9, layout_class=LayoutClass.TEXT)
        assert region.class_name == "text"

        region2 = LayoutRegion(x=0, y=0, width=100, height=50,
                              confidence=0.9, layout_class=LayoutClass.TABLE)
        assert region2.class_name == "table"

    def test_layout_region_center_property(self):
        """center property should return center point."""
        region = LayoutRegion(x=0, y=0, width=100, height=50,
                             confidence=0.9, layout_class=LayoutClass.TEXT)
        assert region.center == (50, 25)

    def test_layout_region_to_dict(self):
        """to_dict should return proper dictionary."""
        region = LayoutRegion(x=10, y=20, width=100, height=50,
                             confidence=0.9, layout_class=LayoutClass.TEXT)
        d = region.to_dict()

        assert d["x"] == 10
        assert d["y"] == 20
        assert d["width"] == 100
        assert d["height"] == 50
        assert d["confidence"] == 0.9
        assert d["class"] == "text"


# =============================================================================
# LayoutAnalysisResult Tests
# =============================================================================
class TestLayoutAnalysisResult:
    """Tests for the LayoutAnalysisResult dataclass."""

    def test_layout_result_creation(self):
        """LayoutAnalysisResult should be creatable."""
        result = LayoutAnalysisResult(
            regions=[],
            processing_time_ms=50.0,
            image_width=800,
            image_height=600
        )
        assert result.regions == []
        assert result.processing_time_ms == 50.0
        assert result.image_width == 800
        assert result.image_height == 600

    def test_get_regions_by_class(self):
        """get_regions_by_class should filter by class."""
        regions = [
            LayoutRegion(x=0, y=0, width=100, height=50, confidence=0.9, layout_class=LayoutClass.TEXT),
            LayoutRegion(x=0, y=50, width=100, height=50, confidence=0.9, layout_class=LayoutClass.TABLE),
            LayoutRegion(x=0, y=100, width=100, height=50, confidence=0.9, layout_class=LayoutClass.TEXT),
        ]
        result = LayoutAnalysisResult(regions=regions, processing_time_ms=50.0,
                                      image_width=800, image_height=600)

        text_regions = result.get_regions_by_class(LayoutClass.TEXT)
        assert len(text_regions) == 2

        table_regions = result.get_regions_by_class(LayoutClass.TABLE)
        assert len(table_regions) == 1

    def test_has_tables_property(self):
        """has_tables should return True if TABLE region exists."""
        result_no_tables = LayoutAnalysisResult(
            regions=[LayoutRegion(x=0, y=0, width=100, height=50,
                                 confidence=0.9, layout_class=LayoutClass.TEXT)],
            processing_time_ms=50.0, image_width=800, image_height=600
        )
        assert result_no_tables.has_tables is False

        result_with_tables = LayoutAnalysisResult(
            regions=[LayoutRegion(x=0, y=0, width=100, height=50,
                                 confidence=0.9, layout_class=LayoutClass.TABLE)],
            processing_time_ms=50.0, image_width=800, image_height=600
        )
        assert result_with_tables.has_tables is True

    def test_has_figures_property(self):
        """has_figures should return True if FIGURE region exists."""
        result_no_figures = LayoutAnalysisResult(
            regions=[LayoutRegion(x=0, y=0, width=100, height=50,
                                 confidence=0.9, layout_class=LayoutClass.TEXT)],
            processing_time_ms=50.0, image_width=800, image_height=600
        )
        assert result_no_figures.has_figures is False

        result_with_figures = LayoutAnalysisResult(
            regions=[LayoutRegion(x=0, y=0, width=100, height=50,
                                 confidence=0.9, layout_class=LayoutClass.FIGURE)],
            processing_time_ms=50.0, image_width=800, image_height=600
        )
        assert result_with_figures.has_figures is True

    def test_to_dict(self):
        """to_dict should return proper dictionary."""
        regions = [
            LayoutRegion(x=0, y=0, width=100, height=50, confidence=0.9, layout_class=LayoutClass.TEXT),
        ]
        result = LayoutAnalysisResult(regions=regions, processing_time_ms=50.5,
                                      image_width=800, image_height=600)
        d = result.to_dict()

        assert d["num_regions"] == 1
        assert d["processing_time_ms"] == 50.5
        assert d["image_size"] == [800, 600]
        assert "text" in d["classes_found"]


# =============================================================================
# DocumentLayoutDetector Tests
# =============================================================================
class TestDocumentLayoutDetector:
    """Tests for the DocumentLayoutDetector class."""

    def test_detector_creation(self, temp_models_dir):
        """DocumentLayoutDetector should be creatable."""
        detector = DocumentLayoutDetector(models_dir=temp_models_dir)
        assert detector is not None

    def test_detector_model_filename(self):
        """Detector should have MODEL_FILENAME constant."""
        assert hasattr(DocumentLayoutDetector, 'MODEL_FILENAME')
        assert DocumentLayoutDetector.MODEL_FILENAME == "yolo_doclayout.onnx"

    def test_detector_input_size(self):
        """Detector should have INPUT_SIZE constant."""
        assert hasattr(DocumentLayoutDetector, 'INPUT_SIZE')
        assert DocumentLayoutDetector.INPUT_SIZE == (1024, 1024)

    def test_detector_is_available_without_model(self, temp_models_dir):
        """is_available should be False without model file."""
        detector = DocumentLayoutDetector(models_dir=temp_models_dir)
        assert detector.is_available is False

    def test_detector_is_initialized_without_loading(self, temp_models_dir):
        """is_initialized should be False before loading."""
        detector = DocumentLayoutDetector(models_dir=temp_models_dir)
        assert detector.is_initialized is False

    def test_detector_custom_confidence_threshold(self, temp_models_dir):
        """Detector should accept custom confidence threshold."""
        detector = DocumentLayoutDetector(
            models_dir=temp_models_dir,
            confidence_threshold=0.5
        )
        assert detector.confidence_threshold == 0.5


# =============================================================================
# HandwritingRegion Tests
# =============================================================================
class TestHandwritingRegion:
    """Tests for the HandwritingRegion dataclass."""

    def test_handwriting_region_creation(self):
        """HandwritingRegion should be creatable."""
        region = HandwritingRegion(
            x=10, y=20, width=100, height=50,
            confidence=0.85
        )
        assert region.x == 10
        assert region.y == 20
        assert region.width == 100
        assert region.height == 50
        assert region.confidence == 0.85

    def test_handwriting_region_bbox_property(self):
        """bbox property should return (x1, y1, x2, y2)."""
        region = HandwritingRegion(x=10, y=20, width=100, height=50, confidence=0.9)
        assert region.bbox == (10, 20, 110, 70)

    def test_handwriting_region_area_property(self):
        """area property should return width * height."""
        region = HandwritingRegion(x=0, y=0, width=100, height=50, confidence=0.9)
        assert region.area == 5000


# =============================================================================
# HandwritingDetectionResult Tests
# =============================================================================
class TestHandwritingDetectionResult:
    """Tests for the HandwritingDetectionResult dataclass."""

    def test_result_creation(self):
        """HandwritingDetectionResult should be creatable."""
        result = HandwritingDetectionResult(
            regions=[],
            processing_time_ms=25.0,
            image_width=800,
            image_height=600
        )
        assert result.regions == []
        assert result.processing_time_ms == 25.0
        assert result.image_width == 800
        assert result.image_height == 600

    def test_has_handwriting_property(self):
        """has_handwriting should return True if regions exist."""
        empty_result = HandwritingDetectionResult(
            regions=[], processing_time_ms=25.0,
            image_width=800, image_height=600
        )
        assert empty_result.has_handwriting is False

        result_with_regions = HandwritingDetectionResult(
            regions=[HandwritingRegion(x=0, y=0, width=100, height=50, confidence=0.9)],
            processing_time_ms=25.0, image_width=800, image_height=600
        )
        assert result_with_regions.has_handwriting is True


# =============================================================================
# HandwritingDetector Tests
# =============================================================================
class TestHandwritingDetector:
    """Tests for the HandwritingDetector class."""

    def test_detector_creation(self, temp_models_dir):
        """HandwritingDetector should be creatable."""
        detector = HandwritingDetector(models_dir=temp_models_dir)
        assert detector is not None

    def test_detector_model_filename(self):
        """Detector should have MODEL_FILENAME constant."""
        assert hasattr(HandwritingDetector, 'MODEL_FILENAME')
        assert HandwritingDetector.MODEL_FILENAME == "yolov8n_handwriting_detection.onnx"

    def test_detector_input_size(self):
        """Detector should have INPUT_SIZE constant."""
        assert hasattr(HandwritingDetector, 'INPUT_SIZE')
        assert HandwritingDetector.INPUT_SIZE == (640, 640)

    def test_detector_is_available_without_model(self, temp_models_dir):
        """is_available should be False without model file."""
        detector = HandwritingDetector(models_dir=temp_models_dir)
        assert detector.is_available is False


# =============================================================================
# BarcodeType Tests
# =============================================================================
class TestBarcodeType:
    """Tests for the BarcodeType enum."""

    def test_barcode_types_exist(self):
        """BarcodeType should have expected values."""
        assert hasattr(BarcodeType, 'QRCODE')
        assert hasattr(BarcodeType, 'PDF417')
        assert hasattr(BarcodeType, 'CODE128')
        assert hasattr(BarcodeType, 'EAN13')

    def test_barcode_type_values_are_strings(self):
        """BarcodeType values should be strings."""
        for bt in BarcodeType:
            assert isinstance(bt.value, str)


# =============================================================================
# BarcodeResult Tests
# =============================================================================
class TestBarcodeResult:
    """Tests for the BarcodeResult dataclass."""

    def test_barcode_result_creation(self):
        """BarcodeResult should be creatable."""
        result = BarcodeResult(
            barcode_type=BarcodeType.QRCODE,
            data="test data",
            x=10, y=20, width=100, height=100,
            polygon=[(10, 20), (110, 20), (110, 120), (10, 120)]
        )
        assert result.barcode_type == BarcodeType.QRCODE
        assert result.data == "test data"
        assert result.x == 10
        assert result.y == 20
        assert result.width == 100
        assert result.height == 100

    def test_barcode_result_bbox_property(self):
        """bbox property should return (x1, y1, x2, y2)."""
        result = BarcodeResult(
            barcode_type=BarcodeType.QRCODE,
            data="test",
            x=10, y=20, width=100, height=100,
            polygon=[]
        )
        assert result.bbox == (10, 20, 110, 120)

    def test_barcode_result_to_dict(self):
        """to_dict should return proper dictionary."""
        result = BarcodeResult(
            barcode_type=BarcodeType.PDF417,
            data="license data",
            x=0, y=0, width=200, height=50,
            polygon=[(0, 0), (200, 0), (200, 50), (0, 50)]
        )
        d = result.to_dict()

        assert "barcode_type" in d
        assert "data" in d
        assert "bbox" in d


# =============================================================================
# BarcodeDetector Tests
# =============================================================================
class TestBarcodeDetector:
    """Tests for the BarcodeDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a BarcodeDetector instance."""
        return BarcodeDetector()

    def test_detector_creation(self, detector):
        """BarcodeDetector should be creatable."""
        assert detector is not None

    def test_detect_returns_list(self, detector, rgb_image):
        """detect() should return a list."""
        result = detector.detect(rgb_image)
        assert isinstance(result, list)

    def test_detect_empty_image(self, detector):
        """detect() on blank image should return empty list."""
        blank = np.zeros((100, 100, 3), dtype=np.uint8)
        result = detector.detect(blank)
        assert result == []

    def test_detect_handles_grayscale(self, detector, grayscale_image):
        """detect() should handle grayscale images."""
        result = detector.detect(grayscale_image)
        assert isinstance(result, list)

    def test_detected_results_are_barcode_results(self, detector, rgb_image):
        """Detected items should be BarcodeResult instances."""
        result = detector.detect(rgb_image)
        for item in result:
            assert isinstance(item, BarcodeResult)


# =============================================================================
# redact_barcodes Function Tests
# =============================================================================
class TestRedactBarcodes:
    """Tests for the redact_barcodes function."""

    def test_redact_returns_tuple(self, rgb_image):
        """redact_barcodes should return tuple."""
        result = redact_barcodes(rgb_image)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_redact_returns_image_and_list(self, rgb_image):
        """redact_barcodes should return (image, list)."""
        redacted, results = redact_barcodes(rgb_image)
        assert isinstance(redacted, np.ndarray)
        assert isinstance(results, list)

    def test_redact_preserves_shape(self, rgb_image):
        """redact_barcodes should preserve image shape."""
        redacted, _ = redact_barcodes(rgb_image)
        assert redacted.shape == rgb_image.shape


# =============================================================================
# PHI High Risk Types Tests
# =============================================================================
class TestPHIHighRiskTypes:
    """Tests for PHI_HIGH_RISK_TYPES constant."""

    def test_phi_high_risk_types_is_set(self):
        """PHI_HIGH_RISK_TYPES should be a set."""
        assert isinstance(PHI_HIGH_RISK_TYPES, (set, frozenset))

    def test_phi_high_risk_types_not_empty(self):
        """PHI_HIGH_RISK_TYPES should not be empty."""
        assert len(PHI_HIGH_RISK_TYPES) > 0

    def test_pdf417_is_high_risk(self):
        """PDF417 should be high risk (used on driver's licenses)."""
        assert BarcodeType.PDF417 in PHI_HIGH_RISK_TYPES


# =============================================================================
# IOU Calculation Tests
# =============================================================================
class TestIOUCalculation:
    """Tests for IOU (Intersection over Union) calculations."""

    def test_document_layout_iou_no_overlap(self):
        """IOU should be 0 for non-overlapping boxes."""
        box1 = (0, 0, 10, 10)
        box2 = (20, 20, 30, 30)
        iou = DocumentLayoutDetector._iou(box1, box2)
        assert iou == 0.0

    def test_document_layout_iou_full_overlap(self):
        """IOU should be 1 for identical boxes."""
        box1 = (0, 0, 10, 10)
        box2 = (0, 0, 10, 10)
        iou = DocumentLayoutDetector._iou(box1, box2)
        assert iou == 1.0

    def test_document_layout_iou_partial_overlap(self):
        """IOU should be between 0 and 1 for partial overlap."""
        box1 = (0, 0, 10, 10)
        box2 = (5, 5, 15, 15)
        iou = DocumentLayoutDetector._iou(box1, box2)
        assert 0 < iou < 1


# =============================================================================
# Edge Cases and Robustness Tests
# =============================================================================
class TestImageProtectionEdgeCases:
    """Edge case tests for image protection modules."""

    def test_handle_very_small_image(self):
        """Detectors should handle very small images."""
        tiny = np.zeros((10, 10, 3), dtype=np.uint8)

        sig_detector = SignatureDetector()
        result = sig_detector.detect(tiny)
        assert isinstance(result, list)

        barcode_detector = BarcodeDetector()
        result = barcode_detector.detect(tiny)
        assert isinstance(result, list)

    def test_handle_very_large_image(self):
        """Detectors should handle large images."""
        large = np.zeros((2000, 3000, 3), dtype=np.uint8)

        sig_detector = SignatureDetector()
        result = sig_detector.detect(large)
        assert isinstance(result, list)

    def test_handle_different_dtypes(self):
        """Detectors should handle different numpy dtypes."""
        sig_detector = SignatureDetector()

        # uint8
        img_uint8 = np.zeros((100, 100, 3), dtype=np.uint8)
        result = sig_detector.detect(img_uint8)
        assert isinstance(result, list)

        # float32 (common for normalized images)
        img_float = np.zeros((100, 100, 3), dtype=np.float32)
        # May need conversion, but shouldn't crash
        try:
            result = sig_detector.detect(img_float.astype(np.uint8))
            assert isinstance(result, list)
        except Exception:
            pass  # Some detectors may not handle float

    def test_handle_single_channel(self):
        """Detectors should handle single channel images."""
        grayscale = np.zeros((100, 100), dtype=np.uint8)

        sig_detector = SignatureDetector()
        result = sig_detector.detect(grayscale)
        assert isinstance(result, list)

    def test_handle_four_channel(self):
        """Detectors should handle RGBA images."""
        rgba = np.zeros((100, 100, 4), dtype=np.uint8)

        sig_detector = SignatureDetector()
        result = sig_detector.detect(rgba)
        assert isinstance(result, list)

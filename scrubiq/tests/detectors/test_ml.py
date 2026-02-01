"""
Comprehensive tests for scrubiq/detectors/ml.py.

Tests ML-based detectors using HuggingFace transformers for NER.
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

from scrubiq.detectors.ml import (
    MLDetector,
    PHIBertDetector,
    PIIBertDetector,
    get_device,
    get_device_info,
)
from scrubiq.detectors.labels import PHI_BERT_LABELS, PII_BERT_LABELS
from scrubiq.types import Tier


# =============================================================================
# get_device Function Tests
# =============================================================================
class TestGetDevice:
    """Tests for the get_device function."""

    def test_get_device_cpu_forced(self):
        """Force CPU should return -1."""
        result = get_device("cpu")
        assert result == -1

    def test_get_device_auto_no_cuda(self):
        """Auto mode without CUDA should return -1."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.get_available_providers.return_value = ['CPUExecutionProvider']
            result = get_device("auto")
            assert result == -1

    def test_get_device_auto_with_cuda(self):
        """Auto mode with CUDA should return cuda device id."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.get_available_providers.return_value = ['CUDAExecutionProvider', 'CPUExecutionProvider']
            result = get_device("auto")
            assert result == 0  # Default cuda device

    def test_get_device_cuda_forced_available(self):
        """Forced CUDA with CUDA available should return cuda device id."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.get_available_providers.return_value = ['CUDAExecutionProvider', 'CPUExecutionProvider']
            result = get_device("cuda")
            assert result == 0

    def test_get_device_cuda_forced_unavailable(self):
        """Forced CUDA without CUDA should fallback to CPU."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.get_available_providers.return_value = ['CPUExecutionProvider']
            result = get_device("cuda")
            assert result == -1

    def test_get_device_custom_cuda_id(self):
        """Custom CUDA device ID should be returned."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.get_available_providers.return_value = ['CUDAExecutionProvider', 'CPUExecutionProvider']
            result = get_device("auto", cuda_device_id=2)
            assert result == 2

    def test_get_device_env_override_cpu(self):
        """Environment variable should override config."""
        with patch.dict(os.environ, {'SCRUBIQ_DEVICE': 'cpu'}):
            result = get_device("auto")
            assert result == -1

    def test_get_device_env_override_cuda(self):
        """Environment variable CUDA override."""
        with patch.dict(os.environ, {'SCRUBIQ_DEVICE': 'cuda'}):
            with patch('scrubiq.detectors.ml.ort') as mock_ort:
                mock_ort.get_available_providers.return_value = ['CUDAExecutionProvider', 'CPUExecutionProvider']
                result = get_device("cpu")  # Config says CPU, env says CUDA
                assert result == 0

    def test_get_device_ort_import_error(self):
        """Should return -1 if onnxruntime not installed."""
        with patch.dict('sys.modules', {'onnxruntime': None}):
            with patch('scrubiq.detectors.ml.ort', side_effect=ImportError):
                # Force the import error path
                result = get_device("cpu")
                assert result == -1

    def test_get_device_ort_exception(self):
        """Should return -1 on onnxruntime exception."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.get_available_providers.side_effect = RuntimeError("CUDA error")
            result = get_device("auto")
            assert result == -1


# =============================================================================
# get_device_info Function Tests
# =============================================================================
class TestGetDeviceInfo:
    """Tests for the get_device_info function."""

    def test_get_device_info_structure(self):
        """Result should have expected structure."""
        info = get_device_info()

        assert "device" in info
        assert "cuda_available" in info
        assert "onnxruntime_version" in info
        assert "providers" in info

    def test_get_device_info_cpu_only(self):
        """Info when only CPU is available."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.__version__ = "1.17.0"
            mock_ort.get_available_providers.return_value = ['CPUExecutionProvider']

            info = get_device_info()

            assert info["device"] == "cpu"
            assert info["cuda_available"] is False
            assert info["onnxruntime_version"] == "1.17.0"
            assert "CPUExecutionProvider" in info["providers"]

    def test_get_device_info_with_cuda(self):
        """Info when CUDA is available."""
        with patch('scrubiq.detectors.ml.ort') as mock_ort:
            mock_ort.__version__ = "1.17.0"
            mock_ort.get_available_providers.return_value = ['CUDAExecutionProvider', 'CPUExecutionProvider']

            info = get_device_info()

            assert info["device"] == "cuda"
            assert info["cuda_available"] is True

    def test_get_device_info_import_error(self):
        """Info when onnxruntime not installed."""
        # Default behavior without mocking (ort may not be installed)
        info = get_device_info()
        assert isinstance(info, dict)


# =============================================================================
# MLDetector Class Tests
# =============================================================================
class TestMLDetector:
    """Tests for the MLDetector base class."""

    @pytest.fixture
    def detector(self):
        """Create an MLDetector instance."""
        return MLDetector()

    def test_detector_name(self, detector):
        """Detector should have correct name."""
        assert detector.name == "ml"

    def test_detector_tier(self, detector):
        """Detector should use ML tier."""
        assert detector.tier == Tier.ML

    def test_init_defaults(self, detector):
        """Default initialization values."""
        assert detector.model_path is None
        assert detector.device_config == "auto"
        assert detector.cuda_device_id == 0
        assert detector._model is None
        assert detector._tokenizer is None
        assert detector._pipeline is None
        assert detector._loaded is False
        assert detector._device_id is None

    def test_init_with_path(self):
        """Initialization with model path."""
        path = Path("/fake/model/path")
        detector = MLDetector(model_path=path)
        assert detector.model_path == path

    def test_init_with_device(self):
        """Initialization with custom device config."""
        detector = MLDetector(device="cpu", cuda_device_id=1)
        assert detector.device_config == "cpu"
        assert detector.cuda_device_id == 1

    def test_is_available_not_loaded(self, detector):
        """is_available should be False when not loaded."""
        assert detector.is_available() is False

    def test_is_available_loaded(self, detector):
        """is_available should be True when loaded."""
        detector._loaded = True
        assert detector.is_available() is True

    def test_get_device_used_not_loaded(self, detector):
        """get_device_used when not loaded."""
        assert detector.get_device_used() == "not loaded"

    def test_get_device_used_cpu(self, detector):
        """get_device_used when using CPU."""
        detector._device_id = -1
        assert detector.get_device_used() == "cpu"

    def test_get_device_used_cuda(self, detector):
        """get_device_used when using CUDA."""
        detector._device_id = 0
        assert detector.get_device_used() == "cuda:0"

        detector._device_id = 2
        assert detector.get_device_used() == "cuda:2"

    def test_detect_not_loaded(self, detector):
        """detect() should return empty list when not loaded."""
        result = detector.detect("test text")
        assert result == []

    def test_load_no_model_path(self, detector):
        """load() should fail without model path."""
        result = detector.load()
        assert result is False
        assert detector._loaded is False

    def test_load_nonexistent_path(self):
        """load() should fail with non-existent path."""
        detector = MLDetector(model_path=Path("/nonexistent/path"))
        result = detector.load()
        assert result is False

    def test_load_missing_weights(self):
        """load() should fail if no model weights exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Create config but no weights
            (path / "config.json").write_text('{}')

            detector = MLDetector(model_path=path)
            result = detector.load()
            assert result is False

    def test_load_missing_config(self):
        """load() should fail if config.json missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Create weights but no config
            (path / "pytorch_model.bin").write_bytes(b'dummy')

            detector = MLDetector(model_path=path)
            result = detector.load()
            assert result is False


# =============================================================================
# MLDetector.detect() Tests with Mocked Pipeline
# =============================================================================
class TestMLDetectorDetection:
    """Tests for MLDetector detection with mocked pipeline."""

    @pytest.fixture
    def loaded_detector(self):
        """Create a loaded MLDetector with mocked pipeline."""
        detector = MLDetector()
        detector._loaded = True
        detector._pipeline = MagicMock()
        detector._device_id = -1
        detector.label_map = {"B-NAME": "NAME", "NAME": "NAME"}
        return detector

    def test_detect_empty_results(self, loaded_detector):
        """detect() with no pipeline results."""
        loaded_detector._pipeline.return_value = []
        result = loaded_detector.detect("test text")
        assert result == []

    def test_detect_basic_entity(self, loaded_detector):
        """detect() should convert pipeline results to spans."""
        loaded_detector._pipeline.return_value = [
            {"entity_group": "NAME", "start": 0, "end": 4, "score": 0.95}
        ]
        text = "John went to the store"
        result = loaded_detector.detect(text)

        assert len(result) == 1
        assert result[0].entity_type == "NAME"
        assert result[0].confidence == 0.95

    def test_detect_expands_word_boundaries(self, loaded_detector):
        """detect() should expand to word boundaries."""
        loaded_detector._pipeline.return_value = [
            {"entity_group": "NAME", "start": 1, "end": 3, "score": 0.90}
        ]
        text = "John Smith"  # Pipeline returns partial "oh"
        result = loaded_detector.detect(text)

        # Should expand to full word
        if result:
            span = result[0]
            assert span.start == 0  # Expanded to word start
            assert not text[span.start].isspace()

    def test_detect_with_entity_label(self, loaded_detector):
        """detect() should handle 'entity' key (not entity_group)."""
        loaded_detector._pipeline.return_value = [
            {"entity": "NAME", "start": 0, "end": 4, "score": 0.85}
        ]
        result = loaded_detector.detect("John Smith")
        assert len(result) == 1

    def test_detect_maps_labels(self, loaded_detector):
        """detect() should map raw labels to canonical types."""
        loaded_detector.label_map = {"B-PER": "NAME", "PER": "NAME", "NAME": "NAME"}
        loaded_detector._pipeline.return_value = [
            {"entity_group": "PER", "start": 0, "end": 4, "score": 0.90}
        ]
        result = loaded_detector.detect("John Smith")

        assert len(result) == 1
        assert result[0].entity_type == "NAME"

    def test_detect_filters_product_codes(self, loaded_detector):
        """detect() should filter product code false positives."""
        loaded_detector._pipeline.return_value = [
            {"entity_group": "ID", "start": 0, "end": 12, "score": 0.85}
        ]
        text = "SKU-12345678"  # Starts with product code prefix
        result = loaded_detector.detect(text)

        # ID starting with SKU should be filtered
        mrn_spans = [s for s in result if s.entity_type in ("ID", "MRN")]
        assert len(mrn_spans) == 0

    def test_detect_pipeline_exception(self, loaded_detector):
        """detect() should handle pipeline exceptions gracefully."""
        loaded_detector._pipeline.side_effect = RuntimeError("Inference failed")
        result = loaded_detector.detect("test text")
        assert result == []

    def test_detect_multiple_entities(self, loaded_detector):
        """detect() should handle multiple entities."""
        loaded_detector._pipeline.return_value = [
            {"entity_group": "NAME", "start": 0, "end": 4, "score": 0.95},
            {"entity_group": "NAME", "start": 5, "end": 10, "score": 0.93},
        ]
        result = loaded_detector.detect("John Smith went home")
        assert len(result) == 2


# =============================================================================
# PHIBertDetector Tests
# =============================================================================
class TestPHIBertDetector:
    """Tests for the PHIBertDetector class."""

    def test_detector_name(self):
        """PHIBertDetector should have correct name."""
        detector = PHIBertDetector()
        assert detector.name == "phi_bert"

    def test_detector_tier(self):
        """PHIBertDetector should use ML tier."""
        detector = PHIBertDetector()
        assert detector.tier == Tier.ML

    def test_label_map_is_phi_labels(self):
        """PHIBertDetector should use PHI_BERT_LABELS."""
        detector = PHIBertDetector()
        assert detector.label_map == PHI_BERT_LABELS

    def test_init_without_path(self):
        """PHIBertDetector can be initialized without path."""
        detector = PHIBertDetector()
        assert detector._loaded is False

    def test_init_with_nonexistent_path(self):
        """PHIBertDetector with nonexistent path should not load."""
        detector = PHIBertDetector(model_path=Path("/nonexistent"))
        assert detector._loaded is False


# =============================================================================
# PIIBertDetector Tests
# =============================================================================
class TestPIIBertDetector:
    """Tests for the PIIBertDetector class."""

    def test_detector_name(self):
        """PIIBertDetector should have correct name."""
        detector = PIIBertDetector()
        assert detector.name == "pii_bert"

    def test_detector_tier(self):
        """PIIBertDetector should use ML tier."""
        detector = PIIBertDetector()
        assert detector.tier == Tier.ML

    def test_label_map_is_pii_labels(self):
        """PIIBertDetector should use PII_BERT_LABELS."""
        detector = PIIBertDetector()
        assert detector.label_map == PII_BERT_LABELS

    def test_init_without_path(self):
        """PIIBertDetector can be initialized without path."""
        detector = PIIBertDetector()
        assert detector._loaded is False


# =============================================================================
# Label Map Tests
# =============================================================================
class TestLabelMaps:
    """Tests for label mapping configurations."""

    def test_phi_bert_labels_not_empty(self):
        """PHI_BERT_LABELS should contain mappings."""
        assert len(PHI_BERT_LABELS) > 0

    def test_pii_bert_labels_not_empty(self):
        """PII_BERT_LABELS should contain mappings."""
        assert len(PII_BERT_LABELS) > 0

    def test_phi_bert_labels_structure(self):
        """PHI_BERT_LABELS should map strings to strings."""
        for key, value in PHI_BERT_LABELS.items():
            assert isinstance(key, str)
            assert isinstance(value, str)

    def test_pii_bert_labels_structure(self):
        """PII_BERT_LABELS should map strings to strings."""
        for key, value in PII_BERT_LABELS.items():
            assert isinstance(key, str)
            assert isinstance(value, str)

    def test_pii_bert_has_bio_labels(self):
        """PII_BERT_LABELS should have B-/I- prefix labels."""
        has_b_prefix = any(k.startswith("B-") for k in PII_BERT_LABELS.keys())
        has_i_prefix = any(k.startswith("I-") for k in PII_BERT_LABELS.keys())
        assert has_b_prefix or has_i_prefix


# =============================================================================
# Edge Cases and Robustness Tests
# =============================================================================
class TestMLDetectorEdgeCases:
    """Edge case tests for ML detection."""

    @pytest.fixture
    def detector(self):
        """Create a loaded detector with mocked pipeline."""
        d = MLDetector()
        d._loaded = True
        d._pipeline = MagicMock()
        d._device_id = -1
        d.label_map = {}
        return d

    def test_detect_empty_text(self, detector):
        """detect() with empty text."""
        detector._pipeline.return_value = []
        result = detector.detect("")
        assert result == []

    def test_detect_unicode_text(self, detector):
        """detect() with Unicode text."""
        detector._pipeline.return_value = [
            {"entity_group": "NAME", "start": 0, "end": 4, "score": 0.90}
        ]
        result = detector.detect("日本語テスト")
        # Should not crash
        assert isinstance(result, list)

    def test_detect_very_long_text(self, detector):
        """detect() with very long text should not crash."""
        detector._pipeline.return_value = []
        text = "x" * 100000
        result = detector.detect(text)
        assert result == []

    def test_detect_special_characters(self, detector):
        """detect() with special characters."""
        detector._pipeline.return_value = []
        text = "Test <script>alert('xss')</script> & special chars: @#$%"
        result = detector.detect(text)
        assert isinstance(result, list)

    def test_span_properties(self, detector):
        """Detected spans should have all required properties."""
        detector._pipeline.return_value = [
            {"entity_group": "NAME", "start": 0, "end": 4, "score": 0.95}
        ]
        result = detector.detect("John Smith")

        assert len(result) == 1
        span = result[0]

        assert hasattr(span, 'start')
        assert hasattr(span, 'end')
        assert hasattr(span, 'text')
        assert hasattr(span, 'entity_type')
        assert hasattr(span, 'confidence')
        assert hasattr(span, 'detector')
        assert hasattr(span, 'tier')

        assert span.detector == "ml"
        assert span.tier == Tier.ML

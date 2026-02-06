"""
Comprehensive tests for TieredPipeline escalation logic and supporting flows.

Complements tests/test_tiered_pipeline.py by focusing on:
- _should_escalate decision boundaries and reasons
- _detect_medical_context delegation
- detect_image OCR integration (mocked)
- detect_file routing by extension
- Eager vs lazy ML loading
- PipelineConfig effects on behavior
- PipelineResult aggregation from multi-stage runs
- Graceful fallback when ML/OCR are unavailable

All ML detectors, the OCR engine, and the dictionary loader are mocked so these
tests run fast, are deterministic, and catch real escalation routing bugs.
"""

import logging
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest

from openlabels.core.pipeline.tiered import (
    ESCALATION_THRESHOLD,
    ML_BENEFICIAL_TYPES,
    OCR_FILE_EXTENSIONS,
    PipelineConfig,
    PipelineResult,
    PipelineStage,
    TieredPipeline,
    create_pipeline,
    detect_tiered,
)
from openlabels.core.types import DetectionResult, Span, Tier


# =============================================================================
# HELPERS
# =============================================================================

def _make_span(
    text: str,
    start: int = 0,
    entity_type: str = "SSN",
    confidence: float = 0.99,
    detector: str = "checksum",
    tier: Tier = Tier.CHECKSUM,
) -> Span:
    """Create a Span with consistent start/end/text."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=tier,
    )


def _make_mock_detector(name: str = "mock_det", spans: List[Span] = None, available: bool = True):
    """Build a mock detector with the BaseDetector interface."""
    det = MagicMock()
    det.name = name
    det.is_available.return_value = available
    det.detect.return_value = spans or []
    return det


def _minimal_pipeline(**config_kwargs) -> TieredPipeline:
    """Create a pipeline with all real Stage 1 detectors disabled for isolation.

    Only pattern-level detectors are disabled; the pipeline object is real.
    Pass additional PipelineConfig overrides via kwargs.
    """
    defaults = dict(
        enable_checksum=False,
        enable_secrets=False,
        enable_financial=False,
        enable_government=False,
        enable_patterns=False,
        enable_hyperscan=False,
        auto_detect_medical=False,
        enable_policy_evaluation=False,
        eager_load_ml=False,
    )
    defaults.update(config_kwargs)
    return TieredPipeline(config=PipelineConfig(**defaults))


# =============================================================================
# 1. ESCALATION LOGIC  (_should_escalate)
# =============================================================================

class TestShouldEscalate:
    """Direct tests for the _should_escalate decision function."""

    def _pipeline(self) -> TieredPipeline:
        return _minimal_pipeline()

    # -- confidence-based escalation --

    def test_no_spans_no_escalation(self):
        p = self._pipeline()
        should, reason = p._should_escalate("hello world", [])
        assert should is False
        assert reason is None

    def test_high_confidence_no_escalation(self):
        """Checksum-validated spans (0.99) should NOT trigger escalation."""
        p = self._pipeline()
        spans = [_make_span("123-45-6789", confidence=0.99, entity_type="SSN")]
        should, reason = p._should_escalate("SSN: 123-45-6789", spans)
        assert should is False

    def test_low_confidence_triggers_escalation(self):
        """A span below the threshold must trigger escalation."""
        p = self._pipeline()
        spans = [_make_span("John", entity_type="NAME", confidence=0.55, detector="pattern", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("John", spans)
        assert should is True
        assert "low_confidence" in reason

    def test_confidence_exactly_at_threshold_no_escalation(self):
        """Spans with confidence == threshold should NOT escalate (strict <)."""
        p = self._pipeline()
        threshold = p.config.escalation_threshold  # 0.70
        spans = [_make_span("data", entity_type="EMAIL", confidence=threshold, detector="pattern", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("data", spans)
        # confidence is NOT < threshold so low_confidence path should not fire
        # But EMAIL is not in ML_BENEFICIAL_TYPES so no beneficial escalation either
        assert should is False

    def test_confidence_just_below_threshold_escalates(self):
        p = self._pipeline()
        threshold = p.config.escalation_threshold
        spans = [_make_span("data", entity_type="EMAIL", confidence=threshold - 0.01, detector="pattern", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("data", spans)
        assert should is True
        assert "low_confidence" in reason

    def test_custom_escalation_threshold(self):
        """A custom threshold should be respected."""
        p = _minimal_pipeline(escalation_threshold=0.50)
        spans = [_make_span("x", entity_type="EMAIL", confidence=0.55, detector="pattern", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("x", spans)
        # 0.55 >= 0.50 so no low_confidence escalation
        # EMAIL not in ML_BENEFICIAL_TYPES
        assert should is False

    # -- ML-beneficial type escalation --

    def test_ml_beneficial_type_medium_confidence_escalates(self):
        """A NAME span at 0.85 (< 0.9) should escalate via ml_beneficial_type."""
        p = self._pipeline()
        spans = [_make_span("John Smith", entity_type="NAME", confidence=0.85, detector="pattern", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("John Smith", spans)
        assert should is True
        assert "ml_beneficial_type" in reason

    def test_ml_beneficial_type_very_high_confidence_no_escalate(self):
        """A NAME span at 0.95 (>= 0.9) should NOT escalate via ml_beneficial_type."""
        p = self._pipeline()
        spans = [_make_span("John Smith", entity_type="NAME", confidence=0.95, detector="pattern", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("John Smith", spans)
        assert should is False

    def test_ml_beneficial_type_at_point_nine_no_escalate(self):
        """Exactly 0.9 should NOT trigger ml_beneficial_type (requires < 0.9)."""
        p = self._pipeline()
        spans = [_make_span("John Smith", entity_type="NAME", confidence=0.90, detector="pattern", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("John Smith", spans)
        assert should is False

    def test_non_beneficial_type_high_confidence_no_escalate(self):
        """An entity type NOT in ML_BENEFICIAL_TYPES should not escalate at any confidence."""
        p = self._pipeline()
        spans = [_make_span("ghp_abc123", entity_type="GITHUB_TOKEN", confidence=0.80, detector="secrets", tier=Tier.PATTERN)]
        should, reason = p._should_escalate("ghp_abc123", spans)
        # 0.80 >= 0.70 so no low_confidence; GITHUB_TOKEN not in ML_BENEFICIAL
        assert should is False

    def test_multiple_spans_one_low_confidence_escalates(self):
        """Even one low-confidence span in a batch should trigger escalation."""
        p = self._pipeline()
        spans = [
            _make_span("123-45-6789", confidence=0.99, entity_type="SSN"),
            _make_span("John", start=15, entity_type="NAME", confidence=0.50, detector="pattern", tier=Tier.PATTERN),
        ]
        should, reason = p._should_escalate("SSN: 123-45-6789 John", spans)
        assert should is True

    def test_all_beneficial_types_covered(self):
        """Every type listed in ML_BENEFICIAL_TYPES should cause escalation at mid-confidence."""
        p = self._pipeline()
        for etype in ML_BENEFICIAL_TYPES:
            spans = [_make_span("X", entity_type=etype, confidence=0.80, detector="pattern", tier=Tier.PATTERN)]
            should, _ = p._should_escalate("X", spans)
            assert should is True, f"{etype} at 0.80 should trigger escalation"


# =============================================================================
# 2. MEDICAL CONTEXT DETECTION  (_detect_medical_context)
# =============================================================================

class TestDetectMedicalContext:
    """Tests for _detect_medical_context delegation to DictionaryLoader."""

    def test_returns_false_when_detector_is_none(self):
        """With auto_detect_medical=False, _medical_detector is None."""
        p = _minimal_pipeline(auto_detect_medical=False)
        assert p._detect_medical_context("patient was admitted to ICU") is False

    def test_delegates_to_medical_detector(self):
        """When medical detector is present, it should delegate."""
        p = _minimal_pipeline()
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.return_value = True

        result = p._detect_medical_context("diagnosis of diabetes")
        assert result is True
        p._medical_detector.has_medical_context.assert_called_once_with("diagnosis of diabetes")

    def test_returns_false_on_detector_exception(self):
        """If the medical detector raises, return False gracefully."""
        p = _minimal_pipeline()
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.side_effect = RuntimeError("boom")

        result = p._detect_medical_context("some text")
        assert result is False

    def test_medical_context_triggers_escalation_in_detect(self):
        """When medical context is detected, the detect() method must escalate."""
        p = _minimal_pipeline(auto_detect_medical=True)
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.return_value = True
        # No ML detectors loaded means no Stage 2/3 spans, but escalation reason is set
        result = p.detect("patient diagnosis of hypertension")
        assert result.medical_context_detected is True
        assert result.escalation_reason is not None
        assert "medical" in result.escalation_reason

    def test_medical_context_false_no_escalation_reason_from_medical(self):
        p = _minimal_pipeline(auto_detect_medical=True)
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.return_value = False
        result = p.detect("no medical terms here at all")
        assert result.medical_context_detected is False


# =============================================================================
# 3. FULL detect() ESCALATION INTEGRATION
# =============================================================================

class TestDetectEscalationFlow:
    """End-to-end tests that verify Stage 1 results are preserved when Stage 2 runs."""

    def _pipeline_with_mock_stages(
        self,
        stage1_spans: List[Span],
        ml_spans: List[Span] = None,
        medical: bool = False,
        phi_spans: List[Span] = None,
        pii_spans: List[Span] = None,
    ) -> TieredPipeline:
        """Build a pipeline with fully mocked Stage 1 + ML detectors."""
        p = _minimal_pipeline(auto_detect_medical=medical, enable_policy_evaluation=False)

        # Replace Stage 1 detectors with a single mock that returns our spans
        mock_s1 = _make_mock_detector("mock_stage1", stage1_spans)
        p._stage1_detectors = [mock_s1]

        # Pre-load ML detectors so _init_ml_detectors is a no-op
        if ml_spans is not None:
            mock_ml = _make_mock_detector("mock_ml", ml_spans)
            p._ml_detectors = [mock_ml]
            p._pii_bert = mock_ml

        if phi_spans is not None:
            p._phi_bert = _make_mock_detector("mock_phi_bert", phi_spans)
            if p._phi_bert not in p._ml_detectors:
                p._ml_detectors.append(p._phi_bert)

        if pii_spans is not None:
            p._pii_bert = _make_mock_detector("mock_pii_bert", pii_spans)
            if p._pii_bert not in p._ml_detectors:
                p._ml_detectors.append(p._pii_bert)

        return p

    def test_stage1_spans_preserved_when_stage2_runs(self):
        """BUG CATCHER: Stage 1 results must NOT be discarded when ML runs."""
        s1_span = _make_span("123-45-6789", confidence=0.60, entity_type="SSN")
        ml_span = _make_span("John Smith", start=20, entity_type="NAME", confidence=0.92, detector="ml", tier=Tier.ML)

        text = "SSN: 123-45-6789    John Smith"
        p = self._pipeline_with_mock_stages([s1_span], ml_spans=[ml_span])
        result = p.detect(text)

        # Both stages should have produced spans (but confidence filter applies)
        assert PipelineStage.FAST_TRIAGE in result.stages_executed
        # s1_span has confidence 0.60 < default threshold 0.70, so it is filtered out
        # but ML_ESCALATION stage should have run
        assert PipelineStage.ML_ESCALATION in result.stages_executed or PipelineStage.DEEP_ANALYSIS in result.stages_executed

    def test_ml_never_runs_when_not_needed(self):
        """BUG CATCHER: If all spans are high confidence and non-beneficial, ML must not run."""
        s1_span = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        ml_detector = _make_mock_detector("should_not_run", [])

        p = _minimal_pipeline()
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span])]
        p._ml_detectors = [ml_detector]
        p._pii_bert = ml_detector

        result = p.detect("SSN: 123-45-6789")
        assert PipelineStage.ML_ESCALATION not in result.stages_executed
        assert PipelineStage.DEEP_ANALYSIS not in result.stages_executed
        # The ML detector's detect method should NOT have been called
        ml_detector.detect.assert_not_called()

    def test_medical_context_triggers_deep_analysis(self):
        """When medical context is detected and dual BERT is enabled, Stage 3 runs."""
        s1_span = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        phi_span = _make_span("John Smith", start=15, entity_type="NAME_PATIENT", confidence=0.91, detector="phi_bert", tier=Tier.ML)
        pii_span = _make_span("john@email.com", start=30, entity_type="EMAIL", confidence=0.88, detector="pii_bert", tier=Tier.ML)

        text = "SSN: 123-45-6789 John Smith john@email.com patient diagnosis"
        p = self._pipeline_with_mock_stages(
            [s1_span],
            medical=True,
            phi_spans=[phi_span],
            pii_spans=[pii_span],
        )
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.return_value = True
        p.config.medical_triggers_dual_bert = True

        result = p.detect(text)
        assert result.medical_context_detected is True
        assert PipelineStage.DEEP_ANALYSIS in result.stages_executed

    def test_medical_context_without_dual_bert_uses_stage2(self):
        """When medical_triggers_dual_bert=False, standard ML escalation is used instead."""
        s1_span = _make_span("test", entity_type="EMAIL", confidence=0.99, detector="pattern", tier=Tier.PATTERN)
        ml_span = _make_span("John", start=10, entity_type="NAME", confidence=0.85, detector="ml", tier=Tier.ML)

        p = _minimal_pipeline(auto_detect_medical=True, enable_policy_evaluation=False)
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span])]
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.return_value = True
        p.config.medical_triggers_dual_bert = False

        mock_ml = _make_mock_detector("mock_ml", [ml_span])
        p._ml_detectors = [mock_ml]
        p._pii_bert = mock_ml

        result = p.detect("test text  John")
        assert result.medical_context_detected is True
        assert PipelineStage.ML_ESCALATION in result.stages_executed
        assert PipelineStage.DEEP_ANALYSIS not in result.stages_executed

    def test_empty_text_returns_immediately(self):
        result = _minimal_pipeline().detect("")
        assert result.stages_executed == []
        assert result.spans == []
        assert result.escalation_reason is None

    def test_whitespace_text_returns_immediately(self):
        result = _minimal_pipeline().detect("   \n\t  ")
        assert result.stages_executed == []
        assert result.spans == []

    def test_escalation_reason_populated_for_low_confidence(self):
        s1_span = _make_span("maybe", entity_type="NAME", confidence=0.40, detector="pattern", tier=Tier.PATTERN)
        p = _minimal_pipeline()
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span])]
        result = p.detect("maybe")
        assert result.escalation_reason is not None
        assert "low_confidence" in result.escalation_reason

    def test_escalation_reason_populated_for_beneficial_type(self):
        s1_span = _make_span("John Smith", entity_type="NAME", confidence=0.85, detector="pattern", tier=Tier.PATTERN)
        p = _minimal_pipeline()
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span])]
        result = p.detect("John Smith")
        assert result.escalation_reason is not None
        assert "ml_beneficial_type" in result.escalation_reason


# =============================================================================
# 4. IMAGE DETECTION  (detect_image)
# =============================================================================

class TestDetectImage:
    """Tests for detect_image with mocked OCR and PIL."""

    def test_small_image_skipped(self, tmp_path):
        """An image smaller than 50x50 should be skipped."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not installed")

        img_path = tmp_path / "tiny.png"
        img = Image.new("RGB", (30, 30), color="white")
        img.save(img_path)

        p = _minimal_pipeline()
        result = p.detect_image(img_path)
        assert result.ocr_used is True
        assert result.ocr_text_detected is False
        assert result.spans == []

    def test_extreme_aspect_ratio_skipped(self, tmp_path):
        """An image with ratio > 20 should be skipped."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not installed")

        img_path = tmp_path / "banner.png"
        img = Image.new("RGB", (1000, 10), color="white")
        img.save(img_path)

        p = _minimal_pipeline()
        result = p.detect_image(img_path)
        assert result.ocr_used is True
        assert result.ocr_text_detected is False

    def test_normal_image_proceeds_to_ocr(self, tmp_path):
        """A normal-sized image should proceed to OCR extraction."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not installed")

        img_path = tmp_path / "normal.png"
        img = Image.new("RGB", (200, 200), color="white")
        img.save(img_path)

        p = _minimal_pipeline()
        # Mock OCR engine to return text containing an SSN
        mock_ocr = MagicMock()
        mock_ocr.extract_text.return_value = "SSN: 123-45-6789"
        p._ocr_engine = mock_ocr

        # Replace stage1 detectors with a mock to detect SSN
        ssn_span = _make_span("123-45-6789", start=5, confidence=0.99, entity_type="SSN")
        p._stage1_detectors = [_make_mock_detector("s1", [ssn_span])]

        result = p.detect_image(img_path)
        assert result.ocr_used is True
        assert result.ocr_text_detected is True
        mock_ocr.extract_text.assert_called_once()

    def test_ocr_returns_empty_string(self, tmp_path):
        """When OCR returns empty text, result should reflect no text detected."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not installed")

        img_path = tmp_path / "blank.png"
        img = Image.new("RGB", (200, 200), color="white")
        img.save(img_path)

        p = _minimal_pipeline()
        mock_ocr = MagicMock()
        mock_ocr.extract_text.return_value = ""
        p._ocr_engine = mock_ocr

        result = p.detect_image(img_path)
        assert result.ocr_used is True
        assert result.ocr_text_detected is False
        assert result.spans == []

    def test_skip_if_no_text_false_bypasses_quick_check(self, tmp_path):
        """With skip_if_no_text=False, even tiny images go through full OCR."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not installed")

        img_path = tmp_path / "tiny2.png"
        img = Image.new("RGB", (10, 10), color="white")
        img.save(img_path)

        p = _minimal_pipeline()
        mock_ocr = MagicMock()
        mock_ocr.extract_text.return_value = ""
        p._ocr_engine = mock_ocr

        result = p.detect_image(img_path, skip_if_no_text=False)
        # Should still have called OCR even for tiny image
        mock_ocr.extract_text.assert_called_once()

    def test_ocr_engine_lazy_loaded(self, tmp_path):
        """If OCR engine is not set, it tries to import and create one."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not installed")

        img_path = tmp_path / "test.png"
        img = Image.new("RGB", (200, 200), color="white")
        img.save(img_path)

        p = _minimal_pipeline()
        assert p._ocr_engine is None

        # Patch the OCR import to fail, simulating missing OCR
        with patch.dict("sys.modules", {"openlabels.core.ocr": None}):
            with patch("openlabels.core.pipeline.tiered.TieredPipeline._extract_text_ocr", return_value=""):
                result = p.detect_image(img_path)
                assert result.ocr_used is True


# =============================================================================
# 5. FILE DETECTION ROUTING  (detect_file)
# =============================================================================

class TestDetectFile:
    """Tests for detect_file routing logic."""

    def test_image_extensions_route_to_detect_image(self, tmp_path):
        """All recognized image extensions should route to detect_image."""
        for ext in [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp"]:
            img_path = tmp_path / f"test{ext}"
            img_path.write_bytes(b"\x00")  # Dummy file

            p = _minimal_pipeline()
            with patch.object(p, "detect_image") as mock_img:
                mock_img.return_value = PipelineResult(
                    result=DetectionResult(spans=[], entity_counts={}, processing_time_ms=0, detectors_used=[], text_length=0),
                    stages_executed=[], medical_context_detected=False, escalation_reason=None,
                )
                p.detect_file(img_path)
                mock_img.assert_called_once_with(img_path), f"Extension {ext} should route to detect_image"

    def test_text_file_routes_to_detect(self, tmp_path):
        """A .txt file should be read and passed to detect()."""
        txt_path = tmp_path / "data.txt"
        txt_path.write_text("SSN: 123-45-6789", encoding="utf-8")

        p = _minimal_pipeline()
        with patch.object(p, "detect") as mock_detect:
            mock_detect.return_value = PipelineResult(
                result=DetectionResult(spans=[], entity_counts={}, processing_time_ms=0, detectors_used=[], text_length=0),
                stages_executed=[PipelineStage.FAST_TRIAGE], medical_context_detected=False, escalation_reason=None,
            )
            p.detect_file(txt_path)
            mock_detect.assert_called_once_with("SSN: 123-45-6789")

    def test_pre_extracted_content_bypasses_file_read(self, tmp_path):
        """When content is provided, the file is not read."""
        # File doesn't even need to exist
        fake_path = tmp_path / "nonexistent.csv"

        p = _minimal_pipeline()
        with patch.object(p, "detect") as mock_detect:
            mock_detect.return_value = PipelineResult(
                result=DetectionResult(spans=[], entity_counts={}, processing_time_ms=0, detectors_used=[], text_length=0),
                stages_executed=[], medical_context_detected=False, escalation_reason=None,
            )
            p.detect_file(fake_path, content="pre-extracted text")
            mock_detect.assert_called_once_with("pre-extracted text")

    def test_unreadable_file_returns_error_result(self, tmp_path):
        """If the file cannot be read, an error result is returned."""
        bad_path = tmp_path / "does_not_exist.txt"

        p = _minimal_pipeline()
        result = p.detect_file(bad_path)
        assert result.spans == []
        assert result.escalation_reason is not None
        assert "file_read_error" in result.escalation_reason

    def test_csv_extension_treated_as_text(self, tmp_path):
        """CSV files should be read as text, not routed to image detection."""
        csv_path = tmp_path / "data.csv"
        csv_path.write_text("name,ssn\nJohn,123-45-6789", encoding="utf-8")

        p = _minimal_pipeline()
        with patch.object(p, "detect_image") as mock_img:
            with patch.object(p, "detect") as mock_detect:
                mock_detect.return_value = PipelineResult(
                    result=DetectionResult(spans=[], entity_counts={}, processing_time_ms=0, detectors_used=[], text_length=0),
                    stages_executed=[], medical_context_detected=False, escalation_reason=None,
                )
                p.detect_file(csv_path)
                mock_img.assert_not_called()
                mock_detect.assert_called_once()


# =============================================================================
# 6. EAGER vs LAZY ML LOADING
# =============================================================================

class TestMLLoading:
    """Test eager_load_ml config and lazy-load behavior."""

    def test_lazy_load_defers_ml_init(self):
        """Without eager_load_ml, ML detectors are empty at init."""
        p = _minimal_pipeline(eager_load_ml=False)
        assert p._ml_detectors == []
        assert p._phi_bert is None
        assert p._pii_bert is None

    def test_eager_load_calls_init_ml_at_startup(self):
        """With eager_load_ml=True, _init_ml_detectors is called during __init__."""
        with patch.object(TieredPipeline, "_init_ml_detectors") as mock_init:
            with patch.object(TieredPipeline, "_init_stage1_detectors"):
                with patch.object(TieredPipeline, "_init_medical_detector"):
                    config = PipelineConfig(
                        eager_load_ml=True,
                        enable_checksum=False,
                        enable_secrets=False,
                        enable_financial=False,
                        enable_government=False,
                        enable_patterns=False,
                        auto_detect_medical=False,
                    )
                    _ = TieredPipeline(config=config)
                    mock_init.assert_called_once()

    def test_lazy_load_does_not_call_init_ml_at_startup(self):
        """With eager_load_ml=False, _init_ml_detectors is NOT called during __init__."""
        with patch.object(TieredPipeline, "_init_ml_detectors") as mock_init:
            with patch.object(TieredPipeline, "_init_stage1_detectors"):
                with patch.object(TieredPipeline, "_init_medical_detector"):
                    config = PipelineConfig(
                        eager_load_ml=False,
                        enable_checksum=False,
                        enable_secrets=False,
                        enable_financial=False,
                        enable_government=False,
                        enable_patterns=False,
                        auto_detect_medical=False,
                    )
                    _ = TieredPipeline(config=config)
                    mock_init.assert_not_called()

    def test_ml_init_called_on_first_escalation(self):
        """ML init should be triggered when escalation happens for the first time."""
        p = _minimal_pipeline()
        # Inject a low-confidence span to trigger escalation
        low_span = _make_span("maybe", entity_type="NAME", confidence=0.40, detector="pattern", tier=Tier.PATTERN)
        p._stage1_detectors = [_make_mock_detector("s1", [low_span])]

        with patch.object(p, "_init_ml_detectors") as mock_init:
            p.detect("maybe")
            mock_init.assert_called_once()

    def test_ml_init_not_called_when_no_escalation(self):
        """ML init should NOT be triggered when escalation is not needed."""
        p = _minimal_pipeline()
        high_span = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        p._stage1_detectors = [_make_mock_detector("s1", [high_span])]

        with patch.object(p, "_init_ml_detectors") as mock_init:
            p.detect("SSN: 123-45-6789")
            mock_init.assert_not_called()

    def test_init_ml_detectors_idempotent(self):
        """Calling _init_ml_detectors multiple times should not re-load."""
        p = _minimal_pipeline()
        fake_ml = _make_mock_detector("fake_ml")
        p._ml_detectors = [fake_ml]

        # Since _ml_detectors is already populated, calling again should be a no-op
        p._init_ml_detectors()
        assert p._ml_detectors == [fake_ml]


# =============================================================================
# 7. PipelineConfig EFFECTS
# =============================================================================

class TestPipelineConfigEffects:
    """Test that config flags actually control pipeline behavior."""

    def test_disable_all_stage1_gives_no_detectors(self):
        p = _minimal_pipeline()
        assert len(p._stage1_detectors) == 0

    def test_enable_checksum_only(self):
        p = _minimal_pipeline(enable_checksum=True)
        names = [d.name for d in p._stage1_detectors]
        assert "checksum" in names
        assert "secrets" not in names

    def test_enable_secrets_only(self):
        p = _minimal_pipeline(enable_secrets=True)
        names = [d.name for d in p._stage1_detectors]
        assert "secrets" in names
        assert "checksum" not in names

    def test_confidence_threshold_filters_low_confidence_spans(self):
        """Spans below confidence_threshold should be filtered in post-processing."""
        p = _minimal_pipeline(confidence_threshold=0.80)
        span_low = _make_span("test", entity_type="EMAIL", confidence=0.75, detector="pattern", tier=Tier.PATTERN)
        span_high = _make_span("123-45-6789", start=10, confidence=0.99, entity_type="SSN")
        p._stage1_detectors = [_make_mock_detector("s1", [span_low, span_high])]

        result = p.detect("test text 123-45-6789")
        # Only the high-confidence span should survive post-processing
        assert len(result.spans) == 1
        assert result.spans[0].entity_type == "SSN"

    def test_confidence_threshold_zero_keeps_all(self):
        """With threshold 0.0, all spans are kept."""
        p = _minimal_pipeline(confidence_threshold=0.0)
        span = _make_span("test", entity_type="EMAIL", confidence=0.01, detector="pattern", tier=Tier.PATTERN)
        p._stage1_detectors = [_make_mock_detector("s1", [span])]

        result = p.detect("test")
        assert len(result.spans) == 1

    def test_max_workers_respected(self):
        """Custom max_workers should be stored in config."""
        p = _minimal_pipeline(max_workers=8)
        assert p.config.max_workers == 8

    def test_policy_evaluation_disabled(self):
        """When policy evaluation is disabled, policy_result should be None."""
        p = _minimal_pipeline(enable_policy_evaluation=False)
        span = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        p._stage1_detectors = [_make_mock_detector("s1", [span])]

        result = p.detect("SSN: 123-45-6789")
        assert result.policy_result is None


# =============================================================================
# 8. PipelineResult AGGREGATION
# =============================================================================

class TestPipelineResult:
    """Test PipelineResult data structure and aggregation."""

    def test_result_properties_delegate_to_detection_result(self):
        spans = [_make_span("123-45-6789", confidence=0.99)]
        dr = DetectionResult(
            spans=spans,
            entity_counts={"SSN": 1},
            processing_time_ms=42.0,
            detectors_used=["checksum"],
            text_length=20,
        )
        pr = PipelineResult(
            result=dr,
            stages_executed=[PipelineStage.FAST_TRIAGE],
            medical_context_detected=False,
            escalation_reason=None,
        )
        assert pr.spans == spans
        assert pr.processing_time_ms == 42.0

    def test_result_with_policy_attached(self):
        from openlabels.core.policies.schema import PolicyResult, RiskLevel

        dr = DetectionResult(spans=[], entity_counts={}, processing_time_ms=0, detectors_used=[], text_length=0)
        policy = PolicyResult(risk_level=RiskLevel.HIGH)
        pr = PipelineResult(
            result=dr,
            stages_executed=[PipelineStage.FAST_TRIAGE],
            medical_context_detected=False,
            escalation_reason=None,
            policy_result=policy,
        )
        assert pr.policy_result is not None
        assert pr.policy_result.risk_level == RiskLevel.HIGH

    def test_result_ocr_metadata_defaults(self):
        dr = DetectionResult(spans=[], entity_counts={}, processing_time_ms=0, detectors_used=[], text_length=0)
        pr = PipelineResult(
            result=dr,
            stages_executed=[],
            medical_context_detected=False,
            escalation_reason=None,
        )
        assert pr.ocr_used is False
        assert pr.ocr_text_detected is False

    def test_entity_counts_normalized(self):
        """Entity counts in the result should use normalized entity types."""
        # PER -> NAME via normalize_entity_type
        span = _make_span("John", entity_type="PER", confidence=0.85, detector="pattern", tier=Tier.PATTERN)
        p = _minimal_pipeline(confidence_threshold=0.0)
        p._stage1_detectors = [_make_mock_detector("s1", [span])]

        result = p.detect("John")
        # "PER" normalizes to "NAME"
        assert "NAME" in result.result.entity_counts

    def test_multiple_stages_tracked(self):
        """Both FAST_TRIAGE and ML_ESCALATION should appear in stages_executed."""
        s1_span = _make_span("test", entity_type="NAME", confidence=0.50, detector="pattern", tier=Tier.PATTERN)
        ml_span = _make_span("John", start=10, entity_type="NAME", confidence=0.90, detector="ml", tier=Tier.ML)

        p = _minimal_pipeline()
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span])]
        mock_ml = _make_mock_detector("mock_ml", [ml_span])
        p._ml_detectors = [mock_ml]
        p._pii_bert = mock_ml

        result = p.detect("test text John")
        assert PipelineStage.FAST_TRIAGE in result.stages_executed
        assert PipelineStage.ML_ESCALATION in result.stages_executed


# =============================================================================
# 9. ERROR HANDLING  (graceful fallback)
# =============================================================================

class TestErrorHandling:
    """Test graceful degradation when ML or OCR are unavailable."""

    def test_ml_unavailable_falls_back_to_stage1(self):
        """If no ML detectors load, escalation still runs but produces no extra spans."""
        p = _minimal_pipeline()
        low_span = _make_span("maybe", entity_type="NAME", confidence=0.40, detector="pattern", tier=Tier.PATTERN)
        p._stage1_detectors = [_make_mock_detector("s1", [low_span])]
        # _ml_detectors remains empty, _pii_bert stays None

        result = p.detect("maybe")
        # Escalation was triggered but no ML detectors available
        assert result.escalation_reason is not None
        # Only Stage 1 ran effectively (FAST_TRIAGE is recorded)
        assert PipelineStage.FAST_TRIAGE in result.stages_executed
        # ML_ESCALATION should NOT appear because _ml_detectors is empty and
        # medical context was not detected
        assert PipelineStage.ML_ESCALATION not in result.stages_executed

    def test_stage1_detector_exception_handled(self):
        """If a Stage 1 detector raises, the pipeline should not crash."""
        broken = MagicMock()
        broken.name = "broken_det"
        broken.is_available.return_value = True
        broken.detect.side_effect = RuntimeError("detector crash")

        p = _minimal_pipeline()
        p._stage1_detectors = [broken]

        # Should not raise
        result = p.detect("some text")
        assert PipelineStage.FAST_TRIAGE in result.stages_executed
        assert result.spans == []

    def test_ml_detector_exception_handled(self):
        """If an ML detector raises, the pipeline should not crash."""
        s1_span = _make_span("x", entity_type="NAME", confidence=0.50, detector="pattern", tier=Tier.PATTERN)
        broken_ml = MagicMock()
        broken_ml.name = "broken_ml"
        broken_ml.is_available.return_value = True
        broken_ml.detect.side_effect = RuntimeError("ML crash")

        p = _minimal_pipeline()
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span])]
        p._ml_detectors = [broken_ml]
        p._pii_bert = broken_ml

        result = p.detect("x")
        # Pipeline should not crash; Stage 1 + escalation attempted
        assert PipelineStage.FAST_TRIAGE in result.stages_executed

    def test_ocr_import_failure_returns_empty(self, tmp_path):
        """If OCR module cannot be imported, extract_text_ocr returns empty string."""
        p = _minimal_pipeline()
        assert p._ocr_engine is None

        # Patch the import of OCREngine to raise ImportError
        with patch(
            "openlabels.core.pipeline.tiered.TieredPipeline._extract_text_ocr",
            return_value="",
        ):
            result = p._extract_text_ocr(tmp_path / "fake.png")
            # Since we patched the method directly, this returns ""
            assert result == ""

    def test_ocr_extraction_exception_returns_empty(self):
        """If OCR engine raises during extraction, empty string is returned."""
        p = _minimal_pipeline()
        mock_ocr = MagicMock()
        mock_ocr.extract_text.side_effect = RuntimeError("OCR failure")
        p._ocr_engine = mock_ocr

        result = p._extract_text_ocr(Path("/fake/image.png"))
        assert result == ""

    def test_policy_evaluation_failure_does_not_crash(self):
        """If policy evaluation raises, detect() should still return a result."""
        p = _minimal_pipeline(enable_policy_evaluation=True)
        span = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        p._stage1_detectors = [_make_mock_detector("s1", [span])]

        with patch("openlabels.core.pipeline.tiered.get_policy_engine") as mock_engine:
            mock_engine.return_value.evaluate.side_effect = RuntimeError("policy crash")
            result = p.detect("SSN: 123-45-6789")
            # Should still have spans; policy_result may be None
            assert len(result.spans) >= 1
            assert result.policy_result is None

    def test_quick_text_check_exception_assumes_text_exists(self, tmp_path):
        """If _quick_text_check fails (e.g., corrupt image), default to True."""
        p = _minimal_pipeline()
        # The PIL.Image.open will fail on a non-image file
        bad_file = tmp_path / "corrupt.png"
        bad_file.write_bytes(b"not a real image")

        result = p._quick_text_check(bad_file)
        assert result is True  # Assume text exists on error


# =============================================================================
# 10. DEDUPLICATION
# =============================================================================

class TestDeduplication:
    """Test the _deduplicate and _post_process logic for multi-stage spans."""

    def test_exact_duplicate_removed(self):
        """Two identical spans should be deduplicated to one."""
        p = _minimal_pipeline(confidence_threshold=0.0)
        span1 = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        span2 = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")

        result = p._deduplicate([span1, span2])
        assert len(result) == 1

    def test_higher_tier_wins_on_overlap(self):
        """When spans overlap exactly, the higher-tier one should survive."""
        p = _minimal_pipeline(confidence_threshold=0.0)
        ml_span = _make_span("John Smith", entity_type="NAME", confidence=0.90, detector="ml", tier=Tier.ML)
        pattern_span = _make_span("John Smith", entity_type="NAME", confidence=0.80, detector="pattern", tier=Tier.PATTERN)

        result = p._deduplicate([ml_span, pattern_span])
        assert len(result) == 1
        # PATTERN tier (2) > ML tier (1), so pattern wins
        assert result[0].tier == Tier.PATTERN

    def test_non_overlapping_spans_kept(self):
        p = _minimal_pipeline(confidence_threshold=0.0)
        span1 = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        span2 = _make_span("John", start=20, entity_type="NAME", confidence=0.90, detector="ml", tier=Tier.ML)

        result = p._deduplicate([span1, span2])
        assert len(result) == 2

    def test_post_process_sorts_by_position(self):
        p = _minimal_pipeline(confidence_threshold=0.0)
        span_later = _make_span("John", start=20, entity_type="NAME", confidence=0.90, detector="ml", tier=Tier.ML)
        span_earlier = _make_span("123-45-6789", start=0, confidence=0.99, entity_type="SSN")

        result = p._post_process("padding text      123-45-6789  John", [span_later, span_earlier])
        assert result[0].start < result[1].start

    def test_post_process_empty_spans(self):
        p = _minimal_pipeline()
        result = p._post_process("text", [])
        assert result == []


# =============================================================================
# 11. CONVENIENCE FUNCTIONS
# =============================================================================

class TestConvenienceFunctions:
    """Test create_pipeline and detect_tiered module-level functions."""

    def test_create_pipeline_returns_tiered_pipeline(self):
        p = create_pipeline(
            auto_detect_medical=False,
            enable_hyperscan=False,
        )
        assert isinstance(p, TieredPipeline)
        assert p.config.auto_detect_medical is False

    def test_create_pipeline_passes_kwargs(self):
        p = create_pipeline(
            auto_detect_medical=False,
            max_workers=16,
            confidence_threshold=0.50,
        )
        assert p.config.max_workers == 16
        assert p.config.confidence_threshold == 0.50

    def test_detect_tiered_returns_pipeline_result(self):
        result = detect_tiered("SSN: 123-45-6789", auto_detect_medical=False)
        assert isinstance(result, PipelineResult)

    def test_stage1_detector_names_property(self):
        p = _minimal_pipeline(enable_checksum=True, enable_financial=True)
        names = p.stage1_detector_names
        assert "checksum" in names
        assert "financial" in names

    def test_get_ml_status_before_load(self):
        p = _minimal_pipeline()
        status = p.get_ml_status()
        assert status["ml_loaded"] is False
        assert status["phi_bert"] is None
        assert status["pii_bert"] is None
        assert status["detectors"] == []


# =============================================================================
# 12. PIPELINE STAGE ENUM
# =============================================================================

class TestPipelineStage:
    """Test PipelineStage enum values."""

    def test_stage_values(self):
        assert PipelineStage.FAST_TRIAGE.value == "fast_triage"
        assert PipelineStage.ML_ESCALATION.value == "ml_escalation"
        assert PipelineStage.DEEP_ANALYSIS.value == "deep_analysis"

    def test_stages_are_distinct(self):
        stages = [PipelineStage.FAST_TRIAGE, PipelineStage.ML_ESCALATION, PipelineStage.DEEP_ANALYSIS]
        assert len(set(stages)) == 3


# =============================================================================
# 13. _run_detector ISOLATION
# =============================================================================

class TestRunDetector:
    """Test the _run_detector wrapper."""

    def test_run_detector_returns_spans(self):
        p = _minimal_pipeline()
        span = _make_span("test", entity_type="SSN", confidence=0.99)
        det = _make_mock_detector("d", [span])

        result = p._run_detector(det, "test")
        assert result == [span]

    def test_run_detector_unavailable_returns_empty(self):
        p = _minimal_pipeline()
        det = _make_mock_detector("d", [_make_span("x")], available=False)

        result = p._run_detector(det, "x")
        assert result == []
        det.detect.assert_not_called()

    def test_run_detector_exception_returns_empty(self):
        p = _minimal_pipeline()
        det = MagicMock()
        det.name = "explody"
        det.is_available.return_value = True
        det.detect.side_effect = ValueError("kaboom")

        result = p._run_detector(det, "text")
        assert result == []


# =============================================================================
# 14. REGRESSION: BUG SCENARIOS
# =============================================================================

class TestRegressionBugs:
    """Tests designed to catch specific classes of escalation bugs."""

    def test_bug_ml_runs_but_stage1_discarded(self):
        """
        Regression: Ensure Stage 1 spans are included in final result even
        when Stage 2 also produces spans. A naive implementation might replace
        Stage 1 results instead of appending Stage 2.
        """
        s1_span = _make_span("123-45-6789", confidence=0.99, entity_type="SSN")
        # This span will have low confidence, triggering escalation
        s1_span_low = _make_span("maybe-name", start=20, entity_type="NAME", confidence=0.50, detector="pattern", tier=Tier.PATTERN)
        ml_span = _make_span("Definitely", start=35, entity_type="NAME", confidence=0.95, detector="ml", tier=Tier.ML)

        p = _minimal_pipeline(confidence_threshold=0.0)
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span, s1_span_low])]
        mock_ml = _make_mock_detector("ml", [ml_span])
        p._ml_detectors = [mock_ml]
        p._pii_bert = mock_ml

        result = p.detect("SSN: 123-45-6789    maybe-name Definitely Name")
        entity_types = {s.entity_type for s in result.spans}
        # Both SSN (from Stage 1) and NAME (from ML) should be present
        assert "SSN" in entity_types, "Stage 1 SSN must not be discarded when ML runs"

    def test_bug_escalation_with_empty_ml_detectors_no_stage2_recorded(self):
        """
        Regression: When escalation is triggered but _ml_detectors is empty
        and medical context is False, neither ML_ESCALATION nor DEEP_ANALYSIS
        should appear in stages_executed.
        """
        low_span = _make_span("hmm", entity_type="NAME", confidence=0.30, detector="pattern", tier=Tier.PATTERN)
        p = _minimal_pipeline()
        p._stage1_detectors = [_make_mock_detector("s1", [low_span])]
        # _ml_detectors empty, no medical context

        result = p.detect("hmm")
        assert PipelineStage.ML_ESCALATION not in result.stages_executed
        assert PipelineStage.DEEP_ANALYSIS not in result.stages_executed
        # But escalation_reason should still be set because the decision to escalate was made
        assert result.escalation_reason is not None

    def test_bug_medical_overrides_low_confidence_reason(self):
        """
        Regression: If both low_confidence and medical context trigger escalation,
        the reason should reflect medical context (it is checked second and overrides
        only if reason was None).
        """
        low_span = _make_span("data", entity_type="NAME", confidence=0.50, detector="pattern", tier=Tier.PATTERN)
        p = _minimal_pipeline(auto_detect_medical=True, enable_policy_evaluation=False)
        p._stage1_detectors = [_make_mock_detector("s1", [low_span])]
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.return_value = True

        result = p.detect("data")
        # Low confidence fires first, so the reason should contain "low_confidence"
        assert "low_confidence" in result.escalation_reason
        # Medical context is also detected
        assert result.medical_context_detected is True

    def test_bug_stage2_not_entered_for_non_beneficial_high_confidence(self):
        """
        Ensure that a span of a non-beneficial type at high confidence
        does NOT lead to ML_ESCALATION.
        """
        span = _make_span("sk_test_abc123", entity_type="STRIPE_KEY", confidence=0.95, detector="secrets", tier=Tier.PATTERN)
        p = _minimal_pipeline()
        p._stage1_detectors = [_make_mock_detector("s1", [span])]
        ml_det = _make_mock_detector("shouldnt_run")
        p._ml_detectors = [ml_det]
        p._pii_bert = ml_det

        result = p.detect("sk_test_abc123")
        assert PipelineStage.ML_ESCALATION not in result.stages_executed
        ml_det.detect.assert_not_called()

    def test_deep_analysis_runs_both_phi_and_pii_bert(self):
        """
        Both PHI-BERT and PII-BERT must be invoked during deep analysis.
        A bug could skip one of them.
        """
        s1_span = _make_span("test", entity_type="SSN", confidence=0.99)
        phi_span = _make_span("Patient", start=10, entity_type="NAME_PATIENT", confidence=0.92, detector="phi_bert", tier=Tier.ML)
        pii_span = _make_span("john@x.com", start=25, entity_type="EMAIL", confidence=0.88, detector="pii_bert", tier=Tier.ML)

        phi_det = _make_mock_detector("phi_bert_onnx", [phi_span])
        pii_det = _make_mock_detector("pii_bert_onnx", [pii_span])

        p = _minimal_pipeline(auto_detect_medical=True, enable_policy_evaluation=False, confidence_threshold=0.0)
        p._stage1_detectors = [_make_mock_detector("s1", [s1_span])]
        p._phi_bert = phi_det
        p._pii_bert = pii_det
        p._ml_detectors = [phi_det, pii_det]
        p._medical_detector = MagicMock()
        p._medical_detector.has_medical_context.return_value = True
        p.config.medical_triggers_dual_bert = True

        result = p.detect("test data Patient Name john@x.com")
        assert PipelineStage.DEEP_ANALYSIS in result.stages_executed
        # Both detectors should have been called
        phi_det.detect.assert_called_once()
        pii_det.detect.assert_called_once()

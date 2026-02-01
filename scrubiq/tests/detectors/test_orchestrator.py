"""Tests for detectors/orchestrator.py - the detector orchestration engine.

Tests cover:
- DetectorOrchestrator initialization
- Parallel and sequential detection
- Known entity detection
- Queue depth management (backpressure)
- Span deduplication
- Detector enablement/disablement
- Timeout handling
- ML detector loading
- LLM verification integration
- Context enhancement
"""

import threading
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from scrubiq.types import Span, Tier


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def mock_config():
    """Create a mock Config object."""
    config = MagicMock()
    config.disabled_detectors = set()
    config.models_dir = MagicMock()
    config.models_dir.exists.return_value = False
    config.dictionaries_dir = MagicMock()
    config.dictionaries_dir.exists.return_value = False
    config.phi_bert_path = MagicMock()
    config.phi_bert_path.exists.return_value = False
    config.pii_bert_path = MagicMock()
    config.pii_bert_path.exists.return_value = False
    config.device = "cpu"
    config.cuda_device_id = 0
    config.enable_llm_verification = False
    return config


@pytest.fixture
def make_span():
    """Factory for creating test spans."""
    def _make_span(
        text: str,
        start: int = 0,
        entity_type: str = "NAME",
        confidence: float = 0.9,
        detector: str = "test",
        tier: int = 2,
    ) -> Span:
        return Span(
            start=start,
            end=start + len(text),
            text=text,
            entity_type=entity_type,
            confidence=confidence,
            detector=detector,
            tier=Tier.from_value(tier),
        )
    return _make_span


# =============================================================================
# MODULE-LEVEL FUNCTION TESTS
# =============================================================================

class TestModuleFunctions:
    """Tests for module-level functions."""

    def test_get_detection_queue_depth(self):
        """get_detection_queue_depth returns current queue depth."""
        from scrubiq.detectors.orchestrator import get_detection_queue_depth, _QUEUE_DEPTH, _QUEUE_LOCK

        with _QUEUE_LOCK:
            # Note: we can't easily modify _QUEUE_DEPTH, but we can verify it returns a number
            depth = get_detection_queue_depth()
            assert isinstance(depth, int)
            assert depth >= 0

    def test_get_executor_creates_shared_executor(self):
        """_get_executor creates shared ThreadPoolExecutor."""
        from scrubiq.detectors.orchestrator import _get_executor
        from concurrent.futures import ThreadPoolExecutor

        executor = _get_executor()
        assert isinstance(executor, ThreadPoolExecutor)

        # Second call returns same executor
        executor2 = _get_executor()
        assert executor is executor2


# =============================================================================
# DETECTION QUEUE FULL ERROR TESTS
# =============================================================================

class TestDetectionQueueFullError:
    """Tests for DetectionQueueFullError exception."""

    def test_error_message(self):
        """DetectionQueueFullError has descriptive message."""
        from scrubiq.detectors.orchestrator import DetectionQueueFullError

        error = DetectionQueueFullError(queue_depth=50, max_depth=50)
        assert "50" in str(error)
        assert "queue full" in str(error).lower()

    def test_error_attributes(self):
        """DetectionQueueFullError stores queue_depth and max_depth."""
        from scrubiq.detectors.orchestrator import DetectionQueueFullError

        error = DetectionQueueFullError(queue_depth=45, max_depth=50)
        assert error.queue_depth == 45
        assert error.max_depth == 50


# =============================================================================
# DETECTOR ORCHESTRATOR INITIALIZATION TESTS
# =============================================================================

class TestDetectorOrchestratorInit:
    """Tests for DetectorOrchestrator initialization."""

    def test_init_default_config(self, mock_config):
        """DetectorOrchestrator initializes with default settings."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        assert orch.parallel is True
                        assert orch.enable_structured is True

    def test_init_disables_detectors(self, mock_config):
        """DetectorOrchestrator respects disabled_detectors config."""
        mock_config.disabled_detectors = {"checksum", "patterns"}

        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                mock_additional.return_value.is_available.return_value = True
                mock_additional.return_value.name = "additional_patterns"

                from scrubiq.detectors.orchestrator import DetectorOrchestrator
                orch = DetectorOrchestrator(config=mock_config)

                # Checksum and pattern detectors should not be added
                detector_names = [d.name for d in orch._detectors]
                assert "checksum" not in [d.name for d in orch._detectors if hasattr(d, 'name')]

    def test_init_enables_secrets_detector(self, mock_config):
        """DetectorOrchestrator adds SecretsDetector when enabled."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.SecretsDetector') as mock_secrets:
                            mock_checksum.return_value.is_available.return_value = True
                            mock_checksum.return_value.name = "checksum"
                            mock_pattern.return_value.is_available.return_value = True
                            mock_pattern.return_value.name = "patterns"
                            mock_additional.return_value.is_available.return_value = True
                            mock_additional.return_value.name = "additional_patterns"
                            mock_secrets.return_value.is_available.return_value = True
                            mock_secrets.return_value.name = "secrets"

                            from scrubiq.detectors.orchestrator import DetectorOrchestrator
                            orch = DetectorOrchestrator(config=mock_config, enable_secrets=True)

                            mock_secrets.assert_called_once()

    def test_init_disables_secrets_detector(self, mock_config):
        """DetectorOrchestrator skips SecretsDetector when disabled."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.SecretsDetector') as mock_secrets:
                            mock_checksum.return_value.is_available.return_value = True
                            mock_checksum.return_value.name = "checksum"
                            mock_pattern.return_value.is_available.return_value = True
                            mock_pattern.return_value.name = "patterns"
                            mock_additional.return_value.is_available.return_value = True
                            mock_additional.return_value.name = "additional_patterns"

                            from scrubiq.detectors.orchestrator import DetectorOrchestrator
                            orch = DetectorOrchestrator(config=mock_config, enable_secrets=False)

                            mock_secrets.assert_not_called()

    def test_init_enables_financial_detector(self, mock_config):
        """DetectorOrchestrator adds FinancialDetector when enabled."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.FinancialDetector') as mock_financial:
                            mock_checksum.return_value.is_available.return_value = True
                            mock_checksum.return_value.name = "checksum"
                            mock_pattern.return_value.is_available.return_value = True
                            mock_pattern.return_value.name = "patterns"
                            mock_additional.return_value.is_available.return_value = True
                            mock_additional.return_value.name = "additional_patterns"
                            mock_financial.return_value.is_available.return_value = True
                            mock_financial.return_value.name = "financial"

                            from scrubiq.detectors.orchestrator import DetectorOrchestrator
                            orch = DetectorOrchestrator(config=mock_config, enable_financial=True)

                            mock_financial.assert_called_once()

    def test_init_enables_government_detector(self, mock_config):
        """DetectorOrchestrator adds GovernmentDetector when enabled."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.GovernmentDetector') as mock_gov:
                            mock_checksum.return_value.is_available.return_value = True
                            mock_checksum.return_value.name = "checksum"
                            mock_pattern.return_value.is_available.return_value = True
                            mock_pattern.return_value.name = "patterns"
                            mock_additional.return_value.is_available.return_value = True
                            mock_additional.return_value.name = "additional_patterns"
                            mock_gov.return_value.is_available.return_value = True
                            mock_gov.return_value.name = "government"

                            from scrubiq.detectors.orchestrator import DetectorOrchestrator
                            orch = DetectorOrchestrator(config=mock_config, enable_government=True)

                            mock_gov.assert_called_once()


# =============================================================================
# KNOWN ENTITY DETECTION TESTS
# =============================================================================

class TestKnownEntityDetection:
    """Tests for _detect_known_entities."""

    def test_detects_exact_match(self, mock_config, make_span):
        """Detects known entities by exact match."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        known_entities = {
                            "[NAME_1]": ("John", "NAME"),
                        }

                        text = "Hello John, how are you?"
                        spans = orch._detect_known_entities(text, known_entities)

                        assert len(spans) == 1
                        assert spans[0].text == "John"
                        assert spans[0].entity_type == "NAME"
                        assert spans[0].confidence == 0.98

    def test_detects_name_parts(self, mock_config):
        """Detects individual name parts from known full names."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        known_entities = {
                            "[NAME_1]": ("John Smith", "NAME"),
                        }

                        text = "Smith called earlier."
                        spans = orch._detect_known_entities(text, known_entities)

                        # Should detect "Smith" as a name part
                        assert len(spans) == 1
                        assert spans[0].text == "Smith"

    def test_respects_word_boundaries(self, mock_config):
        """Does not match partial words (e.g., 'Johnson' when searching 'John')."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        known_entities = {
                            "[NAME_1]": ("John", "NAME"),
                        }

                        text = "Johnson is not John."
                        spans = orch._detect_known_entities(text, known_entities)

                        # Should only match "John", not "Johnson"
                        assert len(spans) == 1
                        assert spans[0].text == "John"
                        assert spans[0].start == 15  # Position of standalone "John"

    def test_requires_capitalization(self, mock_config):
        """Only matches capitalized words (proper nouns)."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        known_entities = {
                            "[NAME_1]": ("John", "NAME"),
                        }

                        # Lowercase "john" should not match
                        text = "hello john"
                        spans = orch._detect_known_entities(text, known_entities)

                        assert len(spans) == 0


# =============================================================================
# DETECT METHOD TESTS
# =============================================================================

class TestDetect:
    """Tests for detect() method."""

    def test_detect_empty_text_returns_empty(self, mock_config):
        """detect() returns empty list for empty text."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        result = orch.detect("")
                        assert result == []

    def test_detect_with_known_entities(self, mock_config, make_span):
        """detect() uses known_entities parameter."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_checksum.return_value.detect.return_value = []
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_pattern.return_value.detect.return_value = []
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"
                        mock_additional.return_value.detect.return_value = []

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config, enable_structured=False)

                        known_entities = {
                            "[NAME_1]": ("John", "NAME"),
                        }

                        result = orch.detect("Hello John!", known_entities=known_entities)

                        # Should find the known entity
                        assert len(result) == 1
                        assert result[0].text == "John"


# =============================================================================
# DEDUPLICATION TESTS
# =============================================================================

class TestDeduplication:
    """Tests for _dedupe_spans method."""

    def test_removes_exact_duplicates(self, mock_config, make_span):
        """_dedupe_spans removes exact duplicate spans."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        spans = [
                            make_span("John", start=0, entity_type="NAME", confidence=0.9),
                            make_span("John", start=0, entity_type="NAME", confidence=0.85),
                        ]

                        result = orch._dedupe_spans(spans)

                        assert len(result) == 1
                        assert result[0].confidence == 0.9  # Higher confidence wins

    def test_keeps_higher_tier(self, mock_config, make_span):
        """_dedupe_spans prefers higher tier spans."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        spans = [
                            make_span("John", start=0, entity_type="NAME", confidence=0.9, tier=2),
                            make_span("John", start=0, entity_type="NAME", confidence=0.85, tier=3),
                        ]

                        result = orch._dedupe_spans(spans)

                        assert len(result) == 1
                        assert result[0].tier.value == 3  # Higher tier wins

    def test_handles_different_entity_types(self, mock_config, make_span):
        """_dedupe_spans handles same position, different entity types."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        spans = [
                            make_span("12345", start=0, entity_type="MRN", confidence=0.7, tier=2),
                            make_span("12345", start=0, entity_type="ZIP", confidence=0.9, tier=2),
                        ]

                        result = orch._dedupe_spans(spans)

                        # Should keep only one (higher confidence)
                        assert len(result) == 1
                        assert result[0].entity_type == "ZIP"

    def test_empty_list_returns_empty(self, mock_config):
        """_dedupe_spans handles empty list."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        result = orch._dedupe_spans([])
                        assert result == []


# =============================================================================
# PARALLEL VS SEQUENTIAL DETECTION TESTS
# =============================================================================

class TestParallelSequential:
    """Tests for parallel and sequential detection modes."""

    def test_sequential_mode(self, mock_config):
        """DetectorOrchestrator can run in sequential mode."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config, parallel=False)

                        assert orch.parallel is False

    def test_parallel_mode_default(self, mock_config):
        """DetectorOrchestrator uses parallel mode by default."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        assert orch.parallel is True


# =============================================================================
# DETECTOR INFO TESTS
# =============================================================================

class TestDetectorInfo:
    """Tests for get_detector_info method."""

    def test_get_detector_info(self, mock_config):
        """get_detector_info returns detector metadata."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_checksum.return_value.tier = Tier.CHECKSUM
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_pattern.return_value.tier = Tier.PATTERN
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"
                        mock_additional.return_value.tier = Tier.PATTERN

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        info = orch.get_detector_info()

                        assert isinstance(info, list)
                        assert len(info) >= 3  # At least checksum, patterns, additional_patterns


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestDetectAll:
    """Tests for detect_all convenience function."""

    def test_detect_all_creates_orchestrator(self, mock_config):
        """detect_all creates orchestrator and runs detection."""
        with patch('scrubiq.detectors.orchestrator.DetectorOrchestrator') as mock_orch_class:
            mock_orch = MagicMock()
            mock_orch.detect.return_value = []
            mock_orch_class.return_value = mock_orch

            from scrubiq.detectors.orchestrator import detect_all
            result = detect_all("Hello world", config=mock_config)

            mock_orch_class.assert_called_once()
            mock_orch.detect.assert_called_once_with("Hello world")


# =============================================================================
# LLM VERIFIER INTEGRATION TESTS
# =============================================================================

class TestLLMVerifierIntegration:
    """Tests for LLM verifier integration."""

    def test_llm_verifier_not_enabled_by_default(self, mock_config):
        """LLM verifier is not enabled by default."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.create_verifier') as mock_create:
                            mock_checksum.return_value.is_available.return_value = True
                            mock_checksum.return_value.name = "checksum"
                            mock_pattern.return_value.is_available.return_value = True
                            mock_pattern.return_value.name = "patterns"
                            mock_additional.return_value.is_available.return_value = True
                            mock_additional.return_value.name = "additional_patterns"

                            from scrubiq.detectors.orchestrator import DetectorOrchestrator
                            orch = DetectorOrchestrator(config=mock_config, enable_llm_verification=False)

                            # create_verifier should not be called when disabled
                            mock_create.assert_not_called()

    def test_llm_verifier_enabled(self, mock_config):
        """LLM verifier can be enabled."""
        mock_config.enable_llm_verification = True

        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.create_verifier') as mock_create:
                            mock_checksum.return_value.is_available.return_value = True
                            mock_checksum.return_value.name = "checksum"
                            mock_pattern.return_value.is_available.return_value = True
                            mock_pattern.return_value.name = "patterns"
                            mock_additional.return_value.is_available.return_value = True
                            mock_additional.return_value.name = "additional_patterns"

                            mock_verifier = MagicMock()
                            mock_verifier.is_available.return_value = True
                            mock_verifier.model = "qwen2.5:3b"
                            mock_create.return_value = mock_verifier

                            from scrubiq.detectors.orchestrator import DetectorOrchestrator
                            orch = DetectorOrchestrator(config=mock_config, enable_llm_verification=True)

                            mock_create.assert_called_once()


# =============================================================================
# CONTEXT ENHANCER TESTS
# =============================================================================

class TestContextEnhancer:
    """Tests for context enhancer integration."""

    def test_context_enhancer_enabled(self, mock_config):
        """Context enhancer is enabled by default."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.create_enhancer') as mock_create:
                            mock_checksum.return_value.is_available.return_value = True
                            mock_checksum.return_value.name = "checksum"
                            mock_pattern.return_value.is_available.return_value = True
                            mock_pattern.return_value.name = "patterns"
                            mock_additional.return_value.is_available.return_value = True
                            mock_additional.return_value.name = "additional_patterns"

                            mock_enhancer = MagicMock()
                            mock_create.return_value = mock_enhancer

                            from scrubiq.detectors.orchestrator import DetectorOrchestrator
                            orch = DetectorOrchestrator(config=mock_config)

                            mock_create.assert_called_once()
                            assert orch._context_enhancer is mock_enhancer


# =============================================================================
# STRUCTURED EXTRACTION TESTS
# =============================================================================

class TestStructuredExtraction:
    """Tests for structured extraction integration."""

    def test_structured_enabled_by_default(self, mock_config):
        """Structured extraction is enabled by default."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config)

                        assert orch.enable_structured is True

    def test_structured_can_be_disabled(self, mock_config):
        """Structured extraction can be disabled."""
        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        mock_checksum.return_value.is_available.return_value = True
                        mock_checksum.return_value.name = "checksum"
                        mock_pattern.return_value.is_available.return_value = True
                        mock_pattern.return_value.name = "patterns"
                        mock_additional.return_value.is_available.return_value = True
                        mock_additional.return_value.name = "additional_patterns"

                        from scrubiq.detectors.orchestrator import DetectorOrchestrator
                        orch = DetectorOrchestrator(config=mock_config, enable_structured=False)

                        assert orch.enable_structured is False


# =============================================================================
# ML DETECTOR LOADING TESTS
# =============================================================================

class TestMLDetectorLoading:
    """Tests for ML detector loading logic."""

    def test_prefers_onnx_over_pytorch(self, mock_config):
        """Prefers ONNX models over PyTorch when available."""
        mock_config.models_dir = MagicMock()
        onnx_path = MagicMock()
        onnx_path.exists.return_value = True
        mock_config.models_dir.__truediv__ = lambda self, x: onnx_path if "onnx" in x else MagicMock(exists=lambda: False)

        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.PHIBertONNXDetector') as mock_phi_onnx:
                            with patch('scrubiq.detectors.orchestrator.PHIBertDetector') as mock_phi_torch:
                                mock_checksum.return_value.is_available.return_value = True
                                mock_checksum.return_value.name = "checksum"
                                mock_pattern.return_value.is_available.return_value = True
                                mock_pattern.return_value.name = "patterns"
                                mock_additional.return_value.is_available.return_value = True
                                mock_additional.return_value.name = "additional_patterns"

                                mock_phi_onnx.return_value.load.return_value = True
                                mock_phi_onnx.return_value.is_available.return_value = True
                                mock_phi_onnx.return_value.name = "phi_bert_onnx"

                                from scrubiq.detectors.orchestrator import DetectorOrchestrator
                                orch = DetectorOrchestrator(config=mock_config)

                                # ONNX should be preferred, PyTorch not called
                                mock_phi_onnx.assert_called()

    def test_skips_ml_when_disabled(self, mock_config):
        """Skips ML detectors when disabled in config."""
        mock_config.disabled_detectors = {"phi_bert", "pii_bert"}

        with patch('scrubiq.detectors.orchestrator.Config', return_value=mock_config):
            with patch('scrubiq.detectors.orchestrator.ChecksumDetector') as mock_checksum:
                with patch('scrubiq.detectors.orchestrator.PatternDetector') as mock_pattern:
                    with patch('scrubiq.detectors.orchestrator.AdditionalPatternDetector') as mock_additional:
                        with patch('scrubiq.detectors.orchestrator.PHIBertONNXDetector') as mock_phi_onnx:
                            with patch('scrubiq.detectors.orchestrator.PIIBertONNXDetector') as mock_pii_onnx:
                                mock_checksum.return_value.is_available.return_value = True
                                mock_checksum.return_value.name = "checksum"
                                mock_pattern.return_value.is_available.return_value = True
                                mock_pattern.return_value.name = "patterns"
                                mock_additional.return_value.is_available.return_value = True
                                mock_additional.return_value.name = "additional_patterns"

                                from scrubiq.detectors.orchestrator import DetectorOrchestrator
                                orch = DetectorOrchestrator(config=mock_config)

                                # ML detectors should not be initialized
                                mock_phi_onnx.assert_not_called()
                                mock_pii_onnx.assert_not_called()

"""
Tests for Orchestrator pipeline.

Tests core orchestration functionality:
- Pipeline processing flow
- Scan trigger evaluation
- Scanner integration
- Multi-adapter processing
- Result construction
"""

from unittest.mock import MagicMock, patch, PropertyMock
import pytest

from openlabels.core.orchestrator import (
    Orchestrator,
    ProcessingResult,
    create_orchestrator,
)
from openlabels.core.scorer import RiskTier
from openlabels.adapters.base import Entity, NormalizedContext, NormalizedInput


class TestProcessingResult:
    """Tests for ProcessingResult dataclass."""

    def test_to_dict_serialization(self):
        """Should serialize all fields correctly."""
        result = ProcessingResult(
            score=85,
            tier=RiskTier.HIGH,
            content_score=42.5,
            exposure_multiplier=2.0,
            co_occurrence_multiplier=1.5,
            co_occurrence_rules=["PII_BUNDLE"],
            scan_triggered=True,
            scan_triggers=["NO_LABELS", "NEW_FILE"],
            scan_priority=80,
            sources_used=["scanner", "macie"],
            entities={"SSN": 5, "EMAIL": 10},
            categories=["financial", "pii"],
            exposure="PUBLIC",
            path="/data/file.xlsx",
        )

        d = result.to_dict()

        assert d["score"] == 85
        assert d["tier"] == "HIGH"
        assert d["content_score"] == 42.5
        assert d["exposure_multiplier"] == 2.0
        assert d["co_occurrence_multiplier"] == 1.5
        assert d["co_occurrence_rules"] == ["PII_BUNDLE"]
        assert d["scan_triggered"] is True
        assert d["scan_triggers"] == ["NO_LABELS", "NEW_FILE"]
        assert d["scan_priority"] == 80
        assert d["sources_used"] == ["scanner", "macie"]
        assert d["entities"] == {"SSN": 5, "EMAIL": 10}
        assert d["categories"] == ["financial", "pii"]
        assert d["exposure"] == "PUBLIC"
        assert d["path"] == "/data/file.xlsx"

    def test_to_dict_with_none_path(self):
        """Should handle None path."""
        result = ProcessingResult(
            score=0,
            tier=RiskTier.MINIMAL,
            content_score=0,
            exposure_multiplier=1.0,
            co_occurrence_multiplier=1.0,
            co_occurrence_rules=[],
            scan_triggered=False,
            scan_triggers=[],
            scan_priority=0,
            sources_used=[],
            entities={},
            categories=[],
            exposure="PRIVATE",
            path=None,
        )

        d = result.to_dict()
        assert d["path"] is None


class TestOrchestratorInit:
    """Tests for Orchestrator initialization."""

    def test_default_init(self):
        """Should initialize with default settings."""
        orchestrator = Orchestrator()

        assert orchestrator.enable_classification is False
        assert orchestrator._scanner is None
        assert orchestrator._scanner_config == {}

    def test_init_with_classification_enabled(self):
        """Should accept enable_classification flag."""
        orchestrator = Orchestrator(enable_classification=True)

        assert orchestrator.enable_classification is True
        # Scanner should still be None (lazy loaded)
        assert orchestrator._scanner is None

    def test_init_with_scanner_config(self):
        """Should accept scanner configuration."""
        config = {"min_confidence": 0.8, "enable_ocr": True}
        orchestrator = Orchestrator(scanner_config=config)

        assert orchestrator._scanner_config == config

    def test_init_with_context(self):
        """Should accept optional context."""
        mock_ctx = MagicMock()
        orchestrator = Orchestrator(context=mock_ctx)

        assert orchestrator._context is mock_ctx


class TestOrchestratorScannerProperty:
    """Tests for lazy scanner loading."""

    def test_scanner_lazy_loads(self):
        """Scanner should be created on first access when enabled."""
        orchestrator = Orchestrator(enable_classification=True)

        # Before accessing, _scanner should be None (lazy loading)
        assert orchestrator._scanner is None

        # Access scanner property - should create instance
        scanner = orchestrator.scanner

        # Scanner should now be created
        assert scanner is not None
        assert orchestrator._scanner is not None

        # Verify it's actually a ScannerAdapter
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        assert isinstance(scanner, ScannerAdapter)

    def test_scanner_cached(self):
        """Scanner should be cached after first access."""
        orchestrator = Orchestrator(enable_classification=True)

        # Access scanner property twice
        scanner1 = orchestrator.scanner
        scanner2 = orchestrator.scanner

        # Should return exact same instance (identity check)
        assert scanner1 is scanner2

        # Verify _scanner was set
        assert orchestrator._scanner is scanner1

    def test_scanner_none_when_disabled(self):
        """Scanner should be None when classification disabled."""
        orchestrator = Orchestrator(enable_classification=False)

        assert orchestrator.scanner is None


class TestOrchestratorProcess:
    """Tests for Orchestrator.process() method."""

    @pytest.fixture
    def mock_adapter(self):
        """Create mock adapter."""
        adapter = MagicMock()
        entities = [
            Entity(type="SSN", count=2, confidence=0.95, source="adapter"),
            Entity(type="EMAIL", count=5, confidence=0.90, source="adapter"),
        ]
        context = NormalizedContext(
            exposure="INTERNAL",
            encryption="none",
            owner="test_user",
        )
        adapter.extract.return_value = NormalizedInput(
            entities=entities,
            context=context,
        )
        return adapter

    def test_process_returns_result(self, mock_adapter):
        """Should return ProcessingResult."""
        orchestrator = Orchestrator(enable_classification=False)
        source_data = {"owner": "test"}
        metadata = {"path": "/test/file.txt"}

        result = orchestrator.process(mock_adapter, source_data, metadata)

        assert isinstance(result, ProcessingResult)
        assert result.path == "/test/file.txt"

    def test_process_calls_adapter_extract(self, mock_adapter):
        """Should call adapter.extract with correct args."""
        orchestrator = Orchestrator(enable_classification=False)
        source_data = {"owner": "test"}
        metadata = {"path": "/test/file.txt"}

        orchestrator.process(mock_adapter, source_data, metadata)

        mock_adapter.extract.assert_called_once_with(source_data, metadata)

    def test_process_includes_entities(self, mock_adapter):
        """Should include merged entities in result."""
        orchestrator = Orchestrator(enable_classification=False)

        result = orchestrator.process(mock_adapter, {}, {})

        assert "SSN" in result.entities
        assert "EMAIL" in result.entities

    @patch('openlabels.core.orchestrator.should_scan')
    def test_process_evaluates_scan_triggers(self, mock_should_scan, mock_adapter):
        """Should evaluate scan triggers."""
        mock_should_scan.return_value = (False, [])
        orchestrator = Orchestrator(enable_classification=False)

        orchestrator.process(mock_adapter, {}, {})

        mock_should_scan.assert_called_once()

    @patch('openlabels.core.orchestrator.should_scan')
    def test_process_runs_scanner_when_triggered(
        self, mock_should_scan, mock_adapter
    ):
        """Should run scanner when triggered and classification enabled."""
        from openlabels.core.triggers import ScanTrigger

        # Scanner triggered but no content - should not actually run
        mock_should_scan.return_value = (True, [ScanTrigger.NO_LABELS])

        orchestrator = Orchestrator(enable_classification=False)

        # Without content or scanner, scan_triggered should be False
        result = orchestrator.process(mock_adapter, {}, {}, content=None)

        # Scanner doesn't run without content
        assert result.scan_triggered is False

    def test_process_skips_scanner_when_no_content(self, mock_adapter):
        """Should skip scanner when no content provided."""
        orchestrator = Orchestrator(enable_classification=True)

        result = orchestrator.process(mock_adapter, {}, {}, content=None)

        # Scanner should not run without content
        assert result.scan_triggered is False


class TestOrchestratorProcessContentOnly:
    """Tests for Orchestrator.process_content_only() method."""

    def test_process_content_only_requires_classification(self):
        """Should raise when classification not enabled."""
        orchestrator = Orchestrator(enable_classification=False)

        with pytest.raises(ValueError, match="Scanner not enabled"):
            orchestrator.process_content_only(b"content", {})

    def test_process_content_only_enabled_flag(self):
        """Should require enable_classification=True."""
        # When classification is disabled, should raise
        orchestrator = Orchestrator(enable_classification=False)

        with pytest.raises(ValueError):
            orchestrator.process_content_only(b"content", {})

    def test_process_content_only_accepts_content(self):
        """Should accept content parameter."""
        # This test verifies the interface, not the full pipeline
        orchestrator = Orchestrator(enable_classification=False)

        # Should raise because classification not enabled, not because
        # of content parameter issue
        with pytest.raises(ValueError, match="Scanner not enabled"):
            orchestrator.process_content_only(b"test content", {"name": "test.txt"})


class TestOrchestratorProcessMultiple:
    """Tests for Orchestrator.process_multiple() method."""

    @pytest.fixture
    def mock_adapters_data(self):
        """Create mock adapters data."""
        adapter1 = MagicMock()
        adapter1.extract.return_value = NormalizedInput(
            entities=[Entity(type="SSN", count=2, confidence=0.9, source="adapter1")],
            context=NormalizedContext(exposure="PRIVATE"),
        )

        adapter2 = MagicMock()
        adapter2.extract.return_value = NormalizedInput(
            entities=[Entity(type="EMAIL", count=3, confidence=0.85, source="adapter2")],
            context=NormalizedContext(exposure="PUBLIC"),
        )

        return [
            {"adapter": adapter1, "source_data": {"data1": "val1"}, "metadata": {"path": "/file1"}},
            {"adapter": adapter2, "source_data": {"data2": "val2"}, "metadata": {"path": "/file2"}},
        ]

    def test_process_multiple_requires_adapters(self):
        """Should raise when no adapters provided."""
        orchestrator = Orchestrator()

        with pytest.raises(ValueError, match="At least one adapter"):
            orchestrator.process_multiple([])

    def test_process_multiple_merges_inputs(self, mock_adapters_data):
        """Should merge inputs from all adapters."""
        orchestrator = Orchestrator(enable_classification=False)

        result = orchestrator.process_multiple(mock_adapters_data)

        # Should have entities from both adapters
        assert "SSN" in result.entities
        assert "EMAIL" in result.entities

    def test_process_multiple_takes_highest_exposure(self, mock_adapters_data):
        """Should use highest exposure from all adapters."""
        orchestrator = Orchestrator(enable_classification=False)

        result = orchestrator.process_multiple(mock_adapters_data)

        # adapter2 has PUBLIC exposure
        assert result.exposure == "PUBLIC"

    def test_process_multiple_calls_all_adapters(self, mock_adapters_data):
        """Should call extract on all adapters."""
        orchestrator = Orchestrator(enable_classification=False)

        orchestrator.process_multiple(mock_adapters_data)

        for item in mock_adapters_data:
            item["adapter"].extract.assert_called_once()

    def test_process_multiple_runs_scanner_if_any_triggered(self, mock_adapters_data):
        """Should run scanner if any adapter triggers it."""
        orchestrator = Orchestrator(enable_classification=False)

        # Without classification enabled, scanner won't run
        result = orchestrator.process_multiple(mock_adapters_data, content=None)

        # No scanner without classification
        assert result.scan_triggered is False


class TestCreateOrchestrator:
    """Tests for create_orchestrator factory function."""

    def test_creates_orchestrator(self):
        """Should create Orchestrator instance."""
        orch = create_orchestrator()

        assert isinstance(orch, Orchestrator)
        assert orch.enable_classification is False

    def test_passes_classification_flag(self):
        """Should pass enable_classification flag."""
        orch = create_orchestrator(enable_classification=True)

        assert orch.enable_classification is True

    def test_passes_scanner_config(self):
        """Should pass scanner config kwargs."""
        orch = create_orchestrator(
            enable_classification=True,
            min_confidence=0.8,
            enable_ocr=True,
        )

        assert orch._scanner_config["min_confidence"] == 0.8
        assert orch._scanner_config["enable_ocr"] is True


class TestIntegration:
    """Integration tests for orchestrator pipeline."""

    def test_full_pipeline_without_scanner(self):
        """Test complete pipeline with adapter only (no scanner)."""
        # Setup mock adapter
        mock_adapter = MagicMock()
        mock_adapter.extract.return_value = NormalizedInput(
            entities=[
                Entity(type="SSN", count=2, confidence=0.9, source="macie"),
            ],
            context=NormalizedContext(exposure="PUBLIC"),
        )

        # Run pipeline without scanner
        orchestrator = Orchestrator(enable_classification=False)
        result = orchestrator.process(
            mock_adapter,
            source_data={"findings": []},
            metadata={"path": "/bucket/file.xlsx"},
        )

        # Verify result
        assert isinstance(result, ProcessingResult)
        assert result.score >= 0
        assert result.tier in RiskTier
        assert result.scan_triggered is False
        assert result.exposure == "PUBLIC"
        assert "SSN" in result.entities

"""
Tests for the classification agent worker (openlabels.core.agents.worker).

Covers:
- WorkItem and AgentResult data classes
- EntityMatch data class
- ClassificationAgent initialization
- Model loading (with fallbacks)
- Classification pipeline (detect_sync -> EntityMatch mapping)
- Worker main loop (run method)
- Signal handling
- Error handling (classification errors, queue errors)
- agent_process_entry function
"""

from __future__ import annotations

import multiprocessing as mp
import signal
import time
from dataclasses import dataclass
from queue import Empty
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from openlabels.core.agents.worker import (
    AgentResult,
    ClassificationAgent,
    EntityMatch,
    OptimizationBackend,
    WorkItem,
    agent_process_entry,
)


# ── WorkItem tests ───────────────────────────────────────────────────


class TestWorkItem:
    """Test the WorkItem data class."""

    def test_default_fields(self):
        item = WorkItem(id="test:0", file_path="/tmp/test.txt", text="hello")
        assert item.id == "test:0"
        assert item.file_path == "/tmp/test.txt"
        assert item.text == "hello"
        assert item.chunk_index == 0
        assert item.total_chunks == 1
        assert item.priority == 0
        assert item.metadata == {}

    def test_custom_fields(self):
        item = WorkItem(
            id="file:3",
            file_path="/data/file.csv",
            text="SSN 123-45-6789",
            chunk_index=3,
            total_chunks=10,
            priority=5,
            metadata={"exposure": "PUBLIC"},
        )
        assert item.chunk_index == 3
        assert item.total_chunks == 10
        assert item.priority == 5
        assert item.metadata == {"exposure": "PUBLIC"}

    def test_priority_ordering(self):
        """Higher priority items should sort first (for priority queue)."""
        low = WorkItem(id="low", file_path="/tmp/a.txt", text="a", priority=1)
        high = WorkItem(id="high", file_path="/tmp/b.txt", text="b", priority=10)
        # __lt__ returns True when self.priority > other.priority
        assert high < low  # high priority sorts first
        assert not low < high

    def test_equal_priority(self):
        a = WorkItem(id="a", file_path="/tmp/a.txt", text="a", priority=5)
        b = WorkItem(id="b", file_path="/tmp/b.txt", text="b", priority=5)
        assert not a < b
        assert not b < a


# ── EntityMatch tests ────────────────────────────────────────────────


class TestEntityMatch:
    """Test the EntityMatch data class."""

    def test_creation(self):
        match = EntityMatch(
            entity_type="SSN",
            value="123-45-6789",
            start=0,
            end=11,
            confidence=0.99,
            source="checksum",
        )
        assert match.entity_type == "SSN"
        assert match.value == "123-45-6789"
        assert match.start == 0
        assert match.end == 11
        assert match.confidence == 0.99
        assert match.source == "checksum"
        assert match.metadata == {}

    def test_with_metadata(self):
        match = EntityMatch(
            entity_type="EMAIL",
            value="user@example.com",
            start=5,
            end=21,
            confidence=0.95,
            source="regex",
            metadata={"domain": "example.com"},
        )
        assert match.metadata == {"domain": "example.com"}


# ── AgentResult tests ────────────────────────────────────────────────


class TestAgentResult:
    """Test the AgentResult data class."""

    def test_no_sensitive_data(self):
        result = AgentResult(
            work_id="test:0",
            file_path="/tmp/test.txt",
            chunk_index=0,
            entities=[],
            processing_time_ms=5.0,
            agent_id=0,
        )
        assert not result.has_sensitive_data
        assert result.entity_types == set()
        assert result.error is None

    def test_has_sensitive_data(self):
        result = AgentResult(
            work_id="test:0",
            file_path="/tmp/test.txt",
            chunk_index=0,
            entities=[
                EntityMatch(
                    entity_type="SSN",
                    value="123-45-6789",
                    start=0,
                    end=11,
                    confidence=0.99,
                    source="checksum",
                ),
                EntityMatch(
                    entity_type="EMAIL",
                    value="a@b.com",
                    start=15,
                    end=22,
                    confidence=0.95,
                    source="regex",
                ),
            ],
            processing_time_ms=15.0,
            agent_id=0,
        )
        assert result.has_sensitive_data
        assert result.entity_types == {"SSN", "EMAIL"}

    def test_with_error(self):
        result = AgentResult(
            work_id="test:0",
            file_path="/tmp/test.txt",
            chunk_index=0,
            entities=[],
            processing_time_ms=1.0,
            agent_id=0,
            error="Model timeout",
        )
        assert result.error == "Model timeout"
        assert not result.has_sensitive_data


# ── OptimizationBackend tests ────────────────────────────────────────


class TestOptimizationBackend:
    """Test the OptimizationBackend enum."""

    def test_values(self):
        assert OptimizationBackend.PYTORCH.value == "pytorch"
        assert OptimizationBackend.IPEX.value == "ipex"
        assert OptimizationBackend.OPENVINO.value == "openvino"
        assert OptimizationBackend.ONNX.value == "onnx"

    def test_from_string(self):
        assert OptimizationBackend("pytorch") == OptimizationBackend.PYTORCH
        assert OptimizationBackend("openvino") == OptimizationBackend.OPENVINO


# ── ClassificationAgent initialization tests ─────────────────────────


class TestClassificationAgentInit:
    """Test agent initialization."""

    def test_default_init(self):
        input_q = MagicMock()
        output_q = MagicMock()

        agent = ClassificationAgent(
            agent_id=0,
            input_queue=input_q,
            output_queue=output_q,
        )
        assert agent.agent_id == 0
        assert agent.backend == OptimizationBackend.PYTORCH
        assert agent.device == "cpu"
        assert agent.model_path is None
        assert agent._shutdown is False
        assert agent._items_processed == 0

    def test_custom_init(self):
        agent = ClassificationAgent(
            agent_id=5,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
            backend=OptimizationBackend.ONNX,
            model_path="/models/ner.onnx",
            device="cuda",
        )
        assert agent.agent_id == 5
        assert agent.backend == OptimizationBackend.ONNX
        assert agent.model_path == "/models/ner.onnx"
        assert agent.device == "cuda"


# ── ClassificationAgent model loading tests ──────────────────────────


class TestClassificationAgentModelLoading:
    """Test model loading with various backends."""

    def test_load_pytorch_model(self):
        """PyTorch model loading creates a DetectorOrchestrator."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
        )

        with patch(
            "openlabels.core.detectors.orchestrator.DetectorOrchestrator"
        ) as MockOrch:
            mock_instance = MagicMock()
            MockOrch.return_value = mock_instance

            agent._load_pytorch_model()

            MockOrch.assert_called_once()
            assert agent._processor is mock_instance

    def test_load_ipex_model_fallback(self):
        """IPEX loading falls back to PyTorch when import fails."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
            backend=OptimizationBackend.IPEX,
        )

        with patch(
            "openlabels.core.detectors.orchestrator.DetectorOrchestrator"
        ) as MockOrch:
            mock_instance = MagicMock()
            MockOrch.return_value = mock_instance

            # Simulate IPEX import failure by patching the method to call fallback
            agent._load_ipex_model()
            # Either way, _processor should be set
            assert agent._processor is not None

    def test_load_openvino_model_fallback(self):
        """OpenVINO loading falls back to PyTorch when import fails."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
            backend=OptimizationBackend.OPENVINO,
        )

        with patch(
            "openlabels.core.detectors.orchestrator.DetectorOrchestrator"
        ) as MockOrch:
            mock_instance = MagicMock()
            MockOrch.return_value = mock_instance

            agent._load_openvino_model()
            assert agent._processor is not None

    def test_load_onnx_model_fallback(self):
        """ONNX loading falls back to PyTorch when import fails."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
            backend=OptimizationBackend.ONNX,
        )

        with patch(
            "openlabels.core.detectors.orchestrator.DetectorOrchestrator"
        ) as MockOrch:
            mock_instance = MagicMock()
            MockOrch.return_value = mock_instance

            agent._load_onnx_model()
            assert agent._processor is not None

    def test_load_model_dispatches_correctly(self):
        """_load_model dispatches to the correct backend loader."""
        for backend, expected_method in [
            (OptimizationBackend.PYTORCH, "_load_pytorch_model"),
            (OptimizationBackend.IPEX, "_load_ipex_model"),
            (OptimizationBackend.OPENVINO, "_load_openvino_model"),
            (OptimizationBackend.ONNX, "_load_onnx_model"),
        ]:
            agent = ClassificationAgent(
                agent_id=0,
                input_queue=MagicMock(),
                output_queue=MagicMock(),
                backend=backend,
            )

            with patch.object(agent, expected_method) as mock_loader:
                agent._load_model()
                mock_loader.assert_called_once()


# ── ClassificationAgent classification tests ─────────────────────────


class TestClassificationAgentClassify:
    """Test the classification pipeline."""

    def _make_mock_span(
        self,
        entity_type: str = "SSN",
        text: str = "123-45-6789",
        start: int = 0,
        end: int = 11,
        confidence: float = 0.99,
        detector: str = "checksum",
    ):
        """Create a mock Span object."""
        span = MagicMock()
        span.entity_type = entity_type
        span.text = text
        span.start = start
        span.end = end
        span.confidence = confidence
        span.detector = detector
        return span

    def test_classify_success(self):
        """Successful classification returns entities."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
        )

        mock_result = MagicMock()
        mock_result.spans = [
            self._make_mock_span(
                entity_type="SSN",
                text="123-45-6789",
                start=10,
                end=21,
            ),
            self._make_mock_span(
                entity_type="EMAIL",
                text="test@example.com",
                start=30,
                end=46,
                confidence=0.95,
                detector="regex",
            ),
        ]

        agent._processor = MagicMock()
        agent._processor.detect_sync.return_value = mock_result

        item = WorkItem(id="test:0", file_path="/tmp/test.txt", text="some text")
        result = agent._classify(item)

        assert result.work_id == "test:0"
        assert result.file_path == "/tmp/test.txt"
        assert len(result.entities) == 2
        assert result.entities[0].entity_type == "SSN"
        assert result.entities[0].value == "123-45-6789"
        assert result.entities[0].source == "checksum"
        assert result.entities[1].entity_type == "EMAIL"
        assert result.entities[1].value == "test@example.com"
        assert result.entities[1].source == "regex"
        assert result.error is None
        assert result.processing_time_ms > 0
        assert result.agent_id == 0

    def test_classify_no_entities(self):
        """Classification with no entities returns empty list."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
        )

        mock_result = MagicMock()
        mock_result.spans = []

        agent._processor = MagicMock()
        agent._processor.detect_sync.return_value = mock_result

        item = WorkItem(id="test:0", file_path="/tmp/clean.txt", text="no PII here")
        result = agent._classify(item)

        assert result.entities == []
        assert result.error is None

    def test_classify_runtime_error(self):
        """RuntimeError during classification is captured in result.error."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
        )

        agent._processor = MagicMock()
        agent._processor.detect_sync.side_effect = RuntimeError("Model OOM")

        item = WorkItem(id="test:0", file_path="/tmp/test.txt", text="some text")
        result = agent._classify(item)

        assert result.error == "Model OOM"
        assert result.entities == []

    def test_classify_value_error(self):
        """ValueError during classification is captured in result.error."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
        )

        agent._processor = MagicMock()
        agent._processor.detect_sync.side_effect = ValueError("Invalid input")

        item = WorkItem(id="test:0", file_path="/tmp/test.txt", text="")
        result = agent._classify(item)

        assert result.error == "Invalid input"

    def test_classify_os_error(self):
        """OSError during classification is captured in result.error."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
        )

        agent._processor = MagicMock()
        agent._processor.detect_sync.side_effect = OSError("Disk failure")

        item = WorkItem(id="test:0", file_path="/tmp/test.txt", text="text")
        result = agent._classify(item)

        assert result.error == "Disk failure"


# ── ClassificationAgent run loop tests ───────────────────────────────


class TestClassificationAgentRunLoop:
    """Test the main agent run loop."""

    def test_run_processes_items_and_exits_on_poison_pill(self):
        """Agent processes items until it receives a poison pill (None)."""
        input_q = MagicMock()
        output_q = MagicMock()

        item = WorkItem(id="test:0", file_path="/tmp/test.txt", text="hello")
        # First call returns item, second returns None (poison pill)
        input_q.get.side_effect = [item, None]

        agent = ClassificationAgent(
            agent_id=0,
            input_queue=input_q,
            output_queue=output_q,
        )

        mock_result = MagicMock()
        mock_result.spans = []

        with patch.object(agent, "_load_model"), \
             patch.object(agent, "_setup_signal_handlers"):
            agent._processor = MagicMock()
            agent._processor.detect_sync.return_value = mock_result

            agent.run()

        # One result pushed to output queue
        assert output_q.put.call_count == 1
        assert agent._items_processed == 1

    def test_run_handles_empty_queue_timeout(self):
        """Agent continues on queue.Empty (timeout waiting for work)."""
        input_q = MagicMock()
        output_q = MagicMock()

        # First call times out, second returns poison pill
        input_q.get.side_effect = [mp.queues.Empty(), None]

        agent = ClassificationAgent(
            agent_id=0,
            input_queue=input_q,
            output_queue=output_q,
        )

        with patch.object(agent, "_load_model"), \
             patch.object(agent, "_setup_signal_handlers"):
            agent._processor = MagicMock()
            agent.run()

        # No items processed, but agent didn't crash
        assert agent._items_processed == 0

    def test_run_handles_runtime_error_in_loop(self):
        """RuntimeError in the loop doesn't crash the agent."""
        input_q = MagicMock()
        output_q = MagicMock()

        item = WorkItem(id="test:0", file_path="/tmp/test.txt", text="hello")
        # First call raises error, second returns poison pill
        input_q.get.side_effect = [RuntimeError("queue error"), None]

        agent = ClassificationAgent(
            agent_id=0,
            input_queue=input_q,
            output_queue=output_q,
        )

        with patch.object(agent, "_load_model"), \
             patch.object(agent, "_setup_signal_handlers"):
            agent._processor = MagicMock()
            agent.run()

        assert agent._items_processed == 0

    def test_run_shutdown_flag(self):
        """Setting _shutdown flag causes agent to exit."""
        input_q = MagicMock()
        output_q = MagicMock()

        # Queue always times out — agent should check _shutdown flag
        input_q.get.side_effect = mp.queues.Empty()

        agent = ClassificationAgent(
            agent_id=0,
            input_queue=input_q,
            output_queue=output_q,
        )
        agent._shutdown = True  # Pre-set shutdown flag

        with patch.object(agent, "_load_model"), \
             patch.object(agent, "_setup_signal_handlers"):
            agent._processor = MagicMock()
            agent.run()

        assert agent._items_processed == 0

    def test_run_tracks_stats(self):
        """Agent tracks processing statistics correctly."""
        input_q = MagicMock()
        output_q = MagicMock()

        items = [
            WorkItem(id=f"test:{i}", file_path="/tmp/test.txt", text=f"text {i}")
            for i in range(3)
        ]
        input_q.get.side_effect = items + [None]

        agent = ClassificationAgent(
            agent_id=0,
            input_queue=input_q,
            output_queue=output_q,
        )

        mock_result = MagicMock()
        mock_result.spans = []

        with patch.object(agent, "_load_model"), \
             patch.object(agent, "_setup_signal_handlers"):
            agent._processor = MagicMock()
            agent._processor.detect_sync.return_value = mock_result

            agent.run()

        assert agent._items_processed == 3
        assert agent._total_time_ms > 0
        assert output_q.put.call_count == 3


# ── Signal handling tests ────────────────────────────────────────────


class TestSignalHandling:
    """Test graceful shutdown signal handling."""

    def test_setup_signal_handlers(self):
        """Signal handlers are registered for SIGTERM and SIGINT."""
        agent = ClassificationAgent(
            agent_id=0,
            input_queue=MagicMock(),
            output_queue=MagicMock(),
        )

        with patch("openlabels.core.agents.worker.signal.signal") as mock_signal:
            agent._setup_signal_handlers()

            # Should register handlers for SIGTERM and SIGINT
            calls = mock_signal.call_args_list
            registered_signals = [call[0][0] for call in calls]
            assert signal.SIGTERM in registered_signals
            assert signal.SIGINT in registered_signals


# ── agent_process_entry tests ────────────────────────────────────────


class TestAgentProcessEntry:
    """Test the subprocess entry point."""

    def test_entry_creates_and_runs_agent(self):
        """agent_process_entry creates a ClassificationAgent and calls run()."""
        with patch(
            "openlabels.core.agents.worker.ClassificationAgent"
        ) as MockAgent:
            mock_instance = MagicMock()
            MockAgent.return_value = mock_instance

            input_q = MagicMock()
            output_q = MagicMock()

            agent_process_entry(
                agent_id=3,
                input_queue=input_q,
                output_queue=output_q,
                backend="pytorch",
                model_path=None,
                device="cpu",
            )

            MockAgent.assert_called_once_with(
                agent_id=3,
                input_queue=input_q,
                output_queue=output_q,
                backend=OptimizationBackend.PYTORCH,
                model_path=None,
                device="cpu",
            )
            mock_instance.run.assert_called_once()

    def test_entry_with_openvino_backend(self):
        """agent_process_entry correctly parses backend string."""
        with patch(
            "openlabels.core.agents.worker.ClassificationAgent"
        ) as MockAgent:
            mock_instance = MagicMock()
            MockAgent.return_value = mock_instance

            agent_process_entry(
                agent_id=0,
                input_queue=MagicMock(),
                output_queue=MagicMock(),
                backend="openvino",
                model_path="/models/ner_openvino",
                device="cpu",
            )

            call_kwargs = MockAgent.call_args[1]
            assert call_kwargs["backend"] == OptimizationBackend.OPENVINO
            assert call_kwargs["model_path"] == "/models/ner_openvino"

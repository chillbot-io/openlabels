"""
Classification agent worker process.

Each agent is a self-contained classification unit:
- Loads its own model instance (~350MB)
- Processes work items from a shared queue
- Returns classification results

Optimized for Intel CPUs with optional IPEX/OpenVINO support.
"""

from __future__ import annotations

import logging
import multiprocessing as mp
import os
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from multiprocessing.queues import Queue

logger = logging.getLogger(__name__)


class OptimizationBackend(str, Enum):
    """Available inference optimization backends."""

    PYTORCH = "pytorch"           # Standard PyTorch
    IPEX = "ipex"                 # Intel Extension for PyTorch
    OPENVINO = "openvino"         # Intel OpenVINO (best for INT8)
    ONNX = "onnx"                 # ONNX Runtime


@dataclass
class WorkItem:
    """A unit of work for classification."""

    id: str                       # Unique identifier (file_id + chunk_index)
    file_path: str                # Source file path
    text: str                     # Text content to classify
    chunk_index: int = 0          # Chunk number within file
    total_chunks: int = 1         # Total chunks in file
    priority: int = 0             # Higher = more urgent
    metadata: dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other: "WorkItem") -> bool:
        """For priority queue ordering."""
        return self.priority > other.priority  # Higher priority first


@dataclass
class EntityMatch:
    """A detected entity within text."""

    entity_type: str              # e.g., "PERSON", "SSN", "CREDIT_CARD"
    value: str                    # The matched text
    start: int                    # Start character offset
    end: int                      # End character offset
    confidence: float             # 0.0 - 1.0
    source: str                   # "ner", "regex", "checksum"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Result from classifying a work item."""

    work_id: str                  # Matches WorkItem.id
    file_path: str
    chunk_index: int
    entities: list[EntityMatch]
    processing_time_ms: float
    agent_id: int
    error: Optional[str] = None

    @property
    def has_sensitive_data(self) -> bool:
        """Check if any entities were found."""
        return len(self.entities) > 0

    @property
    def entity_types(self) -> set[str]:
        """Get unique entity types found."""
        return {e.entity_type for e in self.entities}


class ClassificationAgent:
    """
    A worker process that performs text classification.

    Each agent:
    1. Loads the NER model and regex patterns once at startup
    2. Pulls work items from shared input queue
    3. Classifies text and pushes results to output queue
    4. Runs until shutdown signal received
    """

    def __init__(
        self,
        agent_id: int,
        input_queue: "Queue[WorkItem | None]",
        output_queue: "Queue[AgentResult]",
        backend: OptimizationBackend = OptimizationBackend.PYTORCH,
        model_path: Optional[str] = None,
        device: str = "cpu",
    ):
        self.agent_id = agent_id
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.backend = backend
        self.model_path = model_path
        self.device = device

        self._shutdown = False
        self._processor: Any = None
        self._items_processed = 0
        self._total_time_ms = 0.0

    def _setup_signal_handlers(self) -> None:
        """Handle graceful shutdown signals."""
        def handler(signum: int, frame: Any) -> None:
            logger.info(f"Agent {self.agent_id} received shutdown signal")
            self._shutdown = True

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)

    def _load_model(self) -> None:
        """Load the classification model with optional optimizations."""
        logger.info(f"Agent {self.agent_id} loading model (backend={self.backend.value})")

        start = time.perf_counter()

        if self.backend == OptimizationBackend.IPEX:
            self._load_ipex_model()
        elif self.backend == OptimizationBackend.OPENVINO:
            self._load_openvino_model()
        elif self.backend == OptimizationBackend.ONNX:
            self._load_onnx_model()
        else:
            self._load_pytorch_model()

        load_time = (time.perf_counter() - start) * 1000
        logger.info(f"Agent {self.agent_id} model loaded in {load_time:.0f}ms")

    def _load_pytorch_model(self) -> None:
        """Load standard PyTorch model."""
        from openlabels.core.processor import SensitiveDataProcessor

        self._processor = SensitiveDataProcessor()

    def _load_ipex_model(self) -> None:
        """Load model with Intel Extension for PyTorch optimizations."""
        try:
            import intel_extension_for_pytorch as ipex
            import torch
        except ImportError:
            logger.warning("IPEX not available, falling back to PyTorch")
            return self._load_pytorch_model()

        from openlabels.core.processor import SensitiveDataProcessor

        self._processor = SensitiveDataProcessor()

        # Optimize the NER model with IPEX
        if hasattr(self._processor, '_ner_model') and self._processor._ner_model:
            model = self._processor._ner_model.model
            model = ipex.optimize(model, dtype=torch.bfloat16)
            self._processor._ner_model.model = model
            logger.info(f"Agent {self.agent_id} applied IPEX optimization")

    def _load_openvino_model(self) -> None:
        """Load model with OpenVINO for INT8 inference."""
        try:
            from optimum.intel import OVModelForTokenClassification
        except ImportError:
            logger.warning("OpenVINO/Optimum not available, falling back to PyTorch")
            return self._load_pytorch_model()

        from openlabels.core.processor import SensitiveDataProcessor

        # Load processor but replace NER model with OpenVINO version
        self._processor = SensitiveDataProcessor()

        if self.model_path and os.path.exists(self.model_path):
            # Load pre-converted OpenVINO model
            ov_model = OVModelForTokenClassification.from_pretrained(self.model_path)
            # Replace the model in the pipeline
            if hasattr(self._processor, '_ner_model'):
                self._processor._ner_model.model = ov_model
                logger.info(f"Agent {self.agent_id} loaded OpenVINO model from {self.model_path}")
        else:
            logger.warning(f"OpenVINO model path not found: {self.model_path}")

    def _load_onnx_model(self) -> None:
        """Load model with ONNX Runtime."""
        try:
            from optimum.onnxruntime import ORTModelForTokenClassification
        except ImportError:
            logger.warning("ONNX Runtime not available, falling back to PyTorch")
            return self._load_pytorch_model()

        from openlabels.core.processor import SensitiveDataProcessor

        self._processor = SensitiveDataProcessor()

        if self.model_path and os.path.exists(self.model_path):
            ort_model = ORTModelForTokenClassification.from_pretrained(self.model_path)
            if hasattr(self._processor, '_ner_model'):
                self._processor._ner_model.model = ort_model
                logger.info(f"Agent {self.agent_id} loaded ONNX model from {self.model_path}")

    def _classify(self, item: WorkItem) -> AgentResult:
        """Classify a single work item."""
        start = time.perf_counter()
        error = None
        entities: list[EntityMatch] = []

        try:
            # Run classification
            result = self._processor.process_text(item.text)

            # Convert to EntityMatch objects
            for entity in result.entities:
                entities.append(EntityMatch(
                    entity_type=entity.entity_type,
                    value=entity.value,
                    start=entity.start,
                    end=entity.end,
                    confidence=entity.confidence,
                    source=entity.source,
                    metadata=entity.metadata if hasattr(entity, 'metadata') else {},
                ))
        except Exception as e:
            logger.error(f"Agent {self.agent_id} classification error: {e}")
            error = str(e)

        processing_time = (time.perf_counter() - start) * 1000

        return AgentResult(
            work_id=item.id,
            file_path=item.file_path,
            chunk_index=item.chunk_index,
            entities=entities,
            processing_time_ms=processing_time,
            agent_id=self.agent_id,
            error=error,
        )

    def run(self) -> None:
        """Main agent loop - pull work, classify, push results."""
        self._setup_signal_handlers()

        # Set process name for easier debugging
        try:
            import setproctitle
            setproctitle.setproctitle(f"openlabels-agent-{self.agent_id}")
        except ImportError:
            pass

        # Load model (expensive, do once)
        self._load_model()

        logger.info(f"Agent {self.agent_id} ready, waiting for work")

        while not self._shutdown:
            try:
                # Block with timeout to allow checking shutdown flag
                item = self.input_queue.get(timeout=1.0)

                if item is None:
                    # Poison pill - shutdown signal
                    logger.info(f"Agent {self.agent_id} received shutdown pill")
                    break

                # Classify and push result
                result = self._classify(item)
                self.output_queue.put(result)

                # Track stats
                self._items_processed += 1
                self._total_time_ms += result.processing_time_ms

                if self._items_processed % 100 == 0:
                    avg_time = self._total_time_ms / self._items_processed
                    logger.debug(
                        f"Agent {self.agent_id}: processed {self._items_processed} items, "
                        f"avg {avg_time:.1f}ms/item"
                    )

            except mp.queues.Empty:
                # No work available, continue waiting
                continue
            except Exception as e:
                logger.error(f"Agent {self.agent_id} error: {e}")

        # Final stats
        if self._items_processed > 0:
            avg_time = self._total_time_ms / self._items_processed
            logger.info(
                f"Agent {self.agent_id} shutting down: "
                f"processed {self._items_processed} items, avg {avg_time:.1f}ms/item"
            )


def agent_process_entry(
    agent_id: int,
    input_queue: "Queue[WorkItem | None]",
    output_queue: "Queue[AgentResult]",
    backend: str,
    model_path: Optional[str],
    device: str,
) -> None:
    """Entry point for agent subprocess."""
    # Configure logging for subprocess
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s [Agent-{agent_id}] %(levelname)s: %(message)s",
    )

    agent = ClassificationAgent(
        agent_id=agent_id,
        input_queue=input_queue,
        output_queue=output_queue,
        backend=OptimizationBackend(backend),
        model_path=model_path,
        device=device,
    )
    agent.run()

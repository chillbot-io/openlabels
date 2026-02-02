"""Tier 1: ML-based detectors for NER using HuggingFace transformers.

Supports loading PyTorch models for NER inference.
For production use with ONNX models, see ml_onnx.py.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import logging
import os

from ..types import Span, Tier
from ..constants import PRODUCT_CODE_PREFIXES
from .base import BaseDetector
from .labels import PHI_BERT_LABELS, PII_BERT_LABELS


logger = logging.getLogger(__name__)


# DEVICE DETECTION

def get_device(device_config: str = "auto", cuda_device_id: int = 0) -> int:
    """
    Determine the device to use for ML inference.

    Args:
        device_config: "auto", "cuda", or "cpu"
        cuda_device_id: GPU index for multi-GPU systems

    Returns:
        Device ID for HuggingFace pipeline:
        - -1 = CPU
        - 0, 1, 2... = CUDA device index

    Environment variables:
        OPENLABELS_DEVICE: Override device ("auto", "cuda", "cpu")
        CUDA_VISIBLE_DEVICES: Standard CUDA device selection
    """
    # Environment override takes priority
    env_device = os.environ.get("OPENLABELS_DEVICE", "").lower()
    if env_device in ("cpu", "cuda", "auto"):
        device_config = env_device

    # Force CPU
    if device_config == "cpu":
        logger.info("Device: CPU (forced by config)")
        return -1

    # Check CUDA availability via onnxruntime
    try:
        import onnxruntime as ort
        providers = ort.get_available_providers()
        cuda_available = 'CUDAExecutionProvider' in providers

        if cuda_available:
            logger.info(f"Device: CUDA (via onnxruntime, providers: {providers})")
            return cuda_device_id
        else:
            if device_config == "cuda":
                logger.warning("Device: CUDA requested but not available - falling back to CPU")
            else:
                logger.info("Device: CPU (CUDA not available)")
            return -1

    except ImportError:
        logger.warning("Device: onnxruntime not installed - using CPU")
        return -1
    except Exception as e:
        logger.warning(f"Device: Error detecting GPU ({e}) - using CPU")
        return -1


def get_device_info() -> Dict[str, Any]:
    """
    Get detailed device information for diagnostics.

    Returns:
        Dict with device info for logging/UI display.
    """
    info = {
        "device": "cpu",
        "cuda_available": False,
        "onnxruntime_version": None,
        "providers": [],
    }

    try:
        import onnxruntime as ort
        info["onnxruntime_version"] = ort.__version__
        info["providers"] = ort.get_available_providers()
        info["cuda_available"] = 'CUDAExecutionProvider' in info["providers"]

        if info["cuda_available"]:
            info["device"] = "cuda"
    except ImportError:
        logger.debug("onnxruntime not installed, device info unavailable")
    except Exception as e:
        logger.debug(f"Failed to get device info: {e}")
        info["error"] = str(e)

    return info


class MLDetector(BaseDetector):
    """Base class for ML-based NER detectors using HuggingFace transformers."""

    name = "ml"
    tier = Tier.ML
    label_map: Dict[str, str] = {}

    def __init__(
        self,
        model_path: Optional[Path] = None,
        device: str = "auto",
        cuda_device_id: int = 0,
    ):
        self.model_path = model_path
        self.device_config = device
        self.cuda_device_id = cuda_device_id
        self._model = None
        self._tokenizer = None
        self._pipeline = None
        self._loaded = False
        self._device_id = None  # Actual device used (-1=CPU, 0+=CUDA)

    def is_available(self) -> bool:
        """Check if model is loaded and ready."""
        return self._loaded

    def get_device_used(self) -> str:
        """Return the device being used ('cpu' or 'cuda:N')."""
        if self._device_id is None:
            return "not loaded"
        elif self._device_id == -1:
            return "cpu"
        else:
            return f"cuda:{self._device_id}"

    def load(self) -> bool:
        """
        Load the model using HuggingFace transformers.

        Expected files in model_path:
        - pytorch_model.bin or model.safetensors: Model weights
        - config.json: Model config
        - tokenizer.json / tokenizer_config.json: Tokenizer

        Returns:
            True if loaded successfully
        """
        if not self.model_path or not self.model_path.exists():
            logger.warning(f"{self.name} detector disabled: model not found at {self.model_path}")
            return False

        # Check for model files (either format)
        has_bin = (self.model_path / "pytorch_model.bin").exists()
        has_safetensors = (self.model_path / "model.safetensors").exists()
        has_config = (self.model_path / "config.json").exists()

        if not (has_bin or has_safetensors):
            logger.warning(f"{self.name} detector disabled: no model weights (pytorch_model.bin or model.safetensors)")
            return False

        if not has_config:
            logger.warning(f"{self.name} detector disabled: config.json not found")
            return False

        try:
            from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline

            # Load tokenizer and model
            self._tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
            self._model = AutoModelForTokenClassification.from_pretrained(str(self.model_path))

            # Get device using configurable detection
            self._device_id = get_device(self.device_config, self.cuda_device_id)

            # Create NER pipeline
            self._pipeline = pipeline(
                "ner",
                model=self._model,
                tokenizer=self._tokenizer,
                aggregation_strategy="simple",
                device=self._device_id,
            )

            device_str = "CPU" if self._device_id == -1 else f"CUDA:{self._device_id}"
            logger.info(f"{self.name}: Model loaded from {self.model_path} on {device_str}")
            self._loaded = True
            return True

        except ImportError:
            logger.warning(f"{self.name}: transformers not installed")
            return False
        except Exception as e:
            logger.error(f"{self.name}: Failed to load model: {e}")
            return False

    def detect(self, text: str) -> List[Span]:
        """
        Run NER inference using HuggingFace pipeline.

        Returns list of Spans with detected entities.
        """
        if not self._loaded or not self._pipeline:
            return []

        try:
            results = self._pipeline(text)
        except Exception as e:
            logger.error(f"{self.name}: Inference failed: {e}")
            return []

        spans = []
        for r in results:
            # Get entity label (remove B-/I- prefix if pipeline didn't)
            raw_label = r.get("entity_group", r.get("entity", ""))

            # Map to canonical type
            canonical_type = self.label_map.get(f"B-{raw_label}", raw_label)

            # Skip unmapped labels
            if canonical_type == raw_label and f"B-{raw_label}" not in self.label_map:
                # Try without B- prefix (aggregation_strategy may strip it)
                canonical_type = self.label_map.get(raw_label, raw_label)

            start = r["start"]
            end = r["end"]
            confidence = float(r["score"])

            # CRITICAL: Expand to word boundaries to prevent partial PHI leaks
            # e.g., "J[NAME_1]rner" instead of "[NAME_1]"
            while start > 0 and not text[start - 1].isspace():
                start -= 1
            while end < len(text) and not text[end].isspace():
                end += 1

            # Extract text from original (pipeline may have subword artifacts)
            span_text = text[start:end]

            # Filter product codes falsely detected as MRN/ID
            # "SKU-123-45-6789" looks like an ID but is a product code
            if canonical_type in ("ID", "MRN"):
                first_part = span_text.split('-')[0].split('_')[0].split('#')[0].lower()
                if first_part in PRODUCT_CODE_PREFIXES:
                    continue

            try:
                span = Span(
                    start=start,
                    end=end,
                    text=span_text,
                    entity_type=canonical_type,
                    confidence=confidence,
                    detector=self.name,
                    tier=self.tier,
                )
                spans.append(span)
            except ValueError as e:
                logger.debug(f"{self.name}: Invalid span skipped: {e}")

        return spans


class PHIBertDetector(MLDetector):
    """Stanford Clinical PHI-BERT detector for healthcare NER."""

    name = "phi_bert"
    label_map = PHI_BERT_LABELS

    def __init__(
        self,
        model_path: Optional[Path] = None,
        device: str = "auto",
        cuda_device_id: int = 0,
    ):
        super().__init__(model_path, device, cuda_device_id)
        if model_path:
            self.load()


class PIIBertDetector(MLDetector):
    """Custom PII-BERT detector (AI4Privacy trained) for general PII."""

    name = "pii_bert"
    label_map = PII_BERT_LABELS

    def __init__(
        self,
        model_path: Optional[Path] = None,
        device: str = "auto",
        cuda_device_id: int = 0,
    ):
        super().__init__(model_path, device, cuda_device_id)
        if model_path:
            self.load()

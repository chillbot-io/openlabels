"""Model configuration and availability checking for ML detectors.

Defines the expected model directory structure and provides utilities
for checking which models are present and ready for inference.

Expected directory layout under the models directory (DEFAULT_MODELS_DIR):

    models/
        stanford_phi/                   # Stanford Clinical De-identifier
            pytorch_model.bin           # Model weights (~438 MB)
            config.json                 # Model config
            vocab.txt                   # WordPiece vocabulary
            special_tokens_map.json
            tokenizer_config.json

        rapidocr/                       # RapidOCR (PaddleOCR ONNX)
            det.onnx
            rec.onnx
            cls.onnx

How to obtain models:
    Models are not distributed with the package. To use ML detectors:

    1. Download models via CLI:
           openlabels models download all
           openlabels models download phi     # Stanford PHI detector only
           openlabels models download ocr     # OCR models only
    2. Models are fetched from HuggingFace Hub and placed under
       DEFAULT_MODELS_DIR (typically .openlabels/models/).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import DEFAULT_MODELS_DIR

logger = logging.getLogger(__name__)


# Model specs for availability checking
PHI_MODEL_SPEC = {
    "subdir": "stanford_phi",
    "required_files": ["config.json", "vocab.txt"],
    "weight_files": ["pytorch_model.bin", "model.safetensors"],
}


@dataclass
class ModelStatus:
    """Status of a single model."""
    name: str
    available: bool
    path: Path | None = None
    missing_files: list[str] = field(default_factory=list)
    backend: str = "unknown"


@dataclass
class ModelsReport:
    """Report on all model availability."""
    models_dir: Path
    models_dir_exists: bool
    models: dict[str, ModelStatus] = field(default_factory=dict)

    @property
    def any_available(self) -> bool:
        return any(m.available for m in self.models.values())

    @property
    def all_available(self) -> bool:
        return all(m.available for m in self.models.values())

    def summary(self) -> str:
        lines = [f"Models directory: {self.models_dir} (exists={self.models_dir_exists})"]
        for name, status in self.models.items():
            if status.available:
                lines.append(f"  {name}: AVAILABLE ({status.backend}) at {status.path}")
            else:
                lines.append(f"  {name}: MISSING")
                for f in status.missing_files:
                    lines.append(f"    - needs: {f}")
        return "\n".join(lines)


def check_models_available(
    model_dir: Path | None = None,
    use_onnx: bool = True,
) -> ModelsReport:
    """Check which ML models are present and ready for use.

    Args:
        model_dir: Base models directory. Defaults to DEFAULT_MODELS_DIR.
        use_onnx: Ignored (kept for API compatibility). PHI model uses
                  HuggingFace transformers backend.

    Returns:
        ModelsReport with per-model availability status.
    """
    base = Path(model_dir) if model_dir else DEFAULT_MODELS_DIR
    base = base.expanduser()

    report = ModelsReport(
        models_dir=base,
        models_dir_exists=base.exists(),
    )

    if not base.exists():
        report.models["phi"] = ModelStatus(
            name="phi",
            available=False,
            missing_files=[f"directory {base} does not exist"],
            backend="hf",
        )
        return report

    # Check Stanford PHI model
    spec = PHI_MODEL_SPEC
    missing = []
    subdir = base / spec["subdir"]

    if not subdir.is_dir():
        missing.append(f"directory {subdir}")
    else:
        for req in spec["required_files"]:
            if not (subdir / req).exists():
                missing.append(req)

        has_weights = any((subdir / w).exists() for w in spec["weight_files"])
        if not has_weights:
            missing.append(
                f"weights (one of: {', '.join(spec['weight_files'])})"
            )

    report.models["phi"] = ModelStatus(
        name="phi",
        available=len(missing) == 0,
        path=subdir if len(missing) == 0 else None,
        missing_files=missing,
        backend="hf",
    )

    return report

"""Model configuration and availability checking for ML detectors.

Defines the expected model directory structure and provides utilities
for checking which models are present and ready for inference.

Expected directory layout under the models directory (DEFAULT_MODELS_DIR):

    models/
        phi_bert_int8.onnx          # ONNX model (INT8 quantized, preferred)
        phi_bert.onnx               # ONNX model (full precision, fallback)
        phi_bert.tokenizer.json     # Standalone fast tokenizer
        phi_bert.labels.json        # Label ID to name mapping
        phi_bert_tokenizer/         # HuggingFace tokenizer dir (fallback)
            tokenizer.json
            tokenizer_config.json
            special_tokens_map.json
            vocab.txt

        pii_bert_int8.onnx
        pii_bert.onnx
        pii_bert.tokenizer.json
        pii_bert.labels.json
        pii_bert_tokenizer/
            tokenizer.json
            tokenizer_config.json
            special_tokens_map.json
            vocab.txt

    For HuggingFace transformers (non-ONNX) mode, each model needs
    a subdirectory with standard HuggingFace model files:

        phi_bert/
            config.json
            pytorch_model.bin or model.safetensors
            tokenizer.json
            tokenizer_config.json

        pii_bert/
            config.json
            pytorch_model.bin or model.safetensors
            tokenizer.json
            tokenizer_config.json

How to obtain models:
    Models are not distributed with the package. To use ML detectors:

    1. Download the fine-tuned BERT NER models (PHI-BERT and PII-BERT).
    2. If using ONNX mode (recommended), export them with:
           python -m optimum.exporters.onnx --model <model_dir> <output_dir>
       Then quantize to INT8 with:
           python -m onnxruntime.quantization.preprocess <model.onnx> <preprocessed.onnx>
           python scripts/quantize_onnx.py <preprocessed.onnx> <model_int8.onnx>
    3. Export standalone tokenizers with:
           python scripts/export_tokenizers.py
    4. Place all files under DEFAULT_MODELS_DIR (typically .openlabels/models/).
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import DEFAULT_MODELS_DIR

logger = logging.getLogger(__name__)


# Model names and their required files for each backend
ONNX_MODEL_SPECS = {
    "phi_bert": {
        "onnx_files": ["phi_bert_int8.onnx", "phi_bert.onnx"],  # first found wins
        "tokenizer_files": ["phi_bert.tokenizer.json"],  # standalone fast tokenizer
        "tokenizer_dir": "phi_bert_tokenizer",  # fallback HF tokenizer dir
        "labels_file": "phi_bert.labels.json",
    },
    "pii_bert": {
        "onnx_files": ["pii_bert_int8.onnx", "pii_bert.onnx"],
        "tokenizer_files": ["pii_bert.tokenizer.json"],
        "tokenizer_dir": "pii_bert_tokenizer",
        "labels_file": "pii_bert.labels.json",
    },
}

HF_MODEL_SPECS = {
    "phi_bert": {
        "subdir": "phi_bert",
        "required_files": ["config.json"],
        "weight_files": ["pytorch_model.bin", "model.safetensors"],  # any one
    },
    "pii_bert": {
        "subdir": "pii_bert",
        "required_files": ["config.json"],
        "weight_files": ["pytorch_model.bin", "model.safetensors"],
    },
}


@dataclass
class ModelStatus:
    """Status of a single model."""
    name: str
    available: bool
    path: Path | None = None
    missing_files: list[str] = field(default_factory=list)
    backend: str = "unknown"  # "onnx" or "hf"


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


def get_model_paths(
    model_dir: Path | None = None,
) -> dict[str, Path]:
    """Return expected paths for phi_bert and pii_bert model directories.

    Args:
        model_dir: Base models directory. Defaults to DEFAULT_MODELS_DIR.

    Returns:
        Dict mapping model name to its expected path. For ONNX mode, this
        is the base model_dir (models are flat files). For HF mode, this
        is the model subdirectory.
    """
    base = Path(model_dir) if model_dir else DEFAULT_MODELS_DIR

    return {
        "phi_bert": base,  # ONNX files are flat in models dir
        "pii_bert": base,
        "phi_bert_hf": base / "phi_bert",   # HF subdirectory
        "pii_bert_hf": base / "pii_bert",
    }


def check_models_available(
    model_dir: Path | None = None,
    use_onnx: bool = True,
) -> ModelsReport:
    """Check which ML models are present and ready for use.

    Inspects the model directory for expected files and reports
    which models are available and which files are missing.

    Args:
        model_dir: Base models directory. Defaults to DEFAULT_MODELS_DIR.
        use_onnx: If True, check for ONNX model files. If False, check
                  for HuggingFace transformers model files.

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
        # Report all models as missing with the directory itself as the issue
        for name in ["phi_bert", "pii_bert"]:
            report.models[name] = ModelStatus(
                name=name,
                available=False,
                missing_files=[f"directory {base} does not exist"],
                backend="onnx" if use_onnx else "hf",
            )
        return report

    if use_onnx:
        specs = ONNX_MODEL_SPECS
        for name, spec in specs.items():
            missing = []

            # Check ONNX model file (any variant)
            has_onnx = any((base / f).exists() for f in spec["onnx_files"])
            if not has_onnx:
                missing.append(f"model file (one of: {', '.join(spec['onnx_files'])})")

            # Check tokenizer (standalone or HF dir)
            has_tokenizer = any((base / f).exists() for f in spec["tokenizer_files"])
            has_tokenizer_dir = (base / spec["tokenizer_dir"]).is_dir()
            if not has_tokenizer and not has_tokenizer_dir:
                missing.append(
                    f"tokenizer ({' or '.join(spec['tokenizer_files'])} "
                    f"or {spec['tokenizer_dir']}/ directory)"
                )

            report.models[name] = ModelStatus(
                name=name,
                available=len(missing) == 0,
                path=base if len(missing) == 0 else None,
                missing_files=missing,
                backend="onnx",
            )
    else:
        specs = HF_MODEL_SPECS
        for name, spec in specs.items():
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

            report.models[name] = ModelStatus(
                name=name,
                available=len(missing) == 0,
                path=subdir if len(missing) == 0 else None,
                missing_files=missing,
                backend="hf",
            )

    return report

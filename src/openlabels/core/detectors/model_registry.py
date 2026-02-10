"""Model registry and download manager for ML detectors and OCR.

Defines the canonical model manifest — which files each model needs,
where to fetch them from HuggingFace, and how to verify integrity.

Usage:
    from openlabels.core.detectors.model_registry import (
        get_registry, download_model, list_models,
    )

    # Check what's installed
    for model in list_models():
        print(f"{model.name}: {'installed' if model.is_installed else 'missing'}")

    # Download a specific model
    download_model("phi_bert")

    # Download everything
    for model in list_models():
        download_model(model.name)
"""

import hashlib
import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..constants import DEFAULT_MODELS_DIR

logger = logging.getLogger(__name__)


@dataclass
class ModelFile:
    """A single file within a model package."""

    # Relative path under the model's install directory
    filename: str
    # HuggingFace repo-relative path (may differ from local filename)
    repo_path: str = ""
    # SHA-256 checksum for verification (empty = skip verification)
    sha256: str = ""
    # Approximate size in bytes (for progress reporting)
    size_bytes: int = 0

    def __post_init__(self):
        if not self.repo_path:
            self.repo_path = self.filename


@dataclass
class ModelSpec:
    """Specification for a downloadable model."""

    name: str
    description: str
    # HuggingFace repository ID (e.g. "chillbot-io/phi-bert-onnx")
    repo_id: str
    # Files to download
    files: List[ModelFile] = field(default_factory=list)
    # Where to install relative to models_dir (empty = flat in models_dir)
    install_subdir: str = ""
    # Optional: alternative file sets (e.g. INT8 preferred over FP32)
    # If the first file in an alternative group exists, skip the rest
    alternatives: Dict[str, List[str]] = field(default_factory=dict)

    def get_install_dir(self, models_dir: Path) -> Path:
        if self.install_subdir:
            return models_dir / self.install_subdir
        return models_dir

    def is_installed(self, models_dir: Path) -> bool:
        """Check if all required files are present."""
        install_dir = self.get_install_dir(models_dir)
        if not install_dir.exists():
            return False

        for mf in self.files:
            target = install_dir / mf.filename
            if not target.exists():
                # Check alternatives — if any alternative exists, this file
                # is optional (e.g. phi_bert.onnx when phi_bert_int8.onnx exists)
                if self._has_alternative(mf.filename, install_dir):
                    continue
                return False
        return True

    def get_missing_files(self, models_dir: Path) -> List[str]:
        """Return list of missing file names."""
        install_dir = self.get_install_dir(models_dir)
        missing = []
        for mf in self.files:
            target = install_dir / mf.filename
            if not target.exists() and not self._has_alternative(mf.filename, install_dir):
                missing.append(mf.filename)
        return missing

    def _has_alternative(self, filename: str, install_dir: Path) -> bool:
        """Check if an alternative file exists for this filename."""
        for _group, alt_files in self.alternatives.items():
            if filename in alt_files:
                return any((install_dir / af).exists() for af in alt_files if af != filename)
        return False


# ---------------------------------------------------------------------------
# Model manifest
# ---------------------------------------------------------------------------
# HuggingFace repo IDs are placeholders until the user publishes models.
# The download logic works with any valid HF repo.

_PHI_BERT_SPEC = ModelSpec(
    name="phi_bert",
    description="Stanford Clinical PHI-BERT NER (ONNX, INT8 quantized)",
    repo_id="chillbot-io/openlabels-phi-bert",
    files=[
        ModelFile("phi_bert_int8.onnx", size_bytes=45_000_000),
        ModelFile("phi_bert.onnx", size_bytes=170_000_000),
        ModelFile("phi_bert.tokenizer.json", size_bytes=700_000),
        ModelFile("phi_bert.labels.json", size_bytes=500),
    ],
    alternatives={
        "onnx_model": ["phi_bert_int8.onnx", "phi_bert.onnx"],
    },
)

_PII_BERT_SPEC = ModelSpec(
    name="pii_bert",
    description="PII-BERT general NER (ONNX, INT8 quantized)",
    repo_id="chillbot-io/openlabels-pii-bert",
    files=[
        ModelFile("pii_bert_int8.onnx", size_bytes=45_000_000),
        ModelFile("pii_bert.onnx", size_bytes=170_000_000),
        ModelFile("pii_bert.tokenizer.json", size_bytes=700_000),
        ModelFile("pii_bert.labels.json", size_bytes=500),
    ],
    alternatives={
        "onnx_model": ["pii_bert_int8.onnx", "pii_bert.onnx"],
    },
)

_OCR_SPEC = ModelSpec(
    name="ocr",
    description="RapidOCR text detection + recognition (PaddleOCR ONNX)",
    repo_id="chillbot-io/openlabels-ocr",
    install_subdir="rapidocr",
    files=[
        ModelFile("det.onnx", size_bytes=4_500_000),
        ModelFile("rec.onnx", size_bytes=11_000_000),
        ModelFile("cls.onnx", size_bytes=1_500_000),
    ],
)

_REGISTRY: Dict[str, ModelSpec] = {
    spec.name: spec for spec in [_PHI_BERT_SPEC, _PII_BERT_SPEC, _OCR_SPEC]
}

# Convenience aliases
MODEL_ALIASES: Dict[str, List[str]] = {
    "all": list(_REGISTRY.keys()),
    "ner": ["phi_bert", "pii_bert"],
    "bert": ["phi_bert", "pii_bert"],
}


def get_registry() -> Dict[str, ModelSpec]:
    """Return the full model registry."""
    return dict(_REGISTRY)


def get_model_spec(name: str) -> ModelSpec:
    """Get spec for a single model. Raises KeyError if not found."""
    return _REGISTRY[name]


def list_models(models_dir: Optional[Path] = None) -> List[ModelSpec]:
    """Return all model specs."""
    return list(_REGISTRY.values())


def resolve_names(names: List[str]) -> List[str]:
    """Resolve aliases like 'all', 'ner' to concrete model names."""
    resolved = []
    for name in names:
        if name in MODEL_ALIASES:
            resolved.extend(MODEL_ALIASES[name])
        elif name in _REGISTRY:
            resolved.append(name)
        else:
            raise KeyError(
                f"Unknown model: {name!r}. "
                f"Available: {', '.join(sorted(_REGISTRY))} "
                f"(aliases: {', '.join(sorted(MODEL_ALIASES))})"
            )
    # Deduplicate while preserving order
    seen = set()
    return [n for n in resolved if not (n in seen or seen.add(n))]


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def _verify_sha256(path: Path, expected: str) -> bool:
    """Verify file SHA-256 checksum."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest() == expected


def download_model(
    name: str,
    models_dir: Optional[Path] = None,
    force: bool = False,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> Path:
    """Download a model from HuggingFace Hub.

    Args:
        name: Model name (e.g. "phi_bert", "pii_bert", "ocr").
        models_dir: Target directory. Defaults to DEFAULT_MODELS_DIR.
        force: Re-download even if already installed.
        progress_callback: Optional (filename, downloaded, total) callback.

    Returns:
        Path to the installed model directory.

    Raises:
        KeyError: If model name is not in the registry.
        ImportError: If huggingface_hub is not installed.
        OSError: On download or filesystem errors.
    """
    spec = _REGISTRY[name]
    base = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
    install_dir = spec.get_install_dir(base)

    if not force and spec.is_installed(base):
        logger.info(f"Model {name!r} already installed at {install_dir}")
        return install_dir

    # Ensure target directory exists
    install_dir.mkdir(parents=True, exist_ok=True)

    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        raise ImportError(
            "huggingface_hub is required for model downloads. "
            "Install it with: pip install huggingface_hub"
        )

    downloaded = []
    for mf in spec.files:
        target = install_dir / mf.filename

        # Skip if already present (and not forced) or if an alternative exists
        if not force and target.exists():
            logger.debug(f"  Skipping {mf.filename} (already exists)")
            continue
        if not force and spec._has_alternative(mf.filename, install_dir):
            logger.debug(f"  Skipping {mf.filename} (alternative present)")
            continue

        logger.info(f"  Downloading {mf.repo_path} from {spec.repo_id}...")
        if progress_callback:
            progress_callback(mf.filename, 0, mf.size_bytes)

        cached_path = hf_hub_download(
            repo_id=spec.repo_id,
            filename=mf.repo_path,
        )

        # Copy from HF cache to our models directory
        shutil.copy2(cached_path, target)

        # Verify checksum if available
        if mf.sha256 and not _verify_sha256(target, mf.sha256):
            target.unlink()
            raise OSError(
                f"Checksum mismatch for {mf.filename}. "
                f"Expected {mf.sha256[:16]}..."
            )

        downloaded.append(mf.filename)
        if progress_callback:
            progress_callback(mf.filename, mf.size_bytes, mf.size_bytes)

    if downloaded:
        logger.info(f"Model {name!r} installed to {install_dir} ({len(downloaded)} files)")
    else:
        logger.info(f"Model {name!r} already up-to-date at {install_dir}")

    return install_dir


def download_all(
    models_dir: Optional[Path] = None,
    force: bool = False,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, Path]:
    """Download all models.

    Returns:
        Dict mapping model name to install path.
    """
    results = {}
    for name in _REGISTRY:
        results[name] = download_model(
            name, models_dir=models_dir, force=force,
            progress_callback=progress_callback,
        )
    return results

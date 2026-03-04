"""SHA-256 integrity verification for ML model files.

Implements trust-on-first-use (TOFU) model integrity checking:
- On first load when no manifest exists, computes and saves hashes.
- On subsequent loads, verifies hashes match the manifest.
- Logs a CRITICAL warning on mismatch but still allows loading
  (to avoid breaking existing deployments).

The manifest is stored as a JSON file alongside the model files or
at a well-known location (model_manifest.json in the detectors package).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Well-known manifest location (next to this module)
_DEFAULT_MANIFEST_PATH = Path(__file__).parent / "model_manifest.json"

# Files we track for integrity verification (common ML model files)
_MODEL_FILE_PATTERNS = (
    "pytorch_model.bin",
    "model.safetensors",
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.txt",
    "special_tokens_map.json",
    "*.onnx",
)


def _sha256_file(path: Path, chunk_size: int = 8192) -> str:
    """Compute SHA-256 hex digest of a single file.

    Args:
        path: Path to the file.
        chunk_size: Read buffer size in bytes.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_model_hashes(model_path: Path) -> dict[str, str]:
    """Compute SHA-256 hashes for all recognised model files in a directory.

    Args:
        model_path: Directory containing model files.

    Returns:
        Dict mapping relative file names to their SHA-256 hex digests.
        Only files that exist are included.
    """
    hashes: dict[str, str] = {}

    if not model_path.is_dir():
        # Single file model (e.g. a single ONNX file)
        if model_path.is_file():
            hashes[model_path.name] = _sha256_file(model_path)
        return hashes

    for pattern in _MODEL_FILE_PATTERNS:
        for file_path in model_path.glob(pattern):
            if file_path.is_file():
                relative = file_path.name
                hashes[relative] = _sha256_file(file_path)

    return hashes


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load the model manifest JSON file.

    Returns:
        Parsed manifest dict, or empty dict if file doesn't exist or is invalid.
    """
    if not manifest_path.exists():
        return {}

    try:
        with open(manifest_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read model manifest %s: %s", manifest_path, e)
        return {}


def _save_manifest(manifest_path: Path, manifest: dict[str, Any]) -> bool:
    """Save the model manifest JSON file.

    Returns:
        True if saved successfully.
    """
    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        return True
    except OSError as e:
        logger.warning("Failed to write model manifest %s: %s", manifest_path, e)
        return False


def verify_model_integrity(
    model_path: Path,
    model_name: str | None = None,
    manifest_path: Path | None = None,
) -> bool:
    """Verify ML model integrity using SHA-256 hashes.

    Implements trust-on-first-use (TOFU):
    - If no manifest entry exists for this model, computes and stores hashes.
    - If a manifest entry exists, verifies current hashes match.
    - Logs CRITICAL on mismatch but returns False (caller decides whether
      to proceed).

    Args:
        model_path: Path to the model directory or file.
        model_name: Optional human-readable name for log messages.
            Defaults to the directory/file name.
        manifest_path: Path to the manifest JSON file.
            Defaults to ``model_manifest.json`` in the detectors package.

    Returns:
        True if integrity is verified (or first use), False if mismatch detected.
    """
    if manifest_path is None:
        manifest_path = _DEFAULT_MANIFEST_PATH

    if model_name is None:
        model_name = model_path.name

    # Compute current hashes
    try:
        current_hashes = compute_model_hashes(model_path)
    except OSError as e:
        logger.error(
            "Model integrity check failed for '%s': cannot read model files: %s",
            model_name, e,
        )
        return False

    if not current_hashes:
        logger.warning(
            "Model integrity check for '%s': no recognised model files found at %s",
            model_name, model_path,
        )
        return True  # Nothing to verify

    # Load manifest
    manifest = _load_manifest(manifest_path)
    manifest_key = str(model_path.resolve())

    if manifest_key not in manifest:
        # Trust-on-first-use: record hashes.
        # SECURITY NOTE: TOFU is vulnerable to first-load attacks — if an
        # attacker places a poisoned model before the first legitimate load,
        # the poisoned hashes become the trusted baseline.  Operators should
        # pre-populate the manifest with known-good hashes from a trusted
        # source (e.g. CI/CD pipeline) or verify hashes against published
        # checksums before first deployment.
        manifest[manifest_key] = {
            "name": model_name,
            "hashes": current_hashes,
        }
        if _save_manifest(manifest_path, manifest):
            logger.warning(
                "Model integrity: TRUST-ON-FIRST-USE — recorded initial hashes "
                "for '%s' (%d files). Verify these hashes against a trusted "
                "source to prevent first-load poisoning attacks.",
                model_name, len(current_hashes),
            )
        else:
            logger.warning(
                "Model integrity: computed hashes for '%s' but failed to save manifest",
                model_name,
            )
        return True

    # Verify against stored hashes
    stored_entry = manifest[manifest_key]
    stored_hashes: dict[str, str] = stored_entry.get("hashes", {})

    mismatches: list[str] = []
    missing_files: list[str] = []
    new_files: list[str] = []

    # Check stored files against current
    for filename, expected_hash in stored_hashes.items():
        if filename not in current_hashes:
            missing_files.append(filename)
        elif current_hashes[filename] != expected_hash:
            mismatches.append(filename)

    # Check for new files not in manifest
    for filename in current_hashes:
        if filename not in stored_hashes:
            new_files.append(filename)

    if mismatches or missing_files:
        logger.critical(
            "MODEL INTEGRITY MISMATCH for '%s' at %s! "
            "This may indicate model tampering or corruption. "
            "Mismatched files: %s. Missing files: %s. New files: %s. "
            "The model will NOT be loaded. "
            "To re-baseline, delete the entry in %s and reload.",
            model_name,
            model_path,
            mismatches or "(none)",
            missing_files or "(none)",
            new_files or "(none)",
            manifest_path,
        )
        return False

    if new_files:
        logger.info(
            "Model integrity: '%s' has new files not in manifest: %s. "
            "Updating manifest.",
            model_name, new_files,
        )
        # Update manifest with new files (non-breaking addition)
        stored_hashes.update(
            {f: current_hashes[f] for f in new_files}
        )
        _save_manifest(manifest_path, manifest)

    logger.debug(
        "Model integrity verified for '%s' (%d files)",
        model_name, len(current_hashes),
    )
    return True

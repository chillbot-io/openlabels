"""Post-hoc confidence calibration for GLiNER predictions.

Applies Platt scaling (temperature + bias) per entity label to correct
for systematic over-/under-confidence in the zero-shot GLiNER model.

Parameters were derived by running GLiNER on the AI4Privacy benchmark
(10k English samples) and fitting a logistic regression from
(raw_confidence, is_correct) pairs per label.

Labels not in the calibration table pass through with their raw score.

Custom calibration
------------------
Call :func:`load_calibration` with a path to a JSON file to override the
built-in defaults.  The file must map label strings to ``[temperature, bias]``
pairs.  Call :func:`fit_calibration` to derive parameters from labeled
benchmark results.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path

logger = logging.getLogger(__name__)

# Per-label calibration: (temperature, bias)
# temperature > 1.0  → spreads scores (reduces overconfidence)
# temperature < 1.0  → sharpens scores (increases confidence)
# bias > 0           → shifts scores down (model is overconfident)
# bias < 0           → shifts scores up (model is underconfident)
#
# Identity transform: temperature=1.0, bias=0.0
GLINER_CALIBRATION: dict[str, tuple[float, float]] = {
    # ── Names ──────────────────────────────────────────────
    # Names are the most frequent entity and GLiNER tends to be
    # overconfident on partial matches.
    "person name": (1.35, 0.06),
    # FIRSTNAME: balanced dampening — (1.40, 0.08) recovered recall but
    # introduced 10 FIRSTNAME FPs on 400k (100 samples).  (1.50, 0.10)
    # requires raw >= 0.68 to survive solo — keeps most recall gains
    # while cutting marginal false positives.
    "first name": (1.50, 0.10),
    # LASTNAME: same calibration as FIRSTNAME.
    "last name": (1.50, 0.10),
    "middle name": (1.30, 0.08),
    # ── Contact ────────────────────────────────────────────
    # Emails are structurally obvious; GLiNER is well-calibrated.
    "email address": (0.90, -0.05),
    # Phone: 0 TP / 1 FP on 1k — too few samples; identity transform.
    "phone number": (1.00, 0.00),
    "url": (0.95, -0.03),
    # Username: 0 TP / 1 FP on 1k — too few samples; identity transform.
    "username": (1.00, 0.00),
    # ── Locations ──────────────────────────────────────────
    # Street address: 2 TP / 0 FP on 1k — too few samples; identity.
    "street address": (1.00, 0.00),
    # City: 18 TP / 4 FP on 1k — 18% FP rate.  Max suppression
    # to reduce spurious city detections on common words.
    "city": (2.00, 0.185),
    "state": (1.15, 0.03),
    # Zip code: 6 TP / 0 FP on 1k — identity (reliable).
    "zip code": (1.00, 0.00),
    # Country: 1 TP / 13 FP on 1k — 93% FP rate.  Heavy suppression.
    "country": (2.00, 0.185),
    "county": (1.20, 0.05),
    # ── Dates ──────────────────────────────────────────────
    "date of birth": (1.10, 0.03),
    "date": (1.15, 0.04),
    "date and time": (1.15, 0.04),
    # Time: 0 TP / 11 FP on ai4privacy 100 — near-100% FP rate.
    # The 1k benchmark had too few samples.  Heavy suppression.
    "time": (1.80, 0.15),
    # Age: on ai4privacy 100, 6 spurious at identity transform.
    # Moderate suppression to reduce FP on bare numbers.
    "age": (1.50, 0.10),
    # ── Government IDs ─────────────────────────────────────
    # Structured patterns exist for most of these.  GLiNER over-fires on
    # alphanumeric codes common in financial / EDI documents.
    "social security number": (1.05, 0.01),
    "driver license number": (1.35, 0.08),   # confused with reference codes
    "passport number": (1.30, 0.07),          # confused with short alphanumeric IDs
    "tax identification number": (1.25, 0.06),
    "national identity number": (1.30, 0.07),
    # ── Medical ────────────────────────────────────────────
    "medical record number": (1.25, 0.06),
    "health plan number": (1.20, 0.05),
    "npi number": (1.10, 0.02),
    # ── Financial ──────────────────────────────────────────
    # Credit card: 80 TP / 0 FP on 1k — 100% precision.
    # Boost confidence; GLiNER excels at Luhn-structured numbers.
    "credit card number": (0.60, -0.185),
    "bank account number": (1.35, 0.08),  # Random numbers in finance text
    "iban": (0.95, -0.02),
    # SWIFT code: 0 TP / 17 FP on 1k — 100% FP rate.  Max suppression.
    "swift code": (2.00, 0.185),
    "bank routing number": (1.25, 0.06),  # Caught well by pattern detectors
    # ── Network ────────────────────────────────────────────
    "ip address": (0.90, -0.05),  # Very structural
    "mac address": (0.90, -0.05),
    # IMEI: 0 TP / 1 FP on 1k — too few samples; identity.
    "imei number": (1.00, 0.00),
    # ── Professional ───────────────────────────────────────
    # COMPANY: lowered from 1.45 to 1.35 — the 1.45 temp suppressed
    # 22 real companies on nemotron_pii.  At 1.35, moderate-confidence
    # detections survive while still dampening overconfident FPs.
    "company name": (1.35, 0.10),
    # JOB_TITLE: lowered from (1.25, 0.08) — with JOB_TITLE ML-primary
    # and no pattern detector, the 1.25 temp required raw >= 0.58 to
    # survive solo, filtering out 39 real job titles on nemotron_pii.
    # Near-identity (1.05, 0.02) means raw >= 0.52 survives solo,
    # matching the effective solo_min for well-calibrated labels.
    "job title": (1.05, 0.02),
    "employee id": (1.15, 0.04),
    # ── Vehicle ──────────────────────────────────────────
    # VIN has checksum detector; GLiNER hallucinates on alphanumeric codes.
    "vehicle identification number": (1.45, 0.12),
    "license plate number": (1.40, 0.10),
    # ── Secrets (when detected via GLiNER in GENERAL label set) ─────
    # Password: 1 TP / 0 FP on 1k — too few samples; identity.
    "password": (1.00, 0.00),
    # Pin code: 0 TP / 3 FP on 1k — too few samples; identity.
    "pin code": (1.00, 0.00),
}

# Module-level override: when set, ``calibrate_gliner_score`` uses this
# table instead of ``GLINER_CALIBRATION``.
_custom_calibration: dict[str, tuple[float, float]] | None = None


# ── Public API ─────────────────────────────────────────────────────────

def calibrate_gliner_score(label: str, raw_score: float) -> float:
    """Apply Platt scaling to a raw GLiNER confidence score.

    If custom calibration parameters have been loaded via
    :func:`load_calibration`, those are used; otherwise the built-in
    ``GLINER_CALIBRATION`` table is used.

    Args:
        label: The GLiNER natural-language label (e.g., "person name").
        raw_score: Raw confidence from predict_entities() in (0, 1).

    Returns:
        Calibrated confidence in (0, 1).
    """
    table = _custom_calibration if _custom_calibration is not None else GLINER_CALIBRATION
    params = table.get(label)
    if params is None:
        return raw_score

    temperature, bias = params
    return _platt_transform(raw_score, temperature, bias)


def get_active_calibration() -> dict[str, tuple[float, float]]:
    """Return the currently active calibration table (custom or built-in)."""
    if _custom_calibration is not None:
        return dict(_custom_calibration)
    return dict(GLINER_CALIBRATION)


def load_calibration(path: str | Path) -> dict[str, tuple[float, float]]:
    """Load calibration parameters from a JSON file.

    The file must be a JSON object mapping label strings to
    ``[temperature, bias]`` arrays::

        {
          "person name": [1.35, 0.06],
          "email address": [0.90, -0.05]
        }

    Returns:
        The loaded calibration table.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the file is malformed.
    """
    global _custom_calibration

    path = Path(path)
    with open(path) as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object, got {type(data).__name__}")

    calibration: dict[str, tuple[float, float]] = {}
    for label, params in data.items():
        if not isinstance(params, (list, tuple)) or len(params) != 2:
            raise ValueError(
                f"Label {label!r}: expected [temperature, bias], got {params!r}"
            )
        temp, bias = float(params[0]), float(params[1])
        if temp <= 0:
            raise ValueError(f"Label {label!r}: temperature must be > 0, got {temp}")
        calibration[label] = (temp, bias)

    _custom_calibration = calibration
    logger.info("Loaded custom calibration from %s (%d labels)", path, len(calibration))
    return calibration


def save_calibration(
    params: dict[str, tuple[float, float]],
    path: str | Path,
) -> None:
    """Save calibration parameters to a JSON file.

    Args:
        params: Mapping of label → (temperature, bias).
        path: Destination file path.
    """
    path = Path(path)
    data = {label: list(vals) for label, vals in sorted(params.items())}
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    logger.info("Saved calibration to %s (%d labels)", path, len(data))


def reset_calibration() -> None:
    """Reset to built-in calibration (discard any custom table)."""
    global _custom_calibration
    _custom_calibration = None


def fit_calibration(
    labels: list[str],
    raw_scores: list[float],
    is_correct: list[bool],
    *,
    min_samples: int = 10,
) -> dict[str, tuple[float, float]]:
    """Fit Platt scaling parameters from labeled predictions.

    Groups predictions by label and fits (temperature, bias) for each
    label that has at least *min_samples* predictions using grid search
    to minimise log-loss.

    Args:
        labels: GLiNER label for each prediction.
        raw_scores: Raw confidence score for each prediction.
        is_correct: Whether each prediction was a true positive.
        min_samples: Minimum predictions per label to fit.

    Returns:
        Dict mapping label → (temperature, bias).
    """
    # Group by label
    by_label: dict[str, list[tuple[float, bool]]] = {}
    for label, score, correct in zip(labels, raw_scores, is_correct):
        by_label.setdefault(label, []).append((score, correct))

    calibration: dict[str, tuple[float, float]] = {}

    for label, pairs in sorted(by_label.items()):
        if len(pairs) < min_samples:
            # Not enough data — use identity transform
            calibration[label] = (1.0, 0.0)
            continue

        scores = [p[0] for p in pairs]
        targets = [p[1] for p in pairs]
        best_temp, best_bias = _grid_search_platt(scores, targets)
        calibration[label] = (best_temp, best_bias)

    return calibration


# ── Internal helpers ───────────────────────────────────────────────────

def _platt_transform(raw_score: float, temperature: float, bias: float) -> float:
    """Apply Platt scaling: logit → scale → sigmoid."""
    clamped = max(1e-7, min(1.0 - 1e-7, raw_score))
    logit = math.log(clamped / (1.0 - clamped))
    scaled = (logit - bias) / temperature
    return 1.0 / (1.0 + math.exp(-scaled))


def _log_loss(
    scores: list[float],
    targets: list[bool],
    temperature: float,
    bias: float,
) -> float:
    """Compute mean binary cross-entropy after Platt transform."""
    total = 0.0
    for score, target in zip(scores, targets):
        p = _platt_transform(score, temperature, bias)
        p = max(1e-7, min(1.0 - 1e-7, p))
        if target:
            total -= math.log(p)
        else:
            total -= math.log(1.0 - p)
    return total / max(len(scores), 1)


def _grid_search_platt(
    scores: list[float],
    targets: list[bool],
) -> tuple[float, float]:
    """Find (temperature, bias) that minimises log-loss via grid search.

    Explores a coarse grid then refines around the best point.
    """
    best_loss = float("inf")
    best_params = (1.0, 0.0)

    # Coarse grid
    for temp in [x * 0.1 for x in range(7, 20)]:  # 0.7 .. 1.9
        for bias in [x * 0.02 for x in range(-8, 9)]:  # -0.16 .. 0.16
            loss = _log_loss(scores, targets, temp, bias)
            if loss < best_loss:
                best_loss = loss
                best_params = (temp, bias)

    # Fine grid around best
    ct, cb = best_params
    for temp in [ct + x * 0.02 for x in range(-5, 6)]:
        if temp <= 0:
            continue
        for bias in [cb + x * 0.005 for x in range(-5, 6)]:
            loss = _log_loss(scores, targets, temp, bias)
            if loss < best_loss:
                best_loss = loss
                best_params = (round(temp, 3), round(bias, 4))

    return best_params

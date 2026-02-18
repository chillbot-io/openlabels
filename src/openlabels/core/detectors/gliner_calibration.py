"""Post-hoc confidence calibration for GLiNER predictions.

Applies Platt scaling (temperature + bias) per entity label to correct
for systematic over-/under-confidence in the zero-shot GLiNER model.

Parameters were derived by running GLiNER on the AI4Privacy benchmark
(10k English samples) and fitting a logistic regression from
(raw_confidence, is_correct) pairs per label.

Labels not in the calibration table pass through with their raw score.
"""

from __future__ import annotations

import math

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
    # slightly overconfident on partial matches.
    "person name": (1.25, 0.05),
    "first name": (1.20, 0.04),
    "last name": (1.20, 0.04),
    "middle name": (1.30, 0.08),
    # ── Contact ────────────────────────────────────────────
    # Emails are structurally obvious; GLiNER is well-calibrated.
    "email address": (0.90, -0.05),
    # Phone numbers are often confused with other digit sequences.
    "phone number": (1.40, 0.10),
    "url": (0.95, -0.03),
    "username": (1.30, 0.06),
    # ── Locations ──────────────────────────────────────────
    # Addresses span multiple tokens and GLiNER sometimes
    # underestimates boundaries, leading to partial matches.
    "street address": (1.30, 0.08),
    "city": (1.15, 0.03),
    "state": (1.15, 0.03),
    "zip code": (1.10, 0.02),
    "country": (1.10, 0.02),
    "county": (1.20, 0.05),
    # ── Dates ──────────────────────────────────────────────
    "date of birth": (1.10, 0.03),
    "date": (1.15, 0.04),
    "date and time": (1.15, 0.04),
    "age": (1.50, 0.12),  # Very noisy; any 2-digit number matches
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
    "credit card number": (0.95, -0.02),  # Well-calibrated (Luhn structure)
    "bank account number": (1.35, 0.08),  # Random numbers in finance text
    "iban": (0.95, -0.02),
    "swift code": (1.00, 0.00),
    "bank routing number": (1.25, 0.06),  # Caught well by pattern detectors
    # ── Network ────────────────────────────────────────────
    "ip address": (0.90, -0.05),  # Very structural
    "mac address": (0.90, -0.05),
    # ── Professional ───────────────────────────────────────
    "company name": (1.35, 0.08),  # Often confused with person names
    "job title": (1.40, 0.10),
    "employee id": (1.15, 0.04),
    # ── Vehicle ──────────────────────────────────────────
    # VIN has checksum detector; GLiNER hallucinates on alphanumeric codes.
    "vehicle identification number": (1.45, 0.12),
    "license plate number": (1.40, 0.10),
    # ── Secrets (when detected via GLiNER in GENERAL label set) ─────
    "password": (1.35, 0.08),
    "pin code": (1.40, 0.10),  # Very noisy; short digit sequences
}


def calibrate_gliner_score(label: str, raw_score: float) -> float:
    """Apply Platt scaling to a raw GLiNER confidence score.

    Args:
        label: The GLiNER natural-language label (e.g., "person name").
        raw_score: Raw confidence from predict_entities() in (0, 1).

    Returns:
        Calibrated confidence in (0, 1).
    """
    params = GLINER_CALIBRATION.get(label)
    if params is None:
        return raw_score

    temperature, bias = params

    # Clamp to avoid log(0) or log(inf)
    clamped = max(1e-7, min(1.0 - 1e-7, raw_score))

    # Convert probability to logit
    logit = math.log(clamped / (1.0 - clamped))

    # Apply temperature scaling and bias
    scaled = (logit - bias) / temperature

    # Convert back to probability
    return 1.0 / (1.0 + math.exp(-scaled))

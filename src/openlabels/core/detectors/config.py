"""Detection configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DetectionConfig:
    """Configuration for the detection pipeline.

    Use class methods for common presets:
        config = DetectionConfig.full()       # Everything enabled
        config = DetectionConfig.patterns_only()  # Patterns only, no ML
        config = DetectionConfig.quick()      # Fast detectors only
    """

    # Pattern detectors
    enable_checksum: bool = True
    enable_secrets: bool = True
    enable_financial: bool = True
    enable_government: bool = True
    enable_patterns: bool = True
    enable_dictionary_names: bool = True

    # Accelerated detection
    enable_hyperscan: bool = False

    # Language-gated detection: auto-detect language and route to
    # the appropriate detector subset (skip English-only models on
    # non-English text, activate multilingual GLiNER where appropriate).
    enable_language_detection: bool = True

    # ML detectors
    enable_ml: bool = True
    ml_model_dir: Path | None = None
    use_onnx: bool = True

    # GLiNER settings (PII detection)
    gliner_model: str = "gretelai/gretel-gliner-bi-base-v1.0"
    gliner_threshold: float = 0.4
    enable_label_selection: bool = True

    # Multilingual GLiNER (9 languages: EN, ES, FR, PT, DE, IT, EL, NL, SL)
    enable_multilingual: bool = False
    multilingual_gliner_model: str = "E3-JSI/gliner-multi-pii-domains-v1"
    multilingual_gliner_threshold: float = 0.4

    # Stanford PHI detection (clinical de-identification)
    enable_phi: bool = True
    phi_model: str = "StanfordAIMI/stanford-deidentifier-base"
    phi_threshold: float = 0.65

    # Post-processing
    enable_coref: bool = False
    enable_context_enhancement: bool = True
    enable_context_keywords: bool = True
    enable_policy: bool = True
    enable_allowlist: bool = True

    # Entity proximity / co-occurrence boosting
    enable_proximity_boost: bool = False
    proximity_window_chars: int = 500

    # Tuning
    confidence_threshold: float = 0.65
    ml_confidence_threshold: float = 0.50
    max_workers: int = 4

    # Per-entity-type confidence thresholds (overrides global threshold)
    entity_thresholds: tuple[tuple[str, float], ...] = (
        # Structural — regex is reliable, lower threshold
        ("EMAIL", 0.60),
        ("CREDIT_CARD", 0.60),
        ("SSN", 0.60),
        ("IBAN", 0.60),
        ("IP_ADDRESS", 0.60),
        # URL — regex pattern has 0.90 confidence and no minimum length,
        # causing 92 spurious on ai4privacy 1k.  Raise threshold so only
        # high-confidence URL detections survive.
        ("URL", 0.88),
        # Contextual — standard threshold
        ("PHONE", 0.70),
        ("ADDRESS", 0.68),
        # DATE/TIME/AGE removed from GLiNER GENERAL labels (patterns
        # handle detection).  Threshold at 0.78 filters patterns with
        # confidence below this level; well-formed date patterns were
        # bumped to 0.80+ so they survive.
        ("DATE", 0.78),
        ("DATE_DOB", 0.72),
        ("DATETIME", 0.78),
        # Country: removed from GLiNER GENERAL (93% FP rate).  Pattern
        # detectors now provide coverage at 0.78 confidence.  Threshold
        # must be below pattern confidence or ALL country detections die.
        ("COUNTRY", 0.76),
        # USERNAME — 23 spurious on nemotron_pii are from PATTERN detectors
        # (not GLiNER).  "Name+Digits" (0.72) and "word_word" (0.78)
        # patterns are the noisiest.  Threshold 0.79 filters both while
        # keeping "Word_Word" compound (0.80) and labeled (0.82-0.85).
        ("USERNAME", 0.79),
        # Names — entity thresholds are pre-ensemble filters; raising them
        # kills detections before ensemble boost can save them.  Keep at
        # original values and rely on Platt calibration + solo survival
        # thresholds for FP control instead.
        ("NAME", 0.50),
        ("FIRSTNAME", 0.60),
        ("LASTNAME", 0.58),
        ("PERSON", 0.45),
        # Professional — not PII, excluded from benchmark scoring.
        # Thresholds kept for production use but don't affect F1.
        ("COMPANY", 0.60),
        # JOB_TITLE: lowered from 0.50 to 0.45 — no pattern detector
        # exists so only GLiNER can detect these.  At 0.50 + calibration
        # (1.25, 0.08), 39 real job titles on nemotron_pii were filtered.
        # Lowering to 0.45 with near-identity calibration (1.05, 0.02)
        # recovers borderline detections while ML-primary solo_min gating
        # still filters unreliable low-confidence FPs.
        ("JOB_TITLE", 0.45),
        # FACILITY from PHI model — trained on clinical text where every
        # hospital name is PHI; massively over-fires on general-purpose text.
        ("FACILITY", 0.80),
        # PHI name types — clinical model's priors don't match general text;
        # require higher confidence than GLiNER name types.  At 0.80,
        # only strong PHI detections enter the pipeline; borderline ones
        # are filtered before they can become false positives.
        ("NAME_PATIENT", 0.80),
        ("NAME_PROVIDER", 0.80),
        # Time — removed from GLiNER GENERAL.  Unambiguous AM/PM time
        # patterns bumped to 0.92 so they survive at this threshold.
        ("TIME", 0.91),
        # Honorifics — name-splitting PREFIX removed; only pattern
        # PREFIX survives.  Raise to suppress low-confidence patterns.
        ("PREFIX", 0.80),
        # AGE — removed from GLiNER GENERAL and ML-primary.
        ("AGE", 0.82),
        ("ZIP", 0.75),
        # LICENSE_PLATE — 2 spurious from generic state-format patterns.
        # Only labeled ("License Plate: XXX") at 0.88 survives.
        ("LICENSE_PLATE", 0.87),
        # SWIFT_BIC — 2 spurious from standalone 8-char pattern (0.75).
        # Only labeled ("SWIFT: XXXX") at 0.98 survives.
        ("SWIFT_BIC", 0.80),
        # GPS_COORDINATE — GLiNER "gps coordinate" (CONTACT) has no
        # calibration and over-fires (8 spurious).  Pattern detectors
        # cover all structural GPS formats at 0.85–0.92 confidence.
        # Threshold at 0.86 filters GLiNER noise while keeping patterns.
        ("GPS_COORDINATE", 0.86),
        # DRIVER_LICENSE — context-free interleaved patterns (0.72) match
        # generic alphanumeric strings (19 ACCOUNT_NUMBER→DL mismatches).
        # Threshold at 0.78 filters context-free interleaved (0.72) while
        # keeping labeled (0.85+), state-specific (0.78+), and WDL (0.92).
        ("DRIVER_LICENSE", 0.78),
    )

    @classmethod
    def full(cls) -> DetectionConfig:
        """All detectors and post-processing enabled."""
        return cls(
            enable_hyperscan=True,
            enable_ml=True,
            enable_phi=True,
            enable_multilingual=True,
            enable_coref=True,
            enable_context_enhancement=True,
            enable_context_keywords=True,
            enable_policy=True,
            enable_proximity_boost=True,
        )

    @classmethod
    def patterns_only(cls) -> DetectionConfig:
        """Pattern detectors only (no ML, no acceleration)."""
        return cls(enable_ml=False)

    @classmethod
    def quick(cls) -> DetectionConfig:
        """Fast detectors only — no ML, no post-processing."""
        return cls(
            enable_ml=False,
            enable_coref=False,
            enable_context_enhancement=False,
        )

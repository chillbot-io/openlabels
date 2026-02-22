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
        # have 100% recall).  Higher thresholds here only affect the
        # rare case where a category-specific label set activates.
        ("DATE", 0.78),
        ("DATE_DOB", 0.72),
        ("DATETIME", 0.78),
        # Country: 93% FP rate from GLiNER, removed from GENERAL.
        ("COUNTRY", 0.82),
        # Names — ML-dependent, need lower threshold to recover
        # borderline GLiNER detections after Platt calibration.
        # Raised from 0.55 to 0.58: 12 FIRSTNAME + 6 LASTNAME
        # spurious on ai4privacy 400k at 0.55.
        ("NAME", 0.50),
        ("FIRSTNAME", 0.58),
        ("LASTNAME", 0.58),
        ("PERSON", 0.45),
        # Professional — ML-dependent, similar to names.
        # COMPANY raised from 0.55 to 0.60: still 80 spurious on
        # ai4privacy 1k at 0.55 with ML enabled (multiple detectors:
        # GLiNER + pattern + additional_patterns all producing COMPANY).
        ("COMPANY", 0.60),
        ("JOB_TITLE", 0.50),
        # FACILITY from PHI model — trained on clinical text where every
        # hospital name is PHI; massively over-fires on general-purpose text.
        ("FACILITY", 0.80),
        # PHI name types — clinical model's priors don't match general text;
        # require higher confidence than GLiNER name types.  At 0.80,
        # only strong PHI detections enter the pipeline; borderline ones
        # are filtered before they can become false positives.
        ("NAME_PATIENT", 0.80),
        ("NAME_PROVIDER", 0.80),
        # Time — removed from GLiNER GENERAL.  6 spurious at 0.85.
        # Only labeled TIME patterns ("time: HH:MM") at 0.90+ survive.
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

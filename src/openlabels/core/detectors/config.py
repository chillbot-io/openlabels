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
        # Contextual — standard threshold
        ("PHONE", 0.70),
        ("ADDRESS", 0.70),
        ("DATE", 0.65),
        ("DATE_DOB", 0.65),
        # Names — ML-dependent, need lower threshold to recover
        # borderline GLiNER detections after Platt calibration.
        # Raised from 0.45 to reduce spurious FIRSTNAME/LASTNAME FPs
        # (80 FIRSTNAME + 34 LASTNAME spurious on 1k-sample benchmark).
        ("NAME", 0.45),
        ("FIRSTNAME", 0.48),
        ("LASTNAME", 0.48),
        ("PERSON", 0.45),
        # Professional — ML-dependent, similar to names.
        ("COMPANY", 0.50),
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
        # Honorifics — structurally reliable when detected
        ("PREFIX", 0.65),
        # Ambiguous — higher threshold to reduce FP
        ("AGE", 0.70),
        ("ZIP", 0.75),
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

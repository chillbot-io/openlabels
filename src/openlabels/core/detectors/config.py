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

    # Accelerated detection
    enable_hyperscan: bool = False

    # ML detectors
    enable_ml: bool = False
    ml_model_dir: Path | None = None
    use_onnx: bool = True

    # Post-processing
    enable_coref: bool = False
    enable_context_enhancement: bool = False
    enable_policy: bool = True

    # Tuning
    confidence_threshold: float = 0.70
    max_workers: int = 4

    @classmethod
    def full(cls) -> DetectionConfig:
        """All detectors and post-processing enabled."""
        return cls(
            enable_hyperscan=True,
            enable_ml=True,
            enable_coref=True,
            enable_context_enhancement=True,
            enable_policy=True,
        )

    @classmethod
    def patterns_only(cls) -> DetectionConfig:
        """Pattern detectors only (no ML, no acceleration)."""
        return cls()

    @classmethod
    def quick(cls) -> DetectionConfig:
        """Fast detectors only — no ML, no post-processing."""
        return cls(
            enable_ml=False,
            enable_coref=False,
            enable_context_enhancement=False,
        )

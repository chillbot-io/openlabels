"""
OpenLabels Scanner - the core detection engine.

This is the main entry point for detecting PII/PHI in text and files.
Part of OpenLabels - where labels are the primitive, risk is derived.
Detector accepts optional Context for resource isolation.
"""

import stat as stat_module
import time
from pathlib import Path
from typing import List, Optional, Union, TYPE_CHECKING

from .types import DetectionResult
from .config import Config

if TYPE_CHECKING:
    from ...context import Context


class Detector:
    """
    Content scanner for PII/PHI detection.

    Orchestrates multiple detection engines (patterns, checksums, structured
    extraction) to find sensitive data in text or files.

    Example:
        >>> from openlabels.adapters.scanner import Detector
        >>> detector = Detector()
        >>> result = detector.detect("Patient John Smith, SSN 123-45-6789")
        >>> for span in result.spans:
        ...     print(f"{span.entity_type}: {span.text}")
        NAME: John Smith
        SSN: 123-45-6789

    For isolated operation:
        >>> from openlabels import Context
        >>> ctx = Context()
        >>> detector = Detector(context=ctx)
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        context: Optional["Context"] = None,
    ):
        """
        Initialize the detector.

        Args:
            config: Optional configuration. If not provided, uses defaults
                   or loads from environment variables.
            context: Optional Context for resource isolation.
                    When provided, orchestrator uses context resources
                    instead of module-level globals.
        """
        self.config = config or Config.from_env()
        self._context = context
        self._orchestrator = None

    @property
    def orchestrator(self):
        """Lazy-load the detector orchestrator."""
        if self._orchestrator is None:
            from .detectors.orchestrator import DetectorOrchestrator
            self._orchestrator = DetectorOrchestrator(
                config=self.config,
                context=self._context,
            )
        return self._orchestrator

    def detect(self, text: str) -> DetectionResult:
        """
        Detect PII/PHI entities in text.

        Args:
            text: The text to scan for sensitive data.

        Returns:
            DetectionResult containing all detected spans with metadata.

        Raises:
            ValueError: If text exceeds max_text_size limit.
        """
        from .pipeline.normalizer import normalize_text
        from .pipeline.merger import merge_spans
        from .pipeline.allowlist import apply_allowlist

        start_time = time.perf_counter()

        # Check text size limit to prevent OOM from adversarial input
        if text and len(text) > self.config.max_text_size:
            raise ValueError(
                f"Text input size ({len(text):,} characters) exceeds maximum "
                f"allowed size ({self.config.max_text_size:,} characters). "
                f"Configure max_text_size to increase the limit."
            )

        if not text or not text.strip():
            return DetectionResult(
                text=text or "",
                spans=[],
                processing_time_ms=0.0,
                detectors_used=[],
            )

        # Step 1: Normalize text (handle encoding, whitespace, etc.)
        normalized_text = normalize_text(text)

        # Step 2: Run all detectors and get metadata about failures/degradation
        raw_spans, metadata = self.orchestrator.detect_with_metadata(normalized_text)

        # Step 3: Merge overlapping spans (keep highest confidence/tier)
        merged_spans = merge_spans(raw_spans, text=normalized_text)

        # Step 4: Apply allowlist to filter false positives
        filtered_spans = apply_allowlist(normalized_text, merged_spans)

        # Step 5: Filter by confidence threshold
        final_spans = [
            span for span in filtered_spans
            if span.confidence >= self.config.min_confidence
        ]

        # Sort by position
        final_spans.sort(key=lambda s: (s.start, -s.end))

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return DetectionResult(
            text=normalized_text,
            spans=final_spans,
            processing_time_ms=elapsed_ms,
            detectors_used=metadata.detectors_run,
            detectors_failed=metadata.detectors_failed + metadata.detectors_timed_out,
            warnings=metadata.warnings,
            degraded=metadata.degraded,
            all_detectors_failed=metadata.all_detectors_failed,
        )

    def detect_file(
        self,
        path: Union[str, Path],
        extract_text_only: bool = False,
    ) -> DetectionResult:
        """
        Detect PII/PHI entities in a file.

        Supports 30+ file formats including:
        - Text: txt, md, csv, tsv, json, jsonl, xml, yaml, log, html, rtf, sql
        - Office: pdf, docx, xlsx, pptx
        - Images (OCR): jpg, png, gif, bmp, tiff, webp
        - Email: eml, msg
        - Config: env, ini, conf
        - Archives: zip, tar, gz

        Args:
            path: Path to the file to scan.
            extract_text_only: If True, only extract text without detection.

        Returns:
            DetectionResult containing detected spans and extracted text.

        Raises:
            FileNotFoundError: If file does not exist.
            ValueError: If file size exceeds max_file_size limit.
        """
        from .extractors import extract_text

        start_time = time.perf_counter()
        path = Path(path)

        try:
            st = path.lstat()  # TOCTOU-001: atomic stat
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")

        if stat_module.S_ISLNK(st.st_mode):  # Reject symlinks
            raise ValueError(f"Symlinks not allowed for security: {path}")

        if not stat_module.S_ISREG(st.st_mode):  # Regular files only
            raise ValueError(f"Not a regular file: {path}")

        # Check file size BEFORE reading to prevent OOM
        file_size = st.st_size
        if file_size > self.config.max_file_size:
            raise ValueError(
                f"File size ({file_size:,} bytes) exceeds maximum "
                f"allowed size ({self.config.max_file_size:,} bytes): {path}. "
                f"Configure max_file_size to increase the limit."
            )

        # Read file and extract text
        content = path.read_bytes()
        extraction_result = extract_text(content, path.name)
        text = extraction_result.text

        if extract_text_only:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return DetectionResult(
                text=text,
                spans=[],
                processing_time_ms=elapsed_ms,
                detectors_used=[],
            )

        # Run detection on extracted text
        result = self.detect(text)

        # Update timing to include extraction
        result.processing_time_ms = (time.perf_counter() - start_time) * 1000

        return result


def _make_config(**kwargs) -> Config:
    """Create Config with optional overrides."""
    config = Config()
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
    config.__post_init__()  # HIGH-006: re-validate after setattr
    return config


def detect(
    text: str,
    context: Optional["Context"] = None,
    **config_kwargs,
) -> DetectionResult:
    """
    Quick detection without explicitly creating a Detector.

    Args:
        text: Text to scan for PII/PHI.
        context: Optional Context for resource isolation.
        **config_kwargs: Optional config overrides (min_confidence, etc.)

    Returns:
        DetectionResult with detected spans.

    Example:
        >>> from openlabels.adapters.scanner import detect
        >>> result = detect("Call me at 555-123-4567")
        >>> print(result.entity_counts)
        {'PHONE': 1}

        >>> # With context for isolation:
        >>> from openlabels import Context
        >>> ctx = Context()
        >>> result = detect("SSN: 123-45-6789", context=ctx)
    """
    return Detector(config=_make_config(**config_kwargs), context=context).detect(text)


def detect_file(
    path: Union[str, Path],
    context: Optional["Context"] = None,
    **config_kwargs,
) -> DetectionResult:
    """
    Quick file detection without explicitly creating a Detector.

    Args:
        path: Path to file to scan.
        context: Optional Context for resource isolation.
        **config_kwargs: Optional config overrides.

    Returns:
        DetectionResult with detected spans.
    """
    return Detector(config=_make_config(**config_kwargs), context=context).detect_file(path)

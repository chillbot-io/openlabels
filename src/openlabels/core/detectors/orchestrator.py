"""
Detector orchestrator for OpenLabels detection engine.

Coordinates multiple detectors running in parallel and handles
deduplication and post-processing of results.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

from ..types import Span, Tier, DetectionResult, normalize_entity_type
from .base import BaseDetector
from .checksum import ChecksumDetector
from .secrets import SecretsDetector
from .financial import FinancialDetector
from .government import GovernmentDetector

logger = logging.getLogger(__name__)

# Default detector timeout in seconds
DETECTOR_TIMEOUT = 30.0

# Default confidence threshold for filtering
DEFAULT_CONFIDENCE_THRESHOLD = 0.70


class DetectorOrchestrator:
    """
    Orchestrates multiple detectors for comprehensive entity detection.

    Features:
    - Runs detectors in parallel for performance
    - Handles deduplication across detectors
    - Higher tier detections take precedence
    - Configurable detector enablement

    Usage:
        orchestrator = DetectorOrchestrator()
        result = orchestrator.detect("My SSN is 123-45-6789")
        for span in result.spans:
            print(f"{span.entity_type}: {span.text}")
    """

    def __init__(
        self,
        enable_checksum: bool = True,
        enable_secrets: bool = True,
        enable_financial: bool = True,
        enable_government: bool = True,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        max_workers: int = 4,
    ):
        """
        Initialize the orchestrator with configured detectors.

        Args:
            enable_checksum: Enable checksum-validated detector
            enable_secrets: Enable secrets/credentials detector
            enable_financial: Enable financial instruments detector
            enable_government: Enable government markings detector
            confidence_threshold: Minimum confidence to include results
            max_workers: Max parallel detector threads
        """
        self.confidence_threshold = confidence_threshold
        self.max_workers = max_workers
        self.detectors: List[BaseDetector] = []

        # Initialize enabled detectors
        if enable_checksum:
            self.detectors.append(ChecksumDetector())
        if enable_secrets:
            self.detectors.append(SecretsDetector())
        if enable_financial:
            self.detectors.append(FinancialDetector())
        if enable_government:
            self.detectors.append(GovernmentDetector())

        logger.info(
            f"DetectorOrchestrator initialized with {len(self.detectors)} detectors: "
            f"{[d.name for d in self.detectors]}"
        )

    def detect(self, text: str) -> DetectionResult:
        """
        Run all detectors on the input text.

        Args:
            text: Text to scan for entities

        Returns:
            DetectionResult with all detected spans
        """
        start_time = time.time()

        if not text or not text.strip():
            return DetectionResult(
                spans=[],
                entity_counts={},
                processing_time_ms=0.0,
                detectors_used=[],
                text_length=0,
            )

        # Run detectors in parallel
        all_spans: List[Span] = []
        detectors_used: List[str] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_detector = {
                executor.submit(self._run_detector, detector, text): detector
                for detector in self.detectors
            }

            for future in as_completed(future_to_detector, timeout=DETECTOR_TIMEOUT):
                detector = future_to_detector[future]
                try:
                    spans = future.result()
                    all_spans.extend(spans)
                    if spans:
                        detectors_used.append(detector.name)
                except Exception as e:
                    logger.error(f"Detector {detector.name} failed: {e}")

        # Post-process: deduplicate, filter, sort
        processed_spans = self._post_process(all_spans)

        # Calculate entity counts
        entity_counts: Dict[str, int] = {}
        for span in processed_spans:
            normalized = normalize_entity_type(span.entity_type)
            entity_counts[normalized] = entity_counts.get(normalized, 0) + 1

        processing_time_ms = (time.time() - start_time) * 1000

        return DetectionResult(
            spans=processed_spans,
            entity_counts=entity_counts,
            processing_time_ms=processing_time_ms,
            detectors_used=detectors_used,
            text_length=len(text),
        )

    def _run_detector(self, detector: BaseDetector, text: str) -> List[Span]:
        """Run a single detector with error handling."""
        try:
            if not detector.is_available():
                logger.warning(f"Detector {detector.name} not available")
                return []
            return detector.detect(text)
        except Exception as e:
            logger.error(f"Error in detector {detector.name}: {e}")
            return []

    def _post_process(self, spans: List[Span]) -> List[Span]:
        """
        Post-process detected spans.

        1. Filter by confidence threshold
        2. Deduplicate overlapping spans (higher tier wins)
        3. Sort by position
        """
        if not spans:
            return []

        # Filter by confidence
        filtered = [s for s in spans if s.confidence >= self.confidence_threshold]

        # Deduplicate: for overlapping spans, keep the one with higher tier
        # (or higher confidence if same tier)
        deduped = self._deduplicate(filtered)

        # Sort by start position
        deduped.sort(key=lambda s: (s.start, -s.end))

        return deduped

    def _deduplicate(self, spans: List[Span]) -> List[Span]:
        """
        Remove duplicate/overlapping detections.

        When two spans overlap at the same position:
        - Higher tier wins (CHECKSUM > STRUCTURED > PATTERN > ML)
        - If same tier, higher confidence wins
        """
        if not spans:
            return []

        # Sort by start position, then by tier (descending), then by confidence (descending)
        sorted_spans = sorted(
            spans,
            key=lambda s: (s.start, -s.tier.value, -s.confidence)
        )

        result: List[Span] = []
        for span in sorted_spans:
            # Check if this span overlaps with any already accepted span
            overlaps = False
            for accepted in result:
                if span.overlaps(accepted):
                    # If same position, the first one (higher tier) wins
                    if span.start == accepted.start and span.end == accepted.end:
                        overlaps = True
                        break
                    # If contained within, skip
                    if accepted.contains(span):
                        overlaps = True
                        break

            if not overlaps:
                result.append(span)

        return result

    def add_detector(self, detector: BaseDetector) -> None:
        """Add a custom detector to the orchestrator."""
        self.detectors.append(detector)
        logger.info(f"Added detector: {detector.name}")

    def remove_detector(self, name: str) -> bool:
        """Remove a detector by name."""
        for i, detector in enumerate(self.detectors):
            if detector.name == name:
                self.detectors.pop(i)
                logger.info(f"Removed detector: {name}")
                return True
        return False

    @property
    def detector_names(self) -> List[str]:
        """Get list of active detector names."""
        return [d.name for d in self.detectors]


# Convenience function for simple usage
def detect(text: str, **kwargs) -> DetectionResult:
    """
    Convenience function to detect entities in text.

    Args:
        text: Text to scan
        **kwargs: Options passed to DetectorOrchestrator

    Returns:
        DetectionResult with detected spans
    """
    orchestrator = DetectorOrchestrator(**kwargs)
    return orchestrator.detect(text)

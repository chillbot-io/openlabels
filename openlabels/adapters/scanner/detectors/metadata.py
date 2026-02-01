"""Detection metadata and exception classes.

This module contains:
- DetectionMetadata: Tracks which detectors ran, failed, timed out
- DetectionQueueFullError: Raised when backpressure limits exceeded
- DetectorFailureError: Raised in strict mode when detectors fail

These are separated from orchestrator.py for cleaner imports and testing.
"""

from dataclasses import dataclass, field as dataclass_field
from typing import List


class DetectionQueueFullError(Exception):
    """Raised when detection queue depth exceeds maximum.

    This is a backpressure mechanism to prevent unbounded memory growth
    under high load. Callers should either retry with exponential backoff
    or return a 503 Service Unavailable response.
    """
    def __init__(self, queue_depth: int, max_depth: int):
        self.queue_depth = queue_depth
        self.max_depth = max_depth
        super().__init__(
            f"Detection queue full: {queue_depth} pending requests "
            f"(max: {max_depth}). Try again later."
        )


class DetectorFailureError(Exception):
    """
    Raised when detector(s) fail in strict mode (LOW-004).

    SECURITY FIX (LOW-004): By default, detector failures are logged but don't
    fail the scan (tolerant mode). In strict mode, any detector failure raises
    this exception to ensure complete coverage.

    Use strict mode when:
    - Complete detection coverage is required (compliance scanning)
    - False negatives are more dangerous than performance impact
    - Running in validation/testing mode

    Attributes:
        failed_detectors: List of detector names that failed
        metadata: Full detection metadata for debugging
    """
    def __init__(self, failed_detectors: List[str], metadata: "DetectionMetadata"):
        self.failed_detectors = failed_detectors
        self.metadata = metadata
        super().__init__(
            f"Detector(s) failed in strict mode: {', '.join(failed_detectors)}. "
            f"Detection results may be incomplete."
        )


@dataclass
class DetectionMetadata:
    """
    Metadata about the detection process.

    Tracks:
    - Which detectors succeeded
    - Which detectors failed and why
    - Whether results are degraded
    - Warnings generated during detection

    This enables callers to understand if results may be incomplete.
    """
    detectors_run: List[str] = dataclass_field(default_factory=list)
    detectors_failed: List[str] = dataclass_field(default_factory=list)
    detectors_timed_out: List[str] = dataclass_field(default_factory=list)
    warnings: List[str] = dataclass_field(default_factory=list)
    degraded: bool = False
    all_detectors_failed: bool = False
    structured_extractor_failed: bool = False
    runaway_threads: int = 0

    def add_failure(self, detector_name: str, error: str):
        """Record a detector failure."""
        self.detectors_failed.append(detector_name)
        self.warnings.append(f"Detector {detector_name} failed: {error}")

    def add_timeout(self, detector_name: str, timeout_seconds: float, cancelled: bool):
        """Record a detector timeout."""
        self.detectors_timed_out.append(detector_name)
        status = "cancelled" if cancelled else "still running"
        self.warnings.append(
            f"Detector {detector_name} timed out after {timeout_seconds:.1f}s ({status})"
        )

    def add_success(self, detector_name: str):
        """Record a successful detector run."""
        self.detectors_run.append(detector_name)

    def finalize(self):
        """
        Finalize metadata after all detectors have run.

        Sets all_detectors_failed if no detectors succeeded.
        """
        total_attempted = len(self.detectors_run) + len(self.detectors_failed) + len(self.detectors_timed_out)
        if total_attempted > 0 and len(self.detectors_run) == 0:
            self.all_detectors_failed = True
            self.warnings.append(
                f"All {total_attempted} detectors failed - results unreliable"
            )


# Export all public symbols
__all__ = [
    'DetectionQueueFullError',
    'DetectorFailureError',
    'DetectionMetadata',
]

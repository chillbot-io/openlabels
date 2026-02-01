"""Metrics collection for scanner performance monitoring.

This module provides:
- Timing metrics for detector and pipeline operations
- Entity count tracking by type
- Performance percentile calculation (p50, p95, p99)
- Thread-safe metric collection
- Export to dict/JSON for monitoring systems

Usage:
    from openlabels.adapters.scanner.metrics import MetricsCollector, get_metrics

    # Get the global metrics collector
    metrics = get_metrics()

    # Track detector timing
    with metrics.track_detector("checksum"):
        results = detector.detect(text)

    # Record entity counts
    metrics.record_entities("SSN", 5)

    # Get percentile stats
    stats = metrics.get_stats()
    print(f"p95 detector latency: {stats['detectors']['checksum']['p95_ms']}ms")
"""

import logging
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Generator
import statistics

logger = logging.getLogger(__name__)


@dataclass
class TimingStats:
    """Statistics for a set of timing measurements."""
    count: int = 0
    total_ms: float = 0.0
    min_ms: float = float("inf")
    max_ms: float = 0.0
    samples: List[float] = field(default_factory=list)

    # Maximum samples to keep for percentile calculation
    MAX_SAMPLES: int = 1000

    def record(self, duration_ms: float) -> None:
        """Record a timing measurement."""
        self.count += 1
        self.total_ms += duration_ms
        self.min_ms = min(self.min_ms, duration_ms)
        self.max_ms = max(self.max_ms, duration_ms)

        # Keep samples for percentile calculation (with cap)
        if len(self.samples) < self.MAX_SAMPLES:
            self.samples.append(duration_ms)
        else:
            # Reservoir sampling to maintain representative samples
            import random
            idx = random.randint(0, self.count - 1)
            if idx < self.MAX_SAMPLES:
                self.samples[idx] = duration_ms

    @property
    def avg_ms(self) -> float:
        """Average latency in milliseconds."""
        return self.total_ms / self.count if self.count > 0 else 0.0

    def percentile(self, p: int) -> float:
        """
        Calculate the p-th percentile.

        Args:
            p: Percentile (0-100), e.g., 50 for p50, 95 for p95

        Returns:
            Latency at the p-th percentile, or 0 if no samples
        """
        if not self.samples:
            return 0.0
        sorted_samples = sorted(self.samples)
        idx = int(len(sorted_samples) * p / 100)
        idx = min(idx, len(sorted_samples) - 1)
        return sorted_samples[idx]

    def to_dict(self) -> Dict[str, float]:
        """Export stats to dictionary."""
        return {
            "count": self.count,
            "total_ms": round(self.total_ms, 2),
            "avg_ms": round(self.avg_ms, 3),
            "min_ms": round(self.min_ms, 3) if self.count > 0 else 0,
            "max_ms": round(self.max_ms, 3),
            "p50_ms": round(self.percentile(50), 3),
            "p95_ms": round(self.percentile(95), 3),
            "p99_ms": round(self.percentile(99), 3),
        }

    def reset(self) -> None:
        """Reset all statistics."""
        self.count = 0
        self.total_ms = 0.0
        self.min_ms = float("inf")
        self.max_ms = 0.0
        self.samples.clear()


class MetricsCollector:
    """
    Thread-safe metrics collector for scanner operations.

    Tracks:
    - Detector execution times by name
    - Pipeline stage execution times
    - Entity counts by type
    - File processing stats
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._detector_timings: Dict[str, TimingStats] = defaultdict(TimingStats)
        self._pipeline_timings: Dict[str, TimingStats] = defaultdict(TimingStats)
        self._entity_counts: Dict[str, int] = defaultdict(int)
        self._file_stats = {
            "total_files": 0,
            "total_bytes": 0,
            "files_with_entities": 0,
            "errors": 0,
        }
        self._start_time = time.time()
        self._enabled = True

    def enable(self) -> None:
        """Enable metrics collection."""
        self._enabled = True

    def disable(self) -> None:
        """Disable metrics collection (for performance-critical paths)."""
        self._enabled = False

    @contextmanager
    def track_detector(self, detector_name: str) -> Generator[None, None, None]:
        """
        Context manager to track detector execution time.

        Args:
            detector_name: Name of the detector being timed

        Example:
            with metrics.track_detector("checksum"):
                results = detector.detect(text)
        """
        if not self._enabled:
            yield
            return

        start = time.perf_counter()
        try:
            yield
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            with self._lock:
                self._detector_timings[detector_name].record(duration_ms)

    @contextmanager
    def track_pipeline(self, stage_name: str) -> Generator[None, None, None]:
        """
        Context manager to track pipeline stage execution time.

        Args:
            stage_name: Name of the pipeline stage being timed
        """
        if not self._enabled:
            yield
            return

        start = time.perf_counter()
        try:
            yield
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            with self._lock:
                self._pipeline_timings[stage_name].record(duration_ms)

    def record_entities(self, entity_type: str, count: int = 1) -> None:
        """
        Record detected entity counts.

        Args:
            entity_type: Type of entity detected
            count: Number of entities (default 1)
        """
        if not self._enabled:
            return

        with self._lock:
            self._entity_counts[entity_type] += count

    def record_file(
        self,
        size_bytes: int,
        has_entities: bool,
        is_error: bool = False,
    ) -> None:
        """
        Record file processing statistics.

        Args:
            size_bytes: File size in bytes
            has_entities: Whether entities were found
            is_error: Whether processing encountered an error
        """
        if not self._enabled:
            return

        with self._lock:
            self._file_stats["total_files"] += 1
            self._file_stats["total_bytes"] += size_bytes
            if has_entities:
                self._file_stats["files_with_entities"] += 1
            if is_error:
                self._file_stats["errors"] += 1

    def get_detector_stats(self, detector_name: str) -> Dict[str, float]:
        """Get timing stats for a specific detector."""
        with self._lock:
            if detector_name in self._detector_timings:
                return self._detector_timings[detector_name].to_dict()
            return {}

    def get_stats(self) -> Dict[str, Any]:
        """
        Get complete metrics snapshot.

        Returns:
            Dictionary with all metrics:
            - detectors: Dict of detector timing stats
            - pipeline: Dict of pipeline stage timing stats
            - entities: Dict of entity counts by type
            - files: File processing stats
            - uptime_seconds: Time since collector creation
        """
        with self._lock:
            return {
                "detectors": {
                    name: stats.to_dict()
                    for name, stats in self._detector_timings.items()
                },
                "pipeline": {
                    name: stats.to_dict()
                    for name, stats in self._pipeline_timings.items()
                },
                "entities": dict(self._entity_counts),
                "files": dict(self._file_stats),
                "uptime_seconds": round(time.time() - self._start_time, 1),
            }

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a concise metrics summary.

        Returns:
            Summary with key performance indicators
        """
        stats = self.get_stats()

        # Calculate totals
        total_detections = 0
        total_detector_time = 0.0
        slowest_detector = None
        slowest_time = 0.0

        for name, timing in stats["detectors"].items():
            total_detections += timing["count"]
            total_detector_time += timing["total_ms"]
            if timing["avg_ms"] > slowest_time:
                slowest_time = timing["avg_ms"]
                slowest_detector = name

        total_entities = sum(stats["entities"].values())

        return {
            "total_files": stats["files"]["total_files"],
            "total_entities": total_entities,
            "total_detector_calls": total_detections,
            "total_detector_time_ms": round(total_detector_time, 2),
            "slowest_detector": slowest_detector,
            "slowest_detector_avg_ms": round(slowest_time, 3),
            "files_with_entities": stats["files"]["files_with_entities"],
            "error_count": stats["files"]["errors"],
            "top_entity_types": dict(
                sorted(
                    stats["entities"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10]
            ),
        }

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        with self._lock:
            for timing in self._detector_timings.values():
                timing.reset()
            for timing in self._pipeline_timings.values():
                timing.reset()
            self._entity_counts.clear()
            self._file_stats = {
                "total_files": 0,
                "total_bytes": 0,
                "files_with_entities": 0,
                "errors": 0,
            }
            self._start_time = time.time()


# Global metrics collector instance
_global_metrics: Optional[MetricsCollector] = None
_metrics_lock = threading.Lock()


def get_metrics() -> MetricsCollector:
    """
    Get the global metrics collector.

    Returns:
        Singleton MetricsCollector instance
    """
    global _global_metrics
    if _global_metrics is None:
        with _metrics_lock:
            if _global_metrics is None:
                _global_metrics = MetricsCollector()
    return _global_metrics


def reset_metrics() -> None:
    """Reset the global metrics collector."""
    global _global_metrics
    with _metrics_lock:
        if _global_metrics is not None:
            _global_metrics.reset()


# Convenience functions for common operations
def track_detector(detector_name: str):
    """
    Context manager to track detector timing on the global collector.

    Example:
        with track_detector("checksum"):
            results = detector.detect(text)
    """
    return get_metrics().track_detector(detector_name)


def track_pipeline(stage_name: str):
    """
    Context manager to track pipeline stage timing on the global collector.

    Example:
        with track_pipeline("deduplication"):
            spans = dedupe(spans)
    """
    return get_metrics().track_pipeline(stage_name)


def record_entities(entity_type: str, count: int = 1) -> None:
    """Record entity detection on the global collector."""
    get_metrics().record_entities(entity_type, count)

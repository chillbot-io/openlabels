"""Comprehensive tests for scanner metrics.py.

Tests the MetricsCollector class including:
- Timing metrics for detectors and pipeline stages
- Entity count tracking
- File processing stats
- Percentile calculations
- Thread safety
- Export functionality
"""

import pytest
import threading
import time
from unittest.mock import patch

from openlabels.adapters.scanner.metrics import (
    TimingStats,
    MetricsCollector,
    get_metrics,
    reset_metrics,
    track_detector,
    track_pipeline,
    record_entities,
)


class TestTimingStats:
    """Tests for TimingStats dataclass."""

    def test_initial_state(self):
        """TimingStats should start with zero counts."""
        stats = TimingStats()
        assert stats.count == 0
        assert stats.total_ms == 0.0
        assert stats.min_ms == float("inf")
        assert stats.max_ms == 0.0
        assert stats.samples == []

    def test_record_single_measurement(self):
        """Recording a measurement should update all stats."""
        stats = TimingStats()
        stats.record(10.5)

        assert stats.count == 1
        assert stats.total_ms == 10.5
        assert stats.min_ms == 10.5
        assert stats.max_ms == 10.5
        assert stats.samples == [10.5]

    def test_record_multiple_measurements(self):
        """Recording multiple measurements should track min/max."""
        stats = TimingStats()
        stats.record(10.0)
        stats.record(5.0)
        stats.record(20.0)

        assert stats.count == 3
        assert stats.total_ms == 35.0
        assert stats.min_ms == 5.0
        assert stats.max_ms == 20.0
        assert len(stats.samples) == 3

    def test_avg_ms_calculation(self):
        """Average should be calculated correctly."""
        stats = TimingStats()
        stats.record(10.0)
        stats.record(20.0)
        stats.record(30.0)

        assert stats.avg_ms == 20.0

    def test_avg_ms_empty(self):
        """Average should be 0 for empty stats."""
        stats = TimingStats()
        assert stats.avg_ms == 0.0

    def test_percentile_p50(self):
        """P50 should be the median value."""
        stats = TimingStats()
        for i in range(1, 101):  # 1-100
            stats.record(float(i))

        # P50 should be around 50
        p50 = stats.percentile(50)
        assert 48 <= p50 <= 52

    def test_percentile_p95(self):
        """P95 should be near the high end."""
        stats = TimingStats()
        for i in range(1, 101):
            stats.record(float(i))

        p95 = stats.percentile(95)
        assert 93 <= p95 <= 97

    def test_percentile_p99(self):
        """P99 should be near the maximum."""
        stats = TimingStats()
        for i in range(1, 101):
            stats.record(float(i))

        p99 = stats.percentile(99)
        assert 97 <= p99 <= 100

    def test_percentile_empty(self):
        """Percentile should be 0 for empty stats."""
        stats = TimingStats()
        assert stats.percentile(50) == 0.0
        assert stats.percentile(95) == 0.0

    def test_reservoir_sampling(self):
        """Samples should be capped at MAX_SAMPLES."""
        stats = TimingStats()
        for i in range(2000):
            stats.record(float(i))

        assert stats.count == 2000
        assert len(stats.samples) == TimingStats.MAX_SAMPLES

    def test_to_dict(self):
        """to_dict should export all relevant stats."""
        stats = TimingStats()
        stats.record(10.0)
        stats.record(20.0)
        stats.record(30.0)

        d = stats.to_dict()

        assert d["count"] == 3
        assert d["total_ms"] == 60.0
        assert d["avg_ms"] == 20.0
        assert d["min_ms"] == 10.0
        assert d["max_ms"] == 30.0
        assert "p50_ms" in d
        assert "p95_ms" in d
        assert "p99_ms" in d

    def test_to_dict_empty(self):
        """to_dict should handle empty stats."""
        stats = TimingStats()
        d = stats.to_dict()

        assert d["count"] == 0
        assert d["min_ms"] == 0
        assert d["p50_ms"] == 0.0

    def test_reset(self):
        """Reset should clear all stats."""
        stats = TimingStats()
        stats.record(10.0)
        stats.record(20.0)

        stats.reset()

        assert stats.count == 0
        assert stats.total_ms == 0.0
        assert stats.min_ms == float("inf")
        assert stats.max_ms == 0.0
        assert stats.samples == []


class TestMetricsCollector:
    """Tests for MetricsCollector class."""

    def test_initialization(self):
        """MetricsCollector should initialize properly."""
        collector = MetricsCollector()
        assert collector._enabled is True
        assert len(collector._detector_timings) == 0
        assert len(collector._entity_counts) == 0

    def test_enable_disable(self):
        """Enable/disable should control metrics collection."""
        collector = MetricsCollector()

        collector.disable()
        assert collector._enabled is False

        collector.enable()
        assert collector._enabled is True

    def test_track_detector_timing(self):
        """track_detector should record timing."""
        collector = MetricsCollector()

        with collector.track_detector("test_detector"):
            time.sleep(0.01)  # 10ms

        stats = collector.get_detector_stats("test_detector")
        assert stats["count"] == 1
        assert stats["total_ms"] >= 5  # At least 5ms

    def test_track_detector_disabled(self):
        """track_detector should skip when disabled."""
        collector = MetricsCollector()
        collector.disable()

        with collector.track_detector("test_detector"):
            time.sleep(0.01)

        stats = collector.get_detector_stats("test_detector")
        assert stats == {}

    def test_track_multiple_detectors(self):
        """Multiple detectors should be tracked separately."""
        collector = MetricsCollector()

        with collector.track_detector("detector_a"):
            time.sleep(0.005)

        with collector.track_detector("detector_b"):
            time.sleep(0.010)

        stats = collector.get_stats()
        assert "detector_a" in stats["detectors"]
        assert "detector_b" in stats["detectors"]

    def test_track_pipeline_timing(self):
        """track_pipeline should record pipeline stage timing."""
        collector = MetricsCollector()

        with collector.track_pipeline("deduplication"):
            time.sleep(0.01)

        stats = collector.get_stats()
        assert "deduplication" in stats["pipeline"]
        assert stats["pipeline"]["deduplication"]["count"] == 1

    def test_record_entities(self):
        """record_entities should track entity counts."""
        collector = MetricsCollector()

        collector.record_entities("SSN", 5)
        collector.record_entities("EMAIL", 3)
        collector.record_entities("SSN", 2)

        stats = collector.get_stats()
        assert stats["entities"]["SSN"] == 7
        assert stats["entities"]["EMAIL"] == 3

    def test_record_entities_disabled(self):
        """record_entities should skip when disabled."""
        collector = MetricsCollector()
        collector.disable()

        collector.record_entities("SSN", 5)

        stats = collector.get_stats()
        assert stats["entities"] == {}

    def test_record_file(self):
        """record_file should track file processing stats."""
        collector = MetricsCollector()

        collector.record_file(1024, has_entities=True, is_error=False)
        collector.record_file(2048, has_entities=False, is_error=False)
        collector.record_file(512, has_entities=True, is_error=True)

        stats = collector.get_stats()
        assert stats["files"]["total_files"] == 3
        assert stats["files"]["total_bytes"] == 3584
        assert stats["files"]["files_with_entities"] == 2
        assert stats["files"]["errors"] == 1

    def test_record_file_disabled(self):
        """record_file should skip when disabled."""
        collector = MetricsCollector()
        collector.disable()

        collector.record_file(1024, has_entities=True)

        stats = collector.get_stats()
        assert stats["files"]["total_files"] == 0

    def test_get_stats_complete(self):
        """get_stats should return complete snapshot."""
        collector = MetricsCollector()

        with collector.track_detector("checksum"):
            pass
        collector.record_entities("SSN", 5)
        collector.record_file(1024, has_entities=True)

        stats = collector.get_stats()

        assert "detectors" in stats
        assert "pipeline" in stats
        assert "entities" in stats
        assert "files" in stats
        assert "uptime_seconds" in stats
        assert stats["uptime_seconds"] >= 0

    def test_get_summary(self):
        """get_summary should return concise KPIs."""
        collector = MetricsCollector()

        # Add some data
        with collector.track_detector("checksum"):
            time.sleep(0.005)
        with collector.track_detector("patterns"):
            time.sleep(0.010)

        collector.record_entities("SSN", 5)
        collector.record_entities("EMAIL", 3)
        collector.record_file(1024, has_entities=True)

        summary = collector.get_summary()

        assert summary["total_files"] == 1
        assert summary["total_entities"] == 8
        assert summary["total_detector_calls"] == 2
        assert summary["files_with_entities"] == 1
        assert summary["error_count"] == 0
        assert "slowest_detector" in summary
        assert "top_entity_types" in summary

    def test_reset(self):
        """reset should clear all metrics."""
        collector = MetricsCollector()

        with collector.track_detector("test"):
            pass
        collector.record_entities("SSN", 5)
        collector.record_file(1024, has_entities=True)

        collector.reset()

        stats = collector.get_stats()
        assert stats["entities"] == {}
        assert stats["files"]["total_files"] == 0

    def test_thread_safety_detector_timing(self):
        """Detector timing should be thread-safe."""
        collector = MetricsCollector()
        errors = []

        def track_work(detector_name):
            try:
                for _ in range(100):
                    with collector.track_detector(detector_name):
                        time.sleep(0.0001)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=track_work, args=(f"detector_{i}",))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        stats = collector.get_stats()
        # Each detector should have 100 recordings
        for i in range(5):
            assert stats["detectors"][f"detector_{i}"]["count"] == 100

    def test_thread_safety_entity_counts(self):
        """Entity counting should be thread-safe."""
        collector = MetricsCollector()
        errors = []

        def count_entities():
            try:
                for _ in range(100):
                    collector.record_entities("SSN", 1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=count_entities) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        stats = collector.get_stats()
        assert stats["entities"]["SSN"] == 1000


class TestGlobalMetrics:
    """Tests for global metrics functions."""

    def test_get_metrics_returns_collector(self):
        """get_metrics should return a MetricsCollector."""
        collector = get_metrics()
        assert isinstance(collector, MetricsCollector)

    def test_get_metrics_singleton(self):
        """get_metrics should return same instance."""
        c1 = get_metrics()
        c2 = get_metrics()
        assert c1 is c2

    def test_reset_metrics(self):
        """reset_metrics should clear global collector."""
        collector = get_metrics()
        collector.record_entities("SSN", 5)

        reset_metrics()

        stats = collector.get_stats()
        assert stats["entities"] == {}

    def test_track_detector_global(self):
        """Global track_detector should work."""
        reset_metrics()

        with track_detector("global_test"):
            time.sleep(0.001)

        stats = get_metrics().get_stats()
        assert "global_test" in stats["detectors"]

    def test_track_pipeline_global(self):
        """Global track_pipeline should work."""
        reset_metrics()

        with track_pipeline("global_stage"):
            time.sleep(0.001)

        stats = get_metrics().get_stats()
        assert "global_stage" in stats["pipeline"]

    def test_record_entities_global(self):
        """Global record_entities should work."""
        reset_metrics()

        record_entities("EMAIL", 10)

        stats = get_metrics().get_stats()
        assert stats["entities"]["EMAIL"] == 10


class TestMetricsEdgeCases:
    """Tests for edge cases and error handling."""

    def test_very_small_timing(self):
        """Very small timings should be recorded accurately."""
        stats = TimingStats()
        stats.record(0.001)  # 1 microsecond

        assert stats.count == 1
        assert stats.min_ms == 0.001

    def test_very_large_timing(self):
        """Very large timings should be recorded."""
        stats = TimingStats()
        stats.record(100000.0)  # 100 seconds

        assert stats.count == 1
        assert stats.max_ms == 100000.0

    def test_negative_timing_recorded(self):
        """Negative timings (shouldn't happen) are still recorded."""
        stats = TimingStats()
        stats.record(-1.0)

        # This shouldn't happen in practice but code handles it
        assert stats.count == 1
        assert stats.min_ms == -1.0

    def test_exception_in_context_manager(self):
        """Timing should still be recorded when exception occurs."""
        collector = MetricsCollector()

        with pytest.raises(ValueError):
            with collector.track_detector("test"):
                time.sleep(0.01)
                raise ValueError("intentional error")

        # Timing should still be recorded
        stats = collector.get_detector_stats("test")
        assert stats["count"] == 1

    def test_detector_stats_nonexistent(self):
        """Getting stats for nonexistent detector returns empty dict."""
        collector = MetricsCollector()
        stats = collector.get_detector_stats("nonexistent")
        assert stats == {}

    def test_percentile_boundary_values(self):
        """Percentile should handle boundary values."""
        stats = TimingStats()
        stats.record(100.0)

        assert stats.percentile(0) == 100.0
        assert stats.percentile(100) == 100.0

    def test_to_dict_rounding(self):
        """to_dict should round values appropriately."""
        stats = TimingStats()
        stats.record(10.123456789)

        d = stats.to_dict()
        # avg_ms rounds to 3 decimals
        assert d["avg_ms"] == 10.123
        # total_ms rounds to 2 decimals
        assert d["total_ms"] == 10.12

    def test_summary_no_detectors(self):
        """Summary should handle no detectors gracefully."""
        collector = MetricsCollector()
        summary = collector.get_summary()

        assert summary["total_detector_calls"] == 0
        assert summary["slowest_detector"] is None
        assert summary["slowest_detector_avg_ms"] == 0.0

    def test_summary_top_entity_types_limit(self):
        """Top entity types should be limited to 10."""
        collector = MetricsCollector()

        # Record 15 different entity types
        for i in range(15):
            collector.record_entities(f"TYPE_{i}", i + 1)

        summary = collector.get_summary()
        assert len(summary["top_entity_types"]) <= 10

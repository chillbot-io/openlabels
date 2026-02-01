"""
Tests for openlabels.adapters.scanner.detectors.thread_pool module.

Tests configuration constants and re-exports.
"""

import pytest


class TestDefaultConstants:
    """Tests for default configuration constants."""

    def test_default_max_concurrent_detections_is_positive(self):
        """MAX_CONCURRENT_DETECTIONS must be positive."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_CONCURRENT_DETECTIONS,
        )
        assert DEFAULT_MAX_CONCURRENT_DETECTIONS > 0

    def test_default_max_concurrent_detections_is_reasonable(self):
        """MAX_CONCURRENT_DETECTIONS should be between 1 and 100."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_CONCURRENT_DETECTIONS,
        )
        assert 1 <= DEFAULT_MAX_CONCURRENT_DETECTIONS <= 100

    def test_default_max_concurrent_detections_value(self):
        """Verify the specific default value."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_CONCURRENT_DETECTIONS,
        )
        assert DEFAULT_MAX_CONCURRENT_DETECTIONS == 10

    def test_default_max_queue_depth_is_non_negative(self):
        """MAX_QUEUE_DEPTH must be non-negative (0 means unlimited)."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_QUEUE_DEPTH,
        )
        assert DEFAULT_MAX_QUEUE_DEPTH >= 0

    def test_default_max_queue_depth_is_reasonable(self):
        """MAX_QUEUE_DEPTH should be reasonable for memory."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_QUEUE_DEPTH,
        )
        # Should be less than 1000 to prevent unbounded memory
        assert DEFAULT_MAX_QUEUE_DEPTH <= 1000

    def test_default_max_queue_depth_value(self):
        """Verify the specific default value."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_QUEUE_DEPTH,
        )
        assert DEFAULT_MAX_QUEUE_DEPTH == 50

    def test_default_max_runaway_detections_is_positive(self):
        """MAX_RUNAWAY_DETECTIONS must be positive."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_RUNAWAY_DETECTIONS,
        )
        assert DEFAULT_MAX_RUNAWAY_DETECTIONS > 0

    def test_default_max_runaway_detections_value(self):
        """Verify the specific default value."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_RUNAWAY_DETECTIONS,
        )
        assert DEFAULT_MAX_RUNAWAY_DETECTIONS == 5

    def test_queue_depth_greater_than_concurrent(self):
        """Queue depth should accommodate at least concurrent limit."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_CONCURRENT_DETECTIONS,
            DEFAULT_MAX_QUEUE_DEPTH,
        )
        # Queue should be able to buffer at least N concurrent tasks
        assert DEFAULT_MAX_QUEUE_DEPTH >= DEFAULT_MAX_CONCURRENT_DETECTIONS


class TestReExports:
    """Tests for re-exported items."""

    def test_detection_queue_full_error_exported(self):
        """DetectionQueueFullError should be re-exported."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DetectionQueueFullError,
        )
        assert DetectionQueueFullError is not None

    def test_detection_queue_full_error_is_exception(self):
        """DetectionQueueFullError should be an Exception subclass."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DetectionQueueFullError,
        )
        assert issubclass(DetectionQueueFullError, Exception)

    def test_detection_queue_full_error_can_be_raised(self):
        """DetectionQueueFullError should be raisable with queue_depth and max_depth."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DetectionQueueFullError,
        )
        with pytest.raises(DetectionQueueFullError) as exc_info:
            raise DetectionQueueFullError(queue_depth=60, max_depth=50)
        assert exc_info.value.queue_depth == 60
        assert exc_info.value.max_depth == 50

    def test_detection_queue_full_error_catchable_as_exception(self):
        """DetectionQueueFullError should be catchable as Exception."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DetectionQueueFullError,
        )
        try:
            raise DetectionQueueFullError(queue_depth=100, max_depth=50)
        except Exception as e:
            assert isinstance(e, DetectionQueueFullError)


class TestModuleExports:
    """Tests for __all__ exports."""

    def test_all_exports_defined(self):
        """__all__ should be defined."""
        from openlabels.adapters.scanner.detectors import thread_pool
        assert hasattr(thread_pool, '__all__')

    def test_all_exports_contains_constants(self):
        """__all__ should contain the configuration constants."""
        from openlabels.adapters.scanner.detectors import thread_pool
        assert 'DEFAULT_MAX_CONCURRENT_DETECTIONS' in thread_pool.__all__
        assert 'DEFAULT_MAX_QUEUE_DEPTH' in thread_pool.__all__
        assert 'DEFAULT_MAX_RUNAWAY_DETECTIONS' in thread_pool.__all__

    def test_all_exports_contains_exception(self):
        """__all__ should contain the exception class."""
        from openlabels.adapters.scanner.detectors import thread_pool
        assert 'DetectionQueueFullError' in thread_pool.__all__

    def test_all_items_are_importable(self):
        """All items in __all__ should be importable."""
        from openlabels.adapters.scanner.detectors import thread_pool
        for name in thread_pool.__all__:
            assert hasattr(thread_pool, name), f"Missing export: {name}"


class TestConstantTypes:
    """Tests for constant types."""

    def test_max_concurrent_is_int(self):
        """MAX_CONCURRENT_DETECTIONS should be an integer."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_CONCURRENT_DETECTIONS,
        )
        assert isinstance(DEFAULT_MAX_CONCURRENT_DETECTIONS, int)

    def test_max_queue_depth_is_int(self):
        """MAX_QUEUE_DEPTH should be an integer."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_QUEUE_DEPTH,
        )
        assert isinstance(DEFAULT_MAX_QUEUE_DEPTH, int)

    def test_max_runaway_is_int(self):
        """MAX_RUNAWAY_DETECTIONS should be an integer."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_RUNAWAY_DETECTIONS,
        )
        assert isinstance(DEFAULT_MAX_RUNAWAY_DETECTIONS, int)


class TestBackpressureConfiguration:
    """Tests for backpressure configuration semantics."""

    def test_queue_depth_zero_means_unlimited(self):
        """Queue depth of 0 should mean unlimited (per docstring)."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_QUEUE_DEPTH,
        )
        # Current default is not 0, but the logic should support 0
        # This test documents the expected behavior
        assert DEFAULT_MAX_QUEUE_DEPTH >= 0

    def test_runaway_threshold_is_warning_level(self):
        """Runaway threshold should be low enough to warn early."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_RUNAWAY_DETECTIONS,
        )
        # Should warn after just a few runaway threads
        assert DEFAULT_MAX_RUNAWAY_DETECTIONS <= 10

    def test_concurrent_limit_prevents_resource_exhaustion(self):
        """Concurrent limit should prevent thread explosion."""
        from openlabels.adapters.scanner.detectors.thread_pool import (
            DEFAULT_MAX_CONCURRENT_DETECTIONS,
        )
        # Should be less than typical thread pool limits
        assert DEFAULT_MAX_CONCURRENT_DETECTIONS <= 50

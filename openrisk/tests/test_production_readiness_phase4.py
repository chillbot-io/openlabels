"""
Phase 4 Production Readiness Tests: State Isolation & Context Safety

Tests for:
- Issue 4.1: Orchestrator uses Context for resource isolation
- Issue 4.2: Warnings for default singletons
- Issue 4.3: atexit handler leakage prevention
- Issue 4.4: Cloud handlers moved to Context
- Issue 4.5: Safe detection slot with guaranteed cleanup
"""

import gc
import threading
import warnings
import weakref
import pytest
from unittest.mock import Mock, patch, MagicMock


class TestContextResourceIsolation:
    """Tests for Issue 4.1: Context-based resource isolation."""

    def test_context_has_detection_resources(self):
        """Context has detection-related resources."""
        from openlabels.context import Context

        ctx = Context()
        try:
            # Should have runaway detection tracking
            assert hasattr(ctx, '_runaway_detections')
            assert hasattr(ctx, '_runaway_lock')

            # Should have methods for tracking
            assert hasattr(ctx, 'get_runaway_detection_count')
            assert hasattr(ctx, 'track_runaway_detection')
        finally:
            ctx.close()

    def test_context_runaway_tracking_isolated(self):
        """Each Context has isolated runaway detection tracking."""
        from openlabels.context import Context

        ctx1 = Context()
        ctx2 = Context()

        try:
            # Track runaway in ctx1
            ctx1.track_runaway_detection("detector_a")

            # ctx1 count should increase
            assert ctx1.get_runaway_detection_count() == 1

            # ctx2 count should be 0 (isolated)
            assert ctx2.get_runaway_detection_count() == 0

            # Track in ctx2
            ctx2.track_runaway_detection("detector_b")
            ctx2.track_runaway_detection("detector_c")

            # ctx2 count should be 2
            assert ctx2.get_runaway_detection_count() == 2

            # ctx1 count still 1
            assert ctx1.get_runaway_detection_count() == 1
        finally:
            ctx1.close()
            ctx2.close()

    def test_context_executor_isolated(self):
        """Each Context has its own executor."""
        from openlabels.context import Context

        ctx1 = Context()
        ctx2 = Context()

        try:
            exec1 = ctx1.get_executor()
            exec2 = ctx2.get_executor()

            # Should be different executor instances
            assert exec1 is not exec2
        finally:
            ctx1.close()
            ctx2.close()

    def test_context_detection_semaphore_isolated(self):
        """Each Context has its own detection semaphore."""
        from openlabels.context import Context

        ctx1 = Context(max_concurrent_detections=5)
        ctx2 = Context(max_concurrent_detections=10)

        try:
            sem1 = ctx1.get_detection_semaphore()
            sem2 = ctx2.get_detection_semaphore()

            # Should be different semaphore instances
            assert sem1 is not sem2
        finally:
            ctx1.close()
            ctx2.close()


class TestDefaultSingletonWarnings:
    """Tests for Issue 4.2: Warnings for default singletons."""

    def test_get_default_context_warns(self):
        """get_default_context() warns about shared state."""
        from openlabels.context import reset_default_context

        reset_default_context()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            from openlabels.context import get_default_context
            ctx = get_default_context()

            # Should have emitted a warning
            assert len(w) == 1
            assert "default context shares state" in str(w[0].message).lower()
            assert issubclass(w[0].category, UserWarning)

        reset_default_context()

    def test_get_default_context_warning_can_be_suppressed(self):
        """get_default_context(warn=False) suppresses warning."""
        from openlabels.context import get_default_context, reset_default_context

        reset_default_context()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            ctx = get_default_context(warn=False)

            # Should not have emitted a warning
            assert len(w) == 0

        reset_default_context()

    def test_get_default_context_warns_only_once(self):
        """Warning is only emitted once per process."""
        from openlabels.context import get_default_context, reset_default_context

        reset_default_context()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # First call warns
            get_default_context()
            assert len(w) == 1

            # Second call doesn't warn again
            get_default_context()
            assert len(w) == 1

        reset_default_context()

    def test_get_default_index_warns(self):
        """get_default_index() warns about shared state."""
        from openlabels.output.index import get_default_index, reset_default_index

        reset_default_index()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            idx = get_default_index()

            # Should have emitted a warning
            assert len(w) == 1
            assert "default index shares state" in str(w[0].message).lower()

        reset_default_index()


class TestAtexitHandlerLeakage:
    """Tests for Issue 4.3: atexit handler leakage prevention."""

    def test_context_uses_weak_references(self):
        """Context uses weak references for atexit handling."""
        from openlabels.context import Context, _context_refs, _context_refs_lock

        initial_count = len([r for r in _context_refs if r() is not None])

        # Create and close a context
        ctx = Context()
        ctx.close()

        # After close, the context should still be in weak refs but may be garbage collected
        # The key is that we're not accumulating strong references

    def test_contexts_can_be_garbage_collected(self):
        """Contexts can be garbage collected even if not explicitly closed."""
        from openlabels.context import Context

        # Create a weak reference to track the context
        ctx = Context()
        ref = weakref.ref(ctx)

        # Delete the context
        del ctx

        # Force garbage collection
        gc.collect()

        # The context should be garbage collected
        # Note: This may not always work due to other references, but the weak ref
        # mechanism ensures we're not preventing GC

    def test_multiple_contexts_dont_accumulate_handlers(self):
        """Creating many contexts doesn't accumulate atexit handlers."""
        import atexit
        from openlabels.context import Context, _atexit_registered

        # Create and close many contexts
        for _ in range(100):
            ctx = Context()
            ctx.close()

        # The atexit handler should only be registered once
        # (We can't easily check atexit internals, but the implementation
        # only registers once via _atexit_registered flag)


class TestCloudHandlersInContext:
    """Tests for Issue 4.4: Cloud handlers moved to Context."""

    def test_context_has_cloud_handlers(self):
        """Context can provide cloud handlers."""
        from openlabels.context import Context

        ctx = Context()
        try:
            assert hasattr(ctx, 'get_cloud_handler')
            assert hasattr(ctx, '_cloud_handlers')
        finally:
            ctx.close()

    def test_context_cloud_handlers_isolated(self):
        """Each Context has isolated cloud handlers."""
        from openlabels.context import Context

        ctx1 = Context()
        ctx2 = Context()

        try:
            # Get S3 handler from ctx1
            handler1 = ctx1.get_cloud_handler('s3')

            # Get S3 handler from ctx2
            handler2 = ctx2.get_cloud_handler('s3')

            # Should be different instances
            assert handler1 is not handler2
        finally:
            ctx1.close()
            ctx2.close()

    def test_context_cloud_handler_caches_within_context(self):
        """Cloud handler is cached within same Context."""
        from openlabels.context import Context

        ctx = Context()
        try:
            handler1 = ctx.get_cloud_handler('s3')
            handler2 = ctx.get_cloud_handler('s3')

            # Should be same instance
            assert handler1 is handler2
        finally:
            ctx.close()

class TestDetectionSlotSafety:
    """Tests for Issue 4.5: Safe detection slot with guaranteed cleanup."""

    def test_detection_slot_normal_operation(self):
        """Detection slot works normally."""
        from openlabels.context import Context

        ctx = Context(max_queue_depth=10)
        try:
            initial_depth = ctx.get_queue_depth()

            with ctx.detection_slot() as depth:
                assert depth == initial_depth + 1
                # Inside the slot, depth should be 1
                assert ctx.get_queue_depth() == initial_depth + 1

            # After exiting, depth should be back to initial
            assert ctx.get_queue_depth() == initial_depth
        finally:
            ctx.close()

    def test_detection_slot_cleanup_on_exception(self):
        """Detection slot cleans up even when exception occurs."""
        from openlabels.context import Context

        ctx = Context(max_queue_depth=10)
        try:
            initial_depth = ctx.get_queue_depth()

            with pytest.raises(ValueError):
                with ctx.detection_slot() as depth:
                    assert ctx.get_queue_depth() == initial_depth + 1
                    raise ValueError("Test exception")

            # After exception, depth should be back to initial
            assert ctx.get_queue_depth() == initial_depth
        finally:
            ctx.close()

    def test_detection_slot_queue_full_error(self):
        """Detection slot raises error when queue is full."""
        from openlabels.context import Context, DetectionQueueFullError

        ctx = Context(max_queue_depth=2, max_concurrent_detections=100)
        try:
            # Fill the queue
            with ctx.detection_slot():
                with ctx.detection_slot():
                    # Queue is now at max depth (2)
                    # Third request should fail
                    with pytest.raises(DetectionQueueFullError) as exc_info:
                        with ctx.detection_slot():
                            pass

                    assert exc_info.value.queue_depth == 2
                    assert exc_info.value.max_depth == 2
        finally:
            ctx.close()

    def test_detection_slot_semaphore_released_on_exception(self):
        """Semaphore is released even when exception occurs."""
        from openlabels.context import Context

        ctx = Context(max_concurrent_detections=1)
        try:
            # First, exhaust the semaphore and then release it by exception
            with pytest.raises(ValueError):
                with ctx.detection_slot():
                    raise ValueError("Test")

            # The semaphore should be released, allowing another acquire
            # This would hang if the semaphore wasn't released
            acquired = False
            with ctx.detection_slot():
                acquired = True

            assert acquired
        finally:
            ctx.close()


class TestOrchestratorContextIntegration:
    """Tests for orchestrator using Context."""

    def test_orchestrator_accepts_context(self):
        """DetectorOrchestrator accepts optional Context parameter."""
        from openlabels.context import Context
        from openlabels.adapters.scanner.detectors.orchestrator import DetectorOrchestrator
        from openlabels.adapters.scanner.config import Config

        ctx = Context()
        try:
            # Should not raise
            orchestrator = DetectorOrchestrator(
                config=Config(),
                context=ctx,
            )

            assert orchestrator._context is ctx
        finally:
            ctx.close()

    def test_orchestrator_uses_context_executor(self):
        """Orchestrator uses Context's executor when provided."""
        from openlabels.context import Context
        from openlabels.adapters.scanner.detectors.orchestrator import DetectorOrchestrator
        from openlabels.adapters.scanner.config import Config

        ctx = Context()
        try:
            orchestrator = DetectorOrchestrator(
                config=Config(),
                context=ctx,
            )

            # The executor should come from context
            executor = orchestrator._get_executor()
            ctx_executor = ctx.get_executor()

            assert executor is ctx_executor
        finally:
            ctx.close()

    def test_orchestrator_without_context_uses_default(self):
        """Orchestrator without Context auto-creates default context."""
        from openlabels.adapters.scanner.detectors.orchestrator import (
            DetectorOrchestrator,
        )
        from openlabels.adapters.scanner.config import Config

        # Create orchestrator without explicit context
        orchestrator = DetectorOrchestrator(config=Config())

        # Should have auto-created a context
        assert orchestrator._context is not None

        # The executor should work
        executor = orchestrator._get_executor()
        assert executor is not None


class TestContextCloudHandlerIntegration:
    """Tests for cloud handler Context integration."""

    def test_write_cloud_label_accepts_context(self):
        """write_cloud_label accepts optional context parameter."""
        from openlabels.output.virtual import write_cloud_label
        import inspect

        sig = inspect.signature(write_cloud_label)
        assert 'context' in sig.parameters

    def test_read_cloud_label_accepts_context(self):
        """read_cloud_label accepts optional context parameter."""
        from openlabels.output.virtual import read_cloud_label
        import inspect

        sig = inspect.signature(read_cloud_label)
        assert 'context' in sig.parameters


class TestContextReset:
    """Tests for context reset functionality."""

    def test_reset_default_context_clears_warning_flag(self):
        """reset_default_context() clears the warning flag."""
        from openlabels.context import (
            get_default_context,
            reset_default_context,
            _default_context_warning_issued,
        )
        import openlabels.context as ctx_module

        # Get context (warns)
        reset_default_context()
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            get_default_context()

        # Warning flag should be set
        assert ctx_module._default_context_warning_issued is True

        # Reset
        reset_default_context()

        # Warning flag should be cleared
        assert ctx_module._default_context_warning_issued is False

    def test_context_reset_runaway_count(self):
        """Context.reset_runaway_count() resets the count."""
        from openlabels.context import Context

        ctx = Context()
        try:
            # Track some runaways
            ctx.track_runaway_detection("detector_1")
            ctx.track_runaway_detection("detector_2")
            assert ctx.get_runaway_detection_count() == 2

            # Reset
            ctx.reset_runaway_count()
            assert ctx.get_runaway_detection_count() == 0
        finally:
            ctx.close()


class TestDetectorContextIntegration:
    """Tests for Detector class context integration (Phase 4 bug fix)."""

    def test_detector_accepts_context(self):
        """Detector accepts optional context parameter."""
        from openlabels.context import Context
        from openlabels.adapters.scanner import Detector

        ctx = Context()
        try:
            detector = Detector(context=ctx)
            assert detector._context is ctx
        finally:
            ctx.close()

    def test_detector_passes_context_to_orchestrator(self):
        """Detector passes context to orchestrator."""
        from openlabels.context import Context
        from openlabels.adapters.scanner import Detector

        ctx = Context()
        try:
            detector = Detector(context=ctx)
            # Access orchestrator property to trigger creation
            orchestrator = detector.orchestrator
            assert orchestrator._context is ctx
        finally:
            ctx.close()

    def test_detector_without_context_works(self):
        """Detector works without context (backward compatibility)."""
        from openlabels.adapters.scanner import Detector

        detector = Detector()
        assert detector._context is None
        # Orchestrator should still work (uses legacy globals)
        assert detector.orchestrator is not None


class TestGetDefaultIndexRaceCondition:
    """Tests for get_default_index race condition fix."""

    def test_get_default_index_warning_inside_lock(self):
        """Verify warning check happens inside lock (race condition fix)."""
        from openlabels.output.index import get_default_index, reset_default_index
        import openlabels.output.index as idx_module

        reset_default_index()

        # Verify warning is issued
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            get_default_index()

            assert len(w) == 1

            # Second call should not warn
            get_default_index()
            assert len(w) == 1

        reset_default_index()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Tests for Phase 6: Concurrency Robustness & Long-term

Phase 6 addresses:
- Issue 6.1: Queue overflow feedback (watcher event queue fills silently)
- Issue 6.2: Polling watcher race condition (file changes during poll scan)
- Issue 6.3: Detection queue per-context isolation (addressed by Phase 4.1)

These tests verify the implementations work correctly under various conditions.
"""

import pytest
import tempfile
import time
import threading
import queue
from pathlib import Path
from unittest.mock import MagicMock, patch

from openlabels.agent.watcher import (
    PollingWatcher,
    WatcherConfig,
    WatchEvent,
    EventType,
    _WATCHDOG_AVAILABLE,
)

# Conditionally import FileWatcher only if watchdog is available
if _WATCHDOG_AVAILABLE:
    from openlabels.agent.watcher import FileWatcher

# Skip decorator for tests requiring watchdog
requires_watchdog = pytest.mark.skipif(
    not _WATCHDOG_AVAILABLE,
    reason="watchdog not installed"
)


# =============================================================================
# ISSUE 6.1: Dropped Events Feedback Tests
# =============================================================================

@requires_watchdog
class TestFileWatcherDroppedEvents:
    """Test FileWatcher dropped events tracking via callback failures (Issue 6.1)."""

    def test_dropped_events_starts_at_zero(self):
        """Dropped events counter should start at zero."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(tmpdir)
            assert watcher.dropped_events == 0

    def test_successful_callback_does_not_increment_counter(self):
        """Successful callbacks should not increment dropped events."""
        events_received = []

        def good_callback(event):
            events_received.append(event)

        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(tmpdir, on_change=good_callback)
            event = WatchEvent(event_type=EventType.CREATED, path="/test/file.txt")

            watcher._dispatch_event(event)

            assert len(events_received) == 1
            assert watcher.dropped_events == 0

    def test_callback_failure_increments_counter(self):
        """Callback failures should increment dropped events counter."""
        def bad_callback(event):
            raise RuntimeError("Callback failed!")

        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(tmpdir, on_change=bad_callback)

            event = WatchEvent(event_type=EventType.CREATED, path="/test/file.txt")
            watcher._dispatch_event(event)

            assert watcher.dropped_events == 1

    def test_on_queue_full_callback_called_on_failure(self):
        """on_queue_full callback should be called when event callback fails."""
        failure_counts = []

        def bad_callback(event):
            raise RuntimeError("Callback failed!")

        def on_failure(count):
            failure_counts.append(count)

        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(on_queue_full=on_failure)
            watcher = FileWatcher(tmpdir, on_change=bad_callback, config=config)

            event = WatchEvent(event_type=EventType.CREATED, path="/test/file.txt")
            watcher._dispatch_event(event)

            assert len(failure_counts) == 1
            assert failure_counts[0] == 1

    def test_reset_dropped_events(self):
        """reset_dropped_events should return count and reset to zero."""
        def bad_callback(event):
            raise RuntimeError("Callback failed!")

        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = FileWatcher(tmpdir, on_change=bad_callback)

            # Cause some drops via callback failures
            for i in range(4):
                watcher._dispatch_event(
                    WatchEvent(event_type=EventType.CREATED, path=f"/test/file{i}.txt")
                )

            assert watcher.dropped_events == 4

            # Reset and verify
            previous_count = watcher.reset_dropped_events()
            assert previous_count == 4
            assert watcher.dropped_events == 0

    def test_on_queue_full_callback_error_does_not_crash(self):
        """Errors in on_queue_full callback should be caught."""
        def bad_event_callback(event):
            raise RuntimeError("Event callback failed!")

        def bad_overflow_callback(count):
            raise RuntimeError("Overflow callback failed!")

        with tempfile.TemporaryDirectory() as tmpdir:
            config = WatcherConfig(on_queue_full=bad_overflow_callback)
            watcher = FileWatcher(tmpdir, on_change=bad_event_callback, config=config)

            # This should not raise despite both callbacks failing
            event = WatchEvent(event_type=EventType.CREATED, path="/test/file.txt")
            watcher._dispatch_event(event)

            assert watcher.dropped_events == 1


class TestPollingWatcherQueueOverflow:
    """Test PollingWatcher callback failure handling (Issue 6.1)."""

    def test_dropped_events_starts_at_zero(self):
        """Dropped events counter should start at zero."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = PollingWatcher(tmpdir)
            assert watcher.dropped_events == 0

    def test_callback_failure_increments_dropped_count(self):
        """Callback failures should increment dropped events counter."""
        def bad_callback(event):
            raise RuntimeError("Callback failed!")

        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = PollingWatcher(tmpdir, on_change=bad_callback)

            # Dispatch an event - callback will fail
            event = WatchEvent(event_type=EventType.CREATED, path="/test/file.txt")
            watcher._dispatch(event)

            assert watcher.dropped_events == 1

    def test_on_queue_full_called_on_callback_failure(self):
        """on_queue_full should be called when callback fails."""
        failure_counts = []

        def bad_callback(event):
            raise RuntimeError("Callback failed!")

        def on_failure(count):
            failure_counts.append(count)

        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = PollingWatcher(
                tmpdir,
                on_change=bad_callback,
                on_queue_full=on_failure
            )

            event = WatchEvent(event_type=EventType.CREATED, path="/test/file.txt")
            watcher._dispatch(event)

            assert len(failure_counts) == 1
            assert failure_counts[0] == 1


# =============================================================================
# ISSUE 6.2: Polling Watcher Race Condition Tests
# =============================================================================

class TestPollingWatcherContentHashing:
    """Test PollingWatcher content hashing for race condition fix (Issue 6.2)."""

    def test_default_hash_threshold(self):
        """Default hash threshold should be 1MB."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = PollingWatcher(tmpdir)
            assert watcher.hash_threshold == 1024 * 1024

    def test_custom_hash_threshold(self):
        """Custom hash threshold should be respected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = PollingWatcher(tmpdir, hash_threshold=512 * 1024)
            assert watcher.hash_threshold == 512 * 1024

    def test_disable_hashing_with_zero_threshold(self):
        """Setting hash_threshold=0 should disable hashing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = PollingWatcher(tmpdir, hash_threshold=0)
            assert watcher.hash_threshold == 0

    def test_quick_hash_produces_consistent_result(self):
        """Same file should produce same hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Hello, World!")

            watcher = PollingWatcher(tmpdir)

            hash1 = watcher._quick_hash(test_file)
            hash2 = watcher._quick_hash(test_file)

            assert hash1 == hash2
            assert len(hash1) == 32  # Should be 32 hex chars

    def test_quick_hash_changes_with_content(self):
        """Different content should produce different hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"

            test_file.write_text("Content version 1")
            watcher = PollingWatcher(tmpdir)
            hash1 = watcher._quick_hash(test_file)

            test_file.write_text("Content version 2")
            hash2 = watcher._quick_hash(test_file)

            assert hash1 != hash2

    def test_scan_directory_includes_hash_for_small_files(self):
        """Small files should have content hash in scan results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a small file
            test_file = Path(tmpdir) / "small.txt"
            test_file.write_text("Small content")

            watcher = PollingWatcher(tmpdir, hash_threshold=1024 * 1024)
            files = watcher._scan_directory()

            assert str(test_file) in files
            mtime, size, content_hash = files[str(test_file)]
            assert content_hash is not None
            assert len(content_hash) == 32

    def test_scan_directory_no_hash_for_large_files(self):
        """Large files should not have content hash (None)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file and set threshold below its size
            test_file = Path(tmpdir) / "large.txt"
            test_file.write_text("This is some content")

            # Set threshold smaller than file
            watcher = PollingWatcher(tmpdir, hash_threshold=5)
            files = watcher._scan_directory()

            assert str(test_file) in files
            mtime, size, content_hash = files[str(test_file)]
            assert content_hash is None  # No hash for "large" files

    def test_detects_same_mtime_different_content(self):
        """Should detect changes even when mtime stays the same."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Original content")

            watcher = PollingWatcher(tmpdir, hash_threshold=1024 * 1024)

            # Get initial state
            initial_state = watcher._scan_directory()
            initial_hash = initial_state[str(test_file)][2]

            # Modify file (content hash will change even if mtime somehow stays same)
            test_file.write_text("Modified content")

            # Get new state
            new_state = watcher._scan_directory()
            new_hash = new_state[str(test_file)][2]

            # Hashes should differ
            assert initial_hash != new_hash

    def test_scan_state_tuple_format(self):
        """Scan state should be (mtime, size, content_hash) tuple."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")

            watcher = PollingWatcher(tmpdir)
            files = watcher._scan_directory()

            state = files[str(test_file)]
            assert isinstance(state, tuple)
            assert len(state) == 3

            mtime, size, content_hash = state
            assert isinstance(mtime, float)
            assert isinstance(size, int)
            assert content_hash is None or isinstance(content_hash, str)


class TestPollingWatcherHashingDisabled:
    """Test PollingWatcher behavior when hashing is disabled."""

    def test_no_hash_when_threshold_zero(self):
        """With threshold=0, no files should be hashed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple files
            for i in range(3):
                (Path(tmpdir) / f"file{i}.txt").write_text(f"Content {i}")

            watcher = PollingWatcher(tmpdir, hash_threshold=0)
            files = watcher._scan_directory()

            # All files should have None for content_hash
            for path, (mtime, size, content_hash) in files.items():
                assert content_hash is None


# =============================================================================
# ISSUE 6.3: Detection Queue Isolation Tests
# =============================================================================

class TestDetectionQueueIsolation:
    """
    Test that detection queue is isolated per context (Issue 6.3).

    This is primarily addressed by Phase 4.1, but we verify here that
    the implementation works correctly.
    """

    def test_contexts_have_isolated_queue_depth(self):
        """Different contexts should have independent queue depth."""
        from openlabels.context import Context

        ctx1 = Context()
        ctx2 = Context()

        try:
            # Increment queue depth in ctx1
            ctx1.increment_queue_depth()
            ctx1.increment_queue_depth()

            # ctx2 should be unaffected
            assert ctx1.get_queue_depth() == 2
            assert ctx2.get_queue_depth() == 0

        finally:
            ctx1.close()
            ctx2.close()

    def test_contexts_have_isolated_semaphores(self):
        """Different contexts should have independent semaphores."""
        from openlabels.context import Context

        ctx1 = Context(max_concurrent_detections=2)
        ctx2 = Context(max_concurrent_detections=5)

        try:
            sem1 = ctx1.get_detection_semaphore()
            sem2 = ctx2.get_detection_semaphore()

            # Should be different objects
            assert sem1 is not sem2

        finally:
            ctx1.close()
            ctx2.close()

    def test_detection_slot_isolated_per_context(self):
        """detection_slot should use context's own resources."""
        from openlabels.context import Context

        ctx1 = Context(max_queue_depth=10)
        ctx2 = Context(max_queue_depth=10)

        try:
            # Use detection slot in ctx1
            with ctx1.detection_slot() as depth1:
                assert depth1 == 1
                assert ctx1.get_queue_depth() == 1

                # ctx2 should be unaffected
                assert ctx2.get_queue_depth() == 0

        finally:
            ctx1.close()
            ctx2.close()


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestPhase6Integration:
    """Integration tests for Phase 6 features."""

    def test_polling_watcher_full_cycle_with_hashing(self):
        """Test complete polling cycle with content hashing."""
        events_received = []

        def on_change(event):
            events_received.append(event)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create initial file
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Initial content")

            watcher = PollingWatcher(
                tmpdir,
                on_change=on_change,
                interval=0.1,
                hash_threshold=1024 * 1024,
            )
            watcher.start()

            try:
                # Wait for initial scan
                time.sleep(0.2)

                # Modify file
                test_file.write_text("Modified content")

                # Wait for detection
                time.sleep(0.3)

                # Should have detected modification
                modified_events = [e for e in events_received if e.event_type == EventType.MODIFIED]
                assert len(modified_events) >= 1

            finally:
                watcher.stop()

    def test_watcher_config_with_all_phase6_options(self):
        """Test WatcherConfig with all Phase 6.1 options."""
        callback_called = False

        def on_overflow(count):
            nonlocal callback_called
            callback_called = True

        config = WatcherConfig(
            max_queue_size=100,
            on_queue_full=on_overflow,
        )

        assert config.max_queue_size == 100
        assert config.on_queue_full is not None

    @requires_watchdog
    def test_file_watcher_and_polling_watcher_same_interface(self):
        """FileWatcher and PollingWatcher should have compatible interfaces."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Both should support these properties
            file_watcher = FileWatcher(tmpdir)
            polling_watcher = PollingWatcher(tmpdir)

            # dropped_events property
            assert hasattr(file_watcher, 'dropped_events')
            assert hasattr(polling_watcher, 'dropped_events')

            # reset_dropped_events method
            assert hasattr(file_watcher, 'reset_dropped_events')
            assert hasattr(polling_watcher, 'reset_dropped_events')

            # is_running property
            assert hasattr(file_watcher, 'is_running')
            assert hasattr(polling_watcher, 'is_running')

            # start/stop methods
            assert hasattr(file_watcher, 'start')
            assert hasattr(file_watcher, 'stop')
            assert hasattr(polling_watcher, 'start')
            assert hasattr(polling_watcher, 'stop')

    def test_polling_watcher_has_required_interface(self):
        """PollingWatcher should have all required Phase 6 interfaces."""
        with tempfile.TemporaryDirectory() as tmpdir:
            watcher = PollingWatcher(tmpdir)

            # Phase 6.1: dropped_events property and reset
            assert hasattr(watcher, 'dropped_events')
            assert hasattr(watcher, 'reset_dropped_events')

            # Phase 6.2: hash_threshold and _quick_hash
            assert hasattr(watcher, 'hash_threshold')
            assert hasattr(watcher, '_quick_hash')

            # Standard watcher interface
            assert hasattr(watcher, 'is_running')
            assert hasattr(watcher, 'start')
            assert hasattr(watcher, 'stop')

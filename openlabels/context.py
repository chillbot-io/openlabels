"""
OpenLabels Context.

Thread-safe context for dependency injection. Holds shared resources
like handlers, indices, and thread pools that would otherwise be globals.

SECURITY NOTE (LOW-008): Default Context Singleton Leakage

    The default context (accessed via get_default_context() or implicitly via
    Client()) is a PROCESS-WIDE SINGLETON. This can cause:

    1. STATE LEAKAGE BETWEEN TESTS: Test A modifies context state, Test B sees
       those changes. Use reset_default_context() in test teardown or create
       explicit Context instances per test.

    2. MULTI-TENANT ISOLATION ISSUES: In a multi-tenant application, different
       tenants may see each other's cached data if using the default context.
       Create explicit Context instances per tenant/request.

    3. THREAD POOL SHARING: Detection thread pools are shared across all users
       of the default context. One slow caller can impact others.

    When to use DEFAULT context:
    - Simple scripts and CLI tools
    - Single-tenant applications
    - Quick prototyping

    When to use EXPLICIT contexts:
    - Unit tests (one Context per test, or reset_default_context() in teardown)
    - Multi-tenant applications (one Context per tenant/request)
    - Long-running services (to control resource lifecycle)
    - When isolation between components is required

Usage:
    >>> from openlabels import Context, Client
    >>>
    >>> # Default context (created automatically) - SHARES STATE!
    >>> client = Client()
    >>>
    >>> # Explicit context (for testing or isolation) - ISOLATED
    >>> ctx = Context()
    >>> client = Client(context=ctx)
    >>>
    >>> # Multiple isolated clients
    >>> ctx1 = Context()
    >>> ctx2 = Context()
    >>> client1 = Client(context=ctx1)
    >>> client2 = Client(context=ctx2)
    >>>
    >>> # Test isolation pattern
    >>> def test_something():
    ...     ctx = Context()  # Fresh context per test
    ...     try:
    ...         client = Client(context=ctx)
    ...         # ... test code ...
    ...     finally:
    ...         ctx.close()
"""

import atexit
import logging
import threading
import warnings
import weakref
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional, Any, List, Callable

from .adapters.scanner.constants import MAX_DETECTOR_WORKERS
from .adapters.base import normalize_exposure_level

logger = logging.getLogger(__name__)

_EXECUTOR_SHUTDOWN_TIMEOUT = 5.0  # Timeout for executor shutdown


def _get_shutdown_coordinator():
    """Lazy import to avoid circular dependency."""
    from .shutdown import get_shutdown_coordinator
    return get_shutdown_coordinator()


# Weak references for cleanup at exit (prevents memory leaks)
_context_refs: List[weakref.ref] = []
_context_refs_lock = threading.Lock()
_atexit_registered = False


def _cleanup_all_contexts():
    """
    atexit handler that cleans up all live contexts.

    Uses weak references so contexts can be garbage collected normally.
    Only contexts that are still alive at process exit get cleaned up.
    """
    with _context_refs_lock:
        for ref in _context_refs:
            ctx = ref()
            if ctx is not None:
                try:
                    ctx.close()
                except Exception as e:
                    # Don't let cleanup errors propagate during exit
                    logger.debug(f"Error during context cleanup: {e}")
        _context_refs.clear()


def _register_context(ctx: "Context") -> None:
    """Register a context for cleanup at exit and signal handling."""
    global _atexit_registered

    with _context_refs_lock:
        # Register atexit handler once (not per context)
        if not _atexit_registered:
            atexit.register(_cleanup_all_contexts)
            # Also register with shutdown coordinator for signal handling
            try:
                coordinator = _get_shutdown_coordinator()
                coordinator.register(
                    _cleanup_all_contexts,
                    name="context_cleanup",
                    priority=10,  # Run early in shutdown
                )
            except Exception as e:
                logger.warning(
                    f"Could not register with shutdown coordinator: {e}. "
                    "Graceful shutdown may not work correctly."
                )
            _atexit_registered = True

        # Add weak reference to this context
        _context_refs.append(weakref.ref(ctx))

        # Periodically clean up dead references to prevent unbounded growth
        if len(_context_refs) > 100:
            _context_refs[:] = [ref for ref in _context_refs if ref() is not None]


class DetectionQueueFullError(Exception):
    """
    Raised when detection queue depth exceeds maximum.

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


@dataclass
class Context:
    """
    Thread-safe context holding shared resources.

    Each Context instance is isolated - no global state is shared.
    This enables:
    - Thread safety (each thread can have its own context)
    - Testing (inject mock resources)
    - Isolation (multiple clients don't interfere)

    Resources are created lazily on first access.
    """

    default_exposure: str = "PRIVATE"
    max_detector_workers: int = MAX_DETECTOR_WORKERS
    max_concurrent_detections: int = 10
    max_queue_depth: int = 50
    max_runaway_detections: int = 5

    # Internal state (created lazily)
    _executor: Optional[ThreadPoolExecutor] = field(default=None, repr=False)
    _executor_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _label_index: Optional[Any] = field(default=None, repr=False)
    _index_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _virtual_handlers: dict = field(default_factory=dict, repr=False)
    _handlers_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # Backpressure tracking
    _detection_semaphore: Optional[threading.BoundedSemaphore] = field(default=None, repr=False)
    _queue_depth: int = field(default=0, repr=False)
    _queue_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # Runaway detection tracking
    _runaway_detections: int = field(default=0, repr=False)
    _runaway_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # Cloud handlers
    _cloud_handlers: dict = field(default_factory=dict, repr=False)
    _cloud_handlers_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    _shutdown: bool = field(default=False, repr=False)

    def __post_init__(self):
        """Initialize context with validation and cleanup registration."""
        self.default_exposure = normalize_exposure_level(self.default_exposure)
        _register_context(self)  # Weak ref cleanup (not atexit directly - leaks)

    def get_executor(self) -> ThreadPoolExecutor:
        """Get or create the thread pool executor."""
        if self._shutdown:
            raise RuntimeError("Context has been closed")

        with self._executor_lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self.max_detector_workers,
                    thread_name_prefix="detector_"
                )
            return self._executor

    def get_detection_semaphore(self) -> threading.BoundedSemaphore:
        """Get or create the detection backpressure semaphore."""
        with self._queue_lock:
            if self._detection_semaphore is None:
                self._detection_semaphore = threading.BoundedSemaphore(
                    self.max_concurrent_detections
                )
            return self._detection_semaphore

    def get_queue_depth(self) -> int:
        """Get current detection queue depth."""
        with self._queue_lock:
            return self._queue_depth

    def increment_queue_depth(self) -> int:
        """Increment queue depth, returns new depth."""
        with self._queue_lock:
            self._queue_depth += 1
            return self._queue_depth

    def decrement_queue_depth(self) -> None:
        """Decrement queue depth."""
        with self._queue_lock:
            self._queue_depth = max(0, self._queue_depth - 1)

    @contextmanager
    def detection_slot(self):
        """
        Context manager for detection backpressure with guaranteed cleanup.

        This is a safer implementation than the original that ensures:
        1. Queue depth is always decremented, even on exceptions
        2. Semaphore is always released if acquired
        3. The "acquired" flag prevents double-release bugs

        Raises:
            DetectionQueueFullError: If queue depth exceeds max_queue_depth

        Yields:
            Current queue depth

        Example:
            >>> with context.detection_slot() as depth:
            ...     print(f"Queue depth: {depth}")
            ...     # Do detection work
        """
        # Check queue depth and increment
        with self._queue_lock:
            if self.max_queue_depth > 0 and self._queue_depth >= self.max_queue_depth:
                raise DetectionQueueFullError(self._queue_depth, self.max_queue_depth)
            self._queue_depth += 1
            current_depth = self._queue_depth

        acquired = False
        try:
            self.get_detection_semaphore().acquire()
            acquired = True
            yield current_depth
        finally:
            if acquired:
                self.get_detection_semaphore().release()
            with self._queue_lock:
                self._queue_depth = max(0, self._queue_depth - 1)

    def get_runaway_detection_count(self) -> int:
        """
        Get count of runaway detections for this context.

        Runaway detections are threads that timed out but could not be
        cancelled. They continue running in the background, consuming
        resources.
        """
        with self._runaway_lock:
            return self._runaway_detections

    def track_runaway_detection(self, detector_name: str) -> int:
        """
        Track a runaway detection thread.

        Called when a detector times out and cannot be cancelled.

        Args:
            detector_name: Name of the detector that timed out

        Returns:
            Current runaway detection count
        """
        with self._runaway_lock:
            self._runaway_detections += 1
            count = self._runaway_detections

        if count == 1:
            logger.warning(
                f"Detector {detector_name} timed out and could not be cancelled. "
                "Thread still running in background."
            )
        elif count % 5 == 0 or count >= self.max_runaway_detections:
            logger.warning(
                f"Runaway detection count: {count}. "
                f"Detector {detector_name} is the latest."
            )

        if count >= self.max_runaway_detections:
            logger.critical(
                f"CRITICAL: {count} runaway detections (max: {self.max_runaway_detections}). "
                "System may be under adversarial input attack or has a detector bug. "
                "Consider restarting the process to reclaim resources."
            )

        return count

    def reset_runaway_count(self) -> None:
        """Reset runaway detection count (mainly for testing)."""
        with self._runaway_lock:
            self._runaway_detections = 0

    def get_cloud_handler(self, provider: str):
        """
        Get or create a cloud metadata handler.

        Args:
            provider: Cloud provider ('s3', 'gcs', or 'azure')

        Returns:
            Cloud metadata handler instance
        """
        with self._cloud_handlers_lock:
            if provider not in self._cloud_handlers:
                from .output.virtual import (
                    S3MetadataHandler,
                    GCSMetadataHandler,
                    AzureBlobMetadataHandler,
                )

                handler_map = {
                    's3': S3MetadataHandler,
                    'gcs': GCSMetadataHandler,
                    'azure': AzureBlobMetadataHandler,
                }

                handler_class = handler_map.get(provider)
                if handler_class:
                    self._cloud_handlers[provider] = handler_class()

            return self._cloud_handlers.get(provider)

    def get_label_index(self):
        """Get or create the default label index."""
        with self._index_lock:
            if self._label_index is None:
                from .output.index import LabelIndex
                self._label_index = LabelIndex()
            return self._label_index

    def set_label_index(self, index) -> None:
        """Set a custom label index (for testing)."""
        with self._index_lock:
            self._label_index = index

    def get_virtual_handler(self, handler_type: str):
        """Get or create a virtual label handler by type."""
        with self._handlers_lock:
            if handler_type not in self._virtual_handlers:
                from .output.virtual import (
                    LinuxXattrHandler,
                    MacOSXattrHandler,
                    WindowsADSHandler,
                )
                import platform

                handler_map = {
                    "linux": LinuxXattrHandler,
                    "macos": MacOSXattrHandler,
                    "windows": WindowsADSHandler,
                }

                if handler_type == "auto":
                    system = platform.system().lower()
                    if system == "darwin":
                        handler_type = "macos"
                    elif system == "windows":
                        handler_type = "windows"
                    else:
                        handler_type = "linux"

                handler_class = handler_map.get(handler_type)
                if handler_class:
                    self._virtual_handlers[handler_type] = handler_class()

            return self._virtual_handlers.get(handler_type)

    def close(self) -> None:
        """Release all resources with timeout-enforced executor shutdown."""
        if self._shutdown:
            return

        self._shutdown = True

        with self._executor_lock:
            if self._executor is not None:
                executor = self._executor
                self._executor = None  # Clear early to prevent double-shutdown

                logger.debug(
                    f"Shutting down context executor (timeout: {_EXECUTOR_SHUTDOWN_TIMEOUT}s)..."
                )
                shutdown_complete = threading.Event()

                def do_shutdown():
                    try:
                        executor.shutdown(wait=True, cancel_futures=False)
                        shutdown_complete.set()
                    except Exception as e:
                        logger.warning(f"Error during context executor shutdown: {e}")

                shutdown_thread = threading.Thread(target=do_shutdown, daemon=True)
                shutdown_thread.start()

                # Wait for graceful shutdown with timeout
                if shutdown_complete.wait(timeout=_EXECUTOR_SHUTDOWN_TIMEOUT):
                    logger.debug("Context executor shutdown complete")
                else:
                    # Timeout - force shutdown
                    logger.warning(
                        f"Context executor shutdown timed out after "
                        f"{_EXECUTOR_SHUTDOWN_TIMEOUT}s, forcing cancellation"
                    )
                    try:
                        executor.shutdown(wait=False, cancel_futures=True)
                    except Exception as e:
                        logger.debug(f"Error during forced executor shutdown: {e}")

        with self._index_lock:
            if self._label_index is not None:
                # Close index if it has a close method
                if hasattr(self._label_index, 'close'):
                    self._label_index.close()
                self._label_index = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False



# --- Default Context Singleton ---


# Default context for simple usage
_default_context: Optional[Context] = None
_default_context_lock = threading.Lock()
_default_context_warning_issued = False


def get_default_context(warn: bool = True) -> Context:
    """
    Get the default shared context.

    WARNING: Default context shares state across all callers .
    For isolated operation, create explicit Context instances.

    Args:
        warn: If True, emit a warning about shared state (default True).
              Set to False to suppress warning (e.g., in internal code).

    Returns:
        The default shared Context instance

    Example:
        >>> # For quick prototyping (warns about shared state):
        >>> ctx = get_default_context()
        >>>
        >>> # For production - create isolated contexts:
        >>> ctx = Context()
    """
    global _default_context, _default_context_warning_issued

    with _default_context_lock:
        if warn and not _default_context_warning_issued:
            warnings.warn(
                "Using default context shares state across all callers. "
                "For isolated operation, create explicit Context instances. "
                "Suppress this warning with get_default_context(warn=False).",
                UserWarning,
                stacklevel=2,
            )
            _default_context_warning_issued = True

        if _default_context is None:
            _default_context = Context()
        return _default_context


def reset_default_context() -> None:
    """Reset the default context (mainly for testing)."""
    global _default_context, _default_context_warning_issued
    with _default_context_lock:
        if _default_context is not None:
            _default_context.close()
            _default_context = None
        _default_context_warning_issued = False

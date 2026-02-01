"""Thread pool and concurrency configuration for detector orchestration.

This module contains configuration constants for thread pool and backpressure
management. All mutable state is now managed via Context instances.

SECURITY NOTE (LOW-005): Thread Timeout Limitations
    Python threads cannot be forcibly killed - only cancelled gracefully via
    Future.cancel(). When a detector times out:

    1. If the thread hasn't started yet, it can be cancelled (good)
    2. If the thread is running, cancel() has NO EFFECT (problematic)

    Runaway threads (those that can't be cancelled) will continue executing
    in the background, consuming CPU and memory. This is a fundamental Python
    limitation, not a bug in this code.

    Mitigations:
    - Context tracks runaway thread count via get_runaway_detection_count()
    - Critical warnings are logged when runaway count exceeds threshold
    - Use detect_with_metadata() to check metadata.detectors_timed_out
    - For true isolation, consider process-based parallelism (multiprocessing)
    - Monitor and restart long-running processes if runaway count grows

Resource Management:
    All thread pool and backpressure state is managed via Context instances.
    DetectorOrchestrator automatically uses the default context if none is provided.

    For isolated operation:
        >>> from openlabels import Context
        >>> ctx = Context(max_concurrent_detections=20, max_queue_depth=100)
        >>> detector = Detector(context=ctx)

    For testing:
        >>> ctx = Context()  # Fresh context per test
        >>> try:
        ...     detector = Detector(context=ctx)
        ...     # ... test code ...
        ... finally:
        ...     ctx.close()
"""

import logging

logger = logging.getLogger(__name__)


# Default configuration values
# These are used as defaults in Context if not specified

# Maximum concurrent detection requests (backpressure)
# If exceeded, new requests will block until a slot is available
DEFAULT_MAX_CONCURRENT_DETECTIONS = 10

# Maximum queue depth before rejecting requests (prevents unbounded memory growth)
# Set to 0 to disable queue depth limit (block indefinitely)
DEFAULT_MAX_QUEUE_DEPTH = 50

# Maximum runaway detections before logging critical warning
# Runaway detections are threads that timed out but couldn't be cancelled
DEFAULT_MAX_RUNAWAY_DETECTIONS = 5


# Re-export DetectionQueueFullError for backward compatibility
from .metadata import DetectionQueueFullError


__all__ = [
    # Configuration defaults
    'DEFAULT_MAX_CONCURRENT_DETECTIONS',
    'DEFAULT_MAX_QUEUE_DEPTH',
    'DEFAULT_MAX_RUNAWAY_DETECTIONS',
    # Exception
    'DetectionQueueFullError',
]

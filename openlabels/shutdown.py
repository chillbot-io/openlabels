"""
OpenLabels Graceful Shutdown.

Provides signal handling and cleanup coordination for graceful shutdown.

This module enables proper cleanup when:
- User presses Ctrl+C (SIGINT)
- Process receives SIGTERM (container stop, systemd stop)
- Process is terminating normally

Usage:
    from openlabels.shutdown import ShutdownCoordinator, get_shutdown_coordinator

    # Get the global coordinator
    coordinator = get_shutdown_coordinator()

    # Register a cleanup callback
    def my_cleanup():
        print("Cleaning up...")

    coordinator.register(my_cleanup, name="my_component")

    # Check if shutdown is in progress (in long-running loops)
    while coordinator.is_running():
        do_work()

    # Or use the context manager for auto-registration
    with coordinator.managed_resource(my_object, "my_resource"):
        # my_object.close() will be called on shutdown
        pass
"""

import atexit
import logging
import signal
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Optional, List, Any

logger = logging.getLogger(__name__)


@dataclass
class ShutdownCallback:
    """A registered shutdown callback."""
    callback: Callable[[], None]
    name: str
    priority: int = 0  # Higher priority runs first


class ShutdownCoordinator:
    """
    Coordinates graceful shutdown across components.

    Handles:
    - SIGINT (Ctrl+C)
    - SIGTERM (docker stop, kill, etc.)
    - Normal atexit cleanup

    Thread-safe for registering callbacks from multiple threads.
    """

    def __init__(self, timeout: float = 10.0):
        """
        Initialize shutdown coordinator.

        Args:
            timeout: Maximum time (seconds) to wait for cleanup callbacks
        """
        self._callbacks: List[ShutdownCallback] = []
        self._lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._shutdown_in_progress = False
        self._signals_installed = False
        self._timeout = timeout
        self._original_handlers = {}

    def install_signal_handlers(self) -> None:
        """
        Install signal handlers for SIGINT and SIGTERM.

        Safe to call multiple times - only installs once.
        """
        if self._signals_installed:
            return

        # Only install in main thread
        if threading.current_thread() is not threading.main_thread():
            logger.debug("Cannot install signal handlers from non-main thread")
            return

        try:
            # Save original handlers for restoration
            self._original_handlers[signal.SIGINT] = signal.signal(
                signal.SIGINT, self._signal_handler
            )
            self._original_handlers[signal.SIGTERM] = signal.signal(
                signal.SIGTERM, self._signal_handler
            )
            self._signals_installed = True
            logger.debug("Signal handlers installed for graceful shutdown")
        except (ValueError, OSError) as e:
            # May fail in some environments (e.g., threads, Windows services)
            logger.debug(f"Could not install signal handlers: {e}")

    def uninstall_signal_handlers(self) -> None:
        """Restore original signal handlers."""
        if not self._signals_installed:
            return

        try:
            for sig, handler in self._original_handlers.items():
                signal.signal(sig, handler)
            self._signals_installed = False
            self._original_handlers.clear()
        except (ValueError, OSError) as e:
            logger.debug(f"Could not restore signal handlers: {e}")

    def _signal_handler(self, signum: int, frame) -> None:
        """Handle shutdown signals."""
        sig_name = signal.Signals(signum).name
        logger.debug(f"Received {sig_name}, initiating graceful shutdown...")

        # Set shutdown event for any waiting threads
        self._shutdown_event.set()

        # Perform shutdown
        self.shutdown(reason=f"signal:{sig_name}")

        # For SIGINT, raise KeyboardInterrupt to properly unwind stack
        if signum == signal.SIGINT:
            raise KeyboardInterrupt()

    def register(
        self,
        callback: Callable[[], None],
        name: str = "",
        priority: int = 0,
    ) -> None:
        """
        Register a cleanup callback.

        Args:
            callback: Function to call during shutdown (no arguments)
            name: Human-readable name for logging
            priority: Higher values run first (default: 0)
        """
        with self._lock:
            self._callbacks.append(ShutdownCallback(
                callback=callback,
                name=name or f"callback_{len(self._callbacks)}",
                priority=priority,
            ))

    def unregister(self, callback: Callable[[], None]) -> bool:
        """
        Unregister a cleanup callback.

        Returns:
            True if callback was found and removed
        """
        with self._lock:
            for i, cb in enumerate(self._callbacks):
                if cb.callback is callback:
                    self._callbacks.pop(i)
                    return True
            return False

    def is_running(self) -> bool:
        """
        Check if the system is still running (not shutting down).

        Use this in long-running loops to enable graceful interruption:

            while coordinator.is_running():
                process_next_item()
        """
        return not self._shutdown_event.is_set()

    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress."""
        return self._shutdown_event.is_set()

    def wait_for_shutdown(self, timeout: Optional[float] = None) -> bool:
        """
        Block until shutdown signal is received.

        Args:
            timeout: Maximum time to wait (None = forever)

        Returns:
            True if shutdown was signaled, False if timeout expired
        """
        return self._shutdown_event.wait(timeout=timeout)

    def request_shutdown(self) -> None:
        """
        Request a graceful shutdown.

        Sets the shutdown event but doesn't run callbacks yet.
        Useful for signaling worker threads to stop.
        """
        self._shutdown_event.set()

    def shutdown(self, reason: str = "requested") -> None:
        """
        Perform graceful shutdown - run all cleanup callbacks.

        Args:
            reason: Reason for shutdown (for logging)
        """
        with self._lock:
            if self._shutdown_in_progress:
                return
            self._shutdown_in_progress = True

        logger.debug(f"Starting graceful shutdown (reason: {reason})")
        self._shutdown_event.set()

        # Sort by priority (higher first)
        with self._lock:
            callbacks = sorted(
                self._callbacks.copy(),
                key=lambda c: c.priority,
                reverse=True
            )

        # Run callbacks with timeout
        start = time.monotonic()
        for cb in callbacks:
            remaining = self._timeout - (time.monotonic() - start)
            if remaining <= 0:
                logger.warning(
                    f"Shutdown timeout expired, skipping remaining callbacks"
                )
                break

            try:
                logger.debug(f"Running shutdown callback: {cb.name}")
                cb.callback()
            except Exception as e:
                logger.warning(f"Error in shutdown callback {cb.name}: {e}")

        elapsed = time.monotonic() - start
        logger.debug(f"Graceful shutdown complete ({elapsed:.2f}s)")

    @contextmanager
    def managed_resource(self, resource: Any, name: str = ""):
        """
        Context manager that ensures resource cleanup on shutdown.

        The resource must have a close() method.

        Usage:
            with coordinator.managed_resource(connection, "database"):
                # Use connection
                pass
            # connection.close() called automatically
        """
        def cleanup():
            if hasattr(resource, 'close'):
                resource.close()

        self.register(cleanup, name=name or str(type(resource).__name__))
        try:
            yield resource
        finally:
            self.unregister(cleanup)
            # Still close if we're exiting the context normally
            if not self._shutdown_in_progress:
                cleanup()



# --- Global Coordinator ---


_coordinator: Optional[ShutdownCoordinator] = None
_coordinator_lock = threading.Lock()


def get_shutdown_coordinator() -> ShutdownCoordinator:
    """
    Get the global shutdown coordinator.

    Creates one if it doesn't exist.
    """
    global _coordinator
    with _coordinator_lock:
        if _coordinator is None:
            _coordinator = ShutdownCoordinator()
            # Register with atexit as backup
            atexit.register(_coordinator.shutdown, reason="atexit")
        return _coordinator


def install_signal_handlers() -> None:
    """
    Install signal handlers for graceful shutdown.

    Call this early in main() to enable Ctrl+C handling.
    """
    coordinator = get_shutdown_coordinator()
    coordinator.install_signal_handlers()


def register_shutdown_callback(
    callback: Callable[[], None],
    name: str = "",
    priority: int = 0,
) -> None:
    """
    Register a cleanup callback with the global coordinator.

    Convenience function for simple use cases.
    """
    coordinator = get_shutdown_coordinator()
    coordinator.register(callback, name=name, priority=priority)


def is_shutting_down() -> bool:
    """Check if shutdown is in progress."""
    global _coordinator
    if _coordinator is None:
        return False
    return _coordinator.is_shutting_down()

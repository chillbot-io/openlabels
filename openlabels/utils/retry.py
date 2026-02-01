"""
Retry utilities with exponential backoff and circuit breaker.

GA-FIX (1.4): Provides resilience for transient network failures in cloud operations.

Usage:
    @with_retry(max_retries=3)
    def fetch_from_api():
        return requests.get(url)

    breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)
    @breaker
    def call_external_service():
        return api.fetch()
"""

import logging
import threading
import time
from functools import wraps
from typing import Callable, Optional, Tuple, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')

# Default retry configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0  # seconds
DEFAULT_MAX_DELAY = 30.0  # seconds
DEFAULT_EXPONENTIAL_BASE = 2

# Transient exceptions that should trigger retry
TRANSIENT_EXCEPTIONS: Tuple[Type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,  # Network-related OS errors
)


def _get_aws_transient_exceptions() -> Tuple[Type[Exception], ...]:
    """Get AWS-specific transient exceptions if boto3 is available."""
    try:
        from botocore.exceptions import (
            ConnectionError as BotoConnectionError,
            ReadTimeoutError,
            ConnectTimeoutError,
            EndpointConnectionError,
        )
        return (BotoConnectionError, ReadTimeoutError, ConnectTimeoutError, EndpointConnectionError)
    except ImportError:
        return ()


def _get_gcp_transient_exceptions() -> Tuple[Type[Exception], ...]:
    """Get GCP-specific transient exceptions if google-cloud is available."""
    try:
        from google.api_core.exceptions import (
            ServiceUnavailable,
            DeadlineExceeded,
            Aborted,
        )
        return (ServiceUnavailable, DeadlineExceeded, Aborted)
    except ImportError:
        return ()


def _get_azure_transient_exceptions() -> Tuple[Type[Exception], ...]:
    """Get Azure-specific transient exceptions if azure SDK is available."""
    try:
        from azure.core.exceptions import (
            ServiceRequestError,
            ServiceResponseError,
        )
        return (ServiceRequestError, ServiceResponseError)
    except ImportError:
        return ()


def get_cloud_transient_exceptions() -> Tuple[Type[Exception], ...]:
    """
    Get all transient exceptions for cloud operations.

    Combines base transient exceptions with cloud-specific ones.
    """
    return (
        TRANSIENT_EXCEPTIONS +
        _get_aws_transient_exceptions() +
        _get_gcp_transient_exceptions() +
        _get_azure_transient_exceptions()
    )


def with_retry(
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    exponential_base: float = DEFAULT_EXPONENTIAL_BASE,
    retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    on_retry: Optional[Callable[[Exception, int], None]] = None,
):
    """
    Decorator for retrying functions with exponential backoff.

    GA-FIX (1.4): Provides automatic retry for transient failures.

    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        base_delay: Initial delay between retries in seconds (default: 1.0)
        max_delay: Maximum delay between retries (default: 30.0)
        exponential_base: Base for exponential backoff calculation (default: 2)
        retryable_exceptions: Exception types that trigger retry.
            If None, uses get_cloud_transient_exceptions().
        on_retry: Optional callback called on each retry with (exception, attempt)

    Returns:
        Decorated function with retry capability

    Example:
        @with_retry(max_retries=3)
        def fetch_from_api():
            return requests.get(url)

        @with_retry(max_retries=5, base_delay=0.5, retryable_exceptions=(TimeoutError,))
        def slow_operation():
            return long_running_call()
    """
    if retryable_exceptions is None:
        retryable_exceptions = get_cloud_transient_exceptions()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception: Optional[Exception] = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = min(
                            base_delay * (exponential_base ** attempt),
                            max_delay
                        )
                        logger.warning(
                            f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        if on_retry:
                            on_retry(e, attempt)
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_retries + 1} attempts: {e}"
                        )

            # Should not reach here, but satisfy type checker
            if last_exception is not None:
                raise last_exception
            raise RuntimeError("Retry loop completed without success or exception")

        return wrapper
    return decorator


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and rejecting requests."""

    def __init__(self, message: str, recovery_time: Optional[float] = None):
        super().__init__(message)
        self.recovery_time = recovery_time


class CircuitBreaker:
    """
    Circuit breaker for protecting against cascading failures.

    GA-FIX (1.4): Prevents overwhelming failing services with retries.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Service failing, requests rejected immediately
    - HALF_OPEN: Testing if service has recovered

    Example:
        breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)

        @breaker
        def call_external_service():
            return api.fetch()

        # Or use as context manager:
        with breaker:
            result = api.fetch()
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        expected_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
        name: Optional[str] = None,
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before testing if service recovered
            expected_exceptions: Exception types that count as failures.
                If None, uses get_cloud_transient_exceptions().
            name: Optional name for logging
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exceptions = expected_exceptions or get_cloud_transient_exceptions()
        self.name = name or "circuit_breaker"

        self._state = self.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        """Get current circuit breaker state, checking for recovery timeout."""
        with self._lock:
            if self._state == self.OPEN:
                # Check if recovery timeout has passed
                if time.time() - self._last_failure_time >= self.recovery_timeout:
                    logger.info(f"{self.name}: Circuit half-open, testing recovery")
                    self._state = self.HALF_OPEN
            return self._state

    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        with self._lock:
            return self._failure_count

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Use as decorator."""
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            return self._execute(lambda: func(*args, **kwargs))
        return wrapper

    def __enter__(self):
        """Use as context manager."""
        if self.state == self.OPEN:
            time_until_recovery = self.recovery_timeout - (time.time() - self._last_failure_time)
            raise CircuitBreakerOpenError(
                f"{self.name}: Circuit breaker is open. "
                f"Retry after {max(0, time_until_recovery):.1f}s.",
                recovery_time=max(0, time_until_recovery),
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Handle exception from context manager."""
        if exc_type is None:
            self._on_success()
        elif exc_type and issubclass(exc_type, self.expected_exceptions):
            self._on_failure()
        return False  # Don't suppress exceptions

    def _execute(self, func: Callable[[], T]) -> T:
        """Execute function with circuit breaker protection."""
        current_state = self.state

        if current_state == self.OPEN:
            time_until_recovery = self.recovery_timeout - (time.time() - self._last_failure_time)
            raise CircuitBreakerOpenError(
                f"{self.name}: Circuit breaker is open. "
                f"Retry after {max(0, time_until_recovery):.1f}s.",
                recovery_time=max(0, time_until_recovery),
            )

        try:
            result = func()
            self._on_success()
            return result
        except self.expected_exceptions:
            self._on_failure()
            raise

    def _on_success(self):
        """Handle successful call."""
        with self._lock:
            if self._state == self.HALF_OPEN:
                logger.info(f"{self.name}: Service recovered, circuit closed")
            self._failure_count = 0
            self._state = self.CLOSED

    def _on_failure(self):
        """Handle failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._failure_count >= self.failure_threshold:
                if self._state != self.OPEN:
                    logger.warning(
                        f"{self.name}: Circuit opened after {self._failure_count} failures. "
                        f"Requests will be rejected for {self.recovery_timeout}s."
                    )
                self._state = self.OPEN
            elif self._state == self.HALF_OPEN:
                # Failed during recovery test
                logger.warning(f"{self.name}: Recovery test failed, circuit re-opened")
                self._state = self.OPEN

    def reset(self):
        """Manually reset the circuit breaker to closed state."""
        with self._lock:
            self._state = self.CLOSED
            self._failure_count = 0
            logger.info(f"{self.name}: Circuit breaker manually reset")


def with_resilience(
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    failure_threshold: int = 5,
    recovery_timeout: float = 30.0,
    retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    circuit_breaker: Optional[CircuitBreaker] = None,
):
    """
    Decorator combining retry with circuit breaker for full resilience.

    GA-FIX (1.4): Comprehensive resilience pattern for cloud operations.

    The decorator applies:
    1. Circuit breaker check (fast-fail if service is down)
    2. Retry with exponential backoff
    3. Circuit breaker tracking for failures

    Args:
        max_retries: Maximum retry attempts
        base_delay: Initial delay between retries
        failure_threshold: Failures before opening circuit
        recovery_timeout: Seconds before testing recovery
        retryable_exceptions: Exception types for retry/circuit breaker
        circuit_breaker: Optional existing CircuitBreaker instance.
            If None, creates a new one per decorated function.

    Example:
        @with_resilience(max_retries=3, failure_threshold=5)
        def call_cloud_api():
            return boto3.client('s3').list_buckets()
    """
    if retryable_exceptions is None:
        retryable_exceptions = get_cloud_transient_exceptions()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        # Create circuit breaker for this function if not provided
        breaker = circuit_breaker or CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            expected_exceptions=retryable_exceptions,
            name=f"cb_{func.__name__}",
        )

        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # Check circuit breaker first
            if breaker.state == CircuitBreaker.OPEN:
                time_until_recovery = breaker.recovery_timeout - (time.time() - breaker._last_failure_time)
                raise CircuitBreakerOpenError(
                    f"Circuit breaker open for {func.__name__}. "
                    f"Retry after {max(0, time_until_recovery):.1f}s.",
                    recovery_time=max(0, time_until_recovery),
                )

            last_exception: Optional[Exception] = None

            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    breaker._on_success()
                    return result
                except retryable_exceptions as e:
                    last_exception = e
                    breaker._on_failure()

                    # Check if circuit breaker opened
                    if breaker.state == CircuitBreaker.OPEN:
                        logger.error(
                            f"{func.__name__}: Circuit breaker opened during retries"
                        )
                        raise

                    if attempt < max_retries:
                        delay = min(
                            base_delay * (DEFAULT_EXPONENTIAL_BASE ** attempt),
                            DEFAULT_MAX_DELAY
                        )
                        logger.warning(
                            f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_retries + 1} attempts: {e}"
                        )

            if last_exception is not None:
                raise last_exception
            raise RuntimeError("Retry loop completed without success or exception")

        # Expose circuit breaker for testing/monitoring
        wrapper.circuit_breaker = breaker  # type: ignore
        return wrapper

    return decorator


__all__ = [
    # Configuration
    'DEFAULT_MAX_RETRIES',
    'DEFAULT_BASE_DELAY',
    'DEFAULT_MAX_DELAY',
    'DEFAULT_EXPONENTIAL_BASE',
    'TRANSIENT_EXCEPTIONS',
    # Exception helpers
    'get_cloud_transient_exceptions',
    # Retry decorator
    'with_retry',
    # Circuit breaker
    'CircuitBreaker',
    'CircuitBreakerOpenError',
    # Combined
    'with_resilience',
]

"""
Circuit breaker implementation for external service resilience.

The circuit breaker pattern prevents cascading failures when external
services are unavailable by:
1. Monitoring failures and successes
2. "Opening" the circuit after threshold failures
3. Allowing test requests after recovery timeout
4. "Closing" the circuit after successful test requests

Usage:
    from openlabels.core.circuit_breaker import CircuitBreaker

    # Create a circuit breaker for Graph API
    graph_breaker = CircuitBreaker(name="graph_api")

    # Use as decorator
    @graph_breaker
    async def call_graph_api():
        ...

    # Or use as context manager
    async with graph_breaker:
        response = await client.get(url)

    # Check state
    if graph_breaker.is_open:
        return cached_response
"""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation, requests pass through
    OPEN = "open"  # Failures exceeded threshold, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitOpenError(Exception):
    """Raised when circuit is open and request is blocked."""

    def __init__(self, name: str, recovery_time: float):
        self.name = name
        self.recovery_time = recovery_time
        super().__init__(
            f"Circuit breaker '{name}' is open. "
            f"Recovery in {recovery_time:.1f}s"
        )


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker instance."""

    failure_threshold: int = 5
    success_threshold: int = 2
    recovery_timeout: float = 60.0
    exclude_exceptions: tuple = ()  # Exceptions that don't count as failures
    exclude_status_codes: tuple = (400, 401, 403, 404)  # HTTP codes that don't count


@dataclass
class CircuitBreakerStats:
    """Statistics for monitoring circuit breaker behavior."""

    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    state_changes: int = 0
    last_failure_time: float | None = None
    last_success_time: float | None = None


class CircuitBreaker:
    """
    Async-compatible circuit breaker for external service calls.

    Thread-safe via asyncio.Lock for concurrent access.
    """

    # Registry of all circuit breakers for monitoring
    _registry: dict[str, "CircuitBreaker"] = {}

    def __init__(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
    ):
        """
        Initialize circuit breaker.

        Args:
            name: Unique identifier for this circuit breaker
            config: Configuration options (uses defaults if None)
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float | None = None
        self._lock = asyncio.Lock()

        # Statistics
        self.stats = CircuitBreakerStats()

        # Register for monitoring
        CircuitBreaker._registry[name] = self

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (blocking requests)."""
        return self._state == CircuitState.OPEN

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED

    @property
    def time_until_recovery(self) -> float:
        """Seconds until circuit enters half-open state."""
        if self._state != CircuitState.OPEN or self._last_failure_time is None:
            return 0.0
        elapsed = time.monotonic() - self._last_failure_time
        remaining = self.config.recovery_timeout - elapsed
        return max(0.0, remaining)

    async def _check_state(self) -> None:
        """Check and potentially transition state based on recovery timeout."""
        if self._state == CircuitState.OPEN:
            if self._last_failure_time is not None:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.config.recovery_timeout:
                    await self._transition_to(CircuitState.HALF_OPEN)

    async def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        if self._state != new_state:
            old_state = self._state
            self._state = new_state
            self.stats.state_changes += 1

            if new_state == CircuitState.CLOSED:
                self._failure_count = 0
                self._success_count = 0
            elif new_state == CircuitState.HALF_OPEN:
                self._success_count = 0

            logger.info(
                f"Circuit breaker '{self.name}' state: {old_state.value} -> {new_state.value}"
            )

    async def record_success(self) -> None:
        """Record a successful call."""
        async with self._lock:
            self.stats.total_calls += 1
            self.stats.successful_calls += 1
            self.stats.last_success_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    await self._transition_to(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0

    async def record_failure(self, exception: Exception | None = None) -> None:
        """Record a failed call."""
        async with self._lock:
            self.stats.total_calls += 1
            self.stats.failed_calls += 1
            self.stats.last_failure_time = time.monotonic()
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open returns to open
                await self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self.config.failure_threshold:
                    await self._transition_to(CircuitState.OPEN)

    async def allow_request(self) -> bool:
        """
        Check if a request should be allowed.

        Returns:
            True if request can proceed, False if circuit is open
        """
        async with self._lock:
            await self._check_state()

            if self._state == CircuitState.CLOSED:
                return True
            elif self._state == CircuitState.HALF_OPEN:
                # Allow one test request
                return True
            else:  # OPEN
                self.stats.rejected_calls += 1
                return False

    async def __aenter__(self) -> "CircuitBreaker":
        """Async context manager entry."""
        if not await self.allow_request():
            raise CircuitOpenError(self.name, self.time_until_recovery)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Async context manager exit."""
        if exc_type is None:
            await self.record_success()
        else:
            # Check if exception should be excluded
            if self.config.exclude_exceptions and isinstance(
                exc_val, self.config.exclude_exceptions
            ):
                await self.record_success()
            else:
                await self.record_failure(exc_val)
        return False  # Don't suppress exceptions

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Use circuit breaker as decorator."""

        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            async with self:
                return await func(*args, **kwargs)

        return wrapper

    def get_status(self) -> dict:
        """Get current status for monitoring."""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "time_until_recovery": self.time_until_recovery,
            "stats": {
                "total_calls": self.stats.total_calls,
                "successful_calls": self.stats.successful_calls,
                "failed_calls": self.stats.failed_calls,
                "rejected_calls": self.stats.rejected_calls,
                "state_changes": self.stats.state_changes,
            },
        }

    @classmethod
    def get_all_status(cls) -> dict[str, dict]:
        """Get status of all registered circuit breakers."""
        return {name: cb.get_status() for name, cb in cls._registry.items()}

    @classmethod
    def reset_all(cls) -> None:
        """Reset all circuit breakers to closed state (for testing)."""
        for cb in cls._registry.values():
            cb._state = CircuitState.CLOSED
            cb._failure_count = 0
            cb._success_count = 0
            cb._last_failure_time = None

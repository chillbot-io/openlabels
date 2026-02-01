"""
Tests for retry utilities (GA-FIX 1.4).

Tests the retry decorator, circuit breaker, and combined resilience patterns.
"""

import threading
import time
from unittest.mock import patch

import pytest

from openlabels.utils.retry import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    TRANSIENT_EXCEPTIONS,
    get_cloud_transient_exceptions,
    with_resilience,
    with_retry,
)


class TestWithRetry:
    """Tests for the with_retry decorator."""

    def test_successful_call_no_retry(self):
        """Successful calls should not retry."""
        call_count = 0

        @with_retry(max_retries=3)
        def success():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = success()
        assert result == "ok"
        assert call_count == 1

    def test_retry_on_transient_exception(self):
        """Should retry on transient exceptions."""
        call_count = 0

        @with_retry(max_retries=3, base_delay=0.01)
        def fails_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Connection failed")
            return "ok"

        result = fails_twice()
        assert result == "ok"
        assert call_count == 3

    def test_max_retries_exceeded(self):
        """Should raise after max retries exceeded."""
        call_count = 0

        @with_retry(max_retries=2, base_delay=0.01)
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise TimeoutError("Timed out")

        with pytest.raises(TimeoutError):
            always_fails()

        assert call_count == 3  # Initial + 2 retries

    def test_non_retryable_exception_not_retried(self):
        """Non-retryable exceptions should not trigger retry."""
        call_count = 0

        @with_retry(max_retries=3, retryable_exceptions=(ConnectionError,))
        def raises_value_error():
            nonlocal call_count
            call_count += 1
            raise ValueError("Not retryable")

        with pytest.raises(ValueError):
            raises_value_error()

        assert call_count == 1

    def test_exponential_backoff(self):
        """Should use exponential backoff between retries."""
        timestamps = []

        @with_retry(max_retries=2, base_delay=0.05, exponential_base=2)
        def track_time():
            timestamps.append(time.time())
            raise ConnectionError("fail")

        with pytest.raises(ConnectionError):
            track_time()

        assert len(timestamps) == 3

        # Check delays (should be ~0.05s and ~0.1s with some tolerance)
        delay1 = timestamps[1] - timestamps[0]
        delay2 = timestamps[2] - timestamps[1]

        assert 0.04 < delay1 < 0.1  # ~0.05s with tolerance
        assert 0.08 < delay2 < 0.2  # ~0.1s with tolerance

    def test_on_retry_callback(self):
        """Should call on_retry callback on each retry."""
        retry_info = []

        def on_retry(exc, attempt):
            retry_info.append((type(exc).__name__, attempt))

        @with_retry(max_retries=2, base_delay=0.01, on_retry=on_retry)
        def fails_then_succeeds():
            if len(retry_info) < 2:
                raise ConnectionError("fail")
            return "ok"

        result = fails_then_succeeds()
        assert result == "ok"
        assert retry_info == [("ConnectionError", 0), ("ConnectionError", 1)]


class TestCircuitBreaker:
    """Tests for the CircuitBreaker class."""

    def test_closed_state_allows_requests(self):
        """Closed circuit should allow requests through."""
        breaker = CircuitBreaker(failure_threshold=3)

        @breaker
        def success():
            return "ok"

        assert success() == "ok"
        assert breaker.state == CircuitBreaker.CLOSED

    def test_opens_after_failure_threshold(self):
        """Circuit should open after reaching failure threshold."""
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=10)

        @breaker
        def fails():
            raise ConnectionError("fail")

        # Trigger failures
        for _ in range(3):
            with pytest.raises(ConnectionError):
                fails()

        assert breaker.state == CircuitBreaker.OPEN

    def test_open_circuit_rejects_requests(self):
        """Open circuit should reject requests immediately."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=10)

        @breaker
        def fails():
            raise ConnectionError("fail")

        # Trigger failures to open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                fails()

        # Next call should be rejected by circuit breaker
        with pytest.raises(CircuitBreakerOpenError):
            fails()

    def test_half_open_after_recovery_timeout(self):
        """Circuit should transition to half-open after recovery timeout."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)

        @breaker
        def fails():
            raise ConnectionError("fail")

        # Open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                fails()

        assert breaker.state == CircuitBreaker.OPEN

        # Wait for recovery timeout
        time.sleep(0.1)

        assert breaker.state == CircuitBreaker.HALF_OPEN

    def test_closes_after_successful_half_open(self):
        """Circuit should close after successful call in half-open state."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)
        call_count = 0

        @breaker
        def recovers():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ConnectionError("fail")
            return "ok"

        # Open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                recovers()

        assert breaker.state == CircuitBreaker.OPEN

        # Wait for recovery
        time.sleep(0.1)

        # Successful call should close circuit
        result = recovers()
        assert result == "ok"
        assert breaker.state == CircuitBreaker.CLOSED

    def test_reopens_on_half_open_failure(self):
        """Circuit should reopen if half-open call fails."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)

        @breaker
        def always_fails():
            raise ConnectionError("fail")

        # Open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                always_fails()

        # Wait for recovery
        time.sleep(0.1)
        assert breaker.state == CircuitBreaker.HALF_OPEN

        # Failure in half-open should reopen
        with pytest.raises(ConnectionError):
            always_fails()

        assert breaker.state == CircuitBreaker.OPEN

    def test_context_manager_success(self):
        """Context manager should track success."""
        breaker = CircuitBreaker(failure_threshold=2)

        with breaker:
            result = "ok"

        assert breaker.failure_count == 0

    def test_context_manager_failure(self):
        """Context manager should track failures."""
        breaker = CircuitBreaker(failure_threshold=2)

        with pytest.raises(ConnectionError):
            with breaker:
                raise ConnectionError("fail")

        assert breaker.failure_count == 1

    def test_reset(self):
        """Manual reset should close circuit."""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=60)

        @breaker
        def fails():
            raise ConnectionError("fail")

        # Open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                fails()

        assert breaker.state == CircuitBreaker.OPEN

        breaker.reset()

        assert breaker.state == CircuitBreaker.CLOSED
        assert breaker.failure_count == 0

    def test_thread_safety(self):
        """Circuit breaker should be thread-safe."""
        breaker = CircuitBreaker(failure_threshold=10, recovery_timeout=60)
        errors = []

        @breaker
        def thread_work():
            time.sleep(0.001)
            if breaker.failure_count < 5:
                raise ConnectionError("fail")
            return "ok"

        def run_thread():
            try:
                for _ in range(5):
                    try:
                        thread_work()
                    except (ConnectionError, CircuitBreakerOpenError):
                        pass
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=run_thread) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


class TestWithResilience:
    """Tests for the combined with_resilience decorator."""

    def test_retry_before_circuit_opens(self):
        """Should retry before circuit breaker opens."""
        call_count = 0

        @with_resilience(
            max_retries=2,
            base_delay=0.01,
            failure_threshold=5,
        )
        def fails_once():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError("fail")
            return "ok"

        result = fails_once()
        assert result == "ok"
        assert call_count == 2

    def test_circuit_opens_after_many_failures(self):
        """Circuit should open after repeated failures across retries."""
        @with_resilience(
            max_retries=1,
            base_delay=0.01,
            failure_threshold=3,
            recovery_timeout=60,
        )
        def always_fails():
            raise ConnectionError("fail")

        # Each call does 2 attempts (initial + 1 retry), so 2 calls = 4 failures
        for i in range(2):
            with pytest.raises(ConnectionError):
                always_fails()

        # Circuit should now be open
        with pytest.raises(CircuitBreakerOpenError):
            always_fails()

    def test_exposes_circuit_breaker(self):
        """Decorated function should expose circuit breaker."""
        @with_resilience(failure_threshold=5)
        def my_func():
            return "ok"

        assert hasattr(my_func, 'circuit_breaker')
        assert isinstance(my_func.circuit_breaker, CircuitBreaker)


class TestTransientExceptions:
    """Tests for transient exception detection."""

    def test_base_transient_exceptions(self):
        """Should include base transient exceptions."""
        assert ConnectionError in TRANSIENT_EXCEPTIONS
        assert TimeoutError in TRANSIENT_EXCEPTIONS
        assert OSError in TRANSIENT_EXCEPTIONS

    def test_get_cloud_transient_includes_base(self):
        """get_cloud_transient_exceptions should include base exceptions."""
        exceptions = get_cloud_transient_exceptions()
        assert ConnectionError in exceptions
        assert TimeoutError in exceptions

    @patch('openlabels.utils.retry._get_aws_transient_exceptions')
    def test_includes_aws_exceptions_when_available(self, mock_aws):
        """Should include AWS exceptions when boto3 is available."""
        mock_exception = type('MockBotoError', (Exception,), {})
        mock_aws.return_value = (mock_exception,)

        exceptions = get_cloud_transient_exceptions()
        assert mock_exception in exceptions


class TestCircuitBreakerOpenError:
    """Tests for CircuitBreakerOpenError."""

    def test_error_message(self):
        """Should include descriptive message."""
        error = CircuitBreakerOpenError("Circuit is open", recovery_time=10.5)
        assert "Circuit is open" in str(error)
        assert error.recovery_time == 10.5

    def test_no_recovery_time(self):
        """Should handle no recovery time."""
        error = CircuitBreakerOpenError("Circuit is open")
        assert error.recovery_time is None

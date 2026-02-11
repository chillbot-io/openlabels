"""Tests for circuit breaker resilience pattern."""

import asyncio
from unittest.mock import patch

import pytest

from openlabels.core.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitOpenError,
    CircuitState,
)


@pytest.fixture(autouse=True)
def _reset_registry():
    """Clear the global circuit breaker registry between tests."""
    CircuitBreaker._registry.clear()
    yield
    CircuitBreaker._registry.clear()


class TestCircuitBreakerStates:
    """State machine transition tests."""

    @pytest.mark.asyncio
    async def test_initial_state_is_closed(self):
        cb = CircuitBreaker("test")
        assert cb.state == CircuitState.CLOSED
        assert cb.is_closed
        assert not cb.is_open

    @pytest.mark.asyncio
    async def test_closed_to_open_on_failure_threshold(self):
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config=config)

        for _ in range(3):
            await cb.record_failure()

        assert cb.state == CircuitState.OPEN
        assert cb.is_open

    @pytest.mark.asyncio
    async def test_stays_closed_below_threshold(self):
        config = CircuitBreakerConfig(failure_threshold=5)
        cb = CircuitBreaker("test", config=config)

        for _ in range(4):
            await cb.record_failure()

        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_open_to_half_open_after_recovery_timeout(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=10.0)
        cb = CircuitBreaker("test", config=config)

        await cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Simulate time passing beyond recovery timeout
        with patch("time.monotonic", return_value=cb._last_failure_time + 11.0):
            allowed = await cb.allow_request()

        assert cb.state == CircuitState.HALF_OPEN
        assert allowed is True

    @pytest.mark.asyncio
    async def test_half_open_to_closed_on_success_threshold(self):
        config = CircuitBreakerConfig(
            failure_threshold=1, success_threshold=2, recovery_timeout=0.0
        )
        cb = CircuitBreaker("test", config=config)

        # Open it
        await cb.record_failure()
        # Let it go to half-open
        await cb.allow_request()
        assert cb.state == CircuitState.HALF_OPEN

        # Record enough successes
        await cb.record_success()
        await cb.record_success()

        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_to_open_on_failure(self):
        config = CircuitBreakerConfig(
            failure_threshold=1, recovery_timeout=0.0
        )
        cb = CircuitBreaker("test", config=config)

        # Open it
        await cb.record_failure()
        # Half-open
        await cb.allow_request()
        assert cb.state == CircuitState.HALF_OPEN

        # Fail again -> back to open
        await cb.record_failure()
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_success_resets_failure_count_in_closed(self):
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test", config=config)

        await cb.record_failure()
        await cb.record_failure()
        await cb.record_success()  # Reset
        await cb.record_failure()
        await cb.record_failure()

        # Should still be closed (2 failures after reset, not 3)
        assert cb.state == CircuitState.CLOSED


class TestAllowRequest:
    """Tests for allow_request() behavior per state."""

    @pytest.mark.asyncio
    async def test_closed_allows(self):
        cb = CircuitBreaker("test")
        assert await cb.allow_request() is True

    @pytest.mark.asyncio
    async def test_open_rejects(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=60.0)
        cb = CircuitBreaker("test", config=config)
        await cb.record_failure()

        assert await cb.allow_request() is False

    @pytest.mark.asyncio
    async def test_open_rejection_increments_rejected_stat(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=60.0)
        cb = CircuitBreaker("test", config=config)
        await cb.record_failure()

        await cb.allow_request()
        await cb.allow_request()

        assert cb.stats.rejected_calls == 2

    @pytest.mark.asyncio
    async def test_half_open_allows(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0.0)
        cb = CircuitBreaker("test", config=config)
        await cb.record_failure()

        # Transition to half-open via allow_request
        allowed = await cb.allow_request()
        assert allowed is True
        assert cb.state == CircuitState.HALF_OPEN


class TestContextManager:
    """Tests for async with usage."""

    @pytest.mark.asyncio
    async def test_success_path(self):
        cb = CircuitBreaker("test")
        async with cb:
            pass

        assert cb.stats.successful_calls == 1
        assert cb.stats.total_calls == 1

    @pytest.mark.asyncio
    async def test_failure_path(self):
        cb = CircuitBreaker("test")
        with pytest.raises(ValueError):
            async with cb:
                raise ValueError("boom")

        assert cb.stats.failed_calls == 1

    @pytest.mark.asyncio
    async def test_raises_circuit_open_error_when_open(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=60.0)
        cb = CircuitBreaker("test", config=config)
        await cb.record_failure()

        with pytest.raises(CircuitOpenError) as exc_info:
            async with cb:
                pass

        assert exc_info.value.name == "test"
        assert exc_info.value.recovery_time > 0

    @pytest.mark.asyncio
    async def test_excluded_exceptions_counted_as_success(self):
        config = CircuitBreakerConfig(
            failure_threshold=1,
            exclude_exceptions=(ValueError,),
        )
        cb = CircuitBreaker("test", config=config)

        with pytest.raises(ValueError):
            async with cb:
                raise ValueError("expected")

        # Should be counted as success, not failure
        assert cb.stats.successful_calls == 1
        assert cb.stats.failed_calls == 0
        assert cb.state == CircuitState.CLOSED


class TestDecorator:
    """Tests for @circuit_breaker decorator usage."""

    @pytest.mark.asyncio
    async def test_decorator_records_success(self):
        cb = CircuitBreaker("test")

        @cb
        async def my_func():
            return 42

        result = await my_func()
        assert result == 42
        assert cb.stats.successful_calls == 1

    @pytest.mark.asyncio
    async def test_decorator_records_failure(self):
        cb = CircuitBreaker("test")

        @cb
        async def my_func():
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError):
            await my_func()

        assert cb.stats.failed_calls == 1


class TestTimeUntilRecovery:
    """Tests for time_until_recovery property."""

    @pytest.mark.asyncio
    async def test_zero_when_closed(self):
        cb = CircuitBreaker("test")
        assert cb.time_until_recovery == 0.0

    @pytest.mark.asyncio
    async def test_positive_when_open(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=60.0)
        cb = CircuitBreaker("test", config=config)
        await cb.record_failure()

        assert cb.time_until_recovery > 0
        assert cb.time_until_recovery <= 60.0


class TestStats:
    """Tests for statistics tracking."""

    @pytest.mark.asyncio
    async def test_stats_accumulate(self):
        cb = CircuitBreaker("test")

        await cb.record_success()
        await cb.record_success()
        await cb.record_failure()

        assert cb.stats.total_calls == 3
        assert cb.stats.successful_calls == 2
        assert cb.stats.failed_calls == 1

    @pytest.mark.asyncio
    async def test_state_changes_counted(self):
        config = CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0.0)
        cb = CircuitBreaker("test", config=config)

        await cb.record_failure()  # CLOSED -> OPEN
        await cb.allow_request()   # OPEN -> HALF_OPEN
        await cb.record_success()
        await cb.record_success()  # HALF_OPEN -> CLOSED

        assert cb.stats.state_changes == 3


class TestGetStatusAndRegistry:
    """Tests for monitoring helpers."""

    @pytest.mark.asyncio
    async def test_get_status(self):
        cb = CircuitBreaker("my-service")
        status = cb.get_status()

        assert status["name"] == "my-service"
        assert status["state"] == "closed"
        assert "stats" in status

    def test_registry_tracks_instances(self):
        cb1 = CircuitBreaker("svc1")
        cb2 = CircuitBreaker("svc2")

        all_status = CircuitBreaker.get_all_status()
        assert "svc1" in all_status
        assert "svc2" in all_status

    def test_reset_all(self):
        config = CircuitBreakerConfig(failure_threshold=1)
        cb = CircuitBreaker("test", config=config)
        # Manually set to open
        cb._state = CircuitState.OPEN
        cb._failure_count = 5

        CircuitBreaker.reset_all()

        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0

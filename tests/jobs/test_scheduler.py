"""
Comprehensive tests for the database-driven cron scheduler.

Tests focus on:
- Scheduler initialization and lifecycle
- Cron expression parsing and validation
- Singleton pattern
- Database polling (with mocks)
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch

from openlabels.jobs.scheduler import (
    DatabaseScheduler,
    Scheduler,  # Alias for DatabaseScheduler
    parse_cron_expression,
    validate_cron_expression,
    get_cron_description,
    get_scheduler,
    APSCHEDULER_AVAILABLE,
)


class TestSchedulerInitialization:
    """Tests for Scheduler class initialization."""

    def test_init_creates_scheduler_object(self):
        """Scheduler should initialize properly."""
        scheduler = DatabaseScheduler()

        assert scheduler._running is False
        assert scheduler._task is None

    def test_is_running_property_initially_false(self):
        """is_running should be False initially."""
        scheduler = DatabaseScheduler()

        assert scheduler.is_running is False

    def test_custom_poll_interval(self):
        """Scheduler should accept custom poll interval."""
        scheduler = DatabaseScheduler(poll_interval=10)
        assert scheduler._poll_interval == 10

    def test_custom_min_trigger_interval(self):
        """Scheduler should accept custom min trigger interval."""
        scheduler = DatabaseScheduler(min_trigger_interval=120)
        assert scheduler._min_trigger_interval == 120


class TestSchedulerStartStop:
    """Tests for scheduler start/stop lifecycle."""

    async def test_start_returns_true(self):
        """Start should return True on success."""
        scheduler = DatabaseScheduler()

        result = await scheduler.start()

        assert result is True
        assert scheduler.is_running is True

        # Cleanup
        await scheduler.stop()

    async def test_start_when_already_running(self):
        """Start should return True if already running."""
        scheduler = DatabaseScheduler()
        await scheduler.start()

        result = await scheduler.start()  # Second call

        assert result is True
        assert scheduler.is_running is True

        # Cleanup
        await scheduler.stop()

    async def test_stop_shuts_down_scheduler(self):
        """Stop should shut down the scheduler."""
        scheduler = DatabaseScheduler()
        await scheduler.start()

        await scheduler.stop()

        assert scheduler.is_running is False
        assert scheduler._task is None

    async def test_stop_when_not_running(self):
        """Stop should handle case where not running."""
        scheduler = DatabaseScheduler()

        # Should not raise
        await scheduler.stop()

        assert scheduler.is_running is False

    async def test_multiple_start_stop_cycles(self):
        """Scheduler should handle multiple start/stop cycles."""
        scheduler = DatabaseScheduler()

        # First cycle
        result1 = await scheduler.start()
        assert result1 is True
        await scheduler.stop()
        assert scheduler.is_running is False

        # Second cycle
        result2 = await scheduler.start()
        assert result2 is True
        await scheduler.stop()
        assert scheduler.is_running is False


class TestParseCronExpression:
    """Tests for parse_cron_expression function."""

    def test_parse_valid_cron_expression(self):
        """Valid cron expression should return next fire time."""
        result = parse_cron_expression("0 * * * *")

        assert result is not None
        assert isinstance(result, datetime)

    def test_parse_invalid_cron_expression(self):
        """Invalid cron expression should return None."""
        result = parse_cron_expression("invalid cron")

        assert result is None

    def test_parse_complex_cron_expressions(self):
        """Various valid cron expressions should parse."""
        cron_expressions = [
            "0 0 * * *",      # Daily at midnight
            "0 */6 * * *",    # Every 6 hours
            "0 9 * * 1-5",    # Weekdays at 9am
            "30 4 1 * *",     # 4:30 AM on 1st of each month
            "0 0 1 1 *",      # Midnight on January 1st
        ]

        for expr in cron_expressions:
            result = parse_cron_expression(expr)
            assert result is not None, f"Failed to parse: {expr}"

    def test_parse_cron_returns_future_time(self):
        """Parsed next run should be in the future."""
        result = parse_cron_expression("* * * * *")  # Every minute

        assert result is not None
        assert result >= datetime.now(timezone.utc)


class TestValidateCronExpression:
    """Tests for validate_cron_expression function."""

    def test_validate_valid_expressions(self):
        """Valid cron expressions should return True."""
        valid_expressions = [
            "* * * * *",
            "0 0 * * *",
            "0 */6 * * *",
            "0 9 * * 1-5",
            "30 4 1 * *",
        ]

        for expr in valid_expressions:
            assert validate_cron_expression(expr) is True, f"Should be valid: {expr}"

    def test_validate_invalid_expressions(self):
        """Invalid cron expressions should return False."""
        invalid_expressions = [
            "invalid",
            "* * *",
            "60 * * * *",   # Invalid minute
            "* 25 * * *",   # Invalid hour
            "",
        ]

        for expr in invalid_expressions:
            assert validate_cron_expression(expr) is False, f"Should be invalid: {expr}"


class TestGetCronDescription:
    """Tests for get_cron_description function."""

    def test_description_daily_midnight(self):
        """Daily midnight should have appropriate description."""
        result = get_cron_description("0 0 * * *")
        assert "00:00" in result

    def test_description_hourly(self):
        """Hourly cron should mention minutes."""
        result = get_cron_description("0 * * * *")
        # Should mention "at minute 0" or similar
        assert "0" in result or "minute" in result.lower()

    def test_description_every_minute(self):
        """Every minute pattern should have description."""
        result = get_cron_description("* * * * *")
        assert "minute" in result.lower()

    def test_description_invalid(self):
        """Invalid expression should return error message."""
        result = get_cron_description("invalid")
        assert "invalid" in result.lower()


class TestGetSchedulerSingleton:
    """Tests for get_scheduler singleton function."""

    @pytest.fixture(autouse=True)
    def reset_scheduler_singleton(self):
        """Reset scheduler singleton before and after each test."""
        import openlabels.jobs.scheduler as scheduler_module
        # Save original state
        original_scheduler = scheduler_module._scheduler
        # Reset before test
        scheduler_module._scheduler = None
        yield
        # Restore after test to prevent state leakage
        scheduler_module._scheduler = original_scheduler

    def test_get_scheduler_returns_scheduler(self):
        """get_scheduler should return a Scheduler instance."""
        scheduler = get_scheduler()
        assert isinstance(scheduler, DatabaseScheduler)

    def test_get_scheduler_returns_same_instance(self):
        """get_scheduler should return the same instance on multiple calls."""
        scheduler1 = get_scheduler()
        scheduler2 = get_scheduler()
        assert scheduler1 is scheduler2

    def test_get_scheduler_creates_new_if_none(self):
        """get_scheduler should create new scheduler if none exists."""
        import openlabels.jobs.scheduler as scheduler_module

        scheduler = get_scheduler()

        assert scheduler is not None
        assert scheduler_module._scheduler is scheduler


class TestCronExpressionConcepts:
    """Tests for cron expression concepts and edge cases."""

    def test_cron_step_values(self):
        """Cron expressions with step values should parse."""
        expressions = [
            "*/5 * * * *",    # Every 5 minutes
            "*/15 * * * *",   # Every 15 minutes
            "0 */2 * * *",    # Every 2 hours
        ]

        for expr in expressions:
            result = parse_cron_expression(expr)
            assert result is not None, f"Failed: {expr}"

    def test_cron_ranges(self):
        """Cron expressions with ranges should parse."""
        expressions = [
            "0 9-17 * * *",   # 9 AM to 5 PM
            "0 * * * 1-5",    # Mon-Fri
        ]

        for expr in expressions:
            result = parse_cron_expression(expr)
            assert result is not None, f"Failed: {expr}"

    def test_cron_lists(self):
        """Cron expressions with lists should parse."""
        expressions = [
            "0 0,12 * * *",   # Noon and midnight
            "0 0 1,15 * *",   # 1st and 15th of month
        ]

        for expr in expressions:
            result = parse_cron_expression(expr)
            assert result is not None, f"Failed: {expr}"


class TestSchedulerPolling:
    """Tests for scheduler polling functionality (mocked)."""

    async def test_poll_loop_starts_on_start(self):
        """Poll loop should start when scheduler starts."""
        scheduler = DatabaseScheduler(poll_interval=1)

        await scheduler.start()

        assert scheduler._task is not None
        assert not scheduler._task.done()

        await scheduler.stop()

    async def test_shutdown_event_stops_polling(self):
        """Setting shutdown event should stop the poll loop."""
        scheduler = DatabaseScheduler(poll_interval=60)
        await scheduler.start()

        # Stop should set shutdown event
        await scheduler.stop()

        assert scheduler._running is False



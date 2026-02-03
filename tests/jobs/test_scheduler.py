"""
Comprehensive tests for the cron-based job scheduler.

Tests focus on:
- Scheduler initialization and lifecycle
- Cron expression parsing
- Job management (add, remove, pause, resume)
- APScheduler availability handling
- Singleton pattern
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock, patch

from openlabels.jobs.scheduler import (
    Scheduler,
    parse_cron_expression,
    get_scheduler,
    APSCHEDULER_AVAILABLE,
)


class TestSchedulerInitialization:
    """Tests for Scheduler class initialization."""

    def test_init_creates_scheduler_object(self):
        """Scheduler should initialize properly."""
        scheduler = Scheduler()

        assert scheduler._scheduler is None
        assert scheduler._running is False

    def test_is_available_property(self):
        """is_available should reflect APScheduler installation."""
        scheduler = Scheduler()

        # Should return boolean
        assert isinstance(scheduler.is_available, bool)
        assert scheduler.is_available == APSCHEDULER_AVAILABLE

    def test_is_running_property_initially_false(self):
        """is_running should be False initially."""
        scheduler = Scheduler()

        assert scheduler.is_running is False


class TestSchedulerStartStop:
    """Tests for scheduler start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_returns_false_without_apscheduler(self):
        """Start should return False if APScheduler not installed."""
        import openlabels.jobs.scheduler as sched_module
        original = sched_module.APSCHEDULER_AVAILABLE

        try:
            sched_module.APSCHEDULER_AVAILABLE = False
            scheduler = Scheduler()
            result = await scheduler.start()
            assert result is False
        finally:
            sched_module.APSCHEDULER_AVAILABLE = original

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_start_creates_scheduler(self):
        """Start should create and start the APScheduler."""
        scheduler = Scheduler()

        result = await scheduler.start()

        assert result is True
        assert scheduler._running is True
        assert scheduler._scheduler is not None

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_start_when_already_running(self):
        """Start should return True if already running."""
        scheduler = Scheduler()
        await scheduler.start()

        result = await scheduler.start()  # Second call

        assert result is True

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_stop_shuts_down_scheduler(self):
        """Stop should shut down the scheduler."""
        scheduler = Scheduler()
        await scheduler.start()

        await scheduler.stop()

        assert scheduler._running is False

    @pytest.mark.asyncio
    async def test_stop_when_not_running(self):
        """Stop should handle case where not running."""
        scheduler = Scheduler()

        # Should not raise
        await scheduler.stop()

        assert scheduler._running is False


class TestSchedulerJobManagement:
    """Tests for schedule management methods."""

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_add_schedule_when_not_running(self):
        """add_schedule should return False when scheduler not running."""
        scheduler = Scheduler()

        result = scheduler.add_schedule(
            schedule_id="test-1",
            cron_expression="0 * * * *",
            callback=AsyncMock(),
        )

        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_add_schedule_when_running(self):
        """add_schedule should add job when scheduler running."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy_callback():
            pass

        result = scheduler.add_schedule(
            schedule_id="test-job-1",
            cron_expression="0 * * * *",  # Every hour
            callback=dummy_callback,
        )

        assert result is True

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_add_schedule_with_invalid_cron(self):
        """add_schedule should handle invalid cron expressions."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy_callback():
            pass

        result = scheduler.add_schedule(
            schedule_id="test-invalid",
            cron_expression="invalid cron",
            callback=dummy_callback,
        )

        assert result is False

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_add_schedule_replace_existing(self):
        """add_schedule should replace existing job with same ID."""
        scheduler = Scheduler()
        await scheduler.start()

        async def callback1():
            pass

        async def callback2():
            pass

        # Add first job
        scheduler.add_schedule("dup-job", "0 * * * *", callback1)

        # Add with same ID - should replace
        result = scheduler.add_schedule("dup-job", "30 * * * *", callback2)

        assert result is True

        # Cleanup
        await scheduler.stop()

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_remove_schedule_when_not_running(self):
        """remove_schedule should return False when no scheduler."""
        scheduler = Scheduler()

        result = scheduler.remove_schedule("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_remove_schedule_success(self):
        """remove_schedule should remove existing job."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy():
            pass

        scheduler.add_schedule("to-remove", "0 * * * *", dummy)
        result = scheduler.remove_schedule("to-remove")

        assert result is True

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_remove_nonexistent_schedule(self):
        """remove_schedule should return False for nonexistent job."""
        scheduler = Scheduler()
        await scheduler.start()

        result = scheduler.remove_schedule("does-not-exist")

        assert result is False

        # Cleanup
        await scheduler.stop()


class TestSchedulerPauseResume:
    """Tests for pause/resume functionality."""

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_pause_when_not_running(self):
        """pause_schedule should return False when no scheduler."""
        scheduler = Scheduler()

        result = scheduler.pause_schedule("some-job")

        assert result is False

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_resume_when_not_running(self):
        """resume_schedule should return False when no scheduler."""
        scheduler = Scheduler()

        result = scheduler.resume_schedule("some-job")

        assert result is False

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_pause_and_resume_schedule(self):
        """pause and resume should work on existing jobs."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy():
            pass

        scheduler.add_schedule("pausable-job", "0 * * * *", dummy)

        pause_result = scheduler.pause_schedule("pausable-job")
        resume_result = scheduler.resume_schedule("pausable-job")

        assert pause_result is True
        assert resume_result is True

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_pause_nonexistent_job(self):
        """pause_schedule should return False for nonexistent job."""
        scheduler = Scheduler()
        await scheduler.start()

        result = scheduler.pause_schedule("nonexistent")

        assert result is False

        # Cleanup
        await scheduler.stop()


class TestSchedulerNextRun:
    """Tests for get_next_run method."""

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_get_next_run_when_not_running(self):
        """get_next_run should return None when no scheduler."""
        scheduler = Scheduler()

        result = scheduler.get_next_run("some-job")

        assert result is None

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_get_next_run_for_existing_job(self):
        """get_next_run should return datetime for existing job."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy():
            pass

        scheduler.add_schedule("timed-job", "0 * * * *", dummy)
        next_run = scheduler.get_next_run("timed-job")

        assert next_run is not None
        assert isinstance(next_run, datetime)

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_get_next_run_for_nonexistent_job(self):
        """get_next_run should return None for nonexistent job."""
        scheduler = Scheduler()
        await scheduler.start()

        result = scheduler.get_next_run("nonexistent")

        assert result is None

        # Cleanup
        await scheduler.stop()


class TestSchedulerListSchedules:
    """Tests for list_schedules method."""

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_list_schedules_when_not_running(self):
        """list_schedules should return empty list when no scheduler."""
        scheduler = Scheduler()

        result = scheduler.list_schedules()

        assert result == []

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_list_schedules_returns_jobs(self):
        """list_schedules should return list of job info."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy():
            pass

        scheduler.add_schedule("job-1", "0 * * * *", dummy)
        scheduler.add_schedule("job-2", "30 * * * *", dummy)

        jobs = scheduler.list_schedules()

        assert len(jobs) == 2
        job_ids = [j["id"] for j in jobs]
        assert "job-1" in job_ids
        assert "job-2" in job_ids

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_list_schedules_includes_next_run(self):
        """list_schedules should include next_run in job info."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy():
            pass

        scheduler.add_schedule("job-with-time", "0 * * * *", dummy)
        jobs = scheduler.list_schedules()

        assert len(jobs) == 1
        assert "next_run" in jobs[0]
        assert "trigger" in jobs[0]

        # Cleanup
        await scheduler.stop()


class TestParseCronExpression:
    """Tests for parse_cron_expression function."""

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_parse_valid_cron_expression(self):
        """Valid cron expression should return next fire time."""
        result = parse_cron_expression("0 * * * *")

        assert result is not None
        assert isinstance(result, datetime)

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_parse_invalid_cron_expression(self):
        """Invalid cron expression should return None."""
        result = parse_cron_expression("invalid cron")

        assert result is None

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
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

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_parse_cron_returns_future_time(self):
        """Parsed next run should be in the future."""
        result = parse_cron_expression("* * * * *")  # Every minute

        assert result is not None
        assert result >= datetime.now(timezone.utc)

    def test_parse_without_apscheduler(self):
        """parse_cron_expression should return None if APScheduler unavailable."""
        with patch('openlabels.jobs.scheduler.APSCHEDULER_AVAILABLE', False):
            # Need to reload the function with the patched value
            from openlabels.jobs import scheduler
            original_available = scheduler.APSCHEDULER_AVAILABLE

            try:
                scheduler.APSCHEDULER_AVAILABLE = False
                result = scheduler.parse_cron_expression("0 * * * *")
                assert result is None
            finally:
                scheduler.APSCHEDULER_AVAILABLE = original_available


class TestGetSchedulerSingleton:
    """Tests for get_scheduler singleton function."""

    def test_get_scheduler_returns_scheduler(self):
        """get_scheduler should return a Scheduler instance."""
        # Reset global first
        import openlabels.jobs.scheduler as scheduler_module
        scheduler_module._scheduler = None

        scheduler = get_scheduler()

        assert isinstance(scheduler, Scheduler)

    def test_get_scheduler_returns_same_instance(self):
        """get_scheduler should return the same instance on multiple calls."""
        # Reset global first
        import openlabels.jobs.scheduler as scheduler_module
        scheduler_module._scheduler = None

        scheduler1 = get_scheduler()
        scheduler2 = get_scheduler()

        assert scheduler1 is scheduler2

    def test_get_scheduler_creates_new_if_none(self):
        """get_scheduler should create new scheduler if none exists."""
        import openlabels.jobs.scheduler as scheduler_module
        scheduler_module._scheduler = None

        scheduler = get_scheduler()

        assert scheduler is not None
        assert scheduler_module._scheduler is scheduler


class TestCronExpressionConcepts:
    """Tests for cron expression concepts and edge cases."""

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
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

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_cron_ranges(self):
        """Cron expressions with ranges should parse."""
        expressions = [
            "0 9-17 * * *",   # 9 AM to 5 PM
            "0 * * * 1-5",    # Mon-Fri
        ]

        for expr in expressions:
            result = parse_cron_expression(expr)
            assert result is not None, f"Failed: {expr}"

    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    def test_cron_lists(self):
        """Cron expressions with lists should parse."""
        expressions = [
            "0 0,12 * * *",   # Noon and midnight
            "0 0 1,15 * *",   # 1st and 15th of month
        ]

        for expr in expressions:
            result = parse_cron_expression(expr)
            assert result is not None, f"Failed: {expr}"


class TestSchedulerEdgeCases:
    """Edge case and robustness tests."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_add_schedule_with_kwargs(self):
        """add_schedule should pass kwargs to callback."""
        scheduler = Scheduler()
        await scheduler.start()

        async def callback_with_args(**kwargs):
            pass

        result = scheduler.add_schedule(
            "job-with-args",
            "0 * * * *",
            callback_with_args,
            tenant_id="abc123",
            scan_id="def456",
        )

        assert result is True

        # Cleanup
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_multiple_start_stop_cycles(self):
        """Scheduler should handle multiple start/stop cycles."""
        scheduler = Scheduler()

        # First cycle
        result1 = await scheduler.start()
        assert result1 is True
        await scheduler.stop()

        # Second cycle
        result2 = await scheduler.start()
        assert result2 is True
        await scheduler.stop()

    @pytest.mark.asyncio
    @pytest.mark.skipif(not APSCHEDULER_AVAILABLE, reason="APScheduler not installed")
    async def test_schedule_id_with_special_characters(self):
        """Schedule IDs with special characters should be handled."""
        scheduler = Scheduler()
        await scheduler.start()

        async def dummy():
            pass

        # Various potentially problematic IDs
        test_ids = [
            "job-with-dashes",
            "job_with_underscores",
            "job.with.dots",
            "job:with:colons",
        ]

        for job_id in test_ids:
            result = scheduler.add_schedule(job_id, "0 * * * *", dummy)
            assert result is True, f"Failed for ID: {job_id}"

        # Cleanup
        await scheduler.stop()

"""
Database-driven cron scheduler for OpenLabels.

Replaces APScheduler with a database polling approach that:
- Persists schedules across restarts
- Supports multiple server instances without duplicate triggers
- Uses PostgreSQL row locking for safe concurrent access

Features:
- Polls scan_schedules table periodically (configurable interval)
- Uses croniter for cron expression matching
- Tracks last_run_at to prevent duplicate triggers
- Uses SELECT FOR UPDATE SKIP LOCKED for distributed locking
- Enqueues scan jobs via the existing JobQueue
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from croniter import croniter
from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import ScanJob, ScanSchedule, ScanTarget

logger = logging.getLogger(__name__)

# Backwards compatibility - APScheduler has been replaced with database-driven scheduling
# but tests may still check for this constant
APSCHEDULER_AVAILABLE = True

# Default polling interval in seconds
DEFAULT_POLL_INTERVAL = 30

# Default minimum interval between schedule checks to avoid rapid re-triggering
DEFAULT_MIN_TRIGGER_INTERVAL_SECONDS = 60


def _get_scheduler_settings():
    """Get scheduler settings from config, with fallback defaults."""
    try:
        from openlabels.server.config import get_settings
        settings = get_settings()
        return {
            "poll_interval": settings.scheduler.poll_interval,
            "min_trigger_interval": settings.scheduler.min_trigger_interval,
        }
    except (ImportError, AttributeError) as e:
        logger.debug(f"Using default scheduler settings: {e}")
        return {
            "poll_interval": DEFAULT_POLL_INTERVAL,
            "min_trigger_interval": DEFAULT_MIN_TRIGGER_INTERVAL_SECONDS,
        }


class DatabaseScheduler:
    """
    Database-driven scheduler that polls for due schedules.

    This scheduler:
    - Runs as a background task alongside the API
    - Polls the database for enabled schedules with cron expressions
    - Uses croniter to determine if a schedule is due
    - Uses database locking to prevent duplicate triggers across instances
    - Enqueues scan jobs via the existing JobQueue

    Usage:
        scheduler = DatabaseScheduler()
        await scheduler.start()

        # ... application runs ...

        await scheduler.stop()
    """

    def __init__(
        self,
        poll_interval: Optional[int] = None,
        min_trigger_interval: Optional[int] = None,
    ):
        """
        Initialize the database scheduler.

        Args:
            poll_interval: How often to poll for due schedules (seconds).
                          If not provided, uses value from settings.
            min_trigger_interval: Minimum seconds between triggering same schedule.
                                 If not provided, uses value from settings.
        """
        settings = _get_scheduler_settings()
        self._poll_interval = poll_interval or settings["poll_interval"]
        self._min_trigger_interval = min_trigger_interval or settings["min_trigger_interval"]
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    async def start(self) -> bool:
        """
        Start the scheduler background task.

        Returns:
            True if started successfully
        """
        if self._running:
            logger.warning("Scheduler already running")
            return True

        try:
            self._shutdown_event.clear()
            self._running = True
            self._task = asyncio.create_task(self._poll_loop())
            logger.info(
                f"Database scheduler started (poll interval: {self._poll_interval}s)"
            )
            return True
        except (RuntimeError, OSError) as e:
            logger.error(f"Failed to start scheduler: {e}")
            self._running = False
            return False

    async def stop(self) -> None:
        """Stop the scheduler gracefully."""
        if not self._running:
            return

        logger.info("Stopping database scheduler...")
        self._running = False
        self._shutdown_event.set()

        if self._task:
            try:
                # Give the task a moment to finish cleanly
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Scheduler task did not stop cleanly, cancelling")
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None

        logger.info("Database scheduler stopped")

    async def _poll_loop(self) -> None:
        """Main polling loop that checks for due schedules."""
        logger.debug("Scheduler poll loop started")

        while self._running:
            try:
                await self._check_due_schedules()
            except (SQLAlchemyError, ConnectionError, OSError, RuntimeError) as e:
                # Log but don't crash - continue polling
                logger.error(f"Error checking schedules: {e}", exc_info=True)

            # Wait for next poll interval or shutdown signal
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self._poll_interval,
                )
                # Shutdown event was set
                break
            except asyncio.TimeoutError:
                # Normal timeout - continue polling
                pass

        logger.debug("Scheduler poll loop exited")

    async def _check_due_schedules(self) -> None:
        """Check for and trigger due schedules."""
        from openlabels.server.db import get_session_context

        async with get_session_context() as session:
            # Find enabled schedules with cron expressions that might be due
            now = datetime.now(timezone.utc)

            # Query for schedules that:
            # 1. Are enabled
            # 2. Have a cron expression
            # 3. Either never ran OR last ran more than MIN_TRIGGER_INTERVAL ago
            query = (
                select(ScanSchedule)
                .where(
                    and_(
                        ScanSchedule.enabled == True,  # noqa: E712
                        ScanSchedule.cron.isnot(None),
                        ScanSchedule.cron != "",
                    )
                )
                .with_for_update(skip_locked=True)
            )

            result = await session.execute(query)
            schedules = result.scalars().all()

            for schedule in schedules:
                try:
                    await self._maybe_trigger_schedule(session, schedule, now)
                except (SQLAlchemyError, ConnectionError, OSError, RuntimeError) as e:
                    # Log but continue with other schedules
                    logger.error(
                        f"Error processing schedule {schedule.id} ({schedule.name}): {e}",
                        exc_info=True,
                    )

    async def _maybe_trigger_schedule(
        self,
        session: AsyncSession,
        schedule: ScanSchedule,
        now: datetime,
    ) -> None:
        """Check if a schedule is due and trigger it if so."""
        from openlabels.jobs.queue import JobQueue

        # Skip if recently triggered (within minimum interval)
        if schedule.last_run_at:
            time_since_last_run = (now - schedule.last_run_at).total_seconds()
            if time_since_last_run < self._min_trigger_interval:
                logger.debug(
                    f"Schedule {schedule.id} skipped: last ran {time_since_last_run:.0f}s ago"
                )
                return

        # Check if schedule is due based on cron expression
        if not self._is_schedule_due(schedule, now):
            return

        logger.info(
            f"Triggering schedule {schedule.id} ({schedule.name}) - cron: {schedule.cron}"
        )

        # Get the target to verify it exists and is enabled
        target = await session.get(ScanTarget, schedule.target_id)
        if not target:
            logger.warning(
                f"Schedule {schedule.id} references missing target {schedule.target_id}"
            )
            return

        if not target.enabled:
            logger.debug(
                f"Schedule {schedule.id} skipped: target {target.id} is disabled"
            )
            return

        # Create a scan job
        job = ScanJob(
            tenant_id=schedule.tenant_id,
            schedule_id=schedule.id,
            target_id=schedule.target_id,
            target_name=target.name,
            name=f"{schedule.name} (scheduled)",
            status="pending",
        )
        session.add(job)
        await session.flush()

        # Enqueue the scan job
        queue = JobQueue(session, schedule.tenant_id)
        await queue.enqueue(
            task_type="scan",
            payload={"job_id": str(job.id)},
            priority=50,  # Normal priority for scheduled scans
        )

        # Update schedule tracking
        schedule.last_run_at = now
        schedule.next_run_at = self._get_next_run_time(schedule.cron, now)

        logger.info(
            f"Schedule {schedule.id} triggered - created job {job.id}, "
            f"next run: {schedule.next_run_at}"
        )

    def _is_schedule_due(self, schedule: ScanSchedule, now: datetime) -> bool:
        """
        Check if a schedule is due to run based on its cron expression.

        A schedule is due if:
        - It has never run (last_run_at is None), OR
        - The previous cron occurrence after last_run_at is before now

        Args:
            schedule: The schedule to check
            now: Current UTC datetime

        Returns:
            True if the schedule should trigger
        """
        try:
            cron = croniter(schedule.cron, now)

            if schedule.last_run_at is None:
                # Never ran - check if there's a past occurrence
                # Get the previous occurrence from now
                prev_occurrence = cron.get_prev(datetime)
                # If prev_occurrence is within a reasonable window, trigger
                # Use a 2-hour window for first-time schedules
                time_since = (now - prev_occurrence).total_seconds()
                return time_since <= 7200  # 2 hours

            # Get the next occurrence after the last run
            cron_after_last_run = croniter(schedule.cron, schedule.last_run_at)
            next_occurrence = cron_after_last_run.get_next(datetime)

            # Schedule is due if the next occurrence after last run is <= now
            return next_occurrence <= now

        except (ValueError, KeyError, TypeError) as e:
            logger.warning(
                f"Invalid cron expression for schedule {schedule.id}: "
                f"'{schedule.cron}' - {e}"
            )
            return False

    def _get_next_run_time(
        self,
        cron_expr: str,
        from_time: datetime,
    ) -> Optional[datetime]:
        """
        Calculate the next run time for a cron expression.

        Args:
            cron_expr: Cron expression string
            from_time: Starting datetime (usually now)

        Returns:
            Next run datetime or None if invalid
        """
        try:
            cron = croniter(cron_expr, from_time)
            return cron.get_next(datetime)
        except (ValueError, KeyError, TypeError) as e:
            logger.warning(f"Failed to calculate next run time: {e}")
            return None


def parse_cron_expression(cron_expr: str) -> Optional[datetime]:
    """
    Parse a cron expression and return the next run time.

    This function provides backward compatibility with the previous
    APScheduler-based implementation.

    Args:
        cron_expr: Cron expression (e.g., "0 2 * * *")

    Returns:
        Next run datetime (UTC) or None if invalid
    """
    try:
        now = datetime.now(timezone.utc)
        cron = croniter(cron_expr, now)
        return cron.get_next(datetime)
    except (ValueError, KeyError, TypeError) as e:
        logger.info(f"Invalid cron expression '{cron_expr}': {e}")
        return None


def validate_cron_expression(cron_expr: str) -> bool:
    """
    Validate a cron expression.

    Args:
        cron_expr: Cron expression to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        croniter(cron_expr)
        return True
    except (ValueError, KeyError, TypeError):
        return False


def get_cron_description(cron_expr: str) -> str:
    """
    Get a human-readable description of a cron expression.

    Args:
        cron_expr: Cron expression

    Returns:
        Human-readable description or error message
    """
    try:
        # croniter doesn't provide descriptions, so we'll do basic parsing
        parts = cron_expr.split()
        if len(parts) != 5:
            return "Invalid cron expression"

        minute, hour, day, month, weekday = parts

        # Build a simple description
        desc_parts = []

        if minute == "0" and hour != "*":
            if hour.isdigit():
                desc_parts.append(f"at {int(hour):02d}:00")
            else:
                desc_parts.append(f"at minute 0 of hour {hour}")
        elif minute != "*" and hour != "*":
            if minute.isdigit() and hour.isdigit():
                desc_parts.append(f"at {int(hour):02d}:{int(minute):02d}")
            else:
                desc_parts.append(f"at {hour}:{minute}")
        elif minute != "*":
            desc_parts.append(f"at minute {minute}")

        if weekday != "*":
            days = {
                "0": "Sunday",
                "1": "Monday",
                "2": "Tuesday",
                "3": "Wednesday",
                "4": "Thursday",
                "5": "Friday",
                "6": "Saturday",
                "7": "Sunday",
            }
            if weekday in days:
                desc_parts.append(f"on {days[weekday]}")
            else:
                desc_parts.append(f"on weekday {weekday}")
        elif day != "*":
            desc_parts.append(f"on day {day} of the month")

        if month != "*":
            desc_parts.append(f"in month {month}")

        if not desc_parts:
            return "Every minute"

        return " ".join(desc_parts)

    except (ValueError, IndexError, TypeError):
        return "Invalid cron expression"


# Scheduler classes for backward compatibility
# The Scheduler class name is kept for imports
Scheduler = DatabaseScheduler


# Global scheduler instance
_scheduler: Optional[DatabaseScheduler] = None


def get_scheduler() -> DatabaseScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = DatabaseScheduler()
    return _scheduler


async def start_scheduler() -> bool:
    """Start the global scheduler instance."""
    scheduler = get_scheduler()
    return await scheduler.start()


async def stop_scheduler() -> None:
    """Stop the global scheduler instance."""
    scheduler = get_scheduler()
    await scheduler.stop()

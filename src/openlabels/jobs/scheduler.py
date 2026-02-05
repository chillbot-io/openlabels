"""
Cron-based job scheduler using APScheduler.

Triggers scheduled scans based on cron expressions defined in ScanSchedule.
Integrates with the job queue for distributed execution.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List, Callable, Awaitable

logger = logging.getLogger(__name__)

# APScheduler imports (optional dependency)
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.jobstores.memory import MemoryJobStore
    APSCHEDULER_AVAILABLE = True
except ImportError:
    # APScheduler not installed - scheduling functionality unavailable
    logger.debug("APScheduler not installed - cron scheduling disabled")
    APSCHEDULER_AVAILABLE = False
    AsyncIOScheduler = None
    CronTrigger = None


class Scheduler:
    """
    Manages scheduled scan jobs.

    Uses APScheduler to trigger jobs based on cron expressions.
    Jobs are enqueued to the distributed job queue for execution.

    Usage:
        scheduler = Scheduler()
        await scheduler.start()

        # Add a scheduled scan
        scheduler.add_schedule(
            schedule_id="abc123",
            cron_expression="0 2 * * *",  # Daily at 2 AM
            callback=enqueue_scan_job,
        )

        # Graceful shutdown
        await scheduler.stop()
    """

    def __init__(self):
        self._scheduler: Optional[AsyncIOScheduler] = None
        self._running = False

    @property
    def is_available(self) -> bool:
        """Check if APScheduler is installed."""
        return APSCHEDULER_AVAILABLE

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    async def start(self) -> bool:
        """
        Start the scheduler.

        Returns:
            True if started successfully
        """
        if not APSCHEDULER_AVAILABLE:
            logger.warning("APScheduler not installed. Scheduled scans disabled.")
            return False

        if self._running:
            logger.warning("Scheduler already running")
            return True

        try:
            self._scheduler = AsyncIOScheduler(
                jobstores={"default": MemoryJobStore()},
                timezone=timezone.utc,
            )
            self._scheduler.start()
            self._running = True
            logger.info("Scheduler started")
            return True
        except Exception as e:
            logger.error(f"Failed to start scheduler: {e}")
            return False

    async def stop(self) -> None:
        """Stop the scheduler gracefully."""
        if self._scheduler and self._running:
            self._scheduler.shutdown(wait=True)
            self._running = False
            logger.info("Scheduler stopped")

    def add_schedule(
        self,
        schedule_id: str,
        cron_expression: str,
        callback: Callable[..., Awaitable[None]],
        **kwargs,
    ) -> bool:
        """
        Add a scheduled job.

        Args:
            schedule_id: Unique identifier for this schedule
            cron_expression: Cron expression (e.g., "0 2 * * *")
            callback: Async function to call when triggered
            **kwargs: Arguments to pass to the callback

        Returns:
            True if added successfully
        """
        if not self._scheduler or not self._running:
            logger.warning("Scheduler not running")
            return False

        try:
            trigger = CronTrigger.from_crontab(cron_expression)
            self._scheduler.add_job(
                callback,
                trigger=trigger,
                id=schedule_id,
                replace_existing=True,
                kwargs=kwargs,
            )
            logger.info(f"Added schedule {schedule_id}: {cron_expression}")
            return True
        except Exception as e:
            logger.error(f"Failed to add schedule {schedule_id}: {e}")
            return False

    def remove_schedule(self, schedule_id: str) -> bool:
        """
        Remove a scheduled job.

        Args:
            schedule_id: ID of the schedule to remove

        Returns:
            True if removed successfully
        """
        if not self._scheduler:
            return False

        try:
            self._scheduler.remove_job(schedule_id)
            logger.info(f"Removed schedule {schedule_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to remove schedule {schedule_id}: {e}")
            return False

    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a scheduled job."""
        if not self._scheduler:
            return False
        try:
            self._scheduler.pause_job(schedule_id)
            return True
        except Exception as e:
            # Log at info level since failing to pause a schedule may affect scan timing
            logger.info(f"Failed to pause schedule {schedule_id}: {type(e).__name__}: {e}")
            return False

    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a paused scheduled job."""
        if not self._scheduler:
            return False
        try:
            self._scheduler.resume_job(schedule_id)
            return True
        except Exception as e:
            # Log at info level since failing to resume a schedule may affect scan timing
            logger.info(f"Failed to resume schedule {schedule_id}: {type(e).__name__}: {e}")
            return False

    def get_next_run(self, schedule_id: str) -> Optional[datetime]:
        """
        Get the next scheduled run time.

        Args:
            schedule_id: ID of the schedule

        Returns:
            Next run datetime or None
        """
        if not self._scheduler:
            return None
        try:
            job = self._scheduler.get_job(schedule_id)
            if job:
                return job.next_run_time
        except Exception as e:
            # Non-critical but worth logging for debugging schedule issues
            logger.debug(f"Failed to get next run for {schedule_id}: {type(e).__name__}: {e}")
        return None

    def list_schedules(self) -> List[dict]:
        """
        List all scheduled jobs.

        Returns:
            List of schedule info dicts
        """
        if not self._scheduler:
            return []

        jobs = []
        for job in self._scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "next_run": job.next_run_time,
                "trigger": str(job.trigger),
            })
        return jobs


def parse_cron_expression(cron_expr: str) -> Optional[datetime]:
    """
    Parse a cron expression and return the next run time.

    Args:
        cron_expr: Cron expression (e.g., "0 2 * * *")

    Returns:
        Next run datetime or None if invalid
    """
    if not APSCHEDULER_AVAILABLE:
        return None

    try:
        trigger = CronTrigger.from_crontab(cron_expr)
        return trigger.get_next_fire_time(None, datetime.now(timezone.utc))
    except Exception as e:
        # Log at info level since invalid cron expressions may indicate configuration issues
        logger.info(f"Invalid cron expression '{cron_expr}': {type(e).__name__}: {e}")
        return None


# Global scheduler instance
_scheduler: Optional[Scheduler] = None


def get_scheduler() -> Scheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler

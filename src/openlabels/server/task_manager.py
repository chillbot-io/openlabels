"""Background task lifecycle management.

Provides:
- ``BackgroundTaskManager``: registry that tracks, supervises, and reports
  on ``asyncio.Task`` instances created during application startup.
- ``supervised``: coroutine wrapper that auto-restarts a task on crash
  with exponential backoff.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    CRASHED = "crashed"
    RESTARTING = "restarting"


@dataclass
class TaskInfo:
    """Metadata for a managed background task."""

    name: str
    status: TaskStatus = TaskStatus.STARTING
    task: asyncio.Task | None = None
    shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)
    started_at: float = 0.0
    last_heartbeat: float = 0.0
    cycles_completed: int = 0
    errors_total: int = 0
    consecutive_failures: int = 0
    last_error: str | None = None


class BackgroundTaskManager:
    """Registry and supervisor for background ``asyncio.Task`` objects.

    Usage inside ``lifespan``::

        mgr = BackgroundTaskManager()
        app.state.task_manager = mgr

        mgr.register("flush", periodic_event_flush, interval_seconds=300, ...)
        mgr.register("harvester", periodic_event_harvest, ...)
        await mgr.start_all()
        yield  # application runs
        await mgr.stop_all()
    """

    def __init__(self, *, max_restarts: int = 5, max_backoff: float = 60.0) -> None:
        self._tasks: dict[str, TaskInfo] = {}
        self._max_restarts = max_restarts
        self._max_backoff = max_backoff

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def create_shutdown_event(self, name: str) -> asyncio.Event:
        """Create and register a shutdown event for task *name*."""
        info = self._tasks.setdefault(name, TaskInfo(name=name))
        return info.shutdown_event

    def register_task(
        self,
        name: str,
        task: asyncio.Task,
        shutdown_event: asyncio.Event | None = None,
    ) -> None:
        """Register an already-created ``asyncio.Task``."""
        info = self._tasks.get(name)
        if info is None:
            info = TaskInfo(name=name)
            self._tasks[name] = info
        info.task = task
        if shutdown_event is not None:
            info.shutdown_event = shutdown_event
        info.status = TaskStatus.RUNNING
        info.started_at = time.monotonic()
        info.last_heartbeat = time.monotonic()

    def supervised_task(
        self,
        name: str,
        coro_factory: Callable[..., Coroutine[Any, Any, None]],
        *,
        shutdown_event: asyncio.Event | None = None,
        **kwargs: Any,
    ) -> asyncio.Task:
        """Create a supervised task that auto-restarts on crash.

        *coro_factory* is called with ``shutdown_event=<event>, **kwargs``
        each time the task is (re)started.

        Returns the wrapping ``asyncio.Task``.
        """
        info = self._tasks.get(name)
        if info is None:
            info = TaskInfo(name=name)
            self._tasks[name] = info
        if shutdown_event is not None:
            info.shutdown_event = shutdown_event

        async def _supervised() -> None:
            backoff = min(1.0, self._max_backoff)
            while not info.shutdown_event.is_set():
                info.status = TaskStatus.RUNNING
                info.started_at = time.monotonic()
                info.last_heartbeat = time.monotonic()
                try:
                    await coro_factory(shutdown_event=info.shutdown_event, **kwargs)
                    # Normal exit (shutdown requested)
                    break
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    info.errors_total += 1
                    info.consecutive_failures += 1
                    info.last_error = f"{type(exc).__name__}: {exc}"
                    info.status = TaskStatus.CRASHED

                    if info.consecutive_failures > self._max_restarts:
                        logger.error(
                            "%s: exceeded %d consecutive failures — giving up",
                            name,
                            self._max_restarts,
                        )
                        break

                    logger.warning(
                        "%s: crashed (%s), restarting in %.0fs (attempt %d/%d)",
                        name,
                        info.last_error,
                        backoff,
                        info.consecutive_failures,
                        self._max_restarts,
                    )
                    info.status = TaskStatus.RESTARTING
                    try:
                        await asyncio.wait_for(
                            info.shutdown_event.wait(), timeout=backoff
                        )
                        break  # shutdown during backoff
                    except asyncio.TimeoutError:
                        pass
                    backoff = min(backoff * 2, self._max_backoff)

            info.status = TaskStatus.STOPPED

        task = asyncio.create_task(_supervised(), name=f"supervised-{name}")
        info.task = task
        return task

    # ------------------------------------------------------------------
    # Heartbeat (called by tasks to signal liveness)
    # ------------------------------------------------------------------

    def heartbeat(self, name: str, *, items_processed: int = 0) -> None:
        """Record a heartbeat from task *name*."""
        info = self._tasks.get(name)
        if info is None:
            return
        info.last_heartbeat = time.monotonic()
        info.cycles_completed += 1
        info.consecutive_failures = 0  # reset on success

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    async def stop_all(self, timeout: float = 10.0) -> None:
        """Signal all tasks to stop and wait for graceful termination."""
        # Phase 1: signal all tasks
        for info in self._tasks.values():
            if info.status in (TaskStatus.RUNNING, TaskStatus.RESTARTING):
                info.status = TaskStatus.STOPPING
                info.shutdown_event.set()

        # Phase 2: wait for graceful completion
        running = [
            info.task
            for info in self._tasks.values()
            if info.task and not info.task.done()
        ]
        if running:
            done, pending = await asyncio.wait(running, timeout=timeout)
            # Phase 3: force cancel stragglers
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.wait(pending, timeout=2.0)
                logger.warning(
                    "Force-cancelled %d background tasks after %.0fs timeout",
                    len(pending),
                    timeout,
                )

        for info in self._tasks.values():
            info.status = TaskStatus.STOPPED

    # ------------------------------------------------------------------
    # Status reporting
    # ------------------------------------------------------------------

    def get_status(self) -> list[dict[str, Any]]:
        """Return status summary for all registered tasks."""
        now = time.monotonic()
        result = []
        for info in self._tasks.values():
            entry: dict[str, Any] = {
                "name": info.name,
                "status": info.status.value,
                "cycles_completed": info.cycles_completed,
                "errors_total": info.errors_total,
                "consecutive_failures": info.consecutive_failures,
            }
            if info.started_at:
                entry["uptime_seconds"] = round(now - info.started_at, 1)
            if info.last_heartbeat:
                entry["seconds_since_heartbeat"] = round(
                    now - info.last_heartbeat, 1
                )
            if info.last_error:
                entry["last_error"] = info.last_error
            result.append(entry)
        return result

    def is_healthy(self, stale_threshold: float = 300.0) -> bool:
        """Return True if all registered tasks are healthy.

        A task is healthy if it's running and has sent a heartbeat
        within *stale_threshold* seconds.
        """
        now = time.monotonic()
        for info in self._tasks.values():
            if info.status in (TaskStatus.CRASHED, TaskStatus.STOPPING):
                return False
            if (
                info.status == TaskStatus.RUNNING
                and info.last_heartbeat
                and (now - info.last_heartbeat) > stale_threshold
            ):
                return False
        return True

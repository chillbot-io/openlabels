"""
Job queue, worker, and scheduler management.

Uses lazy imports for worker and scheduler to avoid pulling in heavy
dependencies (adapters, ML libs, etc.) when only the queue is needed.
"""

from .queue import JobCallback, JobQueue


def __getattr__(name: str):
    if name == "run_worker":
        from .worker import run_worker
        return run_worker
    if name in (
        "DatabaseScheduler",
        "Scheduler",
        "get_scheduler",
        "start_scheduler",
        "stop_scheduler",
        "parse_cron_expression",
        "validate_cron_expression",
        "get_cron_description",
    ):
        from . import scheduler as _sched
        return getattr(_sched, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "JobCallback",
    "JobQueue",
    "run_worker",
    "DatabaseScheduler",
    "Scheduler",
    "get_scheduler",
    "start_scheduler",
    "stop_scheduler",
    "parse_cron_expression",
    "validate_cron_expression",
    "get_cron_description",
]

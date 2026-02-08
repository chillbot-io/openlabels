"""Application startup and shutdown lifecycle."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI

from openlabels import __version__
from openlabels.server.config import get_settings
from openlabels.server.db import init_db, close_db
from openlabels.server.cache import get_cache_manager, close_cache
from openlabels.server.logging import setup_logging
from openlabels.server.sentry import init_sentry
from openlabels.jobs.scheduler import get_scheduler, DatabaseScheduler

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan — startup and shutdown handlers."""
    settings = get_settings()

    # Structured logging
    setup_logging(
        level=settings.logging.level,
        json_format=not settings.server.debug,
        log_file=settings.logging.file,
    )

    # Sentry error tracking (optional)
    init_sentry(settings.sentry, settings.server.environment)

    # Database
    await init_db(settings.database.url)

    # Cache (Redis with in-memory fallback)
    try:
        cache_manager = await get_cache_manager()
        if cache_manager.is_redis_connected:
            logger.info("Redis cache initialized")
        else:
            logger.info("Using in-memory cache (Redis not available)")
    except Exception as e:
        logger.warning(
            f"Cache initialization failed: {type(e).__name__}: {e} — caching disabled"
        )

    # Rate limiter (Redis with in-memory fallback)
    if settings.rate_limit.enabled:
        try:
            from openlabels.server.middleware.rate_limit import create_limiter
            import openlabels.server.app as _app_module

            configured_limiter = create_limiter()
            app.state.limiter = configured_limiter
            _app_module.limiter = configured_limiter
        except Exception as e:
            logger.warning(
                f"Rate limiter initialization failed ({type(e).__name__}: {e}) — "
                "using default in-memory limiter"
            )

    # Database-driven scheduler for cron jobs
    scheduler: DatabaseScheduler | None = None
    if settings.scheduler.enabled:
        try:
            scheduler = get_scheduler()
            started = await scheduler.start()
            if started:
                logger.info(
                    f"Scheduler started (poll interval: {settings.scheduler.poll_interval}s, "
                    f"min trigger interval: {settings.scheduler.min_trigger_interval}s)"
                )
            else:
                logger.warning("Scheduler failed to start")
        except Exception as e:
            logger.error(f"Failed to initialize scheduler: {type(e).__name__}: {e}")
    else:
        logger.info("Scheduler disabled by configuration")

    # Analytics engine (DuckDB + Parquet data lake)
    flush_task: asyncio.Task | None = None
    if settings.catalog.enabled:
        try:
            from openlabels.analytics.engine import DuckDBEngine
            from openlabels.analytics.service import AnalyticsService, DuckDBDashboardService
            from openlabels.analytics.storage import create_storage

            catalog_storage = create_storage(settings.catalog)
            engine = DuckDBEngine(
                catalog_storage.root,
                memory_limit=settings.catalog.duckdb_memory_limit,
                threads=settings.catalog.duckdb_threads,
            )
            analytics_svc = AnalyticsService(engine)
            app.state.analytics = analytics_svc
            app.state.catalog_storage = catalog_storage
            app.state.dashboard_service = DuckDBDashboardService(analytics_svc)
            logger.info("Analytics engine initialized (DuckDB + Parquet)")

            # Start periodic event flush background task
            flush_task = asyncio.create_task(
                _periodic_flush_loop(
                    app,
                    catalog_storage,
                    analytics_svc,
                    settings.catalog.event_flush_interval_seconds,
                )
            )
            logger.info(
                "Periodic event flush started (interval=%ds)",
                settings.catalog.event_flush_interval_seconds,
            )
        except Exception as e:
            logger.error(
                "Analytics engine initialization failed (%s: %s) — "
                "falling back to PostgreSQL for dashboard queries",
                type(e).__name__, e,
            )
            app.state.analytics = None
            app.state.catalog_storage = None
            app.state.dashboard_service = None
    else:
        app.state.analytics = None
        app.state.catalog_storage = None
        app.state.dashboard_service = None

    # Periodic event flush background task (Parquet data lake)
    flush_shutdown = asyncio.Event()
    flush_task: asyncio.Task | None = None
    if settings.catalog.enabled:
        try:
            from openlabels.jobs.tasks.flush import periodic_event_flush

            flush_task = asyncio.create_task(
                periodic_event_flush(
                    interval_seconds=settings.catalog.event_flush_interval_seconds,
                    shutdown_event=flush_shutdown,
                )
            )
            logger.info(
                "Periodic event flush task started (interval=%ds)",
                settings.catalog.event_flush_interval_seconds,
            )
        except Exception as e:
            logger.warning(
                "Failed to start periodic event flush: %s: %s",
                type(e).__name__, e,
            )

    logger.info(f"OpenLabels v{__version__} starting up")
    yield

    # Shutdown
    if flush_task and not flush_task.done():
        flush_task.cancel()
        try:
            await flush_task
        except asyncio.CancelledError:
            pass
        logger.info("Periodic event flush stopped")

    if scheduler and scheduler.is_running:
        try:
            await scheduler.stop()
            logger.info("Scheduler stopped")
        except Exception as e:
            logger.warning(f"Error stopping scheduler: {type(e).__name__}: {e}")

    # Stop periodic event flush
    if flush_task and not flush_task.done():
        flush_shutdown.set()
        try:
            await asyncio.wait_for(flush_task, timeout=5.0)
        except asyncio.TimeoutError:
            flush_task.cancel()
            try:
                await flush_task
            except asyncio.CancelledError:
                pass
        logger.info("Periodic event flush stopped")

    # Close analytics engine
    if getattr(app.state, "analytics", None):
        try:
            app.state.analytics.close()
            logger.info("Analytics engine closed")
        except Exception as e:
            logger.warning(f"Error closing analytics engine: {type(e).__name__}: {e}")

    await close_cache()
    await close_db()
    logger.info("OpenLabels shutting down")


async def _periodic_flush_loop(
    app: FastAPI,
    catalog_storage,
    analytics_svc,
    interval_seconds: int,
) -> None:
    """Background task that periodically flushes access events and audit logs to Parquet."""
    from openlabels.analytics.flush import flush_events_to_catalog
    from openlabels.server.db import async_session_factory

    while True:
        await asyncio.sleep(interval_seconds)
        try:
            async with async_session_factory() as session:
                counts = await flush_events_to_catalog(session, catalog_storage)

            if counts["access_events"] or counts["audit_logs"]:
                analytics_svc.refresh_views()
                logger.info(
                    "Periodic flush: %d access events, %d audit logs",
                    counts["access_events"],
                    counts["audit_logs"],
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Periodic event flush failed", exc_info=True)

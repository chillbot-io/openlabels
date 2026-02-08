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
    if settings.catalog.enabled:
        try:
            from openlabels.analytics.engine import DuckDBEngine
            from openlabels.analytics.service import AnalyticsService, DuckDBDashboardService
            from openlabels.analytics.storage import create_storage

            _storage = create_storage(settings.catalog)
            catalog_root = _storage.root
            engine = DuckDBEngine(
                catalog_root,
                memory_limit=settings.catalog.duckdb_memory_limit,
                threads=settings.catalog.duckdb_threads,
                storage_config=settings.catalog,
            )
            analytics_svc = AnalyticsService(engine)
            app.state.analytics = analytics_svc
            app.state.dashboard_service = DuckDBDashboardService(analytics_svc)
            logger.info("Analytics engine initialized (DuckDB + Parquet)")
        except Exception as e:
            logger.error(
                "Analytics engine initialization failed (%s: %s) — "
                "falling back to PostgreSQL for dashboard queries",
                type(e).__name__, e,
            )
            app.state.analytics = None
            app.state.dashboard_service = None
    else:
        app.state.analytics = None
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

    # Monitoring: populate registry cache from DB on startup
    if settings.monitoring.enabled and settings.monitoring.sync_cache_on_startup:
        try:
            if settings.monitoring.tenant_id:
                from uuid import UUID as _UUID
                from openlabels.monitoring.registry import populate_cache_from_db
                from openlabels.server.db import get_session_context

                _tenant = _UUID(settings.monitoring.tenant_id)
                async with get_session_context() as session:
                    added = await populate_cache_from_db(session, _tenant)
                    logger.info(
                        "Monitoring registry cache populated (%d entries from DB)", added,
                    )
            else:
                logger.info(
                    "Monitoring: tenant_id not configured — "
                    "skipping registry cache population from DB "
                    "(harvester will resolve files via DB queries)"
                )
        except Exception as e:
            logger.warning(
                "Failed to populate monitoring cache from DB: %s: %s",
                type(e).__name__, e,
            )

    # Event harvester background task (monitoring)
    harvester_shutdown = asyncio.Event()
    harvester_task: asyncio.Task | None = None
    if settings.monitoring.enabled:
        try:
            from openlabels.monitoring.harvester import periodic_event_harvest

            harvester_task = asyncio.create_task(
                periodic_event_harvest(
                    interval_seconds=settings.monitoring.harvest_interval_seconds,
                    max_events_per_cycle=settings.monitoring.max_events_per_cycle,
                    store_raw_events=settings.monitoring.store_raw_events,
                    enabled_providers=settings.monitoring.providers,
                    shutdown_event=harvester_shutdown,
                )
            )
            logger.info(
                "Event harvester started (interval=%ds, providers=%s)",
                settings.monitoring.harvest_interval_seconds,
                settings.monitoring.providers,
            )
        except Exception as e:
            logger.warning(
                "Failed to start event harvester: %s: %s",
                type(e).__name__, e,
            )

    logger.info(f"OpenLabels v{__version__} starting up")
    yield

    # Shutdown

    # Stop event harvester
    if harvester_task and not harvester_task.done():
        harvester_shutdown.set()
        try:
            await asyncio.wait_for(harvester_task, timeout=5.0)
        except asyncio.TimeoutError:
            harvester_task.cancel()
            try:
                await harvester_task
            except asyncio.CancelledError:
                pass
        logger.info("Event harvester stopped")

    # Monitoring: sync registry cache to DB on shutdown
    if settings.monitoring.enabled and settings.monitoring.sync_cache_on_shutdown:
        try:
            if settings.monitoring.tenant_id:
                from uuid import UUID as _UUID
                from openlabels.monitoring.registry import sync_cache_to_db
                from openlabels.server.db import get_session_context

                _tenant = _UUID(settings.monitoring.tenant_id)
                async with get_session_context() as session:
                    synced = await sync_cache_to_db(session, _tenant)
                    logger.info(
                        "Monitoring registry cache synced to DB (%d entries)", synced,
                    )
        except Exception as e:
            logger.warning(
                "Failed to sync monitoring cache to DB: %s: %s",
                type(e).__name__, e,
            )
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

"""Application startup and shutdown lifecycle."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from openlabels import __version__
from openlabels.jobs.scheduler import DatabaseScheduler, get_scheduler
from openlabels.server.cache import close_cache, get_cache_manager
from openlabels.server.config import get_settings
from openlabels.server.db import close_db, ensure_partitions, init_db
from openlabels.server.logging import setup_logging
from openlabels.server.sentry import init_sentry
from openlabels.server.task_manager import BackgroundTaskManager

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

    # Ensure monthly partitions exist for partitioned tables
    try:
        await ensure_partitions(months_ahead=3)
    except Exception as e:
        logger.warning("Partition maintenance failed: %s: %s", type(e).__name__, e)

    # Purge expired sessions and stale pending-auth entries on startup
    try:
        from openlabels.server.db import get_session_context
        from openlabels.server.session import PendingAuthStore, SessionStore

        async with get_session_context() as db_session:
            ss = SessionStore(db_session)
            ps = PendingAuthStore(db_session)
            expired = await ss.cleanup_expired()
            stale = await ps.cleanup_expired()
            if expired or stale:
                logger.info(
                    "Startup session cleanup: removed %d expired sessions, %d stale auth entries",
                    expired, stale,
                )
    except Exception as e:
        logger.warning("Startup session cleanup failed: %s: %s", type(e).__name__, e)

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
            import openlabels.server.app as _app_module
            from openlabels.server.middleware.rate_limit import create_limiter

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

    # Analytics engine (DuckDB + Parquet data lake) — always active
    try:
        from openlabels.analytics.engine import DuckDBEngine
        from openlabels.analytics.service import AnalyticsService, DuckDBDashboardService
        from openlabels.analytics.storage import create_storage

        catalog_storage = create_storage(settings.catalog)
        engine = DuckDBEngine(
            catalog_storage.root,
            memory_limit=settings.catalog.duckdb_memory_limit,
            threads=settings.catalog.duckdb_threads,
            storage_config=settings.catalog,
        )
        analytics_svc = AnalyticsService(engine)
        app.state.analytics = analytics_svc
        app.state.catalog_storage = catalog_storage
        app.state.dashboard_service = DuckDBDashboardService(analytics_svc)
        logger.info("Analytics engine initialized (DuckDB + Parquet)")
    except Exception as e:
        logger.error(
            "Analytics engine initialization failed (%s: %s) — "
            "dashboard endpoints will return 503 until resolved",
            type(e).__name__, e,
        )
        app.state.analytics = None
        app.state.catalog_storage = None
        app.state.dashboard_service = None

    # Background task manager — supervises periodic tasks, auto-restarts on crash
    task_mgr = BackgroundTaskManager()
    app.state.task_manager = task_mgr

    # Periodic event flush background task (Parquet data lake)
    flush_shutdown = asyncio.Event()
    flush_task: asyncio.Task | None = None
    try:
        from openlabels.jobs.tasks.flush import periodic_event_flush

        flush_task = task_mgr.supervised_task(
            "event_flush",
            periodic_event_flush,
            shutdown_event=flush_shutdown,
            interval_seconds=settings.catalog.event_flush_interval_seconds,
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

    # Periodic SIEM export background task
    siem_shutdown = asyncio.Event()
    siem_task: asyncio.Task | None = None
    if settings.siem_export.enabled and settings.siem_export.mode == "periodic":
        try:
            from openlabels.jobs.tasks.export import periodic_siem_export

            siem_task = task_mgr.supervised_task(
                "siem_export",
                periodic_siem_export,
                shutdown_event=siem_shutdown,
                interval_seconds=settings.siem_export.periodic_interval_seconds,
            )
            logger.info(
                "Periodic SIEM export task started (interval=%ds)",
                settings.siem_export.periodic_interval_seconds,
            )
        except Exception as e:
            logger.warning(
                "Failed to start periodic SIEM export: %s: %s",
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

    # Periodic monitoring registry cache sync (re-populates from DB)
    monitoring_sync_shutdown = asyncio.Event()
    monitoring_sync_task: asyncio.Task | None = None
    if (
        settings.monitoring.enabled
        and settings.monitoring.tenant_id
        and settings.monitoring.cache_sync_interval_seconds > 0
    ):
        try:
            from uuid import UUID as _UUID

            from openlabels.monitoring.registry import periodic_cache_sync

            monitoring_sync_task = task_mgr.supervised_task(
                "monitoring_sync",
                periodic_cache_sync,
                shutdown_event=monitoring_sync_shutdown,
                tenant_id=_UUID(settings.monitoring.tenant_id),
                interval_seconds=settings.monitoring.cache_sync_interval_seconds,
            )
            logger.info(
                "Monitoring cache periodic sync started (interval=%ds)",
                settings.monitoring.cache_sync_interval_seconds,
            )
        except Exception as e:
            logger.warning(
                "Failed to start monitoring cache sync: %s: %s",
                type(e).__name__, e,
            )

    # Event harvester background task (monitoring)
    harvester_shutdown = asyncio.Event()
    harvester_task: asyncio.Task | None = None
    if settings.monitoring.enabled:
        try:
            from openlabels.monitoring.harvester import periodic_event_harvest

            harvester_task = task_mgr.supervised_task(
                "event_harvester",
                periodic_event_harvest,
                shutdown_event=harvester_shutdown,
                interval_seconds=settings.monitoring.harvest_interval_seconds,
                max_events_per_cycle=settings.monitoring.max_events_per_cycle,
                store_raw_events=settings.monitoring.store_raw_events,
                enabled_providers=settings.monitoring.providers,
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

    # M365 cloud event harvester (separate interval, separate task)
    m365_shutdown = asyncio.Event()
    m365_task: asyncio.Task | None = None
    _graph_client = None  # Shared GraphClient for webhook provider (closed on shutdown)
    if (
        settings.monitoring.enabled
        and settings.auth.tenant_id
        and settings.auth.client_id
        and settings.auth.client_secret
        and any(
            p in settings.monitoring.providers
            for p in ("m365_audit", "graph_webhook")
        )
    ):
        try:
            from openlabels.monitoring.harvester import periodic_m365_harvest

            # Build graph_client for GraphWebhookProvider if credentials are available
            if "graph_webhook" in settings.monitoring.providers:
                try:
                    from openlabels.adapters.graph_client import GraphClient

                    _graph_client = GraphClient(
                        tenant_id=settings.auth.tenant_id,
                        client_id=settings.auth.client_id,
                        client_secret=settings.auth.client_secret,
                    )
                except Exception as _gc_err:
                    logger.error(
                        "Failed to create GraphClient for webhook provider — "
                        "graph_webhook monitoring will be unavailable: %s: %s",
                        type(_gc_err).__name__,
                        _gc_err,
                    )

            m365_task = task_mgr.supervised_task(
                "m365_harvester",
                periodic_m365_harvest,
                shutdown_event=m365_shutdown,
                tenant_id=settings.auth.tenant_id,
                client_id=settings.auth.client_id,
                client_secret=settings.auth.client_secret,
                interval_seconds=settings.monitoring.m365_harvest_interval_seconds,
                max_events_per_cycle=settings.monitoring.max_events_per_cycle,
                store_raw_events=settings.monitoring.store_raw_events,
                monitored_site_urls=settings.monitoring.m365_site_urls or None,
                graph_client=_graph_client,
                webhook_url=settings.monitoring.webhook_url,
                webhook_client_state=settings.monitoring.webhook_client_state,
                enabled_providers=settings.monitoring.providers,
            )
            logger.info(
                "M365 event harvester started (interval=%ds)",
                settings.monitoring.m365_harvest_interval_seconds,
            )
        except Exception as e:
            logger.warning(
                "Failed to start M365 event harvester: %s: %s",
                type(e).__name__, e,
            )

    # Real-time event stream manager (Phase I: USN + fanotify)
    stream_shutdown = asyncio.Event()
    stream_task: asyncio.Task | None = None
    trigger_task: asyncio.Task | None = None
    _fanotify_provider = None
    if settings.monitoring.enabled and settings.monitoring.stream_enabled:
        try:
            from openlabels.core.change_providers import (
                FanotifyChangeProvider,
                USNChangeProvider,
            )
            from openlabels.monitoring.registry import get_watched_file, get_watched_files
            from openlabels.monitoring.scan_trigger import ScanTriggerBuffer
            from openlabels.monitoring.stream_manager import EventStreamManager

            stream_providers = []
            change_providers = []
            active_paths = [str(wf.path) for wf in get_watched_files()]

            # USN Journal (Windows)
            if "usn_journal" in settings.monitoring.stream_providers:
                from openlabels.monitoring.providers.usn_journal import USNJournalProvider
                if USNJournalProvider.is_available():
                    usn = USNJournalProvider(
                        drive_letter=settings.monitoring.usn_drive_letter,
                        watched_paths=active_paths or None,
                    )
                    stream_providers.append(usn)
                    change_providers.append(USNChangeProvider())
                    logger.info("USN journal provider activated (drive %s:)", settings.monitoring.usn_drive_letter)

            # fanotify (Linux)
            if "fanotify" in settings.monitoring.stream_providers:
                from openlabels.monitoring.providers.fanotify import FanotifyProvider
                if FanotifyProvider.is_available():
                    _fanotify_provider = FanotifyProvider(
                        watched_paths=active_paths or None,
                    )
                    stream_providers.append(_fanotify_provider)
                    change_providers.append(FanotifyChangeProvider())
                    logger.info("fanotify provider activated (%d paths)", len(active_paths))

            if stream_providers:
                # Build scan trigger (optional)
                scan_trigger = None
                if settings.monitoring.scan_trigger_enabled:
                    scan_trigger = ScanTriggerBuffer(
                        registry_lookup=get_watched_file,
                        rate_limit=settings.monitoring.scan_trigger_rate_limit,
                        cooldown_seconds=settings.monitoring.scan_trigger_cooldown_seconds,
                        min_risk_tier=settings.monitoring.scan_trigger_min_risk_tier,
                    )

                manager = EventStreamManager(
                    providers=stream_providers,
                    batch_size=settings.monitoring.stream_batch_size,
                    flush_interval=settings.monitoring.stream_flush_interval,
                    scan_trigger=scan_trigger,
                    change_providers=change_providers,
                )
                app.state.stream_manager = manager
                app.state.change_providers = change_providers

                stream_task = asyncio.create_task(
                    manager.run(stream_shutdown),
                    name="event-stream-manager",
                )
                task_mgr.register_task("event_stream", stream_task, stream_shutdown)

                # Start scan trigger loop if enabled
                if scan_trigger is not None:
                    trigger_task = asyncio.create_task(
                        scan_trigger.run(stream_shutdown),
                        name="scan-trigger-buffer",
                    )
                    task_mgr.register_task("scan_trigger", trigger_task, stream_shutdown)
                    app.state.scan_trigger = scan_trigger

                logger.info(
                    "EventStreamManager started (%d providers)",
                    len(stream_providers),
                )
            else:
                logger.info(
                    "No real-time stream providers available on this platform"
                )
        except Exception as e:
            logger.warning(
                "Failed to start EventStreamManager: %s: %s",
                type(e).__name__, e,
            )

    # WebSocket pub/sub for cross-instance delivery
    try:
        from openlabels.server.routes.ws import broadcaster as ws_broadcaster

        pubsub_active = await ws_broadcaster.start()
        if pubsub_active:
            logger.info("WebSocket pub/sub: distributed mode (Redis)")
        else:
            logger.info("WebSocket pub/sub: local-only mode")
    except Exception as e:
        logger.warning(
            "WebSocket pub/sub initialization failed: %s: %s",
            type(e).__name__, e,
        )

    # Global WebSocket event bus for frontend (/ws/events)
    try:
        from openlabels.server.routes.ws_events import global_broadcaster

        global_pubsub_active = await global_broadcaster.start()
        if global_pubsub_active:
            logger.info("Global WS pub/sub: distributed mode (Redis)")
        else:
            logger.info("Global WS pub/sub: local-only mode")
    except Exception as e:
        logger.warning(
            "Global WS pub/sub initialization failed: %s: %s",
            type(e).__name__, e,
        )

    logger.info(f"OpenLabels v{__version__} starting up")
    yield

    # Shutdown

    # Stop WebSocket pub/sub
    try:
        from openlabels.server.routes.ws import broadcaster as ws_broadcaster

        await ws_broadcaster.stop()
    except Exception as e:
        logger.warning("WebSocket pub/sub shutdown error: %s: %s", type(e).__name__, e)

    # Stop global WebSocket pub/sub
    try:
        from openlabels.server.routes.ws_events import global_broadcaster

        await global_broadcaster.stop()
    except Exception as e:
        logger.warning("Global WS pub/sub shutdown error: %s: %s", type(e).__name__, e)

    # Stop all managed background tasks (supervised + registered)
    await task_mgr.stop_all(timeout=10.0)
    logger.info("Background tasks stopped")

    # Close fanotify fd
    if _fanotify_provider is not None:
        _fanotify_provider.close()

    # Close GraphClient used by webhook provider (if created)
    if _graph_client is not None:
        try:
            await _graph_client.close()
        except Exception as e:
            logger.debug("Graph client close failed: %s", e)

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

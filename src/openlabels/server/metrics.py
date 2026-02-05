"""
Prometheus metrics for OpenLabels server monitoring.

This module provides:
- HTTP request metrics (count, latency, active connections)
- Database connection pool metrics
- Job queue metrics
- A /metrics endpoint for Prometheus scraping

Usage:
    from openlabels.server.metrics import (
        setup_metrics,
        metrics_router,
        PrometheusMiddleware,
    )

    # In app setup
    setup_metrics()
    app.add_middleware(PrometheusMiddleware)
    app.include_router(metrics_router)
"""

import logging
import time
from collections.abc import Callable

from fastapi import APIRouter, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    multiprocess,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match

logger = logging.getLogger(__name__)


# =============================================================================
# Metric Definitions
# =============================================================================

# HTTP Request Metrics
HTTP_REQUESTS_TOTAL = Counter(
    "openlabels_http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "openlabels_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

HTTP_REQUESTS_IN_PROGRESS = Gauge(
    "openlabels_http_requests_in_progress",
    "Number of HTTP requests currently being processed",
    ["method", "endpoint"],
)

HTTP_REQUEST_SIZE_BYTES = Histogram(
    "openlabels_http_request_size_bytes",
    "HTTP request size in bytes",
    ["method", "endpoint"],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
)

HTTP_RESPONSE_SIZE_BYTES = Histogram(
    "openlabels_http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "endpoint"],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
)

# Database Connection Pool Metrics
DB_POOL_SIZE = Gauge(
    "openlabels_db_pool_size",
    "Current database connection pool size",
)

DB_POOL_CHECKED_IN = Gauge(
    "openlabels_db_pool_checked_in",
    "Number of database connections currently checked into the pool",
)

DB_POOL_CHECKED_OUT = Gauge(
    "openlabels_db_pool_checked_out",
    "Number of database connections currently checked out of the pool",
)

DB_POOL_OVERFLOW = Gauge(
    "openlabels_db_pool_overflow",
    "Current number of overflow connections",
)

DB_POOL_INVALID = Gauge(
    "openlabels_db_pool_invalid",
    "Number of invalid/detached connections",
)

# Job Queue Metrics
JOB_QUEUE_SIZE = Gauge(
    "openlabels_job_queue_size",
    "Number of jobs in queue by status",
    ["status"],
)

JOB_QUEUE_BY_TYPE = Gauge(
    "openlabels_job_queue_by_type",
    "Number of jobs by task type and status",
    ["task_type", "status"],
)

JOBS_PROCESSED_TOTAL = Counter(
    "openlabels_jobs_processed_total",
    "Total number of jobs processed",
    ["task_type", "status"],
)

JOB_PROCESSING_DURATION_SECONDS = Histogram(
    "openlabels_job_processing_duration_seconds",
    "Job processing duration in seconds",
    ["task_type"],
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
)

# Application Info
APP_INFO = Info(
    "openlabels",
    "OpenLabels application information",
)


# =============================================================================
# Endpoints to exclude from metrics (prevent metric explosion)
# =============================================================================

EXCLUDED_PATHS = {
    "/metrics",
    "/health",
    "/favicon.ico",
}


def get_path_template(request: Request) -> str:
    """
    Extract the path template (e.g., /api/jobs/{job_id}) from a request.

    This prevents high-cardinality metrics from path parameters.
    """
    # Try to match against the app's routes
    for route in request.app.routes:
        match, _ = route.matches(request.scope)
        if match == Match.FULL:
            return route.path if hasattr(route, "path") else request.url.path

    # Fall back to the actual path
    return request.url.path


# =============================================================================
# Prometheus Middleware
# =============================================================================

class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Middleware to collect HTTP request metrics for Prometheus.

    Tracks:
    - Request count by method, endpoint, and status code
    - Request latency distribution
    - Active connections
    - Request/response sizes
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and record metrics."""
        path = request.url.path

        # Skip excluded paths
        if path in EXCLUDED_PATHS:
            return await call_next(request)

        method = request.method
        endpoint = get_path_template(request)

        # Track request size
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                HTTP_REQUEST_SIZE_BYTES.labels(
                    method=method,
                    endpoint=endpoint,
                ).observe(int(content_length))
            except (ValueError, TypeError):
                pass

        # Track in-progress requests
        HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()

        start_time = time.perf_counter()
        status_code = 500  # Default for exceptions

        try:
            response = await call_next(request)
            status_code = response.status_code

            # Track response size
            response_size = response.headers.get("content-length")
            if response_size:
                try:
                    HTTP_RESPONSE_SIZE_BYTES.labels(
                        method=method,
                        endpoint=endpoint,
                    ).observe(int(response_size))
                except (ValueError, TypeError):
                    pass

            return response
        except Exception:
            raise
        finally:
            # Record request duration
            duration = time.perf_counter() - start_time
            HTTP_REQUEST_DURATION_SECONDS.labels(
                method=method,
                endpoint=endpoint,
            ).observe(duration)

            # Record request count
            HTTP_REQUESTS_TOTAL.labels(
                method=method,
                endpoint=endpoint,
                status_code=str(status_code),
            ).inc()

            # Decrement in-progress counter
            HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()


# =============================================================================
# Metric Collection Functions
# =============================================================================

def collect_db_pool_metrics() -> None:
    """
    Collect database connection pool metrics.

    Must be called with an active database engine.
    """
    try:
        from openlabels.server.db import get_engine

        engine = get_engine()
        if engine is None:
            return

        # SQLAlchemy async engines wrap a sync engine internally
        # Access the pool through the sync_engine
        sync_engine = engine.sync_engine
        pool = sync_engine.pool

        if hasattr(pool, "size"):
            DB_POOL_SIZE.set(pool.size())

        if hasattr(pool, "checkedin"):
            DB_POOL_CHECKED_IN.set(pool.checkedin())

        if hasattr(pool, "checkedout"):
            DB_POOL_CHECKED_OUT.set(pool.checkedout())

        if hasattr(pool, "overflow"):
            DB_POOL_OVERFLOW.set(pool.overflow())

        if hasattr(pool, "invalidatedcount"):
            DB_POOL_INVALID.set(pool.invalidatedcount())

    except Exception as e:
        logger.debug(f"Failed to collect DB pool metrics: {e}")


async def collect_job_queue_metrics() -> None:
    """
    Collect job queue metrics from the database.

    This performs a database query, so should not be called too frequently.
    """
    try:
        from sqlalchemy import func, select

        from openlabels.server.db import get_session_context
        from openlabels.server.models import JobQueue

        async with get_session_context() as session:
            # Count by status
            status_query = (
                select(JobQueue.status, func.count())
                .group_by(JobQueue.status)
            )
            result = await session.execute(status_query)
            status_counts = dict(result.all())

            for status in ["pending", "running", "completed", "failed", "cancelled"]:
                JOB_QUEUE_SIZE.labels(status=status).set(
                    status_counts.get(status, 0)
                )

            # Count by type and status
            type_query = (
                select(JobQueue.task_type, JobQueue.status, func.count())
                .group_by(JobQueue.task_type, JobQueue.status)
            )
            result = await session.execute(type_query)
            for task_type, status, count in result.all():
                JOB_QUEUE_BY_TYPE.labels(
                    task_type=task_type,
                    status=status,
                ).set(count)

    except Exception as e:
        logger.debug(f"Failed to collect job queue metrics: {e}")


def setup_metrics(version: str = "unknown") -> None:
    """
    Initialize metrics and set application info.

    Args:
        version: Application version string
    """
    from openlabels import __version__

    APP_INFO.info({
        "version": __version__,
        "name": "openlabels",
    })

    logger.info("Prometheus metrics initialized")


# =============================================================================
# Metrics Router
# =============================================================================

metrics_router = APIRouter(tags=["Metrics"])


@metrics_router.get(
    "/metrics",
    summary="Prometheus metrics endpoint",
    description="Returns Prometheus-formatted metrics for scraping",
    response_class=Response,
    include_in_schema=False,  # Hide from API docs
)
async def metrics_endpoint() -> Response:
    """
    Prometheus metrics endpoint.

    This endpoint is excluded from authentication to allow Prometheus
    to scrape metrics without credentials.

    Returns metrics in Prometheus text format.
    """
    # Collect current metrics
    collect_db_pool_metrics()

    # Note: Job queue metrics are collected asynchronously but we don't
    # await them here to keep the endpoint fast. They're updated by
    # a background task or on-demand.

    # Generate metrics output
    try:
        # Check if running in multiprocess mode (gunicorn with multiple workers)
        import os
        if "prometheus_multiproc_dir" in os.environ:
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            output = generate_latest(registry)
        else:
            output = generate_latest(REGISTRY)

        return Response(
            content=output,
            media_type=CONTENT_TYPE_LATEST,
        )
    except Exception as e:
        logger.error(f"Failed to generate metrics: {e}")
        return Response(
            content=f"# Error generating metrics: {e}\n",
            media_type="text/plain",
            status_code=500,
        )


# =============================================================================
# Helper Functions for Recording Metrics
# =============================================================================

def record_job_completion(
    task_type: str,
    status: str,
    duration_seconds: float | None = None,
) -> None:
    """
    Record job completion metrics.

    Args:
        task_type: Type of job (scan, label, etc.)
        status: Final status (completed, failed, cancelled)
        duration_seconds: Optional processing duration
    """
    JOBS_PROCESSED_TOTAL.labels(
        task_type=task_type,
        status=status,
    ).inc()

    if duration_seconds is not None:
        JOB_PROCESSING_DURATION_SECONDS.labels(
            task_type=task_type,
        ).observe(duration_seconds)

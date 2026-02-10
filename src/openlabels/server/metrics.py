"""
Prometheus metrics for OpenLabels server.

Provides metrics for monitoring:
- HTTP request counts, durations, and errors
- Active connections
- Job queue operations and depth
- Detection/scan processing statistics
"""

from prometheus_client import REGISTRY, Counter, Gauge, Histogram

# Use the default registry
registry = REGISTRY

# =============================================================================
# HTTP Request Metrics
# =============================================================================

http_requests_total = Counter(
    "openlabels_http_requests_total",
    "Total number of HTTP requests",
    labelnames=["method", "path", "status"],
    registry=registry,
)

http_request_duration_seconds = Histogram(
    "openlabels_http_request_duration_seconds",
    "HTTP request duration in seconds",
    labelnames=["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=registry,
)

http_active_connections = Gauge(
    "openlabels_http_active_connections",
    "Number of active HTTP connections",
    registry=registry,
)

# =============================================================================
# Job Queue Metrics
# =============================================================================

jobs_enqueued_total = Counter(
    "openlabels_jobs_enqueued_total",
    "Total number of jobs enqueued",
    labelnames=["task_type"],
    registry=registry,
)

jobs_completed_total = Counter(
    "openlabels_jobs_completed_total",
    "Total number of jobs completed successfully",
    labelnames=["task_type"],
    registry=registry,
)

jobs_failed_total = Counter(
    "openlabels_jobs_failed_total",
    "Total number of jobs that failed",
    labelnames=["task_type"],
    registry=registry,
)

jobs_queue_depth = Gauge(
    "openlabels_jobs_queue_depth",
    "Current number of jobs in the queue",
    labelnames=["status"],
    registry=registry,
)

# =============================================================================
# Detection/Scan Metrics
# =============================================================================

files_processed_total = Counter(
    "openlabels_files_processed_total",
    "Total number of files processed for detection",
    labelnames=["adapter"],
    registry=registry,
)

entities_found_total = Counter(
    "openlabels_entities_found_total",
    "Total number of sensitive entities detected",
    labelnames=["entity_type"],
    registry=registry,
)

processing_duration_seconds = Histogram(
    "openlabels_processing_duration_seconds",
    "File processing duration in seconds",
    labelnames=["adapter"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    registry=registry,
)


# =============================================================================
# Catalog / Data Lake Metrics
# =============================================================================

catalog_flush_lag_seconds = Gauge(
    "openlabels_catalog_flush_lag_seconds",
    "Seconds since last successful catalog event flush",
    registry=registry,
)

catalog_file_count = Gauge(
    "openlabels_catalog_file_count",
    "Number of Parquet files in the catalog",
    labelnames=["table"],
    registry=registry,
)

catalog_storage_bytes = Gauge(
    "openlabels_catalog_storage_bytes",
    "Total size of Parquet files in the catalog (bytes)",
    registry=registry,
)

catalog_flush_total = Counter(
    "openlabels_catalog_flush_total",
    "Total number of catalog flush operations",
    labelnames=["status"],
    registry=registry,
)


# =============================================================================
# Convenience Functions
# =============================================================================

def record_http_request(method: str, path: str, status: int, duration: float) -> None:
    """
    Record metrics for an HTTP request.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: Request path (normalized)
        status: HTTP status code
        duration: Request duration in seconds
    """
    # Normalize path to avoid high cardinality
    normalized_path = _normalize_path(path)
    http_requests_total.labels(method=method, path=normalized_path, status=str(status)).inc()
    http_request_duration_seconds.labels(method=method, path=normalized_path).observe(duration)


def _normalize_path(path: str) -> str:
    """
    Normalize request path to reduce cardinality.

    Replaces UUIDs and numeric IDs with placeholders.
    """
    import re

    # Replace UUIDs with placeholder
    path = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "{id}",
        path,
        flags=re.IGNORECASE,
    )
    # Replace numeric IDs with placeholder
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)

    return path


def record_job_enqueued(task_type: str) -> None:
    """Record that a job was enqueued."""
    jobs_enqueued_total.labels(task_type=task_type).inc()


def record_job_completed(task_type: str) -> None:
    """Record that a job completed successfully."""
    jobs_completed_total.labels(task_type=task_type).inc()


def record_job_failed(task_type: str) -> None:
    """Record that a job failed."""
    jobs_failed_total.labels(task_type=task_type).inc()


def update_queue_depth(pending: int, running: int, failed: int) -> None:
    """Update the job queue depth gauges."""
    jobs_queue_depth.labels(status="pending").set(pending)
    jobs_queue_depth.labels(status="running").set(running)
    jobs_queue_depth.labels(status="failed").set(failed)


def record_file_processed(adapter: str) -> None:
    """Record that a file was processed."""
    files_processed_total.labels(adapter=adapter).inc()


def record_entities_found(entity_counts: dict[str, int]) -> None:
    """Record detected entities by type."""
    for entity_type, count in entity_counts.items():
        entities_found_total.labels(entity_type=entity_type).inc(count)


def record_processing_duration(adapter: str, duration: float) -> None:
    """Record file processing duration."""
    processing_duration_seconds.labels(adapter=adapter).observe(duration)


def record_catalog_flush(success: bool) -> None:
    """Record a catalog flush attempt."""
    catalog_flush_total.labels(status="success" if success else "failure").inc()
    if success:
        catalog_flush_lag_seconds.set(0)


def update_catalog_health(storage) -> None:
    """Update catalog health gauges from storage state.

    Call periodically (e.g. after each flush) to keep metrics current.
    """
    from openlabels.analytics.flush import load_flush_state

    try:
        state = load_flush_state(storage)

        # Flush lag — time since last successful event flush
        last_flush = state.get("last_access_event_flush") or state.get("last_audit_log_flush")
        if last_flush:
            from datetime import datetime, timezone
            last_dt = datetime.fromisoformat(last_flush)
            lag = (datetime.now(timezone.utc) - last_dt).total_seconds()
            catalog_flush_lag_seconds.set(max(0, lag))

        # File counts per table
        tables = [
            "scan_results", "file_inventory", "access_events",
            "audit_log", "remediation_actions",
        ]
        for table in tables:
            files = storage.list_files(table)
            catalog_file_count.labels(table=table).set(len(files))

        # Total storage size (local only — remote would need HEAD calls)
        total_bytes = 0
        if hasattr(storage, "_base"):
            import pathlib
            base = pathlib.Path(storage._base)
            for p in base.rglob("*.parquet"):
                total_bytes += p.stat().st_size
        catalog_storage_bytes.set(total_bytes)

    except Exception:
        pass  # Metrics are best-effort

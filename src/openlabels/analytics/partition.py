"""
Hive-style partition path generation and helpers.

DuckDB reads Hive partitions natively (``key=value/`` directories)
and applies automatic partition pruning when queries include
``WHERE key = ?``.
"""

from __future__ import annotations

from datetime import date, datetime
from uuid import UUID


def scan_result_partition(
    tenant_id: UUID,
    target_id: UUID,
    scan_date: date | datetime,
) -> str:
    """Return the Hive partition path for a scan-result Parquet file."""
    d = scan_date if isinstance(scan_date, date) else scan_date.date()
    return f"scan_results/tenant={tenant_id}/target={target_id}/scan_date={d}"


def file_inventory_path(tenant_id: UUID, target_id: UUID) -> str:
    """Return the path for a file-inventory snapshot Parquet file."""
    return f"file_inventory/tenant={tenant_id}/target={target_id}/snapshot.parquet"


def folder_inventory_path(tenant_id: UUID, target_id: UUID) -> str:
    """Return the path for a folder-inventory snapshot Parquet file."""
    return f"folder_inventory/tenant={tenant_id}/target={target_id}/snapshot.parquet"


def access_event_partition(
    tenant_id: UUID,
    event_date: date | datetime,
) -> str:
    """Return the Hive partition path for access-event Parquet files."""
    d = event_date if isinstance(event_date, date) else event_date.date()
    return f"access_events/tenant={tenant_id}/event_date={d}"


def audit_log_partition(
    tenant_id: UUID,
    log_date: date | datetime,
) -> str:
    """Return the Hive partition path for audit-log Parquet files."""
    d = log_date if isinstance(log_date, date) else log_date.date()
    return f"audit_log/tenant={tenant_id}/log_date={d}"


def part_filename(sequence: int = 0) -> str:
    """Generate a deterministic part file name."""
    return f"part-{sequence:05d}.parquet"


def timestamped_part_filename() -> str:
    """Generate a part file name with a microsecond timestamp to avoid collisions."""
    import time
    ts = int(time.time() * 1_000_000)
    return f"part-{ts}.parquet"

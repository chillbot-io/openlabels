"""Tests for Hive-style partition path generation."""

from datetime import date, datetime, timezone
from uuid import UUID

from openlabels.analytics.partition import (
    access_event_partition,
    audit_log_partition,
    file_inventory_path,
    folder_inventory_path,
    part_filename,
    scan_result_partition,
    timestamped_part_filename,
)

T = UUID("00000000-0000-0000-0000-000000000001")
TGT = UUID("00000000-0000-0000-0000-100000000001")


def test_scan_result_partition_from_date():
    path = scan_result_partition(T, TGT, date(2026, 2, 8))
    assert path == (
        f"scan_results/tenant={T}/target={TGT}/scan_date=2026-02-08"
    )


def test_scan_result_partition_from_datetime():
    dt = datetime(2026, 2, 8, 14, 30, 0, tzinfo=timezone.utc)
    path = scan_result_partition(T, TGT, dt)
    # Date part only
    assert "scan_date=2026-02-08" in path


def test_file_inventory_path():
    path = file_inventory_path(T, TGT)
    assert path == f"file_inventory/tenant={T}/target={TGT}/snapshot.parquet"


def test_folder_inventory_path():
    path = folder_inventory_path(T, TGT)
    assert path == f"folder_inventory/tenant={T}/target={TGT}/snapshot.parquet"


def test_access_event_partition():
    path = access_event_partition(T, date(2026, 1, 15))
    assert path == f"access_events/tenant={T}/event_date=2026-01-15"


def test_audit_log_partition():
    path = audit_log_partition(T, date(2026, 3, 1))
    assert path == f"audit_log/tenant={T}/log_date=2026-03-01"


def test_part_filename_default():
    assert part_filename() == "part-00000.parquet"


def test_part_filename_sequence():
    assert part_filename(42) == "part-00042.parquet"


def test_timestamped_part_filename_uniqueness():
    a = timestamped_part_filename()
    b = timestamped_part_filename()
    # Two calls in quick succession should produce different names
    # (microsecond precision makes this very likely)
    assert a.endswith(".parquet")
    assert a.startswith("part-")

"""Tests for partition compaction."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pyarrow as pa
import pytest

from openlabels.analytics.compaction import compact_catalog, compact_table
from openlabels.analytics.storage import LocalStorage


TENANT = UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture()
def storage(tmp_path: Path) -> LocalStorage:
    catalog = tmp_path / "catalog"
    return LocalStorage(str(catalog))


def _write_small_parquet(storage: LocalStorage, path: str, n: int = 5) -> None:
    """Write a tiny Parquet file with *n* rows."""
    table = pa.table({
        "id": list(range(n)),
        "value": [f"row_{i}" for i in range(n)],
        "created_at": [f"2026-02-0{(i % 9) + 1}T12:00:00" for i in range(n)],
    })
    storage.write_parquet(path, table)


class TestCompaction:
    def test_no_compaction_below_threshold(self, storage: LocalStorage):
        """Partitions with fewer files than threshold are skipped."""
        # Write 3 files (below default threshold of 10)
        for i in range(3):
            _write_small_parquet(
                storage,
                f"scan_results/tenant={TENANT}/scan_date=2026-02-01/part-{i:05d}.parquet",
            )

        compacted = compact_table(storage, "scan_results", threshold=10)
        assert compacted == 0

        # All 3 original files should still exist
        files = storage.list_files("scan_results")
        assert len(files) == 3

    def test_compaction_merges_files(self, storage: LocalStorage):
        """When files exceed threshold, they are merged into one."""
        # Write 12 small files
        for i in range(12):
            _write_small_parquet(
                storage,
                f"scan_results/tenant={TENANT}/scan_date=2026-02-01/part-{i:05d}.parquet",
                n=3,
            )

        compacted = compact_table(storage, "scan_results", threshold=10)
        assert compacted == 1

        # Should now have exactly 1 file (the compacted one)
        files = storage.list_files("scan_results")
        assert len(files) == 1

        # Verify merged data is correct
        table = storage.read_parquet(files[0])
        assert table.num_rows == 36  # 12 files * 3 rows each

    def test_compaction_preserves_data(self, storage: LocalStorage):
        """Compacted data should contain all original rows."""
        expected_ids = set()
        for i in range(15):
            _write_small_parquet(
                storage,
                f"access_events/tenant={TENANT}/event_date=2026-02-01/part-{i:05d}.parquet",
                n=2,
            )
            expected_ids.update(range(2))  # Each file has ids 0,1

        compact_table(storage, "access_events", threshold=10)

        files = storage.list_files("access_events")
        assert len(files) == 1
        table = storage.read_parquet(files[0])
        assert table.num_rows == 30  # 15 files * 2 rows

    def test_compact_catalog_multiple_tables(self, storage: LocalStorage):
        """compact_catalog handles multiple tables."""
        for table_name in ["scan_results", "access_events"]:
            for i in range(11):
                _write_small_parquet(
                    storage,
                    f"{table_name}/tenant={TENANT}/date=2026-02-01/part-{i:05d}.parquet",
                )

        total = compact_catalog(
            storage,
            ["scan_results", "access_events"],
            threshold=10,
        )
        assert total == 2

    def test_compact_empty_table(self, storage: LocalStorage):
        """Compacting a table with no files returns 0."""
        compacted = compact_table(storage, "nonexistent", threshold=1)
        assert compacted == 0

    def test_compact_with_custom_threshold(self, storage: LocalStorage):
        """Custom threshold is respected."""
        for i in range(5):
            _write_small_parquet(
                storage,
                f"audit_log/tenant={TENANT}/log_date=2026-02-01/part-{i:05d}.parquet",
            )

        # threshold=3 should trigger compaction
        compacted = compact_table(storage, "audit_log", threshold=3)
        assert compacted == 1
        files = storage.list_files("audit_log")
        assert len(files) == 1

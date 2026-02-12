"""Tests for DuckDB engine: view registration, queries, partition pruning."""

import pytest

from openlabels.analytics.engine import DuckDBEngine
from openlabels.analytics.storage import LocalStorage

from tests.analytics.conftest import TENANT_A, TARGET_1, JOB_1, write_scan_results


class TestDuckDBEngine:
    def test_init_creates_views(self, engine: DuckDBEngine):
        """Engine registers views on init; querying empty views returns 0 rows."""
        rows = engine.fetch_all("SELECT count(*) AS cnt FROM scan_results")
        assert rows[0]["cnt"] == 0

    def test_fetch_all_with_data(self, storage: LocalStorage, engine: DuckDBEngine):
        write_scan_results(storage)
        engine.refresh_views()

        rows = engine.fetch_all("SELECT count(*) AS cnt FROM scan_results")
        assert rows[0]["cnt"] == 2  # sensitive files only

    def test_fetch_all_columns(self, storage: LocalStorage, engine: DuckDBEngine):
        write_scan_results(storage)
        engine.refresh_views()

        rows = engine.fetch_all(
            "SELECT file_name, risk_score FROM scan_results ORDER BY risk_score DESC"
        )
        assert len(rows) == 2
        assert rows[0]["risk_score"] == 85  # CRITICAL file first
        assert all("file_name" in r for r in rows)

    def test_parameterized_query(self, storage: LocalStorage, engine: DuckDBEngine):
        write_scan_results(storage)
        engine.refresh_views()

        rows = engine.fetch_all(
            "SELECT file_name FROM scan_results WHERE risk_score > ?", [50]
        )
        assert len(rows) == 2  # 85 and 60

    def test_fetch_arrow(self, storage: LocalStorage, engine: DuckDBEngine):
        write_scan_results(storage)
        engine.refresh_views()

        table = engine.fetch_arrow("SELECT * FROM scan_results")
        assert table.num_rows == 2
        assert "file_path" in table.column_names

    def test_partition_pruning(self, storage: LocalStorage, engine: DuckDBEngine):
        """Tenant filter should only return matching data."""
        write_scan_results(storage, tenant_id=TENANT_A)

        from tests.analytics.conftest import TENANT_B
        write_scan_results(
            storage,
            tenant_id=TENANT_B,
            target_id=TARGET_1,
            scan_date="2026-02-02",
        )
        engine.refresh_views()

        all_rows = engine.fetch_all("SELECT count(*) AS cnt FROM scan_results")
        assert all_rows[0]["cnt"] == 4  # 2 per tenant (sensitive only)

        filtered = engine.fetch_all(
            "SELECT count(*) AS cnt FROM scan_results WHERE tenant = ?",
            [str(TENANT_A)],
        )
        assert filtered[0]["cnt"] == 2

    def test_refresh_views_picks_up_new_data(
        self, storage: LocalStorage, engine: DuckDBEngine,
    ):
        rows = engine.fetch_all("SELECT count(*) AS cnt FROM scan_results")
        assert rows[0]["cnt"] == 0

        write_scan_results(storage)
        engine.refresh_views()

        rows = engine.fetch_all("SELECT count(*) AS cnt FROM scan_results")
        assert rows[0]["cnt"] == 2

    def test_close_and_reuse_raises(self, catalog_dir):
        e = DuckDBEngine(str(catalog_dir), memory_limit="128MB", threads=1)
        e.close()
        # DuckDB connection is closed; further queries should fail
        with pytest.raises(Exception):
            e.fetch_all("SELECT 1")

    def test_aggregate_query(self, storage: LocalStorage, engine: DuckDBEngine):
        write_scan_results(storage)
        engine.refresh_views()

        rows = engine.fetch_all("""
            SELECT risk_tier, count(*) AS cnt
            FROM scan_results
            GROUP BY risk_tier
            ORDER BY cnt DESC
        """)
        tiers = {r["risk_tier"]: r["cnt"] for r in rows}
        assert tiers["CRITICAL"] == 1
        assert tiers["HIGH"] == 1

    def test_invalid_memory_limit_raises(self, catalog_dir):
        with pytest.raises(ValueError, match="Invalid duckdb_memory_limit"):
            DuckDBEngine(str(catalog_dir), memory_limit="DROP TABLE x;--")

    def test_invalid_threads_raises(self, catalog_dir):
        with pytest.raises(ValueError, match="duckdb_threads must be"):
            DuckDBEngine(str(catalog_dir), threads=-1)

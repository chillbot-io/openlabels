"""Tests for AnalyticsService (async wrapper) and DuckDBDashboardService."""

from datetime import datetime, timedelta, timezone

import pytest

from openlabels.analytics.service import (
    AnalyticsService,
    DuckDBDashboardService,
    EntityTrendsData,
    FileStats,
    HeatmapFileRow,
    TrendPoint,
)
from openlabels.analytics.storage import LocalStorage

from tests.analytics.conftest import (
    TENANT_A,
    TARGET_1,
    JOB_1,
    write_access_events,
    write_scan_results,
)


# ── AnalyticsService (low-level async wrapper) ─────────────────────

@pytest.mark.asyncio
class TestAnalyticsService:
    async def test_query_empty(self, analytics: AnalyticsService):
        rows = await analytics.query("SELECT count(*) AS cnt FROM scan_results")
        assert rows[0]["cnt"] == 0

    async def test_query_with_data(
        self, storage: LocalStorage, analytics: AnalyticsService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        rows = await analytics.query("SELECT count(*) AS cnt FROM scan_results")
        assert rows[0]["cnt"] == 3

    async def test_query_arrow(
        self, storage: LocalStorage, analytics: AnalyticsService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        table = await analytics.query_arrow("SELECT * FROM scan_results")
        assert table.num_rows == 3


# ── DuckDBDashboardService ──────────────────────────────────────────

@pytest.mark.asyncio
class TestDuckDBDashboardService:
    async def test_get_file_stats_empty(
        self, dashboard_service: DuckDBDashboardService,
    ):
        stats = await dashboard_service.get_file_stats(TENANT_A)
        assert stats.total_files == 0
        assert stats.files_with_pii == 0

    async def test_get_file_stats_with_data(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        stats = await dashboard_service.get_file_stats(TENANT_A)
        assert stats.total_files == 3
        assert stats.files_with_pii == 2  # report.pdf + payroll.xlsx
        assert stats.labels_applied == 1  # report.pdf
        assert stats.critical_files == 1
        assert stats.high_files == 1

    async def test_get_trends(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 3, 1, tzinfo=timezone.utc)

        points = await dashboard_service.get_trends(TENANT_A, start, end)
        assert isinstance(points, list)
        assert len(points) >= 1  # At least the scan_date=2026-02-01 partition
        total_scanned = sum(p.files_scanned for p in points)
        assert total_scanned == 3

    async def test_get_entity_trends(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 3, 1, tzinfo=timezone.utc)

        data = await dashboard_service.get_entity_trends(
            TENANT_A, start, end, top_n=5,
        )
        assert isinstance(data, EntityTrendsData)
        assert not data.truncated
        # We have SSN and EMAIL and NAME in test data
        assert "Total" in data.series

    async def test_get_access_heatmap(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_access_events(storage)
        analytics.refresh_views()

        since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        heatmap = await dashboard_service.get_access_heatmap(TENANT_A, since)

        assert len(heatmap) == 7
        assert len(heatmap[0]) == 24
        # At least one cell should be non-zero
        total = sum(sum(row) for row in heatmap)
        assert total > 0

    async def test_get_heatmap_data(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        rows, total = await dashboard_service.get_heatmap_data(TENANT_A, limit=100)
        assert total == 3
        assert len(rows) == 3
        assert all(isinstance(r, HeatmapFileRow) for r in rows)
        # Sorted by risk_score desc
        assert rows[0].risk_score >= rows[-1].risk_score

    async def test_get_heatmap_data_limit(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        rows, total = await dashboard_service.get_heatmap_data(TENANT_A, limit=1)
        assert total == 3
        assert len(rows) == 1
        assert rows[0].risk_score == 85  # highest risk file

    async def test_tenant_isolation(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        """Data for TENANT_B must not leak into TENANT_A queries."""
        from tests.analytics.conftest import TENANT_B

        write_scan_results(storage, tenant_id=TENANT_A)
        write_scan_results(
            storage,
            tenant_id=TENANT_B,
            scan_date="2026-02-02",
        )
        analytics.refresh_views()

        stats_a = await dashboard_service.get_file_stats(TENANT_A)
        stats_b = await dashboard_service.get_file_stats(TENANT_B)
        assert stats_a.total_files == 3
        assert stats_b.total_files == 3  # same shape, but distinct

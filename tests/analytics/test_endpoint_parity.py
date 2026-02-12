"""Endpoint parity tests — verify DuckDB service returns the same shape
as the PostgreSQL implementation for all migrated dashboard methods.

These tests exercise the DuckDB-backed :class:`DuckDBDashboardService`
with known Parquet data and validate that the returned DTOs match the
expected structure and semantics.
"""

from datetime import datetime, timezone

import pytest

from openlabels.analytics.service import (
    AccessStats,
    AnalyticsService,
    DuckDBDashboardService,
    RemediationStats,
)
from openlabels.analytics.storage import LocalStorage

from tests.analytics.conftest import (
    TENANT_A,
    write_access_events,
    write_remediation_actions,
    write_scan_results,
)


@pytest.mark.asyncio
class TestAccessStatsParity:
    """Test get_access_stats returns correct aggregations."""

    async def test_access_stats_empty(
        self, dashboard_service: DuckDBDashboardService,
    ):
        stats = await dashboard_service.get_access_stats(TENANT_A)
        assert isinstance(stats, AccessStats)
        assert stats.total_events == 0
        assert stats.events_last_24h == 0
        assert stats.events_last_7d == 0
        assert stats.by_action == {}
        assert stats.top_users == []

    async def test_access_stats_with_data(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_access_events(storage)
        analytics.refresh_views()

        stats = await dashboard_service.get_access_stats(TENANT_A)
        assert isinstance(stats, AccessStats)
        assert stats.total_events == 5
        # by_action should have "read" since all test events are reads
        assert "read" in stats.by_action
        assert stats.by_action["read"] == 5
        # top_users should contain "alice"
        assert len(stats.top_users) >= 1
        assert stats.top_users[0]["user"] == "alice"
        assert stats.top_users[0]["count"] == 5


@pytest.mark.asyncio
class TestRemediationStatsParity:
    """Test get_remediation_stats returns correct aggregations."""

    async def test_remediation_stats_empty(
        self, dashboard_service: DuckDBDashboardService,
    ):
        stats = await dashboard_service.get_remediation_stats(TENANT_A)
        assert isinstance(stats, RemediationStats)
        assert stats.total_actions == 0

    async def test_remediation_stats_with_data(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
        dashboard_service: DuckDBDashboardService,
    ):
        write_remediation_actions(storage)
        analytics.refresh_views()

        stats = await dashboard_service.get_remediation_stats(TENANT_A)
        assert isinstance(stats, RemediationStats)
        assert stats.total_actions == 4
        assert stats.by_type["quarantine"] == 2
        assert stats.by_type["lockdown"] == 1
        assert stats.by_type["rollback"] == 1
        assert stats.by_status["completed"] == 2
        assert stats.by_status["failed"] == 1
        assert stats.by_status["pending"] == 1


@pytest.mark.asyncio
class TestExportParity:
    """Verify DuckDB export query returns the same columns as PG streaming."""

    async def test_export_query_returns_expected_columns(
        self,
        storage: LocalStorage,
        analytics: AnalyticsService,
    ):
        write_scan_results(storage)
        analytics.refresh_views()

        rows = await analytics.query(
            """
            SELECT file_path, file_name, risk_score, risk_tier,
                   total_entities, exposure_level, owner,
                   current_label_name, label_applied
            FROM scan_results
            WHERE tenant = ?
            ORDER BY risk_score DESC
            """,
            [str(TENANT_A)],
        )

        assert len(rows) == 2  # sensitive files only
        # Check expected columns present in each row
        expected_keys = {
            "file_path", "file_name", "risk_score", "risk_tier",
            "total_entities", "exposure_level", "owner",
            "current_label_name", "label_applied",
        }
        for r in rows:
            assert expected_keys <= set(r.keys()), f"Missing keys: {expected_keys - set(r.keys())}"

        # Verify sort order (risk_score DESC)
        assert rows[0]["risk_score"] >= rows[-1]["risk_score"]

        # Verify first result is the highest-risk file
        assert rows[0]["file_path"] == "/data/docs/report.pdf"
        assert rows[0]["risk_score"] == 85

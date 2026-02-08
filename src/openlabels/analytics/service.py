"""
Async analytics service — wraps :class:`DuckDBEngine` for FastAPI.

DuckDB is not async-native, so every query is dispatched to a small
:class:`~concurrent.futures.ThreadPoolExecutor`.

This module also defines the :class:`DashboardQueryService` protocol
used by route handlers.  Two implementations exist:

* :class:`DuckDBDashboardService` — reads from Parquet via DuckDB
* :class:`PostgresDashboardService` (in ``dashboard_pg.py``) — the
  existing PostgreSQL implementation, extracted for parity.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from openlabels.analytics.engine import DuckDBEngine

logger = logging.getLogger(__name__)


# ── Data transfer objects ─────────────────────────────────────────────

@dataclass
class FileStats:
    """Aggregated file statistics for the dashboard."""
    total_files: int = 0
    files_with_pii: int = 0
    labels_applied: int = 0
    critical_files: int = 0
    high_files: int = 0


@dataclass
class TrendPoint:
    date: str
    files_scanned: int = 0
    files_with_pii: int = 0
    labels_applied: int = 0


@dataclass
class EntityTrendsData:
    series: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    truncated: bool = False
    total_records: int = 0


@dataclass
class HeatmapFileRow:
    file_path: str
    risk_score: int
    entity_counts: dict[str, int]


@dataclass
class AccessStats:
    """Aggregated access event statistics."""
    total_events: int = 0
    events_last_24h: int = 0
    events_last_7d: int = 0
    by_action: dict[str, int] = field(default_factory=dict)
    top_users: list[dict] = field(default_factory=list)


@dataclass
class RemediationStats:
    """Aggregated remediation action statistics."""
    total_actions: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)


# ── Protocol ──────────────────────────────────────────────────────────

@runtime_checkable
class DashboardQueryService(Protocol):
    """Interface for dashboard analytical queries."""

    async def get_file_stats(self, tenant_id: UUID) -> FileStats: ...

    async def get_trends(
        self, tenant_id: UUID, start_date: datetime, end_date: datetime,
    ) -> list[TrendPoint]: ...

    async def get_entity_trends(
        self, tenant_id: UUID, start_date: datetime, end_date: datetime,
        *, top_n: int = 6,
    ) -> EntityTrendsData: ...

    async def get_access_heatmap(
        self, tenant_id: UUID, since: datetime,
    ) -> list[list[int]]: ...

    async def get_heatmap_data(
        self, tenant_id: UUID, *, job_id: UUID | None = None, limit: int = 10_000,
    ) -> tuple[list[HeatmapFileRow], int]: ...

    async def get_access_stats(
        self, tenant_id: UUID,
    ) -> AccessStats: ...

    async def get_remediation_stats(
        self, tenant_id: UUID,
    ) -> RemediationStats: ...


# ── Low-level async wrapper ──────────────────────────────────────────

class AnalyticsService:
    """Async wrapper around :class:`DuckDBEngine`."""

    def __init__(self, engine: DuckDBEngine, max_workers: int = 4) -> None:
        self._engine = engine
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="duckdb",
        )

    async def query(
        self,
        sql: str,
        params: dict[str, Any] | list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Run an analytical query in a background thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._engine.fetch_all(sql, params),
        )

    async def query_arrow(self, sql: str, params=None):
        """Run a query and return a PyArrow Table (zero-copy)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._engine.fetch_arrow(sql, params),
        )

    def refresh_views(self) -> None:
        """Re-register DuckDB views after new Parquet files are written."""
        self._engine.refresh_views()

    def close(self) -> None:
        self._executor.shutdown(wait=False)
        self._engine.close()


# ── DuckDB-backed dashboard service ──────────────────────────────────

class DuckDBDashboardService:
    """Implements :class:`DashboardQueryService` over DuckDB + Parquet."""

    def __init__(self, analytics: AnalyticsService) -> None:
        self._a = analytics

    async def _safe_query(
        self, sql: str, params=None, default=None,
    ) -> list[dict[str, Any]]:
        """Execute a query, returning *default* if the view is a stub table."""
        try:
            return await self._a.query(sql, params)
        except Exception as exc:
            # Stub tables only have a ``placeholder`` column — any real
            # query will fail with a BinderException.  Return empty.
            if "not found in FROM clause" in str(exc) or "placeholder" in str(exc):
                return default if default is not None else []
            raise

    async def get_file_stats(self, tenant_id: UUID) -> FileStats:
        rows = await self._safe_query(
            """
            SELECT
                count(*)                                        AS total_files,
                count(*) FILTER (WHERE total_entities > 0)      AS files_with_pii,
                count(*) FILTER (WHERE label_applied)           AS labels_applied,
                count(*) FILTER (WHERE risk_tier = 'CRITICAL')  AS critical_files,
                count(*) FILTER (WHERE risk_tier = 'HIGH')      AS high_files
            FROM scan_results
            WHERE tenant = ?
            """,
            [str(tenant_id)],
        )
        if not rows:
            return FileStats()
        r = rows[0]
        return FileStats(
            total_files=r["total_files"],
            files_with_pii=r["files_with_pii"],
            labels_applied=r["labels_applied"],
            critical_files=r["critical_files"],
            high_files=r["high_files"],
        )

    async def get_trends(
        self,
        tenant_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> list[TrendPoint]:
        rows = await self._safe_query(
            """
            SELECT
                scan_date,
                count(*)                                       AS files_scanned,
                count(*) FILTER (WHERE total_entities > 0)     AS files_with_pii,
                count(*) FILTER (WHERE label_applied)          AS labels_applied
            FROM scan_results
            WHERE tenant = ? AND scan_date >= ? AND scan_date <= ?
            GROUP BY scan_date
            ORDER BY scan_date
            """,
            [str(tenant_id), start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d")],
        )
        return [
            TrendPoint(
                date=str(r["scan_date"]),
                files_scanned=r["files_scanned"],
                files_with_pii=r["files_with_pii"],
                labels_applied=r["labels_applied"],
            )
            for r in rows
        ]

    async def get_entity_trends(
        self,
        tenant_id: UUID,
        start_date: datetime,
        end_date: datetime,
        *,
        top_n: int = 6,
    ) -> EntityTrendsData:
        # DuckDB can unnest MAP columns natively — no sampling needed
        rows = await self._safe_query(
            """
            WITH expanded AS (
                SELECT
                    scan_date,
                    unnest(map_keys(entity_counts))   AS entity_type,
                    unnest(map_values(entity_counts))  AS entity_count
                FROM scan_results
                WHERE tenant = ?
                  AND scan_date >= ?
                  AND scan_date <= ?
                  AND total_entities > 0
            ),
            top_types AS (
                SELECT entity_type, sum(entity_count) AS total
                FROM expanded
                GROUP BY entity_type
                ORDER BY total DESC
                LIMIT ?
            )
            SELECT
                e.scan_date,
                e.entity_type,
                sum(e.entity_count) AS count
            FROM expanded e
            JOIN top_types t ON e.entity_type = t.entity_type
            GROUP BY e.scan_date, e.entity_type
            ORDER BY e.scan_date, e.entity_type
            """,
            [
                str(tenant_id),
                start_date.strftime("%Y-%m-%d"),
                end_date.strftime("%Y-%m-%d"),
                top_n,
            ],
        )

        # Also get daily totals
        total_rows = await self._safe_query(
            """
            SELECT scan_date, sum(total_entities) AS total
            FROM scan_results
            WHERE tenant = ?
              AND scan_date >= ?
              AND scan_date <= ?
              AND total_entities > 0
            GROUP BY scan_date
            ORDER BY scan_date
            """,
            [str(tenant_id), start_date.strftime("%Y-%m-%d"), end_date.strftime("%Y-%m-%d")],
        )

        series: dict[str, list[tuple[str, int]]] = {"Total": []}
        for r in total_rows:
            series["Total"].append((str(r["scan_date"]), r["total"]))

        for r in rows:
            et = r["entity_type"]
            if et not in series:
                series[et] = []
            series[et].append((str(r["scan_date"]), r["count"]))

        return EntityTrendsData(series=series, truncated=False, total_records=len(rows))

    async def get_access_heatmap(
        self, tenant_id: UUID, since: datetime,
    ) -> list[list[int]]:
        rows = await self._safe_query(
            """
            SELECT
                dayofweek(event_time) AS day_of_week,
                hour(event_time)     AS hour,
                count(*)             AS access_count
            FROM access_events
            WHERE tenant = ? AND event_time >= ?
            GROUP BY day_of_week, hour
            ORDER BY day_of_week, hour
            """,
            [str(tenant_id), since.isoformat()],
        )
        heatmap = [[0] * 24 for _ in range(7)]
        for r in rows:
            # DuckDB dayofweek: 0=Sunday, 1=Monday ... 6=Saturday
            # We want 0=Monday ... 6=Sunday
            day = (r["day_of_week"] - 1) % 7
            hour = r["hour"]
            if 0 <= day < 7 and 0 <= hour < 24:
                heatmap[day][hour] = r["access_count"]
        return heatmap

    async def get_heatmap_data(
        self,
        tenant_id: UUID,
        *,
        job_id: UUID | None = None,
        limit: int = 10_000,
    ) -> tuple[list[HeatmapFileRow], int]:
        # Total count
        count_params: list = [str(tenant_id)]
        count_sql = "SELECT count(*) AS cnt FROM scan_results WHERE tenant = ?"
        if job_id:
            count_sql += " AND job_id = ?"
            count_params.append(job_id.bytes)

        count_rows = await self._safe_query(count_sql, count_params)
        total = count_rows[0]["cnt"] if count_rows else 0

        # Fetch rows
        params: list = [str(tenant_id)]
        sql = """
            SELECT file_path, risk_score, entity_counts
            FROM scan_results
            WHERE tenant = ?
        """
        if job_id:
            sql += " AND job_id = ?"
            params.append(job_id.bytes)
        sql += " ORDER BY risk_score DESC LIMIT ?"
        params.append(limit)

        rows = await self._safe_query(sql, params)
        result = []
        for r in rows:
            ec = r.get("entity_counts")
            if isinstance(ec, dict):
                entity_counts = ec
            elif isinstance(ec, list):
                # DuckDB MAP → list of {'key': k, 'value': v}
                entity_counts = {item["key"]: item["value"] for item in ec}
            else:
                entity_counts = {}
            result.append(HeatmapFileRow(
                file_path=r["file_path"],
                risk_score=r["risk_score"] or 0,
                entity_counts=entity_counts,
            ))
        return result, total

    async def get_access_stats(self, tenant_id: UUID) -> AccessStats:
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        rows = await self._safe_query(
            """
            SELECT
                count(*)                                                       AS total_events,
                count(*) FILTER (WHERE event_time >= ? ::TIMESTAMP - INTERVAL 1 DAY)  AS events_last_24h,
                count(*) FILTER (WHERE event_time >= ? ::TIMESTAMP - INTERVAL 7 DAY)  AS events_last_7d
            FROM access_events
            WHERE tenant = ?
            """,
            [now_iso, now_iso, str(tenant_id)],
        )
        total_events = rows[0]["total_events"] if rows else 0
        events_24h = rows[0]["events_last_24h"] if rows else 0
        events_7d = rows[0]["events_last_7d"] if rows else 0

        action_rows = await self._safe_query(
            """
            SELECT action, count(*) AS cnt
            FROM access_events
            WHERE tenant = ?
            GROUP BY action
            """,
            [str(tenant_id)],
        )
        by_action = {r["action"]: r["cnt"] for r in action_rows}

        user_rows = await self._safe_query(
            """
            SELECT user_name, count(*) AS cnt
            FROM access_events
            WHERE tenant = ? AND user_name IS NOT NULL
            GROUP BY user_name
            ORDER BY cnt DESC
            LIMIT 10
            """,
            [str(tenant_id)],
        )
        top_users = [{"user": r["user_name"], "count": r["cnt"]} for r in user_rows]

        return AccessStats(
            total_events=total_events,
            events_last_24h=events_24h,
            events_last_7d=events_7d,
            by_action=by_action,
            top_users=top_users,
        )

    async def get_remediation_stats(self, tenant_id: UUID) -> RemediationStats:
        rows = await self._safe_query(
            """
            SELECT
                count(*)                                              AS total,
                count(*) FILTER (WHERE action_type = 'quarantine')    AS quarantine_count,
                count(*) FILTER (WHERE action_type = 'lockdown')      AS lockdown_count,
                count(*) FILTER (WHERE action_type = 'rollback')      AS rollback_count,
                count(*) FILTER (WHERE status = 'completed')          AS completed,
                count(*) FILTER (WHERE status = 'failed')             AS failed,
                count(*) FILTER (WHERE status = 'pending')            AS pending_count
            FROM remediation_actions
            WHERE tenant = ?
            """,
            [str(tenant_id)],
        )
        if not rows:
            return RemediationStats()
        r = rows[0]
        return RemediationStats(
            total_actions=r["total"],
            by_type={
                "quarantine": r["quarantine_count"],
                "lockdown": r["lockdown_count"],
                "rollback": r["rollback_count"],
            },
            by_status={
                "completed": r["completed"],
                "failed": r["failed"],
                "pending": r["pending_count"],
            },
        )

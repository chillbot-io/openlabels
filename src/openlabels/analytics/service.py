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


@dataclass
class ComplianceStats:
    """Policy compliance statistics for the dashboard."""
    total_results: int = 0
    results_with_violations: int = 0
    compliance_pct: float = 100.0
    violations_by_framework: dict[str, int] = field(default_factory=dict)
    violations_by_severity: dict[str, int] = field(default_factory=dict)


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

    async def get_compliance_stats(
        self, tenant_id: UUID,
    ) -> ComplianceStats: ...


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

    async def export_scan_results(
        self,
        tenant_id: UUID,
        *,
        job_id: UUID | None = None,
        risk_tier: str | None = None,
        has_label: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Export scan results from Parquet with filter pushdown.

        All filters are applied in the DuckDB query so only matching
        rows are returned — much cheaper than post-filtering in Python.
        """
        conditions = ["tenant = ?"]
        params: list[Any] = [str(tenant_id)]

        if job_id:
            conditions.append(f"job_id = decode('{job_id.hex}', 'hex')")
        if risk_tier:
            conditions.append("risk_tier = ?")
            params.append(risk_tier)
        if has_label is True:
            conditions.append("label_applied = true")
        elif has_label is False:
            conditions.append("label_applied = false")

        where = " AND ".join(conditions)
        sql = f"""
            SELECT
                file_path, file_name, risk_score, risk_tier,
                total_entities, exposure_level, owner,
                current_label_name, label_applied
            FROM scan_results
            WHERE {where}
            ORDER BY risk_score DESC
        """
        try:
            return await self.query(sql, params)
        except Exception as exc:
            # Stub tables (no Parquet files) only have a placeholder column
            if "not found in FROM clause" in str(exc) or "placeholder" in str(exc):
                return []
            raise

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
        # scan_results parquet only contains sensitive files now, so
        # count(*) == files_with_pii.  total_files is set to 0 here;
        # callers that need the true total should overlay from ScanJob.
        rows = await self._safe_query(
            """
            SELECT
                count(*)                                        AS files_with_pii,
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
            total_files=0,  # must be overlaid from ScanJob by caller
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
        # scan_results parquet only holds sensitive files now, so
        # count(*) == files_with_pii.  files_scanned is set to 0;
        # callers that need the true total should overlay from ScanJob.
        rows = await self._safe_query(
            """
            SELECT
                scan_date,
                count(*)                                       AS files_with_pii,
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
                files_scanned=0,  # must be overlaid from ScanJob by caller
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
        # Use isodow() for ISO weekday numbering (1=Mon ... 7=Sun) to
        # match PostgreSQL's EXTRACT(isodow ...) used in the PG fallback.
        rows = await self._safe_query(
            """
            SELECT
                isodow(event_time)   AS day_of_week,
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
            # isodow: 1=Monday ... 7=Sunday → index 0=Monday ... 6=Sunday
            day = int(r["day_of_week"]) - 1
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
        # job_id is stored as binary(16) in Parquet; DuckDB can compare
        # binary columns to hex-encoded blob literals via decode().
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

    async def get_compliance_stats(self, tenant_id: UUID) -> ComplianceStats:
        import json as _json

        count_rows = await self._safe_query(
            """
            SELECT
                count(*)                                                   AS total,
                count(*) FILTER (WHERE policy_violations IS NOT NULL)       AS violated
            FROM scan_results
            WHERE tenant = ?
            """,
            [str(tenant_id)],
        )
        total = count_rows[0]["total"] if count_rows else 0
        violated = count_rows[0]["violated"] if count_rows else 0
        if total == 0:
            return ComplianceStats()

        compliance_pct = round(((total - violated) / total) * 100, 2)

        # Parse JSONB stored as JSON string in Parquet to build breakdowns
        detail_rows = await self._safe_query(
            """
            SELECT policy_violations
            FROM scan_results
            WHERE tenant = ? AND policy_violations IS NOT NULL
            LIMIT 500
            """,
            [str(tenant_id)],
        )
        by_framework: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for r in detail_rows:
            raw = r.get("policy_violations")
            if not raw:
                continue
            violations = _json.loads(raw) if isinstance(raw, str) else raw
            for v in violations:
                fw = v.get("framework", "unknown")
                by_framework[fw] = by_framework.get(fw, 0) + 1
                sev = v.get("severity", "unknown")
                by_severity[sev] = by_severity.get(sev, 0) + 1

        return ComplianceStats(
            total_results=total,
            results_with_violations=violated,
            compliance_pct=compliance_pct,
            violations_by_framework=by_framework,
            violations_by_severity=by_severity,
        )

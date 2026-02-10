"""
PostgreSQL implementation of :class:`DashboardQueryService`.

This wraps the *existing* dashboard SQL queries behind the protocol so
that route handlers can call the same interface regardless of backend.
When ``catalog.enabled`` is False (the default) this implementation is
used — behaviour is identical to the pre-OLAP codebase.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Date, and_, case, cast, extract, func, select

from openlabels.analytics.service import (
    AccessStats,
    ComplianceStats,
    EntityTrendsData,
    FileStats,
    HeatmapFileRow,
    RemediationStats,
    TrendPoint,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class PostgresDashboardService:
    """Implements :class:`DashboardQueryService` using the existing PostgreSQL queries."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # -- helpers -----------------------------------------------------------

    async def _get_session(self) -> AsyncSession:
        """Return the request-scoped SQLAlchemy session."""
        return self._session

    # -- protocol methods --------------------------------------------------

    async def get_file_stats(self, tenant_id: UUID) -> FileStats:
        from openlabels.server.models import ScanResult

        session = await self._get_session()
        q = select(
            func.count().label("total_files"),
            func.sum(case((ScanResult.total_entities > 0, 1), else_=0)).label("files_with_pii"),
            func.sum(case((ScanResult.label_applied == True, 1), else_=0)).label("labels_applied"),  # noqa: E712
            func.sum(case((ScanResult.risk_tier == "CRITICAL", 1), else_=0)).label("critical_files"),
            func.sum(case((ScanResult.risk_tier == "HIGH", 1), else_=0)).label("high_files"),
        ).where(ScanResult.tenant_id == tenant_id)

        result = await session.execute(q)
        row = result.one()
        return FileStats(
            total_files=row.total_files or 0,
            files_with_pii=row.files_with_pii or 0,
            labels_applied=row.labels_applied or 0,
            critical_files=row.critical_files or 0,
            high_files=row.high_files or 0,
        )

    async def get_trends(
        self, tenant_id: UUID, start_date: datetime, end_date: datetime,
    ) -> list[TrendPoint]:
        from openlabels.server.models import ScanResult

        session = await self._get_session()
        scan_date = cast(ScanResult.scanned_at, Date)

        q = (
            select(
                scan_date.label("scan_date"),
                func.count().label("files_scanned"),
                func.sum(case((ScanResult.total_entities > 0, 1), else_=0)).label("files_with_pii"),
                func.sum(case((ScanResult.label_applied == True, 1), else_=0)).label("labels_applied"),  # noqa: E712
            )
            .where(and_(
                ScanResult.tenant_id == tenant_id,
                ScanResult.scanned_at >= start_date,
            ))
            .group_by(scan_date)
            .order_by(scan_date)
        )

        result = await session.execute(q)
        return [
            TrendPoint(
                date=row.scan_date.strftime("%Y-%m-%d"),
                files_scanned=row.files_scanned or 0,
                files_with_pii=row.files_with_pii or 0,
                labels_applied=row.labels_applied or 0,
            )
            for row in result.all()
        ]

    async def get_entity_trends(
        self, tenant_id: UUID, start_date: datetime, end_date: datetime,
        *, top_n: int = 6,
    ) -> EntityTrendsData:
        """Replicates the existing sampling approach from ``dashboard.py``."""
        from openlabels.server.models import ScanResult

        session = await self._get_session()
        scan_date = cast(ScanResult.scanned_at, Date)

        # Daily totals via SQL aggregation
        totals_q = (
            select(
                scan_date.label("scan_date"),
                func.sum(ScanResult.total_entities).label("total"),
            )
            .where(and_(
                ScanResult.tenant_id == tenant_id,
                ScanResult.scanned_at >= start_date,
                ScanResult.total_entities > 0,
            ))
            .group_by(scan_date)
            .order_by(scan_date)
        )
        totals_result = await session.execute(totals_q)
        daily_totals = {
            row.scan_date.strftime("%Y-%m-%d"): row.total or 0
            for row in totals_result.all()
        }

        # Sample to find top entity types
        sample_q = (
            select(ScanResult.entity_counts)
            .where(and_(
                ScanResult.tenant_id == tenant_id,
                ScanResult.scanned_at >= start_date,
                ScanResult.entity_counts.isnot(None),
                ScanResult.total_entities > 0,
            ))
            .order_by(ScanResult.scanned_at.desc())
            .limit(1000)
        )
        sample_result = await session.execute(sample_q)
        sample_rows = sample_result.scalars().all()

        type_totals: dict[str, int] = {}
        for ec in sample_rows:
            if ec:
                for et, cnt in ec.items():
                    type_totals[et] = type_totals.get(et, 0) + cnt
        top_types = sorted(type_totals, key=lambda t: type_totals[t], reverse=True)[:top_n]

        # Detailed query with cap
        detail_limit = 5000
        daily_counts: dict[str, dict[str, int]] = {}
        total_records = 0
        if top_types:
            detail_q = (
                select(ScanResult.scanned_at, ScanResult.entity_counts)
                .where(and_(
                    ScanResult.tenant_id == tenant_id,
                    ScanResult.scanned_at >= start_date,
                    ScanResult.entity_counts.isnot(None),
                    ScanResult.total_entities > 0,
                ))
                .limit(detail_limit)
            )
            detail_result = await session.execute(detail_q)
            rows = detail_result.all()
            total_records = len(rows)
            for row in rows:
                ds = row.scanned_at.strftime("%Y-%m-%d")
                if ds not in daily_counts:
                    daily_counts[ds] = {}
                ec = row.entity_counts or {}
                for et in top_types:
                    if et in ec:
                        daily_counts[ds][et] = daily_counts[ds].get(et, 0) + ec[et]

        truncated = total_records >= detail_limit

        # Build series
        from datetime import timedelta
        series: dict[str, list[tuple[str, int]]] = {"Total": []}
        for et in top_types:
            series[et] = []

        current = start_date
        while current <= end_date:
            ds = current.strftime("%Y-%m-%d")
            series["Total"].append((ds, daily_totals.get(ds, 0)))
            day_counts = daily_counts.get(ds, {})
            for et in top_types:
                series[et].append((ds, day_counts.get(et, 0)))
            current += timedelta(days=1)

        return EntityTrendsData(series=series, truncated=truncated, total_records=total_records)

    async def get_access_heatmap(
        self, tenant_id: UUID, since: datetime,
    ) -> list[list[int]]:
        from openlabels.server.models import FileAccessEvent

        session = await self._get_session()
        heatmap = [[0] * 24 for _ in range(7)]

        try:
            q = (
                select(
                    extract("isodow", FileAccessEvent.event_time).label("day_of_week"),
                    extract("hour", FileAccessEvent.event_time).label("hour"),
                    func.count().label("count"),
                )
                .where(and_(
                    FileAccessEvent.tenant_id == tenant_id,
                    FileAccessEvent.event_time >= since,
                ))
                .group_by(
                    extract("isodow", FileAccessEvent.event_time),
                    extract("hour", FileAccessEvent.event_time),
                )
            )
            result = await session.execute(q)
            for row in result.all():
                day = int(row.day_of_week) - 1
                if day == -1:
                    day = 6
                hour = int(row.hour)
                if 0 <= day < 7 and 0 <= hour < 24:
                    heatmap[day][hour] = row.count
        except Exception:
            logger.debug("Access heatmap query failed", exc_info=True)

        return heatmap

    async def get_heatmap_data(
        self, tenant_id: UUID, *, job_id: UUID | None = None, limit: int = 10_000,
    ) -> tuple[list[HeatmapFileRow], int]:
        from openlabels.server.models import ScanResult

        session = await self._get_session()

        count_q = select(func.count()).select_from(ScanResult).where(
            ScanResult.tenant_id == tenant_id
        )
        if job_id:
            count_q = count_q.where(ScanResult.job_id == job_id)
        count_result = await session.execute(count_q)
        total = count_result.scalar() or 0

        q = (
            select(ScanResult.file_path, ScanResult.risk_score, ScanResult.entity_counts)
            .where(ScanResult.tenant_id == tenant_id)
            .order_by(ScanResult.risk_score.desc())
            .limit(limit)
        )
        if job_id:
            q = q.where(ScanResult.job_id == job_id)

        result = await session.stream(q)
        rows_out: list[HeatmapFileRow] = []
        async for partition in result.partitions(1000):
            for row in partition:
                rows_out.append(HeatmapFileRow(
                    file_path=row.file_path,
                    risk_score=row.risk_score or 0,
                    entity_counts=row.entity_counts or {},
                ))
        return rows_out, total

    async def get_access_stats(self, tenant_id: UUID) -> AccessStats:
        from datetime import timedelta
        from datetime import timezone as tz

        from openlabels.server.models import FileAccessEvent

        session = await self._get_session()
        now = datetime.now(tz.utc)
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        stats_q = select(
            func.count().label("total"),
            func.sum(case((FileAccessEvent.event_time >= last_24h, 1), else_=0)).label("last_24h"),
            func.sum(case((FileAccessEvent.event_time >= last_7d, 1), else_=0)).label("last_7d"),
        ).where(FileAccessEvent.tenant_id == tenant_id)
        result = await session.execute(stats_q)
        row = result.one()

        action_q = (
            select(FileAccessEvent.action, func.count().label("count"))
            .where(FileAccessEvent.tenant_id == tenant_id)
            .group_by(FileAccessEvent.action)
        )
        action_result = await session.execute(action_q)
        by_action = {r.action: r.count for r in action_result.all()}

        user_q = (
            select(FileAccessEvent.user_name, func.count().label("count"))
            .where(and_(
                FileAccessEvent.tenant_id == tenant_id,
                FileAccessEvent.user_name.isnot(None),
            ))
            .group_by(FileAccessEvent.user_name)
            .order_by(func.count().desc())
            .limit(10)
        )
        user_result = await session.execute(user_q)
        top_users = [{"user": r.user_name, "count": r.count} for r in user_result.all()]

        return AccessStats(
            total_events=row.total or 0,
            events_last_24h=row.last_24h or 0,
            events_last_7d=row.last_7d or 0,
            by_action=by_action,
            top_users=top_users,
        )

    async def get_remediation_stats(self, tenant_id: UUID) -> RemediationStats:
        from openlabels.server.models import RemediationAction

        session = await self._get_session()
        q = select(
            func.count().label("total"),
            func.sum(case((RemediationAction.action_type == "quarantine", 1), else_=0)).label("quarantine_count"),
            func.sum(case((RemediationAction.action_type == "lockdown", 1), else_=0)).label("lockdown_count"),
            func.sum(case((RemediationAction.action_type == "rollback", 1), else_=0)).label("rollback_count"),
            func.sum(case((RemediationAction.status == "completed", 1), else_=0)).label("completed"),
            func.sum(case((RemediationAction.status == "failed", 1), else_=0)).label("failed"),
            func.sum(case((RemediationAction.status == "pending", 1), else_=0)).label("pending_count"),
        ).where(RemediationAction.tenant_id == tenant_id)

        result = await session.execute(q)
        row = result.one()

        return RemediationStats(
            total_actions=row.total or 0,
            by_type={
                "quarantine": row.quarantine_count or 0,
                "lockdown": row.lockdown_count or 0,
                "rollback": row.rollback_count or 0,
            },
            by_status={
                "completed": row.completed or 0,
                "failed": row.failed or 0,
                "pending": row.pending_count or 0,
            },
        )

    async def get_compliance_stats(self, tenant_id: UUID) -> ComplianceStats:
        from openlabels.server.models import ScanResult

        session = await self._get_session()

        total_q = select(func.count()).select_from(
            select(ScanResult).where(ScanResult.tenant_id == tenant_id).subquery()
        )
        total = (await session.execute(total_q)).scalar_one()
        if total == 0:
            return ComplianceStats()

        violated_q = select(func.count()).select_from(
            select(ScanResult).where(
                ScanResult.tenant_id == tenant_id,
                ScanResult.policy_violations.isnot(None),
            ).subquery()
        )
        violated = (await session.execute(violated_q)).scalar_one()
        compliance_pct = round(((total - violated) / total) * 100, 2)

        detail_q = (
            select(ScanResult.policy_violations)
            .where(
                ScanResult.tenant_id == tenant_id,
                ScanResult.policy_violations.isnot(None),
            )
            .limit(500)
        )
        rows = (await session.execute(detail_q)).scalars().all()

        by_framework: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for violations in rows:
            if not violations:
                continue
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

"""
Result service for OpenLabels server.

Provides business logic for scan results with:
- Memory-efficient streaming for large datasets
- Efficient SQL aggregation for statistics
- Proper tenant isolation
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import case, delete, func, select

from openlabels.server.models import ScanResult
from openlabels.server.services.base import BaseService

# Default chunk size for streaming operations
DEFAULT_CHUNK_SIZE = 1000


class ResultService(BaseService):
    """
    Service for managing scan results.

    Provides streaming methods for memory-efficient processing of large
    result sets, standard CRUD operations, and efficient statistics
    aggregation using SQL.

    All methods automatically filter by tenant_id for proper isolation.

    Example:
        from openlabels.server.services import ResultService, TenantContext
        from openlabels.server.config import get_settings

        tenant = TenantContext.from_current_user(user)
        service = ResultService(session, tenant, get_settings())

        # Stream all results for a job
        async for result in service.stream_results(job_id=job_id):
            process(result)

        # Get statistics
        stats = await service.get_stats(job_id=job_id)
    """

    # =========================================================================
    # STREAMING METHODS (Memory Efficient)
    # =========================================================================

    async def stream_results(
        self,
        job_id: UUID | None = None,
        risk_tier: str | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> AsyncIterator[ScanResult]:
        """
        Stream scan results using keyset/cursor pagination for memory efficiency.

        Uses keyset pagination internally to efficiently iterate through large
        result sets without loading everything into memory. Results are yielded
        one at a time, allowing the caller to process them incrementally.

        Args:
            job_id: Optional job ID to filter results
            risk_tier: Optional risk tier filter (MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)
            chunk_size: Number of results to fetch per database query (default: 1000)

        Yields:
            ScanResult: Individual scan result records

        Example:
            async for result in service.stream_results(job_id=job_id):
                yield export_row(result)
        """
        self._log_debug(
            f"Starting result stream job_id={job_id} risk_tier={risk_tier} chunk_size={chunk_size}"
        )

        # Track cursor position for keyset pagination
        last_scanned_at = None
        last_id = None
        total_yielded = 0

        while True:
            # Build query with tenant isolation
            conditions = [ScanResult.tenant_id == self.tenant_id]

            if job_id:
                conditions.append(ScanResult.job_id == job_id)
            if risk_tier:
                conditions.append(ScanResult.risk_tier == risk_tier)

            # Apply cursor filter for keyset pagination
            if last_scanned_at is not None and last_id is not None:
                # Use tuple comparison for stable ordering
                conditions.append(
                    (ScanResult.scanned_at, ScanResult.id) < (last_scanned_at, last_id)
                )

            # Build and execute query
            query = (
                select(ScanResult)
                .where(*conditions)
                .order_by(ScanResult.scanned_at.desc(), ScanResult.id.desc())
                .limit(chunk_size)
            )

            result = await self.session.execute(query)
            results = result.scalars().all()

            if not results:
                self._log_debug(f"Stream completed total_yielded={total_yielded}")
                break

            # Yield each result individually
            for scan_result in results:
                yield scan_result
                total_yielded += 1
                # Update cursor position
                last_scanned_at = scan_result.scanned_at
                last_id = scan_result.id

    async def stream_results_as_dicts(
        self,
        job_id: UUID | None = None,
        fields: list[str] | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> AsyncIterator[dict]:
        """
        Stream scan results as dictionaries for memory-efficient exports.

        More memory efficient than streaming full ORM objects when only
        specific fields are needed. Useful for CSV/JSON exports.

        Args:
            job_id: Optional job ID to filter results
            fields: Optional list of field names to include. If None, includes
                    common export fields: file_path, file_name, risk_score,
                    risk_tier, total_entities, exposure_level, owner,
                    current_label_name, recommended_label_name, label_applied
            chunk_size: Number of results to fetch per database query (default: 1000)

        Yields:
            dict: Dictionary containing requested fields for each result

        Example:
            async for row in service.stream_results_as_dicts(
                job_id=job_id,
                fields=["file_path", "risk_tier", "total_entities"]
            ):
                csv_writer.writerow(row.values())
        """
        # Default export fields if not specified
        if fields is None:
            fields = [
                "file_path",
                "file_name",
                "risk_score",
                "risk_tier",
                "total_entities",
                "exposure_level",
                "owner",
                "current_label_name",
                "recommended_label_name",
                "label_applied",
            ]

        self._log_debug(
            f"Starting dict stream job_id={job_id} fields={len(fields)} chunk_size={chunk_size}"
        )

        # Track cursor position for keyset pagination
        last_scanned_at = None
        last_id = None
        total_yielded = 0

        while True:
            # Build query with tenant isolation
            conditions = [ScanResult.tenant_id == self.tenant_id]

            if job_id:
                conditions.append(ScanResult.job_id == job_id)

            # Apply cursor filter for keyset pagination
            if last_scanned_at is not None and last_id is not None:
                conditions.append(
                    (ScanResult.scanned_at, ScanResult.id) < (last_scanned_at, last_id)
                )

            # Build and execute query
            query = (
                select(ScanResult)
                .where(*conditions)
                .order_by(ScanResult.scanned_at.desc(), ScanResult.id.desc())
                .limit(chunk_size)
            )

            result = await self.session.execute(query)
            results = result.scalars().all()

            if not results:
                self._log_debug(f"Dict stream completed total_yielded={total_yielded}")
                break

            # Yield dictionaries with only requested fields
            for scan_result in results:
                row = {}
                for field in fields:
                    value = getattr(scan_result, field, None)
                    # Convert UUID to string for JSON serialization
                    if isinstance(value, UUID):
                        value = str(value)
                    row[field] = value
                yield row
                total_yielded += 1
                # Update cursor position
                last_scanned_at = scan_result.scanned_at
                last_id = scan_result.id

    # =========================================================================
    # STANDARD METHODS
    # =========================================================================

    async def get_result(self, result_id: UUID) -> ScanResult | None:
        """
        Get a single scan result by ID.

        Args:
            result_id: The UUID of the scan result

        Returns:
            ScanResult if found and belongs to tenant, None otherwise

        Example:
            result = await service.get_result(result_id)
            if result:
                return ResultResponse.model_validate(result)
        """
        result = await self.session.get(ScanResult, result_id)
        if result and result.tenant_id == self.tenant_id:
            return result
        return None

    async def list_results(
        self,
        job_id: UUID | None = None,
        risk_tier: str | None = None,
        has_pii: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ScanResult], int]:
        """
        List scan results with filtering and pagination.

        Args:
            job_id: Optional job ID to filter results
            risk_tier: Optional risk tier filter
            has_pii: Optional filter for files with/without PII detections
            limit: Maximum number of results to return (default: 50)
            offset: Number of results to skip (default: 0)

        Returns:
            Tuple of (list of ScanResult, total count)

        Example:
            results, total = await service.list_results(
                job_id=job_id,
                risk_tier="HIGH",
                limit=25,
                offset=50
            )
        """
        # Build filter conditions
        conditions = [ScanResult.tenant_id == self.tenant_id]

        if job_id:
            conditions.append(ScanResult.job_id == job_id)
        if risk_tier:
            conditions.append(ScanResult.risk_tier == risk_tier)
        if has_pii is not None:
            if has_pii:
                conditions.append(ScanResult.total_entities > 0)
            else:
                conditions.append(ScanResult.total_entities == 0)

        # Get total count
        count_query = select(func.count()).where(*conditions).select_from(ScanResult)
        count_result = await self.session.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated results
        query = (
            select(ScanResult)
            .where(*conditions)
            .order_by(ScanResult.risk_score.desc(), ScanResult.scanned_at.desc())
            .offset(offset)
            .limit(limit)
        )

        result = await self.session.execute(query)
        results = list(result.scalars().all())

        self._log_debug(
            f"Listed results job_id={job_id} risk_tier={risk_tier} count={len(results)} total={total}"
        )

        return results, total

    async def delete_results(self, job_id: UUID | None = None) -> int:
        """
        Delete scan results, optionally filtered by job.

        Args:
            job_id: If provided, only delete results for this job.
                    If None, delete all results for the tenant.

        Returns:
            Number of results deleted

        Example:
            deleted_count = await service.delete_results(job_id)
            logger.info(f"Deleted {deleted_count} results")
        """
        # Build conditions
        conditions = [ScanResult.tenant_id == self.tenant_id]
        if job_id is not None:
            conditions.append(ScanResult.job_id == job_id)

        # First count the results to be deleted
        count_query = (
            select(func.count())
            .where(*conditions)
            .select_from(ScanResult)
        )
        count_result = await self.session.execute(count_query)
        deleted_count = count_result.scalar() or 0

        if deleted_count > 0:
            # Delete the results
            delete_query = delete(ScanResult).where(*conditions)
            await self.session.execute(delete_query)
            await self.session.flush()

            self._log_info(
                f"Deleted results for job job_id={job_id} deleted_count={deleted_count}"
            )

        return deleted_count

    # =========================================================================
    # STATISTICS (Efficient SQL Aggregation)
    # =========================================================================

    async def get_stats(self, job_id: UUID | None = None) -> dict:
        """
        Get aggregated statistics for scan results.

        Uses a single SQL query with CASE expressions for efficient
        aggregation without multiple round-trips to the database.

        Args:
            job_id: Optional job ID to filter statistics

        Returns:
            Dictionary containing:
            - total_files: Total number of scanned files
            - files_with_pii: Files containing at least one entity
            - critical_count: Files with CRITICAL risk tier
            - high_count: Files with HIGH risk tier
            - medium_count: Files with MEDIUM risk tier
            - low_count: Files with LOW risk tier
            - minimal_count: Files with MINIMAL risk tier
            - labels_applied: Files where label has been applied

        Example:
            stats = await service.get_stats(job_id=job_id)
            print(f"Found {stats['files_with_pii']} files with PII")
        """
        # Build filter conditions
        conditions = [ScanResult.tenant_id == self.tenant_id]
        if job_id:
            conditions.append(ScanResult.job_id == job_id)

        # Single aggregation query with CASE expressions
        stats_query = select(
            func.count().label("total_files"),
            func.sum(case((ScanResult.total_entities > 0, 1), else_=0)).label(
                "files_with_pii"
            ),
            func.sum(case((ScanResult.risk_tier == "CRITICAL", 1), else_=0)).label(
                "critical_count"
            ),
            func.sum(case((ScanResult.risk_tier == "HIGH", 1), else_=0)).label(
                "high_count"
            ),
            func.sum(case((ScanResult.risk_tier == "MEDIUM", 1), else_=0)).label(
                "medium_count"
            ),
            func.sum(case((ScanResult.risk_tier == "LOW", 1), else_=0)).label(
                "low_count"
            ),
            func.sum(case((ScanResult.risk_tier == "MINIMAL", 1), else_=0)).label(
                "minimal_count"
            ),
            func.sum(
                case((ScanResult.label_applied == True, 1), else_=0)  # noqa: E712
            ).label("labels_applied"),
        ).where(*conditions)

        result = await self.session.execute(stats_query)
        row = result.one()

        stats = {
            "total_files": row.total_files or 0,
            "files_with_pii": row.files_with_pii or 0,
            "critical_count": row.critical_count or 0,
            "high_count": row.high_count or 0,
            "medium_count": row.medium_count or 0,
            "low_count": row.low_count or 0,
            "minimal_count": row.minimal_count or 0,
            "labels_applied": row.labels_applied or 0,
        }

        self._log_debug(
            f"Computed statistics job_id={job_id} total_files={stats['total_files']} "
            f"files_with_pii={stats['files_with_pii']}"
        )

        return stats

    async def get_entity_type_stats(
        self,
        job_id: UUID | None = None,
        limit: int = 10,
        sample_size: int = 5000,
    ) -> dict[str, int]:
        """
        Get entity type statistics using sample-based aggregation.

        Uses a sample of results to avoid loading all entity_counts JSONB
        data into memory. Provides approximate counts for top entity types.

        Args:
            job_id: Optional job ID to filter results
            limit: Maximum number of entity types to return (default: 10)
            sample_size: Maximum number of results to sample (default: 5000)

        Returns:
            Dictionary mapping entity type names to their total counts,
            sorted by count descending and limited to top N types

        Example:
            entity_stats = await service.get_entity_type_stats(job_id=job_id)
            # {"SSN": 150, "CREDIT_CARD": 85, "EMAIL": 42}
        """
        # Push JSONB aggregation to PostgreSQL using jsonb_each_text()
        # instead of loading thousands of JSONB blobs into Python.
        from sqlalchemy import text as sa_text

        job_filter = "AND r.job_id = :job_id" if job_id else ""
        agg_sql = sa_text(f"""
            SELECT kv.key AS entity_type,
                   SUM(kv.value::int) AS total_count
            FROM (
                SELECT entity_counts
                FROM scan_results r
                WHERE r.tenant_id = :tid
                  AND r.entity_counts IS NOT NULL
                  AND r.total_entities > 0
                  {job_filter}
                ORDER BY r.scanned_at DESC
                LIMIT :sample_size
            ) sub,
            LATERAL jsonb_each_text(sub.entity_counts) AS kv(key, value)
            GROUP BY kv.key
            ORDER BY total_count DESC
            LIMIT :lim
        """)

        params: dict = {"tid": self.tenant_id, "sample_size": sample_size, "lim": limit}
        if job_id:
            params["job_id"] = job_id

        result = await self.session.execute(agg_sql, params)
        rows = result.all()
        top_entities = {row.entity_type: row.total_count for row in rows}

        self._log_debug(
            f"Computed entity type statistics job_id={job_id} "
            f"returned_types={len(top_entities)}"
        )

        return top_entities

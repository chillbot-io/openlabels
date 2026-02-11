"""Range-partition scan_results and file_access_events by time.

Converts both high-volume tables to PostgreSQL range partitions:
- scan_results: PARTITION BY RANGE (scanned_at)
- file_access_events: PARTITION BY RANGE (event_time)

Monthly partitions are created for the past 12 months through
3 months ahead.  A DEFAULT partition catches any rows outside
those ranges (very old or far-future data).

The composite primary key (id, <partition_col>) is required by
PostgreSQL — partition keys must be part of every unique index.
Point-lookups by id alone still work efficiently since each
partition has its own B-tree index on the composite key.

NOTE: This migration copies data from the old unpartitioned table
to the new partitioned table.  On tables with hundreds of millions
of rows this may take significant time.  Plan accordingly.

Revision ID: a1b2c3d4e5f6
Revises: f8a9b0c1d2e3
Create Date: 2026-02-11 22:00:00.000000
"""

from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "f8a9b0c1d2e3"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCAN_RESULTS_INDEXES = [
    "CREATE INDEX ix_scan_results_tenant_risk_time ON scan_results (tenant_id, risk_tier, scanned_at)",
    "CREATE INDEX ix_scan_results_tenant_path ON scan_results (tenant_id, file_path)",
    "CREATE INDEX ix_scan_results_job_time ON scan_results (job_id, scanned_at)",
    "CREATE INDEX ix_scan_results_tenant_label ON scan_results (tenant_id, label_applied, scanned_at)",
    "CREATE INDEX ix_scan_results_entities ON scan_results USING gin (entity_counts)",
]

_ACCESS_EVENTS_INDEXES = [
    "CREATE INDEX ix_access_events_file_time ON file_access_events (tenant_id, file_path, event_time)",
    "CREATE INDEX ix_access_events_user_time ON file_access_events (tenant_id, user_name, event_time)",
    "CREATE INDEX ix_access_events_monitored ON file_access_events (monitored_file_id, event_time)",
    "CREATE INDEX ix_access_events_tenant_action ON file_access_events (tenant_id, action, event_time)",
]

# SQL to create monthly partitions for -12 … +3 months
_CREATE_PARTITIONS_SQL = """
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
    i INTEGER;
BEGIN
    FOR i IN -12..3 LOOP
        start_date := date_trunc('month', CURRENT_DATE + (i || ' months')::interval);
        end_date   := start_date + '1 month'::interval;
        partition_name := '{table}_' || to_char(start_date, 'YYYY_MM');

        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = partition_name
        ) THEN
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF {table} '
                'FOR VALUES FROM (%L) TO (%L)',
                partition_name, start_date, end_date
            );
        END IF;
    END LOOP;
END$$;
"""


def _partition_table(
    table: str,
    partition_col: str,
    fk_defs: list[str],
    index_stmts: list[str],
) -> None:
    """Convert *table* from unpartitioned to RANGE-partitioned on *partition_col*."""

    old = f"_{table}_pre_partition"

    # 1. Ensure partition column has no NULLs (safety net for old data)
    op.execute(
        f"UPDATE {table} SET {partition_col} = NOW() "
        f"WHERE {partition_col} IS NULL"
    )

    # 2. Rename old table (indexes go with it)
    op.execute(f"ALTER TABLE {table} RENAME TO {old}")

    # 3. Create new partitioned table with same column definitions
    #    INCLUDING DEFAULTS copies column defaults; we add our own
    #    constraints afterward.
    op.execute(
        f"CREATE TABLE {table} ("
        f"  LIKE {old} INCLUDING DEFAULTS"
        f") PARTITION BY RANGE ({partition_col})"
    )

    # 4. Composite primary key (required: partition key in every unique index)
    op.execute(
        f"ALTER TABLE {table} ADD PRIMARY KEY (id, {partition_col})"
    )

    # 5. Foreign keys
    for fk in fk_defs:
        op.execute(fk)

    # 6. Default partition (catches data outside named ranges)
    op.execute(
        f"CREATE TABLE {table}_default PARTITION OF {table} DEFAULT"
    )

    # 7. Monthly partitions
    op.execute(_CREATE_PARTITIONS_SQL.replace("{table}", table))

    # 8. Copy data (PostgreSQL routes rows to correct partitions automatically)
    op.execute(f"INSERT INTO {table} SELECT * FROM {old}")

    # 9. Drop old table
    op.execute(f"DROP TABLE {old} CASCADE")

    # 10. Recreate indexes (created on the partitioned table; PostgreSQL
    #     propagates them to each partition automatically)
    for stmt in index_stmts:
        op.execute(stmt)


def _unpartition_table(
    table: str,
    partition_col: str,
    fk_defs: list[str],
    index_stmts: list[str],
    pk_col: str = "id",
) -> None:
    """Reverse: convert a partitioned table back to a regular table."""

    old = f"_{table}_partitioned"

    # 1. Rename partitioned table
    op.execute(f"ALTER TABLE {table} RENAME TO {old}")

    # 2. Create regular (unpartitioned) table
    op.execute(
        f"CREATE TABLE {table} ("
        f"  LIKE {old} INCLUDING DEFAULTS"
        f")"
    )

    # 3. Single-column PK
    op.execute(f"ALTER TABLE {table} ADD PRIMARY KEY ({pk_col})")

    # 4. Foreign keys
    for fk in fk_defs:
        op.execute(fk)

    # 5. Copy data back
    op.execute(f"INSERT INTO {table} SELECT * FROM {old}")

    # 6. Drop partitioned table + all its partitions
    op.execute(f"DROP TABLE {old} CASCADE")

    # 7. Recreate indexes
    for stmt in index_stmts:
        op.execute(stmt)


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

def upgrade() -> None:
    # ── scan_results ──────────────────────────────────────────────
    _partition_table(
        table="scan_results",
        partition_col="scanned_at",
        fk_defs=[
            "ALTER TABLE scan_results ADD CONSTRAINT fk_scan_results_tenant "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id)",
            "ALTER TABLE scan_results ADD CONSTRAINT fk_scan_results_job "
            "FOREIGN KEY (job_id) REFERENCES scan_jobs(id)",
        ],
        index_stmts=_SCAN_RESULTS_INDEXES,
    )

    # ── file_access_events ────────────────────────────────────────
    _partition_table(
        table="file_access_events",
        partition_col="event_time",
        fk_defs=[
            "ALTER TABLE file_access_events ADD CONSTRAINT fk_access_events_tenant "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id)",
            "ALTER TABLE file_access_events ADD CONSTRAINT fk_access_events_monitored "
            "FOREIGN KEY (monitored_file_id) REFERENCES monitored_files(id)",
        ],
        index_stmts=_ACCESS_EVENTS_INDEXES,
    )


def downgrade() -> None:
    # ── scan_results ──────────────────────────────────────────────
    _unpartition_table(
        table="scan_results",
        partition_col="scanned_at",
        fk_defs=[
            "ALTER TABLE scan_results ADD CONSTRAINT fk_scan_results_tenant "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id)",
            "ALTER TABLE scan_results ADD CONSTRAINT fk_scan_results_job "
            "FOREIGN KEY (job_id) REFERENCES scan_jobs(id)",
        ],
        index_stmts=_SCAN_RESULTS_INDEXES,
    )

    # ── file_access_events ────────────────────────────────────────
    _unpartition_table(
        table="file_access_events",
        partition_col="event_time",
        fk_defs=[
            "ALTER TABLE file_access_events ADD CONSTRAINT fk_access_events_tenant "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id)",
            "ALTER TABLE file_access_events ADD CONSTRAINT fk_access_events_monitored "
            "FOREIGN KEY (monitored_file_id) REFERENCES monitored_files(id)",
        ],
        index_stmts=_ACCESS_EVENTS_INDEXES,
    )

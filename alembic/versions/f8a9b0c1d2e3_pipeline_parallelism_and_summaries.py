"""Pipeline parallelism, streaming pagination, and scan summaries.

Adds:
- Pipeline parallelism settings to tenant_settings
- scan_summaries table for pre-aggregated dashboard queries
- Helper function for future table partitioning of scan_results

Revision ID: f8a9b0c1d2e3
Revises: e6f7a8b9c1d2
Create Date: 2026-02-11 21:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "f8a9b0c1d2e3"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Pipeline parallelism settings on tenant_settings ─────────
    op.add_column(
        "tenant_settings",
        sa.Column(
            "pipeline_max_concurrent_files",
            sa.Integer(),
            nullable=False,
            server_default="8",
        ),
    )
    op.add_column(
        "tenant_settings",
        sa.Column(
            "pipeline_memory_budget_mb",
            sa.Integer(),
            nullable=False,
            server_default="512",
        ),
    )

    # ── scan_summaries table ─────────────────────────────────────
    op.create_table(
        "scan_summaries",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            sa.ForeignKey("tenants.id"),
            nullable=False,
        ),
        sa.Column(
            "job_id",
            sa.UUID(),
            sa.ForeignKey("scan_jobs.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "target_id",
            sa.UUID(),
            sa.ForeignKey("scan_targets.id"),
            nullable=False,
        ),
        # Aggregate counts
        sa.Column("files_scanned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("files_with_pii", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("files_skipped", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_entities", sa.Integer(), nullable=False, server_default="0"),
        # Risk tier breakdown
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("minimal_count", sa.Integer(), nullable=False, server_default="0"),
        # Entity type breakdown
        sa.Column("entity_type_counts", JSONB(), nullable=True),
        # Scan metadata
        sa.Column("scan_mode", sa.String(20), nullable=True),
        sa.Column("total_partitions", sa.Integer(), nullable=True),
        sa.Column("scan_duration_seconds", sa.Float(), nullable=True),
        # Label stats
        sa.Column("files_labeled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("files_label_failed", sa.Integer(), nullable=False, server_default="0"),
        # Timestamps
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_index(
        "ix_scan_summaries_tenant_completed",
        "scan_summaries",
        ["tenant_id", "completed_at"],
    )
    op.create_index(
        "ix_scan_summaries_target_completed",
        "scan_summaries",
        ["target_id", "completed_at"],
    )
    op.create_index(
        "ix_scan_summaries_tenant_risk",
        "scan_summaries",
        ["tenant_id", "critical_count", "high_count"],
    )

    # ── SQL function for auto-creating monthly partitions ────────
    # This creates future partitions for scan_results if/when the table
    # is converted to range partitioning by scanned_at. The function can
    # be called by pg_cron or the application on a schedule.
    op.execute("""
        CREATE OR REPLACE FUNCTION create_monthly_partitions(
            table_name TEXT,
            column_name TEXT,
            months_ahead INTEGER DEFAULT 3
        ) RETURNS void AS $$
        DECLARE
            start_date DATE;
            end_date DATE;
            partition_name TEXT;
            i INTEGER;
        BEGIN
            FOR i IN 0..months_ahead LOOP
                start_date := date_trunc('month', CURRENT_DATE + (i || ' months')::interval);
                end_date := start_date + '1 month'::interval;
                partition_name := table_name || '_' || to_char(start_date, 'YYYY_MM');

                -- Only create if it doesn't exist
                IF NOT EXISTS (
                    SELECT 1 FROM pg_class WHERE relname = partition_name
                ) THEN
                    EXECUTE format(
                        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I '
                        'FOR VALUES FROM (%L) TO (%L)',
                        partition_name, table_name, start_date, end_date
                    );
                    RAISE NOTICE 'Created partition: %', partition_name;
                END IF;
            END LOOP;
        END;
        $$ LANGUAGE plpgsql;
    """)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS create_monthly_partitions(TEXT, TEXT, INTEGER)")

    op.drop_index("ix_scan_summaries_tenant_risk", table_name="scan_summaries")
    op.drop_index("ix_scan_summaries_target_completed", table_name="scan_summaries")
    op.drop_index("ix_scan_summaries_tenant_completed", table_name="scan_summaries")
    op.drop_table("scan_summaries")

    op.drop_column("tenant_settings", "pipeline_memory_budget_mb")
    op.drop_column("tenant_settings", "pipeline_max_concurrent_files")

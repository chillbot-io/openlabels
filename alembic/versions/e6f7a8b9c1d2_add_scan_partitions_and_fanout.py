"""Add scan partitions and fan-out columns for horizontal scaling

Revision ID: e6f7a8b9c1d2
Revises: d5e6f7a8b9c0
Create Date: 2026-02-11

Adds:
- ``scan_partitions`` table for distributing scan work across workers
- Fan-out columns on ``scan_jobs`` for tracking partitioned scans
- Fan-out settings on ``tenant_settings`` for user-configurable scaling
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e6f7a8b9c1d2'
down_revision: Union[str, Sequence[str]] = '5f934314bd30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Fan-out columns on scan_jobs
    op.add_column('scan_jobs', sa.Column('scan_mode', sa.String(20), nullable=True))
    op.add_column('scan_jobs', sa.Column('total_partitions', sa.Integer(), nullable=True))
    op.add_column('scan_jobs', sa.Column('partitions_completed', sa.Integer(), nullable=True))
    op.add_column('scan_jobs', sa.Column('partitions_failed', sa.Integer(), nullable=True))
    op.add_column('scan_jobs', sa.Column('total_files_estimated', sa.Integer(), nullable=True))

    # Scan partitions table
    op.create_table(
        'scan_partitions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=False),
        sa.Column('partition_index', sa.Integer(), nullable=False),
        sa.Column('total_partitions', sa.Integer(), nullable=False),
        sa.Column('partition_spec', postgresql.JSONB(), nullable=False),
        sa.Column('status', postgresql.ENUM(
            'pending', 'running', 'completed', 'failed', 'cancelled',
            name='job_status', create_type=False,
        ), server_default='pending'),
        sa.Column('worker_id', sa.String(100), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('files_scanned', sa.Integer(), server_default='0'),
        sa.Column('files_with_pii', sa.Integer(), server_default='0'),
        sa.Column('files_skipped', sa.Integer(), server_default='0'),
        sa.Column('total_entities', sa.Integer(), server_default='0'),
        sa.Column('stats', postgresql.JSONB(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), server_default='0'),
        sa.Column('last_processed_path', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_index('ix_scan_partitions_job_status', 'scan_partitions', ['job_id', 'status'])
    op.create_index('ix_scan_partitions_job_index', 'scan_partitions', ['job_id', 'partition_index'], unique=True)
    op.create_index('ix_scan_partitions_tenant_status', 'scan_partitions', ['tenant_id', 'status'])

    # User-configurable fan-out settings on tenant_settings
    op.add_column('tenant_settings', sa.Column(
        'fanout_enabled', sa.Boolean(), server_default='true',
    ))
    op.add_column('tenant_settings', sa.Column(
        'fanout_threshold', sa.Integer(), server_default='10000',
        comment='Minimum estimated files to trigger fan-out (below this, run single-worker)',
    ))
    op.add_column('tenant_settings', sa.Column(
        'fanout_max_partitions', sa.Integer(), server_default='16',
        comment='Maximum number of partitions to create per scan job',
    ))


def downgrade() -> None:
    op.drop_column('tenant_settings', 'fanout_max_partitions')
    op.drop_column('tenant_settings', 'fanout_threshold')
    op.drop_column('tenant_settings', 'fanout_enabled')

    op.drop_index('ix_scan_partitions_tenant_status', table_name='scan_partitions')
    op.drop_index('ix_scan_partitions_job_index', table_name='scan_partitions')
    op.drop_index('ix_scan_partitions_job_status', table_name='scan_partitions')
    op.drop_table('scan_partitions')

    op.drop_column('scan_jobs', 'total_files_estimated')
    op.drop_column('scan_jobs', 'partitions_failed')
    op.drop_column('scan_jobs', 'partitions_completed')
    op.drop_column('scan_jobs', 'total_partitions')
    op.drop_column('scan_jobs', 'scan_mode')

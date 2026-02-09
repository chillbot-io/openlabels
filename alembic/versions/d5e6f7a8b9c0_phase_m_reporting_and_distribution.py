"""Phase M: Reporting and distribution

Revision ID: d5e6f7a8b9c0
Revises: c4d7e8f9a1b2
Create Date: 2026-02-09

Adds:
- ``reports`` table for generated report metadata
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, Sequence[str]] = 'c4d7e8f9a1b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('report_type', sa.String(50), nullable=False),
        sa.Column('format', sa.String(10), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='pending'),
        sa.Column('filters', postgresql.JSONB),
        sa.Column('result_path', sa.Text),
        sa.Column('result_size_bytes', sa.BigInteger),
        sa.Column('error', sa.Text),
        sa.Column('distributed_to', postgresql.JSONB),
        sa.Column('distributed_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('generated_at', sa.DateTime(timezone=True)),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
    )
    op.create_index('ix_reports_tenant_type', 'reports', ['tenant_id', 'report_type'])
    op.create_index('ix_reports_tenant_created', 'reports', ['tenant_id', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_reports_tenant_created', table_name='reports')
    op.drop_index('ix_reports_tenant_type', table_name='reports')
    op.drop_table('reports')

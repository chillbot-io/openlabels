"""Add alert_rules table

Revision ID: c1b8df0349fc
Revises: 8e0ee9ee0126
Create Date: 2026-02-27

Adds the ``alert_rules`` table for configurable alert rules that detect
suspicious file access patterns (high-volume access, failed attempts,
off-hours access, etc.).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c1b8df0349fc'
down_revision: Union[str, Sequence[str]] = '8e0ee9ee0126'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'alert_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), default=True),
        sa.Column('rule_type', sa.String(50), nullable=False),
        sa.Column('conditions', postgresql.JSONB(), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False, server_default='medium'),
        sa.Column('actions', postgresql.JSONB(), nullable=False, server_default='["log"]'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_alert_rules_tenant', 'alert_rules', ['tenant_id'])


def downgrade() -> None:
    op.drop_index('ix_alert_rules_tenant', table_name='alert_rules')
    op.drop_table('alert_rules')

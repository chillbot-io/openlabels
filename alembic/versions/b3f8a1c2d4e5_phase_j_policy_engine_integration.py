"""Phase J: Policy engine integration

Revision ID: b3f8a1c2d4e5
Revises: 095c7b32510f
Create Date: 2026-02-08

Adds:
- ``policy_violations`` JSONB column to ``scan_results``
- ``policies`` table for tenant-scoped policy configurations
- ``policy_violation`` value to ``audit_action`` enum
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b3f8a1c2d4e5'
down_revision: Union[str, Sequence[str]] = '095c7b32510f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add 'policy_violation' to audit_action enum
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'policy_violation'")

    # Add policy_violations column to scan_results
    op.add_column(
        'scan_results',
        sa.Column('policy_violations', postgresql.JSONB(), nullable=True),
    )

    # Create policies table
    op.create_table(
        'policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('framework', sa.String(50), nullable=False),
        sa.Column('risk_level', sa.String(20), nullable=False, server_default='high'),
        sa.Column('enabled', sa.Boolean(), server_default='true'),
        sa.Column('config', postgresql.JSONB(), nullable=False),
        sa.Column('priority', sa.Integer(), server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id'), nullable=True),
    )
    op.create_index('ix_policies_tenant_framework', 'policies', ['tenant_id', 'framework'])
    op.create_index('ix_policies_tenant_enabled', 'policies', ['tenant_id', 'enabled'])


def downgrade() -> None:
    op.drop_index('ix_policies_tenant_enabled', table_name='policies')
    op.drop_index('ix_policies_tenant_framework', table_name='policies')
    op.drop_table('policies')
    op.drop_column('scan_results', 'policy_violations')

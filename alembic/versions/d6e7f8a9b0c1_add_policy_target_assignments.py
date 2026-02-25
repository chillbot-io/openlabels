"""Add policy_target_assignments table

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-02-25

Story 8: Policy Management

- Create policy_target_assignments join table for assigning policies to scan targets
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd6e7f8a9b0c1'
down_revision: Union[str, Sequence[str]] = 'c5d6e7f8a9b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'policy_target_assignments',
        sa.Column('id', sa.UUID(), primary_key=True),
        sa.Column('tenant_id', sa.UUID(), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('policy_id', sa.UUID(), sa.ForeignKey('policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_id', sa.UUID(), sa.ForeignKey('scan_targets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('assigned_by', sa.UUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.UniqueConstraint('policy_id', 'target_id', name='uq_policy_target'),
        sa.Index('ix_policy_target_tenant', 'tenant_id'),
        sa.Index('ix_policy_target_policy', 'policy_id'),
        sa.Index('ix_policy_target_target', 'target_id'),
    )


def downgrade() -> None:
    op.drop_table('policy_target_assignments')

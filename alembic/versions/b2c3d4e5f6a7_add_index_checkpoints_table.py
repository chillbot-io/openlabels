"""Add index_checkpoints table for delta sync.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-02-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str]] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'index_checkpoints',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('target_id', sa.UUID(), nullable=False),
        sa.Column('last_full_sync', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_delta_sync', sa.DateTime(timezone=True), nullable=True),
        sa.Column('dirs_at_last_sync', sa.Integer(), server_default='0', nullable=False),
        sa.Column('delta_token', sa.Text(), nullable=True),
        sa.Column('usn_journal_cursor', sa.BigInteger(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_checkpoint_tenant_target',
        'index_checkpoints',
        ['tenant_id', 'target_id'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index('ix_checkpoint_tenant_target', table_name='index_checkpoints')
    op.drop_table('index_checkpoints')

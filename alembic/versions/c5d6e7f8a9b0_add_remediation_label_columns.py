"""Add label columns to remediation_actions and expand enums

Revision ID: c5d6e7f8a9b0
Revises: b2d3e4f5a6b7, b3c4d5e6f7a8
Create Date: 2026-02-25

Story 7: Remediation Actions

- Add 'label_apply' to remediation_action_type enum
- Add 'label_apply_executed' to audit_action enum
- Add label_id, label_name columns to remediation_actions table
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c5d6e7f8a9b0'
down_revision: Union[str, Sequence[str]] = ('b2d3e4f5a6b7', 'b3c4d5e6f7a8')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Expand enum types with new values
    op.execute("ALTER TYPE remediation_action_type ADD VALUE IF NOT EXISTS 'label_apply'")
    op.execute("ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'label_apply_executed'")

    # Add label columns to remediation_actions
    op.add_column(
        'remediation_actions',
        sa.Column('label_id', sa.String(36), sa.ForeignKey('sensitivity_labels.id', ondelete='SET NULL'), nullable=True),
    )
    op.add_column(
        'remediation_actions',
        sa.Column('label_name', sa.String(255), nullable=True),
    )


def downgrade() -> None:
    # Remove label columns
    op.drop_column('remediation_actions', 'label_name')
    op.drop_column('remediation_actions', 'label_id')
    # Cannot remove enum values in PostgreSQL - harmless to leave

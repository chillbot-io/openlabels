"""Add enable_ml column to tenant_settings

Revision ID: f9b0c1d2e3f4
Revises: e7f8a9b0c1d3
Create Date: 2026-02-14

Adds enable_ml boolean column to tenant_settings so tenants can
toggle ML-based detection (PHI-BERT / PII-BERT) on or off.
Defaults to True so existing tenants get ML enabled automatically.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f9b0c1d2e3f4'
down_revision: Union[str, Sequence[str]] = 'e7f8a9b0c1d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'tenant_settings',
        sa.Column('enable_ml', sa.Boolean(), nullable=False, server_default=sa.text('true')),
    )


def downgrade() -> None:
    op.drop_column('tenant_settings', 'enable_ml')

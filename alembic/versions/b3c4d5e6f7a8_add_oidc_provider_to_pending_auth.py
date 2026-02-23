"""Add oidc_provider column to pending_auth

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-02-22

Stores the OIDC provider key (e.g. "google", "microsoft") alongside
the OAuth state so the callback can route to the correct provider config.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'b3c4d5e6f7a8'
down_revision: Union[str, Sequence[str]] = 'a2b3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('pending_auth', sa.Column('oidc_provider', sa.String(100), nullable=True))


def downgrade() -> None:
    op.drop_column('pending_auth', 'oidc_provider')

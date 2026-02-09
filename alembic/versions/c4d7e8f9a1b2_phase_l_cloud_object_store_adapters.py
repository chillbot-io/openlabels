"""Phase L: Cloud object store adapters (S3 + GCS)

Revision ID: c4d7e8f9a1b2
Revises: b3f8a1c2d4e5
Create Date: 2026-02-09

Adds:
- ``s3`` and ``gcs`` values to the ``adapter_type`` enum
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c4d7e8f9a1b2'
down_revision: Union[str, Sequence[str]] = 'b3f8a1c2d4e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE adapter_type ADD VALUE IF NOT EXISTS 's3'")
    op.execute("ALTER TYPE adapter_type ADD VALUE IF NOT EXISTS 'gcs'")


def downgrade() -> None:
    # PostgreSQL does not support removing values from an enum type.
    # A full enum recreation would be needed, but is rarely worth the risk.
    pass

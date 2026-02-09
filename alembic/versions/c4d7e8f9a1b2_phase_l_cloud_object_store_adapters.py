"""Phase L: Cloud object store adapters (S3 + GCS)

Revision ID: c4d7e8f9a1b2
Revises: b3f8a1c2d4e5
Create Date: 2026-02-09

Note: s3, gcs, and azure_blob are now included in the initial migration's
adapter_type enum.  This migration is kept as a no-op to preserve the
revision chain for any existing installations.
"""
from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = 'c4d7e8f9a1b2'
down_revision: Union[str, Sequence[str]] = 'b3f8a1c2d4e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

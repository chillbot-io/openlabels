"""Add saved_credentials table

Revision ID: a2b3c4d5e6f7
Revises: f9b0c1d2e3f4
Create Date: 2026-02-22

Adds a table for persistent, encrypted credential storage so that
scheduled scans can authenticate to data sources (SMB, etc.) without
requiring the user to re-enter credentials each session.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = 'a2b3c4d5e6f7'
down_revision: Union[str, Sequence[str]] = 'f9b0c1d2e3f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'saved_credentials',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_id', UUID(as_uuid=True), sa.ForeignKey('scan_targets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('source_type', sa.String(50), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('encrypted_data', sa.Text, nullable=False),
        sa.Column('fields_stored', JSONB, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_by', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_saved_creds_tenant_source', 'saved_credentials', ['tenant_id', 'source_type'])
    op.create_index('ix_saved_creds_target', 'saved_credentials', ['target_id'])


def downgrade() -> None:
    op.drop_index('ix_saved_creds_target', table_name='saved_credentials')
    op.drop_index('ix_saved_creds_tenant_source', table_name='saved_credentials')
    op.drop_table('saved_credentials')

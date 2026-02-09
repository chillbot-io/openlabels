"""Add session, pending_auth, tenant_settings tables and missing columns

Revision ID: 5f934314bd30
Revises: d5e6f7a8b9c0
Create Date: 2026-02-09

Adds:
- ``sessions`` table for database-backed session storage
- ``pending_auth`` table for PKCE OAuth state
- ``tenant_settings`` table for per-tenant configuration overrides
- ``scan_jobs.target_name`` column (denormalized for display)
- ``scan_results.adapter_item_id`` column (adapter file ID)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '5f934314bd30'
down_revision: Union[str, Sequence[str]] = 'd5e6f7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # sessions table
    # ------------------------------------------------------------------
    op.create_table(
        'sessions',
        sa.Column('id', sa.String(64), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('tenants.id'), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id'), nullable=True),
        sa.Column('data', postgresql.JSONB(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )
    op.create_index('ix_sessions_expires', 'sessions', ['expires_at'])
    op.create_index('ix_sessions_user', 'sessions', ['user_id'])

    # ------------------------------------------------------------------
    # pending_auth table
    # ------------------------------------------------------------------
    op.create_table(
        'pending_auth',
        sa.Column('state', sa.String(64), primary_key=True),
        sa.Column('redirect_uri', sa.Text(), nullable=False),
        sa.Column('callback_url', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )
    op.create_index('ix_pending_auth_created', 'pending_auth', ['created_at'])

    # ------------------------------------------------------------------
    # tenant_settings table
    # ------------------------------------------------------------------
    op.create_table(
        'tenant_settings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('tenants.id'), unique=True, nullable=False),
        sa.Column('azure_tenant_id', sa.String(36), nullable=True),
        sa.Column('azure_client_id', sa.String(36), nullable=True),
        sa.Column('azure_client_secret_set', sa.Boolean(),
                  server_default='false'),
        sa.Column('max_file_size_mb', sa.Integer(), server_default='100'),
        sa.Column('concurrent_files', sa.Integer(), server_default='10'),
        sa.Column('enable_ocr', sa.Boolean(), server_default='false'),
        sa.Column('enabled_entities', postgresql.JSONB(),
                  server_default='[]'),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id'), nullable=True),
    )
    op.create_index('ix_tenant_settings_tenant_id', 'tenant_settings',
                    ['tenant_id'], unique=True)

    # ------------------------------------------------------------------
    # Missing columns on existing tables
    # ------------------------------------------------------------------
    op.add_column(
        'scan_jobs',
        sa.Column('target_name', sa.String(255), nullable=True),
    )

    op.add_column(
        'scan_results',
        sa.Column('adapter_item_id', sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('scan_results', 'adapter_item_id')
    op.drop_column('scan_jobs', 'target_name')

    op.drop_index('ix_tenant_settings_tenant_id', table_name='tenant_settings')
    op.drop_table('tenant_settings')

    op.drop_index('ix_pending_auth_created', table_name='pending_auth')
    op.drop_table('pending_auth')

    op.drop_index('ix_sessions_user', table_name='sessions')
    op.drop_index('ix_sessions_expires', table_name='sessions')
    op.drop_table('sessions')

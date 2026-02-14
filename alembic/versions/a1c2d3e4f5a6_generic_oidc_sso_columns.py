"""Add generic OIDC SSO columns

Revision ID: a1c2d3e4f5a6
Revises: f9b0c1d2e3f4
Create Date: 2026-02-14

Adds provider-agnostic identity columns to support generic OIDC SSO:

Users table:
- external_id: Provider-agnostic external user identifier (OIDC sub or Azure oid)
- auth_provider: Which auth provider authenticated this user ('azure_ad', 'oidc', 'none')
  Backfilled from azure_oid: if azure_oid is set, auth_provider='azure_ad', external_id=azure_oid

Tenants table:
- idp_tenant_id: Provider-agnostic tenant identifier from the IdP
  Backfilled from azure_tenant_id

PendingAuth table:
- nonce: OIDC replay protection token (stored during login, validated in callback)

The legacy azure_oid and azure_tenant_id columns are kept for backward
compatibility. New code uses external_id/idp_tenant_id; old code continues
to work via the legacy columns until a future cleanup migration.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a1c2d3e4f5a6'
down_revision: Union[str, Sequence[str]] = 'f9b0c1d2e3f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Users table ---
    # Add external_id (nullable initially for backfill)
    op.add_column(
        'users',
        sa.Column('external_id', sa.String(255), nullable=True),
    )
    # Add auth_provider column
    op.add_column(
        'users',
        sa.Column('auth_provider', sa.String(20), nullable=False, server_default='azure_ad'),
    )

    # Backfill external_id from azure_oid
    op.execute("UPDATE users SET external_id = azure_oid WHERE azure_oid IS NOT NULL")

    # Index for external_id lookups
    op.create_index(
        'ix_users_external_id',
        'users',
        ['external_id'],
    )
    # Index for provider + external_id (unique user per provider)
    op.create_index(
        'ix_users_provider_external_id',
        'users',
        ['auth_provider', 'external_id'],
    )

    # --- Tenants table ---
    # Add idp_tenant_id
    op.add_column(
        'tenants',
        sa.Column('idp_tenant_id', sa.String(255), nullable=True),
    )
    # Add auth_provider to tenants too
    op.add_column(
        'tenants',
        sa.Column('auth_provider', sa.String(20), nullable=False, server_default='azure_ad'),
    )

    # Backfill idp_tenant_id from azure_tenant_id
    op.execute("UPDATE tenants SET idp_tenant_id = azure_tenant_id WHERE azure_tenant_id IS NOT NULL")

    # Index for idp_tenant_id lookups
    op.create_index(
        'ix_tenants_idp_tenant_id',
        'tenants',
        ['idp_tenant_id'],
    )

    # --- PendingAuth table ---
    # Add nonce column for OIDC replay protection
    op.add_column(
        'pending_auth',
        sa.Column('nonce', sa.String(64), nullable=True),
    )


def downgrade() -> None:
    # --- PendingAuth ---
    op.drop_column('pending_auth', 'nonce')

    # --- Tenants ---
    op.drop_index('ix_tenants_idp_tenant_id', table_name='tenants')
    op.drop_column('tenants', 'auth_provider')
    op.drop_column('tenants', 'idp_tenant_id')

    # --- Users ---
    op.drop_index('ix_users_provider_external_id', table_name='users')
    op.drop_index('ix_users_external_id', table_name='users')
    op.drop_column('users', 'auth_provider')
    op.drop_column('users', 'external_id')

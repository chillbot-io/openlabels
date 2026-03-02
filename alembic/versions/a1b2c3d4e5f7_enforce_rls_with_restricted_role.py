"""Enforce Row-Level Security with restricted application role.

Revision ID: a1b2c3d4e5f7
Revises: c1b8df0349fc, b3c4d5e6f7a8
Create Date: 2026-03-02 00:00:00.000000

Fixes CRITICAL findings C1, C2, C3:

C1 - RLS owner bypass: The previous migration (2fdd60bab56c) enabled RLS
     without FORCE, meaning the table owner bypasses all policies.  This
     migration adds ``ALTER TABLE ... FORCE ROW LEVEL SECURITY`` on every
     tenant-scoped table so that even the table owner is subject to RLS
     policies.

C2 - Incomplete table coverage: The original migration only covered 8
     tables.  This migration extends RLS + tenant_isolation policies to
     ALL tenant-scoped tables, including scan_schedules, job_queue,
     folder_inventory, file_inventory, remediation_actions, monitored_files,
     label_rules, tenant_settings, and alert_rules.

C3 - No restricted database role: The application connected as the table
     owner, which bypassed RLS entirely.  This migration creates a
     restricted ``openlabels_app`` role with only DML privileges (no DDL),
     so that RLS policies are enforced on all runtime queries.

Role separation
---------------
After this migration:
* The **owner role** (used for migrations) retains full privileges but is
  still subject to RLS via FORCE.
* The **openlabels_app role** is a restricted LOGIN role with only
  SELECT/INSERT/UPDATE/DELETE on tables and USAGE on sequences.  The
  application should connect as this role in production.

The ``openlabels_app`` role password is read from the environment variable
``OPENLABELS_APP_ROLE_PASSWORD``.  If the variable is not set, a default
placeholder is used and a warning is emitted -- operators MUST change it
before deploying to production.
"""
from __future__ import annotations

import logging
import os
from typing import Sequence, Union

from alembic import op

logger = logging.getLogger(__name__)

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f7'
down_revision: Union[str, Sequence[str]] = ('c1b8df0349fc', 'b3c4d5e6f7a8')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# ── Tables that already have RLS + tenant_isolation from 2fdd60bab56c ────
EXISTING_RLS_TABLES: list[str] = [
    'scan_results',
    'file_access_events',
    'audit_log',
    'scan_jobs',
    'scan_targets',
    'sensitivity_labels',
    'users',
    'sessions',
]

# ── New tables that need RLS + tenant_isolation policies ─────────────────
NEW_RLS_TABLES: list[str] = [
    'scan_schedules',
    'job_queue',
    'folder_inventory',
    'file_inventory',
    'remediation_actions',
    'monitored_files',
    'label_rules',
    'tenant_settings',
    'alert_rules',
]

# ── All tenant-scoped tables (union of the two lists) ────────────────────
ALL_RLS_TABLES: list[str] = EXISTING_RLS_TABLES + NEW_RLS_TABLES


def upgrade() -> None:
    # ── 1. Create the restricted application role ────────────────────────
    password = os.environ.get('OPENLABELS_APP_ROLE_PASSWORD')
    if not password:
        password = 'CHANGE_ME_BEFORE_PRODUCTION'
        logger.warning(
            "OPENLABELS_APP_ROLE_PASSWORD not set -- using placeholder "
            "password. You MUST change this before deploying to production."
        )

    # Use PL/pgSQL DO block so we can use IF NOT EXISTS logic for role
    # creation (CREATE ROLE has no IF NOT EXISTS clause in PostgreSQL).
    op.execute(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openlabels_app'
            ) THEN
                CREATE ROLE openlabels_app LOGIN PASSWORD '{password}';
            ELSE
                -- Ensure the password is up-to-date even if the role exists.
                ALTER ROLE openlabels_app WITH LOGIN PASSWORD '{password}';
            END IF;
        END
        $$;
    """)

    # ── 2. Grant DML privileges to openlabels_app ────────────────────────
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
        "IN SCHEMA public TO openlabels_app"
    )
    op.execute(
        "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO openlabels_app"
    )
    # Ensure future tables/sequences also get the grants automatically.
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO openlabels_app"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT USAGE ON SEQUENCES TO openlabels_app"
    )

    # ── 3. Enable RLS + create tenant_isolation policy on NEW tables ─────
    for table in NEW_RLS_TABLES:
        op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY')
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)"
        )

    # ── 4. FORCE RLS on ALL tenant-scoped tables ────────────────────────
    #    This ensures that even the table owner (migration role) is subject
    #    to RLS policies, closing the owner-bypass gap (C1).
    for table in ALL_RLS_TABLES:
        op.execute(f'ALTER TABLE {table} FORCE ROW LEVEL SECURITY')


def downgrade() -> None:
    # ── Reverse step 4: remove FORCE RLS from all tables ─────────────────
    for table in ALL_RLS_TABLES:
        op.execute(f'ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY')

    # ── Reverse step 3: drop policies and disable RLS on NEW tables ──────
    for table in NEW_RLS_TABLES:
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON {table}')
        op.execute(f'ALTER TABLE {table} DISABLE ROW LEVEL SECURITY')

    # ── Reverse step 2: revoke privileges from openlabels_app ────────────
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM openlabels_app"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE USAGE ON SEQUENCES FROM openlabels_app"
    )
    op.execute(
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
        "IN SCHEMA public FROM openlabels_app"
    )
    op.execute(
        "REVOKE USAGE ON ALL SEQUENCES IN SCHEMA public FROM openlabels_app"
    )

    # ── Reverse step 1: drop the restricted role ─────────────────────────
    # Use DO block to handle the case where the role does not exist.
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openlabels_app'
            ) THEN
                DROP ROLE openlabels_app;
            END IF;
        END
        $$;
    """)

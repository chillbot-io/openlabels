"""Complete RLS coverage: user isolation, sessions fix, tenants self-scope.

Revision ID: c158b3188879
Revises: a1b2c3d4e5f7, d6e7f8a9b0c1
Create Date: 2026-03-04 00:00:00.000000

Merge migration that also closes remaining RLS gaps found during audit:

1. **Merge heads**: Combines the ``a1b2c3d4e5f7`` (enforce RLS with
   restricted role) and ``d6e7f8a9b0c1`` (policy target assignments)
   branches into a single linear history.

2. **Sessions table fix**: The ``sessions`` table has a *nullable*
   ``tenant_id`` (pre-login sessions have no tenant).  The existing
   ``tenant_isolation`` policy uses ``tenant_id = current_setting(...)``
   which evaluates to FALSE when ``tenant_id IS NULL``, silently hiding
   anonymous sessions from all queries.  This migration replaces the
   policy with one that handles NULLs correctly:

       USING (
           tenant_id = current_setting('app.current_tenant_id', true)::uuid
           OR (tenant_id IS NULL
               AND user_id = current_setting('app.current_user_id', true)::uuid)
       )

3. **User isolation for sessions**: Adds ``app.current_user_id`` support
   so that user-scoped rows in ``sessions`` (where tenant_id IS NULL but
   user_id IS NOT NULL) are visible only to the owning user.

4. **Tenants table self-scope**: Applies RLS on the ``tenants`` table
   itself so that a compromised tenant session cannot enumerate other
   tenants.  Policy: ``id = current_setting('app.current_tenant_id', true)::uuid``.

5. **``set_rls_context`` helper**: Adds a SQL helper function
   ``set_rls_context(tenant_uuid, user_uuid)`` that sets both
   ``app.current_tenant_id`` and ``app.current_user_id`` in a single
   call, using ``SET LOCAL`` (transaction-scoped).
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c158b3188879'
down_revision: Union[str, Sequence[str]] = ('a1b2c3d4e5f7', 'd6e7f8a9b0c1')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Create SQL helper function for setting RLS context ─────────
    #    Wraps SET LOCAL for both tenant and user IDs in a single call.
    op.execute("""
        CREATE OR REPLACE FUNCTION set_rls_context(
            p_tenant_id uuid DEFAULT NULL,
            p_user_id   uuid DEFAULT NULL
        ) RETURNS void
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF p_tenant_id IS NOT NULL THEN
                PERFORM set_config('app.current_tenant_id', p_tenant_id::text, true);
            END IF;
            IF p_user_id IS NOT NULL THEN
                PERFORM set_config('app.current_user_id', p_user_id::text, true);
            END IF;
        END;
        $$;
    """)

    # ── 2. RLS on the ``tenants`` table (self-scope) ──────────────────
    op.execute('ALTER TABLE tenants ENABLE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE tenants FORCE ROW LEVEL SECURITY')
    op.execute(
        "CREATE POLICY tenant_isolation ON tenants "
        "USING (id = current_setting('app.current_tenant_id', true)::uuid)"
    )

    # ── 3. Fix the ``sessions`` table policy ──────────────────────────
    #    Drop the old tenant-only policy and replace with one that
    #    handles nullable tenant_id + user_id fallback.
    op.execute('DROP POLICY IF EXISTS tenant_isolation ON sessions')
    op.execute("""
        CREATE POLICY tenant_user_isolation ON sessions
        USING (
            tenant_id = current_setting('app.current_tenant_id', true)::uuid
            OR (
                tenant_id IS NULL
                AND user_id = current_setting('app.current_user_id', true)::uuid
            )
        )
    """)


def downgrade() -> None:
    # ── Reverse 3: Restore original sessions policy ───────────────────
    op.execute('DROP POLICY IF EXISTS tenant_user_isolation ON sessions')
    op.execute(
        "CREATE POLICY tenant_isolation ON sessions "
        "USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)"
    )

    # ── Reverse 2: Remove RLS from tenants table ─────────────────────
    op.execute('DROP POLICY IF EXISTS tenant_isolation ON tenants')
    op.execute('ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY')
    op.execute('ALTER TABLE tenants DISABLE ROW LEVEL SECURITY')

    # ── Reverse 1: Drop the helper function ──────────────────────────
    op.execute('DROP FUNCTION IF EXISTS set_rls_context(uuid, uuid)')

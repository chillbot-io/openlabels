"""Add Row-Level Security policies for tenant isolation.

Revision ID: 2fdd60bab56c
Revises: 8e0ee9ee0126
Create Date: 2026-02-27 12:00:00.000000

Enables PostgreSQL Row-Level Security (RLS) on the highest-risk tables as
defense-in-depth for multi-tenant isolation.  The application already enforces
tenant scoping via WHERE clauses; RLS adds database-level enforcement so that
even a SQL-injection or application bug cannot leak data across tenants.

Policy
------
Each table gets a ``tenant_isolation`` policy:

    CREATE POLICY tenant_isolation ON <table>
        USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)

The second argument ``true`` to ``current_setting`` means "return NULL when the
variable is not set".  A NULL comparison always evaluates to FALSE, so the
safe default when no tenant context is active is **deny all rows**.

Owner bypass
------------
We use ``ENABLE ROW LEVEL SECURITY`` (without ``FORCE``) so that the table
owner (the DB role used for migrations and the application) bypasses RLS.
This means:

* Migrations run unaffected (they use the owner role directly).
* The application also bypasses RLS *today* because it uses the same owner
  role for runtime queries.

TODO: For true runtime enforcement, create a separate limited DB role
(e.g. ``openlabels_app``) that is NOT the table owner, grant it
SELECT/INSERT/UPDATE/DELETE, and have the application connect as that role.
At that point RLS will be enforced on all runtime queries automatically.
Until then, the policies serve as:
1. Documentation of the expected access pattern.
2. Immediate protection if/when role separation is implemented.
3. A safety net that can be activated with ``ALTER TABLE ... FORCE ROW LEVEL
   SECURITY`` once the separate role is in place.

Tables covered
--------------
- scan_results       (partitioned — RLS on parent propagates to partitions)
- file_access_events (partitioned — same)
- audit_log
- scan_jobs
- scan_targets
- sensitivity_labels
- users
- sessions
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '2fdd60bab56c'
down_revision: Union[str, Sequence[str]] = '8e0ee9ee0126'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# High-risk tables that store tenant-scoped data.
# Order does not matter; each statement is independent.
RLS_TABLES: list[str] = [
    'scan_results',
    'file_access_events',
    'audit_log',
    'scan_jobs',
    'scan_targets',
    'sensitivity_labels',
    'users',
    'sessions',
]


def upgrade() -> None:
    for table in RLS_TABLES:
        # Enable RLS (without FORCE — owner role bypasses).
        op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY')

        # Create the tenant isolation policy.
        # current_setting('app.current_tenant_id', true) returns NULL when
        # the session variable is not set, which makes the USING clause
        # evaluate to NULL (i.e. FALSE) — deny all rows by default.
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)"
        )


def downgrade() -> None:
    for table in RLS_TABLES:
        # Drop the policy first, then disable RLS.
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON {table}')
        op.execute(f'ALTER TABLE {table} DISABLE ROW LEVEL SECURITY')

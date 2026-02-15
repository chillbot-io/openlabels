"""Expand audit_action enum with new action types

Revision ID: b2d3e4f5a6b7
Revises: a1c2d3e4f5a6
Create Date: 2026-02-14

Adds new audit action types for comprehensive audit logging:
- policy_created, policy_updated, policy_deleted
- settings_updated
- login_success, login_failed, logout, session_revoked
- report_generated, report_distributed
- siem_exported
- label_rule_created, label_rule_deleted
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b2d3e4f5a6b7'
down_revision: Union[str, Sequence[str]] = 'a1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# New enum values to add
NEW_VALUES = [
    'policy_created',
    'policy_updated',
    'policy_deleted',
    'settings_updated',
    'login_success',
    'login_failed',
    'logout',
    'session_revoked',
    'report_generated',
    'report_distributed',
    'siem_exported',
    'label_rule_created',
    'label_rule_deleted',
]


def upgrade() -> None:
    # PostgreSQL allows adding values to an existing enum type
    # Each ADD VALUE must be in its own transaction or outside a transaction block
    for value in NEW_VALUES:
        op.execute(f"ALTER TYPE audit_action ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    # PostgreSQL does not support removing values from an enum type.
    # A full enum replacement would be needed, which is complex and risky.
    # For safety, downgrade is a no-op — the extra enum values are harmless.
    pass

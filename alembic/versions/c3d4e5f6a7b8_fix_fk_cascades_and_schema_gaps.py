"""Fix FK ondelete cascades, nullability, and missing columns.

- Add ondelete CASCADE/SET NULL to all foreign keys per model definitions
- Fix file_inventory.last_scan_job_id to be nullable (supports SET NULL on delete)
- Add tenant_settings.adapter_defaults JSONB column

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-02-13
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str]] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, constraint_name, column, referenced_table.referenced_column, ondelete)
FK_FIXES = [
    # users
    ("users", "users_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    # scan_targets
    ("scan_targets", "scan_targets_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("scan_targets", "scan_targets_created_by_fkey", "created_by", "users.id", "SET NULL"),
    # scan_schedules
    ("scan_schedules", "scan_schedules_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("scan_schedules", "scan_schedules_target_id_fkey", "target_id", "scan_targets.id", "CASCADE"),
    ("scan_schedules", "scan_schedules_created_by_fkey", "created_by", "users.id", "SET NULL"),
    # scan_jobs
    ("scan_jobs", "scan_jobs_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("scan_jobs", "scan_jobs_schedule_id_fkey", "schedule_id", "scan_schedules.id", "SET NULL"),
    ("scan_jobs", "scan_jobs_target_id_fkey", "target_id", "scan_targets.id", "CASCADE"),
    ("scan_jobs", "scan_jobs_created_by_fkey", "created_by", "users.id", "SET NULL"),
    # scan_results
    ("scan_results", "scan_results_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("scan_results", "scan_results_job_id_fkey", "job_id", "scan_jobs.id", "CASCADE"),
    # sensitivity_labels
    ("sensitivity_labels", "sensitivity_labels_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    # label_rules
    ("label_rules", "label_rules_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("label_rules", "label_rules_label_id_fkey", "label_id", "sensitivity_labels.id", "CASCADE"),
    ("label_rules", "label_rules_created_by_fkey", "created_by", "users.id", "SET NULL"),
    # audit_log
    ("audit_log", "audit_log_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("audit_log", "audit_log_user_id_fkey", "user_id", "users.id", "SET NULL"),
    # job_queue
    ("job_queue", "job_queue_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    # folder_inventory
    ("folder_inventory", "folder_inventory_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("folder_inventory", "folder_inventory_target_id_fkey", "target_id", "scan_targets.id", "CASCADE"),
    ("folder_inventory", "folder_inventory_last_scan_job_id_fkey", "last_scan_job_id", "scan_jobs.id", "SET NULL"),
    # file_inventory
    ("file_inventory", "file_inventory_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("file_inventory", "file_inventory_target_id_fkey", "target_id", "scan_targets.id", "CASCADE"),
    ("file_inventory", "file_inventory_folder_id_fkey", "folder_id", "folder_inventory.id", "SET NULL"),
    ("file_inventory", "file_inventory_last_scan_job_id_fkey", "last_scan_job_id", "scan_jobs.id", "SET NULL"),
    # remediation_actions
    ("remediation_actions", "remediation_actions_tenant_id_fkey", "tenant_id", "tenants.id", "CASCADE"),
    ("remediation_actions", "remediation_actions_file_inventory_id_fkey", "file_inventory_id", "file_inventory.id", "SET NULL"),
    ("remediation_actions", "remediation_actions_created_by_fkey", "created_by", "users.id", "SET NULL"),
]


def upgrade() -> None:
    # 1. Fix FK ondelete rules by dropping and recreating each constraint
    for table, constraint, column, ref, ondelete in FK_FIXES:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(constraint, table, ref.split(".")[0], [column], [ref.split(".")[1]], ondelete=ondelete)

    # 2. Fix file_inventory.last_scan_job_id to be nullable (required for SET NULL ondelete)
    op.alter_column('file_inventory', 'last_scan_job_id', nullable=True)

    # 3. Add tenant_settings.adapter_defaults JSONB column
    op.add_column('tenant_settings', sa.Column('adapter_defaults', postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    # Remove adapter_defaults column
    op.drop_column('tenant_settings', 'adapter_defaults')

    # Revert file_inventory.last_scan_job_id to NOT NULL
    op.alter_column('file_inventory', 'last_scan_job_id', nullable=False)

    # Revert FK constraints to no ondelete
    for table, constraint, column, ref, _ondelete in reversed(FK_FIXES):
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(constraint, table, ref.split(".")[0], [column], [ref.split(".")[1]])

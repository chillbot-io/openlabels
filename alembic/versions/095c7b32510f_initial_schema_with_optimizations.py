"""initial_schema_with_optimizations

Revision ID: 095c7b32510f
Revises:
Create Date: 2026-02-01 22:09:59.253415

This migration creates the complete OpenLabels database schema with:
- UUIDv7 primary keys (time-sorted for better index locality)
- Native PostgreSQL ENUM types for type safety
- Comprehensive indexes for query patterns
- New remediation and monitoring tables
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '095c7b32510f'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all tables with ENUMs and indexes."""

    # ==========================================================================
    # CREATE ENUM TYPES
    # ==========================================================================

    op.execute("CREATE TYPE user_role AS ENUM ('admin', 'viewer')")
    op.execute("CREATE TYPE adapter_type AS ENUM ('filesystem', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob')")
    op.execute("CREATE TYPE job_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled')")
    op.execute("CREATE TYPE risk_tier AS ENUM ('MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')")
    op.execute("CREATE TYPE exposure_level AS ENUM ('PRIVATE', 'INTERNAL', 'ORG_WIDE', 'PUBLIC')")
    op.execute("CREATE TYPE label_rule_type AS ENUM ('risk_tier', 'entity_type', 'exposure_level', 'custom')")
    op.execute("""
        CREATE TYPE audit_action AS ENUM (
            'scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled',
            'label_applied', 'label_removed', 'label_sync',
            'target_created', 'target_updated', 'target_deleted',
            'user_created', 'user_updated', 'user_deleted',
            'schedule_created', 'schedule_updated', 'schedule_deleted',
            'quarantine_executed', 'lockdown_executed', 'rollback_executed',
            'monitoring_enabled', 'monitoring_disabled'
        )
    """)
    op.execute("CREATE TYPE remediation_action_type AS ENUM ('quarantine', 'lockdown', 'rollback')")
    op.execute("CREATE TYPE remediation_status AS ENUM ('pending', 'completed', 'failed', 'rolled_back')")
    op.execute("CREATE TYPE access_action AS ENUM ('read', 'write', 'delete', 'rename', 'permission_change', 'execute')")

    # ==========================================================================
    # CREATE TABLES
    # ==========================================================================

    # tenants
    op.create_table(
        'tenants',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('azure_tenant_id', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_tenants_azure_tenant_id', 'tenants', ['azure_tenant_id'])

    # users
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('name', sa.String(255), nullable=True),
        sa.Column('role', postgresql.ENUM('admin', 'viewer', name='user_role', create_type=False), server_default='viewer'),
        sa.Column('azure_oid', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_users_tenant_email', 'users', ['tenant_id', 'email'], unique=True)
    op.create_index('ix_users_azure_oid', 'users', ['azure_oid'])

    # scan_targets
    op.create_table(
        'scan_targets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('adapter', postgresql.ENUM('filesystem', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob', name='adapter_type', create_type=False), nullable=False),
        sa.Column('config', postgresql.JSONB, nullable=False),
        sa.Column('enabled', sa.Boolean, server_default='true'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_scan_targets_tenant_name', 'scan_targets', ['tenant_id', 'name'])
    op.create_index('ix_scan_targets_tenant_enabled', 'scan_targets', ['tenant_id', 'enabled'])

    # scan_schedules
    op.create_table(
        'scan_schedules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('cron', sa.String(100), nullable=True),
        sa.Column('enabled', sa.Boolean, server_default='true'),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_scan_schedules_tenant_enabled', 'scan_schedules', ['tenant_id', 'enabled'])
    op.create_index('ix_scan_schedules_next_run', 'scan_schedules', ['next_run_at'], postgresql_where='enabled = true')

    # scan_jobs
    op.create_table(
        'scan_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('schedule_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_schedules.id'), nullable=True),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=True),
        sa.Column('status', postgresql.ENUM('pending', 'running', 'completed', 'failed', 'cancelled', name='job_status', create_type=False), server_default='pending'),
        sa.Column('progress', postgresql.JSONB, nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('files_scanned', sa.Integer, server_default='0'),
        sa.Column('files_with_pii', sa.Integer, server_default='0'),
        sa.Column('error', sa.Text, nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_scan_jobs_tenant_status', 'scan_jobs', ['tenant_id', 'status'])
    op.create_index('ix_scan_jobs_tenant_created', 'scan_jobs', ['tenant_id', 'created_at'])
    op.create_index('ix_scan_jobs_target_created', 'scan_jobs', ['target_id', 'created_at'])

    # scan_results
    op.create_table(
        'scan_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=False),
        sa.Column('file_path', sa.Text, nullable=False),
        sa.Column('file_name', sa.String(255), nullable=False),
        sa.Column('file_size', sa.BigInteger, nullable=True),
        sa.Column('file_modified', sa.DateTime(timezone=True), nullable=True),
        sa.Column('content_hash', sa.String(64), nullable=True),
        sa.Column('risk_score', sa.Integer, nullable=False),
        sa.Column('risk_tier', postgresql.ENUM('MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='risk_tier', create_type=False), nullable=False),
        sa.Column('content_score', sa.Float, nullable=True),
        sa.Column('exposure_multiplier', sa.Float, nullable=True),
        sa.Column('co_occurrence_rules', postgresql.JSONB(), nullable=True),
        sa.Column('exposure_level', postgresql.ENUM('PRIVATE', 'INTERNAL', 'ORG_WIDE', 'PUBLIC', name='exposure_level', create_type=False), nullable=True),
        sa.Column('owner', sa.String(255), nullable=True),
        sa.Column('entity_counts', postgresql.JSONB, nullable=False),
        sa.Column('total_entities', sa.Integer, nullable=False),
        sa.Column('findings', postgresql.JSONB, nullable=True),
        sa.Column('current_label_id', sa.String(36), nullable=True),
        sa.Column('current_label_name', sa.String(255), nullable=True),
        sa.Column('recommended_label_id', sa.String(36), nullable=True),
        sa.Column('recommended_label_name', sa.String(255), nullable=True),
        sa.Column('label_applied', sa.Boolean, server_default='false'),
        sa.Column('label_applied_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('label_error', sa.Text, nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_scan_results_tenant_risk_time', 'scan_results', ['tenant_id', 'risk_tier', 'scanned_at'])
    op.create_index('ix_scan_results_tenant_path', 'scan_results', ['tenant_id', 'file_path'])
    op.create_index('ix_scan_results_job_time', 'scan_results', ['job_id', 'scanned_at'])
    op.create_index('ix_scan_results_tenant_label', 'scan_results', ['tenant_id', 'label_applied', 'scanned_at'])
    op.create_index('ix_scan_results_entities', 'scan_results', ['entity_counts'], postgresql_using='gin')

    # sensitivity_labels
    op.create_table(
        'sensitivity_labels',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('priority', sa.Integer, nullable=True),
        sa.Column('color', sa.String(7), nullable=True),
        sa.Column('parent_id', sa.String(36), nullable=True),
        sa.Column('synced_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_sensitivity_labels_tenant_priority', 'sensitivity_labels', ['tenant_id', 'priority'])

    # label_rules
    op.create_table(
        'label_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('rule_type', postgresql.ENUM('risk_tier', 'entity_type', 'exposure_level', 'custom', name='label_rule_type', create_type=False), nullable=False),
        sa.Column('match_value', sa.String(100), nullable=False),
        sa.Column('label_id', sa.String(36), sa.ForeignKey('sensitivity_labels.id'), nullable=False),
        sa.Column('priority', sa.Integer, server_default='0'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_label_rules_tenant_type', 'label_rules', ['tenant_id', 'rule_type', 'priority'])

    # audit_log
    op.create_table(
        'audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('action', postgresql.ENUM(
            'scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled',
            'label_applied', 'label_removed', 'label_sync',
            'target_created', 'target_updated', 'target_deleted',
            'user_created', 'user_updated', 'user_deleted',
            'schedule_created', 'schedule_updated', 'schedule_deleted',
            'quarantine_executed', 'lockdown_executed', 'rollback_executed',
            'monitoring_enabled', 'monitoring_disabled',
            name='audit_action', create_type=False
        ), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('details', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_audit_log_tenant_time', 'audit_log', ['tenant_id', 'created_at'])
    op.create_index('ix_audit_log_tenant_action', 'audit_log', ['tenant_id', 'action', 'created_at'])
    op.create_index('ix_audit_log_resource', 'audit_log', ['resource_type', 'resource_id'])

    # job_queue
    op.create_table(
        'job_queue',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('task_type', sa.String(50), nullable=False),
        sa.Column('payload', postgresql.JSONB, nullable=False),
        sa.Column('priority', sa.Integer, server_default='50'),
        sa.Column('status', postgresql.ENUM('pending', 'running', 'completed', 'failed', 'cancelled', name='job_status', create_type=False), server_default='pending'),
        sa.Column('scheduled_for', sa.DateTime(timezone=True), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('worker_id', sa.String(100), nullable=True),
        sa.Column('result', postgresql.JSONB, nullable=True),
        sa.Column('error', sa.Text, nullable=True),
        sa.Column('retry_count', sa.Integer, server_default='0'),
        sa.Column('max_retries', sa.Integer, server_default='3'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_job_queue_pending', 'job_queue', ['status', 'priority', 'scheduled_for'], postgresql_where="status = 'pending'")
    op.create_index('ix_job_queue_tenant_status', 'job_queue', ['tenant_id', 'status', 'created_at'])

    # folder_inventory
    op.create_table(
        'folder_inventory',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('folder_path', sa.Text, nullable=False),
        sa.Column('adapter', postgresql.ENUM('filesystem', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob', name='adapter_type', create_type=False), nullable=False),
        sa.Column('file_count', sa.Integer, server_default='0'),
        sa.Column('total_size_bytes', sa.BigInteger, nullable=True),
        sa.Column('folder_modified', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_scan_job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=True),
        sa.Column('has_sensitive_files', sa.Boolean, server_default='false'),
        sa.Column('highest_risk_tier', postgresql.ENUM('MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='risk_tier', create_type=False), nullable=True),
        sa.Column('total_entities_found', sa.Integer, server_default='0'),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        comment='Folder-level inventory for delta scanning',
    )
    op.create_index('ix_folder_inventory_tenant_target_path', 'folder_inventory', ['tenant_id', 'target_id', 'folder_path'], unique=True)
    op.create_index('ix_folder_inventory_sensitive', 'folder_inventory', ['tenant_id', 'has_sensitive_files', 'highest_risk_tier'])

    # file_inventory
    op.create_table(
        'file_inventory',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('folder_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('folder_inventory.id'), nullable=True),
        sa.Column('file_path', sa.Text, nullable=False),
        sa.Column('file_name', sa.String(255), nullable=False),
        sa.Column('adapter', postgresql.ENUM('filesystem', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob', name='adapter_type', create_type=False), nullable=False),
        sa.Column('content_hash', sa.String(64), nullable=True),
        sa.Column('file_size', sa.BigInteger, nullable=True),
        sa.Column('file_modified', sa.DateTime(timezone=True), nullable=True),
        sa.Column('risk_score', sa.Integer, nullable=False),
        sa.Column('risk_tier', postgresql.ENUM('MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='risk_tier', create_type=False), nullable=False),
        sa.Column('entity_counts', postgresql.JSONB, nullable=False),
        sa.Column('total_entities', sa.Integer, nullable=False),
        sa.Column('exposure_level', postgresql.ENUM('PRIVATE', 'INTERNAL', 'ORG_WIDE', 'PUBLIC', name='exposure_level', create_type=False), nullable=True),
        sa.Column('owner', sa.String(255), nullable=True),
        sa.Column('current_label_id', sa.String(36), nullable=True),
        sa.Column('current_label_name', sa.String(255), nullable=True),
        sa.Column('label_applied_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_scan_job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=False),
        sa.Column('scan_count', sa.Integer, server_default='1'),
        sa.Column('content_changed_count', sa.Integer, server_default='0'),
        sa.Column('is_monitored', sa.Boolean, server_default='true'),
        sa.Column('needs_rescan', sa.Boolean, server_default='false'),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        comment='File-level inventory for sensitive files',
    )
    op.create_index('ix_file_inventory_tenant_target_path', 'file_inventory', ['tenant_id', 'target_id', 'file_path'], unique=True)
    op.create_index('ix_file_inventory_tenant_risk', 'file_inventory', ['tenant_id', 'risk_tier', 'updated_at'])
    op.create_index('ix_file_inventory_hash', 'file_inventory', ['content_hash'])
    op.create_index('ix_file_inventory_monitored', 'file_inventory', ['tenant_id', 'is_monitored', 'needs_rescan'])

    # ==========================================================================
    # REMEDIATION TABLES
    # ==========================================================================

    # remediation_actions
    op.create_table(
        'remediation_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('file_inventory_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('file_inventory.id'), nullable=True),
        sa.Column('action_type', postgresql.ENUM('quarantine', 'lockdown', 'rollback', name='remediation_action_type', create_type=False), nullable=False),
        sa.Column('status', postgresql.ENUM('pending', 'completed', 'failed', 'rolled_back', name='remediation_status', create_type=False), server_default='pending'),
        sa.Column('source_path', sa.Text, nullable=False),
        sa.Column('dest_path', sa.Text, nullable=True),
        sa.Column('performed_by', sa.String(255), nullable=False),
        sa.Column('principals', postgresql.JSONB, nullable=True),
        sa.Column('previous_acl', sa.Text, nullable=True),
        sa.Column('dry_run', sa.Boolean, server_default='false'),
        sa.Column('error', sa.Text, nullable=True),
        sa.Column('rollback_of_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('remediation_actions.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_remediation_tenant_time', 'remediation_actions', ['tenant_id', 'created_at'])
    op.create_index('ix_remediation_tenant_type_status', 'remediation_actions', ['tenant_id', 'action_type', 'status'])
    op.create_index('ix_remediation_source_path', 'remediation_actions', ['tenant_id', 'source_path'])

    # ==========================================================================
    # MONITORING TABLES
    # ==========================================================================

    # monitored_files
    op.create_table(
        'monitored_files',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('file_inventory_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('file_inventory.id'), nullable=True),
        sa.Column('file_path', sa.Text, nullable=False),
        sa.Column('risk_tier', postgresql.ENUM('MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='risk_tier', create_type=False), nullable=False),
        sa.Column('sacl_enabled', sa.Boolean, server_default='false'),
        sa.Column('audit_rule_enabled', sa.Boolean, server_default='false'),
        sa.Column('audit_read', sa.Boolean, server_default='true'),
        sa.Column('audit_write', sa.Boolean, server_default='true'),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('access_count', sa.Integer, server_default='0'),
        sa.Column('enabled_by', sa.String(255), nullable=True),
    )
    op.create_index('ix_monitored_files_tenant_path', 'monitored_files', ['tenant_id', 'file_path'], unique=True)
    op.create_index('ix_monitored_files_tenant_risk', 'monitored_files', ['tenant_id', 'risk_tier'])
    op.create_index('ix_monitored_files_last_event', 'monitored_files', ['tenant_id', 'last_event_at'])

    # file_access_events
    op.create_table(
        'file_access_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('monitored_file_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('monitored_files.id'), nullable=False),
        sa.Column('file_path', sa.Text, nullable=False),
        sa.Column('action', postgresql.ENUM('read', 'write', 'delete', 'rename', 'permission_change', 'execute', name='access_action', create_type=False), nullable=False),
        sa.Column('success', sa.Boolean, server_default='true'),
        sa.Column('user_sid', sa.String(100), nullable=True),
        sa.Column('user_name', sa.String(255), nullable=True),
        sa.Column('user_domain', sa.String(255), nullable=True),
        sa.Column('process_name', sa.String(255), nullable=True),
        sa.Column('process_id', sa.Integer, nullable=True),
        sa.Column('event_id', sa.Integer, nullable=True),
        sa.Column('event_source', sa.String(50), nullable=True),
        sa.Column('event_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('raw_event', postgresql.JSONB, nullable=True),
    )
    op.create_index('ix_access_events_file_time', 'file_access_events', ['tenant_id', 'file_path', 'event_time'])
    op.create_index('ix_access_events_user_time', 'file_access_events', ['tenant_id', 'user_name', 'event_time'])
    op.create_index('ix_access_events_monitored', 'file_access_events', ['monitored_file_id', 'event_time'])
    op.create_index('ix_access_events_tenant_action', 'file_access_events', ['tenant_id', 'action', 'event_time'])


def downgrade() -> None:
    """Drop all tables and enums in reverse order."""

    # Drop tables in reverse dependency order
    op.drop_table('file_access_events')
    op.drop_table('monitored_files')
    op.drop_table('remediation_actions')
    op.drop_table('file_inventory')
    op.drop_table('folder_inventory')
    op.drop_table('job_queue')
    op.drop_table('audit_log')
    op.drop_table('label_rules')
    op.drop_table('sensitivity_labels')
    op.drop_table('scan_results')
    op.drop_table('scan_jobs')
    op.drop_table('scan_schedules')
    op.drop_table('scan_targets')
    op.drop_table('users')
    op.drop_table('tenants')

    # Drop enum types
    op.execute('DROP TYPE access_action')
    op.execute('DROP TYPE remediation_status')
    op.execute('DROP TYPE remediation_action_type')
    op.execute('DROP TYPE audit_action')
    op.execute('DROP TYPE label_rule_type')
    op.execute('DROP TYPE exposure_level')
    op.execute('DROP TYPE risk_tier')
    op.execute('DROP TYPE job_status')
    op.execute('DROP TYPE adapter_type')
    op.execute('DROP TYPE user_role')

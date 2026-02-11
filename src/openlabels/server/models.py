"""
SQLAlchemy database models for OpenLabels.

Design principles:
- UUIDv7 for primary keys (time-sorted for better index locality)
- Native PostgreSQL ENUMs for type safety and performance
- Explicit indexes for common query patterns
- JSONB for truly flexible data only
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID as PyUUID

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ENUM, UUID
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from openlabels.server.db import Base

# =============================================================================
# CROSS-DATABASE JSON TYPE
# =============================================================================

class JSONB(TypeDecorator):
    """
    Cross-database JSON type.

    Uses PostgreSQL JSONB when available (for performance and indexing),
    falls back to standard JSON for SQLite testing.
    """
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(PG_JSONB())
        return dialect.type_descriptor(JSON())

# =============================================================================
# UUID v7 GENERATION
# =============================================================================

try:
    from uuid_utils import uuid7
except ImportError:
    # Fallback to uuid4 if uuid-utils not installed
    from uuid import uuid4 as uuid7  # type: ignore


def generate_uuid() -> PyUUID:
    """
    Generate a time-sorted UUID (v7) for use as primary key.

    UUIDv7 embeds a timestamp in the first 48 bits, which means:
    - UUIDs generated close in time sort together
    - Better B-tree index locality than random UUIDv4
    - ~20% faster inserts at scale

    Falls back to UUIDv4 if uuid-utils is not installed.

    Note: Always returns a standard library uuid.UUID to ensure compatibility
    with asyncpg which returns standard UUIDs from PostgreSQL.
    """
    generated = uuid7()
    # Ensure we return a standard library UUID, not uuid_utils.UUID
    if not isinstance(generated, PyUUID):
        return PyUUID(str(generated))
    return generated


# =============================================================================
# POSTGRESQL ENUM TYPES
# =============================================================================

# User roles
UserRoleEnum = ENUM(
    'admin', 'viewer',
    name='user_role',
    create_type=True,
)

# Adapter types for scan targets
AdapterTypeEnum = ENUM(
    'filesystem', 'sharepoint', 'onedrive', 's3', 'gcs', 'azure_blob',
    name='adapter_type',
    create_type=True,
)

# Job/scan status
JobStatusEnum = ENUM(
    'pending', 'running', 'completed', 'failed', 'cancelled',
    name='job_status',
    create_type=True,
)

# Risk tiers
RiskTierEnum = ENUM(
    'MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL',
    name='risk_tier',
    create_type=True,
)

# Exposure levels
ExposureLevelEnum = ENUM(
    'PRIVATE', 'INTERNAL', 'ORG_WIDE', 'PUBLIC',
    name='exposure_level',
    create_type=True,
)

# Label rule types
LabelRuleTypeEnum = ENUM(
    'risk_tier', 'entity_type', 'exposure_level', 'custom',
    name='label_rule_type',
    create_type=True,
)

# Audit log actions
AuditActionEnum = ENUM(
    'scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled',
    'label_applied', 'label_removed', 'label_sync',
    'target_created', 'target_updated', 'target_deleted',
    'user_created', 'user_updated', 'user_deleted',
    'schedule_created', 'schedule_updated', 'schedule_deleted',
    'quarantine_executed', 'lockdown_executed', 'rollback_executed',
    'monitoring_enabled', 'monitoring_disabled',
    'policy_violation',
    name='audit_action',
    create_type=True,
)

# Remediation action types
RemediationActionTypeEnum = ENUM(
    'quarantine', 'lockdown', 'rollback',
    name='remediation_action_type',
    create_type=True,
)

# Remediation status
RemediationStatusEnum = ENUM(
    'pending', 'completed', 'failed', 'rolled_back',
    name='remediation_status',
    create_type=True,
)

# File access action types
AccessActionEnum = ENUM(
    'read', 'write', 'delete', 'rename', 'permission_change', 'execute',
    name='access_action',
    create_type=True,
)


# =============================================================================
# CORE MODELS
# =============================================================================


class Tenant(Base):
    """Multi-tenancy support."""

    __tablename__ = "tenants"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    azure_tenant_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    users: Mapped[list[User]] = relationship(back_populates="tenant")
    scan_targets: Mapped[list[ScanTarget]] = relationship(back_populates="tenant")
    scan_jobs: Mapped[list[ScanJob]] = relationship(back_populates="tenant")

    __table_args__ = (
        Index('ix_tenants_azure_tenant_id', 'azure_tenant_id'),
    )


class User(Base):
    """User accounts."""

    __tablename__ = "users"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(UserRoleEnum, default="viewer")
    azure_oid: Mapped[str | None] = mapped_column(String(36))  # Azure AD object ID
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    tenant: Mapped[Tenant] = relationship(back_populates="users")

    __table_args__ = (
        Index('ix_users_tenant_email', 'tenant_id', 'email', unique=True),
        Index('ix_users_azure_oid', 'azure_oid'),
    )


class ScanTarget(Base):
    """Configured locations to scan."""

    __tablename__ = "scan_targets"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    adapter: Mapped[str] = mapped_column(AdapterTypeEnum, nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)  # Adapter-specific config
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    tenant: Mapped[Tenant] = relationship(back_populates="scan_targets")
    schedules: Mapped[list[ScanSchedule]] = relationship(back_populates="target")

    __table_args__ = (
        Index('ix_scan_targets_tenant_name', 'tenant_id', 'name'),
        Index('ix_scan_targets_tenant_enabled', 'tenant_id', 'enabled'),
    )


class ScanSchedule(Base):
    """Scheduled scans."""

    __tablename__ = "scan_schedules"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)
    cron: Mapped[str | None] = mapped_column(String(100))  # Cron expression
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    target: Mapped[ScanTarget] = relationship(back_populates="schedules")
    jobs: Mapped[list[ScanJob]] = relationship(back_populates="schedule")

    __table_args__ = (
        Index('ix_scan_schedules_tenant_enabled', 'tenant_id', 'enabled'),
        Index('ix_scan_schedules_next_run', 'next_run_at', postgresql_where='enabled = true'),
    )


class ScanJob(Base):
    """Individual scan executions."""

    __tablename__ = "scan_jobs"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    schedule_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("scan_schedules.id"))
    target_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)
    target_name: Mapped[str | None] = mapped_column(String(255))  # Denormalized for display/history
    name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(JobStatusEnum, default="pending")
    progress: Mapped[dict | None] = mapped_column(JSONB)  # {files_scanned, files_total, current_file}
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    files_with_pii: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Fan-out columns for horizontal scaling
    scan_mode: Mapped[str | None] = mapped_column(String(20))  # 'single' or 'fanout'; NULL = single
    total_partitions: Mapped[int | None] = mapped_column(Integer)  # Number of partitions created
    partitions_completed: Mapped[int | None] = mapped_column(Integer)  # Completed partition count
    partitions_failed: Mapped[int | None] = mapped_column(Integer)  # Failed partition count
    total_files_estimated: Mapped[int | None] = mapped_column(Integer)  # Pre-scan estimate

    # Relationships
    tenant: Mapped[Tenant] = relationship(back_populates="scan_jobs")
    schedule: Mapped[Optional[ScanSchedule]] = relationship(back_populates="jobs")
    results: Mapped[list[ScanResult]] = relationship(back_populates="job")
    partitions: Mapped[list[ScanPartition]] = relationship(back_populates="job")

    __table_args__ = (
        Index('ix_scan_jobs_tenant_status', 'tenant_id', 'status'),
        Index('ix_scan_jobs_tenant_created', 'tenant_id', 'created_at'),
        Index('ix_scan_jobs_target_created', 'target_id', 'created_at'),
    )


class ScanPartition(Base):
    """
    A partition of work within a fan-out scan job.

    When a scan target is large enough to benefit from horizontal scaling,
    the coordinator splits it into N partitions. Each partition is an
    independent unit of work that a worker can claim and execute.
    """

    __tablename__ = "scan_partitions"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    job_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False)

    # Partition identity
    partition_index: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-based
    total_partitions: Mapped[int] = mapped_column(Integer, nullable=False)

    # What to scan — adapter-specific partition boundaries
    # S3/GCS/Azure: {"start_after": "m", "end_before": "t", "prefix": "data/"}
    # Filesystem: {"directory": "/mnt/share/finance"}
    # SharePoint: {"site_id": "abc123"}
    partition_spec: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Execution state
    status: Mapped[str] = mapped_column(JobStatusEnum, default="pending")
    worker_id: Mapped[str | None] = mapped_column(String(100))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Progress
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    files_with_pii: Mapped[int] = mapped_column(Integer, default=0)
    files_skipped: Mapped[int] = mapped_column(Integer, default=0)
    total_entities: Mapped[int] = mapped_column(Integer, default=0)

    # Full stats from scan (risk breakdown, inventory, etc.)
    stats: Mapped[dict | None] = mapped_column(JSONB)

    # Error tracking
    error: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)

    # Checkpoint for resume on failure
    last_processed_path: Mapped[str | None] = mapped_column(Text)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    job: Mapped[ScanJob] = relationship(back_populates="partitions")

    __table_args__ = (
        Index('ix_scan_partitions_job_status', 'job_id', 'status'),
        Index('ix_scan_partitions_job_index', 'job_id', 'partition_index', unique=True),
        Index('ix_scan_partitions_tenant_status', 'tenant_id', 'status'),
    )


class ScanResult(Base):
    """Per-file scan results."""

    __tablename__ = "scan_results"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    job_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False)

    # File identification
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    file_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str | None] = mapped_column(String(64))  # SHA-256
    adapter_item_id: Mapped[str | None] = mapped_column(String(512))  # Original adapter file ID (e.g. Graph API drive item ID)

    # Risk scoring
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    risk_tier: Mapped[str] = mapped_column(RiskTierEnum, nullable=False)

    # Score breakdown
    content_score: Mapped[float | None] = mapped_column(Float)
    exposure_multiplier: Mapped[float | None] = mapped_column(Float)
    co_occurrence_rules: Mapped[list[str] | None] = mapped_column(JSONB)  # List stored as JSON for cross-db compat

    # Exposure
    exposure_level: Mapped[str | None] = mapped_column(ExposureLevelEnum)
    owner: Mapped[str | None] = mapped_column(String(255))

    # Entity summary
    entity_counts: Mapped[dict] = mapped_column(JSONB, nullable=False)  # {"SSN": 5, "CREDIT_CARD": 2}
    total_entities: Mapped[int] = mapped_column(Integer, nullable=False)

    # Detailed findings (optional)
    findings: Mapped[dict | None] = mapped_column(JSONB)

    # Policy violations (Phase J)
    policy_violations: Mapped[list | None] = mapped_column(JSONB)

    # Labeling status
    current_label_id: Mapped[str | None] = mapped_column(String(36))
    current_label_name: Mapped[str | None] = mapped_column(String(255))
    recommended_label_id: Mapped[str | None] = mapped_column(String(36))
    recommended_label_name: Mapped[str | None] = mapped_column(String(255))
    label_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    label_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    label_error: Mapped[str | None] = mapped_column(Text)

    # Timestamps
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    job: Mapped[ScanJob] = relationship(back_populates="results")

    __table_args__ = (
        # Primary query patterns
        Index('ix_scan_results_tenant_risk_time', 'tenant_id', 'risk_tier', 'scanned_at'),
        Index('ix_scan_results_tenant_path', 'tenant_id', 'file_path'),
        Index('ix_scan_results_job_time', 'job_id', 'scanned_at'),
        # For dashboard queries
        Index('ix_scan_results_tenant_label', 'tenant_id', 'label_applied', 'scanned_at'),
        # GIN index for JSONB queries on entity_counts
        Index('ix_scan_results_entities', 'entity_counts', postgresql_using='gin'),
        # Range-partitioned by scanned_at (monthly).  The actual DB primary
        # key is (id, scanned_at) — required by PostgreSQL for partitioned
        # tables.  SQLAlchemy keeps id as the sole ORM identity key so that
        # session.get(ScanResult, uuid) still works (scans all partitions).
        {"postgresql_partition_by": "RANGE (scanned_at)"},
    )


class SensitivityLabel(Base):
    """Sensitivity labels synced from M365."""

    __tablename__ = "sensitivity_labels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # MIP label GUID
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[int | None] = mapped_column(Integer)
    color: Mapped[str | None] = mapped_column(String(7))  # Hex color
    parent_id: Mapped[str | None] = mapped_column(String(36))
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    rules: Mapped[list[LabelRule]] = relationship(back_populates="label")

    __table_args__ = (
        Index('ix_sensitivity_labels_tenant_priority', 'tenant_id', 'priority'),
    )


class LabelRule(Base):
    """Rules for automatic label assignment."""

    __tablename__ = "label_rules"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    rule_type: Mapped[str] = mapped_column(LabelRuleTypeEnum, nullable=False)
    match_value: Mapped[str] = mapped_column(String(100), nullable=False)  # 'CRITICAL' | 'SSN'
    label_id: Mapped[str] = mapped_column(ForeignKey("sensitivity_labels.id"), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    label: Mapped[SensitivityLabel] = relationship(back_populates="rules")

    __table_args__ = (
        Index('ix_label_rules_tenant_type', 'tenant_id', 'rule_type', 'priority'),
    )


class AuditLog(Base):
    """Audit trail for all actions."""

    __tablename__ = "audit_log"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    user_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(AuditActionEnum, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[PyUUID | None] = mapped_column(UUID(as_uuid=True))
    details: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index('ix_audit_log_tenant_time', 'tenant_id', 'created_at'),
        Index('ix_audit_log_tenant_action', 'tenant_id', 'action', 'created_at'),
        Index('ix_audit_log_resource', 'resource_type', 'resource_id'),
    )


class JobQueue(Base):
    """PostgreSQL-backed job queue."""

    __tablename__ = "job_queue"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'scan', 'label', 'export'
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50)  # 0-100
    status: Mapped[str] = mapped_column(JobStatusEnum, default="pending")
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[str | None] = mapped_column(String(100))
    result: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        # For worker polling: find pending jobs by priority
        Index('ix_job_queue_pending', 'status', 'priority', 'scheduled_for',
              postgresql_where="status = 'pending'"),
        Index('ix_job_queue_tenant_status', 'tenant_id', 'status', 'created_at'),
    )


# =============================================================================
# DATA INVENTORY MODELS (for delta scanning)
# =============================================================================


class FolderInventory(Base):
    """
    Folder-level inventory for delta scanning.

    Tracks all folders discovered during scans. Non-sensitive folders are
    only tracked at this level, enabling efficient delta scans by comparing
    folder modification times.
    """

    __tablename__ = "folder_inventory"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    target_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)

    # Folder identification
    folder_path: Mapped[str] = mapped_column(Text, nullable=False)
    adapter: Mapped[str] = mapped_column(AdapterTypeEnum, nullable=False)

    # Folder metadata
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    total_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    folder_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Scan tracking
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_job_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("scan_jobs.id"))

    # Risk summary for folder
    has_sensitive_files: Mapped[bool] = mapped_column(Boolean, default=False)
    highest_risk_tier: Mapped[str | None] = mapped_column(RiskTierEnum)
    total_entities_found: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index('ix_folder_inventory_tenant_target_path', 'tenant_id', 'target_id', 'folder_path', unique=True),
        Index('ix_folder_inventory_sensitive', 'tenant_id', 'has_sensitive_files', 'highest_risk_tier'),
        {"comment": "Folder-level inventory for delta scanning"},
    )


class FileInventory(Base):
    """
    File-level inventory for sensitive files only.

    Only files with detected sensitive data are tracked at the file level.
    This enables:
    1. Efficient delta scans (only re-scan if content_hash changed)
    2. Label tracking over time
    3. Sensitive file monitoring
    """

    __tablename__ = "file_inventory"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    target_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)
    folder_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("folder_inventory.id"))

    # File identification
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    adapter: Mapped[str] = mapped_column(AdapterTypeEnum, nullable=False)

    # Content tracking for delta scans
    content_hash: Mapped[str | None] = mapped_column(String(64))  # SHA-256
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    file_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Risk information
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_tier: Mapped[str] = mapped_column(RiskTierEnum, nullable=False)
    entity_counts: Mapped[dict] = mapped_column(JSONB, nullable=False)
    total_entities: Mapped[int] = mapped_column(Integer, nullable=False)

    # Exposure
    exposure_level: Mapped[str | None] = mapped_column(ExposureLevelEnum)
    owner: Mapped[str | None] = mapped_column(String(255))

    # Label tracking
    current_label_id: Mapped[str | None] = mapped_column(String(36))
    current_label_name: Mapped[str | None] = mapped_column(String(255))
    label_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Scan tracking
    last_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_scan_job_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False)
    scan_count: Mapped[int] = mapped_column(Integer, default=1)
    content_changed_count: Mapped[int] = mapped_column(Integer, default=0)

    # Monitoring flags
    is_monitored: Mapped[bool] = mapped_column(Boolean, default=True)  # Track changes
    needs_rescan: Mapped[bool] = mapped_column(Boolean, default=False)  # Force rescan

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    folder: Mapped[Optional[FolderInventory]] = relationship()

    __table_args__ = (
        Index('ix_file_inventory_tenant_target_path', 'tenant_id', 'target_id', 'file_path', unique=True),
        Index('ix_file_inventory_tenant_risk', 'tenant_id', 'risk_tier', 'updated_at'),
        Index('ix_file_inventory_hash', 'content_hash'),
        Index('ix_file_inventory_monitored', 'tenant_id', 'is_monitored', 'needs_rescan'),
        {"comment": "File-level inventory for sensitive files"},
    )


# =============================================================================
# REMEDIATION MODELS
# =============================================================================


class RemediationAction(Base):
    """
    Track remediation actions (quarantine, lockdown) for audit and rollback.

    Each action is immutable - rollbacks create a new action record.
    """

    __tablename__ = "remediation_actions"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    file_inventory_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("file_inventory.id"))

    # Action details
    action_type: Mapped[str] = mapped_column(RemediationActionTypeEnum, nullable=False)
    status: Mapped[str] = mapped_column(RemediationStatusEnum, default='pending')

    # File paths
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    dest_path: Mapped[str | None] = mapped_column(Text)  # For quarantine

    # Execution details
    performed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    principals: Mapped[dict | None] = mapped_column(JSONB)  # For lockdown: allowed principals
    previous_acl: Mapped[str | None] = mapped_column(Text)  # Base64 encoded for rollback

    # Flags
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text)

    # Rollback reference
    rollback_of_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("remediation_actions.id"))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Self-referential relationship for rollbacks
    rollback_of: Mapped[Optional[RemediationAction]] = relationship(
        remote_side=[id], foreign_keys=[rollback_of_id]
    )

    __table_args__ = (
        Index('ix_remediation_tenant_time', 'tenant_id', 'created_at'),
        Index('ix_remediation_tenant_type_status', 'tenant_id', 'action_type', 'status'),
        Index('ix_remediation_source_path', 'tenant_id', 'source_path'),
    )


# =============================================================================
# MONITORING MODELS
# =============================================================================


class MonitoredFile(Base):
    """
    Files registered for access monitoring.

    Replaces the in-memory registry for persistence across restarts
    and multi-worker support.
    """

    __tablename__ = "monitored_files"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    file_inventory_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("file_inventory.id"))

    # File identification
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    risk_tier: Mapped[str] = mapped_column(RiskTierEnum, nullable=False)

    # Monitoring configuration
    sacl_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    audit_rule_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    audit_read: Mapped[bool] = mapped_column(Boolean, default=True)
    audit_write: Mapped[bool] = mapped_column(Boolean, default=True)

    # Statistics
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    access_count: Mapped[int] = mapped_column(Integer, default=0)

    # Who enabled monitoring
    enabled_by: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (
        Index('ix_monitored_files_tenant_path', 'tenant_id', 'file_path', unique=True),
        Index('ix_monitored_files_tenant_risk', 'tenant_id', 'risk_tier'),
        Index('ix_monitored_files_last_event', 'tenant_id', 'last_event_at'),
    )


class FileAccessEvent(Base):
    """
    File access events collected from SACL (Windows) or auditd (Linux).

    Range-partitioned by event_time (monthly) for efficient retention
    management and query performance at scale.
    """

    __tablename__ = "file_access_events"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    monitored_file_id: Mapped[PyUUID] = mapped_column(ForeignKey("monitored_files.id"), nullable=False)

    # File info (denormalized for query performance)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)

    # Action
    action: Mapped[str] = mapped_column(AccessActionEnum, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=True)

    # User info
    user_sid: Mapped[str | None] = mapped_column(String(100))  # Windows SID or Linux UID
    user_name: Mapped[str | None] = mapped_column(String(255))
    user_domain: Mapped[str | None] = mapped_column(String(255))

    # Process info
    process_name: Mapped[str | None] = mapped_column(String(255))
    process_id: Mapped[int | None] = mapped_column(Integer)

    # Event source info
    event_id: Mapped[int | None] = mapped_column(Integer)  # Windows Event ID or audit serial
    event_source: Mapped[str | None] = mapped_column(String(50))  # 'windows_sacl', 'auditd'

    # Timing
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Raw event for debugging (optional, can be disabled for space)
    raw_event: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        # Primary query: "who accessed this file recently?"
        Index('ix_access_events_file_time', 'tenant_id', 'file_path', 'event_time'),
        # Secondary query: "what did this user access?"
        Index('ix_access_events_user_time', 'tenant_id', 'user_name', 'event_time'),
        # For updating monitored_file statistics
        Index('ix_access_events_monitored', 'monitored_file_id', 'event_time'),
        # For dashboard: recent events by action type
        Index('ix_access_events_tenant_action', 'tenant_id', 'action', 'event_time'),
        # Range-partitioned by event_time (monthly).
        {"postgresql_partition_by": "RANGE (event_time)"},
    )


# =============================================================================
# SESSION MODELS
# =============================================================================


class Session(Base):
    """
    Database-backed session storage.

    Replaces in-memory session dict for production use:
    - Survives server restarts
    - Works with multiple workers
    - Supports session limits per user
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # Secure token
    tenant_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))

    # Session data (tokens, claims)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Expiration
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index('ix_sessions_expires', 'expires_at'),
        Index('ix_sessions_user', 'user_id'),
    )


class PendingAuth(Base):
    """
    PKCE state storage for OAuth flow.

    Temporary storage during login - entries expire after 10 minutes.
    """

    __tablename__ = "pending_auth"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    callback_url: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index('ix_pending_auth_created', 'created_at'),
    )


class TenantSettings(Base):
    """
    Tenant-specific settings overrides.

    Stores per-tenant configuration such as Azure AD credentials,
    scan parameters, and entity detection preferences. One row per tenant;
    absence of a row means the tenant uses system defaults.

    Note: Azure client secrets are NOT stored here. Only a boolean flag
    tracks whether a secret has been configured (the actual secret would
    be stored in a secrets manager in production).
    """

    __tablename__ = "tenant_settings"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), unique=True, nullable=False)

    # Azure AD configuration
    azure_tenant_id: Mapped[str | None] = mapped_column(String(36))
    azure_client_id: Mapped[str | None] = mapped_column(String(36))
    azure_client_secret_set: Mapped[bool] = mapped_column(Boolean, default=False)

    # Scan configuration
    max_file_size_mb: Mapped[int] = mapped_column(Integer, default=100)
    concurrent_files: Mapped[int] = mapped_column(Integer, default=10)
    enable_ocr: Mapped[bool] = mapped_column(Boolean, default=False)

    # Entity detection configuration
    enabled_entities: Mapped[list] = mapped_column(JSONB, default=list)

    # Horizontal scaling / fan-out configuration
    fanout_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    fanout_threshold: Mapped[int] = mapped_column(Integer, default=10000)  # Min files to trigger fan-out
    fanout_max_partitions: Mapped[int] = mapped_column(Integer, default=16)  # Max partitions per scan

    # Pipeline parallelism (within a single worker)
    pipeline_max_concurrent_files: Mapped[int] = mapped_column(Integer, default=8)  # Max files in flight
    pipeline_memory_budget_mb: Mapped[int] = mapped_column(Integer, default=512)  # Max in-flight content MB

    # Audit fields
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))

    __table_args__ = (
        Index('ix_tenant_settings_tenant_id', 'tenant_id', unique=True),
    )


class Policy(Base):
    """Tenant-scoped policy configurations (Phase J).

    Each row represents a policy pack loaded from a built-in template or
    user-defined YAML/JSON.  The ``config`` JSONB column stores the full
    serialized ``PolicyPack`` so it can be reconstituted by the engine at
    evaluation time.
    """

    __tablename__ = "policies"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    framework: Mapped[str] = mapped_column(String(50), nullable=False)  # hipaa, gdpr, pci_dss, soc2 …
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, server_default="high")
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)  # Serialized PolicyPack
    priority: Mapped[int] = mapped_column(Integer, server_default="0")

    # Audit
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))

    __table_args__ = (
        Index('ix_policies_tenant_framework', 'tenant_id', 'framework'),
        Index('ix_policies_tenant_enabled', 'tenant_id', 'enabled'),
    )


# =============================================================================
# REPORTING (Phase M)
# =============================================================================

class ScanSummary(Base):
    """Pre-aggregated per-job summary for fast dashboard queries.

    Computed once when a scan job completes (or all partitions finish).
    Dashboard endpoints read from this table instead of re-aggregating
    scan_results on every request, eliminating expensive GROUP BY queries
    on multi-million-row tables.
    """

    __tablename__ = "scan_summaries"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    job_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False, unique=True)
    target_id: Mapped[PyUUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)

    # Aggregate counts
    files_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_with_pii: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Risk tier breakdown
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    minimal_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Entity type breakdown (top entity types and counts)
    entity_type_counts: Mapped[dict | None] = mapped_column(JSONB)  # {"SSN": 1234, "EMAIL": 5678}

    # Scan metadata
    scan_mode: Mapped[str | None] = mapped_column(String(20))  # 'single', 'fanout', 'delta'
    total_partitions: Mapped[int | None] = mapped_column(Integer)
    scan_duration_seconds: Mapped[float | None] = mapped_column(Float)

    # Label stats
    files_labeled: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_label_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Timestamps
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index('ix_scan_summaries_tenant_completed', 'tenant_id', 'completed_at'),
        Index('ix_scan_summaries_target_completed', 'target_id', 'completed_at'),
        Index('ix_scan_summaries_tenant_risk', 'tenant_id', 'critical_count', 'high_count'),
    )


class Report(Base):
    """Generated report record (Phase M).

    Tracks metadata for each generated report: type, format, storage
    location, and optional distribution status.
    """

    __tablename__ = "reports"

    id: Mapped[PyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[PyUUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)  # executive_summary, compliance_report, …
    format: Mapped[str] = mapped_column(String(10), nullable=False)  # html, pdf, csv
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")  # pending, generated, distributed, failed
    filters: Mapped[dict | None] = mapped_column(JSONB)  # Query filters used to generate
    result_path: Mapped[str | None] = mapped_column(Text)  # Storage path for generated file
    result_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    error: Mapped[str | None] = mapped_column(Text)

    # Distribution
    distributed_to: Mapped[list | None] = mapped_column(JSONB)  # [{"type": "email", "to": [...]}]
    distributed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Audit
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[PyUUID | None] = mapped_column(ForeignKey("users.id"))

    __table_args__ = (
        Index('ix_reports_tenant_type', 'tenant_id', 'report_type'),
        Index('ix_reports_tenant_created', 'tenant_id', 'created_at'),
    )

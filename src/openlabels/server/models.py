"""
SQLAlchemy database models for OpenLabels.
"""

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    BigInteger,
    ARRAY,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from openlabels.server.db import Base


class Tenant(Base):
    """Multi-tenancy support."""

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    azure_tenant_id: Mapped[Optional[str]] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    users: Mapped[list["User"]] = relationship(back_populates="tenant")
    scan_targets: Mapped[list["ScanTarget"]] = relationship(back_populates="tenant")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="tenant")


class User(Base):
    """User accounts."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="viewer")  # 'admin' | 'viewer'
    azure_oid: Mapped[Optional[str]] = mapped_column(String(36))  # Azure AD object ID
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="users")


class ScanTarget(Base):
    """Configured locations to scan."""

    __tablename__ = "scan_targets"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    adapter: Mapped[str] = mapped_column(String(50), nullable=False)  # 'filesystem', 'sharepoint', 'onedrive'
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)  # Adapter-specific config
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="scan_targets")
    schedules: Mapped[list["ScanSchedule"]] = relationship(back_populates="target")


class ScanSchedule(Base):
    """Scheduled scans."""

    __tablename__ = "scan_schedules"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_id: Mapped[UUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)
    cron: Mapped[Optional[str]] = mapped_column(String(100))  # Cron expression
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    target: Mapped["ScanTarget"] = relationship(back_populates="schedules")
    jobs: Mapped[list["ScanJob"]] = relationship(back_populates="schedule")


class ScanJob(Base):
    """Individual scan executions."""

    __tablename__ = "scan_jobs"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    schedule_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("scan_schedules.id"))
    target_id: Mapped[UUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, running, completed, failed, cancelled
    progress: Mapped[Optional[dict]] = mapped_column(JSONB)  # {files_scanned, files_total, current_file}
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    files_with_pii: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="scan_jobs")
    schedule: Mapped[Optional["ScanSchedule"]] = relationship(back_populates="jobs")
    results: Mapped[list["ScanResult"]] = relationship(back_populates="job")


class ScanResult(Base):
    """Per-file scan results."""

    __tablename__ = "scan_results"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    job_id: Mapped[UUID] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False)

    # File identification
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[Optional[int]] = mapped_column(BigInteger)
    file_modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[Optional[str]] = mapped_column(String(64))  # SHA-256

    # Risk scoring
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    risk_tier: Mapped[str] = mapped_column(String(20), nullable=False)  # MINIMAL, LOW, MEDIUM, HIGH, CRITICAL

    # Score breakdown
    content_score: Mapped[Optional[float]] = mapped_column(Float)
    exposure_multiplier: Mapped[Optional[float]] = mapped_column(Float)
    co_occurrence_rules: Mapped[Optional[list[str]]] = mapped_column(ARRAY(Text))

    # Exposure
    exposure_level: Mapped[Optional[str]] = mapped_column(String(20))  # PRIVATE, INTERNAL, ORG_WIDE, PUBLIC
    owner: Mapped[Optional[str]] = mapped_column(String(255))

    # Entity summary
    entity_counts: Mapped[dict] = mapped_column(JSONB, nullable=False)  # {"SSN": 5, "CREDIT_CARD": 2}
    total_entities: Mapped[int] = mapped_column(Integer, nullable=False)

    # Detailed findings (optional)
    findings: Mapped[Optional[dict]] = mapped_column(JSONB)

    # Labeling status
    current_label_id: Mapped[Optional[str]] = mapped_column(String(36))
    current_label_name: Mapped[Optional[str]] = mapped_column(String(255))
    recommended_label_id: Mapped[Optional[str]] = mapped_column(String(36))
    recommended_label_name: Mapped[Optional[str]] = mapped_column(String(255))
    label_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    label_applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    label_error: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamps
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    job: Mapped["ScanJob"] = relationship(back_populates="results")


class SensitivityLabel(Base):
    """Sensitivity labels synced from M365."""

    __tablename__ = "sensitivity_labels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # MIP label GUID
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    color: Mapped[Optional[str]] = mapped_column(String(7))  # Hex color
    parent_id: Mapped[Optional[str]] = mapped_column(String(36))
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    rules: Mapped[list["LabelRule"]] = relationship(back_populates="label")


class LabelRule(Base):
    """Rules for automatic label assignment."""

    __tablename__ = "label_rules"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'risk_tier' | 'entity_type'
    match_value: Mapped[str] = mapped_column(String(100), nullable=False)  # 'CRITICAL' | 'SSN'
    label_id: Mapped[str] = mapped_column(ForeignKey("sensitivity_labels.id"), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    label: Mapped["SensitivityLabel"] = relationship(back_populates="rules")


class AuditLog(Base):
    """Audit trail for all actions."""

    __tablename__ = "audit_log"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    user_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # scan_started, label_applied, etc.
    resource_type: Mapped[Optional[str]] = mapped_column(String(50))
    resource_id: Mapped[Optional[UUID]] = mapped_column(UUID(as_uuid=True))
    details: Mapped[Optional[dict]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class JobQueue(Base):
    """PostgreSQL-backed job queue."""

    __tablename__ = "job_queue"

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'scan', 'label', 'export'
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50)  # 0-100
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, running, completed, failed
    scheduled_for: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[Optional[str]] = mapped_column(String(100))
    result: Mapped[Optional[dict]] = mapped_column(JSONB)
    error: Mapped[Optional[str]] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


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

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    target_id: Mapped[UUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)

    # Folder identification
    folder_path: Mapped[str] = mapped_column(Text, nullable=False)
    adapter: Mapped[str] = mapped_column(String(50), nullable=False)

    # Folder metadata
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    total_size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger)
    folder_modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Scan tracking
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_scan_job_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("scan_jobs.id"))

    # Risk summary for folder
    has_sensitive_files: Mapped[bool] = mapped_column(Boolean, default=False)
    highest_risk_tier: Mapped[Optional[str]] = mapped_column(String(20))  # MINIMAL, LOW, MEDIUM, HIGH, CRITICAL
    total_entities_found: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Index for fast lookups
    __table_args__ = (
        # Unique constraint on tenant + target + path
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

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    target_id: Mapped[UUID] = mapped_column(ForeignKey("scan_targets.id"), nullable=False)
    folder_id: Mapped[Optional[UUID]] = mapped_column(ForeignKey("folder_inventory.id"))

    # File identification
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    adapter: Mapped[str] = mapped_column(String(50), nullable=False)

    # Content tracking for delta scans
    content_hash: Mapped[Optional[str]] = mapped_column(String(64))  # SHA-256
    file_size: Mapped[Optional[int]] = mapped_column(BigInteger)
    file_modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Risk information
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(20), nullable=False)
    entity_counts: Mapped[dict] = mapped_column(JSONB, nullable=False)
    total_entities: Mapped[int] = mapped_column(Integer, nullable=False)

    # Exposure
    exposure_level: Mapped[Optional[str]] = mapped_column(String(20))
    owner: Mapped[Optional[str]] = mapped_column(String(255))

    # Label tracking
    current_label_id: Mapped[Optional[str]] = mapped_column(String(36))
    current_label_name: Mapped[Optional[str]] = mapped_column(String(255))
    label_applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Scan tracking
    last_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_scan_job_id: Mapped[UUID] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False)
    scan_count: Mapped[int] = mapped_column(Integer, default=1)
    content_changed_count: Mapped[int] = mapped_column(Integer, default=0)

    # Monitoring flags
    is_monitored: Mapped[bool] = mapped_column(Boolean, default=True)  # Track changes
    needs_rescan: Mapped[bool] = mapped_column(Boolean, default=False)  # Force rescan

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    folder: Mapped[Optional["FolderInventory"]] = relationship()

    __table_args__ = (
        {"comment": "File-level inventory for sensitive files"},
    )

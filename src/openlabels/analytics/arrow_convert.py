"""
SQLAlchemy model → PyArrow Table converters.

Each converter accepts an iterable of ORM model instances and returns
a :class:`pyarrow.Table` with the schema defined in :mod:`schemas`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

import pyarrow as pa

from openlabels.analytics.schemas import (
    ACCESS_EVENTS_SCHEMA,
    AUDIT_LOG_SCHEMA,
    FILE_INVENTORY_SCHEMA,
    FOLDER_INVENTORY_SCHEMA,
    REMEDIATION_ACTIONS_SCHEMA,
    SCAN_RESULTS_SCHEMA,
)

if TYPE_CHECKING:
    from openlabels.server.models import (
        AuditLog,
        FileAccessEvent,
        FileInventory,
        FolderInventory,
        RemediationAction,
        ScanResult,
    )


def _uuid_bytes(val: UUID | None) -> bytes | None:
    """Convert a UUID to 16 raw bytes for Parquet storage."""
    if val is None:
        return None
    return val.bytes


def _ts(val: datetime | None) -> datetime | None:
    """Ensure timestamp is UTC-aware for Arrow."""
    if val is None:
        return None
    if val.tzinfo is None:
        return val.replace(tzinfo=timezone.utc)
    return val


def _entity_counts_to_map(ec: dict | None) -> list[tuple[str, int]] | None:
    """Convert entity_counts dict to Arrow MAP-compatible list of tuples."""
    if not ec:
        return []
    return [(k, int(v)) for k, v in ec.items()]


# ── Scan Results ──────────────────────────────────────────────────────

def scan_results_to_arrow(rows: Iterable[ScanResult]) -> pa.Table:
    """Convert ScanResult ORM instances to a PyArrow Table."""
    records: dict[str, list] = {f.name: [] for f in SCAN_RESULTS_SCHEMA}

    for r in rows:
        records["id"].append(_uuid_bytes(r.id))
        records["job_id"].append(_uuid_bytes(r.job_id))
        records["tenant_id"].append(_uuid_bytes(r.tenant_id))
        records["file_path"].append(r.file_path)
        records["file_name"].append(r.file_name)
        records["file_size"].append(r.file_size)
        records["file_modified"].append(_ts(r.file_modified))
        records["content_hash"].append(r.content_hash)
        records["risk_score"].append(r.risk_score)
        records["risk_tier"].append(str(r.risk_tier) if r.risk_tier else None)
        records["content_score"].append(
            float(r.content_score) if r.content_score is not None else None
        )
        records["exposure_multiplier"].append(
            float(r.exposure_multiplier) if r.exposure_multiplier is not None else None
        )
        records["exposure_level"].append(
            str(r.exposure_level) if r.exposure_level else None
        )
        records["owner"].append(r.owner)
        records["entity_counts"].append(_entity_counts_to_map(r.entity_counts))
        records["total_entities"].append(r.total_entities)
        records["label_applied"].append(r.label_applied)
        records["current_label_name"].append(r.current_label_name)
        records["current_label_id"].append(
            r.current_label_id if hasattr(r, "current_label_id") else None
        )
        records["recommended_label_name"].append(
            r.recommended_label_name if hasattr(r, "recommended_label_name") else None
        )
        records["label_applied_at"].append(
            _ts(r.label_applied_at) if hasattr(r, "label_applied_at") and r.label_applied_at else None
        )
        records["label_error"].append(
            r.label_error if hasattr(r, "label_error") else None
        )
        records["scanned_at"].append(_ts(r.scanned_at))

    return pa.table(records, schema=SCAN_RESULTS_SCHEMA)


# ── File Inventory ────────────────────────────────────────────────────

def file_inventory_to_arrow(rows: Iterable[FileInventory]) -> pa.Table:
    """Convert FileInventory ORM instances to a PyArrow Table."""
    records: dict[str, list] = {f.name: [] for f in FILE_INVENTORY_SCHEMA}

    for r in rows:
        records["id"].append(_uuid_bytes(r.id))
        records["tenant_id"].append(_uuid_bytes(r.tenant_id))
        records["target_id"].append(_uuid_bytes(r.target_id))
        records["folder_id"].append(_uuid_bytes(r.folder_id))
        records["file_path"].append(r.file_path)
        records["file_name"].append(r.file_name)
        records["adapter"].append(str(r.adapter) if r.adapter else None)
        records["content_hash"].append(r.content_hash)
        records["file_size"].append(r.file_size)
        records["file_modified"].append(_ts(r.file_modified))
        records["risk_score"].append(r.risk_score)
        records["risk_tier"].append(str(r.risk_tier) if r.risk_tier else None)
        records["entity_counts"].append(_entity_counts_to_map(r.entity_counts))
        records["total_entities"].append(r.total_entities)
        records["exposure_level"].append(
            str(r.exposure_level) if r.exposure_level else None
        )
        records["owner"].append(r.owner)
        records["current_label_name"].append(r.current_label_name)
        records["current_label_id"].append(
            r.current_label_id if hasattr(r, "current_label_id") else None
        )
        records["label_applied_at"].append(
            _ts(r.label_applied_at) if hasattr(r, "label_applied_at") and r.label_applied_at else None
        )
        records["is_monitored"].append(
            r.is_monitored if hasattr(r, "is_monitored") else None
        )
        records["needs_rescan"].append(
            r.needs_rescan if hasattr(r, "needs_rescan") else None
        )
        records["last_scanned_at"].append(_ts(r.last_scanned_at))
        records["discovered_at"].append(
            _ts(r.discovered_at) if hasattr(r, "discovered_at") and r.discovered_at else None
        )
        records["updated_at"].append(
            _ts(r.updated_at) if hasattr(r, "updated_at") and r.updated_at else None
        )
        records["scan_count"].append(r.scan_count)
        records["content_changed_count"].append(r.content_changed_count)

    return pa.table(records, schema=FILE_INVENTORY_SCHEMA)


# ── Folder Inventory ─────────────────────────────────────────────────

def folder_inventory_to_arrow(rows: Iterable[FolderInventory]) -> pa.Table:
    """Convert FolderInventory ORM instances to a PyArrow Table."""
    records: dict[str, list] = {f.name: [] for f in FOLDER_INVENTORY_SCHEMA}

    for r in rows:
        records["id"].append(_uuid_bytes(r.id))
        records["tenant_id"].append(_uuid_bytes(r.tenant_id))
        records["target_id"].append(_uuid_bytes(r.target_id))
        records["folder_path"].append(r.folder_path)
        records["adapter"].append(str(r.adapter) if r.adapter else None)
        records["file_count"].append(r.file_count)
        records["total_size_bytes"].append(r.total_size_bytes)
        records["folder_modified"].append(_ts(r.folder_modified))
        records["last_scanned_at"].append(_ts(r.last_scanned_at))
        records["has_sensitive_files"].append(r.has_sensitive_files)
        records["highest_risk_tier"].append(
            str(r.highest_risk_tier) if r.highest_risk_tier else None
        )
        records["total_entities_found"].append(r.total_entities_found)
        records["discovered_at"].append(_ts(r.discovered_at))
        records["updated_at"].append(_ts(r.updated_at))

    return pa.table(records, schema=FOLDER_INVENTORY_SCHEMA)


# ── Access Events ─────────────────────────────────────────────────────

def access_events_to_arrow(rows: Iterable[FileAccessEvent]) -> pa.Table:
    """Convert FileAccessEvent ORM instances to a PyArrow Table."""
    records: dict[str, list] = {f.name: [] for f in ACCESS_EVENTS_SCHEMA}

    for r in rows:
        records["id"].append(_uuid_bytes(r.id))
        records["tenant_id"].append(_uuid_bytes(r.tenant_id))
        records["monitored_file_id"].append(_uuid_bytes(r.monitored_file_id))
        records["file_path"].append(r.file_path)
        records["action"].append(str(r.action) if r.action else None)
        records["success"].append(r.success)
        records["user_name"].append(r.user_name)
        records["user_domain"].append(r.user_domain)
        records["user_sid"].append(r.user_sid if hasattr(r, "user_sid") else None)
        records["process_name"].append(r.process_name)
        records["process_id"].append(r.process_id if hasattr(r, "process_id") else None)
        records["event_source"].append(
            str(r.event_source) if hasattr(r, "event_source") and r.event_source else None
        )
        records["event_time"].append(_ts(r.event_time))
        records["collected_at"].append(_ts(r.collected_at))

    return pa.table(records, schema=ACCESS_EVENTS_SCHEMA)


# ── Audit Log ─────────────────────────────────────────────────────────

def audit_log_to_arrow(rows: Iterable[AuditLog]) -> pa.Table:
    """Convert AuditLog ORM instances to a PyArrow Table."""
    records: dict[str, list] = {f.name: [] for f in AUDIT_LOG_SCHEMA}

    for r in rows:
        records["id"].append(_uuid_bytes(r.id))
        records["tenant_id"].append(_uuid_bytes(r.tenant_id))
        records["user_id"].append(_uuid_bytes(r.user_id))
        records["action"].append(str(r.action) if r.action else None)
        records["resource_type"].append(r.resource_type)
        records["resource_id"].append(_uuid_bytes(r.resource_id))
        records["details"].append(
            json.dumps(r.details) if r.details is not None else None
        )
        records["created_at"].append(_ts(r.created_at))

    return pa.table(records, schema=AUDIT_LOG_SCHEMA)


# ── Remediation Actions ──────────────────────────────────────────────

def remediation_actions_to_arrow(rows: Iterable[RemediationAction]) -> pa.Table:
    """Convert RemediationAction ORM instances to a PyArrow Table."""
    records: dict[str, list] = {f.name: [] for f in REMEDIATION_ACTIONS_SCHEMA}

    for r in rows:
        records["id"].append(_uuid_bytes(r.id))
        records["tenant_id"].append(_uuid_bytes(r.tenant_id))
        records["file_inventory_id"].append(_uuid_bytes(r.file_inventory_id))
        records["action_type"].append(str(r.action_type) if r.action_type else None)
        records["status"].append(str(r.status) if r.status else None)
        records["source_path"].append(r.source_path)
        records["dest_path"].append(r.dest_path)
        records["performed_by"].append(r.performed_by)
        records["dry_run"].append(r.dry_run)
        records["error"].append(r.error)
        records["created_at"].append(_ts(r.created_at))
        records["completed_at"].append(_ts(r.completed_at))

    return pa.table(records, schema=REMEDIATION_ACTIONS_SCHEMA)

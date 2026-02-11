"""
Shared fixtures for the analytics test suite.

DuckDB analytics is always active — these fixtures provide a
temporary catalog directory and DuckDB engine for test isolation.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pyarrow as pa
import pytest

from openlabels.analytics.engine import DuckDBEngine
from openlabels.analytics.schemas import (
    ACCESS_EVENTS_SCHEMA,
    AUDIT_LOG_SCHEMA,
    REMEDIATION_ACTIONS_SCHEMA,
    SCAN_RESULTS_SCHEMA,
)
from openlabels.analytics.service import AnalyticsService, DuckDBDashboardService
from openlabels.analytics.storage import LocalStorage


# ── Deterministic test UUIDs ──────────────────────────────────────────

TENANT_A = UUID("00000000-0000-0000-0000-000000000001")
TENANT_B = UUID("00000000-0000-0000-0000-000000000002")
TARGET_1 = UUID("00000000-0000-0000-0000-100000000001")
JOB_1 = UUID("00000000-0000-0000-0000-200000000001")
JOB_2 = UUID("00000000-0000-0000-0000-200000000002")


# ── Catalog directory fixture ─────────────────────────────────────────

@pytest.fixture()
def catalog_dir(tmp_path: Path) -> Path:
    """Return a fresh temporary directory for catalog Parquet files."""
    return tmp_path / "catalog"


@pytest.fixture()
def storage(catalog_dir: Path) -> LocalStorage:
    return LocalStorage(str(catalog_dir))


@pytest.fixture()
def engine(catalog_dir: Path) -> DuckDBEngine:
    """DuckDB engine pointing at the catalog temp dir."""
    e = DuckDBEngine(str(catalog_dir), memory_limit="256MB", threads=1)
    yield e
    e.close()


@pytest.fixture()
def analytics(engine: DuckDBEngine) -> AnalyticsService:
    svc = AnalyticsService(engine, max_workers=1)
    yield svc
    svc.close()


@pytest.fixture()
def dashboard_service(analytics: AnalyticsService) -> DuckDBDashboardService:
    return DuckDBDashboardService(analytics)


# ── Helper: write test Parquet ────────────────────────────────────────

def write_scan_results(
    storage: LocalStorage,
    *,
    tenant_id: UUID = TENANT_A,
    target_id: UUID = TARGET_1,
    job_id: UUID = JOB_1,
    rows: list[dict] | None = None,
    scan_date: str = "2026-02-01",
):
    """Write synthetic scan result rows to the catalog."""
    if rows is None:
        rows = _default_scan_result_rows(tenant_id, job_id)

    cols: dict[str, list] = {f.name: [] for f in SCAN_RESULTS_SCHEMA}
    for r in rows:
        for k in cols:
            cols[k].append(r.get(k))

    table = pa.table(cols, schema=SCAN_RESULTS_SCHEMA)
    path = (
        f"scan_results/tenant={tenant_id}/target={target_id}"
        f"/scan_date={scan_date}/part-00000.parquet"
    )
    storage.write_parquet(path, table)


def write_access_events(
    storage: LocalStorage,
    *,
    tenant_id: UUID = TENANT_A,
    rows: list[dict] | None = None,
    event_date: str = "2026-02-01",
):
    """Write synthetic access events."""
    if rows is None:
        rows = _default_access_event_rows(tenant_id)

    cols: dict[str, list] = {f.name: [] for f in ACCESS_EVENTS_SCHEMA}
    for r in rows:
        for k in cols:
            cols[k].append(r.get(k))

    table = pa.table(cols, schema=ACCESS_EVENTS_SCHEMA)
    path = (
        f"access_events/tenant={tenant_id}"
        f"/event_date={event_date}/part-00000.parquet"
    )
    storage.write_parquet(path, table)


# ── Default test data ─────────────────────────────────────────────────

def _default_scan_result_rows(
    tenant_id: UUID,
    job_id: UUID,
) -> list[dict]:
    now = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
    return [
        {
            "id": uuid4().bytes,
            "job_id": job_id.bytes,
            "tenant_id": tenant_id.bytes,
            "file_path": "/data/docs/report.pdf",
            "file_name": "report.pdf",
            "file_size": 102400,
            "file_modified": now,
            "content_hash": "abc123",
            "risk_score": 85,
            "risk_tier": "CRITICAL",
            "content_score": 75.0,
            "exposure_multiplier": 1.2,
            "exposure_level": "INTERNAL",
            "owner": "alice@test.com",
            "entity_counts": [("SSN", 3), ("EMAIL", 2)],
            "total_entities": 5,
            "label_applied": True,
            "current_label_name": "Highly Confidential",
            "scanned_at": now,
        },
        {
            "id": uuid4().bytes,
            "job_id": job_id.bytes,
            "tenant_id": tenant_id.bytes,
            "file_path": "/data/docs/readme.txt",
            "file_name": "readme.txt",
            "file_size": 512,
            "file_modified": now,
            "content_hash": "def456",
            "risk_score": 5,
            "risk_tier": "MINIMAL",
            "content_score": 0.0,
            "exposure_multiplier": 1.0,
            "exposure_level": "INTERNAL",
            "owner": "bob@test.com",
            "entity_counts": [],
            "total_entities": 0,
            "label_applied": False,
            "current_label_name": None,
            "scanned_at": now,
        },
        {
            "id": uuid4().bytes,
            "job_id": job_id.bytes,
            "tenant_id": tenant_id.bytes,
            "file_path": "/data/hr/payroll.xlsx",
            "file_name": "payroll.xlsx",
            "file_size": 204800,
            "file_modified": now,
            "content_hash": "ghi789",
            "risk_score": 60,
            "risk_tier": "HIGH",
            "content_score": 55.0,
            "exposure_multiplier": 1.1,
            "exposure_level": "PRIVATE",
            "owner": "carol@test.com",
            "entity_counts": [("SSN", 10), ("NAME", 5)],
            "total_entities": 15,
            "label_applied": False,
            "current_label_name": None,
            "scanned_at": now,
        },
    ]


def _default_access_event_rows(tenant_id: UUID) -> list[dict]:
    """5 events spread across days/hours for heatmap testing."""
    base = datetime(2026, 2, 2, 10, 30, 0, tzinfo=timezone.utc)  # Monday 10:30
    from datetime import timedelta

    events = []
    for i in range(5):
        events.append({
            "id": uuid4().bytes,
            "tenant_id": tenant_id.bytes,
            "monitored_file_id": uuid4().bytes,
            "file_path": f"/data/file_{i}.txt",
            "action": "read",
            "success": True,
            "user_name": "alice",
            "user_domain": "CORP",
            "process_name": "excel.exe",
            "event_time": base + timedelta(hours=i * 3),
            "collected_at": base + timedelta(hours=i * 3, minutes=1),
        })
    return events


def write_remediation_actions(
    storage: LocalStorage,
    *,
    tenant_id: UUID = TENANT_A,
    rows: list[dict] | None = None,
    action_date: str = "2026-02-01",
):
    """Write synthetic remediation actions."""
    if rows is None:
        rows = _default_remediation_action_rows(tenant_id)

    cols: dict[str, list] = {f.name: [] for f in REMEDIATION_ACTIONS_SCHEMA}
    for r in rows:
        for k in cols:
            cols[k].append(r.get(k))

    table = pa.table(cols, schema=REMEDIATION_ACTIONS_SCHEMA)
    path = (
        f"remediation_actions/tenant={tenant_id}"
        f"/action_date={action_date}/part-00000.parquet"
    )
    storage.write_parquet(path, table)


def _default_remediation_action_rows(tenant_id: UUID) -> list[dict]:
    now = datetime(2026, 2, 1, 14, 0, 0, tzinfo=timezone.utc)
    from datetime import timedelta

    return [
        {
            "id": uuid4().bytes,
            "tenant_id": tenant_id.bytes,
            "file_inventory_id": uuid4().bytes,
            "action_type": "quarantine",
            "status": "completed",
            "source_path": "/data/sensitive/file1.xlsx",
            "dest_path": "/quarantine/file1.xlsx",
            "performed_by": "admin@test.com",
            "dry_run": False,
            "error": None,
            "created_at": now,
            "completed_at": now + timedelta(seconds=5),
        },
        {
            "id": uuid4().bytes,
            "tenant_id": tenant_id.bytes,
            "file_inventory_id": uuid4().bytes,
            "action_type": "lockdown",
            "status": "completed",
            "source_path": "/data/sensitive/file2.docx",
            "dest_path": None,
            "performed_by": "admin@test.com",
            "dry_run": False,
            "error": None,
            "created_at": now + timedelta(minutes=5),
            "completed_at": now + timedelta(minutes=5, seconds=3),
        },
        {
            "id": uuid4().bytes,
            "tenant_id": tenant_id.bytes,
            "file_inventory_id": uuid4().bytes,
            "action_type": "quarantine",
            "status": "failed",
            "source_path": "/data/sensitive/file3.pdf",
            "dest_path": "/quarantine/file3.pdf",
            "performed_by": "admin@test.com",
            "dry_run": False,
            "error": "Permission denied",
            "created_at": now + timedelta(minutes=10),
            "completed_at": None,
        },
        {
            "id": uuid4().bytes,
            "tenant_id": tenant_id.bytes,
            "file_inventory_id": uuid4().bytes,
            "action_type": "rollback",
            "status": "pending",
            "source_path": "/quarantine/file1.xlsx",
            "dest_path": "/data/sensitive/file1.xlsx",
            "performed_by": "admin@test.com",
            "dry_run": False,
            "error": None,
            "created_at": now + timedelta(minutes=15),
            "completed_at": None,
        },
    ]

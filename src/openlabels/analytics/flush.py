"""
Delta flush logic — write changed data from PostgreSQL to the Parquet catalog.

Three flush operations:

1. **Scan completion flush** (event-driven): New ``ScanResult`` rows from a
   completed job + updated ``FileInventory`` snapshot for the target.
2. **Periodic event flush**: New ``FileAccessEvent`` and ``AuditLog`` rows
   since the last flush timestamp.
3. **Inventory snapshot refresh**: Full ``FileInventory`` / ``FolderInventory``
   export for a specific target (bundled with #1 or on-demand).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

import pyarrow as pa
from sqlalchemy import select

from openlabels.analytics.arrow_convert import (
    access_events_to_arrow,
    audit_log_to_arrow,
    file_inventory_to_arrow,
    remediation_actions_to_arrow,
    scan_results_to_arrow,
)
from openlabels.analytics.partition import (
    access_event_partition,
    audit_log_partition,
    file_inventory_path,
    remediation_action_partition,
    scan_result_partition,
    timestamped_part_filename,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from openlabels.analytics.storage import CatalogStorage
    from openlabels.server.models import ScanJob

logger = logging.getLogger(__name__)



_METADATA_DIR = "_metadata"
_FLUSH_STATE_FILE = "flush_state.json"


def _flush_state_path(storage: CatalogStorage) -> str:
    return f"{_METADATA_DIR}/{_FLUSH_STATE_FILE}"


def load_flush_state(storage: CatalogStorage) -> dict:
    """Load the last-flushed cursor state from ``_metadata/flush_state.json``."""
    path = _flush_state_path(storage)
    if not storage.exists(path):
        return {
            "last_access_event_flush": None,
            "last_audit_log_flush": None,
            "last_remediation_action_flush": None,
            "schema_version": 1,
        }
    data = storage.read_bytes(path)
    return json.loads(data)


def save_flush_state(storage: CatalogStorage, state: dict) -> None:
    """Persist flush cursor state."""
    path = _flush_state_path(storage)
    data = json.dumps(state, indent=2, default=str).encode()
    storage.write_bytes(path, data)



async def flush_scan_to_catalog(
    session: AsyncSession,
    job: ScanJob,
    storage: CatalogStorage,
) -> int:
    """
    Export new scan results and updated inventory for *job* to Parquet.

    Returns the number of result rows written.
    """
    from openlabels.server.models import FileInventory, ScanResult

    # 1. Query only results from THIS job (delta — uses ix_scan_results_job_time)
    result = await session.execute(
        select(ScanResult)
        .where(ScanResult.job_id == job.id)
        .order_by(ScanResult.scanned_at)
    )
    rows = list(result.scalars())

    if not rows:
        logger.debug("No scan results to flush for job %s", job.id)
        return 0

    # 2. Convert to Arrow table
    table = scan_results_to_arrow(rows)

    # 3. Write to partitioned path
    completed_at = job.completed_at or datetime.now(timezone.utc)
    partition = scan_result_partition(job.tenant_id, job.target_id, completed_at)
    dest = f"{partition}/{timestamped_part_filename()}"
    storage.write_parquet(dest, table)

    # 4. Overwrite file inventory snapshot for this target
    inv_result = await session.execute(
        select(FileInventory)
        .where(FileInventory.tenant_id == job.tenant_id)
        .where(FileInventory.target_id == job.target_id)
    )
    inv_rows = list(inv_result.scalars())
    if inv_rows:
        inv_table = file_inventory_to_arrow(inv_rows)
        inv_path = file_inventory_path(job.tenant_id, job.target_id)
        storage.write_parquet(inv_path, inv_table)

    logger.info(
        "Flushed %d scan results + %d inventory rows for job %s",
        len(rows),
        len(inv_rows),
        job.id,
    )
    return len(rows)



async def flush_events_to_catalog(
    session: AsyncSession,
    storage: CatalogStorage,
) -> dict[str, int]:
    """
    Export new access events, audit logs, and remediation actions
    since the last flush.

    Returns ``{"access_events": N, "audit_logs": M, "remediation_actions": K}``.
    """
    from openlabels.server.models import AuditLog, FileAccessEvent, RemediationAction

    state = load_flush_state(storage)
    counts: dict[str, int] = {"access_events": 0, "audit_logs": 0, "remediation_actions": 0}

    last_ae = state.get("last_access_event_flush")
    ae_query = select(FileAccessEvent).order_by(FileAccessEvent.collected_at)
    if last_ae:
        cutoff = datetime.fromisoformat(last_ae)
        ae_query = ae_query.where(FileAccessEvent.collected_at > cutoff)

    ae_result = await session.execute(ae_query)
    ae_rows = list(ae_result.scalars())

    if ae_rows:
        table = access_events_to_arrow(ae_rows)

        # Group by tenant + event_date and write partitioned files
        _write_partitioned_access_events(storage, ae_rows, table)

        state["last_access_event_flush"] = ae_rows[-1].collected_at.isoformat()
        counts["access_events"] = len(ae_rows)

    last_al = state.get("last_audit_log_flush")
    al_query = select(AuditLog).order_by(AuditLog.created_at)
    if last_al:
        cutoff = datetime.fromisoformat(last_al)
        al_query = al_query.where(AuditLog.created_at > cutoff)

    al_result = await session.execute(al_query)
    al_rows = list(al_result.scalars())

    if al_rows:
        table = audit_log_to_arrow(al_rows)
        _write_partitioned_audit_logs(storage, al_rows, table)
        state["last_audit_log_flush"] = al_rows[-1].created_at.isoformat()
        counts["audit_logs"] = len(al_rows)

    last_ra = state.get("last_remediation_action_flush")
    ra_query = select(RemediationAction).order_by(RemediationAction.created_at)
    if last_ra:
        cutoff = datetime.fromisoformat(last_ra)
        ra_query = ra_query.where(RemediationAction.created_at > cutoff)

    ra_result = await session.execute(ra_query)
    ra_rows = list(ra_result.scalars())

    if ra_rows:
        table = remediation_actions_to_arrow(ra_rows)
        _write_partitioned_remediation_actions(storage, ra_rows, table)
        state["last_remediation_action_flush"] = ra_rows[-1].created_at.isoformat()
        counts["remediation_actions"] = len(ra_rows)

    save_flush_state(storage, state)
    return counts



def _write_partitioned_access_events(
    storage: CatalogStorage,
    rows,
    table: pa.Table,
) -> None:
    """Group access events by (tenant_id, event_date) and write partitioned Parquet."""
    groups: dict[tuple, list[int]] = {}
    for idx, r in enumerate(rows):
        key = (str(r.tenant_id), r.event_time.date())
        groups.setdefault(key, []).append(idx)

    for (tenant_str, event_date), indices in groups.items():
        partition = access_event_partition(UUID(tenant_str), event_date)
        subset = table.take(indices)
        dest = f"{partition}/{timestamped_part_filename()}"
        storage.write_parquet(dest, subset)


def _write_partitioned_audit_logs(
    storage: CatalogStorage,
    rows,
    table: pa.Table,
) -> None:
    """Group audit logs by (tenant_id, log_date) and write partitioned Parquet."""
    groups: dict[tuple, list[int]] = {}
    for idx, r in enumerate(rows):
        key = (str(r.tenant_id), r.created_at.date())
        groups.setdefault(key, []).append(idx)

    for (tenant_str, log_date), indices in groups.items():
        partition = audit_log_partition(UUID(tenant_str), log_date)
        subset = table.take(indices)
        dest = f"{partition}/{timestamped_part_filename()}"
        storage.write_parquet(dest, subset)


def _write_partitioned_remediation_actions(
    storage: CatalogStorage,
    rows,
    table: pa.Table,
) -> None:
    """Group remediation actions by (tenant_id, action_date) and write partitioned Parquet."""
    groups: dict[tuple, list[int]] = {}
    for idx, r in enumerate(rows):
        key = (str(r.tenant_id), r.created_at.date())
        groups.setdefault(key, []).append(idx)

    for (tenant_str, action_date), indices in groups.items():
        partition = remediation_action_partition(UUID(tenant_str), action_date)
        subset = table.take(indices)
        dest = f"{partition}/{timestamped_part_filename()}"
        storage.write_parquet(dest, subset)

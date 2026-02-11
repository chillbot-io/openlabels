"""Tests for SQLAlchemy model → Arrow converters."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

import pyarrow as pa
import pytest

from openlabels.analytics.arrow_convert import (
    _entity_counts_to_map,
    _ts,
    _uuid_bytes,
    scan_results_to_arrow,
)
from openlabels.analytics.schemas import SCAN_RESULTS_SCHEMA


# ── Unit tests for helpers ────────────────────────────────────────────

def test_uuid_bytes_converts():
    u = UUID("12345678-1234-5678-1234-567812345678")
    b = _uuid_bytes(u)
    assert isinstance(b, bytes)
    assert len(b) == 16
    assert UUID(bytes=b) == u


def test_uuid_bytes_none():
    assert _uuid_bytes(None) is None


def test_ts_adds_utc_to_naive():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    result = _ts(naive)
    assert result.tzinfo == timezone.utc


def test_ts_preserves_aware():
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert _ts(aware) is aware


def test_ts_none():
    assert _ts(None) is None


def test_entity_counts_to_map_dict():
    result = _entity_counts_to_map({"SSN": 3, "EMAIL": 1})
    assert set(result) == {("SSN", 3), ("EMAIL", 1)}


def test_entity_counts_to_map_empty():
    assert _entity_counts_to_map({}) == []


def test_entity_counts_to_map_none_returns_none():
    """None input must produce None (null in Parquet), not []."""
    assert _entity_counts_to_map(None) is None


# ── Integration: scan_results_to_arrow ────────────────────────────────

@dataclass
class FakeScanResult:
    """Minimal mock that quacks like an ORM ScanResult."""
    id: UUID
    job_id: UUID
    tenant_id: UUID
    file_path: str
    file_name: str
    file_size: Optional[int]
    file_modified: Optional[datetime]
    content_hash: Optional[str]
    risk_score: int
    risk_tier: str
    content_score: Optional[float]
    exposure_multiplier: Optional[float]
    exposure_level: Optional[str]
    owner: Optional[str]
    entity_counts: Optional[dict]
    total_entities: int
    label_applied: bool
    current_label_name: Optional[str]
    policy_violations: Optional[dict]
    scanned_at: datetime


def _make_fake(**overrides) -> FakeScanResult:
    defaults = dict(
        id=uuid4(),
        job_id=uuid4(),
        tenant_id=uuid4(),
        file_path="/test/file.txt",
        file_name="file.txt",
        file_size=1024,
        file_modified=datetime(2026, 2, 1, tzinfo=timezone.utc),
        content_hash="abc",
        risk_score=50,
        risk_tier="MEDIUM",
        content_score=40.0,
        exposure_multiplier=1.2,
        exposure_level="INTERNAL",
        owner="user@test.com",
        entity_counts={"SSN": 2, "EMAIL": 1},
        total_entities=3,
        label_applied=False,
        current_label_name=None,
        policy_violations=None,
        scanned_at=datetime(2026, 2, 1, 12, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return FakeScanResult(**defaults)


def test_scan_results_to_arrow_basic():
    rows = [_make_fake(), _make_fake(risk_score=90, risk_tier="CRITICAL")]
    table = scan_results_to_arrow(rows)

    assert isinstance(table, pa.Table)
    assert table.num_rows == 2
    assert table.schema.equals(SCAN_RESULTS_SCHEMA)


def test_scan_results_to_arrow_empty():
    table = scan_results_to_arrow([])
    assert table.num_rows == 0
    assert table.schema.equals(SCAN_RESULTS_SCHEMA)


def test_scan_results_to_arrow_nulls():
    """All nullable fields can be None without error."""
    row = _make_fake(
        file_size=None,
        file_modified=None,
        content_hash=None,
        content_score=None,
        exposure_multiplier=None,
        exposure_level=None,
        owner=None,
        entity_counts=None,
        current_label_name=None,
    )
    table = scan_results_to_arrow([row])
    assert table.num_rows == 1


def test_scan_results_parquet_roundtrip(tmp_path):
    """Write → read roundtrip through Parquet preserves data."""
    import pyarrow.parquet as pq

    rows = [_make_fake(risk_score=75, risk_tier="HIGH")]
    table = scan_results_to_arrow(rows)

    path = tmp_path / "test.parquet"
    pq.write_table(table, path)
    loaded = pq.read_table(path)

    assert loaded.num_rows == 1
    assert loaded.column("risk_score")[0].as_py() == 75

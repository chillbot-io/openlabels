"""Tests for PyArrow schema definitions."""

import pyarrow as pa
import pytest

from openlabels.analytics.schemas import (
    ACCESS_EVENTS_SCHEMA,
    AUDIT_LOG_SCHEMA,
    FILE_INVENTORY_SCHEMA,
    FOLDER_INVENTORY_SCHEMA,
    REMEDIATION_ACTIONS_SCHEMA,
    SCAN_RESULTS_SCHEMA,
)


@pytest.mark.parametrize("schema,name,expected_fields", [
    (SCAN_RESULTS_SCHEMA, "scan_results", [
        "id", "job_id", "tenant_id", "file_path", "file_name",
        "risk_score", "risk_tier", "entity_counts", "total_entities",
        "label_applied", "scanned_at",
    ]),
    (FILE_INVENTORY_SCHEMA, "file_inventory", [
        "id", "tenant_id", "target_id", "file_path", "file_name",
        "risk_score", "risk_tier", "entity_counts", "total_entities",
        "last_scanned_at",
    ]),
    (ACCESS_EVENTS_SCHEMA, "access_events", [
        "id", "tenant_id", "file_path", "action", "event_time",
    ]),
    (AUDIT_LOG_SCHEMA, "audit_log", [
        "id", "tenant_id", "action", "created_at",
    ]),
    (FOLDER_INVENTORY_SCHEMA, "folder_inventory", [
        "id", "tenant_id", "target_id", "folder_path", "adapter",
        "file_count", "has_sensitive_files", "discovered_at",
    ]),
    (REMEDIATION_ACTIONS_SCHEMA, "remediation_actions", [
        "id", "tenant_id", "action_type", "status", "created_at",
    ]),
])
def test_schema_has_expected_fields(schema, name, expected_fields):
    """Each schema must contain at minimum the listed fields."""
    field_names = schema.names
    for f in expected_fields:
        assert f in field_names, f"{name} schema missing field {f!r}"


def test_scan_results_entity_counts_is_map():
    """entity_counts must be a MAP<string, int32> for DuckDB unnest support."""
    field = SCAN_RESULTS_SCHEMA.field("entity_counts")
    assert pa.types.is_map(field.type)
    assert field.type.key_type == pa.utf8()
    assert field.type.item_type == pa.int32()


def test_risk_tier_is_dictionary_encoded():
    """Low-cardinality columns should use dictionary encoding for compression."""
    field = SCAN_RESULTS_SCHEMA.field("risk_tier")
    assert pa.types.is_dictionary(field.type)


def test_timestamps_have_tz():
    """All timestamp columns should be UTC-aware to avoid timezone bugs."""
    for schema in [SCAN_RESULTS_SCHEMA, FILE_INVENTORY_SCHEMA, FOLDER_INVENTORY_SCHEMA,
                    ACCESS_EVENTS_SCHEMA, AUDIT_LOG_SCHEMA, REMEDIATION_ACTIONS_SCHEMA]:
        for i in range(len(schema)):
            f = schema.field(i)
            if pa.types.is_timestamp(f.type):
                assert f.type.tz == "UTC", f"Timestamp field {f.name!r} missing tz=UTC"

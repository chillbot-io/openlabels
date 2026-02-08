"""
PyArrow schema definitions for the Parquet catalog.

Each schema maps directly from the corresponding SQLAlchemy model,
excluding large JSONB blobs (``findings``, ``raw_event``) that are
only needed for single-row OLTP lookups.
"""

import pyarrow as pa

# Dictionary-encoded string type for low-cardinality columns.
_dict_str = pa.dictionary(pa.int8(), pa.utf8())

SCAN_RESULTS_SCHEMA = pa.schema([
    pa.field("id", pa.binary(16)),
    pa.field("job_id", pa.binary(16)),
    pa.field("tenant_id", pa.binary(16)),
    pa.field("file_path", pa.utf8()),
    pa.field("file_name", pa.utf8()),
    pa.field("file_size", pa.int64()),
    pa.field("file_modified", pa.timestamp("ms", tz="UTC")),
    pa.field("content_hash", pa.utf8()),
    pa.field("risk_score", pa.int32()),
    pa.field("risk_tier", _dict_str),
    pa.field("content_score", pa.float64()),
    pa.field("exposure_multiplier", pa.float64()),
    pa.field("exposure_level", _dict_str),
    pa.field("owner", pa.utf8()),
    pa.field("entity_counts", pa.map_(pa.utf8(), pa.int32())),
    pa.field("total_entities", pa.int32()),
    pa.field("label_applied", pa.bool_()),
    pa.field("current_label_name", pa.utf8()),
    pa.field("current_label_id", pa.utf8()),
    pa.field("recommended_label_name", pa.utf8()),
    pa.field("label_applied_at", pa.timestamp("ms", tz="UTC")),
    pa.field("label_error", pa.utf8()),
    pa.field("scanned_at", pa.timestamp("ms", tz="UTC")),
])

FILE_INVENTORY_SCHEMA = pa.schema([
    pa.field("id", pa.binary(16)),
    pa.field("tenant_id", pa.binary(16)),
    pa.field("target_id", pa.binary(16)),
    pa.field("folder_id", pa.binary(16)),
    pa.field("file_path", pa.utf8()),
    pa.field("file_name", pa.utf8()),
    pa.field("adapter", _dict_str),
    pa.field("content_hash", pa.utf8()),
    pa.field("file_size", pa.int64()),
    pa.field("file_modified", pa.timestamp("ms", tz="UTC")),
    pa.field("risk_score", pa.int32()),
    pa.field("risk_tier", _dict_str),
    pa.field("entity_counts", pa.map_(pa.utf8(), pa.int32())),
    pa.field("total_entities", pa.int32()),
    pa.field("exposure_level", _dict_str),
    pa.field("owner", pa.utf8()),
    pa.field("current_label_name", pa.utf8()),
    pa.field("current_label_id", pa.utf8()),
    pa.field("label_applied_at", pa.timestamp("ms", tz="UTC")),
    pa.field("is_monitored", pa.bool_()),
    pa.field("needs_rescan", pa.bool_()),
    pa.field("last_scanned_at", pa.timestamp("ms", tz="UTC")),
    pa.field("discovered_at", pa.timestamp("ms", tz="UTC")),
    pa.field("updated_at", pa.timestamp("ms", tz="UTC")),
    pa.field("scan_count", pa.int32()),
    pa.field("content_changed_count", pa.int32()),
])

ACCESS_EVENTS_SCHEMA = pa.schema([
    pa.field("id", pa.binary(16)),
    pa.field("tenant_id", pa.binary(16)),
    pa.field("monitored_file_id", pa.binary(16)),
    pa.field("file_path", pa.utf8()),
    pa.field("action", _dict_str),
    pa.field("success", pa.bool_()),
    pa.field("user_name", pa.utf8()),
    pa.field("user_domain", pa.utf8()),
    pa.field("user_sid", pa.utf8()),
    pa.field("process_name", pa.utf8()),
    pa.field("process_id", pa.int32()),
    pa.field("event_source", _dict_str),
    pa.field("event_time", pa.timestamp("ms", tz="UTC")),
    pa.field("collected_at", pa.timestamp("ms", tz="UTC")),
])

AUDIT_LOG_SCHEMA = pa.schema([
    pa.field("id", pa.binary(16)),
    pa.field("tenant_id", pa.binary(16)),
    pa.field("user_id", pa.binary(16)),
    pa.field("action", _dict_str),
    pa.field("resource_type", pa.utf8()),
    pa.field("resource_id", pa.binary(16)),
    pa.field("details", pa.utf8()),  # JSON string
    pa.field("created_at", pa.timestamp("ms", tz="UTC")),
])

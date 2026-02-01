"""Comprehensive tests for output/index.py.

Tests the SQLite-based label index including:
- LabelIndex CRUD operations
- Thread-local connection pooling
- Transaction handling
- Query filtering
- Export functionality
- Full store/get cycle with compact schema validation
"""

import pytest
import sqlite3
import threading
import tempfile
import time
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.output.index import (
    LabelIndex,
    _build_filter_clause,
    _validate_label_json,
    get_default_index,
    reset_default_index,
    DEFAULT_VERSION_LIMIT,
)
from openlabels.core.labels import Label, LabelSet, VirtualLabelPointer
from openlabels.core.exceptions import DatabaseError, CorruptedDataError, NotFoundError


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database path."""
    return tmp_path / "test_index.db"


@pytest.fixture
def index(temp_db):
    """Create a LabelIndex for testing."""
    idx = LabelIndex(db_path=str(temp_db), tenant_id="test_tenant")
    yield idx
    idx.close()


@pytest.fixture
def sample_labelset():
    """Create a sample LabelSet."""
    labels = [Label("SSN", 0.95, "checksum", "abc123", count=2)]
    return LabelSet.create(labels, b"test content", source="test:1.0")


class TestBuildFilterClause:
    """Tests for filter clause building."""

    def test_empty_filters(self):
        """No filters should return 1=1."""
        clause, params = _build_filter_clause()
        assert clause == "1=1"
        assert params == []

    def test_min_score_filter(self):
        """min_score should generate >= condition."""
        clause, params = _build_filter_clause(min_score=50)
        assert "v.risk_score >= ?" in clause
        assert 50 in params

    def test_max_score_filter(self):
        """max_score should generate <= condition."""
        clause, params = _build_filter_clause(max_score=80)
        assert "v.risk_score <= ?" in clause
        assert 80 in params

    def test_risk_tier_filter(self):
        """risk_tier should generate = condition."""
        clause, params = _build_filter_clause(risk_tier="HIGH")
        assert "v.risk_tier = ?" in clause
        assert "HIGH" in params

    def test_entity_type_filter(self):
        """entity_type should generate LIKE condition."""
        clause, params = _build_filter_clause(entity_type="SSN")
        assert "v.entity_types LIKE ?" in clause
        assert "%SSN%" in params

    def test_since_filter(self):
        """since should generate >= condition."""
        clause, params = _build_filter_clause(since="2024-01-01")
        assert "v.scanned_at >= ?" in clause
        assert "2024-01-01" in params

    def test_tenant_filter(self):
        """tenant_id should generate = condition."""
        clause, params = _build_filter_clause(tenant_id="tenant1")
        assert "o.tenant_id = ?" in clause
        assert "tenant1" in params

    def test_multiple_filters(self):
        """Multiple filters should be ANDed."""
        clause, params = _build_filter_clause(
            min_score=50,
            max_score=80,
            risk_tier="HIGH",
        )
        assert "AND" in clause
        assert len(params) == 3


class TestValidateLabelJson:
    """Tests for label JSON validation using compact schema."""

    def test_valid_json(self):
        """Valid JSON (compact format) should pass."""
        json_str = json.dumps({
            "v": 1,
            "id": "ol_123456789012",
            "hash": "abc123def456",
            "labels": [],
            "src": "test",
            "ts": 1234567890
        })
        result = _validate_label_json(json_str)
        assert result["id"] == "ol_123456789012"

    def test_invalid_json_syntax(self):
        """Malformed JSON should raise CorruptedDataError."""
        with pytest.raises(CorruptedDataError, match="Malformed JSON"):
            _validate_label_json("not valid json{")

    def test_missing_required_field(self):
        """Missing required field should raise CorruptedDataError."""
        with pytest.raises(CorruptedDataError, match="Missing required field"):
            _validate_label_json('{"v":1,"id":"x"}')

    def test_invalid_label_id_type(self):
        """Non-string id should raise CorruptedDataError."""
        json_str = json.dumps({
            "v": 1, "id": 123, "hash": "x", "labels": [], "src": "x", "ts": 123
        })
        with pytest.raises(CorruptedDataError, match="id.*must be"):
            _validate_label_json(json_str)

    def test_invalid_labels_type(self):
        """Non-array labels should raise CorruptedDataError."""
        json_str = json.dumps({
            "v": 1, "id": "x", "hash": "x", "labels": "not array", "src": "x", "ts": 123
        })
        with pytest.raises(CorruptedDataError, match="labels must be an array"):
            _validate_label_json(json_str)

    def test_invalid_label_entry(self):
        """Invalid label entry should raise CorruptedDataError."""
        json_str = json.dumps({
            "v": 1, "id": "x", "hash": "x", "labels": ["not object"], "src": "x", "ts": 123
        })
        with pytest.raises(CorruptedDataError, match="must be an object"):
            _validate_label_json(json_str)

    def test_invalid_confidence_range(self):
        """Confidence outside 0-1 should raise CorruptedDataError."""
        json_str = json.dumps({
            "v": 1, "id": "x", "hash": "x",
            "labels": [{"t": "SSN", "c": 1.5, "d": "test", "h": "abc123"}],
            "src": "x", "ts": 123
        })
        with pytest.raises(CorruptedDataError, match="confidence.*must be"):
            _validate_label_json(json_str)

    def test_valid_with_labels(self):
        """Valid JSON with labels should pass."""
        json_str = json.dumps({
            "v": 1,
            "id": "ol_123456789012",
            "hash": "abc123def456",
            "labels": [{"t": "SSN", "c": 0.95, "d": "checksum", "h": "abc123"}],
            "src": "test",
            "ts": 1234567890
        })
        result = _validate_label_json(json_str)
        assert len(result["labels"]) == 1

    def test_missing_label_type(self):
        """Missing label type should raise CorruptedDataError."""
        json_str = json.dumps({
            "v": 1, "id": "x", "hash": "x",
            "labels": [{"c": 0.9, "d": "test", "h": "abc123"}],
            "src": "x", "ts": 123
        })
        with pytest.raises(CorruptedDataError, match="t.*type.*must be"):
            _validate_label_json(json_str)

    def test_missing_label_detector(self):
        """Missing label detector should raise CorruptedDataError."""
        json_str = json.dumps({
            "v": 1, "id": "x", "hash": "x",
            "labels": [{"t": "SSN", "c": 0.9, "h": "abc123"}],
            "src": "x", "ts": 123
        })
        with pytest.raises(CorruptedDataError, match="d.*detector.*must be"):
            _validate_label_json(json_str)


class TestLabelIndexInit:
    """Tests for LabelIndex initialization."""

    def test_creates_database(self, temp_db):
        """Should create database file."""
        index = LabelIndex(db_path=str(temp_db))
        index.close()
        assert temp_db.exists()

    def test_creates_parent_directory(self, tmp_path):
        """Should create parent directories."""
        nested_path = tmp_path / "nested" / "path" / "index.db"
        index = LabelIndex(db_path=str(nested_path))
        index.close()
        assert nested_path.exists()

    def test_default_tenant_id(self, temp_db):
        """Default tenant should be 'default'."""
        index = LabelIndex(db_path=str(temp_db))
        assert index.tenant_id == "default"
        index.close()

    def test_custom_tenant_id(self, temp_db):
        """Custom tenant should be preserved."""
        index = LabelIndex(db_path=str(temp_db), tenant_id="custom")
        assert index.tenant_id == "custom"
        index.close()

    def test_schema_created(self, index, temp_db):
        """Schema tables should be created."""
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor}
        conn.close()

        assert "label_objects" in tables
        assert "label_versions" in tables
        assert "file_mappings" in tables
        assert "schema_info" in tables


class TestLabelIndexStore:
    """Tests for storing labels."""

    def test_store_basic(self, index, sample_labelset):
        """Should store a LabelSet successfully."""
        result = index.store(sample_labelset)
        assert result is True

    def test_store_with_file_path(self, index, sample_labelset):
        """Should store with file path."""
        result = index.store(sample_labelset, file_path="/path/to/file.txt")
        assert result is True

    def test_store_with_risk_score(self, index, sample_labelset):
        """Should store with risk score."""
        result = index.store(sample_labelset, risk_score=75, risk_tier="HIGH")
        assert result is True

    def test_store_updates_existing(self, index, sample_labelset):
        """Should update existing label without error."""
        result1 = index.store(sample_labelset, risk_score=50)
        result2 = index.store(sample_labelset, risk_score=75)  # Update

        assert result1 is True
        assert result2 is True


class TestLabelIndexGet:
    """Tests for retrieving labels."""

    def test_get_existing(self, index, sample_labelset):
        """Should retrieve existing label after store."""
        index.store(sample_labelset)

        retrieved = index.get(sample_labelset.label_id)
        assert retrieved is not None
        assert retrieved.label_id == sample_labelset.label_id
        assert retrieved.content_hash == sample_labelset.content_hash

    def test_get_nonexistent(self, index):
        """Should return None for nonexistent label."""
        result = index.get("ol_nonexistent1")
        assert result is None

    def test_get_with_content_hash(self, index, sample_labelset):
        """Should retrieve specific version by content hash."""
        index.store(sample_labelset)

        retrieved = index.get(
            sample_labelset.label_id,
            content_hash=sample_labelset.content_hash
        )
        assert retrieved is not None
        assert retrieved.content_hash == sample_labelset.content_hash

    def test_get_raise_on_error(self, index):
        """Should raise NotFoundError with raise_on_error=True."""
        with pytest.raises(NotFoundError):
            index.get("ol_nonexistent1", raise_on_error=True)

    def test_get_by_path_existing(self, index, sample_labelset):
        """Should retrieve by file path after store."""
        index.store(sample_labelset, file_path="/test/file.txt")

        retrieved = index.get_by_path("/test/file.txt")
        assert retrieved is not None
        assert retrieved.label_id == sample_labelset.label_id

    def test_get_by_path_nonexistent(self, index):
        """Should return None for nonexistent path."""
        result = index.get_by_path("/nonexistent/path")
        assert result is None

    def test_get_by_path_raise_on_error(self, index):
        """Should raise NotFoundError with raise_on_error=True."""
        with pytest.raises(NotFoundError):
            index.get_by_path("/nonexistent", raise_on_error=True)


class TestLabelIndexResolve:
    """Tests for resolving virtual label pointers."""

    def test_resolve_pointer(self, index, sample_labelset):
        """Should resolve valid pointer after store."""
        index.store(sample_labelset)

        pointer = VirtualLabelPointer(
            sample_labelset.label_id,
            sample_labelset.content_hash
        )
        resolved = index.resolve(pointer)

        assert resolved is not None
        assert resolved.label_id == sample_labelset.label_id


class TestLabelIndexVersions:
    """Tests for version history."""

    def test_get_versions_stored(self, index, sample_labelset):
        """Should return version metadata after store."""
        index.store(sample_labelset)

        versions = index.get_versions(sample_labelset.label_id)
        assert len(versions) == 1
        assert versions[0]["content_hash"] == sample_labelset.content_hash

    def test_get_versions_with_limit(self, index, sample_labelset):
        """Should respect limit parameter."""
        index.store(sample_labelset)

        versions = index.get_versions(sample_labelset.label_id, limit=1)
        assert len(versions) <= 1

    def test_get_versions_nonexistent(self, index):
        """Should return empty list for nonexistent label."""
        versions = index.get_versions("ol_nonexistent1")
        assert versions == []


class TestLabelIndexQuery:
    """Tests for querying labels."""

    def test_query_all(self, index, sample_labelset):
        """Should return labels matching query."""
        index.store(sample_labelset)

        results = index.query()
        assert len(results) >= 1

    def test_query_with_filters(self, index, sample_labelset):
        """Should filter by criteria."""
        index.store(sample_labelset, risk_score=75, risk_tier="HIGH")

        results = index.query(min_score=50, risk_tier="HIGH")
        assert len(results) >= 1

    def test_query_pagination(self, index, sample_labelset):
        """Should support pagination."""
        index.store(sample_labelset)

        results = index.query(limit=10, offset=0)
        assert len(results) <= 10

    def test_query_count(self, index, sample_labelset):
        """Should count matching labels."""
        index.store(sample_labelset, risk_score=75)

        count = index.query_count(min_score=50)
        assert count >= 1

    def test_query_with_entity_type(self, index, sample_labelset):
        """Should filter by entity type."""
        index.store(sample_labelset)

        results = index.query(entity_type="SSN")
        assert len(results) >= 1


class TestLabelIndexDelete:
    """Tests for deleting labels."""

    def test_delete_existing(self, index, sample_labelset):
        """Should delete existing label."""
        index.store(sample_labelset)

        result = index.delete(sample_labelset.label_id)
        assert result is True

        # Verify deletion via query
        versions = index.get_versions(sample_labelset.label_id)
        assert versions == []

    def test_delete_nonexistent(self, index):
        """Should return True for nonexistent (no-op)."""
        result = index.delete("ol_nonexistent1")
        assert result is True


class TestLabelIndexCount:
    """Tests for counting labels."""

    def test_count_empty(self, index):
        """Empty index should have zero counts."""
        counts = index.count()
        assert counts["labels"] == 0
        assert counts["versions"] == 0

    def test_count_after_store(self, index, sample_labelset):
        """Should count stored labels."""
        index.store(sample_labelset)

        counts = index.count()
        assert counts["labels"] == 1
        assert counts["versions"] == 1


class TestLabelIndexExport:
    """Tests for exporting labels."""

    def test_export_to_file(self, index, sample_labelset, tmp_path):
        """Should export to JSONL file."""
        index.store(sample_labelset, risk_score=75)

        output_path = tmp_path / "export.jsonl"
        result = index.export(str(output_path))

        assert result["success"] is True
        assert result["count"] >= 1
        assert output_path.exists()

    def test_export_with_filters(self, index, sample_labelset, tmp_path):
        """Should respect export filters."""
        index.store(sample_labelset, risk_score=75, risk_tier="HIGH")

        output_path = tmp_path / "export.jsonl"
        result = index.export(str(output_path), min_score=50, risk_tier="HIGH")

        assert result["success"] is True

    def test_export_iter(self, index, sample_labelset):
        """Should iterate over exported labels."""
        index.store(sample_labelset, risk_score=75)

        records = list(index.export_iter())
        assert len(records) >= 1
        assert "_risk_score" in records[0]


class TestLabelIndexThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_stores(self, temp_db):
        """Concurrent stores should not corrupt database."""
        index = LabelIndex(db_path=str(temp_db))
        errors = []

        def store_labels(thread_id):
            try:
                for i in range(10):
                    labels = [Label("SSN", 0.95, "test", f"hash{thread_id}{i}")]
                    label_set = LabelSet.create(
                        labels,
                        f"content{thread_id}{i}".encode(),
                    )
                    index.store(label_set)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=store_labels, args=(i,))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        index.close()
        assert errors == [], f"Errors during concurrent stores: {errors}"

    def test_concurrent_queries(self, temp_db, sample_labelset):
        """Concurrent queries should work."""
        index = LabelIndex(db_path=str(temp_db))
        index.store(sample_labelset)
        errors = []

        def query_labels():
            try:
                for _ in range(10):
                    index.query()
                    index.count()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=query_labels) for _ in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        index.close()
        assert errors == []


class TestLabelIndexContextManager:
    """Tests for context manager usage."""

    def test_context_manager(self, temp_db, sample_labelset):
        """Should work as context manager."""
        with LabelIndex(db_path=str(temp_db)) as index:
            result = index.store(sample_labelset)
            assert result is True

    def test_close_idempotent(self, index):
        """close() should be safe to call multiple times."""
        index.close()
        index.close()  # Should not raise


class TestGlobalIndex:
    """Tests for global index functions."""

    def test_get_default_index(self):
        """Should return singleton index."""
        reset_default_index()
        with pytest.warns(UserWarning):
            idx1 = get_default_index()
        idx2 = get_default_index(warn=False)
        assert idx1 is idx2

    def test_reset_default_index(self):
        """Should reset the singleton."""
        reset_default_index()
        with pytest.warns(UserWarning):
            get_default_index()
        reset_default_index()
        # After reset, warning flag should be reset too


class TestLabelIndexErrorHandling:
    """Tests for error handling."""

    def test_closed_index_store_returns_false(self, index, sample_labelset):
        """Store on closed index should return False."""
        index.close()

        # Store returns False when index is closed
        result = index.store(sample_labelset)
        assert result is False

    def test_closed_index_get_raises(self, index):
        """Get on closed index should raise DatabaseError."""
        index.close()

        # Get raises DatabaseError when index is closed
        with pytest.raises(DatabaseError, match="closed"):
            index.get("ol_123456789012")

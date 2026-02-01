"""Tests for audit log module.

Tests AuditLog hash chain, integrity verification, and event logging.
"""

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database
from scrubiq.storage.audit import AuditLog
from scrubiq.types import AuditEventType, Span, Tier


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def db_and_audit():
    """Create a database and audit log."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.connect()

        audit = AuditLog(db, "test_session_123")

        yield db, audit

        db.close()


# =============================================================================
# BASIC LOGGING TESTS
# =============================================================================

class TestBasicLogging:
    """Basic tests for audit logging."""

    def test_log_returns_entry(self, db_and_audit):
        """log() returns AuditEntry."""
        db, audit = db_and_audit

        entry = audit.log(AuditEventType.SESSION_START, {"user": "test"})

        assert entry is not None
        assert entry.event_type == AuditEventType.SESSION_START
        assert entry.data == {"user": "test"}

    def test_log_assigns_sequence(self, db_and_audit):
        """log() assigns sequential numbers."""
        db, audit = db_and_audit

        entry1 = audit.log(AuditEventType.SESSION_START, {})
        entry2 = audit.log(AuditEventType.PHI_DETECTED, {})

        assert entry1.sequence == 1
        assert entry2.sequence == 2

    def test_log_sets_timestamp(self, db_and_audit):
        """log() sets timestamp."""
        db, audit = db_and_audit

        before = datetime.now(timezone.utc)
        entry = audit.log(AuditEventType.SESSION_START, {})
        after = datetime.now(timezone.utc)

        assert before <= entry.timestamp <= after

    def test_log_hashes_session_id(self, db_and_audit):
        """log() stores hashed session_id."""
        db, audit = db_and_audit

        entry = audit.log(AuditEventType.SESSION_START, {})

        # Session ID should be hashed
        expected_hash = hashlib.sha256(b"test_session_123").hexdigest()[:32]
        assert entry.session_id == expected_hash

    def test_first_entry_has_genesis_prev_hash(self, db_and_audit):
        """First entry has 'GENESIS' as prev_hash."""
        db, audit = db_and_audit

        entry = audit.log(AuditEventType.SESSION_START, {})

        assert entry.prev_hash == "GENESIS"

    def test_subsequent_entries_chain(self, db_and_audit):
        """Subsequent entries chain to previous hash."""
        db, audit = db_and_audit

        entry1 = audit.log(AuditEventType.SESSION_START, {})
        entry2 = audit.log(AuditEventType.PHI_DETECTED, {})

        assert entry2.prev_hash == entry1.entry_hash


# =============================================================================
# SPECIALIZED LOGGING TESTS
# =============================================================================

class TestSpecializedLogging:
    """Tests for specialized logging methods."""

    def test_log_detection(self, db_and_audit):
        """log_detection() logs PHI detection event."""
        db, audit = db_and_audit

        # Create mock spans
        span1 = MagicMock()
        span1.entity_type = "NAME"
        span1.detector = "patterns"

        span2 = MagicMock()
        span2.entity_type = "SSN"
        span2.detector = "checksum"

        entry = audit.log_detection(
            input_text="John has SSN 123-45-6789",
            spans=[span1, span2],
            processing_time_ms=15.5
        )

        assert entry.event_type == AuditEventType.PHI_DETECTED
        assert entry.data["detection_count"] == 2
        assert "NAME" in entry.data["entity_types"]
        assert "SSN" in entry.data["entity_types"]
        assert entry.data["processing_time_ms"] == 15.5
        # Input hash is 32 chars (128-bit)
        assert len(entry.data["input_hash"]) == 32

    def test_log_redaction(self, db_and_audit):
        """log_redaction() logs PHI redaction event."""
        db, audit = db_and_audit

        entry = audit.log_redaction(
            input_text="John has SSN 123-45-6789",
            output_text="[NAME_1] has SSN [SSN_1]",
            tokens=["[NAME_1]", "[SSN_1]"]
        )

        assert entry.event_type == AuditEventType.PHI_REDACTED
        assert entry.data["tokens_assigned"] == ["[NAME_1]", "[SSN_1]"]
        assert entry.data["token_count"] == 2

    def test_log_restoration(self, db_and_audit):
        """log_restoration() logs PHI restoration event."""
        db, audit = db_and_audit

        entry = audit.log_restoration(
            tokens_restored=["[NAME_1]", "[SSN_1]"],
            unknown_tokens=["[PHONE_1]"]
        )

        assert entry.event_type == AuditEventType.PHI_RESTORED
        assert entry.data["tokens_restored"] == ["[NAME_1]", "[SSN_1]"]
        assert entry.data["unknown_tokens"] == ["[PHONE_1]"]
        assert entry.data["restoration_count"] == 2

    def test_log_error(self, db_and_audit):
        """log_error() logs error event."""
        db, audit = db_and_audit

        entry = audit.log_error(
            error_type="CryptoError",
            component="TokenStore",
            message="Decryption failed",
            phi_exposed=False
        )

        assert entry.event_type == AuditEventType.ERROR
        assert entry.data["error_type"] == "CryptoError"
        assert entry.data["component"] == "TokenStore"
        assert entry.data["phi_exposed"] is False


# =============================================================================
# HASH CHAIN VERIFICATION TESTS
# =============================================================================

class TestHashChainVerification:
    """Tests for hash chain verification."""

    def test_verify_empty_chain_valid(self, db_and_audit):
        """Empty chain is valid."""
        db, audit = db_and_audit

        is_valid, error = audit.verify_chain()

        assert is_valid is True
        assert error is None

    def test_verify_valid_chain(self, db_and_audit):
        """Valid chain passes verification."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {"n": 1})
        audit.log(AuditEventType.PHI_DETECTED, {"n": 2})
        audit.log(AuditEventType.PHI_REDACTED, {"n": 3})

        is_valid, error = audit.verify_chain()

        assert is_valid is True
        assert error is None

    def test_verify_detects_modified_entry(self, db_and_audit):
        """Verification detects modified entry."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {"n": 1})
        audit.log(AuditEventType.PHI_DETECTED, {"n": 2})

        # Tamper with entry data
        db.execute(
            "UPDATE audit_log SET data = ? WHERE sequence = 2",
            ('{"n": 999}',)
        )

        is_valid, error = audit.verify_chain()

        assert is_valid is False
        assert "modified" in error.lower() or "mismatch" in error.lower()

    def test_verify_chain_detailed(self, db_and_audit):
        """verify_chain_detailed() returns comprehensive results."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {"n": 1})
        audit.log(AuditEventType.PHI_DETECTED, {"n": 2})

        result = audit.verify_chain_detailed()

        assert result["valid"] is True
        assert result["total_entries"] == 2
        assert result["valid_entries"] == 2
        assert result["last_valid_sequence"] == 2
        assert result["errors"] == []


# =============================================================================
# CHAIN RECOVERY TESTS
# =============================================================================

class TestChainRecovery:
    """Tests for chain recovery operations."""

    def test_fork_chain_after_valid_chain_fails(self, db_and_audit):
        """fork_chain_after() fails on valid chain."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {})

        success, message = audit.fork_chain_after(0)

        assert success is False
        assert "valid" in message.lower()

    def test_fork_chain_recovers_from_corruption(self, db_and_audit):
        """fork_chain_after() recovers from corruption."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {"n": 1})
        audit.log(AuditEventType.PHI_DETECTED, {"n": 2})

        # Corrupt the second entry
        db.execute(
            "UPDATE audit_log SET entry_hash = 'BAD_HASH' WHERE sequence = 2"
        )

        # Verify corruption
        is_valid, _ = audit.verify_chain()
        assert is_valid is False

        # Fork after sequence 1
        success, message = audit.fork_chain_after(1)

        assert success is True

        # Chain should now be valid (with CHAIN_FORK entry)
        is_valid, _ = audit.verify_chain()
        assert is_valid is True


# =============================================================================
# GET ENTRIES TESTS
# =============================================================================

class TestGetEntries:
    """Tests for get_entries method."""

    def test_get_entries_empty(self, db_and_audit):
        """get_entries() returns empty list for empty log."""
        db, audit = db_and_audit

        entries = audit.get_entries()

        assert entries == []

    def test_get_entries_returns_all(self, db_and_audit):
        """get_entries() returns all entries."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {})
        audit.log(AuditEventType.PHI_DETECTED, {})
        audit.log(AuditEventType.PHI_REDACTED, {})

        entries = audit.get_entries()

        assert len(entries) == 3

    def test_get_entries_with_limit(self, db_and_audit):
        """get_entries() respects limit."""
        db, audit = db_and_audit

        for i in range(10):
            audit.log(AuditEventType.SESSION_START, {"i": i})

        entries = audit.get_entries(limit=5)

        assert len(entries) == 5

    def test_get_entries_with_offset(self, db_and_audit):
        """get_entries() respects offset."""
        db, audit = db_and_audit

        for i in range(10):
            audit.log(AuditEventType.SESSION_START, {"i": i})

        entries = audit.get_entries(limit=5, offset=5)

        assert len(entries) == 5

    def test_get_entries_filter_by_type(self, db_and_audit):
        """get_entries() filters by event type."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {})
        audit.log(AuditEventType.PHI_DETECTED, {})
        audit.log(AuditEventType.PHI_DETECTED, {})
        audit.log(AuditEventType.PHI_REDACTED, {})

        entries = audit.get_entries(event_type=AuditEventType.PHI_DETECTED)

        assert len(entries) == 2
        assert all(e.event_type == AuditEventType.PHI_DETECTED for e in entries)

    def test_get_entries_filter_by_since(self, db_and_audit):
        """get_entries() filters by since timestamp."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {})

        since = datetime.now(timezone.utc)

        audit.log(AuditEventType.PHI_DETECTED, {})

        entries = audit.get_entries(since=since)

        assert len(entries) == 1
        assert entries[0].event_type == AuditEventType.PHI_DETECTED


# =============================================================================
# COUNT AND SIZE TESTS
# =============================================================================

class TestCountAndSize:
    """Tests for count and size methods."""

    def test_count_empty(self, db_and_audit):
        """count() returns 0 for empty log."""
        db, audit = db_and_audit

        assert audit.count() == 0

    def test_count_after_entries(self, db_and_audit):
        """count() returns correct count."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {})
        audit.log(AuditEventType.PHI_DETECTED, {})

        assert audit.count() == 2

    def test_size_bytes(self, db_and_audit):
        """size_bytes() returns estimated size."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {})

        size = audit.size_bytes()

        assert size > 0
        # Estimate is ~500 bytes per entry
        assert size == 500


# =============================================================================
# EXPORT TESTS
# =============================================================================

class TestExport:
    """Tests for export functionality."""

    def test_export_entries_jsonl(self, db_and_audit):
        """export_entries() exports to JSONL format."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {"x": 1})
        audit.log(AuditEventType.PHI_DETECTED, {"x": 2})

        # Export all entries (up to now + 1 day)
        exported = audit.export_entries(
            before=datetime.now(timezone.utc) + timedelta(days=1),
            format="jsonl"
        )

        lines = exported.strip().split("\n")
        assert len(lines) == 2

        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "sequence" in data
            assert "event_type" in data

    def test_export_entries_invalid_format_raises(self, db_and_audit):
        """export_entries() raises for invalid format."""
        db, audit = db_and_audit

        with pytest.raises(ValueError, match="Unknown format"):
            audit.export_entries(
                before=datetime.now(timezone.utc),
                format="invalid"
            )


# =============================================================================
# RETENTION STATUS TESTS
# =============================================================================

class TestRetentionStatus:
    """Tests for retention status."""

    def test_retention_status_empty(self, db_and_audit):
        """get_retention_status() handles empty log."""
        db, audit = db_and_audit

        status = audit.get_retention_status()

        assert status["total_entries"] == 0
        assert status["oldest_entry"] is None
        assert status["entries_past_retention"] == 0

    def test_retention_status_with_entries(self, db_and_audit):
        """get_retention_status() returns correct info."""
        db, audit = db_and_audit

        audit.log(AuditEventType.SESSION_START, {})
        audit.log(AuditEventType.PHI_DETECTED, {})

        status = audit.get_retention_status()

        assert status["total_entries"] == 2
        assert status["oldest_entry"] is not None
        assert status["retention_days"] == 2190  # Default 6 years


# =============================================================================
# OLDEST TIMESTAMP TESTS
# =============================================================================

class TestOldestTimestamp:
    """Tests for get_oldest_timestamp method."""

    def test_oldest_timestamp_empty(self, db_and_audit):
        """get_oldest_timestamp() returns None for empty log."""
        db, audit = db_and_audit

        oldest = audit.get_oldest_timestamp()
        assert oldest is None

    def test_oldest_timestamp_returns_first(self, db_and_audit):
        """get_oldest_timestamp() returns first entry's timestamp."""
        db, audit = db_and_audit

        entry1 = audit.log(AuditEventType.SESSION_START, {})
        audit.log(AuditEventType.PHI_DETECTED, {})

        oldest = audit.get_oldest_timestamp()

        # Should be close to entry1's timestamp
        assert abs((oldest - entry1.timestamp).total_seconds()) < 1


# =============================================================================
# HASH COMPUTATION TESTS
# =============================================================================

class TestHashComputation:
    """Tests for hash computation."""

    def test_hash_is_deterministic(self, db_and_audit):
        """Hash computation is deterministic."""
        db, audit = db_and_audit

        hash1 = audit._compute_hash(
            sequence=1,
            event_type="SESSION_START",
            timestamp="2024-01-01T00:00:00Z",
            data_json='{"x":1}',
            prev_hash="GENESIS"
        )

        hash2 = audit._compute_hash(
            sequence=1,
            event_type="SESSION_START",
            timestamp="2024-01-01T00:00:00Z",
            data_json='{"x":1}',
            prev_hash="GENESIS"
        )

        assert hash1 == hash2

    def test_hash_changes_with_sequence(self, db_and_audit):
        """Hash changes when sequence changes."""
        db, audit = db_and_audit

        hash1 = audit._compute_hash(1, "E", "T", "{}", "P")
        hash2 = audit._compute_hash(2, "E", "T", "{}", "P")

        assert hash1 != hash2

    def test_hash_changes_with_data(self, db_and_audit):
        """Hash changes when data changes."""
        db, audit = db_and_audit

        hash1 = audit._compute_hash(1, "E", "T", '{"x":1}', "P")
        hash2 = audit._compute_hash(1, "E", "T", '{"x":2}', "P")

        assert hash1 != hash2


# =============================================================================
# SESSION ISOLATION TESTS
# =============================================================================

class TestSessionIsolation:
    """Tests for session isolation."""

    def test_different_sessions_isolated(self):
        """Entries from different sessions are isolated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            audit1 = AuditLog(db, "session_1")
            audit2 = AuditLog(db, "session_2")

            audit1.log(AuditEventType.SESSION_START, {"s": 1})
            audit2.log(AuditEventType.SESSION_START, {"s": 2})

            # Each session has its own entry
            entries1 = audit1.get_entries()
            entries2 = audit2.get_entries()

            # Both start at sequence 1 (independent)
            assert len(entries1) == 1
            assert len(entries2) == 1
            assert entries1[0].sequence == 1
            assert entries2[0].sequence == 1

            db.close()

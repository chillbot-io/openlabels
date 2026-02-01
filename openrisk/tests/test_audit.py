"""Tests for audit module."""

import os
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from openlabels.vault.audit import AuditLog
from openlabels.vault.models import AuditAction, AuditEntry
from openlabels.auth.crypto import CryptoProvider


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def crypto():
    return CryptoProvider()


@pytest.fixture
def admin_dek(crypto):
    return crypto.generate_key()


@pytest.fixture
def audit(temp_dir, crypto, admin_dek):
    audit = AuditLog(temp_dir, crypto)
    audit.setup_admin_key(admin_dek)
    return audit


class TestAuditEntry:
    def test_compute_hash_deterministic(self):
        entry = AuditEntry(
            id="test-id",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            user_id="user123",
            action=AuditAction.VAULT_UNLOCK,
            details={"reason": "test"},
            prev_hash="abc123",
        )
        hash1 = entry.compute_hash()
        hash2 = entry.compute_hash()
        assert hash1 == hash2

    def test_compute_hash_changes_with_data(self):
        entry1 = AuditEntry(
            id="test-id",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            user_id="user123",
            action=AuditAction.VAULT_UNLOCK,
            details={},
            prev_hash="",
        )
        entry2 = AuditEntry(
            id="test-id",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            user_id="different-user",
            action=AuditAction.VAULT_UNLOCK,
            details={},
            prev_hash="",
        )
        assert entry1.compute_hash() != entry2.compute_hash()

    def test_to_dict_from_dict_roundtrip(self):
        entry = AuditEntry(
            id="test-id",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            user_id="user123",
            action=AuditAction.SPAN_VIEW,
            details={"file_path": "/test.csv"},
            prev_hash="prev123",
            entry_hash="hash456",
        )
        data = entry.to_dict()
        restored = AuditEntry.from_dict(data)
        assert restored.id == entry.id
        assert restored.timestamp == entry.timestamp
        assert restored.user_id == entry.user_id
        assert restored.action == entry.action
        assert restored.details == entry.details
        assert restored.prev_hash == entry.prev_hash
        assert restored.entry_hash == entry.entry_hash


class TestAuditLog:
    def test_setup_creates_directories(self, temp_dir, crypto, admin_dek):
        audit = AuditLog(temp_dir, crypto)
        audit.setup_admin_key(admin_dek)
        assert (temp_dir / "audit").exists()
        assert (temp_dir / "audit" / "admin_key.enc").exists()

    def test_log_with_admin_dek(self, audit, admin_dek):
        entry = audit.log(
            user_id="user123",
            action=AuditAction.VAULT_UNLOCK,
            details={"test": "data"},
            admin_dek=admin_dek,
        )
        assert isinstance(entry.id, str) and len(entry.id) > 0
        assert entry.user_id == "user123"
        assert entry.action == AuditAction.VAULT_UNLOCK
        assert entry.details == {"test": "data"}
        assert isinstance(entry.entry_hash, str) and len(entry.entry_hash) >= 64

    def test_log_creates_hash_chain(self, audit, admin_dek):
        entry1 = audit.log("user1", AuditAction.VAULT_UNLOCK, {}, admin_dek)
        entry2 = audit.log("user2", AuditAction.VAULT_LOCK, {}, admin_dek)

        assert entry1.prev_hash == ""
        assert entry2.prev_hash == entry1.entry_hash

    def test_read_returns_entries(self, audit, admin_dek):
        audit.log("user1", AuditAction.VAULT_UNLOCK, {}, admin_dek)
        audit.log("user2", AuditAction.SPAN_VIEW, {"file": "test.csv"}, admin_dek)

        entries = list(audit.read(admin_dek))
        assert len(entries) == 2
        # Most recent first
        assert entries[0].action == AuditAction.SPAN_VIEW
        assert entries[1].action == AuditAction.VAULT_UNLOCK

    def test_read_with_action_filter(self, audit, admin_dek):
        audit.log("user1", AuditAction.VAULT_UNLOCK, {}, admin_dek)
        audit.log("user1", AuditAction.SPAN_VIEW, {}, admin_dek)
        audit.log("user1", AuditAction.VAULT_LOCK, {}, admin_dek)

        entries = list(audit.read(admin_dek, action_filter=AuditAction.SPAN_VIEW))
        assert len(entries) == 1
        assert entries[0].action == AuditAction.SPAN_VIEW

    def test_read_with_user_filter(self, audit, admin_dek):
        audit.log("user1", AuditAction.VAULT_UNLOCK, {}, admin_dek)
        audit.log("user2", AuditAction.VAULT_UNLOCK, {}, admin_dek)
        audit.log("user1", AuditAction.VAULT_LOCK, {}, admin_dek)

        entries = list(audit.read(admin_dek, user_filter="user1"))
        assert len(entries) == 2
        assert all(e.user_id == "user1" for e in entries)

    def test_read_with_limit(self, audit, admin_dek):
        for i in range(5):
            audit.log(f"user{i}", AuditAction.VAULT_UNLOCK, {}, admin_dek)

        entries = list(audit.read(admin_dek, limit=3))
        assert len(entries) == 3

    def test_verify_chain_empty_log(self, audit, admin_dek):
        is_valid, message = audit.verify_chain(admin_dek)
        assert is_valid is True
        assert isinstance(message, str) and len(message) > 0

    def test_verify_chain_valid(self, audit, admin_dek):
        audit.log("user1", AuditAction.VAULT_UNLOCK, {}, admin_dek)
        audit.log("user2", AuditAction.SPAN_VIEW, {}, admin_dek)
        audit.log("user3", AuditAction.VAULT_LOCK, {}, admin_dek)

        is_valid, message = audit.verify_chain(admin_dek)
        assert is_valid is True
        assert isinstance(message, str) and len(message) > 0

    def test_get_stats(self, audit, admin_dek):
        audit.log("user1", AuditAction.VAULT_UNLOCK, {}, admin_dek)
        audit.log("user1", AuditAction.SPAN_VIEW, {}, admin_dek)
        audit.log("user2", AuditAction.SPAN_VIEW, {}, admin_dek)

        stats = audit.get_stats(admin_dek)
        assert stats["total_entries"] == 3
        assert stats["by_action"]["vault_unlock"] == 1
        assert stats["by_action"]["span_view"] == 2
        assert stats["by_user"]["user1"] == 2
        assert stats["by_user"]["user2"] == 1

    def test_get_stats_empty(self, audit, admin_dek):
        stats = audit.get_stats(admin_dek)
        assert stats["total_entries"] == 0


class TestAuditQueue:
    def test_log_without_admin_dek_queues(self, audit, temp_dir):
        entry = audit.log("user1", AuditAction.VAULT_UNLOCK, {})
        assert isinstance(entry.entry_hash, str) and len(entry.entry_hash) >= 64
        assert entry.user_id == "user1"
        assert entry.action == AuditAction.VAULT_UNLOCK

        # Should be queued (encrypted)
        queue_file = temp_dir / "audit" / "queue.enc"
        assert queue_file.exists()

    def test_flush_queue(self, audit, admin_dek, temp_dir):
        # Log without admin DEK (queued)
        audit.log("user1", AuditAction.VAULT_UNLOCK, {})
        audit.log("user2", AuditAction.SPAN_VIEW, {})

        queue_file = temp_dir / "audit" / "queue.enc"
        assert queue_file.exists()

        # Flush queue
        count = audit.flush_queue(admin_dek)
        assert count == 2
        assert not queue_file.exists()

        # Entries should now be readable
        entries = list(audit.read(admin_dek))
        assert len(entries) == 2

    def test_read_auto_flushes_queue(self, audit, admin_dek):
        # Log without admin DEK (queued)
        audit.log("user1", AuditAction.VAULT_UNLOCK, {})

        # Reading should flush the queue
        entries = list(audit.read(admin_dek))
        assert len(entries) == 1
        assert entries[0].action == AuditAction.VAULT_UNLOCK

    def test_chain_includes_queued_entries(self, audit, admin_dek):
        # Log with admin DEK
        audit.log("user1", AuditAction.VAULT_UNLOCK, {}, admin_dek)

        # Log without admin DEK (queued)
        audit.log("user2", AuditAction.SPAN_VIEW, {})

        # Flush and verify chain
        audit.flush_queue(admin_dek)
        is_valid, _ = audit.verify_chain(admin_dek)
        assert is_valid


class TestAuditEncryption:
    def test_audit_data_encrypted(self, audit, admin_dek, temp_dir):
        audit.log(
            user_id="secret-user",
            action=AuditAction.SPAN_VIEW,
            details={"file_path": "/sensitive/data.csv"},
            admin_dek=admin_dek,
        )

        # Raw file should not contain plaintext
        audit_file = temp_dir / "audit" / "audit.enc"
        content = audit_file.read_bytes()
        assert b"secret-user" not in content
        assert b"sensitive/data.csv" not in content

    def test_wrong_dek_cannot_read(self, temp_dir, crypto):
        dek1 = crypto.generate_key()
        dek2 = crypto.generate_key()

        audit1 = AuditLog(temp_dir, crypto)
        audit1.setup_admin_key(dek1)
        audit1.log("user1", AuditAction.VAULT_UNLOCK, {}, dek1)

        # Try to read with different key
        audit2 = AuditLog(temp_dir, crypto)
        with pytest.raises(Exception):
            list(audit2.read(dek2))

    def test_queue_keypair_created(self, audit, admin_dek, temp_dir):
        """Verify that setup creates queue keypair files."""
        assert (temp_dir / "audit" / "queue_public.key").exists()
        assert (temp_dir / "audit" / "queue_private.enc").exists()

    def test_queued_entries_encrypted(self, audit, admin_dek, temp_dir):
        """Verify that queued entries are encrypted, not plaintext."""
        # Log without admin DEK (queued)
        audit.log("secret-user", AuditAction.SPAN_VIEW, {"file": "secret.csv"})

        queue_file = temp_dir / "audit" / "queue.enc"
        assert queue_file.exists()

        # Raw queue should not contain plaintext
        content = queue_file.read_bytes()
        assert b"secret-user" not in content
        assert b"secret.csv" not in content

    def test_encrypted_queue_flush(self, audit, admin_dek):
        """Verify that encrypted queued entries can be flushed and read."""
        # Log without admin DEK (queued and encrypted)
        audit.log("user1", AuditAction.VAULT_UNLOCK, {"test": "data1"})
        audit.log("user2", AuditAction.SPAN_VIEW, {"test": "data2"})

        # Flush the encrypted queue
        count = audit.flush_queue(admin_dek)
        assert count == 2

        # Verify entries are readable
        entries = list(audit.read(admin_dek))
        assert len(entries) == 2
        assert entries[0].action == AuditAction.SPAN_VIEW
        assert entries[1].action == AuditAction.VAULT_UNLOCK


class TestCryptoAsymmetric:
    """Tests for asymmetric encryption (seal/unseal)."""

    def test_seal_unseal_roundtrip(self, crypto):
        """Verify seal/unseal roundtrip works."""
        private_key, public_key = crypto.generate_keypair()
        plaintext = b"secret message for asymmetric encryption"

        sealed = crypto.seal(plaintext, public_key)
        unsealed = crypto.unseal(sealed, private_key)

        assert unsealed == plaintext

    def test_seal_different_each_time(self, crypto):
        """Verify sealing produces different output each time (ephemeral keys)."""
        private_key, public_key = crypto.generate_keypair()
        plaintext = b"same message"

        sealed1 = crypto.seal(plaintext, public_key)
        sealed2 = crypto.seal(plaintext, public_key)

        assert sealed1 != sealed2  # Different ephemeral keys

    def test_unseal_wrong_key_fails(self, crypto):
        """Verify unsealing with wrong key fails."""
        private_key1, public_key1 = crypto.generate_keypair()
        private_key2, public_key2 = crypto.generate_keypair()

        sealed = crypto.seal(b"secret", public_key1)

        with pytest.raises(Exception):
            crypto.unseal(sealed, private_key2)

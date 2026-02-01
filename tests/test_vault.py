"""Tests for vault module."""

import os
import tempfile
from pathlib import Path

import pytest

from openlabels.vault.vault import Vault
from openlabels.vault.models import SensitiveSpan, FileClassification


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def dek():
    return os.urandom(32)


@pytest.fixture
def vault(temp_dir, dek):
    return Vault(user_id="test-user", dek=dek, data_dir=temp_dir)


@pytest.fixture
def sample_spans():
    return [
        SensitiveSpan(
            start=10, end=21, text="123-45-6789",
            entity_type="SSN", confidence=0.95, detector="pattern",
            context_before="SSN: ", context_after=" is mine"
        ),
        SensitiveSpan(
            start=50, end=68, text="john@example.com",
            entity_type="EMAIL", confidence=0.99, detector="pattern",
            context_before="Email: ", context_after=""
        ),
    ]


class TestVault:
    def test_store_and_retrieve_spans(self, vault, sample_spans):
        entry_id = vault.store_scan_result(
            file_path="/data/test.csv",
            spans=sample_spans,
            source="openlabels",
            metadata={"score": 85, "tier": "HIGH"},
        )

        entry = vault.get_vault_entry(entry_id)
        assert len(entry.spans) == 2
        assert entry.spans[0].text == "123-45-6789"
        assert entry.spans[1].text == "john@example.com"

    def test_spans_encrypted(self, vault, sample_spans, temp_dir):
        vault.store_scan_result(
            file_path="/data/test.csv",
            spans=sample_spans,
            source="openlabels",
        )

        # Raw file should not contain plaintext
        vault_dir = temp_dir / "vaults" / "test-user"
        for f in vault_dir.rglob("*.enc"):
            content = f.read_bytes()
            assert b"123-45-6789" not in content
            assert b"john@example.com" not in content

    def test_classification_created(self, vault, sample_spans):
        vault.store_scan_result(
            file_path="/data/test.csv",
            spans=sample_spans,
            source="openlabels",
            metadata={"score": 85, "tier": "HIGH"},
        )

        classification = vault.get_classification("/data/test.csv")
        assert classification is not None
        assert classification.file_path == "/data/test.csv"
        assert classification.risk_score == 85
        assert classification.tier == "HIGH"

    def test_classification_has_findings(self, vault, sample_spans):
        vault.store_scan_result(
            file_path="/data/test.csv",
            spans=sample_spans,
            source="openlabels",
        )

        classification = vault.get_classification("/data/test.csv")
        assert len(classification.sources) == 1
        assert classification.sources[0].provider == "openlabels"

        findings = classification.sources[0].findings
        entity_types = {f.entity_type for f in findings}
        assert "SSN" in entity_types
        assert "EMAIL" in entity_types

    def test_classification_aggregates_findings(self, vault):
        # Store multiple scans for same file
        spans1 = [SensitiveSpan(0, 10, "123-45-6789", "SSN", 0.9, "p")]
        spans2 = [SensitiveSpan(0, 10, "john@x.com", "EMAIL", 0.9, "p")]

        vault.store_scan_result("/data/test.csv", spans1, "scanner1")
        vault.store_scan_result("/data/test.csv", spans2, "scanner2")

        classification = vault.get_classification("/data/test.csv")
        assert len(classification.sources) == 2

    def test_tier_uses_most_severe(self, vault):
        spans = [SensitiveSpan(0, 10, "x", "SSN", 0.9, "p")]

        vault.store_scan_result(
            "/data/test.csv", spans, "s1",
            metadata={"score": 50, "tier": "MEDIUM"}
        )
        vault.store_scan_result(
            "/data/test.csv", spans, "s2",
            metadata={"score": 90, "tier": "CRITICAL"}
        )

        classification = vault.get_classification("/data/test.csv")
        assert classification.tier == "CRITICAL"
        assert classification.risk_score == 90

    def test_list_entries(self, vault, sample_spans):
        vault.store_scan_result("/a.csv", sample_spans[:1], "s")
        vault.store_scan_result("/b.csv", sample_spans[1:], "s")

        entries = vault.list_entries()
        assert len(entries) == 2

    def test_get_nonexistent_entry(self, vault):
        entry = vault.get_vault_entry("nonexistent-id")
        assert entry is None

    def test_get_nonexistent_classification(self, vault):
        classification = vault.get_classification("/no/such/file.txt")
        assert classification is None

    def test_clear_vault(self, vault, sample_spans):
        vault.store_scan_result("/test.csv", sample_spans, "s")
        assert len(vault.list_entries()) == 1

        vault.clear()
        assert len(vault.list_entries()) == 0

    def test_different_users_isolated(self, temp_dir, dek):
        vault1 = Vault("user1", dek, temp_dir)
        vault2 = Vault("user2", dek, temp_dir)

        spans = [SensitiveSpan(0, 5, "12345", "SSN", 0.9, "p")]
        vault1.store_scan_result("/test.csv", spans, "s")

        assert len(vault1.list_entries()) == 1
        assert len(vault2.list_entries()) == 0

    def test_wrong_dek_cannot_read(self, temp_dir):
        dek1 = os.urandom(32)
        dek2 = os.urandom(32)

        vault1 = Vault("user", dek1, temp_dir)
        spans = [SensitiveSpan(0, 5, "12345", "SSN", 0.9, "p")]
        entry_id = vault1.store_scan_result("/test.csv", spans, "s")

        vault2 = Vault("user", dek2, temp_dir)
        with pytest.raises(Exception):
            vault2.get_vault_entry(entry_id)

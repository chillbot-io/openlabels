"""Tests for vault models serialization."""

from datetime import datetime

import pytest

from openlabels.vault.models import (
    SensitiveSpan,
    Finding,
    ClassificationSource,
    VaultEntry,
    FileClassification,
)


class TestSensitiveSpan:
    def test_to_dict(self):
        span = SensitiveSpan(
            start=10,
            end=21,
            text="123-45-6789",
            entity_type="SSN",
            confidence=0.95,
            detector="pattern",
            context_before="SSN: ",
            context_after=" is valid",
        )
        d = span.to_dict()
        assert d["start"] == 10
        assert d["end"] == 21
        assert d["text"] == "123-45-6789"
        assert d["entity_type"] == "SSN"
        assert d["confidence"] == 0.95
        assert d["detector"] == "pattern"
        assert d["context_before"] == "SSN: "
        assert d["context_after"] == " is valid"

    def test_from_dict(self):
        d = {
            "start": 10,
            "end": 21,
            "text": "123-45-6789",
            "entity_type": "SSN",
            "confidence": 0.95,
            "detector": "pattern",
            "context_before": "SSN: ",
            "context_after": " is valid",
        }
        span = SensitiveSpan.from_dict(d)
        assert span.start == 10
        assert span.text == "123-45-6789"
        assert span.entity_type == "SSN"

    def test_roundtrip(self):
        span = SensitiveSpan(
            start=0, end=10, text="test@example.com",
            entity_type="EMAIL", confidence=0.9, detector="regex"
        )
        restored = SensitiveSpan.from_dict(span.to_dict())
        assert restored.start == span.start
        assert restored.end == span.end
        assert restored.text == span.text
        assert restored.entity_type == span.entity_type
        assert restored.confidence == span.confidence

    def test_from_dict_missing_context(self):
        d = {
            "start": 0, "end": 10, "text": "secret",
            "entity_type": "PASSWORD", "confidence": 0.8, "detector": "heuristic"
        }
        span = SensitiveSpan.from_dict(d)
        assert span.context_before == ""
        assert span.context_after == ""

    def test_redacted_short(self):
        span = SensitiveSpan(
            start=0, end=3, text="abc",
            entity_type="TEST", confidence=1.0, detector="test"
        )
        assert span.redacted() == "***"

    def test_redacted_long(self):
        span = SensitiveSpan(
            start=0, end=11, text="123-45-6789",
            entity_type="SSN", confidence=1.0, detector="test"
        )
        assert span.redacted() == "12*******89"


class TestFinding:
    def test_to_dict(self):
        finding = Finding(
            entity_type="SSN",
            count=5,
            confidence=0.9,
            severity="HIGH"
        )
        d = finding.to_dict()
        assert d["entity_type"] == "SSN"
        assert d["count"] == 5
        assert d["confidence"] == 0.9
        assert d["severity"] == "HIGH"

    def test_from_dict(self):
        d = {"entity_type": "EMAIL", "count": 10, "confidence": 0.85, "severity": None}
        finding = Finding.from_dict(d)
        assert finding.entity_type == "EMAIL"
        assert finding.count == 10

    def test_roundtrip(self):
        finding = Finding(entity_type="PHONE", count=3, confidence=0.7, severity="MEDIUM")
        restored = Finding.from_dict(finding.to_dict())
        assert restored.entity_type == finding.entity_type
        assert restored.count == finding.count
        assert restored.confidence == finding.confidence
        assert restored.severity == finding.severity


class TestClassificationSource:
    def test_to_dict(self):
        source = ClassificationSource(
            provider="openlabels",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            findings=[Finding("SSN", 5, 0.9, "HIGH")],
            metadata={"scan_duration_ms": 150},
            vault_entry_id="entry-123",
        )
        d = source.to_dict()
        assert d["provider"] == "openlabels"
        assert d["timestamp"] == "2024-01-15T10:30:00"
        assert len(d["findings"]) == 1
        assert d["metadata"]["scan_duration_ms"] == 150
        assert d["vault_entry_id"] == "entry-123"

    def test_from_dict(self):
        d = {
            "provider": "macie",
            "timestamp": "2024-01-15T10:30:00",
            "findings": [{"entity_type": "SSN", "count": 5, "confidence": 0.9, "severity": "HIGH"}],
            "metadata": {"job_id": "abc"},
            "vault_entry_id": None,
        }
        source = ClassificationSource.from_dict(d)
        assert source.provider == "macie"
        assert source.timestamp == datetime(2024, 1, 15, 10, 30, 0)
        assert len(source.findings) == 1

    def test_roundtrip(self):
        source = ClassificationSource(
            provider="purview",
            timestamp=datetime(2024, 6, 1, 12, 0, 0),
            findings=[Finding("EMAIL", 10, 0.95, None)],
        )
        restored = ClassificationSource.from_dict(source.to_dict())
        assert restored.provider == source.provider
        assert restored.timestamp == source.timestamp
        assert len(restored.findings) == 1

    def test_total_findings(self):
        source = ClassificationSource(
            provider="openlabels",
            timestamp=datetime.now(),
            findings=[
                Finding("SSN", 5, 0.9, None),
                Finding("EMAIL", 10, 0.8, None),
                Finding("PHONE", 3, 0.7, None),
            ],
        )
        assert source.total_findings == 18

    def test_provider_display_name(self):
        assert ClassificationSource(
            provider="macie", timestamp=datetime.now(), findings=[]
        ).provider_display_name == "AWS Macie"

        assert ClassificationSource(
            provider="purview", timestamp=datetime.now(), findings=[]
        ).provider_display_name == "Microsoft Purview"

        assert ClassificationSource(
            provider="openlabels", timestamp=datetime.now(), findings=[]
        ).provider_display_name == "OpenLabels Scanner"

        assert ClassificationSource(
            provider="unknown", timestamp=datetime.now(), findings=[]
        ).provider_display_name == "Unknown"


class TestVaultEntry:
    def test_to_dict(self):
        entry = VaultEntry(
            id="entry-123",
            file_hash="abc123",
            file_path="/data/test.csv",
            scan_timestamp=datetime(2024, 1, 15, 10, 30, 0),
            spans=[SensitiveSpan(0, 11, "123-45-6789", "SSN", 0.95, "pattern")],
            entity_counts={"SSN": 1},
        )
        d = entry.to_dict()
        assert d["id"] == "entry-123"
        assert d["file_hash"] == "abc123"
        assert d["file_path"] == "/data/test.csv"
        assert d["scan_timestamp"] == "2024-01-15T10:30:00"
        assert len(d["spans"]) == 1
        assert d["entity_counts"] == {"SSN": 1}

    def test_from_dict(self):
        d = {
            "id": "entry-456",
            "file_hash": "def456",
            "file_path": "/test.txt",
            "scan_timestamp": "2024-06-01T12:00:00",
            "spans": [
                {"start": 0, "end": 10, "text": "test@x.com", "entity_type": "EMAIL",
                 "confidence": 0.9, "detector": "regex"}
            ],
            "entity_counts": {"EMAIL": 1},
        }
        entry = VaultEntry.from_dict(d)
        assert entry.id == "entry-456"
        assert entry.file_path == "/test.txt"
        assert len(entry.spans) == 1
        assert entry.spans[0].entity_type == "EMAIL"

    def test_roundtrip(self):
        entry = VaultEntry(
            id="test-id",
            file_hash="hash123",
            file_path="/path/to/file.csv",
            scan_timestamp=datetime(2024, 3, 15, 8, 0, 0),
            spans=[
                SensitiveSpan(0, 11, "123-45-6789", "SSN", 0.95, "pattern"),
                SensitiveSpan(20, 35, "test@example.com", "EMAIL", 0.9, "regex"),
            ],
        )
        restored = VaultEntry.from_dict(entry.to_dict())
        assert restored.id == entry.id
        assert restored.file_path == entry.file_path
        assert len(restored.spans) == 2

    def test_compute_entity_counts(self):
        entry = VaultEntry(
            id="test",
            file_hash="hash",
            file_path="/test.csv",
            scan_timestamp=datetime.now(),
            spans=[
                SensitiveSpan(0, 11, "123-45-6789", "SSN", 0.95, "pattern"),
                SensitiveSpan(20, 31, "987-65-4321", "SSN", 0.95, "pattern"),
                SensitiveSpan(50, 65, "test@example.com", "EMAIL", 0.9, "regex"),
            ],
        )
        counts = entry.compute_entity_counts()
        assert counts == {"SSN": 2, "EMAIL": 1}
        assert entry.entity_counts == {"SSN": 2, "EMAIL": 1}


class TestFileClassification:
    def test_to_dict(self):
        fc = FileClassification(
            file_path="/data/patients.csv",
            file_hash="abc123",
            risk_score=85,
            tier="HIGH",
            sources=[
                ClassificationSource(
                    provider="openlabels",
                    timestamp=datetime(2024, 1, 15, 10, 30, 0),
                    findings=[Finding("SSN", 10, 0.9, "HIGH")],
                )
            ],
            labels=["PII", "Healthcare"],
        )
        d = fc.to_dict()
        assert d["file_path"] == "/data/patients.csv"
        assert d["risk_score"] == 85
        assert d["tier"] == "HIGH"
        assert len(d["sources"]) == 1
        assert d["labels"] == ["PII", "Healthcare"]

    def test_from_dict(self):
        d = {
            "file_path": "/test.csv",
            "file_hash": "hash123",
            "risk_score": 50,
            "tier": "MEDIUM",
            "sources": [
                {
                    "provider": "macie",
                    "timestamp": "2024-01-15T10:30:00",
                    "findings": [{"entity_type": "EMAIL", "count": 5, "confidence": 0.8, "severity": None}],
                    "metadata": {},
                    "vault_entry_id": None,
                }
            ],
            "labels": [],
        }
        fc = FileClassification.from_dict(d)
        assert fc.file_path == "/test.csv"
        assert fc.risk_score == 50
        assert len(fc.sources) == 1

    def test_roundtrip(self):
        fc = FileClassification(
            file_path="/data/file.csv",
            file_hash="xyz789",
            risk_score=75,
            tier="HIGH",
            sources=[],
            labels=["Confidential"],
        )
        restored = FileClassification.from_dict(fc.to_dict())
        assert restored.file_path == fc.file_path
        assert restored.risk_score == fc.risk_score
        assert restored.labels == fc.labels

    def test_primary_source_empty(self):
        fc = FileClassification(
            file_path="/test.csv",
            file_hash="hash",
            risk_score=0,
            tier="MINIMAL",
            sources=[],
        )
        assert fc.primary_source is None

    def test_primary_source_returns_most_recent(self):
        fc = FileClassification(
            file_path="/test.csv",
            file_hash="hash",
            risk_score=50,
            tier="MEDIUM",
            sources=[
                ClassificationSource("macie", datetime(2024, 1, 1), []),
                ClassificationSource("openlabels", datetime(2024, 6, 1), []),
                ClassificationSource("purview", datetime(2024, 3, 1), []),
            ],
        )
        assert fc.primary_source.provider == "openlabels"

    def test_all_findings_aggregates(self):
        fc = FileClassification(
            file_path="/test.csv",
            file_hash="hash",
            risk_score=60,
            tier="MEDIUM",
            sources=[
                ClassificationSource(
                    "macie", datetime(2024, 1, 1),
                    [Finding("SSN", 5, 0.9, None), Finding("EMAIL", 3, 0.8, None)]
                ),
                ClassificationSource(
                    "openlabels", datetime(2024, 2, 1),
                    [Finding("SSN", 8, 0.95, None), Finding("PHONE", 2, 0.7, None)]
                ),
            ],
        )
        findings = fc.all_findings
        # Should take max count per type
        assert findings["SSN"] == 8
        assert findings["EMAIL"] == 3
        assert findings["PHONE"] == 2

    def test_has_scanned_content_false(self):
        fc = FileClassification(
            file_path="/test.csv",
            file_hash="hash",
            risk_score=50,
            tier="MEDIUM",
            sources=[
                ClassificationSource("macie", datetime.now(), [], vault_entry_id=None),
            ],
        )
        assert fc.has_scanned_content() is False

    def test_has_scanned_content_true(self):
        fc = FileClassification(
            file_path="/test.csv",
            file_hash="hash",
            risk_score=50,
            tier="MEDIUM",
            sources=[
                ClassificationSource("openlabels", datetime.now(), [], vault_entry_id="entry-123"),
            ],
        )
        assert fc.has_scanned_content() is True

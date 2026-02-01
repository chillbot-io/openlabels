"""
Vault data models.

Defines the structure for:
- Sensitive spans (the actual PII/PHI text)
- Classification sources (Macie, Purview, scanner, manual)
- Vault entries (aggregated data per file)
- Audit log entries (hash-chained)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class AuditAction(Enum):
    """Actions that are logged in the audit trail."""
    VAULT_UNLOCK = "vault_unlock"           # User unlocked their vault
    VAULT_LOCK = "vault_lock"               # User locked their vault
    SPAN_VIEW = "span_view"                 # User viewed sensitive text
    SPAN_EXPORT = "span_export"             # User exported sensitive data
    SCAN_STORE = "scan_store"               # Scan results stored in vault
    SCAN_DELETE = "scan_delete"             # Scan results deleted
    CLASSIFICATION_ADD = "classification_add"  # Classification source added
    USER_RESET = "user_reset"               # Admin reset user's vault
    ADMIN_AUDIT_VIEW = "admin_audit_view"   # Admin viewed audit logs


@dataclass
class SensitiveSpan:
    """
    A single detected sensitive data span.

    This is the actual sensitive text - stored encrypted in vault.
    """
    start: int                    # Start position in source text
    end: int                      # End position in source text
    text: str                     # THE ACTUAL SENSITIVE DATA
    entity_type: str              # SSN, EMAIL, PHONE, etc.
    confidence: float             # Detection confidence (0-1)
    detector: str                 # Which detector found it
    context_before: str = ""      # ~50 chars before (for display context)
    context_after: str = ""       # ~50 chars after (for display context)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "entity_type": self.entity_type,
            "confidence": self.confidence,
            "detector": self.detector,
            "context_before": self.context_before,
            "context_after": self.context_after,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SensitiveSpan":
        """Deserialize from dictionary."""
        return cls(
            start=data["start"],
            end=data["end"],
            text=data["text"],
            entity_type=data["entity_type"],
            confidence=data["confidence"],
            detector=data["detector"],
            context_before=data.get("context_before", ""),
            context_after=data.get("context_after", ""),
        )

    def redacted(self) -> str:
        """Return redacted version of the text."""
        if len(self.text) <= 4:
            return "*" * len(self.text)
        return self.text[:2] + "*" * (len(self.text) - 4) + self.text[-2:]


@dataclass
class Finding:
    """
    A finding from a classification source (metadata only, no sensitive text).

    This is safe to display without vault unlock.
    """
    entity_type: str              # Type of entity found
    count: int                    # Number of occurrences
    confidence: float | None      # Average confidence (if available)
    severity: str | None = None   # Source-specific severity

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "entity_type": self.entity_type,
            "count": self.count,
            "confidence": self.confidence,
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Deserialize from dictionary."""
        return cls(
            entity_type=data["entity_type"],
            count=data["count"],
            confidence=data.get("confidence"),
            severity=data.get("severity"),
        )


@dataclass
class ClassificationSource:
    """
    A source of classification for a file.

    Represents data from Macie, Purview, OpenLabels scanner, or manual labels.
    Metadata is always visible; sensitive spans require vault unlock.
    """
    provider: str                 # "macie" | "purview" | "dlp" | "openlabels" | "manual"
    timestamp: datetime           # When this classification was recorded
    findings: list[Finding]       # Entity types and counts (visible)

    # Provider-specific metadata (always visible)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Examples:
    # - Macie: {"job_id": "...", "sensitivity": "HIGH", "labels": ["PII"]}
    # - Purview: {"label_id": "...", "label_name": "Confidential"}
    # - OpenLabels: {"scan_duration_ms": 150, "detectors_used": ["pattern", "ner"]}

    # Reference to sensitive spans in vault (not the spans themselves)
    vault_entry_id: str | None = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "provider": self.provider,
            "timestamp": self.timestamp.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "vault_entry_id": self.vault_entry_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ClassificationSource":
        """Deserialize from dictionary."""
        return cls(
            provider=data["provider"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            findings=[Finding.from_dict(f) for f in data["findings"]],
            metadata=data.get("metadata", {}),
            vault_entry_id=data.get("vault_entry_id"),
        )

    @property
    def total_findings(self) -> int:
        """Total number of findings across all entity types."""
        return sum(f.count for f in self.findings)

    @property
    def provider_display_name(self) -> str:
        """Human-readable provider name."""
        names = {
            "macie": "AWS Macie",
            "purview": "Microsoft Purview",
            "dlp": "Google Cloud DLP",
            "openlabels": "OpenLabels Scanner",
            "manual": "Manual Label",
        }
        return names.get(self.provider, self.provider.title())


@dataclass
class VaultEntry:
    """
    Encrypted vault entry for a single file.

    Contains the sensitive spans that require vault unlock to view.
    """
    id: str                       # Unique entry ID (UUID)
    file_hash: str                # SHA-256 of file path + scan timestamp
    file_path: str                # Original file path (for display)
    scan_timestamp: datetime      # When this scan was performed
    spans: list[SensitiveSpan]    # The sensitive data (encrypted at rest)

    # Summary stats (can be derived from spans)
    entity_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "file_hash": self.file_hash,
            "file_path": self.file_path,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "spans": [s.to_dict() for s in self.spans],
            "entity_counts": self.entity_counts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultEntry":
        """Deserialize from dictionary."""
        return cls(
            id=data["id"],
            file_hash=data["file_hash"],
            file_path=data["file_path"],
            scan_timestamp=datetime.fromisoformat(data["scan_timestamp"]),
            spans=[SensitiveSpan.from_dict(s) for s in data["spans"]],
            entity_counts=data.get("entity_counts", {}),
        )

    def compute_entity_counts(self) -> dict[str, int]:
        """Compute entity counts from spans."""
        counts: dict[str, int] = {}
        for span in self.spans:
            counts[span.entity_type] = counts.get(span.entity_type, 0) + 1
        self.entity_counts = counts
        return counts


@dataclass
class AuditEntry:
    """
    An entry in the hash-chained audit log.

    Each entry links to the previous via hash, making tampering detectable.
    """
    id: str                       # UUID
    timestamp: datetime           # When this action occurred
    user_id: str                  # Who performed the action
    action: AuditAction           # What action was performed
    details: dict[str, Any]       # Action-specific details

    # Hash chain
    prev_hash: str                # SHA-256 of previous entry (empty for first)
    entry_hash: str = ""          # SHA-256 of this entry (computed after creation)

    def to_dict(self) -> dict:
        """Serialize to dictionary (excludes entry_hash for hashing)."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "action": self.action.value,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    def to_dict_for_hash(self) -> dict:
        """Serialize for hash computation (excludes entry_hash)."""
        d = self.to_dict()
        del d["entry_hash"]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        """Deserialize from dictionary."""
        return cls(
            id=data["id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            user_id=data["user_id"],
            action=AuditAction(data["action"]),
            details=data.get("details", {}),
            prev_hash=data["prev_hash"],
            entry_hash=data.get("entry_hash", ""),
        )

    def compute_hash(self) -> str:
        """Compute the hash of this entry."""
        import hashlib
        import json
        content = json.dumps(self.to_dict_for_hash(), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class FileClassification:
    """
    Complete classification data for a file.

    Aggregates all classification sources and provides methods
    for the detail view.
    """
    file_path: str
    file_hash: str
    risk_score: int
    tier: str                     # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    sources: list[ClassificationSource]
    labels: list[str] = field(default_factory=list)  # User-applied labels

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "risk_score": self.risk_score,
            "tier": self.tier,
            "sources": [s.to_dict() for s in self.sources],
            "labels": self.labels,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FileClassification":
        """Deserialize from dictionary."""
        return cls(
            file_path=data["file_path"],
            file_hash=data["file_hash"],
            risk_score=data["risk_score"],
            tier=data["tier"],
            sources=[ClassificationSource.from_dict(s) for s in data["sources"]],
            labels=data.get("labels", []),
        )

    @property
    def primary_source(self) -> ClassificationSource | None:
        """Get the most recent/relevant classification source."""
        if not self.sources:
            return None
        # Return most recent
        return max(self.sources, key=lambda s: s.timestamp)

    @property
    def all_findings(self) -> dict[str, int]:
        """Aggregate findings across all sources."""
        findings: dict[str, int] = {}
        for source in self.sources:
            for finding in source.findings:
                findings[finding.entity_type] = max(
                    findings.get(finding.entity_type, 0),
                    finding.count,
                )
        return findings

    def has_scanned_content(self) -> bool:
        """Check if we have actual scanned content (vs just metadata)."""
        for source in self.sources:
            if source.vault_entry_id is not None:
                return True
        return False

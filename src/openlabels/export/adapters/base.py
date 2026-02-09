"""Base protocol and data types for SIEM export adapters."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

logger = logging.getLogger(__name__)


@dataclass
class ExportRecord:
    """Normalized record for SIEM export.

    Each record represents a single finding (scan result, access event,
    policy violation, or audit log entry) in a SIEM-agnostic format.
    Adapters convert these into their platform-native schema.
    """

    record_type: str  # scan_result, access_event, policy_violation, audit_log
    timestamp: datetime
    tenant_id: UUID
    file_path: str
    risk_score: int | None = None
    risk_tier: str | None = None
    entity_types: list[str] = field(default_factory=list)
    entity_counts: dict[str, int] = field(default_factory=dict)
    policy_violations: list[str] = field(default_factory=list)
    action_taken: str | None = None
    user: str | None = None
    source_adapter: str = "filesystem"
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON-based adapters."""
        return {
            "record_type": self.record_type,
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": str(self.tenant_id),
            "file_path": self.file_path,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier,
            "entity_types": self.entity_types,
            "entity_counts": self.entity_counts,
            "policy_violations": self.policy_violations,
            "action_taken": self.action_taken,
            "user": self.user,
            "source_adapter": self.source_adapter,
            **self.metadata,
        }


@runtime_checkable
class SIEMAdapter(Protocol):
    """Protocol for SIEM-specific export adapters."""

    async def export_batch(self, records: list[ExportRecord]) -> int:
        """Export a batch of records to the SIEM.

        Returns number of records successfully ingested.
        """
        ...

    async def test_connection(self) -> bool:
        """Verify connectivity to the SIEM endpoint."""
        ...

    def format_name(self) -> str:
        """Return adapter name: 'splunk', 'sentinel', 'qradar', etc."""
        ...

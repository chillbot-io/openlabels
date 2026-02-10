"""Quarantine manifest for tracking quarantined files.

Persists quarantine metadata to a JSON file so that files can be
located, verified, and restored long after the original quarantine
operation.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class QuarantineEntry:
    """A single record of a quarantined file."""

    id: str
    original_path: str
    quarantine_path: str
    quarantined_at: str  # ISO-8601
    reason: str
    risk_tier: str
    triggered_by: str
    scan_job_id: str | None = None
    file_hash: str | None = None  # SHA-256 before move
    restored: bool = False
    restored_at: str | None = None


class QuarantineManifest:
    """JSON-file backed quarantine manifest.

    Thread-safety note: this class is NOT thread-safe.  Callers that
    share a manifest across threads must provide external locking.
    For single-worker / single-process deployments (the default) this
    is fine.
    """

    def __init__(self, manifest_path: Path) -> None:
        self._path = Path(manifest_path)
        self._entries: dict[str, QuarantineEntry] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path) as f:
                    data = json.load(f)
                for entry_data in data.get("entries", []):
                    entry = QuarantineEntry(**entry_data)
                    self._entries[entry.id] = entry
            except (json.JSONDecodeError, TypeError, KeyError) as exc:
                logger.error("Failed to load quarantine manifest %s: %s", self._path, exc)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(
                {
                    "entries": [asdict(e) for e in self._entries.values()],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                f,
                indent=2,
            )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(
        self,
        original_path: Path,
        quarantine_path: Path,
        reason: str,
        risk_tier: str,
        triggered_by: str,
        scan_job_id: str | None = None,
        file_hash: str | None = None,
    ) -> QuarantineEntry:
        """Record a new quarantine operation and persist to disk."""
        entry = QuarantineEntry(
            id=str(uuid4()),
            original_path=str(original_path),
            quarantine_path=str(quarantine_path),
            quarantined_at=datetime.now(timezone.utc).isoformat(),
            reason=reason,
            risk_tier=risk_tier,
            triggered_by=triggered_by,
            scan_job_id=scan_job_id,
            file_hash=file_hash,
        )
        self._entries[entry.id] = entry
        self._save()
        return entry

    def get(self, entry_id: str) -> QuarantineEntry | None:
        """Lookup a single entry by ID."""
        return self._entries.get(entry_id)

    def find_by_original_path(self, path: str) -> list[QuarantineEntry]:
        """Find all entries that originated from *path*."""
        return [e for e in self._entries.values() if e.original_path == path]

    def mark_restored(self, entry_id: str) -> None:
        """Mark an entry as restored and persist."""
        if entry_id in self._entries:
            self._entries[entry_id].restored = True
            self._entries[entry_id].restored_at = datetime.now(timezone.utc).isoformat()
            self._save()

    def list_active(self) -> list[QuarantineEntry]:
        """Return entries that have NOT been restored."""
        return [e for e in self._entries.values() if not e.restored]

    def list_all(self) -> list[QuarantineEntry]:
        """Return all entries (active + restored)."""
        return list(self._entries.values())

"""Quarantine manifest for tracking quarantined files.

Persists quarantine metadata to a JSON file so that files can be
located, verified, and restored long after the original quarantine
operation.
"""

from __future__ import annotations

import fcntl
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


# Default allowed base directories for path traversal prevention.
# Restore operations will only target paths under these roots.
# Intentionally restrictive — callers must provide explicit allowed_bases
# matching their scan target directories.
DEFAULT_ALLOWED_BASES: list[Path] = []


class QuarantineManifest:
    """JSON-file backed quarantine manifest.

    Uses file locking (``fcntl.flock``) to prevent corruption from
    concurrent readers/writers.
    """

    def __init__(
        self,
        manifest_path: Path,
        allowed_bases: list[Path] | None = None,
    ) -> None:
        self._path = Path(manifest_path)
        self._entries: dict[str, QuarantineEntry] = {}
        bases = allowed_bases if allowed_bases is not None else DEFAULT_ALLOWED_BASES
        if not bases:
            logger.warning(
                "QuarantineManifest: no allowed_bases configured. "
                "Restore operations will be rejected until explicit bases are set."
            )
        self._allowed_bases = [b.resolve() for b in bases]
        self._load()

    def validate_original_path(self, original_path: str) -> bool:
        """Check that *original_path* falls under an allowed base directory.

        Prevents path-traversal attacks when restoring quarantined files.
        """
        try:
            resolved = Path(original_path).resolve()
        except (OSError, ValueError):
            return False
        return any(
            resolved == base or base in resolved.parents
            for base in self._allowed_bases
        )

    # Persistence
    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path) as f:
                    fcntl.flock(f, fcntl.LOCK_SH)
                    try:
                        data = json.load(f)
                    finally:
                        fcntl.flock(f, fcntl.LOCK_UN)
                for entry_data in data.get("entries", []):
                    entry = QuarantineEntry(**entry_data)
                    # Validate original_path against allowed bases
                    if not self.validate_original_path(entry.original_path):
                        logger.warning(
                            "Skipping manifest entry %s: original_path %r is "
                            "outside allowed base directories",
                            entry.id,
                            entry.original_path,
                        )
                        continue
                    self._entries[entry.id] = entry
            except (json.JSONDecodeError, TypeError, KeyError) as exc:
                logger.error("Failed to load quarantine manifest %s: %s", self._path, exc)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                json.dump(
                    {
                        "entries": [asdict(e) for e in self._entries.values()],
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                    f,
                    indent=2,
                )
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    # CRUD
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

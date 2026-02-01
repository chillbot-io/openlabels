"""
Vault implementation - encrypted storage for sensitive scan data.

Each user has their own vault, encrypted with their DEK.
Vault is only accessible when user is authenticated.
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .models import (
    VaultEntry,
    SensitiveSpan,
    ClassificationSource,
    Finding,
    FileClassification,
    AuditAction,
)

if TYPE_CHECKING:
    from openlabels.auth.crypto import CryptoProvider


class Vault:
    """
    Encrypted vault for storing sensitive scan data.

    Data is encrypted at rest using the user's DEK (Data Encryption Key).
    The DEK is derived from the user's password and only available
    during an authenticated session.

    Storage structure:
        vaults/{user_id}/
        ├── vault.enc           # Encrypted vault data
        ├── classifications/    # File classification metadata (not encrypted)
        │   └── {file_hash}.json
        └── index.json          # File hash -> entry ID mapping

    Example:
        vault = Vault(user_id="123", dek=session_dek)

        # Store scan results
        vault.store_scan_result(
            file_path="/data/patients.csv",
            spans=detected_spans,
            source="openlabels",
            metadata={"scan_duration_ms": 150},
        )

        # Get classification (metadata only)
        classification = vault.get_classification("/data/patients.csv")
        print(classification.sources)  # Safe to display

        # Get sensitive spans (requires vault)
        entry = vault.get_vault_entry(classification.sources[0].vault_entry_id)
        for span in entry.spans:
            print(span.text)  # Actual sensitive data
    """

    def __init__(
        self,
        user_id: str,
        dek: bytes,
        data_dir: Path | None = None,
    ):
        """
        Initialize vault for a user.

        Args:
            user_id: User's unique ID
            dek: Data Encryption Key (from authenticated session)
            data_dir: Base data directory (default: ~/.openlabels)
        """
        self._user_id = user_id
        self._dek = dek
        self._data_dir = Path(data_dir) if data_dir else Path.home() / ".openlabels"
        self._vault_dir = self._data_dir / "vaults" / user_id
        self._crypto: "CryptoProvider | None" = None

        # In-memory cache of vault entries (decrypted)
        self._entries_cache: dict[str, VaultEntry] | None = None

    def _get_crypto(self) -> "CryptoProvider":
        """Lazy load crypto provider."""
        if self._crypto is None:
            from openlabels.auth.crypto import CryptoProvider
            self._crypto = CryptoProvider()
        return self._crypto

    def _ensure_dirs(self) -> None:
        """Ensure vault directories exist."""
        self._vault_dir.mkdir(parents=True, exist_ok=True)
        (self._vault_dir / "classifications").mkdir(exist_ok=True)

    @property
    def _vault_file(self) -> Path:
        """Path to encrypted vault file."""
        return self._vault_dir / "vault.enc"

    @property
    def _index_file(self) -> Path:
        """Path to vault index."""
        return self._vault_dir / "index.json"

    def _load_index(self) -> dict[str, str]:
        """Load file_hash -> entry_id index."""
        if self._index_file.exists():
            return json.loads(self._index_file.read_text())
        return {}

    def _save_index(self, index: dict[str, str]) -> None:
        """Save index to disk."""
        self._ensure_dirs()
        self._index_file.write_text(json.dumps(index, indent=2))

    def _load_vault(self) -> dict[str, VaultEntry]:
        """Load and decrypt vault entries."""
        if self._entries_cache is not None:
            return self._entries_cache

        if not self._vault_file.exists():
            self._entries_cache = {}
            return self._entries_cache

        crypto = self._get_crypto()

        # Read encrypted data
        encrypted_data = self._vault_file.read_bytes()
        if len(encrypted_data) < 12:  # Minimum nonce size
            self._entries_cache = {}
            return self._entries_cache

        # Decrypt
        from openlabels.auth.crypto import EncryptedData
        encrypted = EncryptedData.from_bytes(encrypted_data)
        decrypted = crypto.decrypt(encrypted, self._dek)

        # Parse
        data = json.loads(decrypted.decode("utf-8"))
        self._entries_cache = {
            entry_id: VaultEntry.from_dict(entry_data)
            for entry_id, entry_data in data.items()
        }

        return self._entries_cache

    def _save_vault(self) -> None:
        """Encrypt and save vault entries."""
        if self._entries_cache is None:
            return

        self._ensure_dirs()
        crypto = self._get_crypto()

        # Serialize
        data = {
            entry_id: entry.to_dict()
            for entry_id, entry in self._entries_cache.items()
        }
        plaintext = json.dumps(data).encode("utf-8")

        # Encrypt
        encrypted = crypto.encrypt(plaintext, self._dek)

        # Write
        self._vault_file.write_bytes(encrypted.to_bytes())

    def _compute_file_hash(self, file_path: str, timestamp: datetime) -> str:
        """Compute a unique hash for a file scan."""
        content = f"{file_path}|{timestamp.isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _classification_file(self, file_path: str) -> Path:
        """Get classification file path for a file."""
        # Use hash of file path as filename
        path_hash = hashlib.sha256(file_path.encode()).hexdigest()[:16]
        return self._vault_dir / "classifications" / f"{path_hash}.json"

    def store_scan_result(
        self,
        file_path: str,
        spans: list[SensitiveSpan],
        source: str = "openlabels",
        metadata: dict | None = None,
    ) -> str:
        """
        Store scan results in the vault.

        Args:
            file_path: Path to the scanned file
            spans: Detected sensitive spans
            source: Classification source ("openlabels", "macie", etc.)
            metadata: Source-specific metadata

        Returns:
            Vault entry ID
        """
        from .audit import AuditLog

        timestamp = datetime.now(timezone.utc)
        file_hash = self._compute_file_hash(file_path, timestamp)
        entry_id = str(uuid.uuid4())

        # Create vault entry
        entry = VaultEntry(
            id=entry_id,
            file_hash=file_hash,
            file_path=file_path,
            scan_timestamp=timestamp,
            spans=spans,
        )
        entry.compute_entity_counts()

        # Store in vault
        entries = self._load_vault()
        entries[entry_id] = entry
        self._entries_cache = entries
        self._save_vault()

        # Update index
        index = self._load_index()
        index[file_hash] = entry_id
        self._save_index(index)

        # Create/update classification
        self._add_classification_source(
            file_path=file_path,
            file_hash=file_hash,
            source=source,
            findings=[
                Finding(entity_type=etype, count=count, confidence=None)
                for etype, count in entry.entity_counts.items()
            ],
            metadata=metadata or {},
            vault_entry_id=entry_id,
        )

        # Audit log
        audit = AuditLog(self._data_dir, self._get_crypto())
        audit.log(
            user_id=self._user_id,
            action=AuditAction.SCAN_STORE,
            details={
                "file_path": file_path,
                "file_hash": file_hash,
                "entry_id": entry_id,
                "entity_counts": entry.entity_counts,
            },
        )

        return entry_id

    def _add_classification_source(
        self,
        file_path: str,
        file_hash: str,
        source: str,
        findings: list[Finding],
        metadata: dict,
        vault_entry_id: str | None = None,
    ) -> None:
        """Add or update a classification source for a file."""
        self._ensure_dirs()

        classification = self.get_classification(file_path)
        if classification is None:
            # Use score/tier from metadata if provided
            classification = FileClassification(
                file_path=file_path,
                file_hash=file_hash,
                risk_score=metadata.get("score", 0),
                tier=metadata.get("tier", "UNKNOWN"),
                sources=[],
            )
        else:
            # Update score/tier if new scan provides them
            if "score" in metadata:
                classification.risk_score = max(classification.risk_score, metadata["score"])
            if "tier" in metadata and metadata["tier"] != "UNKNOWN":
                # Use the more severe tier
                tier_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1, "UNKNOWN": 0}
                if tier_order.get(metadata["tier"], 0) > tier_order.get(classification.tier, 0):
                    classification.tier = metadata["tier"]

        # Add new source
        new_source = ClassificationSource(
            provider=source,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            metadata=metadata,
            vault_entry_id=vault_entry_id,
        )
        classification.sources.append(new_source)

        # Save classification
        class_file = self._classification_file(file_path)
        class_file.write_text(json.dumps(classification.to_dict(), indent=2))

    def get_classification(self, file_path: str) -> FileClassification | None:
        """
        Get classification for a file (metadata only, no sensitive text).

        This is safe to display without vault unlock.

        Args:
            file_path: Path to the file

        Returns:
            FileClassification if exists, None otherwise
        """
        class_file = self._classification_file(file_path)
        if not class_file.exists():
            return None

        data = json.loads(class_file.read_text())
        return FileClassification.from_dict(data)

    def get_vault_entry(self, entry_id: str) -> VaultEntry | None:
        """
        Get a vault entry (includes sensitive text).

        Requires vault to be unlocked (i.e., have DEK).

        Args:
            entry_id: Vault entry ID

        Returns:
            VaultEntry if exists, None otherwise
        """
        from .audit import AuditLog

        entries = self._load_vault()
        entry = entries.get(entry_id)

        if entry:
            # Audit the access
            audit = AuditLog(self._data_dir, self._get_crypto())
            audit.log(
                user_id=self._user_id,
                action=AuditAction.SPAN_VIEW,
                details={
                    "entry_id": entry_id,
                    "file_path": entry.file_path,
                },
            )

        return entry

    def get_spans_for_file(self, file_path: str) -> list[SensitiveSpan]:
        """
        Get all sensitive spans for a file.

        Args:
            file_path: Path to the file

        Returns:
            List of SensitiveSpan objects (may be empty)
        """
        classification = self.get_classification(file_path)
        if classification is None:
            return []

        all_spans: list[SensitiveSpan] = []
        for source in classification.sources:
            if source.vault_entry_id:
                entry = self.get_vault_entry(source.vault_entry_id)
                if entry:
                    all_spans.extend(entry.spans)

        return all_spans

    def delete_entry(self, entry_id: str) -> bool:
        """
        Delete a vault entry.

        Args:
            entry_id: Vault entry ID

        Returns:
            True if deleted, False if not found
        """
        from .audit import AuditLog

        entries = self._load_vault()
        if entry_id not in entries:
            return False

        entry = entries[entry_id]
        del entries[entry_id]
        self._entries_cache = entries
        self._save_vault()

        # Update index
        index = self._load_index()
        index = {k: v for k, v in index.items() if v != entry_id}
        self._save_index(index)

        # Audit
        audit = AuditLog(self._data_dir, self._get_crypto())
        audit.log(
            user_id=self._user_id,
            action=AuditAction.SCAN_DELETE,
            details={
                "entry_id": entry_id,
                "file_path": entry.file_path,
            },
        )

        return True

    def list_entries(self) -> list[VaultEntry]:
        """List all vault entries for this user."""
        entries = self._load_vault()
        return list(entries.values())

    def list_classifications(self) -> list[FileClassification]:
        """List all file classifications for this user."""
        self._ensure_dirs()
        class_dir = self._vault_dir / "classifications"
        if not class_dir.exists():
            return []

        classifications = []
        for class_file in class_dir.glob("*.json"):
            try:
                data = json.loads(class_file.read_text())
                classifications.append(FileClassification.from_dict(data))
            except (json.JSONDecodeError, KeyError):
                continue

        return classifications

    def add_label(self, file_path: str, label: str) -> None:
        """
        Add a user label to a file.

        Args:
            file_path: Path to the file
            label: Label to add
        """
        classification = self.get_classification(file_path)
        if classification is None:
            # Create minimal classification for label
            path_hash = hashlib.sha256(file_path.encode()).hexdigest()[:16]
            classification = FileClassification(
                file_path=file_path,
                file_hash=path_hash,
                risk_score=0,
                tier="UNKNOWN",
                sources=[],
            )

        if label not in classification.labels:
            classification.labels.append(label)

        class_file = self._classification_file(file_path)
        self._ensure_dirs()
        class_file.write_text(json.dumps(classification.to_dict(), indent=2))

    def remove_label(self, file_path: str, label: str) -> None:
        """
        Remove a user label from a file.

        Args:
            file_path: Path to the file
            label: Label to remove
        """
        classification = self.get_classification(file_path)
        if classification and label in classification.labels:
            classification.labels.remove(label)
            class_file = self._classification_file(file_path)
            class_file.write_text(json.dumps(classification.to_dict(), indent=2))

    def clear(self) -> None:
        """Clear all vault data for this user."""
        import shutil

        if self._vault_dir.exists():
            shutil.rmtree(self._vault_dir)

        self._entries_cache = None

"""
Hash-chained audit logging.

Provides tamper-evident logging of vault access and operations.
Audit log is stored outside the vault, encrypted with admin key.
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from .models import AuditEntry, AuditAction

if TYPE_CHECKING:
    from openlabels.auth.crypto import CryptoProvider


class AuditLog:
    """
    Hash-chained audit log with admin encryption.

    Each entry contains a hash of the previous entry, forming an
    immutable chain. Tampering with any entry breaks the chain.

    The audit log is encrypted with the admin's key, making it
    accessible only to administrators.

    Storage:
        audit/
        ├── audit.enc           # Encrypted audit entries (symmetric)
        ├── chain_head.txt      # Hash of the latest entry (for verification)
        ├── admin_key.enc       # Audit symmetric key (encrypted with admin DEK)
        ├── queue_public.key    # Queue public key (plaintext, for sealing)
        ├── queue_private.enc   # Queue private key (encrypted with admin DEK)
        └── queue.enc           # Encrypted queued entries (sealed with public key)

    Example:
        audit = AuditLog(data_dir, crypto)

        # Log an action
        audit.log(
            user_id="user123",
            action=AuditAction.SPAN_VIEW,
            details={"file_path": "/data/patients.csv"},
        )

        # Admin: verify chain integrity
        is_valid = audit.verify_chain(admin_dek)

        # Admin: read audit log
        for entry in audit.read(admin_dek):
            print(f"{entry.timestamp}: {entry.action}")
    """

    def __init__(
        self,
        data_dir: Path,
        crypto: "CryptoProvider",
    ):
        """
        Initialize audit log.

        Args:
            data_dir: Base data directory
            crypto: Crypto provider
        """
        self._data_dir = Path(data_dir)
        self._audit_dir = self._data_dir / "audit"
        self._crypto = crypto

        # Admin key for audit encryption (set during admin setup)
        self._admin_audit_key: bytes | None = None

    def _ensure_dirs(self) -> None:
        """Ensure audit directory exists."""
        self._audit_dir.mkdir(parents=True, exist_ok=True)

    @property
    def _audit_file(self) -> Path:
        """Path to encrypted audit log."""
        return self._audit_dir / "audit.enc"

    @property
    def _chain_head_file(self) -> Path:
        """Path to chain head hash."""
        return self._audit_dir / "chain_head.txt"

    @property
    def _admin_key_file(self) -> Path:
        """Path to admin audit key."""
        return self._audit_dir / "admin_key.enc"

    @property
    def _queue_public_key_file(self) -> Path:
        """Path to queue public key (plaintext)."""
        return self._audit_dir / "queue_public.key"

    @property
    def _queue_private_key_file(self) -> Path:
        """Path to queue private key (encrypted with admin DEK)."""
        return self._audit_dir / "queue_private.enc"

    @property
    def _queue_file(self) -> Path:
        """Path to encrypted queue file."""
        return self._audit_dir / "queue.enc"

    def setup_admin_key(self, admin_dek: bytes) -> None:
        """
        Set up admin key for audit log encryption.

        Called during admin account creation. Generates:
        1. A symmetric key for audit log encryption
        2. An asymmetric keypair for queue encryption

        Args:
            admin_dek: Admin's data encryption key
        """
        self._ensure_dirs()

        # Generate dedicated audit encryption key (symmetric)
        audit_key = self._crypto.generate_key()

        # Encrypt with admin's DEK
        encrypted = self._crypto.encrypt(audit_key, admin_dek)
        self._admin_key_file.write_bytes(encrypted.to_bytes())

        self._admin_audit_key = audit_key

        # Generate queue keypair (asymmetric) for encrypted queuing
        private_key, public_key = self._crypto.generate_keypair()

        # Store public key in plaintext (anyone can encrypt to the queue)
        self._queue_public_key_file.write_bytes(public_key)

        # Store private key encrypted with admin's DEK (only admin can decrypt queue)
        encrypted_private = self._crypto.encrypt(private_key, admin_dek)
        self._queue_private_key_file.write_bytes(encrypted_private.to_bytes())

    def _get_audit_key(self, admin_dek: bytes) -> bytes:
        """Get the audit encryption key using admin's DEK."""
        if self._admin_audit_key is not None:
            return self._admin_audit_key

        if not self._admin_key_file.exists():
            raise RuntimeError("Audit log not initialized. Run setup_admin_key first.")

        from openlabels.auth.crypto import EncryptedData
        encrypted_data = self._admin_key_file.read_bytes()
        encrypted = EncryptedData.from_bytes(encrypted_data)
        self._admin_audit_key = self._crypto.decrypt(encrypted, admin_dek)

        return self._admin_audit_key

    def _get_queue_public_key(self) -> bytes | None:
        """Get the queue public key for encrypting queued entries."""
        if not self._queue_public_key_file.exists():
            return None
        return self._queue_public_key_file.read_bytes()

    def _get_queue_private_key(self, admin_dek: bytes) -> bytes:
        """Get the queue private key for decrypting queued entries."""
        if not self._queue_private_key_file.exists():
            raise RuntimeError("Queue keypair not initialized. Run setup_admin_key first.")

        from openlabels.auth.crypto import EncryptedData
        encrypted_data = self._queue_private_key_file.read_bytes()
        encrypted = EncryptedData.from_bytes(encrypted_data)
        return self._crypto.decrypt(encrypted, admin_dek)

    def _load_entries(self, admin_dek: bytes) -> list[AuditEntry]:
        """Load and decrypt audit entries."""
        if not self._audit_file.exists():
            return []

        audit_key = self._get_audit_key(admin_dek)

        from openlabels.auth.crypto import EncryptedData
        encrypted_data = self._audit_file.read_bytes()
        if len(encrypted_data) < 12:
            return []

        encrypted = EncryptedData.from_bytes(encrypted_data)
        decrypted = self._crypto.decrypt(encrypted, audit_key)

        data = json.loads(decrypted.decode("utf-8"))
        return [AuditEntry.from_dict(entry) for entry in data]

    def _save_entries(self, entries: list[AuditEntry], audit_key: bytes) -> None:
        """Encrypt and save audit entries."""
        self._ensure_dirs()

        data = [entry.to_dict() for entry in entries]
        plaintext = json.dumps(data).encode("utf-8")

        encrypted = self._crypto.encrypt(plaintext, audit_key)
        self._audit_file.write_bytes(encrypted.to_bytes())

        # Update chain head
        if entries:
            self._chain_head_file.write_text(entries[-1].entry_hash)

    def _get_chain_head(self) -> str:
        """Get the current chain head hash."""
        if self._chain_head_file.exists():
            return self._chain_head_file.read_text().strip()
        return ""

    def log(
        self,
        user_id: str,
        action: AuditAction,
        details: dict,
        admin_dek: bytes | None = None,
    ) -> AuditEntry:
        """
        Log an action to the audit trail.

        If admin_dek is not provided, the entry is queued and will be
        written when an admin next accesses the audit log. This allows
        logging from non-admin sessions.

        Args:
            user_id: ID of user performing action
            action: The action being logged
            details: Action-specific details
            admin_dek: Admin's DEK (optional, for immediate write)

        Returns:
            The created AuditEntry
        """
        # Get previous hash
        prev_hash = self._get_chain_head()

        # Create entry
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            details=details,
            prev_hash=prev_hash,
        )

        # Compute hash
        entry.entry_hash = entry.compute_hash()

        # If we have admin key, write immediately
        if admin_dek is not None:
            entries = self._load_entries(admin_dek)
            entries.append(entry)
            audit_key = self._get_audit_key(admin_dek)
            self._save_entries(entries, audit_key)
        else:
            # Queue for later write
            self._queue_entry(entry)

        return entry

    def _queue_entry(self, entry: AuditEntry) -> None:
        """Queue an entry for later write (when admin DEK available).

        Entries are encrypted with the queue public key (asymmetric encryption)
        so that only the admin can decrypt them when flushing the queue.
        """
        self._ensure_dirs()

        # Serialize entry
        entry_json = json.dumps(entry.to_dict()).encode("utf-8")

        # Try to encrypt with public key if available
        public_key = self._get_queue_public_key()
        if public_key is not None:
            # Seal the entry with asymmetric encryption
            sealed = self._crypto.seal(entry_json, public_key)

            # Append to encrypted queue (length-prefixed for parsing)
            with open(self._queue_file, "ab") as f:
                # Write 4-byte length prefix + sealed data
                f.write(len(sealed).to_bytes(4, "big") + sealed)
        else:
            # Fallback: no keypair yet (shouldn't happen after setup)
            # Write plaintext for backwards compatibility during migration
            queue_file = self._audit_dir / "queue.jsonl"
            with open(queue_file, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")

        # Update chain head (even for queued entries)
        self._chain_head_file.write_text(entry.entry_hash)

    def flush_queue(self, admin_dek: bytes) -> int:
        """
        Flush queued entries to the encrypted audit log.

        Called when admin logs in. Decrypts entries from the encrypted queue
        using the queue private key, then re-encrypts with the symmetric
        audit key.

        Args:
            admin_dek: Admin's DEK

        Returns:
            Number of entries flushed
        """
        queued = []

        # Try encrypted queue first (new format)
        if self._queue_file.exists():
            try:
                private_key = self._get_queue_private_key(admin_dek)

                with open(self._queue_file, "rb") as f:
                    data = f.read()

                # Parse length-prefixed sealed entries
                offset = 0
                while offset < len(data):
                    if offset + 4 > len(data):
                        break
                    length = int.from_bytes(data[offset:offset + 4], "big")
                    offset += 4
                    if offset + length > len(data):
                        break
                    sealed = data[offset:offset + length]
                    offset += length

                    # Unseal and parse entry
                    entry_json = self._crypto.unseal(sealed, private_key)
                    entry_dict = json.loads(entry_json.decode("utf-8"))
                    queued.append(AuditEntry.from_dict(entry_dict))

                # Remove encrypted queue
                self._queue_file.unlink()

            except Exception:
                pass  # Fall through to check legacy queue

        # Also check legacy plaintext queue (for backwards compatibility)
        legacy_queue = self._audit_dir / "queue.jsonl"
        if legacy_queue.exists():
            with open(legacy_queue, "r") as f:
                for line in f:
                    if line.strip():
                        queued.append(AuditEntry.from_dict(json.loads(line)))
            legacy_queue.unlink()

        if not queued:
            return 0

        # Load existing entries
        entries = self._load_entries(admin_dek)

        # Append queued entries
        entries.extend(queued)

        # Save with symmetric encryption
        audit_key = self._get_audit_key(admin_dek)
        self._save_entries(entries, audit_key)

        return len(queued)

    def read(
        self,
        admin_dek: bytes,
        limit: int | None = None,
        action_filter: AuditAction | None = None,
        user_filter: str | None = None,
    ) -> Iterator[AuditEntry]:
        """
        Read audit log entries (admin only).

        Args:
            admin_dek: Admin's DEK
            limit: Maximum entries to return (most recent first)
            action_filter: Filter by action type
            user_filter: Filter by user ID

        Yields:
            AuditEntry objects (most recent first)
        """
        # Flush any queued entries first
        self.flush_queue(admin_dek)

        entries = self._load_entries(admin_dek)

        # Apply filters
        if action_filter is not None:
            entries = [e for e in entries if e.action == action_filter]

        if user_filter is not None:
            entries = [e for e in entries if e.user_id == user_filter]

        # Return most recent first
        entries = list(reversed(entries))

        if limit is not None:
            entries = entries[:limit]

        yield from entries

    def verify_chain(self, admin_dek: bytes) -> tuple[bool, str]:
        """
        Verify the integrity of the audit chain.

        Args:
            admin_dek: Admin's DEK

        Returns:
            Tuple of (is_valid, error_message)
        """
        entries = self._load_entries(admin_dek)

        if not entries:
            return True, "No entries"

        prev_hash = ""
        for i, entry in enumerate(entries):
            # Check prev_hash links correctly
            if entry.prev_hash != prev_hash:
                return False, f"Entry {i} ({entry.id}): prev_hash mismatch"

            # Verify entry hash
            computed = entry.compute_hash()
            if entry.entry_hash != computed:
                return False, f"Entry {i} ({entry.id}): entry_hash mismatch"

            prev_hash = entry.entry_hash

        # Check chain head matches
        head = self._get_chain_head()
        if head and head != entries[-1].entry_hash:
            return False, "Chain head mismatch"

        return True, f"Valid chain with {len(entries)} entries"

    def get_stats(self, admin_dek: bytes) -> dict:
        """
        Get audit log statistics.

        Args:
            admin_dek: Admin's DEK

        Returns:
            Statistics dictionary
        """
        entries = self._load_entries(admin_dek)

        if not entries:
            return {"total_entries": 0}

        # Count by action
        action_counts: dict[str, int] = {}
        for entry in entries:
            action = entry.action.value
            action_counts[action] = action_counts.get(action, 0) + 1

        # Count by user
        user_counts: dict[str, int] = {}
        for entry in entries:
            user_counts[entry.user_id] = user_counts.get(entry.user_id, 0) + 1

        return {
            "total_entries": len(entries),
            "by_action": action_counts,
            "by_user": user_counts,
            "oldest": entries[0].timestamp.isoformat() if entries else None,
            "newest": entries[-1].timestamp.isoformat() if entries else None,
        }

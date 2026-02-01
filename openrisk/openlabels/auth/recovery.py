"""
Admin recovery key management.

Provides:
- Recovery key generation (multiple keys per admin)
- Recovery key storage (encrypted with the key itself)
- Account recovery using recovery key
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path

from .models import RecoveryKey, User, UserRole, AuthCredentials
from .crypto import CryptoProvider, EncryptedData


# Number of recovery keys to generate
NUM_RECOVERY_KEYS = 2


class RecoveryManager:
    """
    Manages admin recovery keys.

    Recovery keys allow admin account recovery if password is forgotten.
    Multiple keys are generated; each can be used independently.

    Storage:
        recovery/
        └── {admin_user_id}/
            └── recovery_keys.json  # List of RecoveryKey objects

    Example:
        recovery = RecoveryManager(Path("~/.openlabels/recovery"), crypto)

        # Generate recovery keys for admin
        keys = recovery.generate_keys(admin_user, admin_dek)
        # keys = ["ABCD-EFGH-...", "IJKL-MNOP-..."]
        # Display these to user - they must save them!

        # Later: recover account
        success = recovery.recover_admin("ABCD-EFGH-...", "new_password")
    """

    def __init__(self, recovery_dir: Path, crypto: CryptoProvider):
        """
        Initialize recovery manager.

        Args:
            recovery_dir: Directory for recovery data
            crypto: Crypto provider
        """
        self._recovery_dir = Path(recovery_dir)
        self._crypto = crypto

    def _user_recovery_dir(self, user_id: str) -> Path:
        """Get recovery directory for a user."""
        return self._recovery_dir / user_id

    def _recovery_keys_path(self, user_id: str) -> Path:
        """Get recovery keys file path."""
        return self._user_recovery_dir(user_id) / "recovery_keys.json"

    def generate_keys(
        self,
        user: User,
        dek: bytes,
        num_keys: int = NUM_RECOVERY_KEYS,
    ) -> list[str]:
        """
        Generate recovery keys for a user (typically admin).

        Each key independently encrypts the user's DEK, allowing
        account recovery with any single key.

        Args:
            user: The user to generate keys for
            dek: User's data encryption key
            num_keys: Number of recovery keys to generate

        Returns:
            List of recovery key strings (display to user!)
        """
        if user.role != UserRole.ADMIN:
            raise ValueError("Recovery keys are only for admin users")

        recovery_keys: list[str] = []
        stored_keys: list[RecoveryKey] = []

        for _ in range(num_keys):
            # Generate human-readable recovery key
            raw_key = self._crypto.generate_recovery_key()
            recovery_keys.append(raw_key)

            # Derive encryption key from recovery key
            derived_key = self._crypto.derive_key_from_recovery(raw_key)

            # Encrypt DEK with recovery-derived key
            encrypted_dek = self._crypto.encrypt(dek, derived_key)

            # Hash the recovery key for verification
            key_hash = hashlib.sha256(raw_key.encode()).digest()
            key_id = key_hash[:8].hex()  # First 8 bytes as ID

            stored_keys.append(RecoveryKey(
                key_id=key_id,
                key_hash=key_hash,
                dek_encrypted=encrypted_dek.ciphertext,
                dek_nonce=encrypted_dek.nonce,
            ))

        # Save recovery keys
        self._save_keys(user.id, stored_keys)

        return recovery_keys

    def _save_keys(self, user_id: str, keys: list[RecoveryKey]) -> None:
        """Save recovery keys to disk."""
        recovery_dir = self._user_recovery_dir(user_id)
        recovery_dir.mkdir(parents=True, exist_ok=True)

        data = [k.to_dict() for k in keys]
        self._recovery_keys_path(user_id).write_text(json.dumps(data, indent=2))

    def _load_keys(self, user_id: str) -> list[RecoveryKey]:
        """Load recovery keys from disk."""
        path = self._recovery_keys_path(user_id)
        if not path.exists():
            return []

        data = json.loads(path.read_text())
        return [RecoveryKey.from_dict(k) for k in data]

    def verify_key(self, user_id: str, recovery_key: str) -> bytes | None:
        """
        Verify a recovery key and return the decrypted DEK.

        Args:
            user_id: Admin user's ID
            recovery_key: The recovery key to verify

        Returns:
            Decrypted DEK if key is valid, None otherwise
        """
        stored_keys = self._load_keys(user_id)
        if not stored_keys:
            return None

        # Hash the provided key
        key_hash = hashlib.sha256(recovery_key.encode()).digest()

        # Find matching key
        for stored_key in stored_keys:
            if stored_key.key_hash == key_hash:
                if stored_key.used:
                    # Key already used - might want to allow or disallow
                    # For now, allow reuse
                    pass

                # Derive encryption key and decrypt DEK
                derived_key = self._crypto.derive_key_from_recovery(recovery_key)
                try:
                    encrypted_dek = EncryptedData(
                        ciphertext=stored_key.dek_encrypted,
                        nonce=stored_key.dek_nonce,
                    )
                    dek = self._crypto.decrypt(encrypted_dek, derived_key)
                    return dek
                except Exception:
                    # Decryption failed - key might be tampered
                    return None

        return None

    def recover_admin(
        self,
        user_id: str,
        recovery_key: str,
        new_password: str,
        users_manager: "UserManager",
    ) -> bool:
        """
        Recover admin account using recovery key.

        Sets a new password while preserving the existing DEK (and vault data).

        Args:
            user_id: Admin user's ID
            recovery_key: A valid recovery key
            new_password: New password to set
            users_manager: UserManager instance for credential updates

        Returns:
            True if recovery successful, False otherwise
        """
        # Verify recovery key and get DEK
        dek = self.verify_key(user_id, recovery_key)
        if dek is None:
            return False

        # Generate new salt and hash for new password
        new_salt = self._crypto.generate_salt()
        new_hash = self._crypto.hash_password(new_password, new_salt)

        # Encrypt DEK with new password
        new_kek = self._crypto.derive_key(new_password, new_salt)
        encrypted_dek = self._crypto.encrypt(dek, new_kek)

        # Update credentials
        new_credentials = AuthCredentials(
            user_id=user_id,
            password_hash=new_hash,
            salt=new_salt,
            dek_encrypted=encrypted_dek.ciphertext,
            dek_nonce=encrypted_dek.nonce,
        )

        users_manager.update_credentials(user_id, new_credentials)

        # Mark recovery key as used
        self._mark_key_used(user_id, recovery_key)

        # Re-generate recovery keys with new DEK encryption
        # This ensures old recovery keys still work (they encrypt same DEK)
        # But we should regenerate if security policy requires key rotation

        return True

    def _mark_key_used(self, user_id: str, recovery_key: str) -> None:
        """Mark a recovery key as used."""
        stored_keys = self._load_keys(user_id)
        key_hash = hashlib.sha256(recovery_key.encode()).digest()

        for stored_key in stored_keys:
            if stored_key.key_hash == key_hash:
                stored_key.used = True
                break

        self._save_keys(user_id, stored_keys)

    def regenerate_keys(
        self,
        user: User,
        dek: bytes,
    ) -> list[str]:
        """
        Regenerate recovery keys (invalidates old keys).

        Use after recovery to ensure old keys can't be reused,
        or periodically for security.

        Args:
            user: Admin user
            dek: User's DEK (from current session)

        Returns:
            New recovery keys
        """
        # Delete old keys
        recovery_dir = self._user_recovery_dir(user.id)
        if recovery_dir.exists():
            import shutil
            shutil.rmtree(recovery_dir)

        # Generate new keys
        return self.generate_keys(user, dek)

    def has_recovery_keys(self, user_id: str) -> bool:
        """Check if a user has recovery keys set up."""
        keys = self._load_keys(user_id)
        return len(keys) > 0

    def get_key_status(self, user_id: str) -> list[dict]:
        """
        Get status of recovery keys (without exposing the keys).

        Returns:
            List of {key_id, created_at, used} for each key
        """
        keys = self._load_keys(user_id)
        return [
            {
                "key_id": k.key_id,
                "created_at": k.created_at.isoformat(),
                "used": k.used,
            }
            for k in keys
        ]

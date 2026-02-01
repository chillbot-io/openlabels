"""Key management with KEK/DEK hierarchy."""

import base64
import logging
import secrets
from typing import Dict, Optional, Tuple

from .kdf import derive_key, SCRYPT_N_MAX
from .aes import AESCipher, CryptoError, _zero_bytes

logger = logging.getLogger(__name__)


class KeyManager:
    """
    KEK/DEK hierarchy for key rotation without re-encryption.

    - KEK (Key Encryption Key): Derived from key material, encrypts DEKs
    - DEK (Data Encryption Key): Random, encrypts actual PHI

    Key rotation: Generate new DEK, encrypt with KEK.
    Old data remains readable with old DEK (stored encrypted).

    MEMORY SECURITY NOTE:
    Keys exist in multiple memory locations due to Python's design:
    1. The bytearray we control (can be zeroed)
    2. The bytes copy passed to AESCipher (immutable, GC'd eventually)
    3. Internal state in cryptography library's AESGCM object

    We zero what we can via lock()/destroy(), but Python cannot guarantee
    all copies are cleared. For true secure memory, use the Rust backend.
    """

    def __init__(
        self,
        key_material: str,
        salt: bytes = None,
        memory_mb: int = 16,
        scrypt_n: int = None,  # Override n directly (for loading existing vaults)
    ):
        # Validate key material
        if not key_material or not key_material.strip():
            raise ValueError("Key material cannot be empty or whitespace-only")
        
        kek, self._salt, self._scrypt_n = derive_key(key_material, salt, memory_mb, scrypt_n)
        # Store KEK in mutable bytearray for zeroing
        self._kek = bytearray(kek)
        self._kek_cipher = AESCipher(bytes(self._kek))
        self._dek: Optional[bytearray] = None
        self._dek_cipher: Optional[AESCipher] = None
        self._encrypted_dek: Optional[bytes] = None

    @property
    def salt(self) -> bytes:
        return self._salt
    
    @property
    def scrypt_n(self) -> int:
        """Return the scrypt n parameter used for key derivation."""
        return self._scrypt_n

    def needs_kdf_upgrade(self, target_n: int = SCRYPT_N_MAX) -> bool:
        """
        Check if current KDF parameters are slower than target.
        
        Returns True if current n > target_n (meaning slower, needs upgrade).
        """
        return self._scrypt_n > target_n

    def upgrade_kdf(
        self,
        key_material: str,
        target_n: int = SCRYPT_N_MAX,
        memory_mb: int = 16,
    ) -> Tuple[bytes, bytes, int]:
        """
        Re-derive KEK with faster parameters and re-encrypt DEK.

        SECURITY: Only call after successful authentication (DEK must be loaded).
        The DEK (actual data key) is unchanged - only its encryption wrapper changes.

        This is a standard key re-wrapping operation used when upgrading
        password hashing parameters (similar to bcrypt/Argon2 upgrades).

        Args:
            key_material: Key material (must be valid - we just authenticated with it)
            target_n: Target scrypt n parameter (default: SCRYPT_N_MAX = 32768)
            memory_mb: Memory parameter for new KDF

        Returns:
            (new_salt, new_encrypted_dek, new_n) - store these in database

        Raises:
            CryptoError: If DEK not loaded (must authenticate first)
        """
        if self._dek is None:
            raise CryptoError("Cannot upgrade KDF: DEK not loaded. Authenticate first.")
        
        logger.info(f"Upgrading KDF parameters: n={self._scrypt_n} → {target_n}")
        
        # Derive new KEK with faster parameters (new random salt)
        new_kek, new_salt, new_n = derive_key(
            key_material, salt=None, memory_mb=memory_mb, scrypt_n=target_n
        )
        
        # Re-encrypt DEK with new KEK
        new_kek_cipher = AESCipher(new_kek)
        new_encrypted_dek = new_kek_cipher.encrypt(bytes(self._dek))
        
        # Zero old KEK material
        if self._kek is not None:
            _zero_bytes(self._kek)
        
        # Update internal state
        self._kek = bytearray(new_kek)
        self._kek_cipher = new_kek_cipher
        self._salt = new_salt
        self._scrypt_n = new_n
        self._encrypted_dek = new_encrypted_dek
        
        logger.info(f"KDF upgrade complete. New n={new_n}")
        
        return new_salt, new_encrypted_dek, new_n

    @property
    def is_unlocked(self) -> bool:
        return self._dek is not None

    def generate_dek(self) -> bytes:
        """Generate new DEK and encrypt with KEK."""
        self._dek = bytearray(secrets.token_bytes(32))
        self._dek_cipher = AESCipher(bytes(self._dek))
        self._encrypted_dek = self._kek_cipher.encrypt(bytes(self._dek))
        return self._encrypted_dek

    def load_dek(self, encrypted_dek: bytes) -> None:
        """Load existing DEK by decrypting with KEK."""
        self._encrypted_dek = encrypted_dek
        dek_bytes = self._kek_cipher.decrypt(encrypted_dek)
        self._dek = bytearray(dek_bytes)
        self._dek_cipher = AESCipher(bytes(self._dek))

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with DEK."""
        if self._dek_cipher is None:
            self.generate_dek()
        return self._dek_cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with DEK."""
        if self._dek_cipher is None:
            raise CryptoError("DEK not loaded - unlock session first")
        return self._dek_cipher.decrypt(ciphertext)

    def lock(self) -> None:
        """Clear DEK from memory. Requires key material to unlock again."""
        if self._dek is not None:
            _zero_bytes(self._dek)
            self._dek = None
        if self._dek_cipher is not None:
            self._dek_cipher.zero_key()
            self._dek_cipher = None
        # Keep _encrypted_dek so we can reload

    def destroy(self) -> None:
        """
        Destroy all key material (KEK and DEK).
        
        After calling this, the KeyManager cannot be used.
        Call this on session end or application exit.
        """
        self.lock()  # Clear DEK first
        if self._kek is not None:
            _zero_bytes(self._kek)
            self._kek = None
        if self._kek_cipher is not None:
            self._kek_cipher.zero_key()
            self._kek_cipher = None

    def get_encrypted_dek(self) -> Optional[bytes]:
        """Get encrypted DEK for storage (public accessor)."""
        return self._encrypted_dek

    def export_keys(self) -> Dict[str, str]:
        """Export encrypted DEK and salt for storage."""
        if self._encrypted_dek is None:
            self.generate_dek()
        return {
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "encrypted_dek": base64.b64encode(self._encrypted_dek).decode("ascii")
        }

    @classmethod
    def from_stored(
        cls,
        key_material: str,
        stored: Dict[str, str],
        memory_mb: int = 16,
        scrypt_n: int = None,  # Load with specific n (from stored keys)
    ) -> "KeyManager":
        """Restore KeyManager from stored keys."""
        salt = base64.b64decode(stored["salt"])
        km = cls(key_material, salt, memory_mb, scrypt_n)
        km.load_dek(base64.b64decode(stored["encrypted_dek"]))
        return km

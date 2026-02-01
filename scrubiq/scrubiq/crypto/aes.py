"""AES-256-GCM authenticated encryption."""

import secrets
import logging

logger = logging.getLogger(__name__)

NONCE_SIZE = 12
TAG_SIZE = 16


class CryptoError(Exception):
    """Cryptographic operation failed."""
    pass


def _zero_bytes(b: bytearray) -> None:
    """Overwrite bytearray with zeros (best-effort memory clearing)."""
    for i in range(len(b)):
        b[i] = 0


class AESCipher:
    """
    AES-256-GCM authenticated encryption.
    
    Ciphertext format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    
    L2 FIX: XOR fallback removed for security. If cryptography library
    is not installed, raises CryptoError. Install cryptography for production.
    """

    def __init__(self, key: bytes):
        """
        Initialize cipher with key.
        
        Args:
            key: 32-byte AES key
        
        Raises:
            CryptoError: If key wrong size or cryptography library not installed
        """
        if len(key) != 32:
            raise CryptoError(f"Key must be 32 bytes, got {len(key)}")
        
        # Store key in mutable bytearray for zeroing
        self._key = bytearray(key)
        self._aesgcm = None

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aesgcm = AESGCM(bytes(self._key))
        except ImportError:
            # No fallback - require cryptography library
            raise CryptoError(
                "cryptography library required for encryption. "
                "Install with: pip install cryptography"
            )

    def encrypt(self, plaintext: bytes, aad: bytes = None) -> bytes:
        """
        Encrypt plaintext with AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            aad: Additional authenticated data (optional)
        
        Returns:
            nonce || ciphertext || tag
        """
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes = None) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM.
        
        Args:
            ciphertext: nonce || ciphertext || tag
            aad: Additional authenticated data (must match encryption)
        
        Returns:
            Original plaintext
        
        Raises:
            CryptoError: If authentication fails or ciphertext malformed
        """
        if len(ciphertext) < NONCE_SIZE + TAG_SIZE:
            raise CryptoError("Ciphertext too short")

        nonce = ciphertext[:NONCE_SIZE]

        try:
            return self._aesgcm.decrypt(nonce, ciphertext[NONCE_SIZE:], aad)
        except Exception as e:
            raise CryptoError(f"Decryption failed: {e}")

    def zero_key(self) -> None:
        """
        Zero the key material (best-effort).
        
        WARNING: This zeros our copy of the key, but the AESGCM object from
        the cryptography library holds its own internal copy that we cannot
        access or zero. Python's garbage collector will eventually reclaim
        that memory, but timing is non-deterministic.
        
        For true secure memory handling, use the Rust/Tauri backend which
        can use mlock() and explicit zeroing.
        """
        _zero_bytes(self._key)
        self._aesgcm = None

    @property
    def is_secure(self) -> bool:
        """Check if using secure AES-GCM. Always True now (L2 FIX)."""
        return True  # XOR fallback removed

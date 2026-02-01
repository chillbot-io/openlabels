"""Tests for AES-256-GCM authenticated encryption.

These tests verify:
1. Correct encryption/decryption round-trip
2. Key validation
3. Ciphertext tampering detection
4. AAD (additional authenticated data) handling
5. Memory cleanup
"""

import secrets
import pytest

from scrubiq.crypto.aes import (
    AESCipher,
    CryptoError,
    NONCE_SIZE,
    TAG_SIZE,
    _zero_bytes,
)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def make_valid_key() -> bytes:
    """Generate a valid 32-byte key."""
    return secrets.token_bytes(32)


# =============================================================================
# ZERO BYTES TESTS
# =============================================================================

class TestZeroBytes:
    """Tests for _zero_bytes helper function."""

    def test_zeros_bytearray(self):
        """Zeros all bytes in bytearray."""
        data = bytearray(b"secret data here")
        _zero_bytes(data)
        assert all(b == 0 for b in data)

    def test_zeros_empty_bytearray(self):
        """Empty bytearray is no-op."""
        data = bytearray()
        _zero_bytes(data)
        assert len(data) == 0

    def test_preserves_length(self):
        """Preserves length of bytearray."""
        data = bytearray(b"12345")
        _zero_bytes(data)
        assert len(data) == 5


# =============================================================================
# AES CIPHER INITIALIZATION TESTS
# =============================================================================

class TestAESCipherInit:
    """Tests for AESCipher initialization."""

    def test_valid_32_byte_key(self):
        """Accepts 32-byte key."""
        key = make_valid_key()
        cipher = AESCipher(key)
        assert cipher.is_secure is True

    def test_rejects_short_key(self):
        """Rejects key shorter than 32 bytes."""
        with pytest.raises(CryptoError) as exc_info:
            AESCipher(b"too short")
        assert "32 bytes" in str(exc_info.value)

    def test_rejects_long_key(self):
        """Rejects key longer than 32 bytes."""
        with pytest.raises(CryptoError) as exc_info:
            AESCipher(secrets.token_bytes(64))
        assert "32 bytes" in str(exc_info.value)

    def test_rejects_empty_key(self):
        """Rejects empty key."""
        with pytest.raises(CryptoError) as exc_info:
            AESCipher(b"")
        assert "32 bytes" in str(exc_info.value)

    def test_is_secure_property(self):
        """is_secure returns True (XOR fallback removed)."""
        cipher = AESCipher(make_valid_key())
        assert cipher.is_secure is True


# =============================================================================
# ENCRYPTION TESTS
# =============================================================================

class TestAESEncrypt:
    """Tests for AESCipher.encrypt()."""

    def test_basic_encryption(self):
        """Basic encryption produces ciphertext."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Hello, World!"
        ciphertext = cipher.encrypt(plaintext)

        # Ciphertext should be longer due to nonce + tag
        assert len(ciphertext) >= len(plaintext) + NONCE_SIZE + TAG_SIZE

    def test_ciphertext_different_from_plaintext(self):
        """Ciphertext is different from plaintext."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Hello, World!"
        ciphertext = cipher.encrypt(plaintext)

        # Plaintext should not appear in ciphertext
        assert plaintext not in ciphertext

    def test_different_nonce_each_time(self):
        """Each encryption uses different nonce."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Same message"

        ct1 = cipher.encrypt(plaintext)
        ct2 = cipher.encrypt(plaintext)

        # Nonces should be different
        assert ct1[:NONCE_SIZE] != ct2[:NONCE_SIZE]
        # Full ciphertexts should be different
        assert ct1 != ct2

    def test_encrypt_empty_plaintext(self):
        """Can encrypt empty plaintext."""
        cipher = AESCipher(make_valid_key())
        ciphertext = cipher.encrypt(b"")

        # Should have nonce + tag even for empty plaintext
        assert len(ciphertext) >= NONCE_SIZE + TAG_SIZE

    def test_encrypt_large_plaintext(self):
        """Can encrypt large plaintext."""
        cipher = AESCipher(make_valid_key())
        plaintext = secrets.token_bytes(1024 * 1024)  # 1 MB
        ciphertext = cipher.encrypt(plaintext)

        assert len(ciphertext) > len(plaintext)

    def test_encrypt_with_aad(self):
        """Encryption with AAD succeeds."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Secret message"
        aad = b"metadata"

        ciphertext = cipher.encrypt(plaintext, aad=aad)
        assert len(ciphertext) >= NONCE_SIZE + TAG_SIZE

    def test_encrypt_unicode_as_bytes(self):
        """Can encrypt unicode encoded as bytes."""
        cipher = AESCipher(make_valid_key())
        plaintext = "Hello, 世界! 🌍".encode("utf-8")
        ciphertext = cipher.encrypt(plaintext)

        assert len(ciphertext) > len(plaintext)


# =============================================================================
# DECRYPTION TESTS
# =============================================================================

class TestAESDecrypt:
    """Tests for AESCipher.decrypt()."""

    def test_roundtrip_basic(self):
        """Basic encrypt-decrypt roundtrip."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Hello, World!"

        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_roundtrip_empty(self):
        """Roundtrip with empty plaintext."""
        cipher = AESCipher(make_valid_key())
        plaintext = b""

        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_roundtrip_large(self):
        """Roundtrip with large plaintext."""
        cipher = AESCipher(make_valid_key())
        plaintext = secrets.token_bytes(100_000)

        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_roundtrip_with_aad(self):
        """Roundtrip with AAD."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Secret message"
        aad = b"metadata"

        ciphertext = cipher.encrypt(plaintext, aad=aad)
        decrypted = cipher.decrypt(ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_aad_mismatch_fails(self):
        """Decryption fails if AAD doesn't match."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Secret message"

        ciphertext = cipher.encrypt(plaintext, aad=b"original aad")

        with pytest.raises(CryptoError):
            cipher.decrypt(ciphertext, aad=b"different aad")

    def test_missing_aad_fails(self):
        """Decryption fails if AAD was used but not provided."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Secret message"

        ciphertext = cipher.encrypt(plaintext, aad=b"some aad")

        with pytest.raises(CryptoError):
            cipher.decrypt(ciphertext)  # No AAD provided

    def test_ciphertext_too_short_fails(self):
        """Decryption fails for ciphertext shorter than nonce + tag."""
        cipher = AESCipher(make_valid_key())

        with pytest.raises(CryptoError) as exc_info:
            cipher.decrypt(b"too short")
        assert "too short" in str(exc_info.value).lower()

    def test_tampered_ciphertext_fails(self):
        """Decryption fails for tampered ciphertext."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Original message"

        ciphertext = bytearray(cipher.encrypt(plaintext))
        # Flip a bit in the middle of the ciphertext
        ciphertext[NONCE_SIZE + 5] ^= 0xFF

        with pytest.raises(CryptoError):
            cipher.decrypt(bytes(ciphertext))

    def test_tampered_nonce_fails(self):
        """Decryption fails for tampered nonce."""
        cipher = AESCipher(make_valid_key())
        plaintext = b"Original message"

        ciphertext = bytearray(cipher.encrypt(plaintext))
        # Flip a bit in the nonce
        ciphertext[5] ^= 0xFF

        with pytest.raises(CryptoError):
            cipher.decrypt(bytes(ciphertext))

    def test_wrong_key_fails(self):
        """Decryption fails with wrong key."""
        key1 = make_valid_key()
        key2 = make_valid_key()

        cipher1 = AESCipher(key1)
        cipher2 = AESCipher(key2)

        ciphertext = cipher1.encrypt(b"Secret message")

        with pytest.raises(CryptoError):
            cipher2.decrypt(ciphertext)


# =============================================================================
# MEMORY CLEANUP TESTS
# =============================================================================

class TestAESMemoryCleanup:
    """Tests for key zeroing and memory cleanup."""

    def test_zero_key_clears_internal_key(self):
        """zero_key() clears the internal key bytearray."""
        key = make_valid_key()
        cipher = AESCipher(key)

        cipher.zero_key()

        # Internal key should be zeroed
        assert all(b == 0 for b in cipher._key)

    def test_zero_key_clears_aesgcm(self):
        """zero_key() clears the AESGCM object."""
        cipher = AESCipher(make_valid_key())

        cipher.zero_key()

        assert cipher._aesgcm is None

    def test_after_zero_key_cannot_encrypt(self):
        """After zero_key(), encryption fails."""
        cipher = AESCipher(make_valid_key())

        cipher.zero_key()

        with pytest.raises((CryptoError, AttributeError, TypeError)):
            cipher.encrypt(b"test")


# =============================================================================
# CRYPTO ERROR TESTS
# =============================================================================

class TestCryptoError:
    """Tests for CryptoError exception."""

    def test_is_exception(self):
        """CryptoError is an Exception."""
        assert issubclass(CryptoError, Exception)

    def test_message(self):
        """CryptoError stores message."""
        error = CryptoError("test message")
        assert str(error) == "test message"

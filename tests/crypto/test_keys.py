"""Tests for KeyManager with KEK/DEK hierarchy.

These tests verify:
1. KeyManager initialization and key derivation
2. DEK generation and encryption
3. Encrypt/decrypt operations
4. Key locking and destruction
5. Export/import functionality
6. KDF upgrade capability
"""

import base64
import secrets
import pytest

from scrubiq.crypto.keys import KeyManager
from scrubiq.crypto.aes import CryptoError
from scrubiq.crypto.kdf import SCRYPT_N_MIN, SCRYPT_N_MAX, SCRYPT_N_LEGACY


# =============================================================================
# INITIALIZATION TESTS
# =============================================================================

class TestKeyManagerInit:
    """Tests for KeyManager initialization."""

    def test_basic_init(self):
        """Basic initialization succeeds."""
        km = KeyManager("test_password")
        assert km is not None

    def test_init_generates_salt(self):
        """Initialization generates salt."""
        km = KeyManager("test_password")
        assert km.salt is not None
        assert len(km.salt) == 16

    def test_init_with_provided_salt(self):
        """Can initialize with provided salt."""
        salt = secrets.token_bytes(16)
        km = KeyManager("test_password", salt=salt)
        assert km.salt == salt

    def test_init_tracks_scrypt_n(self):
        """Initialization tracks scrypt n parameter."""
        km = KeyManager("test_password")
        # Should be in valid range or 0 (PBKDF2)
        assert km.scrypt_n >= 0

    def test_init_with_explicit_n(self):
        """Can initialize with explicit scrypt_n."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_MIN)
        assert km.scrypt_n == SCRYPT_N_MIN

    def test_empty_key_material_rejected(self):
        """Empty key material is rejected."""
        with pytest.raises(ValueError):
            KeyManager("")

    def test_whitespace_only_key_material_rejected(self):
        """Whitespace-only key material is rejected."""
        with pytest.raises(ValueError):
            KeyManager("   \t\n  ")

    def test_not_unlocked_initially(self):
        """KeyManager is not unlocked initially (no DEK)."""
        km = KeyManager("test_password")
        assert km.is_unlocked is False


# =============================================================================
# DEK GENERATION TESTS
# =============================================================================

class TestDEKGeneration:
    """Tests for DEK (Data Encryption Key) generation."""

    def test_generate_dek(self):
        """generate_dek() creates and returns encrypted DEK."""
        km = KeyManager("test_password")
        encrypted_dek = km.generate_dek()

        assert encrypted_dek is not None
        assert len(encrypted_dek) > 32  # Encrypted, includes nonce + tag

    def test_generate_dek_unlocks(self):
        """generate_dek() unlocks the KeyManager."""
        km = KeyManager("test_password")
        assert km.is_unlocked is False

        km.generate_dek()

        assert km.is_unlocked is True

    def test_generate_dek_returns_same_encrypted_dek(self):
        """Generated encrypted DEK can be retrieved."""
        km = KeyManager("test_password")
        encrypted_dek = km.generate_dek()

        assert km.get_encrypted_dek() == encrypted_dek

    def test_generate_dek_different_each_time(self):
        """Each generate_dek() creates different DEK."""
        km1 = KeyManager("test_password")
        km2 = KeyManager("test_password")

        dek1 = km1.generate_dek()
        dek2 = km2.generate_dek()

        # Encrypted DEKs should be different (different random DEKs)
        assert dek1 != dek2


# =============================================================================
# DEK LOADING TESTS
# =============================================================================

class TestDEKLoading:
    """Tests for loading existing DEK."""

    def test_load_dek(self):
        """load_dek() decrypts and loads DEK."""
        km1 = KeyManager("test_password")
        encrypted_dek = km1.generate_dek()
        salt = km1.salt
        n = km1.scrypt_n

        # Create new KeyManager with same credentials
        km2 = KeyManager("test_password", salt=salt, scrypt_n=n)
        km2.load_dek(encrypted_dek)

        assert km2.is_unlocked is True

    def test_load_dek_wrong_key_fails(self):
        """load_dek() fails with wrong key material."""
        km1 = KeyManager("correct_password")
        encrypted_dek = km1.generate_dek()
        salt = km1.salt
        n = km1.scrypt_n

        # Create new KeyManager with wrong password
        km2 = KeyManager("wrong_password", salt=salt, scrypt_n=n)

        with pytest.raises(CryptoError):
            km2.load_dek(encrypted_dek)

    def test_load_dek_corrupted_fails(self):
        """load_dek() fails with corrupted encrypted DEK."""
        km = KeyManager("test_password")
        encrypted_dek = bytearray(km.generate_dek())

        # Corrupt the encrypted DEK
        encrypted_dek[10] ^= 0xFF

        km2 = KeyManager("test_password", salt=km.salt, scrypt_n=km.scrypt_n)

        with pytest.raises(CryptoError):
            km2.load_dek(bytes(encrypted_dek))


# =============================================================================
# ENCRYPT/DECRYPT TESTS
# =============================================================================

class TestEncryptDecrypt:
    """Tests for data encryption and decryption."""

    def test_encrypt_basic(self):
        """Basic encryption succeeds."""
        km = KeyManager("test_password")
        km.generate_dek()

        plaintext = b"Secret data"
        ciphertext = km.encrypt(plaintext)

        assert ciphertext is not None
        assert ciphertext != plaintext

    def test_decrypt_basic(self):
        """Basic decryption succeeds."""
        km = KeyManager("test_password")
        km.generate_dek()

        plaintext = b"Secret data"
        ciphertext = km.encrypt(plaintext)
        decrypted = km.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_roundtrip(self):
        """Encrypt-decrypt roundtrip preserves data."""
        km = KeyManager("test_password")
        km.generate_dek()

        test_data = [
            b"",
            b"Hello, World!",
            b"Unicode: \xc3\xa9\xc3\xa0\xc3\xb9",
            secrets.token_bytes(1000),
        ]

        for plaintext in test_data:
            ciphertext = km.encrypt(plaintext)
            decrypted = km.decrypt(ciphertext)
            assert decrypted == plaintext

    def test_encrypt_auto_generates_dek(self):
        """encrypt() auto-generates DEK if not present."""
        km = KeyManager("test_password")
        assert km.is_unlocked is False

        ciphertext = km.encrypt(b"test")

        assert km.is_unlocked is True
        assert ciphertext is not None

    def test_decrypt_without_dek_fails(self):
        """decrypt() fails if DEK not loaded."""
        km = KeyManager("test_password")
        # Don't generate DEK

        with pytest.raises(CryptoError):
            km.decrypt(b"some ciphertext")

    def test_decrypt_with_loaded_dek(self):
        """decrypt() works after loading DEK."""
        km1 = KeyManager("test_password")
        km1.generate_dek()
        ciphertext = km1.encrypt(b"Secret")
        encrypted_dek = km1.get_encrypted_dek()
        salt = km1.salt
        n = km1.scrypt_n

        # New KeyManager, load DEK
        km2 = KeyManager("test_password", salt=salt, scrypt_n=n)
        km2.load_dek(encrypted_dek)

        decrypted = km2.decrypt(ciphertext)
        assert decrypted == b"Secret"


# =============================================================================
# LOCK/DESTROY TESTS
# =============================================================================

class TestLockDestroy:
    """Tests for key locking and destruction."""

    def test_lock_clears_dek(self):
        """lock() clears DEK from memory."""
        km = KeyManager("test_password")
        km.generate_dek()
        assert km.is_unlocked is True

        km.lock()

        assert km.is_unlocked is False

    def test_lock_preserves_encrypted_dek(self):
        """lock() preserves encrypted DEK for reload."""
        km = KeyManager("test_password")
        encrypted_dek = km.generate_dek()

        km.lock()

        assert km.get_encrypted_dek() == encrypted_dek

    def test_can_reload_after_lock(self):
        """Can reload DEK after lock()."""
        km = KeyManager("test_password")
        km.generate_dek()
        encrypted_dek = km.get_encrypted_dek()

        km.lock()
        km.load_dek(encrypted_dek)

        assert km.is_unlocked is True

    def test_destroy_clears_all(self):
        """destroy() clears all key material."""
        km = KeyManager("test_password")
        km.generate_dek()

        km.destroy()

        assert km.is_unlocked is False
        assert km._kek is None
        assert km._kek_cipher is None


# =============================================================================
# EXPORT/IMPORT TESTS
# =============================================================================

class TestExportImport:
    """Tests for key export and import."""

    def test_export_keys(self):
        """export_keys() returns dict with salt and encrypted_dek."""
        km = KeyManager("test_password")
        km.generate_dek()

        exported = km.export_keys()

        assert "salt" in exported
        assert "encrypted_dek" in exported
        assert isinstance(exported["salt"], str)
        assert isinstance(exported["encrypted_dek"], str)

    def test_export_keys_base64_encoded(self):
        """Exported keys are base64 encoded."""
        km = KeyManager("test_password")
        km.generate_dek()

        exported = km.export_keys()

        # Should decode without error
        salt = base64.b64decode(exported["salt"])
        dek = base64.b64decode(exported["encrypted_dek"])

        assert len(salt) == 16
        assert len(dek) > 32

    def test_export_auto_generates_dek(self):
        """export_keys() auto-generates DEK if not present."""
        km = KeyManager("test_password")

        exported = km.export_keys()

        assert km.is_unlocked is True

    def test_from_stored(self):
        """from_stored() restores KeyManager from exported keys."""
        km1 = KeyManager("test_password")
        km1.generate_dek()
        exported = km1.export_keys()

        km2 = KeyManager.from_stored("test_password", exported)

        assert km2.is_unlocked is True

    def test_from_stored_can_decrypt(self):
        """KeyManager from_stored can decrypt data encrypted by original."""
        km1 = KeyManager("test_password")
        km1.generate_dek()
        ciphertext = km1.encrypt(b"Secret message")
        exported = km1.export_keys()

        km2 = KeyManager.from_stored("test_password", exported)
        decrypted = km2.decrypt(ciphertext)

        assert decrypted == b"Secret message"

    def test_from_stored_wrong_password_fails(self):
        """from_stored() fails with wrong password."""
        km1 = KeyManager("correct_password")
        km1.generate_dek()
        exported = km1.export_keys()

        with pytest.raises(CryptoError):
            KeyManager.from_stored("wrong_password", exported)


# =============================================================================
# KDF UPGRADE TESTS
# =============================================================================

class TestKDFUpgrade:
    """Tests for KDF parameter upgrade."""

    def test_needs_kdf_upgrade_legacy(self):
        """needs_kdf_upgrade() returns True for legacy n."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_LEGACY)
        assert km.needs_kdf_upgrade(SCRYPT_N_MAX) is True

    def test_needs_kdf_upgrade_current(self):
        """needs_kdf_upgrade() returns False for current n."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_MAX)
        assert km.needs_kdf_upgrade(SCRYPT_N_MAX) is False

    def test_upgrade_kdf_requires_dek(self):
        """upgrade_kdf() requires DEK to be loaded."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_LEGACY)
        # Don't load DEK

        with pytest.raises(CryptoError):
            km.upgrade_kdf("test_password")

    def test_upgrade_kdf_changes_n(self):
        """upgrade_kdf() changes scrypt n parameter."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_LEGACY)
        km.generate_dek()

        new_salt, new_encrypted_dek, new_n = km.upgrade_kdf("test_password")

        assert new_n == SCRYPT_N_MAX
        assert km.scrypt_n == SCRYPT_N_MAX

    def test_upgrade_kdf_generates_new_salt(self):
        """upgrade_kdf() generates new salt."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_LEGACY)
        km.generate_dek()
        old_salt = km.salt

        new_salt, _, _ = km.upgrade_kdf("test_password")

        assert new_salt != old_salt
        assert km.salt == new_salt

    def test_upgrade_kdf_preserves_dek_functionality(self):
        """After upgrade_kdf(), data encrypted before can still be decrypted."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_LEGACY)
        km.generate_dek()
        ciphertext = km.encrypt(b"Secret data")

        km.upgrade_kdf("test_password")

        # Should still be able to decrypt with upgraded key
        decrypted = km.decrypt(ciphertext)
        assert decrypted == b"Secret data"

    def test_upgrade_kdf_returns_storable_values(self):
        """upgrade_kdf() returns values that can be stored."""
        km = KeyManager("test_password", scrypt_n=SCRYPT_N_LEGACY)
        km.generate_dek()

        new_salt, new_encrypted_dek, new_n = km.upgrade_kdf("test_password")

        assert isinstance(new_salt, bytes)
        assert len(new_salt) == 16
        assert isinstance(new_encrypted_dek, bytes)
        assert len(new_encrypted_dek) > 32
        assert isinstance(new_n, int)


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for KeyManager."""

    def test_multiple_encrypt_operations(self):
        """Multiple encryptions produce different ciphertexts."""
        km = KeyManager("test_password")
        km.generate_dek()

        ct1 = km.encrypt(b"same data")
        ct2 = km.encrypt(b"same data")

        # Different nonces = different ciphertexts
        assert ct1 != ct2

    def test_encrypt_large_data(self):
        """Can encrypt large data."""
        km = KeyManager("test_password")
        km.generate_dek()

        large_data = secrets.token_bytes(1_000_000)  # 1 MB
        ciphertext = km.encrypt(large_data)
        decrypted = km.decrypt(ciphertext)

        assert decrypted == large_data

    def test_unicode_key_material(self):
        """Unicode key material is handled correctly."""
        km = KeyManager("пароль日本語🔐")
        km.generate_dek()

        ciphertext = km.encrypt(b"test")
        decrypted = km.decrypt(ciphertext)

        assert decrypted == b"test"

    def test_special_characters_key_material(self):
        """Special characters in key material are handled."""
        km = KeyManager("p@$$w0rd!#$%^&*()[]{}|;':\",./<>?`~")
        km.generate_dek()

        ciphertext = km.encrypt(b"test")
        decrypted = km.decrypt(ciphertext)

        assert decrypted == b"test"

    def test_very_long_key_material(self):
        """Very long key material is handled."""
        long_key = "x" * 10000
        km = KeyManager(long_key)
        km.generate_dek()

        ciphertext = km.encrypt(b"test")
        decrypted = km.decrypt(ciphertext)

        assert decrypted == b"test"

"""Tests for key derivation (Scrypt/PBKDF2).

These tests verify:
1. Key derivation produces correct output sizes
2. Salt generation and handling
3. Deterministic derivation with same inputs
4. Different outputs with different salts
5. Parameter bounds (n values)
"""

import secrets
import pytest

from scrubiq.crypto.kdf import (
    derive_key,
    SALT_SIZE,
    KEY_SIZE,
    SCRYPT_N_MIN,
    SCRYPT_N_MAX,
    SCRYPT_N_LEGACY,
    PBKDF2_ITERATIONS,
)


# =============================================================================
# BASIC DERIVATION TESTS
# =============================================================================

class TestDeriveKeyBasic:
    """Basic key derivation tests."""

    def test_returns_tuple(self):
        """derive_key returns (key, salt, n) tuple."""
        result = derive_key("password123")
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_key_is_correct_size(self):
        """Derived key is KEY_SIZE bytes (32)."""
        key, salt, n = derive_key("password123")
        assert len(key) == KEY_SIZE
        assert len(key) == 32

    def test_salt_is_correct_size(self):
        """Generated salt is SALT_SIZE bytes (16)."""
        key, salt, n = derive_key("password123")
        assert len(salt) == SALT_SIZE
        assert len(salt) == 16

    def test_n_is_positive(self):
        """Scrypt n parameter is positive (or 0 for PBKDF2)."""
        key, salt, n = derive_key("password123")
        assert n >= 0

    def test_n_in_expected_range(self):
        """Scrypt n is in expected range for new derivations."""
        key, salt, n = derive_key("password123")
        # Either PBKDF2 (n=0) or Scrypt in valid range
        assert n == 0 or (SCRYPT_N_MIN <= n <= SCRYPT_N_MAX)


# =============================================================================
# SALT HANDLING TESTS
# =============================================================================

class TestSaltHandling:
    """Tests for salt generation and usage."""

    def test_generates_random_salt_when_none(self):
        """Generates random salt when not provided."""
        result1 = derive_key("password")
        result2 = derive_key("password")

        # Salts should be different
        assert result1[1] != result2[1]

    def test_uses_provided_salt(self):
        """Uses provided salt instead of generating."""
        salt = secrets.token_bytes(SALT_SIZE)
        key, returned_salt, n = derive_key("password", salt=salt)

        assert returned_salt == salt

    def test_same_salt_same_output(self):
        """Same password + salt produces same key."""
        salt = secrets.token_bytes(SALT_SIZE)

        key1, _, n1 = derive_key("password", salt=salt)
        key2, _, n2 = derive_key("password", salt=salt)

        assert key1 == key2
        assert n1 == n2

    def test_different_salt_different_output(self):
        """Different salt produces different key."""
        salt1 = secrets.token_bytes(SALT_SIZE)
        salt2 = secrets.token_bytes(SALT_SIZE)

        key1, _, _ = derive_key("password", salt=salt1)
        key2, _, _ = derive_key("password", salt=salt2)

        assert key1 != key2


# =============================================================================
# PASSWORD HANDLING TESTS
# =============================================================================

class TestPasswordHandling:
    """Tests for password/key material handling."""

    def test_different_passwords_different_keys(self):
        """Different passwords produce different keys."""
        salt = secrets.token_bytes(SALT_SIZE)

        key1, _, _ = derive_key("password1", salt=salt)
        key2, _, _ = derive_key("password2", salt=salt)

        assert key1 != key2

    def test_empty_password(self):
        """Empty password still produces valid key."""
        key, salt, n = derive_key("")
        assert len(key) == KEY_SIZE

    def test_unicode_password(self):
        """Unicode password is handled correctly."""
        key, salt, n = derive_key("пароль123日本語")
        assert len(key) == KEY_SIZE

    def test_long_password(self):
        """Long password is handled correctly."""
        long_password = "x" * 10000
        key, salt, n = derive_key(long_password)
        assert len(key) == KEY_SIZE


# =============================================================================
# SCRYPT N PARAMETER TESTS
# =============================================================================

class TestScryptNParameter:
    """Tests for scrypt n parameter handling."""

    def test_explicit_n_is_used(self):
        """Provided scrypt_n is used instead of calculated."""
        key, salt, n = derive_key("password", scrypt_n=SCRYPT_N_MIN)
        assert n == SCRYPT_N_MIN

    def test_explicit_n_max(self):
        """Can use SCRYPT_N_MAX."""
        key, salt, n = derive_key("password", scrypt_n=SCRYPT_N_MAX)
        assert n == SCRYPT_N_MAX

    def test_legacy_n_supported(self):
        """Legacy n value (for existing vaults) is supported."""
        key, salt, n = derive_key("password", scrypt_n=SCRYPT_N_LEGACY)
        assert n == SCRYPT_N_LEGACY

    def test_memory_mb_affects_n(self):
        """Different memory_mb values can affect n."""
        # Lower memory target
        key1, salt1, n1 = derive_key("password", memory_mb=8)
        # Higher memory target
        key2, salt2, n2 = derive_key("password", memory_mb=32)

        # Both should be clamped to valid range
        assert SCRYPT_N_MIN <= n1 <= SCRYPT_N_MAX
        assert SCRYPT_N_MIN <= n2 <= SCRYPT_N_MAX


# =============================================================================
# DETERMINISM TESTS
# =============================================================================

class TestDeterminism:
    """Tests for deterministic key derivation."""

    def test_deterministic_with_same_inputs(self):
        """Same inputs always produce same key."""
        salt = secrets.token_bytes(SALT_SIZE)
        password = "test_password"
        n = SCRYPT_N_MIN

        results = [
            derive_key(password, salt=salt, scrypt_n=n)
            for _ in range(5)
        ]

        # All keys should be identical
        first_key = results[0][0]
        assert all(r[0] == first_key for r in results)

    def test_key_bytes_are_deterministic(self):
        """Key bytes are deterministic for crypto operations."""
        salt = b"fixed_salt_value"  # 16 bytes
        password = "consistent_password"

        key1, _, _ = derive_key(password, salt=salt, scrypt_n=SCRYPT_N_MIN)
        key2, _, _ = derive_key(password, salt=salt, scrypt_n=SCRYPT_N_MIN)

        assert key1 == key2


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for module constants."""

    def test_salt_size(self):
        """SALT_SIZE is 16 bytes."""
        assert SALT_SIZE == 16

    def test_key_size(self):
        """KEY_SIZE is 32 bytes (256 bits)."""
        assert KEY_SIZE == 32

    def test_scrypt_n_min(self):
        """SCRYPT_N_MIN is 2^14 (16384)."""
        assert SCRYPT_N_MIN == 2 ** 14
        assert SCRYPT_N_MIN == 16384

    def test_scrypt_n_max(self):
        """SCRYPT_N_MAX is 2^15 (32768)."""
        assert SCRYPT_N_MAX == 2 ** 15
        assert SCRYPT_N_MAX == 32768

    def test_scrypt_n_legacy(self):
        """SCRYPT_N_LEGACY is 2^17 (131072)."""
        assert SCRYPT_N_LEGACY == 2 ** 17
        assert SCRYPT_N_LEGACY == 131072

    def test_pbkdf2_iterations(self):
        """PBKDF2_ITERATIONS is 600,000 per OWASP."""
        assert PBKDF2_ITERATIONS == 600_000


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for key derivation."""

    def test_whitespace_only_password(self):
        """Whitespace-only password is handled."""
        key, salt, n = derive_key("   \t\n  ")
        assert len(key) == KEY_SIZE

    def test_special_characters_password(self):
        """Special characters in password are handled."""
        key, salt, n = derive_key("p@$$w0rd!#$%^&*()")
        assert len(key) == KEY_SIZE

    def test_null_bytes_in_password(self):
        """Null bytes in password are handled."""
        key, salt, n = derive_key("pass\x00word")
        assert len(key) == KEY_SIZE

    def test_very_high_memory_mb(self):
        """Very high memory_mb is clamped."""
        key, salt, n = derive_key("password", memory_mb=1024)
        # Should be clamped to SCRYPT_N_MAX
        assert n <= SCRYPT_N_MAX or n == 0  # 0 = PBKDF2

    def test_very_low_memory_mb(self):
        """Very low memory_mb uses minimum n."""
        key, salt, n = derive_key("password", memory_mb=1)
        # Should use at least SCRYPT_N_MIN
        assert n >= SCRYPT_N_MIN or n == 0  # 0 = PBKDF2

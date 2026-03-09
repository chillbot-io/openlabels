"""
Tests for ScanTarget.config JSONB credential encryption.

Verifies that:
1. Credential fields are encrypted before storage
2. Decryption correctly restores plaintext values
3. Non-credential fields are not affected by encryption
4. Invalid/missing encryption key handling
5. Already-encrypted values are not double-encrypted
6. Legacy plaintext values are handled gracefully during decryption
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from openlabels.server.crypto import (
    CREDENTIAL_FIELD_NAMES,
    ENCRYPTED_PREFIX,
    decrypt_config_credentials,
    decrypt_value,
    encrypt_config_credentials,
    encrypt_value,
    is_encrypted,
    mask_config_credentials,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_settings(secret_key: str = "test-secret-key-for-unit-tests"):
    """Create a mock settings object with a secret_key."""
    settings = MagicMock()
    settings.server.secret_key = secret_key
    return settings


@pytest.fixture(autouse=True)
def _patch_settings():
    """Patch get_settings for all tests so Fernet key derivation works."""
    with patch(
        "openlabels.server.crypto.get_settings",
        return_value=_mock_settings(),
    ):
        yield


# ===========================================================================
# Test encrypt_value / decrypt_value
# ===========================================================================

class TestEncryptDecryptValue:
    """Low-level single-value encryption round-trip tests."""

    def test_round_trip(self):
        plaintext = "my-super-secret-password"
        encrypted = encrypt_value(plaintext)
        assert encrypted.startswith(ENCRYPTED_PREFIX)
        assert plaintext not in encrypted
        assert decrypt_value(encrypted) == plaintext

    def test_encrypted_value_has_prefix(self):
        encrypted = encrypt_value("secret123")
        assert encrypted.startswith(ENCRYPTED_PREFIX)

    def test_decrypt_non_encrypted_returns_as_is(self):
        """Plaintext values without the prefix pass through unchanged."""
        assert decrypt_value("just-a-bucket-name") == "just-a-bucket-name"

    def test_is_encrypted_detection(self):
        assert is_encrypted(f"{ENCRYPTED_PREFIX}sometoken") is True
        assert is_encrypted("plaintext") is False
        assert is_encrypted("") is False
        assert is_encrypted(123) is False
        assert is_encrypted(None) is False


# ===========================================================================
# Test encrypt_config_credentials
# ===========================================================================

class TestEncryptConfigCredentials:
    """Tests for selective field encryption in config JSONB dicts."""

    def test_credential_fields_are_encrypted(self):
        config = {
            "bucket": "my-bucket",
            "prefix": "data/",
            "region": "us-east-1",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }
        encrypted = encrypt_config_credentials(config)

        # Non-credential fields unchanged
        assert encrypted["bucket"] == "my-bucket"
        assert encrypted["prefix"] == "data/"
        assert encrypted["region"] == "us-east-1"

        # Credential fields encrypted
        assert encrypted["access_key"] != "AKIAIOSFODNN7EXAMPLE"
        assert encrypted["access_key"].startswith(ENCRYPTED_PREFIX)
        assert encrypted["secret_key"] != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert encrypted["secret_key"].startswith(ENCRYPTED_PREFIX)

    def test_empty_credential_fields_not_encrypted(self):
        config = {
            "bucket": "b",
            "access_key": "",
            "secret_key": "",
        }
        encrypted = encrypt_config_credentials(config)
        assert encrypted["access_key"] == ""
        assert encrypted["secret_key"] == ""

    def test_non_string_values_not_encrypted(self):
        config = {
            "bucket": "b",
            "access_key": 12345,  # not a string
        }
        encrypted = encrypt_config_credentials(config)
        assert encrypted["access_key"] == 12345

    def test_already_encrypted_values_not_double_encrypted(self):
        config = {
            "access_key": "AKIAEXAMPLE",
        }
        encrypted_once = encrypt_config_credentials(config)
        encrypted_twice = encrypt_config_credentials(encrypted_once)

        # Should be identical — the already-encrypted value is skipped
        assert encrypted_once["access_key"] == encrypted_twice["access_key"]

    def test_empty_config_returns_empty(self):
        assert encrypt_config_credentials({}) == {}

    def test_none_config_returns_none(self):
        assert encrypt_config_credentials(None) is None

    def test_all_known_credential_fields(self):
        """Every field in CREDENTIAL_FIELD_NAMES should be encrypted."""
        config = {name: f"secret-{name}" for name in CREDENTIAL_FIELD_NAMES}
        config["bucket"] = "not-a-secret"

        encrypted = encrypt_config_credentials(config)
        for name in CREDENTIAL_FIELD_NAMES:
            assert encrypted[name].startswith(ENCRYPTED_PREFIX), (
                f"Field '{name}' was not encrypted"
            )
        assert encrypted["bucket"] == "not-a-secret"

    def test_returns_new_dict(self):
        """Encryption must not mutate the original dict."""
        config = {"access_key": "secret", "bucket": "b"}
        encrypted = encrypt_config_credentials(config)
        assert config["access_key"] == "secret"  # unchanged
        assert encrypted is not config


# ===========================================================================
# Test decrypt_config_credentials
# ===========================================================================

class TestDecryptConfigCredentials:
    """Tests for selective field decryption."""

    def test_round_trip(self):
        original = {
            "bucket": "my-bucket",
            "region": "us-east-1",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "endpoint_url": "https://s3.example.com",
        }
        encrypted = encrypt_config_credentials(original)
        decrypted = decrypt_config_credentials(encrypted)

        assert decrypted == original

    def test_plaintext_values_pass_through(self):
        """Legacy configs without encryption should work unchanged."""
        legacy_config = {
            "bucket": "old-bucket",
            "access_key": "AKIAOLD",
            "secret_key": "old-secret",
        }
        # No encryption prefix, so decrypt should pass through
        decrypted = decrypt_config_credentials(legacy_config)
        assert decrypted == legacy_config

    def test_empty_config(self):
        assert decrypt_config_credentials({}) == {}

    def test_none_config(self):
        assert decrypt_config_credentials(None) is None

    def test_returns_new_dict(self):
        config = {"access_key": encrypt_value("secret")}
        decrypted = decrypt_config_credentials(config)
        assert decrypted is not config

    def test_invalid_token_returns_raw_value(self):
        """Corrupted tokens should log a warning and return the raw value."""
        config = {
            "access_key": f"{ENCRYPTED_PREFIX}this-is-not-a-valid-fernet-token",
            "bucket": "my-bucket",
        }
        decrypted = decrypt_config_credentials(config)
        # The invalid token should be returned as-is (not crash)
        assert decrypted["access_key"] == config["access_key"]
        assert decrypted["bucket"] == "my-bucket"


# ===========================================================================
# Test mask_config_credentials
# ===========================================================================

class TestMaskConfigCredentials:
    """Tests for API response masking."""

    def test_credential_fields_masked(self):
        config = {
            "bucket": "my-bucket",
            "access_key": "AKIAEXAMPLE",
            "secret_key": "wJalrXUtnFEMI/secret",
        }
        masked = mask_config_credentials(config)
        assert masked["bucket"] == "my-bucket"
        assert masked["access_key"] == "******"
        assert masked["secret_key"] == "******"

    def test_encrypted_values_also_masked(self):
        config = {
            "access_key": f"{ENCRYPTED_PREFIX}some-fernet-token",
        }
        masked = mask_config_credentials(config)
        assert masked["access_key"] == "******"

    def test_empty_credential_fields_not_masked(self):
        config = {"access_key": "", "bucket": "b"}
        masked = mask_config_credentials(config)
        assert masked["access_key"] == ""

    def test_empty_config(self):
        assert mask_config_credentials({}) == {}

    def test_none_config(self):
        assert mask_config_credentials(None) is None


# ===========================================================================
# Test missing/invalid encryption key
# ===========================================================================

class TestMissingEncryptionKey:
    """Tests for behavior when secret_key is not configured."""

    def test_encrypt_without_secret_key_logs_error(self):
        """When secret_key is empty, encrypt_config_credentials should
        log an error and fall back to storing plaintext."""
        with patch(
            "openlabels.server.crypto.get_settings",
            return_value=_mock_settings(secret_key=""),
        ):
            config = {"access_key": "AKIAEXAMPLE", "bucket": "b"}
            result = encrypt_config_credentials(config)
            # Falls back to plaintext when key is missing
            assert result["access_key"] == "AKIAEXAMPLE"
            assert result["bucket"] == "b"

    def test_decrypt_without_secret_key_returns_raw(self):
        """Decryption of a prefixed token without a valid key should
        return the raw token (not crash)."""
        # First encrypt with a valid key
        config = {"access_key": "secret"}
        encrypted = encrypt_config_credentials(config)

        # Now try to decrypt with a different key
        with patch(
            "openlabels.server.crypto.get_settings",
            return_value=_mock_settings(secret_key="different-key"),
        ):
            decrypted = decrypt_config_credentials(encrypted)
            # Should return the raw encrypted value (not crash)
            assert decrypted["access_key"].startswith(ENCRYPTED_PREFIX)

    def test_encrypt_value_raises_with_no_key(self):
        """encrypt_value should raise RuntimeError when secret_key is empty."""
        with patch(
            "openlabels.server.crypto.get_settings",
            return_value=_mock_settings(secret_key=""),
        ):
            with pytest.raises(RuntimeError, match="(?i)secret.key is not configured"):
                encrypt_value("test")


# ===========================================================================
# Test adapter integration
# ===========================================================================

class TestAdapterDecryption:
    """Tests that decrypt_config_credentials correctly prepares config for adapters.

    These tests verify the decryption step that _get_adapter performs
    internally, without importing the full scan module (which has heavy
    dependencies on adapters and settings that may not be available in
    the test environment).
    """

    def test_s3_config_decrypted_for_adapter(self):
        """S3 credential fields should be decrypted before adapter use."""
        config = {
            "bucket": "my-bucket",
            "prefix": "",
            "region": "us-east-1",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "endpoint_url": None,
        }
        encrypted_config = encrypt_config_credentials(config)

        # Verify the encrypted config has encrypted values
        assert encrypted_config["access_key"].startswith(ENCRYPTED_PREFIX)
        assert encrypted_config["secret_key"].startswith(ENCRYPTED_PREFIX)

        # Simulate what _get_adapter does internally
        decrypted = decrypt_config_credentials(encrypted_config)

        # Verify adapter would receive decrypted values
        assert decrypted["access_key"] == "AKIAIOSFODNN7EXAMPLE"
        assert decrypted["secret_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert decrypted["bucket"] == "my-bucket"
        assert decrypted["region"] == "us-east-1"

    def test_azure_config_decrypted_for_adapter(self):
        """Azure Blob credential fields should be decrypted before adapter use."""
        config = {
            "storage_account": "myaccount",
            "container": "mycontainer",
            "prefix": "",
            "connection_string": "DefaultEndpointsProtocol=https;AccountName=test",
            "account_key": "base64accountkey==",
            "sas_token": "sv=2020-08-04&ss=b&srt=sco",
        }
        encrypted_config = encrypt_config_credentials(config)

        assert encrypted_config["connection_string"].startswith(ENCRYPTED_PREFIX)
        assert encrypted_config["account_key"].startswith(ENCRYPTED_PREFIX)
        assert encrypted_config["sas_token"].startswith(ENCRYPTED_PREFIX)

        # Simulate what _get_adapter does internally
        decrypted = decrypt_config_credentials(encrypted_config)

        assert decrypted["connection_string"] == "DefaultEndpointsProtocol=https;AccountName=test"
        assert decrypted["account_key"] == "base64accountkey=="
        assert decrypted["sas_token"] == "sv=2020-08-04&ss=b&srt=sco"
        assert decrypted["storage_account"] == "myaccount"  # not a credential field


# ===========================================================================
# Test full lifecycle (encrypt -> store -> retrieve -> decrypt)
# ===========================================================================

class TestFullLifecycle:
    """End-to-end tests simulating the complete data flow."""

    def test_s3_config_lifecycle(self):
        """Simulate: user submits S3 config -> encrypt -> store -> read -> decrypt."""
        user_input = {
            "bucket": "data-lake",
            "prefix": "scans/",
            "region": "eu-west-1",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }

        # Step 1: Encrypt before storage
        stored = encrypt_config_credentials(user_input)
        assert stored["access_key"].startswith(ENCRYPTED_PREFIX)
        assert stored["secret_key"].startswith(ENCRYPTED_PREFIX)
        assert stored["bucket"] == "data-lake"  # not encrypted

        # Step 2: Verify plaintext secrets are NOT in the stored dict
        stored_json = str(stored)
        assert "AKIAIOSFODNN7EXAMPLE" not in stored_json
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in stored_json

        # Step 3: Decrypt when reading back
        decrypted = decrypt_config_credentials(stored)
        assert decrypted == user_input

        # Step 4: Mask for API response
        masked = mask_config_credentials(stored)
        assert masked["access_key"] == "******"
        assert masked["secret_key"] == "******"
        assert masked["bucket"] == "data-lake"

    def test_azure_blob_config_lifecycle(self):
        user_input = {
            "storage_account": "myaccount",
            "container": "docs",
            "prefix": "",
            "connection_string": "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123==;EndpointSuffix=core.windows.net",
            "account_key": "abc123==",
            "sas_token": "sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacuptfx",
        }

        stored = encrypt_config_credentials(user_input)
        assert "abc123==" not in str(stored)
        assert stored["storage_account"] == "myaccount"  # not a credential field

        decrypted = decrypt_config_credentials(stored)
        assert decrypted == user_input

    def test_filesystem_config_no_credentials(self):
        """Filesystem configs typically have no credential fields."""
        config = {
            "path": "/data/shares/finance",
            "service_account": None,
        }
        encrypted = encrypt_config_credentials(config)
        # Nothing should change
        assert encrypted == config

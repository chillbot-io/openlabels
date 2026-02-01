"""Tests for API key management service.

Tests APIKeyService: key generation, validation, revocation, and encryption derivation.
"""

import hashlib
import hmac
import os
import secrets
import tempfile
import time
from pathlib import Path

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database
from scrubiq.services.api_keys import (
    APIKeyService,
    APIKeyMetadata,
    _generate_key,
    _hash_key,
    _get_key_prefix,
    _derive_encryption_key,
    KEY_PREFIX,
    KEY_BYTES,
    KEY_PREFIX_LENGTH,
    BASE62,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def db_and_service():
    """Create a database and API key service."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.connect()

        service = APIKeyService(db)

        yield db, service

        db.close()


# =============================================================================
# KEY GENERATION TESTS
# =============================================================================

class TestKeyGeneration:
    """Tests for _generate_key function."""

    def test_key_starts_with_prefix(self):
        """Generated key starts with 'sk-' prefix."""
        key = _generate_key()
        assert key.startswith(KEY_PREFIX)

    def test_key_has_correct_format(self):
        """Generated key has correct format."""
        key = _generate_key()
        # Should be "sk-" + base62 encoded bytes
        assert len(key) >= 44  # sk- (3) + ~43 base62 chars

    def test_keys_are_unique(self):
        """Generated keys are unique."""
        keys = {_generate_key() for _ in range(100)}
        assert len(keys) == 100

    def test_key_contains_only_valid_chars(self):
        """Key contains only valid base62 characters after prefix."""
        key = _generate_key()
        payload = key[len(KEY_PREFIX):]
        for char in payload:
            assert char in BASE62


class TestKeyHashing:
    """Tests for _hash_key function."""

    def test_hash_is_sha256(self):
        """Hash uses SHA-256."""
        key = "sk-testkey123"
        expected = hashlib.sha256(key.encode()).hexdigest()
        assert _hash_key(key) == expected

    def test_hash_is_deterministic(self):
        """Same key produces same hash."""
        key = _generate_key()
        hash1 = _hash_key(key)
        hash2 = _hash_key(key)
        assert hash1 == hash2

    def test_different_keys_different_hashes(self):
        """Different keys produce different hashes."""
        key1 = _generate_key()
        key2 = _generate_key()
        assert _hash_key(key1) != _hash_key(key2)


class TestKeyPrefix:
    """Tests for _get_key_prefix function."""

    def test_prefix_length(self):
        """Prefix has correct length."""
        key = _generate_key()
        prefix = _get_key_prefix(key)
        assert len(prefix) == KEY_PREFIX_LENGTH

    def test_prefix_starts_with_sk(self):
        """Prefix starts with 'sk-'."""
        key = _generate_key()
        prefix = _get_key_prefix(key)
        assert prefix.startswith("sk-")


class TestEncryptionKeyDerivation:
    """Tests for _derive_encryption_key function."""

    def test_returns_32_bytes(self):
        """Derived key is 32 bytes (256 bits)."""
        salt = secrets.token_bytes(32)
        key = _derive_encryption_key("sk-testkey", salt)
        assert len(key) == 32

    def test_deterministic_with_same_inputs(self):
        """Same inputs produce same derived key."""
        salt = secrets.token_bytes(32)
        key1 = _derive_encryption_key("sk-testkey", salt)
        key2 = _derive_encryption_key("sk-testkey", salt)
        assert key1 == key2

    def test_different_salts_different_keys(self):
        """Different salts produce different keys."""
        salt1 = secrets.token_bytes(32)
        salt2 = secrets.token_bytes(32)
        key1 = _derive_encryption_key("sk-testkey", salt1)
        key2 = _derive_encryption_key("sk-testkey", salt2)
        assert key1 != key2

    def test_different_api_keys_different_derived_keys(self):
        """Different API keys produce different derived keys."""
        salt = secrets.token_bytes(32)
        key1 = _derive_encryption_key("sk-testkey1", salt)
        key2 = _derive_encryption_key("sk-testkey2", salt)
        assert key1 != key2

    def test_uses_hmac_sha256(self):
        """Uses HMAC-SHA256 for derivation."""
        salt = secrets.token_bytes(32)
        api_key = "sk-testkey"
        expected = hmac.new(salt, api_key.encode(), hashlib.sha256).digest()
        assert _derive_encryption_key(api_key, salt) == expected


# =============================================================================
# API KEY METADATA TESTS
# =============================================================================

class TestAPIKeyMetadata:
    """Tests for APIKeyMetadata dataclass."""

    def test_is_revoked_false_when_revoked_at_none(self):
        """is_revoked is False when revoked_at is None."""
        meta = APIKeyMetadata(
            id=1,
            key_prefix="sk-test",
            name="test",
            created_at=time.time(),
            last_used_at=None,
            rate_limit=1000,
            permissions=["redact"],
            revoked_at=None,
        )
        assert meta.is_revoked is False
        assert meta.is_active is True

    def test_is_revoked_true_when_revoked_at_set(self):
        """is_revoked is True when revoked_at is set."""
        meta = APIKeyMetadata(
            id=1,
            key_prefix="sk-test",
            name="test",
            created_at=time.time(),
            last_used_at=None,
            rate_limit=1000,
            permissions=["redact"],
            revoked_at=time.time(),
        )
        assert meta.is_revoked is True
        assert meta.is_active is False


# =============================================================================
# API KEY SERVICE CREATE TESTS
# =============================================================================

class TestAPIKeyServiceCreate:
    """Tests for APIKeyService.create_key method."""

    def test_create_key_returns_key_and_metadata(self, db_and_service):
        """create_key returns full key and metadata."""
        db, service = db_and_service

        key, meta = service.create_key(name="test-key")

        assert key.startswith(KEY_PREFIX)
        assert meta.name == "test-key"
        assert meta.key_prefix == key[:KEY_PREFIX_LENGTH]

    def test_create_key_with_default_permissions(self, db_and_service):
        """create_key has default permissions."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")

        assert "redact" in meta.permissions
        assert "restore" in meta.permissions
        assert "chat" in meta.permissions

    def test_create_key_with_custom_permissions(self, db_and_service):
        """create_key accepts custom permissions."""
        db, service = db_and_service

        key, meta = service.create_key(
            name="limited",
            permissions=["redact"]
        )

        assert meta.permissions == ["redact"]

    def test_create_key_with_rate_limit(self, db_and_service):
        """create_key accepts custom rate limit."""
        db, service = db_and_service

        key, meta = service.create_key(name="fast", rate_limit=5000)

        assert meta.rate_limit == 5000

    def test_create_key_sets_timestamps(self, db_and_service):
        """create_key sets created_at."""
        db, service = db_and_service

        before = time.time()
        key, meta = service.create_key(name="test")
        after = time.time()

        assert before <= meta.created_at <= after
        assert meta.last_used_at is None
        assert meta.revoked_at is None


# =============================================================================
# API KEY SERVICE VALIDATE TESTS
# =============================================================================

class TestAPIKeyServiceValidate:
    """Tests for APIKeyService.validate_key method."""

    def test_validate_valid_key(self, db_and_service):
        """validate_key returns metadata for valid key."""
        db, service = db_and_service

        key, created_meta = service.create_key(name="test")
        validated = service.validate_key(key)

        assert validated is not None
        assert validated.id == created_meta.id
        assert validated.name == "test"

    def test_validate_invalid_key_returns_none(self, db_and_service):
        """validate_key returns None for invalid key."""
        db, service = db_and_service

        result = service.validate_key("sk-invalidkey123")

        assert result is None

    def test_validate_empty_key_returns_none(self, db_and_service):
        """validate_key returns None for empty key."""
        db, service = db_and_service

        assert service.validate_key("") is None
        assert service.validate_key(None) is None

    def test_validate_wrong_prefix_returns_none(self, db_and_service):
        """validate_key returns None for wrong prefix."""
        db, service = db_and_service

        result = service.validate_key("pk-wrongprefix123")

        assert result is None

    def test_validate_revoked_key_returns_none(self, db_and_service):
        """validate_key returns None for revoked key."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")
        service.revoke_key(meta.key_prefix)

        result = service.validate_key(key)

        assert result is None

    def test_validate_updates_last_used(self, db_and_service):
        """validate_key updates last_used_at in database."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")
        assert meta.last_used_at is None

        time.sleep(0.01)
        # Validate will update last_used_at but return the previous value
        service.validate_key(key)
        db.conn.commit()  # Ensure update is committed

        # Fetch again to see the updated value
        fetched = service.get_key_by_prefix(meta.key_prefix)
        assert fetched.last_used_at is not None


# =============================================================================
# API KEY SERVICE REVOKE TESTS
# =============================================================================

class TestAPIKeyServiceRevoke:
    """Tests for APIKeyService.revoke_key method."""

    def test_revoke_key_by_prefix(self, db_and_service):
        """revoke_key revokes by prefix."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")

        result = service.revoke_key(meta.key_prefix)

        assert result is True

    def test_revoke_makes_key_invalid(self, db_and_service):
        """Revoked key cannot be validated."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")
        service.revoke_key(meta.key_prefix)

        assert service.validate_key(key) is None

    def test_revoke_nonexistent_returns_false(self, db_and_service):
        """revoke_key returns False for nonexistent prefix."""
        db, service = db_and_service

        result = service.revoke_key("sk-none")

        assert result is False

    def test_revoke_already_revoked_returns_false(self, db_and_service):
        """revoke_key returns False for already revoked key."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")
        service.revoke_key(meta.key_prefix)

        # Second revoke should return False
        result = service.revoke_key(meta.key_prefix)

        assert result is False

    def test_revoke_key_by_id(self, db_and_service):
        """revoke_key_by_id revokes by ID."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")

        result = service.revoke_key_by_id(meta.id)

        assert result is True
        assert service.validate_key(key) is None


# =============================================================================
# API KEY SERVICE LIST TESTS
# =============================================================================

class TestAPIKeyServiceList:
    """Tests for APIKeyService.list_keys method."""

    def test_list_empty(self, db_and_service):
        """list_keys returns empty list when no keys."""
        db, service = db_and_service

        keys = service.list_keys()

        assert keys == []

    def test_list_returns_all_active(self, db_and_service):
        """list_keys returns active keys."""
        db, service = db_and_service

        service.create_key(name="key1")
        service.create_key(name="key2")
        service.create_key(name="key3")

        keys = service.list_keys()

        assert len(keys) == 3
        names = {k.name for k in keys}
        assert names == {"key1", "key2", "key3"}

    def test_list_excludes_revoked_by_default(self, db_and_service):
        """list_keys excludes revoked keys by default."""
        db, service = db_and_service

        key1, meta1 = service.create_key(name="active")
        key2, meta2 = service.create_key(name="revoked")
        service.revoke_key(meta2.key_prefix)

        keys = service.list_keys()

        assert len(keys) == 1
        assert keys[0].name == "active"

    def test_list_includes_revoked_when_requested(self, db_and_service):
        """list_keys includes revoked when requested."""
        db, service = db_and_service

        key1, meta1 = service.create_key(name="active")
        key2, meta2 = service.create_key(name="revoked")
        service.revoke_key(meta2.key_prefix)

        keys = service.list_keys(include_revoked=True)

        assert len(keys) == 2

    def test_list_ordered_by_created_desc(self, db_and_service):
        """list_keys orders by created_at descending."""
        db, service = db_and_service

        service.create_key(name="first")
        time.sleep(0.01)
        service.create_key(name="second")
        time.sleep(0.01)
        service.create_key(name="third")

        keys = service.list_keys()

        assert keys[0].name == "third"
        assert keys[1].name == "second"
        assert keys[2].name == "first"


# =============================================================================
# API KEY SERVICE GET BY PREFIX TESTS
# =============================================================================

class TestAPIKeyServiceGetByPrefix:
    """Tests for APIKeyService.get_key_by_prefix method."""

    def test_get_existing_key(self, db_and_service):
        """get_key_by_prefix returns metadata."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")

        fetched = service.get_key_by_prefix(meta.key_prefix)

        assert fetched is not None
        assert fetched.name == "test"

    def test_get_nonexistent_returns_none(self, db_and_service):
        """get_key_by_prefix returns None for unknown prefix."""
        db, service = db_and_service

        result = service.get_key_by_prefix("sk-none")

        assert result is None


# =============================================================================
# API KEY SERVICE UPDATE TESTS
# =============================================================================

class TestAPIKeyServiceUpdate:
    """Tests for APIKeyService.update_key method."""

    def test_update_name(self, db_and_service):
        """update_key changes name."""
        db, service = db_and_service

        key, meta = service.create_key(name="old-name")

        result = service.update_key(meta.key_prefix, name="new-name")

        assert result is True
        fetched = service.get_key_by_prefix(meta.key_prefix)
        assert fetched.name == "new-name"

    def test_update_rate_limit(self, db_and_service):
        """update_key changes rate limit."""
        db, service = db_and_service

        key, meta = service.create_key(name="test", rate_limit=1000)

        service.update_key(meta.key_prefix, rate_limit=5000)

        fetched = service.get_key_by_prefix(meta.key_prefix)
        assert fetched.rate_limit == 5000

    def test_update_permissions(self, db_and_service):
        """update_key changes permissions."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")

        service.update_key(meta.key_prefix, permissions=["admin"])

        fetched = service.get_key_by_prefix(meta.key_prefix)
        assert fetched.permissions == ["admin"]

    def test_update_nonexistent_returns_false(self, db_and_service):
        """update_key returns False for nonexistent key."""
        db, service = db_and_service

        result = service.update_key("sk-none", name="test")

        assert result is False

    def test_update_revoked_returns_false(self, db_and_service):
        """update_key returns False for revoked key."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")
        service.revoke_key(meta.key_prefix)

        result = service.update_key(meta.key_prefix, name="new")

        assert result is False

    def test_update_no_changes_returns_false(self, db_and_service):
        """update_key returns False when no updates provided."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")

        result = service.update_key(meta.key_prefix)

        assert result is False


# =============================================================================
# ENCRYPTION KEY DERIVATION SERVICE TESTS
# =============================================================================

class TestAPIKeyServiceDeriveEncryption:
    """Tests for APIKeyService.derive_encryption_key method."""

    def test_derive_returns_32_bytes(self, db_and_service):
        """derive_encryption_key returns 32 bytes."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")
        encryption_key = service.derive_encryption_key(key)

        assert len(encryption_key) == 32

    def test_derive_deterministic(self, db_and_service):
        """Same API key produces same encryption key."""
        db, service = db_and_service

        key, meta = service.create_key(name="test")

        enc1 = service.derive_encryption_key(key)
        enc2 = service.derive_encryption_key(key)

        assert enc1 == enc2

    def test_derive_different_keys_different_encryption(self, db_and_service):
        """Different API keys produce different encryption keys."""
        db, service = db_and_service

        key1, _ = service.create_key(name="key1")
        key2, _ = service.create_key(name="key2")

        enc1 = service.derive_encryption_key(key1)
        enc2 = service.derive_encryption_key(key2)

        assert enc1 != enc2


# =============================================================================
# BOOTSTRAP KEY TESTS
# =============================================================================

class TestBootstrapKey:
    """Tests for bootstrap key creation."""

    def test_has_any_keys_false_initially(self, db_and_service):
        """has_any_keys returns False when no keys exist."""
        db, service = db_and_service

        assert service.has_any_keys() is False

    def test_has_any_keys_true_after_create(self, db_and_service):
        """has_any_keys returns True after key creation."""
        db, service = db_and_service

        service.create_key(name="test")

        assert service.has_any_keys() is True

    def test_create_bootstrap_key_when_empty(self, db_and_service):
        """create_bootstrap_key succeeds when no keys exist."""
        db, service = db_and_service

        result = service.create_bootstrap_key(name="bootstrap")

        assert result is not None
        key, meta = result
        assert key.startswith(KEY_PREFIX)
        assert "admin" in meta.permissions

    def test_create_bootstrap_key_fails_when_keys_exist(self, db_and_service):
        """create_bootstrap_key returns None when keys exist."""
        db, service = db_and_service

        service.create_key(name="existing")

        result = service.create_bootstrap_key(name="bootstrap")

        assert result is None

    def test_bootstrap_key_has_admin_permissions(self, db_and_service):
        """Bootstrap key has admin permissions by default."""
        db, service = db_and_service

        result = service.create_bootstrap_key(name="bootstrap")
        key, meta = result

        assert "admin" in meta.permissions

    def test_bootstrap_key_custom_permissions(self, db_and_service):
        """Bootstrap key can have custom permissions."""
        db, service = db_and_service

        result = service.create_bootstrap_key(
            name="bootstrap",
            permissions=["redact", "admin"]
        )
        key, meta = result

        assert meta.permissions == ["redact", "admin"]


# =============================================================================
# SALT MANAGEMENT TESTS
# =============================================================================

class TestSaltManagement:
    """Tests for encryption salt management."""

    def test_salt_created_on_init(self, db_and_service):
        """Salt is created on service initialization."""
        db, service = db_and_service

        row = db.fetchone(
            "SELECT value FROM settings WHERE key = 'encryption_salt'"
        )

        assert row is not None
        # Should be 64 hex chars (32 bytes)
        assert len(row["value"]) == 64

    def test_salt_persisted_across_instances(self, db_and_service):
        """Salt persists across service instances."""
        db, service = db_and_service

        key, _ = service.create_key(name="test")
        enc1 = service.derive_encryption_key(key)

        # Create new service instance with same db
        service2 = APIKeyService(db)
        enc2 = service2.derive_encryption_key(key)

        assert enc1 == enc2

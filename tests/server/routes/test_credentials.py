"""
Tests for session-scoped encrypted credential storage.

Tests focus on:
- Credential encryption round-trip
- Valid/invalid source type handling
- Session-based credential lifecycle (store, check, delete)
- Encryption key derivation
- Credential isolation per user and source type
"""

import pytest
from uuid import uuid4
from unittest.mock import patch, AsyncMock, MagicMock

from openlabels.server.routes.credentials import (
    _encrypt,
    _decrypt,
    _derive_fernet_key,
    _cred_key,
    VALID_SOURCE_TYPES,
)


def _mock_settings():
    """Create a mock settings object for credential tests."""
    mock = MagicMock()
    mock.server.secret_key = "test-secret-key-for-unit-tests"
    return mock


# ── Unit Tests ──────────────────────────────────────────────────────────


class TestEncryptDecrypt:
    """Tests for Fernet encryption/decryption helpers."""

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_encrypt_returns_string(self):
        token = _encrypt({"username": "admin", "password": "secret"})
        assert isinstance(token, str)
        assert len(token) > 0

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_decrypt_roundtrip(self):
        original = {"host": "smb.example.com", "username": "user", "password": "pass123"}
        token = _encrypt(original)
        result = _decrypt(token)
        assert result == original

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_decrypt_preserves_types(self):
        original = {"port": 445, "ssl": True, "path": "/share"}
        token = _encrypt(original)
        result = _decrypt(token)
        assert result["port"] == 445
        assert result["ssl"] is True

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_decrypt_invalid_token_raises(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _decrypt("not-a-valid-fernet-token")
        assert exc_info.value.status_code == 400

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_different_data_produces_different_tokens(self):
        t1 = _encrypt({"a": "1"})
        t2 = _encrypt({"a": "2"})
        assert t1 != t2


class TestDeriveFernetKey:
    """Tests for Fernet key derivation."""

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_returns_bytes(self):
        key = _derive_fernet_key()
        assert isinstance(key, bytes)

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_key_is_consistent(self):
        """Same secret should produce same key."""
        k1 = _derive_fernet_key()
        k2 = _derive_fernet_key()
        assert k1 == k2

    @patch("openlabels.server.routes.credentials.get_settings", _mock_settings)
    def test_key_is_valid_fernet_key(self):
        """Derived key should be usable by Fernet."""
        from cryptography.fernet import Fernet
        key = _derive_fernet_key()
        f = Fernet(key)
        # Should not raise
        token = f.encrypt(b"test")
        assert f.decrypt(token) == b"test"


class TestCredKey:
    """Tests for credential key construction."""

    def test_builds_correct_key(self):
        key = _cred_key("user-123", "smb")
        assert key == "cred:user-123:smb"

    def test_different_users_different_keys(self):
        k1 = _cred_key("user-1", "smb")
        k2 = _cred_key("user-2", "smb")
        assert k1 != k2

    def test_different_sources_different_keys(self):
        k1 = _cred_key("user-1", "smb")
        k2 = _cred_key("user-1", "nfs")
        assert k1 != k2


class TestValidSourceTypes:
    """Tests for source type validation."""

    def test_all_expected_types_present(self):
        expected = {"smb", "nfs", "sharepoint", "onedrive", "s3", "gcs", "azure_blob"}
        assert VALID_SOURCE_TYPES == expected

    def test_is_frozen(self):
        assert isinstance(VALID_SOURCE_TYPES, frozenset)


# ── API Endpoint Tests ──────────────────────────────────────────────────


class TestStoreCredentials:
    """Tests for POST /api/credentials endpoint."""

    async def test_rejects_invalid_source_type(self, test_client):
        response = await test_client.post(
            "/api/credentials",
            json={
                "source_type": "invalid_type",
                "credentials": {"host": "example.com"},
            },
        )
        assert response.status_code == 400
        assert "Invalid source type" in response.json()["detail"]

    async def test_rejects_without_session_cookie(self, test_client):
        """Should return 401 when no session cookie is present."""
        response = await test_client.post(
            "/api/credentials",
            json={
                "source_type": "smb",
                "credentials": {"host": "fs.local", "username": "admin"},
            },
        )
        assert response.status_code == 401

    async def test_stores_credentials_with_valid_session(self, test_client, test_db):
        """Should store credentials when session is valid."""
        from openlabels.server.session import SessionStore

        # Create a session in the DB
        session_store = SessionStore(test_db)
        session_id = "test-session-123"
        await session_store.set(
            session_id,
            {"provider": "dev"},
            ttl=3600,
            tenant_id="test-tenant",
            user_id="test-user",
        )
        await test_db.commit()

        response = await test_client.post(
            "/api/credentials",
            json={
                "source_type": "smb",
                "credentials": {"host": "fs.local", "username": "admin", "password": "secret"},
            },
            cookies={"openlabels_session": session_id},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["source_type"] == "smb"
        assert data["saved"] is True
        assert "host" in data["fields_stored"]
        assert "username" in data["fields_stored"]

    @pytest.mark.parametrize("source_type", list(VALID_SOURCE_TYPES))
    async def test_accepts_all_valid_source_types(self, test_client, test_db, source_type):
        """All valid source types should be accepted."""
        from openlabels.server.session import SessionStore

        session_store = SessionStore(test_db)
        session_id = f"test-session-{source_type}"
        await session_store.set(
            session_id,
            {"provider": "dev"},
            ttl=3600,
            tenant_id="test-tenant",
            user_id="test-user",
        )
        await test_db.commit()

        response = await test_client.post(
            "/api/credentials",
            json={
                "source_type": source_type,
                "credentials": {"key": "value"},
            },
            cookies={"openlabels_session": session_id},
        )
        assert response.status_code == 200
        assert response.json()["source_type"] == source_type


class TestCheckCredentials:
    """Tests for GET /api/credentials/{source_type} endpoint."""

    async def test_rejects_invalid_source_type(self, test_client):
        response = await test_client.get("/api/credentials/invalid_type")
        assert response.status_code == 400

    async def test_returns_false_when_no_credentials(self, test_client, test_db):
        from openlabels.server.session import SessionStore

        session_store = SessionStore(test_db)
        session_id = "test-check-session"
        await session_store.set(
            session_id,
            {"provider": "dev"},
            ttl=3600,
            tenant_id="test-tenant",
            user_id="test-user",
        )
        await test_db.commit()

        response = await test_client.get(
            "/api/credentials/smb",
            cookies={"openlabels_session": session_id},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["has_credentials"] is False
        assert data["fields_stored"] == []

    async def test_returns_true_after_store(self, test_client, test_db):
        """After storing credentials, check should return True."""
        from openlabels.server.session import SessionStore

        session_store = SessionStore(test_db)
        session_id = "test-roundtrip-session"
        await session_store.set(
            session_id,
            {"provider": "dev"},
            ttl=3600,
            tenant_id="test-tenant",
            user_id="test-user",
        )
        await test_db.commit()

        # Store
        await test_client.post(
            "/api/credentials",
            json={
                "source_type": "smb",
                "credentials": {"host": "fs.local", "user": "admin"},
            },
            cookies={"openlabels_session": session_id},
        )

        # Check
        response = await test_client.get(
            "/api/credentials/smb",
            cookies={"openlabels_session": session_id},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["has_credentials"] is True
        assert "host" in data["fields_stored"]


class TestDeleteCredentials:
    """Tests for DELETE /api/credentials/{source_type} endpoint."""

    async def test_rejects_invalid_source_type(self, test_client):
        response = await test_client.delete("/api/credentials/invalid_type")
        assert response.status_code == 400

    async def test_delete_returns_ok_even_when_none_stored(self, test_client, test_db):
        from openlabels.server.session import SessionStore

        session_store = SessionStore(test_db)
        session_id = "test-delete-session"
        await session_store.set(
            session_id,
            {"provider": "dev"},
            ttl=3600,
            tenant_id="test-tenant",
            user_id="test-user",
        )
        await test_db.commit()

        response = await test_client.delete(
            "/api/credentials/smb",
            cookies={"openlabels_session": session_id},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_delete_removes_credentials(self, test_client, test_db):
        """After deleting, check should return has_credentials=False."""
        from openlabels.server.session import SessionStore

        session_store = SessionStore(test_db)
        session_id = "test-delete-roundtrip"
        await session_store.set(
            session_id,
            {"provider": "dev"},
            ttl=3600,
            tenant_id="test-tenant",
            user_id="test-user",
        )
        await test_db.commit()

        # Store
        await test_client.post(
            "/api/credentials",
            json={
                "source_type": "s3",
                "credentials": {"access_key": "AKIA...", "secret_key": "xxx"},
            },
            cookies={"openlabels_session": session_id},
        )

        # Delete
        response = await test_client.delete(
            "/api/credentials/s3",
            cookies={"openlabels_session": session_id},
        )
        assert response.status_code == 200

        # Check should now return false
        check = await test_client.get(
            "/api/credentials/s3",
            cookies={"openlabels_session": session_id},
        )
        assert check.json()["has_credentials"] is False

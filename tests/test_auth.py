"""Tests for auth module."""

import os
import tempfile
from pathlib import Path

import pytest

from openlabels.auth import AuthManager, AuthenticationError
from openlabels.auth.crypto import CryptoProvider
from openlabels.auth.models import UserRole


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def auth(temp_dir):
    return AuthManager(data_dir=str(temp_dir))


@pytest.fixture
def crypto():
    return CryptoProvider()


class TestCryptoProvider:
    def test_generate_key(self, crypto):
        key = crypto.generate_key()
        assert len(key) == 32

    def test_generate_salt(self, crypto):
        salt = crypto.generate_salt()
        assert len(salt) == 16

    def test_derive_key_deterministic(self, crypto):
        salt = crypto.generate_salt()
        key1 = crypto.derive_key("password123", salt)
        key2 = crypto.derive_key("password123", salt)
        assert key1 == key2

    def test_derive_key_different_passwords(self, crypto):
        salt = crypto.generate_salt()
        key1 = crypto.derive_key("password1", salt)
        key2 = crypto.derive_key("password2", salt)
        assert key1 != key2

    def test_derive_key_different_salts(self, crypto):
        key1 = crypto.derive_key("password", crypto.generate_salt())
        key2 = crypto.derive_key("password", crypto.generate_salt())
        assert key1 != key2

    def test_encrypt_decrypt(self, crypto):
        key = crypto.generate_key()
        plaintext = b"sensitive data here"
        encrypted = crypto.encrypt(plaintext, key)
        decrypted = crypto.decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_encrypt_different_each_time(self, crypto):
        key = crypto.generate_key()
        plaintext = b"same data"
        enc1 = crypto.encrypt(plaintext, key)
        enc2 = crypto.encrypt(plaintext, key)
        assert enc1.ciphertext != enc2.ciphertext  # Different nonces

    def test_decrypt_wrong_key_fails(self, crypto):
        key1 = crypto.generate_key()
        key2 = crypto.generate_key()
        encrypted = crypto.encrypt(b"data", key1)
        with pytest.raises(Exception):
            crypto.decrypt(encrypted, key2)

    def test_hash_password(self, crypto):
        salt = crypto.generate_salt()
        pw_hash = crypto.hash_password("mypassword", salt)
        assert crypto.verify_password("mypassword", pw_hash, salt)
        assert not crypto.verify_password("wrongpassword", pw_hash, salt)

    def test_generate_recovery_key(self, crypto):
        key = crypto.generate_recovery_key()
        assert "-" in key
        parts = key.split("-")
        assert len(parts) == 8
        assert all(len(p) == 4 for p in parts)


class TestAuthManager:
    def test_needs_setup_true_initially(self, auth):
        assert auth.needs_setup()

    def test_setup_admin(self, auth):
        keys = auth.setup_admin("admin", "password123", email="a@b.com")
        assert not auth.needs_setup()
        assert len(keys) == 2  # 2 recovery keys
        # Verify recovery key format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
        for key in keys:
            parts = key.split("-")
            assert len(parts) == 8
            assert all(len(p) == 4 for p in parts)

    def test_setup_admin_twice_fails(self, auth):
        auth.setup_admin("admin", "password123")
        with pytest.raises(RuntimeError):
            auth.setup_admin("admin2", "password456")

    def test_login_success(self, auth):
        auth.setup_admin("admin", "password123")
        session = auth.login("admin", "password123")
        assert session.user.username == "admin"
        assert session.user.role == UserRole.ADMIN
        assert isinstance(session.token, str) and len(session.token) > 0

    def test_login_wrong_password(self, auth):
        auth.setup_admin("admin", "password123")
        with pytest.raises(AuthenticationError):
            auth.login("admin", "wrongpassword")

    def test_login_wrong_username(self, auth):
        auth.setup_admin("admin", "password123")
        with pytest.raises(AuthenticationError):
            auth.login("nobody", "password123")

    def test_verify_session(self, auth):
        auth.setup_admin("admin", "password123")
        session = auth.login("admin", "password123")
        verified = auth.verify_session(session.token)
        assert verified.user.username == "admin"

    def test_verify_invalid_token(self, auth):
        auth.setup_admin("admin", "password123")
        assert auth.verify_session("invalid-token") is None

    def test_logout_removes_active_session(self, auth):
        auth.setup_admin("admin", "password123")
        session = auth.login("admin", "password123")
        auth.logout(session.token)
        # Session is removed from active sessions but JWT may still be valid
        # The verify will recreate a limited session from JWT
        # But the important thing is the session is no longer in _active_sessions
        assert session.token not in auth._active_sessions

    def test_create_user(self, auth):
        auth.setup_admin("admin", "adminpass")
        admin_session = auth.login("admin", "adminpass")
        auth.create_user(admin_session, "user1", "userpass")

        user_session = auth.login("user1", "userpass")
        assert user_session.user.username == "user1"
        assert user_session.user.role == UserRole.USER

    def test_session_has_dek(self, auth):
        auth.setup_admin("admin", "password123")
        session = auth.login("admin", "password123")
        assert isinstance(session._dek, bytes)
        assert len(session._dek) == 32

    def test_recovery_key_works(self, auth):
        keys = auth.setup_admin("admin", "password123")
        recovery_key = keys[0]

        # Use recovery key to reset password
        result = auth.recover_with_key(recovery_key, "newpassword")
        assert result is True

        # Old password no longer works
        with pytest.raises(AuthenticationError):
            auth.login("admin", "password123")

        # New password works
        session = auth.login("admin", "newpassword")
        assert session.user.username == "admin"
        assert isinstance(session.token, str) and len(session.token) > 0

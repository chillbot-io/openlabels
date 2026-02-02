"""Tests for database session storage."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestSessionStore:
    """Tests for SessionStore class."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        db = AsyncMock()
        db.execute = AsyncMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        return db

    @pytest.fixture
    def session_store(self, mock_db):
        """Create SessionStore with mock db."""
        from openlabels.server.session import SessionStore
        return SessionStore(mock_db)

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self, session_store, mock_db):
        """Test getting a session that doesn't exist."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        result = await session_store.get("nonexistent-session-id")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_existing_session(self, session_store, mock_db):
        """Test getting an existing session."""
        mock_session = MagicMock()
        mock_session.data = {"user_id": "123", "access_token": "token"}

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_session
        mock_db.execute.return_value = mock_result

        result = await session_store.get("existing-session-id")

        assert result == {"user_id": "123", "access_token": "token"}

    @pytest.mark.asyncio
    async def test_set_new_session(self, session_store, mock_db):
        """Test creating a new session."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        await session_store.set(
            "new-session-id",
            {"access_token": "token123"},
            ttl=3600,
        )

        mock_db.add.assert_called_once()
        mock_db.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_updates_existing_session(self, session_store, mock_db):
        """Test updating an existing session."""
        mock_session = MagicMock()
        mock_session.data = {"old": "data"}

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_session
        mock_db.execute.return_value = mock_result

        await session_store.set(
            "existing-session-id",
            {"new": "data"},
            ttl=3600,
        )

        assert mock_session.data == {"new": "data"}
        mock_db.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_session(self, session_store, mock_db):
        """Test deleting a session."""
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.execute.return_value = mock_result

        result = await session_store.delete("session-to-delete")

        assert result is True
        mock_db.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_nonexistent_session(self, session_store, mock_db):
        """Test deleting a session that doesn't exist."""
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.execute.return_value = mock_result

        result = await session_store.delete("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, session_store, mock_db):
        """Test cleaning up expired sessions."""
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_db.execute.return_value = mock_result

        count = await session_store.cleanup_expired()

        assert count == 5


class TestPendingAuthStore:
    """Tests for PendingAuthStore class."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        db = AsyncMock()
        db.execute = AsyncMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        return db

    @pytest.fixture
    def pending_auth_store(self, mock_db):
        """Create PendingAuthStore with mock db."""
        from openlabels.server.session import PendingAuthStore
        return PendingAuthStore(mock_db)

    @pytest.mark.asyncio
    async def test_get_pending_auth(self, pending_auth_store, mock_db):
        """Test getting pending auth data."""
        mock_pending = MagicMock()
        mock_pending.redirect_uri = "http://app/callback"
        mock_pending.callback_url = "http://localhost:8000/auth/callback"
        mock_pending.created_at = datetime.utcnow()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_pending
        mock_db.execute.return_value = mock_result

        result = await pending_auth_store.get("state-token")

        assert result is not None
        assert result["redirect_uri"] == "http://app/callback"

    @pytest.mark.asyncio
    async def test_set_pending_auth(self, pending_auth_store, mock_db):
        """Test setting pending auth data."""
        await pending_auth_store.set(
            state="state-token",
            redirect_uri="http://app/callback",
            callback_url="http://localhost:8000/auth/callback",
        )

        mock_db.add.assert_called_once()
        mock_db.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_pending_auth(self, pending_auth_store, mock_db):
        """Test deleting pending auth data."""
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.execute.return_value = mock_result

        result = await pending_auth_store.delete("state-token")

        assert result is True

    def test_auth_timeout_constant(self):
        """Test auth timeout is reasonable."""
        from openlabels.server.session import PendingAuthStore

        # Should be between 5 and 30 minutes
        assert 5 <= PendingAuthStore.AUTH_TIMEOUT_MINUTES <= 30

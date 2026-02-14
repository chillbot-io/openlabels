"""
Database-backed session storage for OpenLabels.

Replaces in-memory session storage for production use:
- Sessions survive server restarts
- Sessions work across multiple workers
- Automatic cleanup of expired sessions
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.models import PendingAuth, Session

logger = logging.getLogger(__name__)


def _sanitize_id(value: str) -> str:
    """Strip null bytes and control characters from session/state IDs."""
    sanitized = value.replace("\x00", "").strip()
    if not sanitized:
        raise ValueError("Empty ID after sanitization")
    return sanitized


class SessionStore:
    """
    Database-backed session storage.

    Usage:
        async with get_session() as db:
            store = SessionStore(db)
            await store.set("session_id", {"access_token": "...", "claims": {...}}, ttl=3600)
            data = await store.get("session_id")
            await store.delete("session_id")
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, session_id: str) -> dict | None:
        """
        Get session data by ID.

        Returns None if session doesn't exist or is expired.
        """
        try:
            session_id = _sanitize_id(session_id)
        except ValueError:
            return None
        result = await self.db.execute(
            select(Session).where(
                Session.id == session_id,
                Session.expires_at > datetime.now(timezone.utc),
            )
        )
        session = result.scalar_one_or_none()

        if session:
            return session.data
        return None

    async def set(
        self,
        session_id: str,
        data: dict,
        ttl: int,
        tenant_id: str | None = None,
        user_id: str | None = None,
    ) -> None:
        """
        Create or update a session.

        Args:
            session_id: Unique session identifier
            data: Session data (tokens, claims, etc.)
            ttl: Time-to-live in seconds
            tenant_id: Optional tenant ID
            user_id: Optional user ID
        """
        session_id = _sanitize_id(session_id)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        # Check if session exists
        result = await self.db.execute(
            select(Session).where(Session.id == session_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing session
            existing.data = data
            existing.expires_at = expires_at
        else:
            # Create new session
            session = Session(
                id=session_id,
                data=data,
                expires_at=expires_at,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            self.db.add(session)

        await self.db.flush()

    async def delete(self, session_id: str) -> bool:
        """
        Delete a session.

        Returns True if session was deleted, False if it didn't exist.
        """
        try:
            session_id = _sanitize_id(session_id)
        except ValueError:
            return False
        result = await self.db.execute(
            delete(Session).where(Session.id == session_id)
        )
        await self.db.flush()
        return result.rowcount > 0

    async def cleanup_expired(self) -> int:
        """
        Remove expired sessions.

        Returns number of sessions removed.
        """
        result = await self.db.execute(
            delete(Session).where(Session.expires_at < datetime.now(timezone.utc))
        )
        await self.db.flush()

        count = result.rowcount
        if count > 0:
            logger.info(f"Cleaned up {count} expired sessions")
        return count

    async def delete_all_for_user(self, user_id: str) -> int:
        """
        Delete all sessions for a specific user.

        Used for logout-all functionality.
        Returns number of sessions deleted.
        """
        try:
            user_id = _sanitize_id(user_id)
        except ValueError:
            return 0
        result = await self.db.execute(
            delete(Session).where(Session.user_id == user_id)
        )
        await self.db.flush()
        count = result.rowcount
        if count > 0:
            logger.info(f"Deleted {count} sessions for user {user_id}")
        return count

    async def count_user_sessions(self, user_id: str) -> int:
        """Count active sessions for a user."""
        result = await self.db.execute(
            select(func.count(Session.id)).where(
                Session.user_id == user_id,
                Session.expires_at > datetime.now(timezone.utc),
            )
        )
        return result.scalar() or 0


class PendingAuthStore:
    """
    Database-backed PKCE state storage for OAuth flow.

    Entries are temporary and expire after 10 minutes.
    """

    AUTH_TIMEOUT_MINUTES = 10

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get(self, state: str) -> dict | None:
        """
        Get pending auth data by state.

        Returns None if not found or expired.
        """
        try:
            state = _sanitize_id(state)
        except ValueError:
            return None
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.AUTH_TIMEOUT_MINUTES)

        result = await self.db.execute(
            select(PendingAuth).where(
                PendingAuth.state == state,
                PendingAuth.created_at > cutoff,
            )
        )
        pending = result.scalar_one_or_none()

        if pending:
            return {
                "redirect_uri": pending.redirect_uri,
                "callback_url": pending.callback_url,
                "nonce": pending.nonce,
                "created_at": pending.created_at,
            }
        return None

    async def set(
        self,
        state: str,
        redirect_uri: str,
        callback_url: str,
        nonce: str | None = None,
    ) -> None:
        """
        Store pending auth state.
        """
        state = _sanitize_id(state)
        pending = PendingAuth(
            state=state,
            redirect_uri=redirect_uri,
            callback_url=callback_url,
            nonce=nonce,
        )
        self.db.add(pending)
        await self.db.flush()

    async def delete(self, state: str) -> bool:
        """
        Delete pending auth state (used after callback).

        Returns True if deleted, False if not found.
        """
        try:
            state = _sanitize_id(state)
        except ValueError:
            return False
        result = await self.db.execute(
            delete(PendingAuth).where(PendingAuth.state == state)
        )
        await self.db.flush()
        return result.rowcount > 0

    async def cleanup_expired(self) -> int:
        """
        Remove expired pending auth entries.

        Returns number of entries removed.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.AUTH_TIMEOUT_MINUTES)

        result = await self.db.execute(
            delete(PendingAuth).where(PendingAuth.created_at < cutoff)
        )
        await self.db.flush()

        count = result.rowcount
        if count > 0:
            logger.debug(f"Cleaned up {count} expired pending auth entries")
        return count

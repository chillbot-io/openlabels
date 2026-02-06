"""
PostgreSQL integration tests for session storage.

Tests actual database behavior for SessionStore and PendingAuthStore.
Requires PostgreSQL - set TEST_DATABASE_URL env var.

Run with:
    export TEST_DATABASE_URL="postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"
    pytest tests/test_session_store.py -v
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from openlabels.server.session import SessionStore, PendingAuthStore


@pytest.fixture
async def session_store(test_db):
    """Create SessionStore with real database session."""
    return SessionStore(test_db)


@pytest.fixture
async def pending_auth_store(test_db):
    """Create PendingAuthStore with real database session."""
    return PendingAuthStore(test_db)


@pytest.fixture
async def test_tenant_and_user(test_db):
    """Create actual tenant and user records for session tests.

    The Session model has foreign keys to tenants and users tables,
    so we need real records rather than random UUIDs.
    """
    from openlabels.server.models import Tenant, User

    # Create a test tenant
    tenant = Tenant(
        id=uuid4(),
        name=f"Session Test Tenant {uuid4().hex[:6]}",
        azure_tenant_id=f"session-test-{uuid4().hex[:8]}",
    )
    test_db.add(tenant)
    await test_db.flush()

    # Create a test user
    user = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email=f"session-test-{uuid4().hex[:6]}@localhost",
        name="Session Test User",
        role="admin",
    )
    test_db.add(user)
    await test_db.commit()

    return {"tenant_id": str(tenant.id), "user_id": str(user.id)}


@pytest.fixture
async def test_user_id(test_tenant_and_user):
    """Get the test user ID."""
    return test_tenant_and_user["user_id"]


@pytest.fixture
async def test_tenant_id(test_tenant_and_user):
    """Get the test tenant ID."""
    return test_tenant_and_user["tenant_id"]


@pytest.mark.integration
class TestSessionStoreGet:
    """Integration tests for SessionStore.get method."""

    async def test_get_nonexistent_session_returns_none(self, session_store):
        """Get for nonexistent session ID should return None."""
        result = await session_store.get("nonexistent-session-id")
        assert result is None

    async def test_get_valid_session_returns_data(self, session_store):
        """Get for valid session should return stored data."""
        session_id = f"test-session-{uuid4()}"
        session_data = {"access_token": "test-token", "user_id": "123"}

        await session_store.set(session_id, session_data, ttl=3600)
        result = await session_store.get(session_id)

        assert result == session_data
        assert result["access_token"] == "test-token"
        assert result["user_id"] == "123"

    async def test_get_preserves_nested_data(self, session_store):
        """Get should preserve complex nested data structures."""
        session_id = f"test-session-{uuid4()}"
        complex_data = {
            "access_token": "xyz",
            "claims": {
                "oid": "user-oid-123",
                "tid": "tenant-456",
                "roles": ["admin", "user"],
                "nested": {"deep": {"value": 42}}
            },
            "numbers": [1, 2, 3],
        }

        await session_store.set(session_id, complex_data, ttl=3600)
        result = await session_store.get(session_id)

        assert result["claims"]["roles"] == ["admin", "user"]
        assert result["claims"]["nested"]["deep"]["value"] == 42
        assert result["numbers"] == [1, 2, 3]

    async def test_get_empty_data_dict(self, session_store):
        """Get should handle empty data dict."""
        session_id = f"test-session-{uuid4()}"

        await session_store.set(session_id, {}, ttl=3600)
        result = await session_store.get(session_id)

        assert result == {}


@pytest.mark.integration
class TestSessionStoreExpiration:
    """Integration tests for session expiration."""

    async def test_expired_session_returns_none(self, session_store):
        """Expired session should return None."""
        from openlabels.server.models import Session

        session_id = f"test-expired-{uuid4()}"

        # Create session with TTL of 0 (immediately expired)
        await session_store.set(session_id, {"data": True}, ttl=0)

        # Wait a tiny bit to ensure it's past expiration
        import asyncio
        await asyncio.sleep(0.1)

        result = await session_store.get(session_id)
        assert result is None

    async def test_session_with_future_expiry_returns_data(self, session_store):
        """Session with future expiry should return data."""
        session_id = f"test-valid-{uuid4()}"

        await session_store.set(session_id, {"valid": True}, ttl=7200)  # 2 hours
        result = await session_store.get(session_id)

        assert result == {"valid": True}


@pytest.mark.integration
class TestSessionStoreSet:
    """Integration tests for SessionStore.set method."""

    async def test_set_creates_new_session(self, session_store):
        """Set should create new session when ID doesn't exist."""
        session_id = f"test-new-{uuid4()}"

        await session_store.set(session_id, {"new": True}, ttl=3600)
        result = await session_store.get(session_id)

        assert result == {"new": True}

    async def test_set_updates_existing_session(self, session_store):
        """Set should update existing session data."""
        session_id = f"test-update-{uuid4()}"

        # Create initial session
        await session_store.set(session_id, {"version": 1}, ttl=3600)

        # Update session
        await session_store.set(session_id, {"version": 2, "updated": True}, ttl=3600)

        result = await session_store.get(session_id)
        assert result == {"version": 2, "updated": True}

    async def test_set_with_tenant_and_user(self, session_store, test_tenant_id, test_user_id):
        """Set should store tenant_id and user_id."""
        session_id = f"test-with-ids-{uuid4()}"

        await session_store.set(
            session_id,
            {"token": "abc"},
            ttl=3600,
            tenant_id=test_tenant_id,
            user_id=test_user_id,
        )

        result = await session_store.get(session_id)
        assert result == {"token": "abc"}

    async def test_set_extends_expiry_on_update(self, session_store):
        """Updating a session should extend its expiry."""
        session_id = f"test-extend-{uuid4()}"

        # Create with short TTL
        await session_store.set(session_id, {"data": True}, ttl=60)

        # Update with longer TTL
        await session_store.set(session_id, {"data": True, "extended": True}, ttl=7200)

        # Session should still be valid
        result = await session_store.get(session_id)
        assert result["extended"] is True


@pytest.mark.integration
class TestSessionStoreDelete:
    """Integration tests for SessionStore.delete method."""

    async def test_delete_existing_session_returns_true(self, session_store):
        """Delete existing session should return True."""
        session_id = f"test-delete-{uuid4()}"
        await session_store.set(session_id, {"data": True}, ttl=3600)

        result = await session_store.delete(session_id)

        assert result is True

    async def test_delete_nonexistent_session_returns_false(self, session_store):
        """Delete nonexistent session should return False."""
        result = await session_store.delete("nonexistent-delete-test")
        assert result is False

    async def test_delete_makes_session_unretrievable(self, session_store):
        """Deleted session should not be retrievable."""
        session_id = f"test-delete-verify-{uuid4()}"
        await session_store.set(session_id, {"data": True}, ttl=3600)

        await session_store.delete(session_id)
        result = await session_store.get(session_id)

        assert result is None


@pytest.mark.integration
class TestSessionStoreCleanup:
    """Integration tests for SessionStore.cleanup_expired method."""

    async def test_cleanup_removes_expired_sessions(self, session_store):
        """Cleanup should remove expired sessions."""
        # Create some expired sessions
        for i in range(3):
            session_id = f"test-expired-cleanup-{uuid4()}"
            await session_store.set(session_id, {"index": i}, ttl=0)

        import asyncio
        await asyncio.sleep(0.1)

        count = await session_store.cleanup_expired()

        assert count >= 3  # At least the 3 we created

    async def test_cleanup_preserves_valid_sessions(self, session_store):
        """Cleanup should not remove valid sessions."""
        valid_id = f"test-valid-cleanup-{uuid4()}"
        await session_store.set(valid_id, {"valid": True}, ttl=3600)

        # Create and clean expired sessions
        for i in range(2):
            expired_id = f"test-expired-cleanup-{uuid4()}"
            await session_store.set(expired_id, {"index": i}, ttl=0)

        import asyncio
        await asyncio.sleep(0.1)

        await session_store.cleanup_expired()

        # Valid session should still exist
        result = await session_store.get(valid_id)
        assert result == {"valid": True}


@pytest.mark.integration
class TestSessionStoreDeleteAllForUser:
    """Integration tests for SessionStore.delete_all_for_user method."""

    async def test_delete_all_removes_user_sessions(self, session_store, test_user_id):
        """delete_all_for_user should remove all sessions for that user."""
        # Create multiple sessions for the user
        for i in range(3):
            session_id = f"test-user-session-{uuid4()}"
            await session_store.set(
                session_id,
                {"index": i},
                ttl=3600,
                user_id=test_user_id,
            )

        count = await session_store.delete_all_for_user(test_user_id)

        assert count == 3

    async def test_delete_all_preserves_other_user_sessions(self, session_store, test_db):
        """delete_all_for_user should not affect other users' sessions."""
        from openlabels.server.models import Tenant, User

        # Create a tenant for the test users
        tenant = Tenant(
            id=uuid4(),
            name=f"Delete Test Tenant {uuid4().hex[:6]}",
            azure_tenant_id=f"delete-test-{uuid4().hex[:8]}",
        )
        test_db.add(tenant)
        await test_db.flush()

        # Create two real users (foreign key constraint requires real users)
        user1_obj = User(
            id=uuid4(),
            tenant_id=tenant.id,
            email=f"user1-{uuid4().hex[:6]}@localhost",
            name="User 1",
            role="admin",
        )
        user2_obj = User(
            id=uuid4(),
            tenant_id=tenant.id,
            email=f"user2-{uuid4().hex[:6]}@localhost",
            name="User 2",
            role="admin",
        )
        test_db.add(user1_obj)
        test_db.add(user2_obj)
        await test_db.commit()

        user1 = str(user1_obj.id)
        user2 = str(user2_obj.id)

        # Create sessions for user1
        for i in range(2):
            await session_store.set(
                f"user1-session-{uuid4()}",
                {"user": 1, "index": i},
                ttl=3600,
                user_id=user1,
            )

        # Create session for user2
        user2_session_id = f"user2-session-{uuid4()}"
        await session_store.set(
            user2_session_id,
            {"user": 2},
            ttl=3600,
            user_id=user2,
        )

        # Delete all for user1
        await session_store.delete_all_for_user(user1)

        # user2's session should still exist
        result = await session_store.get(user2_session_id)
        assert result == {"user": 2}

    async def test_delete_all_for_user_with_no_sessions(self, session_store):
        """delete_all_for_user should return 0 when user has no sessions."""
        nonexistent_user = str(uuid4())

        count = await session_store.delete_all_for_user(nonexistent_user)

        assert count == 0


@pytest.mark.integration
class TestSessionStoreCountUserSessions:
    """Integration tests for SessionStore.count_user_sessions method."""

    async def test_count_returns_correct_number(self, session_store, test_user_id):
        """count_user_sessions should return correct count."""
        for i in range(5):
            await session_store.set(
                f"count-test-{uuid4()}",
                {"index": i},
                ttl=3600,
                user_id=test_user_id,
            )

        count = await session_store.count_user_sessions(test_user_id)

        assert count == 5

    async def test_count_excludes_expired_sessions(self, session_store, test_user_id):
        """count_user_sessions should not count expired sessions."""
        # Create valid session
        await session_store.set(
            f"valid-count-{uuid4()}",
            {"valid": True},
            ttl=3600,
            user_id=test_user_id,
        )

        # Create expired session
        await session_store.set(
            f"expired-count-{uuid4()}",
            {"expired": True},
            ttl=0,
            user_id=test_user_id,
        )

        import asyncio
        await asyncio.sleep(0.1)

        count = await session_store.count_user_sessions(test_user_id)

        assert count == 1  # Only the valid one

    async def test_count_returns_zero_for_no_sessions(self, session_store):
        """count_user_sessions should return 0 for user with no sessions."""
        count = await session_store.count_user_sessions(str(uuid4()))
        assert count == 0


@pytest.mark.integration
class TestPendingAuthStoreBasicOperations:
    """Integration tests for PendingAuthStore basic operations."""

    async def test_set_and_get_pending_auth(self, pending_auth_store):
        """Should store and retrieve pending auth data."""
        state = f"state-{uuid4()}"

        await pending_auth_store.set(
            state=state,
            redirect_uri="/dashboard",
            callback_url="https://app.example.com/auth/callback",
        )

        result = await pending_auth_store.get(state)

        assert result is not None
        assert result["redirect_uri"] == "/dashboard"
        assert result["callback_url"] == "https://app.example.com/auth/callback"
        assert "created_at" in result

    async def test_get_nonexistent_state_returns_none(self, pending_auth_store):
        """Get for nonexistent state should return None."""
        result = await pending_auth_store.get("nonexistent-state")
        assert result is None

    async def test_delete_pending_auth(self, pending_auth_store):
        """Should delete pending auth entry."""
        state = f"state-delete-{uuid4()}"
        await pending_auth_store.set(state, "/test", "https://callback")

        result = await pending_auth_store.delete(state)
        assert result is True

        # Should not be retrievable after delete
        get_result = await pending_auth_store.get(state)
        assert get_result is None

    async def test_delete_nonexistent_returns_false(self, pending_auth_store):
        """Delete for nonexistent state should return False."""
        result = await pending_auth_store.delete("nonexistent-state")
        assert result is False


@pytest.mark.integration
class TestPendingAuthStoreExpiration:
    """Integration tests for PendingAuthStore expiration."""

    async def test_expired_pending_auth_returns_none(self, pending_auth_store, test_db):
        """Pending auth older than AUTH_TIMEOUT_MINUTES should return None."""
        from openlabels.server.models import PendingAuth as PendingAuthModel

        state = f"state-expired-{uuid4()}"

        # Create pending auth with old timestamp directly
        old_time = datetime.now(timezone.utc) - timedelta(minutes=15)  # Older than timeout
        pending = PendingAuthModel(
            state=state,
            redirect_uri="/expired",
            callback_url="https://callback",
        )
        pending.created_at = old_time  # Manually set old created_at
        test_db.add(pending)
        await test_db.flush()

        # Should not be retrievable because it's expired
        result = await pending_auth_store.get(state)
        assert result is None


@pytest.mark.integration
class TestPendingAuthStoreCleanup:
    """Integration tests for PendingAuthStore.cleanup_expired method."""

    async def test_cleanup_removes_expired_entries(self, pending_auth_store, test_db):
        """Cleanup should remove expired pending auth entries."""
        from openlabels.server.models import PendingAuth as PendingAuthModel

        # Create expired entries directly with old timestamps
        old_time = datetime.now(timezone.utc) - timedelta(minutes=15)
        for i in range(3):
            pending = PendingAuthModel(
                state=f"expired-state-{uuid4()}",
                redirect_uri=f"/expired-{i}",
                callback_url="https://callback",
            )
            pending.created_at = old_time
            test_db.add(pending)
        await test_db.flush()

        count = await pending_auth_store.cleanup_expired()

        assert count >= 3


@pytest.mark.integration
class TestPendingAuthTimeout:
    """Tests for pending auth timeout configuration."""

    def test_auth_timeout_is_reasonable(self):
        """AUTH_TIMEOUT_MINUTES should be between 5 and 15 minutes."""
        timeout = PendingAuthStore.AUTH_TIMEOUT_MINUTES
        assert 5 <= timeout <= 15, \
            f"Auth timeout {timeout} should be 5-15 minutes for security"


@pytest.mark.integration
class TestSessionStoreDataIntegrity:
    """Tests for data integrity and edge cases."""

    async def test_unicode_data_preserved(self, session_store):
        """Unicode data should be preserved correctly."""
        session_id = f"unicode-test-{uuid4()}"
        unicode_data = {
            "name": "用户名",
            "emoji": "🔐🔑",
            "mixed": "Hello 世界",
        }

        await session_store.set(session_id, unicode_data, ttl=3600)
        result = await session_store.get(session_id)

        assert result == unicode_data

    async def test_large_data_stored(self, session_store):
        """Large data should be stored and retrieved correctly."""
        session_id = f"large-test-{uuid4()}"
        large_data = {
            "array": list(range(1000)),
            "nested": {str(i): {"value": i} for i in range(100)},
            "string": "x" * 10000,
        }

        await session_store.set(session_id, large_data, ttl=3600)
        result = await session_store.get(session_id)

        assert result["array"] == list(range(1000))
        assert len(result["string"]) == 10000

    async def test_null_values_in_data(self, session_store):
        """Null values in data should be preserved."""
        session_id = f"null-test-{uuid4()}"
        data_with_nulls = {
            "present": "value",
            "nullable": None,
            "nested": {"also_null": None},
        }

        await session_store.set(session_id, data_with_nulls, ttl=3600)
        result = await session_store.get(session_id)

        assert result["nullable"] is None
        assert result["nested"]["also_null"] is None


@pytest.mark.integration
class TestOAuthFlowLifecycle:
    """Integration tests for complete OAuth flow lifecycle."""

    async def test_complete_oauth_flow(
        self, pending_auth_store, session_store, test_tenant_id, test_user_id
    ):
        """Test complete OAuth flow: pending auth -> delete -> create session."""
        state = f"oauth-flow-{uuid4()}"
        session_id = f"session-{uuid4()}"

        # 1. Create pending auth (user clicks login)
        await pending_auth_store.set(
            state=state,
            redirect_uri="/dashboard",
            callback_url="https://app/callback",
        )

        # 2. Get pending auth (callback received)
        pending = await pending_auth_store.get(state)
        assert pending["redirect_uri"] == "/dashboard"

        # 3. Delete pending auth (state used)
        deleted = await pending_auth_store.delete(state)
        assert deleted is True

        # 4. Create session (user authenticated)
        await session_store.set(
            session_id,
            {"access_token": "real-token", "claims": {"sub": "user123"}},
            ttl=604800,  # 7 days
            tenant_id=test_tenant_id,
            user_id=test_user_id,
        )

        # 5. Verify session exists
        session = await session_store.get(session_id)
        assert session["access_token"] == "real-token"

        # 6. Pending auth should be gone
        pending_again = await pending_auth_store.get(state)
        assert pending_again is None

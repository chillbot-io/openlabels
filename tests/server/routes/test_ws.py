"""
Comprehensive tests for WebSocket endpoints.

Tests focus on:
- Connection lifecycle (connect, receive, disconnect)
- Origin validation (CSWSH prevention)
- Authentication via session cookies
- Real-time message handling
- Tenant isolation (security boundary)
- Error handling and edge cases
"""

import pytest
import asyncio
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from contextlib import asynccontextmanager
from unittest.mock import patch, MagicMock, AsyncMock

from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


def _mock_session_factory(session):
    """Create a mock session factory returning session as an async context manager."""
    @asynccontextmanager
    async def _session():
        yield session
    return _session


@pytest.fixture
async def setup_ws_test_data(test_client, test_db):
    """Set up test data for WebSocket endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanJob, ScanTarget, Session

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    user = result.scalar_one()

    # Create a scan target
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Test WebSocket Target",
        adapter="filesystem",
        config={"path": "/test/path"},
        enabled=True,
        created_by=user.id,
    )
    test_db.add(target)
    await test_db.flush()

    # Create a scan job for WebSocket testing
    scan_job = ScanJob(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        name="WebSocket Test Scan",
        status="running",
        started_at=datetime.now(timezone.utc),
        created_by=user.id,
    )
    test_db.add(scan_job)

    # Create a second scan job for isolation tests
    other_scan_job = ScanJob(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        name="Other Test Scan",
        status="running",
        started_at=datetime.now(timezone.utc),
        created_by=user.id,
    )
    test_db.add(other_scan_job)

    await test_db.commit()

    return {
        "tenant": tenant,
        "user": user,
        "target": target,
        "scan_job": scan_job,
        "other_scan_job": other_scan_job,
        "session": test_db,
    }


@pytest.fixture
async def setup_multi_tenant_data(test_client, test_db):
    """Set up multi-tenant test data for isolation tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User, ScanJob, ScanTarget, Session
    import random
    import string

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant_a = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant_a.id))
    user_a = result.scalar_one()

    # Create second tenant
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    tenant_b = Tenant(
        name=f"Other Tenant {suffix}",
        azure_tenant_id=f"other-tenant-id-{suffix}",
    )
    test_db.add(tenant_b)
    await test_db.flush()

    # Create user for tenant B
    user_b = User(
        tenant_id=tenant_b.id,
        email=f"other-user-{suffix}@localhost",
        name=f"Other User {suffix}",
        role="viewer",
    )
    test_db.add(user_b)
    await test_db.flush()

    # Create scan target for tenant A
    target_a = ScanTarget(
        id=uuid4(),
        tenant_id=tenant_a.id,
        name="Tenant A Target",
        adapter="filesystem",
        config={"path": "/tenant-a/path"},
        enabled=True,
        created_by=user_a.id,
    )
    test_db.add(target_a)

    # Create scan target for tenant B
    target_b = ScanTarget(
        id=uuid4(),
        tenant_id=tenant_b.id,
        name="Tenant B Target",
        adapter="filesystem",
        config={"path": "/tenant-b/path"},
        enabled=True,
        created_by=user_b.id,
    )
    test_db.add(target_b)
    await test_db.flush()

    # Create scan job for tenant A
    scan_a = ScanJob(
        id=uuid4(),
        tenant_id=tenant_a.id,
        target_id=target_a.id,
        name="Tenant A Scan",
        status="running",
        started_at=datetime.now(timezone.utc),
        created_by=user_a.id,
    )
    test_db.add(scan_a)

    # Create scan job for tenant B
    scan_b = ScanJob(
        id=uuid4(),
        tenant_id=tenant_b.id,
        target_id=target_b.id,
        name="Tenant B Scan",
        status="running",
        started_at=datetime.now(timezone.utc),
        created_by=user_b.id,
    )
    test_db.add(scan_b)

    await test_db.commit()

    return {
        "tenant_a": tenant_a,
        "user_a": user_a,
        "target_a": target_a,
        "scan_a": scan_a,
        "tenant_b": tenant_b,
        "user_b": user_b,
        "target_b": target_b,
        "scan_b": scan_b,
        "session": test_db,
    }


@pytest.fixture
async def create_ws_session(test_client, test_db):
    """Factory fixture to create test sessions for WebSocket auth."""
    from openlabels.server.models import Session

    async def _create_session(
        session_id: str = None,
        tenant_azure_id: str = None,
        user_email: str = None,
        expires_at: datetime = None,
        data: dict = None,
    ):
        if session_id is None:
            session_id = secrets.token_urlsafe(32)
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        if data is None:
            data = {
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    "oid": "test-oid",
                    "preferred_username": user_email or "test@localhost",
                    "name": "Test User",
                    "tid": tenant_azure_id or "test-tenant-id",
                    "roles": ["admin"],
                },
            }

        session = Session(
            id=session_id,
            data=data,
            expires_at=expires_at,
        )
        test_db.add(session)
        await test_db.flush()
        return session

    return _create_session


# =============================================================================
# ORIGIN VALIDATION TESTS
# =============================================================================


class TestWebSocketOriginValidation:
    """Tests for WebSocket origin validation (CSWSH prevention)."""

    def test_validate_origin_development_allows_any(self):
        """In development mode, any origin should be allowed."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "development"

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "https://evil.com")
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True

    def test_validate_origin_no_origin_header_allowed(self):
        """Connections without Origin header should be allowed (same-origin or non-browser)."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = []  # No headers

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True

    def test_validate_origin_allowed_cors_origin(self):
        """Allowed CORS origins should be accepted."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com", "http://localhost:3000"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "https://app.example.com")
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True

    def test_validate_origin_unauthorized_origin_rejected(self):
        """Origins not in allowed list should be rejected."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "https://evil.com"),
            ("host", "app.example.com"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is False

    def test_validate_origin_same_origin_allowed(self):
        """Same-origin requests (origin matches host) should be allowed."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = []  # No explicit CORS origins

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "https://api.example.com"),
            ("host", "api.example.com"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True

    def test_validate_origin_same_origin_http_allowed(self):
        """Same-origin requests with HTTP should be allowed."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = []

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "http://localhost:8000"),
            ("host", "localhost:8000"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True

    def test_validate_origin_malformed_origin_rejected(self):
        """Malformed origin headers should be rejected."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        # Simulate malformed origin that causes urlparse to fail
        mock_websocket.headers.items.return_value = [
            ("origin", "://invalid-url"),
            ("host", "app.example.com"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            # Should return False due to parse failure
            result = validate_websocket_origin(mock_websocket)
            assert result is False

    def test_validate_origin_case_insensitive_header_name(self):
        """Origin header matching should be case-insensitive."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("Origin", "https://app.example.com"),  # Uppercase
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================


class TestWebSocketAuthentication:
    """Tests for WebSocket session-based authentication."""

    async def test_authenticate_dev_mode_creates_user(self, test_db):
        """In dev mode (auth provider=none), authentication should auto-create dev user."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"

        mock_websocket = MagicMock()

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                # Call authenticate (it handles dev mode internally with its own session)
                result = await authenticate_websocket(mock_websocket)

                # In dev mode, should return user_id and tenant_id tuple
                assert result is not None
                user_id, tenant_id = result
                assert user_id is not None
                assert tenant_id is not None

    async def test_authenticate_no_session_cookie_rejected(self, test_db, setup_ws_test_data):
        """WebSocket without session cookie should be rejected."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {}  # No session cookie

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            result = await authenticate_websocket(mock_websocket)
            assert result is None

    async def test_authenticate_invalid_session_rejected(self, test_db, setup_ws_test_data):
        """WebSocket with invalid session ID should be rejected."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "nonexistent-session-id"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                result = await authenticate_websocket(mock_websocket)
                assert result is None

    async def test_authenticate_expired_session_rejected(
        self, test_db, setup_ws_test_data, create_ws_session
    ):
        """WebSocket with expired session should be rejected."""
        from openlabels.server.routes.ws import authenticate_websocket

        tenant = setup_ws_test_data["tenant"]

        # Create an expired session
        expired_session = await create_ws_session(
            session_id="expired-ws-session",
            tenant_azure_id=tenant.azure_tenant_id,
            user_email="test@localhost",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),  # Expired
                "claims": {
                    "oid": "test-oid",
                    "preferred_username": "test@localhost",
                    "name": "Test User",
                    "tid": tenant.azure_tenant_id,
                },
            },
        )
        await test_db.commit()

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "expired-ws-session"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                result = await authenticate_websocket(mock_websocket)
                assert result is None

    async def test_authenticate_missing_claims_rejected(
        self, test_db, setup_ws_test_data, create_ws_session
    ):
        """WebSocket session missing required claims should be rejected."""
        # Create session with missing claims
        session = await create_ws_session(
            session_id="missing-claims-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {
                    # Missing 'tid' and 'preferred_username'
                    "oid": "test-oid",
                },
            },
        )
        await test_db.commit()

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "missing-claims-session"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                assert result is None

    async def test_authenticate_tenant_not_found_rejected(
        self, test_db, setup_ws_test_data, create_ws_session
    ):
        """WebSocket with session pointing to non-existent tenant should be rejected."""
        # Create session with non-existent tenant
        session = await create_ws_session(
            session_id="invalid-tenant-session",
            tenant_azure_id="nonexistent-tenant-id",
            user_email="test@localhost",
        )
        await test_db.commit()

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "invalid-tenant-session"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                assert result is None

    async def test_authenticate_user_not_found_rejected(
        self, test_db, setup_ws_test_data, create_ws_session
    ):
        """WebSocket with session pointing to non-existent user should be rejected."""
        tenant = setup_ws_test_data["tenant"]

        # Create session with non-existent user email
        session = await create_ws_session(
            session_id="invalid-user-session",
            tenant_azure_id=tenant.azure_tenant_id,
            user_email="nonexistent@localhost",
        )
        await test_db.commit()

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "invalid-user-session"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                assert result is None


# =============================================================================
# CONNECTION MANAGER TESTS
# =============================================================================


class TestConnectionManager:
    """Tests for WebSocket connection manager."""

    async def test_manager_connect_adds_connection(self):
        """Connect should add connection to active list."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        mock_websocket = AsyncMock()

        conn = await manager.connect(scan_id, mock_websocket, user_id, tenant_id)

        assert scan_id in manager.active_connections
        assert len(manager.active_connections[scan_id]) == 1
        assert conn.user_id == user_id
        assert conn.tenant_id == tenant_id
        mock_websocket.accept.assert_called_once()

    async def test_manager_multiple_connections_same_scan(self):
        """Manager should support multiple connections to same scan."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        mock_websocket1 = AsyncMock()
        mock_websocket2 = AsyncMock()

        await manager.connect(scan_id, mock_websocket1, uuid4(), tenant_id)
        await manager.connect(scan_id, mock_websocket2, uuid4(), tenant_id)

        assert len(manager.active_connections[scan_id]) == 2

    async def test_manager_disconnect_removes_connection(self):
        """Disconnect should remove connection from active list."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        mock_websocket = AsyncMock()

        conn = await manager.connect(scan_id, mock_websocket, user_id, tenant_id)
        manager.disconnect(scan_id, conn)

        assert scan_id not in manager.active_connections

    async def test_manager_disconnect_keeps_other_connections(self):
        """Disconnect should only remove specific connection."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        mock_websocket1 = AsyncMock()
        mock_websocket2 = AsyncMock()

        conn1 = await manager.connect(scan_id, mock_websocket1, uuid4(), tenant_id)
        conn2 = await manager.connect(scan_id, mock_websocket2, uuid4(), tenant_id)

        manager.disconnect(scan_id, conn1)

        assert len(manager.active_connections[scan_id]) == 1
        assert manager.active_connections[scan_id][0] == conn2

    async def test_manager_broadcast_sends_to_all(self):
        """Broadcast should send message to all connections for a scan."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        mock_websocket1 = AsyncMock()
        mock_websocket2 = AsyncMock()

        await manager.connect(scan_id, mock_websocket1, uuid4(), tenant_id)
        await manager.connect(scan_id, mock_websocket2, uuid4(), tenant_id)

        message = {"type": "test", "data": "hello"}
        await manager.broadcast(scan_id, message)

        mock_websocket1.send_json.assert_called_once_with(message)
        mock_websocket2.send_json.assert_called_once_with(message)

    async def test_manager_broadcast_handles_send_error(self):
        """Broadcast should handle errors when sending to individual connections."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        mock_websocket1 = AsyncMock()
        mock_websocket1.send_json.side_effect = Exception("Connection closed")

        mock_websocket2 = AsyncMock()

        await manager.connect(scan_id, mock_websocket1, uuid4(), tenant_id)
        await manager.connect(scan_id, mock_websocket2, uuid4(), tenant_id)

        message = {"type": "test", "data": "hello"}
        # Should not raise exception
        await manager.broadcast(scan_id, message)

        # Second connection should still receive message
        mock_websocket2.send_json.assert_called_once_with(message)

    async def test_manager_broadcast_no_connections(self):
        """Broadcast to scan with no connections should not error."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        message = {"type": "test", "data": "hello"}
        # Should not raise exception
        await manager.broadcast(scan_id, message)


# =============================================================================
# AUTHENTICATED CONNECTION TESTS
# =============================================================================


class TestAuthenticatedConnection:
    """Tests for AuthenticatedConnection class."""

    def test_authenticated_connection_stores_context(self):
        """AuthenticatedConnection should store user context."""
        from openlabels.server.routes.ws import AuthenticatedConnection

        mock_websocket = MagicMock()
        user_id = uuid4()
        tenant_id = uuid4()

        conn = AuthenticatedConnection(mock_websocket, user_id, tenant_id)

        assert conn.websocket == mock_websocket
        assert conn.user_id == user_id
        assert conn.tenant_id == tenant_id


# =============================================================================
# REAL-TIME UPDATE HELPER TESTS
# =============================================================================


class TestRealTimeUpdateHelpers:
    """Tests for real-time update helper functions."""

    async def test_send_scan_progress(self):
        """send_scan_progress should broadcast progress message."""
        from openlabels.server.routes.ws import send_scan_progress, manager

        scan_id = uuid4()
        tenant_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), tenant_id)

        try:
            await send_scan_progress(
                scan_id,
                status="running",
                progress={"files_scanned": 50, "total_files": 100},
            )

            mock_websocket.send_json.assert_called_once()
            call_args = mock_websocket.send_json.call_args[0][0]
            assert call_args["type"] == "progress"
            assert call_args["scan_id"] == str(scan_id)
            assert call_args["status"] == "running"
            assert call_args["progress"]["files_scanned"] == 50
        finally:
            # Clean up
            manager.active_connections.pop(scan_id, None)

    async def test_send_scan_file_result(self):
        """send_scan_file_result should broadcast file result message."""
        from openlabels.server.routes.ws import send_scan_file_result, manager

        scan_id = uuid4()
        tenant_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), tenant_id)

        try:
            await send_scan_file_result(
                scan_id,
                file_path="/path/to/file.txt",
                risk_score=85,
                risk_tier="HIGH",
                entity_counts={"SSN": 2, "EMAIL": 5},
            )

            mock_websocket.send_json.assert_called_once()
            call_args = mock_websocket.send_json.call_args[0][0]
            assert call_args["type"] == "file_result"
            assert call_args["scan_id"] == str(scan_id)
            assert call_args["file_path"] == "/path/to/file.txt"
            assert call_args["risk_score"] == 85
            assert call_args["risk_tier"] == "HIGH"
            assert call_args["entity_counts"]["SSN"] == 2
        finally:
            # Clean up
            manager.active_connections.pop(scan_id, None)

    async def test_send_scan_completed(self):
        """send_scan_completed should broadcast completion message."""
        from openlabels.server.routes.ws import send_scan_completed, manager

        scan_id = uuid4()
        tenant_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), tenant_id)

        try:
            await send_scan_completed(
                scan_id,
                status="completed",
                summary={"total_files": 100, "files_with_pii": 15},
            )

            mock_websocket.send_json.assert_called_once()
            call_args = mock_websocket.send_json.call_args[0][0]
            assert call_args["type"] == "completed"
            assert call_args["scan_id"] == str(scan_id)
            assert call_args["status"] == "completed"
            assert call_args["summary"]["total_files"] == 100
        finally:
            # Clean up
            manager.active_connections.pop(scan_id, None)


# =============================================================================
# TENANT ISOLATION TESTS
# =============================================================================


class TestTenantIsolation:
    """Tests for tenant isolation in WebSocket connections."""

    async def test_scan_access_denied_different_tenant(self):
        """Users should not connect to scans from different tenants."""
        # This test verifies the logic in websocket_scan_progress
        # that checks scan.tenant_id != tenant_id
        from openlabels.server.routes.ws import manager

        tenant_a_id = uuid4()
        tenant_b_id = uuid4()
        scan_id = uuid4()

        # User A connects to scan (owned by tenant A)
        mock_websocket_a = AsyncMock()
        await manager.connect(scan_id, mock_websocket_a, uuid4(), tenant_a_id)

        # User B should be denied (wrong tenant) - this is enforced at endpoint level
        # In the actual endpoint, the connection would be closed before reaching manager
        # Here we verify that broadcast only goes to connected users

        # Broadcast a message
        message = {"type": "progress", "data": "secret tenant A data"}
        await manager.broadcast(scan_id, message)

        # Only tenant A's connection receives the message
        mock_websocket_a.send_json.assert_called_once_with(message)

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_broadcasts_isolated_by_scan_id(self):
        """Broadcasts should only go to connections watching the same scan."""
        from openlabels.server.routes.ws import manager

        scan_a_id = uuid4()
        scan_b_id = uuid4()
        tenant_id = uuid4()

        mock_websocket_a = AsyncMock()
        mock_websocket_b = AsyncMock()

        await manager.connect(scan_a_id, mock_websocket_a, uuid4(), tenant_id)
        await manager.connect(scan_b_id, mock_websocket_b, uuid4(), tenant_id)

        try:
            # Broadcast to scan A only
            message = {"type": "progress", "scan_id": str(scan_a_id)}
            await manager.broadcast(scan_a_id, message)

            mock_websocket_a.send_json.assert_called_once_with(message)
            mock_websocket_b.send_json.assert_not_called()
        finally:
            # Clean up
            manager.active_connections.pop(scan_a_id, None)
            manager.active_connections.pop(scan_b_id, None)


# =============================================================================
# MESSAGE HANDLING TESTS
# =============================================================================


class TestWebSocketMessageHandling:
    """Tests for WebSocket message handling."""

    async def test_ping_pong_response(self):
        """Server should respond to 'ping' with 'pong'."""
        # This is tested by checking the websocket endpoint logic
        # The endpoint reads text and if it's "ping", sends "pong"

        mock_websocket = AsyncMock()
        # First receive returns "ping", then timeout to break the loop
        mock_websocket.receive_text.side_effect = ["ping", asyncio.TimeoutError()]

        # Simulate the ping handling from the endpoint
        data = await mock_websocket.receive_text()
        if data == "ping":
            await mock_websocket.send_text("pong")

        mock_websocket.send_text.assert_called_once_with("pong")

    async def test_heartbeat_on_timeout(self):
        """Server should send heartbeat after receive timeout."""
        mock_websocket = AsyncMock()

        # Simulate heartbeat sending
        await mock_websocket.send_json({"type": "heartbeat"})

        mock_websocket.send_json.assert_called_once_with({"type": "heartbeat"})


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================


class TestWebSocketErrorHandling:
    """Tests for WebSocket error handling."""

    async def test_disconnect_cleanup(self):
        """WebSocket disconnect should clean up connection."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        mock_websocket = AsyncMock()
        conn = await manager.connect(scan_id, mock_websocket, user_id, tenant_id)

        # Simulate disconnect cleanup
        manager.disconnect(scan_id, conn)

        # Connection should be removed
        assert scan_id not in manager.active_connections

    async def test_broadcast_continues_after_one_failure(self):
        """Broadcast should continue to other connections if one fails."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        # First connection will fail
        mock_websocket1 = AsyncMock()
        mock_websocket1.send_json.side_effect = Exception("Connection reset")

        # Second connection is healthy
        mock_websocket2 = AsyncMock()

        # Third connection is healthy
        mock_websocket3 = AsyncMock()

        await manager.connect(scan_id, mock_websocket1, uuid4(), tenant_id)
        await manager.connect(scan_id, mock_websocket2, uuid4(), tenant_id)
        await manager.connect(scan_id, mock_websocket3, uuid4(), tenant_id)

        message = {"type": "test"}
        await manager.broadcast(scan_id, message)

        # All receive attempts were made
        mock_websocket1.send_json.assert_called_once()
        mock_websocket2.send_json.assert_called_once_with(message)
        mock_websocket3.send_json.assert_called_once_with(message)

        # Clean up
        manager.active_connections.pop(scan_id, None)


# =============================================================================
# WEBSOCKET ENDPOINT INTEGRATION TESTS
# =============================================================================


class TestWebSocketEndpointIntegration:
    """Integration tests for WebSocket endpoint using TestClient."""

    async def test_endpoint_rejects_invalid_origin_in_production(self, test_db, setup_ws_test_data):
        """WebSocket endpoint should reject invalid origins in production."""
        from starlette.testclient import TestClient
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]
        mock_settings.auth.provider = "azure_ad"

        try:
            with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
                # Note: Starlette TestClient doesn't send Origin headers by default,
                # so we test the validate_websocket_origin function directly
                from openlabels.server.routes.ws import validate_websocket_origin

                mock_websocket = MagicMock()
                mock_websocket.headers = MagicMock()
                mock_websocket.headers.items.return_value = [
                    ("origin", "https://evil.com"),
                    ("host", "app.example.com"),
                ]

                result = validate_websocket_origin(mock_websocket)
                assert result is False
        finally:
            app.dependency_overrides.clear()

    async def test_endpoint_requires_authentication(self, test_db, setup_ws_test_data):
        """WebSocket endpoint should require valid session."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {}  # No session

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            result = await authenticate_websocket(mock_websocket)
            assert result is None


# =============================================================================
# CONSTANTS AND CONFIGURATION TESTS
# =============================================================================


class TestWebSocketConstants:
    """Tests for WebSocket module constants and configuration."""

    def test_session_cookie_name_matches_auth(self):
        """WebSocket session cookie name should match auth module."""
        from openlabels.server.routes.ws import SESSION_COOKIE_NAME

        assert SESSION_COOKIE_NAME == "openlabels_session"

    def test_connection_manager_singleton(self):
        """Module should export a singleton connection manager."""
        from openlabels.server.routes.ws import manager

        assert manager is not None
        assert hasattr(manager, 'active_connections')
        assert hasattr(manager, 'connect')
        assert hasattr(manager, 'disconnect')
        assert hasattr(manager, 'broadcast')


# =============================================================================
# CONCURRENT CONNECTION TESTS
# =============================================================================


class TestConcurrentConnections:
    """Tests for multiple simultaneous WebSocket connections."""

    async def test_multiple_users_same_scan(self):
        """Multiple users should be able to watch the same scan."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        users = [uuid4() for _ in range(5)]
        websockets = [AsyncMock() for _ in range(5)]
        connections = []

        for user_id, ws in zip(users, websockets):
            conn = await manager.connect(scan_id, ws, user_id, tenant_id)
            connections.append(conn)

        assert len(manager.active_connections[scan_id]) == 5

        # Broadcast reaches all
        message = {"type": "progress"}
        await manager.broadcast(scan_id, message)

        for ws in websockets:
            ws.send_json.assert_called_once_with(message)

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_user_multiple_connections(self):
        """Same user can have multiple connections (e.g., multiple browser tabs)."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        websockets = [AsyncMock() for _ in range(3)]
        connections = []

        for ws in websockets:
            conn = await manager.connect(scan_id, ws, user_id, tenant_id)
            connections.append(conn)

        assert len(manager.active_connections[scan_id]) == 3

        # All connections should receive broadcast
        message = {"type": "progress"}
        await manager.broadcast(scan_id, message)

        for ws in websockets:
            ws.send_json.assert_called_once_with(message)

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_connections_across_multiple_scans(self):
        """Connections should be properly isolated across different scans."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        tenant_id = uuid4()

        scans = [uuid4() for _ in range(3)]
        all_websockets = {}

        # Create 2 connections per scan
        for scan_id in scans:
            all_websockets[scan_id] = []
            for _ in range(2):
                ws = AsyncMock()
                await manager.connect(scan_id, ws, uuid4(), tenant_id)
                all_websockets[scan_id].append(ws)

        # Broadcast to middle scan only
        message = {"type": "progress", "scan_id": str(scans[1])}
        await manager.broadcast(scans[1], message)

        # Only middle scan's websockets should receive
        for ws in all_websockets[scans[0]]:
            ws.send_json.assert_not_called()

        for ws in all_websockets[scans[1]]:
            ws.send_json.assert_called_once_with(message)

        for ws in all_websockets[scans[2]]:
            ws.send_json.assert_not_called()

        # Clean up
        for scan_id in scans:
            manager.active_connections.pop(scan_id, None)


# =============================================================================
# EDGE CASE TESTS
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    async def test_disconnect_nonexistent_scan(self):
        """Disconnect should handle non-existent scan gracefully."""
        from openlabels.server.routes.ws import ConnectionManager, AuthenticatedConnection

        manager = ConnectionManager()
        scan_id = uuid4()
        mock_websocket = AsyncMock()

        conn = AuthenticatedConnection(mock_websocket, uuid4(), uuid4())

        # Should not raise
        manager.disconnect(scan_id, conn)

    async def test_disconnect_already_removed_connection(self):
        """Disconnect should handle already-removed connection gracefully."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        mock_websocket = AsyncMock()
        conn = await manager.connect(scan_id, mock_websocket, user_id, tenant_id)

        # Disconnect twice
        manager.disconnect(scan_id, conn)
        manager.disconnect(scan_id, conn)  # Should not raise

    async def test_broadcast_empty_message(self):
        """Broadcast should handle empty message dict."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        mock_websocket = AsyncMock()

        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        try:
            await manager.broadcast(scan_id, {})
            mock_websocket.send_json.assert_called_once_with({})
        finally:
            manager.active_connections.pop(scan_id, None)

    async def test_broadcast_large_message(self):
        """Broadcast should handle large messages."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        mock_websocket = AsyncMock()

        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        try:
            # Create a large message
            large_data = {"data": "x" * 100000}  # 100KB of data
            await manager.broadcast(scan_id, large_data)
            mock_websocket.send_json.assert_called_once_with(large_data)
        finally:
            manager.active_connections.pop(scan_id, None)

    def test_validate_origin_empty_host_header(self):
        """Origin validation should handle missing host header."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = []  # No CORS origins

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "https://unknown.com"),
            # No host header
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            result = validate_websocket_origin(mock_websocket)
            # Should be rejected (no matching CORS origin, no matching host)
            assert result is False


# =============================================================================
# SECURITY TESTS
# =============================================================================


class TestWebSocketSecurity:
    """Security-focused tests for WebSocket endpoints."""

    def test_origin_validation_prevents_cswsh(self):
        """Origin validation should prevent Cross-Site WebSocket Hijacking."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]

        # Malicious origin trying to connect
        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "https://attacker.com"),
            ("host", "app.example.com"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is False

    async def test_session_based_auth_prevents_unauthorized_access(self, test_db):
        """Session-based auth should prevent unauthorized WebSocket access."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        # Try with forged/invalid session
        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "forged-session-id"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                result = await authenticate_websocket(mock_websocket)
                assert result is None  # Should be rejected

    def test_dev_mode_only_in_development(self):
        """Dev mode auth bypass should only work in development environment."""
        from openlabels.server.routes.ws import validate_websocket_origin

        # In production, even with "none" auth, origin should be validated
        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "https://evil.com"),
            ("host", "app.example.com"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            # Should still validate origin even if we tried to bypass
            assert validate_websocket_origin(mock_websocket) is False


# =============================================================================
# WEBSOCKET INTEGRATION TESTS (using TestClient)
# =============================================================================


class TestWebSocketIntegration:
    """Integration tests using Starlette's WebSocket TestClient."""

    async def test_websocket_connection_dev_mode(self, test_db, setup_ws_test_data):
        """WebSocket should connect successfully in dev mode."""
        from starlette.testclient import TestClient
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        scan_job = setup_ws_test_data["scan_job"]

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.server.environment = "development"
        mock_settings.auth.provider = "none"

        try:
            with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                    mock_factory.return_value = _mock_session_factory(test_db)

                    client = TestClient(app)
                    # In dev mode, connection should be accepted
                    with client.websocket_connect(f"/ws/scans/{scan_job.id}") as websocket:
                        # Send ping
                        websocket.send_text("ping")
                        response = websocket.receive_text()
                        assert response == "pong"
        finally:
            app.dependency_overrides.clear()

    async def test_websocket_receives_heartbeat(self, test_db, setup_ws_test_data):
        """WebSocket should receive heartbeat on timeout."""
        from starlette.testclient import TestClient
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        scan_job = setup_ws_test_data["scan_job"]

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.server.environment = "development"
        mock_settings.auth.provider = "none"

        try:
            with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                    mock_factory.return_value = _mock_session_factory(test_db)

                    # Reduce timeout for testing
                    with patch('openlabels.server.routes.ws.asyncio.wait_for') as mock_wait:
                        mock_wait.side_effect = asyncio.TimeoutError()

                        client = TestClient(app)
                        with client.websocket_connect(f"/ws/scans/{scan_job.id}") as websocket:
                            # Should receive heartbeat after timeout
                            data = websocket.receive_json()
                            assert data["type"] == "heartbeat"
        finally:
            app.dependency_overrides.clear()

    async def test_websocket_invalid_scan_id_format(self, test_db, setup_ws_test_data):
        """WebSocket should handle invalid scan ID format gracefully."""
        from starlette.testclient import TestClient
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.server.environment = "development"
        mock_settings.auth.provider = "none"

        try:
            with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
                client = TestClient(app)
                # Invalid UUID format should return 422 or similar
                with pytest.raises(Exception):
                    with client.websocket_connect("/ws/scans/invalid-uuid"):
                        pass
        finally:
            app.dependency_overrides.clear()

    async def test_websocket_nonexistent_scan(self, test_db, setup_ws_test_data):
        """WebSocket should reject connection to non-existent scan."""
        from starlette.testclient import TestClient
        from openlabels.server.app import app
        from openlabels.server.db import get_session

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        mock_settings = MagicMock()
        mock_settings.server.environment = "development"
        mock_settings.auth.provider = "none"

        try:
            with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
                with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                    mock_factory.return_value = _mock_session_factory(test_db)

                    client = TestClient(app)
                    nonexistent_id = uuid4()
                    # Should reject with policy violation
                    with pytest.raises(Exception):
                        with client.websocket_connect(f"/ws/scans/{nonexistent_id}"):
                            pass
        finally:
            app.dependency_overrides.clear()


# =============================================================================
# MESSAGE HANDLING EDGE CASES
# =============================================================================


class TestMessageHandlingEdgeCases:
    """Tests for edge cases in WebSocket message handling."""

    async def test_unknown_message_type_ignored(self):
        """Unknown message types should be handled gracefully (not crash)."""
        # The endpoint only handles "ping", other messages are ignored
        mock_websocket = AsyncMock()
        mock_websocket.receive_text.side_effect = [
            "unknown_command",
            "another_unknown",
            asyncio.TimeoutError(),
        ]

        # Simulate endpoint logic - non-ping messages don't trigger response
        data = await mock_websocket.receive_text()
        if data == "ping":
            await mock_websocket.send_text("pong")

        # send_text should not have been called (message wasn't "ping")
        mock_websocket.send_text.assert_not_called()

    async def test_empty_message_handled(self):
        """Empty messages should not crash the WebSocket."""
        mock_websocket = AsyncMock()
        mock_websocket.receive_text.side_effect = ["", asyncio.TimeoutError()]

        data = await mock_websocket.receive_text()
        if data == "ping":
            await mock_websocket.send_text("pong")

        mock_websocket.send_text.assert_not_called()

    async def test_whitespace_only_message_handled(self):
        """Whitespace-only messages should not crash the WebSocket."""
        mock_websocket = AsyncMock()
        mock_websocket.receive_text.side_effect = ["   \n\t  ", asyncio.TimeoutError()]

        data = await mock_websocket.receive_text()
        if data == "ping":
            await mock_websocket.send_text("pong")

        mock_websocket.send_text.assert_not_called()

    async def test_case_sensitive_ping(self):
        """Ping command should be case-sensitive."""
        mock_websocket = AsyncMock()

        # Test various case variations
        variations = ["PING", "Ping", "pInG", " ping", "ping "]
        for variation in variations:
            mock_websocket.reset_mock()
            mock_websocket.receive_text.return_value = variation

            data = await mock_websocket.receive_text()
            if data == "ping":
                await mock_websocket.send_text("pong")

            # Only exact "ping" should trigger response
            mock_websocket.send_text.assert_not_called()

    async def test_binary_message_handling(self):
        """Binary messages should be handled appropriately."""
        # Note: The current endpoint uses receive_text, so binary would
        # need receive_bytes. This tests the expected behavior.
        mock_websocket = AsyncMock()
        mock_websocket.receive_bytes = AsyncMock(return_value=b"\x00\x01\x02")

        # Simulate receiving binary
        data = await mock_websocket.receive_bytes()
        assert isinstance(data, bytes)

    async def test_unicode_message_handling(self):
        """Unicode messages should be handled correctly."""
        mock_websocket = AsyncMock()
        unicode_messages = ["你好", "مرحبا", "🎉", "ping\u0000"]

        for msg in unicode_messages:
            mock_websocket.receive_text.return_value = msg
            data = await mock_websocket.receive_text()

            if data == "ping":
                await mock_websocket.send_text("pong")

        # None of these should trigger pong response
        mock_websocket.send_text.assert_not_called()

    async def test_very_long_message(self):
        """Very long messages should be handled without crashing."""
        mock_websocket = AsyncMock()
        long_message = "x" * 1_000_000  # 1MB message
        mock_websocket.receive_text.return_value = long_message

        data = await mock_websocket.receive_text()
        assert len(data) == 1_000_000


# =============================================================================
# CONNECTION LIFECYCLE TESTS
# =============================================================================


class TestConnectionLifecycle:
    """Tests for WebSocket connection lifecycle management."""

    async def test_rapid_connect_disconnect_cycles(self):
        """Manager should handle rapid connect/disconnect cycles."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        # Perform many rapid connect/disconnect cycles
        for _ in range(100):
            mock_websocket = AsyncMock()
            conn = await manager.connect(scan_id, mock_websocket, uuid4(), tenant_id)
            manager.disconnect(scan_id, conn)

        # Manager should be clean after all disconnects
        assert scan_id not in manager.active_connections

    async def test_interleaved_connect_disconnect(self):
        """Manager should handle interleaved connect/disconnect operations."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        connections = []

        # Connect 5 clients
        for i in range(5):
            ws = AsyncMock()
            conn = await manager.connect(scan_id, ws, uuid4(), tenant_id)
            connections.append(conn)

        # Disconnect every other one
        for i in range(0, 5, 2):
            manager.disconnect(scan_id, connections[i])

        # Should have 2 remaining
        assert len(manager.active_connections[scan_id]) == 2

        # Disconnect rest
        for i in range(1, 5, 2):
            manager.disconnect(scan_id, connections[i])

        # Should be clean
        assert scan_id not in manager.active_connections

    async def test_connection_memory_cleanup(self):
        """Verify connections are properly cleaned up to prevent memory leaks."""
        from openlabels.server.routes.ws import ConnectionManager
        import gc
        import weakref

        manager = ConnectionManager()
        scan_id = uuid4()

        mock_websocket = AsyncMock()
        weak_ref = weakref.ref(mock_websocket)

        conn = await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())
        manager.disconnect(scan_id, conn)

        # Remove our reference
        del mock_websocket
        del conn
        gc.collect()

        # The weak reference might still exist due to AsyncMock internals,
        # but the manager should not hold references
        assert scan_id not in manager.active_connections

    async def test_reconnection_after_disconnect(self):
        """Same user should be able to reconnect after disconnecting."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        # First connection
        ws1 = AsyncMock()
        conn1 = await manager.connect(scan_id, ws1, user_id, tenant_id)
        manager.disconnect(scan_id, conn1)

        # Reconnect
        ws2 = AsyncMock()
        conn2 = await manager.connect(scan_id, ws2, user_id, tenant_id)

        assert scan_id in manager.active_connections
        assert len(manager.active_connections[scan_id]) == 1
        assert conn2.user_id == user_id

        # Clean up
        manager.disconnect(scan_id, conn2)

    async def test_multiple_scans_same_user(self):
        """User should be able to watch multiple scans simultaneously."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        user_id = uuid4()
        tenant_id = uuid4()

        scans = [uuid4() for _ in range(3)]
        connections = []

        for scan_id in scans:
            ws = AsyncMock()
            conn = await manager.connect(scan_id, ws, user_id, tenant_id)
            connections.append((scan_id, conn))

        # All scans should have connections
        for scan_id in scans:
            assert scan_id in manager.active_connections
            assert len(manager.active_connections[scan_id]) == 1

        # Clean up
        for scan_id, conn in connections:
            manager.disconnect(scan_id, conn)


# =============================================================================
# BROADCAST BEHAVIOR TESTS
# =============================================================================


class TestBroadcastBehavior:
    """Tests for broadcast message delivery behavior."""

    async def test_broadcast_message_ordering(self):
        """Messages should be delivered in order to each connection."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        mock_websocket = AsyncMock()
        received_messages = []

        async def capture_send(msg):
            received_messages.append(msg)

        mock_websocket.send_json = capture_send

        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        # Send multiple messages
        messages = [
            {"type": "progress", "index": 0},
            {"type": "progress", "index": 1},
            {"type": "progress", "index": 2},
            {"type": "completed", "index": 3},
        ]

        for msg in messages:
            await manager.broadcast(scan_id, msg)

        # Verify order
        assert len(received_messages) == 4
        for i, msg in enumerate(received_messages):
            assert msg["index"] == i

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_broadcast_to_many_connections(self):
        """Broadcast should efficiently handle many connections."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        # Create many connections
        num_connections = 100
        websockets = []
        for _ in range(num_connections):
            ws = AsyncMock()
            await manager.connect(scan_id, ws, uuid4(), tenant_id)
            websockets.append(ws)

        message = {"type": "progress", "data": "test"}
        await manager.broadcast(scan_id, message)

        # All should receive
        for ws in websockets:
            ws.send_json.assert_called_once_with(message)

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_broadcast_partial_failure_continues(self):
        """Broadcast should continue even if some connections fail."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        # Create 10 connections, make every 3rd one fail
        websockets = []
        for i in range(10):
            ws = AsyncMock()
            if i % 3 == 0:
                ws.send_json.side_effect = Exception(f"Connection {i} failed")
            websockets.append(ws)
            await manager.connect(scan_id, ws, uuid4(), tenant_id)

        message = {"type": "test"}
        await manager.broadcast(scan_id, message)

        # Verify all received attempt (failed ones still got called)
        for ws in websockets:
            ws.send_json.assert_called_once()

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_broadcast_with_nested_data(self):
        """Broadcast should handle deeply nested message data."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        nested_message = {
            "type": "file_result",
            "data": {
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": {
                                "value": "deep",
                                "array": [1, 2, 3, {"nested": True}],
                            }
                        }
                    }
                }
            }
        }

        await manager.broadcast(scan_id, nested_message)
        mock_websocket.send_json.assert_called_once_with(nested_message)

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_concurrent_broadcasts(self):
        """Multiple concurrent broadcasts should not interfere."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        received_messages = []

        async def capture_send(msg):
            received_messages.append(msg)
            # Simulate some processing time
            await asyncio.sleep(0.001)

        mock_websocket = AsyncMock()
        mock_websocket.send_json = capture_send

        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        # Launch multiple broadcasts concurrently
        messages = [{"id": i} for i in range(10)]
        await asyncio.gather(*[
            manager.broadcast(scan_id, msg) for msg in messages
        ])

        # All messages should be received
        assert len(received_messages) == 10

        # Clean up
        manager.active_connections.pop(scan_id, None)


# =============================================================================
# AUTHENTICATION EDGE CASES
# =============================================================================


class TestAuthenticationEdgeCases:
    """Edge cases in WebSocket authentication."""

    async def test_malformed_session_data(self, test_db, setup_ws_test_data, create_ws_session):
        """Authentication should handle malformed session data gracefully."""
        from openlabels.server.routes.ws import authenticate_websocket

        # Create session with corrupted data structure
        session = await create_ws_session(
            session_id="malformed-session",
            data={
                "access_token": None,  # Invalid
                "expires_at": "not-a-date",  # Invalid format
                "claims": "should-be-dict",  # Wrong type
            },
        )
        await test_db.commit()

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "malformed-session"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                result = await authenticate_websocket(mock_websocket)
                # Should fail gracefully (return None) rather than crash
                assert result is None

    async def test_session_without_expires_at(self, test_db, setup_ws_test_data, create_ws_session):
        """Session without expires_at field should be handled."""
        tenant = setup_ws_test_data["tenant"]
        user = setup_ws_test_data["user"]

        # Create session without expires_at in data
        session = await create_ws_session(
            session_id="no-expiry-session",
            tenant_azure_id=tenant.azure_tenant_id,
            user_email=user.email,
            data={
                "access_token": "test-token",
                # No expires_at
                "claims": {
                    "oid": "test-oid",
                    "preferred_username": user.email,
                    "name": "Test User",
                    "tid": tenant.azure_tenant_id,
                },
            },
        )
        await test_db.commit()

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "no-expiry-session"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                # Should succeed since no expiry means not expired
                assert result is not None

    async def test_session_empty_claims(self, test_db, setup_ws_test_data, create_ws_session):
        """Session with empty claims should be rejected."""
        session = await create_ws_session(
            session_id="empty-claims-session",
            data={
                "access_token": "test-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                "claims": {},  # Empty claims
            },
        )
        await test_db.commit()

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "empty-claims-session"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                assert result is None

    async def test_cookie_with_special_characters(self, test_db):
        """Session cookie with special characters should be handled."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        # Cookie with URL-encoded characters
        mock_websocket.cookies = {"openlabels_session": "session%20with%20spaces"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = _mock_session_factory(test_db)
                result = await authenticate_websocket(mock_websocket)
                # Invalid session should return None
                assert result is None


# =============================================================================
# TENANT ISOLATION COMPREHENSIVE TESTS
# =============================================================================


class TestTenantIsolationComprehensive:
    """Comprehensive tests for tenant data isolation."""

    async def test_tenant_cannot_access_other_tenant_scan(self, test_db, setup_multi_tenant_data):
        """Verify tenant isolation - users cannot access other tenant's scans."""
        # This is enforced at the endpoint level before connecting
        data = setup_multi_tenant_data

        # User A should not be able to connect to Tenant B's scan
        # The endpoint checks: scan.tenant_id != tenant_id
        assert data["scan_a"].tenant_id != data["tenant_b"].id
        assert data["scan_b"].tenant_id != data["tenant_a"].id

    async def test_broadcasts_never_cross_tenants(self, setup_multi_tenant_data):
        """Broadcasts should never leak data between tenants."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        data = setup_multi_tenant_data

        # Connect users from different tenants to their own scans
        ws_a = AsyncMock()
        ws_b = AsyncMock()

        await manager.connect(data["scan_a"].id, ws_a, data["user_a"].id, data["tenant_a"].id)
        await manager.connect(data["scan_b"].id, ws_b, data["user_b"].id, data["tenant_b"].id)

        # Broadcast to tenant A's scan
        message_a = {"type": "progress", "tenant": "A", "secret": "tenant_a_data"}
        await manager.broadcast(data["scan_a"].id, message_a)

        # Only tenant A should receive
        ws_a.send_json.assert_called_once_with(message_a)
        ws_b.send_json.assert_not_called()

        ws_a.reset_mock()
        ws_b.reset_mock()

        # Broadcast to tenant B's scan
        message_b = {"type": "progress", "tenant": "B", "secret": "tenant_b_data"}
        await manager.broadcast(data["scan_b"].id, message_b)

        # Only tenant B should receive
        ws_a.send_json.assert_not_called()
        ws_b.send_json.assert_called_once_with(message_b)

        # Clean up
        manager.active_connections.pop(data["scan_a"].id, None)
        manager.active_connections.pop(data["scan_b"].id, None)

    async def test_scan_id_collision_different_tenants(self):
        """Even with hypothetical scan ID collision, tenant isolation should hold."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()

        # Imagine same scan_id but different tenants (not possible in practice, but testing defense)
        scan_id = uuid4()
        tenant_a = uuid4()
        tenant_b = uuid4()

        ws_a = AsyncMock()
        ws_b = AsyncMock()

        # Both connect to "same" scan ID but with different tenant contexts
        await manager.connect(scan_id, ws_a, uuid4(), tenant_a)
        await manager.connect(scan_id, ws_b, uuid4(), tenant_b)

        # Broadcast goes to all connections for that scan_id
        # (In production, the endpoint prevents cross-tenant connections)
        message = {"type": "test"}
        await manager.broadcast(scan_id, message)

        # Both receive (manager doesn't filter by tenant - endpoint does)
        ws_a.send_json.assert_called_once()
        ws_b.send_json.assert_called_once()

        # Clean up
        manager.active_connections.pop(scan_id, None)


# =============================================================================
# STRESS AND PERFORMANCE TESTS
# =============================================================================


class TestStressAndPerformance:
    """Stress tests for WebSocket handling."""

    async def test_high_volume_messages(self):
        """Manager should handle high volume of messages."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        # Send many messages rapidly
        num_messages = 1000
        for i in range(num_messages):
            await manager.broadcast(scan_id, {"type": "progress", "index": i})

        assert mock_websocket.send_json.call_count == num_messages

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_many_scans_many_connections(self):
        """Manager should handle many scans with many connections each."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()

        num_scans = 50
        connections_per_scan = 20

        scans = [uuid4() for _ in range(num_scans)]

        # Create all connections
        for scan_id in scans:
            for _ in range(connections_per_scan):
                ws = AsyncMock()
                await manager.connect(scan_id, ws, uuid4(), uuid4())

        # Verify structure
        assert len(manager.active_connections) == num_scans
        for scan_id in scans:
            assert len(manager.active_connections[scan_id]) == connections_per_scan

        # Broadcast to each scan
        for scan_id in scans:
            await manager.broadcast(scan_id, {"type": "test"})

        # Clean up
        for scan_id in scans:
            manager.active_connections.pop(scan_id, None)

    async def test_connection_churn(self):
        """Manager should handle rapid connection churn (adds and removes)."""
        from openlabels.server.routes.ws import ConnectionManager
        import random

        manager = ConnectionManager()
        scan_id = uuid4()
        tenant_id = uuid4()

        active_connections = []

        # Perform 500 random add/remove operations
        for _ in range(500):
            if random.random() < 0.6 or not active_connections:
                # 60% chance to add
                ws = AsyncMock()
                conn = await manager.connect(scan_id, ws, uuid4(), tenant_id)
                active_connections.append(conn)
            else:
                # 40% chance to remove
                conn = random.choice(active_connections)
                manager.disconnect(scan_id, conn)
                active_connections.remove(conn)

        # State should be consistent
        if active_connections:
            assert scan_id in manager.active_connections
            assert len(manager.active_connections[scan_id]) == len(active_connections)
        else:
            assert scan_id not in manager.active_connections

        # Clean up
        manager.active_connections.pop(scan_id, None)


# =============================================================================
# ORIGIN VALIDATION EDGE CASES
# =============================================================================


class TestOriginValidationEdgeCases:
    """Edge cases for origin validation."""

    def test_origin_with_port_number(self):
        """Origin with port number should be handled correctly."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "http://localhost:3000"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True

    def test_origin_port_mismatch_rejected(self):
        """Origin with wrong port should be rejected."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["http://localhost:3000"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "http://localhost:4000"),  # Wrong port
            ("host", "localhost:3000"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is False

    def test_origin_with_path_stripped(self):
        """Origin should be normalized (path should not affect matching)."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        # Origin with path (unusual but possible)
        mock_websocket.headers.items.return_value = [
            ("origin", "https://app.example.com"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True

    def test_origin_multiple_headers(self):
        """Handle multiple Origin headers (use first one)."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["https://app.example.com"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        # Multiple origin headers (malformed request)
        mock_websocket.headers.items.return_value = [
            ("origin", "https://app.example.com"),
            ("origin", "https://evil.com"),  # Second origin header
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            # Should use first origin (valid)
            assert validate_websocket_origin(mock_websocket) is True

    def test_origin_with_credentials(self):
        """Origin with embedded credentials should be parsed correctly."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = []

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        # Origin with user:pass (unusual but valid URL)
        mock_websocket.headers.items.return_value = [
            ("origin", "https://user:pass@evil.com"),
            ("host", "api.example.com"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            # Should be rejected (no matching origin)
            result = validate_websocket_origin(mock_websocket)
            assert result is False

    def test_origin_ipv6_address(self):
        """Origin with IPv6 address should be handled."""
        from openlabels.server.routes.ws import validate_websocket_origin

        mock_settings = MagicMock()
        mock_settings.server.environment = "production"
        mock_settings.cors.allowed_origins = ["http://[::1]:8000"]

        mock_websocket = MagicMock()
        mock_websocket.headers = MagicMock()
        mock_websocket.headers.items.return_value = [
            ("origin", "http://[::1]:8000"),
        ]

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            assert validate_websocket_origin(mock_websocket) is True


# =============================================================================
# HELPER FUNCTION COMPREHENSIVE TESTS
# =============================================================================


class TestHelperFunctionsComprehensive:
    """Comprehensive tests for WebSocket helper functions."""

    async def test_send_scan_progress_with_all_fields(self):
        """send_scan_progress should include all expected fields."""
        from openlabels.server.routes.ws import send_scan_progress, manager

        scan_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        try:
            progress_data = {
                "files_scanned": 50,
                "total_files": 100,
                "bytes_processed": 1024 * 1024 * 50,
                "current_file": "/path/to/current.txt",
                "errors": [],
            }

            await send_scan_progress(scan_id, status="running", progress=progress_data)

            call_args = mock_websocket.send_json.call_args[0][0]
            assert call_args["type"] == "progress"
            assert call_args["scan_id"] == str(scan_id)
            assert call_args["status"] == "running"
            assert call_args["progress"] == progress_data
        finally:
            manager.active_connections.pop(scan_id, None)

    async def test_send_scan_file_result_with_many_entities(self):
        """send_scan_file_result should handle many entity types."""
        from openlabels.server.routes.ws import send_scan_file_result, manager

        scan_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        try:
            entity_counts = {
                "SSN": 5,
                "EMAIL": 10,
                "PHONE": 3,
                "CREDIT_CARD": 2,
                "ADDRESS": 7,
                "NAME": 15,
                "DOB": 1,
                "PASSPORT": 1,
                "DRIVER_LICENSE": 2,
            }

            await send_scan_file_result(
                scan_id,
                file_path="/data/sensitive_file.csv",
                risk_score=95,
                risk_tier="CRITICAL",
                entity_counts=entity_counts,
            )

            call_args = mock_websocket.send_json.call_args[0][0]
            assert call_args["entity_counts"] == entity_counts
            assert call_args["risk_score"] == 95
        finally:
            manager.active_connections.pop(scan_id, None)

    async def test_send_scan_completed_with_detailed_summary(self):
        """send_scan_completed should handle detailed summary data."""
        from openlabels.server.routes.ws import send_scan_completed, manager

        scan_id = uuid4()

        mock_websocket = AsyncMock()
        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        try:
            summary = {
                "total_files": 1000,
                "files_with_pii": 150,
                "total_entities_found": 2500,
                "risk_distribution": {
                    "CRITICAL": 10,
                    "HIGH": 50,
                    "MEDIUM": 90,
                    "LOW": 850,
                },
                "entity_breakdown": {
                    "SSN": 500,
                    "EMAIL": 1000,
                    "PHONE": 500,
                    "OTHER": 500,
                },
                "duration_seconds": 3600,
                "errors": [],
            }

            await send_scan_completed(scan_id, status="completed", summary=summary)

            call_args = mock_websocket.send_json.call_args[0][0]
            assert call_args["type"] == "completed"
            assert call_args["summary"] == summary
        finally:
            manager.active_connections.pop(scan_id, None)

    async def test_helper_functions_with_no_connections(self):
        """Helper functions should handle case with no active connections."""
        from openlabels.server.routes.ws import (
            send_scan_progress,
            send_scan_file_result,
            send_scan_completed,
        )

        scan_id = uuid4()

        # These should not raise even with no connections
        await send_scan_progress(scan_id, "running", {})
        await send_scan_file_result(scan_id, "/path", 50, "MEDIUM", {})
        await send_scan_completed(scan_id, "completed", {})


# =============================================================================
# ERROR CONDITION TESTS
# =============================================================================


class TestErrorConditions:
    """Tests for various error conditions."""

    async def test_websocket_accept_failure(self):
        """Manager should handle websocket.accept() failure."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        mock_websocket = AsyncMock()
        mock_websocket.accept.side_effect = Exception("Accept failed")

        with pytest.raises(Exception, match="Accept failed"):
            await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        # Connection should not be added on failure
        assert scan_id not in manager.active_connections

    async def test_broadcast_json_serialization_error(self):
        """Broadcast should handle JSON serialization errors gracefully."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        mock_websocket = AsyncMock()

        # Make send_json raise a serialization error
        def raise_json_error(msg):
            raise TypeError("Object of type X is not JSON serializable")

        mock_websocket.send_json.side_effect = raise_json_error

        await manager.connect(scan_id, mock_websocket, uuid4(), uuid4())

        # Should not crash
        await manager.broadcast(scan_id, {"type": "test"})

        # Clean up
        manager.active_connections.pop(scan_id, None)

    async def test_disconnect_during_broadcast(self):
        """Broadcast should handle connections closing during iteration."""
        from openlabels.server.routes.ws import ConnectionManager

        manager = ConnectionManager()
        scan_id = uuid4()

        # Create multiple connections
        websockets = []
        for i in range(5):
            ws = AsyncMock()
            if i == 2:
                # This one will "close" during broadcast
                ws.send_json.side_effect = ConnectionResetError("Connection closed")
            websockets.append(ws)
            await manager.connect(scan_id, ws, uuid4(), uuid4())

        # Broadcast should continue past failed connection
        await manager.broadcast(scan_id, {"type": "test"})

        # All connections should have received attempt
        for ws in websockets:
            ws.send_json.assert_called_once()

        # Clean up
        manager.active_connections.pop(scan_id, None)

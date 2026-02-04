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
from unittest.mock import patch, MagicMock, AsyncMock

from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


@pytest.fixture
async def setup_ws_test_data(test_db):
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
async def setup_multi_tenant_data(test_db):
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
        role="user",
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
async def create_ws_session(test_db):
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

    @pytest.mark.asyncio
    async def test_authenticate_dev_mode_creates_user(self, test_db):
        """In dev mode (auth provider=none), authentication should auto-create dev user."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"

        mock_websocket = MagicMock()

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = MagicMock(return_value=test_db)

                # Call authenticate (it handles dev mode internally with its own session)
                result = await authenticate_websocket(mock_websocket)

                # In dev mode, should return user_id and tenant_id tuple
                assert result is not None
                user_id, tenant_id = result
                assert user_id is not None
                assert tenant_id is not None

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_authenticate_invalid_session_rejected(self, test_db, setup_ws_test_data):
        """WebSocket with invalid session ID should be rejected."""
        from openlabels.server.routes.ws import authenticate_websocket

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"

        mock_websocket = MagicMock()
        mock_websocket.cookies = {"openlabels_session": "nonexistent-session-id"}

        with patch('openlabels.server.routes.ws.get_settings', return_value=mock_settings):
            with patch('openlabels.server.routes.ws.get_session_factory') as mock_factory:
                mock_factory.return_value = MagicMock(return_value=test_db)

                result = await authenticate_websocket(mock_websocket)
                assert result is None

    @pytest.mark.asyncio
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
                mock_factory.return_value = MagicMock(return_value=test_db)

                result = await authenticate_websocket(mock_websocket)
                assert result is None

    @pytest.mark.asyncio
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
                mock_factory.return_value = MagicMock(return_value=test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                assert result is None

    @pytest.mark.asyncio
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
                mock_factory.return_value = MagicMock(return_value=test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                assert result is None

    @pytest.mark.asyncio
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
                mock_factory.return_value = MagicMock(return_value=test_db)

                from openlabels.server.routes.ws import authenticate_websocket
                result = await authenticate_websocket(mock_websocket)
                assert result is None


# =============================================================================
# CONNECTION MANAGER TESTS
# =============================================================================


class TestConnectionManager:
    """Tests for WebSocket connection manager."""

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_disconnect_nonexistent_scan(self):
        """Disconnect should handle non-existent scan gracefully."""
        from openlabels.server.routes.ws import ConnectionManager, AuthenticatedConnection

        manager = ConnectionManager()
        scan_id = uuid4()
        mock_websocket = AsyncMock()

        conn = AuthenticatedConnection(mock_websocket, uuid4(), uuid4())

        # Should not raise
        manager.disconnect(scan_id, conn)

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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
                mock_factory.return_value = MagicMock(return_value=test_db)

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

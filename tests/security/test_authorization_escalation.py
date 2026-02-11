"""
Tests for authorization and privilege escalation.

These tests verify that users cannot perform actions
beyond their assigned permissions (vertical privilege escalation)
and cannot access other users' resources (horizontal privilege escalation).
"""

import pytest
from uuid import uuid4

from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, MagicMock
from openlabels.server.app import app
from openlabels.server.db import get_session
from openlabels.server.dependencies import get_db_session
from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin, CurrentUser
from openlabels.server.models import Tenant, User, ScanTarget, ScanJob


@pytest.fixture
async def viewer_client(test_db):
    """Create a test client authenticated as a viewer (read-only) user."""
    import random
    import string
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    # Create test tenant and user in the database
    test_tenant = Tenant(
        name=f"Viewer Test Tenant {suffix}",
        azure_tenant_id=f"viewer-test-tenant-id-{suffix}",
    )
    test_db.add(test_tenant)
    await test_db.flush()

    # Create an admin user for creating targets
    admin_user = User(
        tenant_id=test_tenant.id,
        email=f"admin-{suffix}@localhost",
        name=f"Admin User {suffix}",
        role="admin",
    )
    test_db.add(admin_user)
    await test_db.flush()

    # Create a viewer user
    viewer_user = User(
        tenant_id=test_tenant.id,
        email=f"viewer-{suffix}@localhost",
        name=f"Viewer User {suffix}",
        role="viewer",
    )
    test_db.add(viewer_user)

    # Create a target owned by admin
    target = ScanTarget(
        tenant_id=test_tenant.id,
        name=f"Test Target {suffix}",
        adapter="filesystem",
        config={"path": "/test"},
        enabled=True,
        created_by=admin_user.id,
    )
    test_db.add(target)

    await test_db.commit()
    await test_db.refresh(test_tenant)
    await test_db.refresh(viewer_user)
    await test_db.refresh(admin_user)
    await test_db.refresh(target)

    async def override_get_session():
        yield test_db

    def _create_viewer_user():
        return CurrentUser(
            id=viewer_user.id,
            tenant_id=test_tenant.id,
            email=viewer_user.email,
            name=viewer_user.name,
            role="viewer",
        )

    async def override_get_current_user():
        return _create_viewer_user()

    async def override_get_optional_user():
        return _create_viewer_user()

    async def override_require_admin():
        # Viewer should fail admin check
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin access required")

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_db_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_optional_user] = override_get_optional_user
    app.dependency_overrides[require_admin] = override_require_admin

    from openlabels.server.app import limiter as app_limiter
    from openlabels.server.routes.remediation import limiter as remediation_limiter
    from openlabels.server.routes.scans import limiter as scans_limiter
    from openlabels.server.routes.auth import limiter as auth_limiter

    limiters = [app_limiter, remediation_limiter, scans_limiter, auth_limiter]
    original_states = [l.enabled for l in limiters]
    for l in limiters:
        l.enabled = False

    mock_cache = MagicMock()
    mock_cache.is_redis_connected = False
    with patch("openlabels.server.lifespan.init_db", new_callable=AsyncMock), \
         patch("openlabels.server.lifespan.close_db", new_callable=AsyncMock), \
         patch("openlabels.server.lifespan.get_cache_manager", new_callable=AsyncMock, return_value=mock_cache), \
         patch("openlabels.server.lifespan.close_cache", new_callable=AsyncMock):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://localhost") as client:
            yield client, test_tenant, viewer_user, admin_user, target, test_db

    for l, state in zip(limiters, original_states):
        l.enabled = state
    app.dependency_overrides.clear()


class TestRoleBasedAccessControl:
    """Tests for role-based access control enforcement."""

    async def test_viewer_cannot_create_targets(self, viewer_client):
        """Viewer role should not be able to create scan targets."""
        from sqlalchemy import select, func

        client, tenant, viewer, admin, target, test_db = viewer_client

        # Count targets before attempt
        count_before = (await test_db.execute(
            select(func.count(ScanTarget.id)).where(ScanTarget.tenant_id == tenant.id)
        )).scalar()

        response = await client.post(
            "/api/targets",
            json={
                "name": "Unauthorized Target",
                "adapter": "filesystem",
                "config": {"path": "/hacker"},
            },
        )
        assert response.status_code == 403, \
            f"Expected 403 for viewer creating target, got {response.status_code}"

        # CRITICAL: Verify no target was actually created in database
        count_after = (await test_db.execute(
            select(func.count(ScanTarget.id)).where(ScanTarget.tenant_id == tenant.id)
        )).scalar()
        assert count_after == count_before, \
            f"Target created despite 403! Before: {count_before}, After: {count_after}"

    async def test_viewer_cannot_start_scans(self, viewer_client):
        """Viewer role should not be able to start scans."""
        from sqlalchemy import select, func

        client, tenant, viewer, admin, target, test_db = viewer_client

        # Count scans before attempt
        count_before = (await test_db.execute(
            select(func.count(ScanJob.id)).where(ScanJob.tenant_id == tenant.id)
        )).scalar()

        response = await client.post(
            "/api/scans",
            json={"target_id": str(target.id)},
        )
        assert response.status_code == 403, \
            f"Expected 403 for viewer starting scan, got {response.status_code}"

        # CRITICAL: Verify no scan was actually created in database
        count_after = (await test_db.execute(
            select(func.count(ScanJob.id)).where(ScanJob.tenant_id == tenant.id)
        )).scalar()
        assert count_after == count_before, \
            f"Scan created despite 403! Before: {count_before}, After: {count_after}"

    async def test_viewer_cannot_delete_targets(self, viewer_client):
        """Viewer role should not be able to delete targets."""
        from sqlalchemy import select

        client, tenant, viewer, admin, target, test_db = viewer_client
        target_id = target.id

        response = await client.delete(f"/api/targets/{target.id}")
        assert response.status_code == 403, \
            f"Expected 403 for viewer deleting target, got {response.status_code}"

        # CRITICAL: Verify target still exists in database
        target_after = (await test_db.execute(
            select(ScanTarget).where(ScanTarget.id == target_id)
        )).scalar_one_or_none()
        assert target_after is not None, \
            "Target deleted despite 403 response! CRITICAL authorization bypass!"
        assert target_after.name == target.name, \
            "Target was modified despite 403 response!"

    async def test_viewer_cannot_modify_settings(self, viewer_client):
        """Viewer role should not be able to modify system settings."""
        client, tenant, viewer, admin, target, _db = viewer_client

        response = await client.post(
            "/api/settings/scan",
            json={"some_setting": "value"},
        )
        # Settings endpoints require admin role. Should return 403 for viewer.
        # 404/405 is also acceptable if the specific endpoint doesn't exist,
        # but it must NOT return 200/201/204 (success).
        assert response.status_code in (403, 404, 405), \
            f"Expected 403/404/405 for viewer modifying settings, got {response.status_code}"
        # Critically: must not be a success status
        assert response.status_code >= 400, \
            f"Viewer was able to modify settings! Got status {response.status_code}"

    async def test_admin_can_create_targets(self, test_client):
        """Admin role should be able to create targets with correct data."""
        response = await test_client.post(
            "/api/targets",
            json={
                "name": "Admin Target",
                "adapter": "filesystem",
                "config": {"path": "/admin-path"},
            },
        )
        # Admin should succeed with 201 Created
        assert response.status_code in (200, 201), \
            f"Expected 200/201 for admin creating target, got {response.status_code}"

        # Verify the target was actually created with correct data
        target_data = response.json()
        assert target_data["name"] == "Admin Target", \
            f"Target name mismatch: expected 'Admin Target', got {target_data['name']!r}"
        assert target_data["adapter"] == "filesystem", \
            f"Target adapter mismatch: expected 'filesystem', got {target_data['adapter']!r}"
        assert target_data["enabled"] is True, \
            "New target should be enabled by default"
        assert "id" in target_data, "Response should include the generated ID"

        # Verify the target is retrievable
        target_id = target_data["id"]
        get_response = await test_client.get(f"/api/targets/{target_id}")
        assert get_response.status_code == 200, \
            f"Created target not retrievable: status {get_response.status_code}"
        assert get_response.json()["name"] == "Admin Target"


class TestRoleEscalation:
    """Tests for preventing role escalation attacks."""

    async def test_cannot_self_promote_to_admin(self, viewer_client):
        """User should not be able to change their own role to admin."""
        from sqlalchemy import select

        client, tenant, viewer, admin, target, test_db = viewer_client
        viewer_id = viewer.id

        # Try to update own user to admin
        response = await client.put(
            f"/api/users/{viewer.id}",
            json={"role": "admin"},
        )
        # Should be denied - either 403 (forbidden) or 404/405
        assert response.status_code in (400, 403, 404, 405, 422), \
            f"Expected error for self-promotion, got {response.status_code}"

        # CRITICAL: Verify user role was NOT changed in database
        user_after = (await test_db.execute(
            select(User).where(User.id == viewer_id)
        )).scalar_one()
        assert user_after.role == "viewer", \
            f"PRIVILEGE ESCALATION: User role changed to '{user_after.role}' despite error response!"

    async def test_viewer_cannot_create_admin_users(self, viewer_client):
        """Viewer should not be able to create users with admin role."""
        from sqlalchemy import select

        client, tenant, viewer, admin, target, test_db = viewer_client

        response = await client.post(
            "/api/users",
            json={
                "email": "hacker@evil.com",
                "name": "Hacker",
                "role": "admin",
            },
        )
        # Should be denied
        assert response.status_code in (403, 404, 405), \
            f"Expected error for viewer creating admin, got {response.status_code}"

        # CRITICAL: Verify no hacker user was created in database
        hacker_user = (await test_db.execute(
            select(User).where(User.email == "hacker@evil.com")
        )).scalar_one_or_none()
        assert hacker_user is None, \
            "Admin user created despite error response! CRITICAL authorization bypass!"


class TestAuthenticationBypass:
    """Tests for authentication bypass attempts."""

    async def test_missing_auth_header_rejected(self, test_db):
        """Requests without authentication should be rejected in production mode."""
        from unittest.mock import patch, MagicMock
        from openlabels.server.config import get_settings

        # Mock settings to simulate production auth mode
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            with patch('openlabels.auth.dependencies.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://localhost") as client:
                    response = await client.get("/api/dashboard/stats")
                    # Should be 401 Unauthorized or redirect to login
                    assert response.status_code in (401, 302, 307), \
                        f"Expected 401 for unauthenticated request, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.skip(reason="Requires full Azure AD configuration to test token validation")
    async def test_invalid_bearer_token_rejected(self, test_db):
        """Invalid JWT tokens should be rejected in production mode."""
        from unittest.mock import patch, MagicMock

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            with patch('openlabels.auth.dependencies.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://localhost") as client:
                    response = await client.get(
                        "/api/dashboard/stats",
                        headers={"Authorization": "Bearer invalid.token.here"},
                    )
                    # Should be 401 Unauthorized
                    assert response.status_code in (401, 302, 307), \
                        f"Expected 401 for invalid token, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()

    async def test_malformed_auth_header_rejected(self, test_db):
        """Malformed authorization headers should be rejected in production mode."""
        from unittest.mock import patch, MagicMock

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            with patch('openlabels.auth.dependencies.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://localhost") as client:
                    # Test various malformed headers
                    malformed_headers = [
                        {"Authorization": "NotBearer token"},
                        {"Authorization": "Bearer"},  # Missing token
                        {"Authorization": ""},
                    ]

                    for headers in malformed_headers:
                        response = await client.get("/api/dashboard/stats", headers=headers)
                        assert response.status_code in (401, 302, 307), \
                            f"Expected 401 for malformed header {headers}, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()


class TestSessionSecurity:
    """Tests for session security."""

    async def test_user_sees_own_context(self, test_client):
        """User should see their own context via /users/me."""
        response = await test_client.get("/api/users/me")
        # The /users/me endpoint should be accessible to authenticated users
        assert response.status_code == 200, \
            f"Expected 200 for /users/me, got {response.status_code}"

        user_data = response.json()
        # Should be the test user created by test_client fixture
        # Email format: test-{suffix}@localhost
        email = user_data.get("email", "")
        assert email.startswith("test") and "@localhost" in email, \
            f"Expected test user email pattern 'test-*@localhost', got: {email!r}"
        assert "id" in user_data, "User context should include id"
        assert user_data.get("role") == "admin", \
            f"Test user should have admin role, got: {user_data.get('role')!r}"


class TestAPIKeyAuthentication:
    """Tests for API key authentication (if implemented)."""

    async def test_random_api_key_rejected(self, test_db):
        """Random API keys should be rejected in production mode."""
        from unittest.mock import patch, MagicMock

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"

        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            with patch('openlabels.auth.dependencies.get_settings', return_value=mock_settings):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://localhost") as client:
                    response = await client.get(
                        "/api/dashboard/stats",
                        headers={"X-API-Key": "random-fake-api-key"},
                    )
                    # Should be 401 (requires proper auth) or handled
                    assert response.status_code in (401, 302, 307, 403), \
                        f"Expected auth error for fake API key, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()


class TestVerticalPrivilegeEscalation:
    """Tests specifically for vertical privilege escalation."""

    async def test_viewer_cannot_access_admin_endpoints(self, viewer_client):
        """Viewer should not access admin-only endpoints."""
        client, tenant, viewer, admin, target, _db = viewer_client

        admin_endpoints = [
            ("POST", "/api/targets", {}),
            ("DELETE", f"/api/targets/{target.id}", None),
            ("POST", "/api/scans", {"target_id": str(target.id)}),
            ("POST", "/api/schedules", {}),
        ]

        for method, endpoint, json_data in admin_endpoints:
            if method == "POST":
                response = await client.post(endpoint, json=json_data or {})
            elif method == "DELETE":
                response = await client.delete(endpoint)
            else:
                response = await client.request(method, endpoint)

            # All admin endpoints should return 403 for viewers
            assert response.status_code in (403, 404, 422), \
                f"Viewer accessed {method} {endpoint} with status {response.status_code}"

    async def test_viewer_can_access_read_endpoints(self, viewer_client):
        """Viewer should be able to access read-only endpoints."""
        client, tenant, viewer, admin, target, _db = viewer_client

        read_endpoints = [
            "/api/dashboard/stats",
            "/api/scans",
            "/api/results",
            "/api/targets",
        ]

        for endpoint in read_endpoints:
            response = await client.get(endpoint)
            assert response.status_code == 200, \
                f"Viewer denied access to read endpoint {endpoint}"

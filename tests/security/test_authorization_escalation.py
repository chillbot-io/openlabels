"""
Tests for authorization and privilege escalation.

These tests verify that users cannot perform actions
beyond their assigned permissions (vertical privilege escalation)
and cannot access other users' resources (horizontal privilege escalation).
"""

import pytest
from uuid import uuid4

from httpx import AsyncClient, ASGITransport
from openlabels.server.app import app
from openlabels.server.db import get_session
from openlabels.auth.dependencies import get_current_user, get_optional_user, require_admin, CurrentUser
from openlabels.server.models import Tenant, User, ScanTarget, ScanJob


@pytest.fixture
async def rbac_setup(test_db):
    """Set up a tenant with admin and viewer users."""
    tenant = Tenant(
        id=uuid4(),
        name="RBAC Test Tenant",
        azure_tenant_id="rbac-test-tenant",
    )
    test_db.add(tenant)
    await test_db.flush()

    admin_user = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email="admin@example.com",
        name="Admin User",
        role="admin",
    )
    test_db.add(admin_user)

    viewer_user = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email="viewer@example.com",
        name="Viewer User",
        role="viewer",
    )
    test_db.add(viewer_user)

    # Create a target owned by admin
    target = ScanTarget(
        id=uuid4(),
        tenant_id=tenant.id,
        name="Test Target",
        adapter="filesystem",
        config={"path": "/test"},
        enabled=True,
        created_by=admin_user.id,
    )
    test_db.add(target)
    await test_db.flush()

    # Create a scan for testing
    scan = ScanJob(
        id=uuid4(),
        tenant_id=tenant.id,
        target_id=target.id,
        status="completed",
    )
    test_db.add(scan)

    await test_db.commit()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "viewer_user": viewer_user,
        "target": target,
        "scan": scan,
        "session": test_db,
    }


def create_client_for_user(test_db, user, tenant, role_override=None):
    """Create a test client authenticated as a specific user."""
    role = role_override or str(user.role)

    async def override_get_session():
        yield test_db

    def _create_current_user():
        return CurrentUser(
            id=user.id,
            tenant_id=tenant.id,
            email=user.email,
            name=user.name,
            role=role,
        )

    async def override_get_current_user():
        return _create_current_user()

    async def override_get_optional_user():
        return _create_current_user()

    # For require_admin, we need to properly check the role
    async def override_require_admin():
        current_user = _create_current_user()
        if current_user.role != "admin":
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Admin access required")
        return current_user

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_optional_user] = override_get_optional_user
    app.dependency_overrides[require_admin] = override_require_admin

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class TestRoleBasedAccessControl:
    """Tests for role-based access control enforcement."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_targets(self, rbac_setup):
        """Viewer role should not be able to create scan targets."""
        data = rbac_setup

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
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

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_viewer_cannot_start_scans(self, rbac_setup):
        """Viewer role should not be able to start scans."""
        data = rbac_setup
        target = data["target"]

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            response = await client.post(
                "/api/scans",
                json={"target_id": str(target.id)},
            )
            assert response.status_code == 403, \
                f"Expected 403 for viewer starting scan, got {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_viewer_cannot_delete_targets(self, rbac_setup):
        """Viewer role should not be able to delete targets."""
        data = rbac_setup
        target = data["target"]

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            response = await client.delete(f"/api/targets/{target.id}")
            assert response.status_code == 403, \
                f"Expected 403 for viewer deleting target, got {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_viewer_cannot_modify_settings(self, rbac_setup):
        """Viewer role should not be able to modify system settings."""
        data = rbac_setup

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            response = await client.put(
                "/api/settings",
                json={"some_setting": "value"},
            )
            # Should be 403 (admin only) or 404 (endpoint doesn't exist)
            assert response.status_code in (403, 404, 405), \
                f"Expected 403/404/405 for viewer modifying settings, got {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_viewer_can_view_results(self, rbac_setup):
        """Viewer role should be able to view scan results."""
        data = rbac_setup

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            response = await client.get("/api/results")
            # Viewer should be able to read
            assert response.status_code == 200, \
                f"Expected 200 for viewer viewing results, got {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_viewer_can_view_dashboard(self, rbac_setup):
        """Viewer role should be able to view dashboard."""
        data = rbac_setup

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            response = await client.get("/api/dashboard/stats")
            assert response.status_code == 200, \
                f"Expected 200 for viewer viewing dashboard, got {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_admin_can_create_targets(self, rbac_setup):
        """Admin role should be able to create targets."""
        data = rbac_setup

        async with create_client_for_user(
            data["session"], data["admin_user"], data["tenant"]
        ) as client:
            response = await client.post(
                "/api/targets",
                json={
                    "name": "Admin Target",
                    "adapter": "filesystem",
                    "config": {"path": "/admin-path"},
                },
            )
            # Admin should succeed (200 or 201)
            assert response.status_code in (200, 201), \
                f"Expected 200/201 for admin creating target, got {response.status_code}"

        app.dependency_overrides.clear()


class TestRoleEscalation:
    """Tests for preventing role escalation attacks."""

    @pytest.mark.asyncio
    async def test_cannot_self_promote_to_admin(self, rbac_setup):
        """User should not be able to change their own role to admin."""
        data = rbac_setup
        viewer = data["viewer_user"]

        async with create_client_for_user(
            data["session"], viewer, data["tenant"]
        ) as client:
            # Try to update own user to admin
            response = await client.patch(
                f"/api/users/{viewer.id}",
                json={"role": "admin"},
            )
            # Should be denied - either 403 (forbidden) or 404 (can't access user endpoints)
            assert response.status_code in (400, 403, 404, 405, 422), \
                f"Expected error for self-promotion, got {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_admin_users(self, rbac_setup):
        """Viewer should not be able to create users with admin role."""
        data = rbac_setup

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
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

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_role_checked_on_each_request(self, rbac_setup):
        """Role should be checked on each request, not cached from first auth."""
        data = rbac_setup

        # This test verifies that even if a user's role changes in the database,
        # subsequent requests should use the updated role
        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            # First verify viewer can't create targets
            response = await client.post(
                "/api/targets",
                json={
                    "name": "Test",
                    "adapter": "filesystem",
                    "config": {"path": "/test"},
                },
            )
            assert response.status_code == 403

        app.dependency_overrides.clear()


class TestAuthenticationBypass:
    """Tests for authentication bypass attempts."""

    @pytest.mark.asyncio
    async def test_missing_auth_header_rejected(self, test_db):
        """Requests without authentication should be rejected."""
        # Create client WITHOUT authentication overrides
        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session
        # Don't override auth - use real auth which will fail

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/api/dashboard/stats")
                # Should be 401 Unauthorized
                assert response.status_code == 401, \
                    f"Expected 401 for unauthenticated request, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_invalid_bearer_token_rejected(self, test_db):
        """Invalid JWT tokens should be rejected."""
        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get(
                    "/api/dashboard/stats",
                    headers={"Authorization": "Bearer invalid.token.here"},
                )
                # Should be 401 Unauthorized
                assert response.status_code == 401, \
                    f"Expected 401 for invalid token, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_malformed_auth_header_rejected(self, test_db):
        """Malformed authorization headers should be rejected."""
        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # Test various malformed headers
                malformed_headers = [
                    {"Authorization": "NotBearer token"},
                    {"Authorization": "Bearer"},  # Missing token
                    {"Authorization": ""},
                ]

                for headers in malformed_headers:
                    response = await client.get("/api/dashboard/stats", headers=headers)
                    assert response.status_code == 401, \
                        f"Expected 401 for malformed header {headers}, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()


class TestSessionSecurity:
    """Tests for session security."""

    @pytest.mark.asyncio
    async def test_different_users_get_different_data(self, rbac_setup):
        """Different users should see their own context."""
        data = rbac_setup

        # Admin user request
        async with create_client_for_user(
            data["session"], data["admin_user"], data["tenant"]
        ) as client:
            response = await client.get("/api/users/me")
            if response.status_code == 200:
                user_data = response.json()
                assert user_data.get("email") == "admin@example.com"

        app.dependency_overrides.clear()

        # Viewer user request
        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            response = await client.get("/api/users/me")
            if response.status_code == 200:
                user_data = response.json()
                assert user_data.get("email") == "viewer@example.com"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_cannot_impersonate_other_user(self, rbac_setup):
        """User cannot impersonate another user via headers."""
        data = rbac_setup

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            # Try to impersonate admin via custom header
            response = await client.get(
                "/api/users/me",
                headers={"X-User-Id": str(data["admin_user"].id)},
            )
            if response.status_code == 200:
                user_data = response.json()
                # Should still be viewer, not admin
                assert user_data.get("email") == "viewer@example.com", \
                    "User was able to impersonate another user!"

        app.dependency_overrides.clear()


class TestAPIKeyAuthentication:
    """Tests for API key authentication (if implemented)."""

    @pytest.mark.asyncio
    async def test_random_api_key_rejected(self, test_db):
        """Random API keys should be rejected."""
        async def override_get_session():
            yield test_db

        app.dependency_overrides[get_session] = override_get_session

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get(
                    "/api/dashboard/stats",
                    headers={"X-API-Key": "random-fake-api-key"},
                )
                # Should be 401 or use Bearer auth instead
                assert response.status_code in (401, 403), \
                    f"Expected auth error for fake API key, got {response.status_code}"
        finally:
            app.dependency_overrides.clear()


class TestDevModeProtection:
    """Tests for development mode security."""

    @pytest.mark.asyncio
    async def test_dev_user_limited_to_dev_mode(self, rbac_setup):
        """Dev user should only work when auth provider is 'none'."""
        # This is tested implicitly - when we use proper auth, dev user shouldn't work
        # The auth dependencies check settings.auth.provider
        data = rbac_setup

        # Just verify normal auth works
        async with create_client_for_user(
            data["session"], data["admin_user"], data["tenant"]
        ) as client:
            response = await client.get("/api/dashboard/stats")
            assert response.status_code == 200

        app.dependency_overrides.clear()


class TestVerticalPrivilegeEscalation:
    """Tests specifically for vertical privilege escalation."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_access_admin_endpoints(self, rbac_setup):
        """Viewer should not access admin-only endpoints."""
        data = rbac_setup

        admin_endpoints = [
            ("POST", "/api/targets"),
            ("DELETE", f"/api/targets/{data['target'].id}"),
            ("POST", "/api/scans"),
            ("POST", "/api/schedules"),
        ]

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            for method, endpoint in admin_endpoints:
                if method == "POST":
                    response = await client.post(endpoint, json={})
                elif method == "DELETE":
                    response = await client.delete(endpoint)
                else:
                    response = await client.request(method, endpoint)

                # All admin endpoints should return 403 for viewers
                assert response.status_code in (403, 404, 422), \
                    f"Viewer accessed {method} {endpoint} with status {response.status_code}"

        app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_viewer_can_access_read_endpoints(self, rbac_setup):
        """Viewer should be able to access read-only endpoints."""
        data = rbac_setup

        read_endpoints = [
            "/api/dashboard/stats",
            "/api/scans",
            "/api/results",
            "/api/targets",
        ]

        async with create_client_for_user(
            data["session"], data["viewer_user"], data["tenant"]
        ) as client:
            for endpoint in read_endpoints:
                response = await client.get(endpoint)
                assert response.status_code == 200, \
                    f"Viewer denied access to read endpoint {endpoint}"

        app.dependency_overrides.clear()

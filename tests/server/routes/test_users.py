"""
Comprehensive tests for users API endpoints.

Tests focus on:
- User listing with pagination
- User creation with validation
- User retrieval by ID
- User updates
- User deletion
- Admin authorization requirements
- Tenant isolation
- Self-deletion prevention
"""

import pytest
from uuid import uuid4


@pytest.fixture
async def setup_users_data(test_db):
    """Set up test data for user endpoint tests."""
    from sqlalchemy import select
    from openlabels.server.models import Tenant, User

    # Get the existing tenant created by test_client
    result = await test_db.execute(select(Tenant).where(Tenant.name.like("Test Tenant%")))
    tenant = result.scalar_one()

    result = await test_db.execute(select(User).where(User.tenant_id == tenant.id))
    admin_user = result.scalar_one()

    return {
        "tenant": tenant,
        "admin_user": admin_user,
        "session": test_db,
    }


class TestListUsers:
    """Tests for GET /api/users endpoint."""

    async def test_includes_test_user(self, test_client, setup_users_data):
        """List should include the test user."""
        response = await test_client.get("/api/users")
        assert response.status_code == 200
        data = response.json()
        items = data["items"]

        # Should have at least the test user
        assert len(items) >= 1
        emails = [u["email"] for u in items]
        # Test user email format: test-{suffix}@localhost
        test_user_found = any(
            e.startswith("test") and "@localhost" in e for e in emails
        )
        assert test_user_found, f"Test user not found in emails: {emails}"

    async def test_user_response_structure(self, test_client, setup_users_data):
        """User response should have all required fields."""
        response = await test_client.get("/api/users")
        assert response.status_code == 200
        data = response.json()

        user = data["items"][0]
        assert "id" in user
        assert "email" in user
        assert "name" in user
        assert "role" in user
        assert "created_at" in user

    async def test_pagination_default(self, test_client, setup_users_data):
        """List should use default pagination."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        # Add many users (flush after each to avoid asyncpg sentinel issues)
        for i in range(60):
            user = User(
                tenant_id=tenant.id,
                email=f"user{i}@test.com",
                name=f"User {i}",
                role="viewer",
            )
            session.add(user)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/users")
        assert response.status_code == 200
        data = response.json()

        # Default page_size is 50
        assert len(data["items"]) <= 50

    async def test_pagination_custom_limit(self, test_client, setup_users_data):
        """List should respect custom page_size."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        # Add users (flush after each to avoid asyncpg sentinel issues)
        for i in range(20):
            user = User(
                tenant_id=tenant.id,
                email=f"paginated{i}@test.com",
                name=f"Paginated User {i}",
                role="viewer",
            )
            session.add(user)
            await session.flush()
        await session.commit()

        response = await test_client.get("/api/users?page_size=5")
        assert response.status_code == 200
        data = response.json()

        assert len(data["items"]) == 5

    async def test_pagination_page_parameter(self, test_client, setup_users_data):
        """List should respect page parameter."""
        response = await test_client.get("/api/users?page=1&page_size=10")
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        data = response.json()
        assert "items" in data, "Response should be paginated"
        assert len(data["items"]) <= 10, "Response should respect the page_size parameter"

    async def test_pagination_validation_min_page(self, test_client, setup_users_data):
        """Page parameter should be >= 1."""
        response = await test_client.get("/api/users?page=0")
        assert response.status_code == 422  # Validation error

    async def test_pagination_validation_min_limit(self, test_client, setup_users_data):
        """page_size parameter should be >= 1."""
        response = await test_client.get("/api/users?page_size=0")
        assert response.status_code == 422  # Validation error

    async def test_pagination_validation_max_limit(self, test_client, setup_users_data):
        """page_size parameter should be <= 100."""
        response = await test_client.get("/api/users?page_size=200")
        assert response.status_code == 422  # Validation error


class TestCreateUser:
    """Tests for POST /api/users endpoint."""

    async def test_returns_created_user(self, test_client, setup_users_data):
        """Create user should return 201 with the created user details."""
        response = await test_client.post(
            "/api/users",
            json={
                "email": "created@test.com",
                "name": "Created User",
                "role": "viewer",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["email"] == "created@test.com"
        assert data["name"] == "Created User"
        assert data["role"] == "viewer"
        assert "id" in data
        assert "created_at" in data

    async def test_create_admin_user(self, test_client, setup_users_data):
        """Should be able to create admin user."""
        response = await test_client.post(
            "/api/users",
            json={
                "email": "admin@test.com",
                "name": "Admin User",
                "role": "admin",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["role"] == "admin"

    async def test_create_user_default_role(self, test_client, setup_users_data):
        """User creation should default to viewer role."""
        response = await test_client.post(
            "/api/users",
            json={
                "email": "default-role@test.com",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["role"] == "viewer"

    async def test_create_user_without_name(self, test_client, setup_users_data):
        """User can be created without name."""
        response = await test_client.post(
            "/api/users",
            json={
                "email": "noname@test.com",
                "role": "viewer",
            },
        )
        assert response.status_code == 201
        data = response.json()

        assert data["name"] is None

    async def test_create_duplicate_email_returns_409(self, test_client, setup_users_data):
        """Creating user with duplicate email should return 409."""
        # First creation
        await test_client.post(
            "/api/users",
            json={"email": "duplicate@test.com"},
        )

        # Duplicate
        response = await test_client.post(
            "/api/users",
            json={"email": "duplicate@test.com"},
        )
        assert response.status_code == 409

    async def test_create_user_invalid_email(self, test_client, setup_users_data):
        """Creating user with invalid email should return 422."""
        response = await test_client.post(
            "/api/users",
            json={
                "email": "not-an-email",
                "role": "viewer",
            },
        )
        assert response.status_code == 422

    async def test_create_user_invalid_role(self, test_client, setup_users_data):
        """Creating user with invalid role should return 422."""
        response = await test_client.post(
            "/api/users",
            json={
                "email": "invalid-role@test.com",
                "role": "superuser",  # Invalid
            },
        )
        assert response.status_code == 422

    async def test_create_user_missing_email(self, test_client, setup_users_data):
        """Creating user without email should return 422."""
        response = await test_client.post(
            "/api/users",
            json={
                "name": "No Email User",
                "role": "viewer",
            },
        )
        assert response.status_code == 422


class TestGetUser:
    """Tests for GET /api/users/{user_id} endpoint."""

    async def test_returns_user_details(self, test_client, setup_users_data):
        """Get user should return 200 with all user fields."""
        admin_user = setup_users_data["admin_user"]

        response = await test_client.get(f"/api/users/{admin_user.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == str(admin_user.id)
        assert data["email"] == admin_user.email
        assert "name" in data
        assert "role" in data
        assert "created_at" in data

    async def test_returns_404_for_nonexistent_user(self, test_client, setup_users_data):
        """Get nonexistent user should return 404."""
        fake_id = uuid4()
        response = await test_client.get(f"/api/users/{fake_id}")
        assert response.status_code == 404

    async def test_returns_404_for_invalid_uuid(self, test_client, setup_users_data):
        """Get user with invalid UUID should return 422."""
        response = await test_client.get("/api/users/not-a-uuid")
        assert response.status_code == 422


class TestUpdateUser:
    """Tests for PUT /api/users/{user_id} endpoint."""

    async def test_updates_name(self, test_client, setup_users_data):
        """Update user should return 200 and update name."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        user = User(
            tenant_id=tenant.id,
            email="update-name@test.com",
            name="Original",
            role="viewer",
        )
        session.add(user)
        await session.commit()

        response = await test_client.put(
            f"/api/users/{user.id}",
            json={"name": "New Name"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "New Name"

    async def test_updates_role(self, test_client, setup_users_data):
        """Update user should update role."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        user = User(
            tenant_id=tenant.id,
            email="update-role@test.com",
            name="Test",
            role="viewer",
        )
        session.add(user)
        await session.commit()

        response = await test_client.put(
            f"/api/users/{user.id}",
            json={"role": "admin"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["role"] == "admin"

    async def test_partial_update(self, test_client, setup_users_data):
        """Update should only change provided fields."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        user = User(
            tenant_id=tenant.id,
            email="partial@test.com",
            name="Original Name",
            role="viewer",
        )
        session.add(user)
        await session.commit()

        # Only update name
        response = await test_client.put(
            f"/api/users/{user.id}",
            json={"name": "New Name"},
        )
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "New Name"
        assert data["role"] == "viewer"  # Unchanged

    async def test_returns_404_for_nonexistent_user(self, test_client, setup_users_data):
        """Update nonexistent user should return 404."""
        fake_id = uuid4()
        response = await test_client.put(
            f"/api/users/{fake_id}",
            json={"name": "Test"},
        )
        assert response.status_code == 404

    async def test_rejects_invalid_role(self, test_client, setup_users_data):
        """Update with invalid role should return 422."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        user = User(
            tenant_id=tenant.id,
            email="invalid-role-update@test.com",
            name="Test",
            role="viewer",
        )
        session.add(user)
        await session.commit()

        response = await test_client.put(
            f"/api/users/{user.id}",
            json={"role": "superuser"},  # Invalid
        )
        assert response.status_code == 422


class TestDeleteUser:
    """Tests for DELETE /api/users/{user_id} endpoint."""

    async def test_returns_204_status(self, test_client, setup_users_data):
        """Delete user should return 204 No Content."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        user = User(
            tenant_id=tenant.id,
            email="todelete@test.com",
            name="Delete Me",
            role="viewer",
        )
        session.add(user)
        await session.commit()

        response = await test_client.delete(f"/api/users/{user.id}")
        assert response.status_code == 204

    async def test_user_is_removed(self, test_client, setup_users_data):
        """Deleted user should no longer exist."""
        from openlabels.server.models import User

        session = setup_users_data["session"]
        tenant = setup_users_data["tenant"]

        user = User(
            tenant_id=tenant.id,
            email="remove-me@test.com",
            name="Remove Me",
            role="viewer",
        )
        session.add(user)
        await session.commit()
        user_id = user.id

        # Delete
        await test_client.delete(f"/api/users/{user_id}")

        # Try to get - should be 404
        response = await test_client.get(f"/api/users/{user_id}")
        assert response.status_code == 404

    async def test_returns_404_for_nonexistent_user(self, test_client, setup_users_data):
        """Delete nonexistent user should return 404."""
        fake_id = uuid4()
        response = await test_client.delete(f"/api/users/{fake_id}")
        assert response.status_code == 404

    async def test_prevents_self_deletion(self, test_client, setup_users_data):
        """User cannot delete themselves."""
        admin_user = setup_users_data["admin_user"]

        response = await test_client.delete(f"/api/users/{admin_user.id}")
        assert response.status_code == 400
        assert "Cannot delete yourself" in response.json()["message"]


class TestUserTenantIsolation:
    """Tests for tenant isolation in user endpoints."""

    async def test_cannot_access_other_tenant_user(self, test_client, setup_users_data):
        """Should not be able to access users from other tenants."""
        from openlabels.server.models import Tenant, User

        session = setup_users_data["session"]

        # Create another tenant and user
        other_tenant = Tenant(
            name="Other Tenant",
            azure_tenant_id="other-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="other@other.com",
            name="Other User",
            role="viewer",
        )
        session.add(other_user)
        await session.commit()

        # Try to access the other tenant's user
        response = await test_client.get(f"/api/users/{other_user.id}")
        assert response.status_code == 404

    async def test_cannot_update_other_tenant_user(self, test_client, setup_users_data):
        """Should not be able to update users from other tenants."""
        from openlabels.server.models import Tenant, User

        session = setup_users_data["session"]

        other_tenant = Tenant(
            name="Update Other Tenant",
            azure_tenant_id="update-other-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="update-other@other.com",
            name="Other User",
            role="viewer",
        )
        session.add(other_user)
        await session.commit()

        response = await test_client.put(
            f"/api/users/{other_user.id}",
            json={"name": "Hacked!"},
        )
        assert response.status_code == 404

    async def test_cannot_delete_other_tenant_user(self, test_client, setup_users_data):
        """Should not be able to delete users from other tenants."""
        from openlabels.server.models import Tenant, User

        session = setup_users_data["session"]

        other_tenant = Tenant(
            name="Delete Other Tenant",
            azure_tenant_id="delete-other-tenant-id",
        )
        session.add(other_tenant)
        await session.flush()

        other_user = User(
            tenant_id=other_tenant.id,
            email="delete-other@other.com",
            name="Other User",
            role="viewer",
        )
        session.add(other_user)
        await session.commit()

        response = await test_client.delete(f"/api/users/{other_user.id}")
        assert response.status_code == 404



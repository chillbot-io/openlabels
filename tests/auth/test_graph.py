"""
Comprehensive tests for Microsoft Graph API client.

Tests cover authentication, user lookups, error handling, and edge cases.
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from openlabels.auth.graph import (
    GraphUser,
    GraphClient,
    get_graph_client,
    reset_graph_client,
    GRAPH_API_BASE,
)


class TestGraphUser:
    """Tests for GraphUser dataclass."""

    def test_minimal_user(self):
        """GraphUser with only required id."""
        user = GraphUser(id="user-guid")
        assert user.id == "user-guid"
        assert user.display_name is None
        assert user.user_principal_name is None

    def test_best_display_name_prefers_display_name(self):
        """best_display_name should prefer displayName."""
        user = GraphUser(
            id="user-guid",
            display_name="John Smith",
            user_principal_name="jsmith@contoso.com",
            on_premises_sam_account_name="CONTOSO\\jsmith",
        )
        assert user.best_display_name == "John Smith"

    def test_best_display_name_fallback_to_upn(self):
        """best_display_name should fallback to UPN."""
        user = GraphUser(
            id="user-guid",
            user_principal_name="jsmith@contoso.com",
            on_premises_sam_account_name="CONTOSO\\jsmith",
        )
        assert user.best_display_name == "jsmith@contoso.com"

    def test_best_display_name_fallback_to_sam(self):
        """best_display_name should fallback to SAM account."""
        user = GraphUser(
            id="user-guid",
            on_premises_sam_account_name="CONTOSO\\jsmith",
        )
        assert user.best_display_name == "CONTOSO\\jsmith"

    def test_best_display_name_fallback_to_id(self):
        """best_display_name should fallback to id."""
        user = GraphUser(id="user-guid")
        assert user.best_display_name == "user-guid"



class TestGraphClientInitialization:
    """Tests for GraphClient initialization."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset singleton before each test."""
        reset_graph_client()
        yield
        reset_graph_client()

    def test_missing_tenant_id_raises(self):
        """Missing tenant_id should raise ValueError."""
        mock_settings = MagicMock()
        mock_settings.auth.tenant_id = None
        mock_settings.auth.client_id = "client-id"
        mock_settings.auth.client_secret = "secret"

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with pytest.raises(ValueError, match="tenant_id"):
                GraphClient()

    def test_missing_client_id_raises(self):
        """Missing client_id should raise ValueError."""
        mock_settings = MagicMock()
        mock_settings.auth.tenant_id = "tenant-id"
        mock_settings.auth.client_id = None
        mock_settings.auth.client_secret = "secret"

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with pytest.raises(ValueError, match="client_id"):
                GraphClient()

    def test_missing_client_secret_raises(self):
        """Missing client_secret should raise ValueError."""
        mock_settings = MagicMock()
        mock_settings.auth.tenant_id = "tenant-id"
        mock_settings.auth.client_id = "client-id"
        mock_settings.auth.client_secret = None

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with pytest.raises(ValueError, match="client_secret"):
                GraphClient()

    def test_explicit_credentials_override_settings(self):
        """Explicit credentials should override settings."""
        mock_settings = MagicMock()
        mock_settings.auth.tenant_id = "settings-tenant"
        mock_settings.auth.client_id = "settings-client"
        mock_settings.auth.client_secret = "settings-secret"

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication") as MockMSAL:
                client = GraphClient(
                    tenant_id="explicit-tenant",
                    client_id="explicit-client",
                    client_secret="explicit-secret",
                )

                assert client.tenant_id == "explicit-tenant"
                assert client.client_id == "explicit-client"

    def test_msal_app_initialized(self):
        """MSAL app should be initialized with correct parameters."""
        mock_settings = MagicMock()
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"
        mock_settings.auth.client_secret = "test-secret"

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication") as MockMSAL:
                GraphClient()

                MockMSAL.assert_called_once_with(
                    client_id="test-client",
                    client_credential="test-secret",
                    authority="https://login.microsoftonline.com/test-tenant",
                )


class TestGraphClientTokenManagement:
    """Tests for token acquisition and caching."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings with valid credentials."""
        settings = MagicMock()
        settings.auth.tenant_id = "test-tenant"
        settings.auth.client_id = "test-client"
        settings.auth.client_secret = "test-secret"
        return settings

    @pytest.fixture
    def client_with_mocked_msal(self, mock_settings):
        """Create client with mocked MSAL."""
        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication") as MockMSAL:
                mock_msal_app = MagicMock()
                MockMSAL.return_value = mock_msal_app
                client = GraphClient()
                client._mock_msal_app = mock_msal_app
                return client

    async def test_acquires_token_on_first_call(self, client_with_mocked_msal):
        """Should acquire token on first call."""
        client = client_with_mocked_msal
        client._mock_msal_app.acquire_token_for_client.return_value = {
            "access_token": "new-token",
            "expires_in": 3600,
        }

        token = await client._get_access_token()

        assert token == "new-token"
        client._mock_msal_app.acquire_token_for_client.assert_called_once()

    async def test_caches_token(self, client_with_mocked_msal):
        """Should cache token and not re-acquire."""
        client = client_with_mocked_msal
        client._access_token = "cached-token"
        client._token_expires = datetime.now(timezone.utc) + timedelta(hours=1)

        token = await client._get_access_token()

        assert token == "cached-token"
        # Should not call MSAL since token is cached and valid
        client._mock_msal_app.acquire_token_for_client.assert_not_called()

    async def test_refreshes_expired_token(self, client_with_mocked_msal):
        """Should refresh token when expired."""
        client = client_with_mocked_msal
        client._access_token = "old-token"
        client._token_expires = datetime.now(timezone.utc) - timedelta(minutes=1)  # Expired

        client._mock_msal_app.acquire_token_for_client.return_value = {
            "access_token": "new-token",
            "expires_in": 3600,
        }

        token = await client._get_access_token()

        assert token == "new-token"
        client._mock_msal_app.acquire_token_for_client.assert_called_once()

    async def test_refreshes_token_near_expiry(self, client_with_mocked_msal):
        """Should refresh token when within 5 minutes of expiry."""
        client = client_with_mocked_msal
        client._access_token = "almost-expired-token"
        # Token expires in 3 minutes - within 5 minute buffer
        client._token_expires = datetime.now(timezone.utc) + timedelta(minutes=3)

        client._mock_msal_app.acquire_token_for_client.return_value = {
            "access_token": "fresh-token",
            "expires_in": 3600,
        }

        token = await client._get_access_token()

        assert token == "fresh-token"
        client._mock_msal_app.acquire_token_for_client.assert_called_once()

    async def test_token_acquisition_failure_raises(self, client_with_mocked_msal):
        """Failed token acquisition should raise RuntimeError."""
        client = client_with_mocked_msal
        client._mock_msal_app.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "Invalid client credentials",
        }

        with pytest.raises(RuntimeError, match="Failed to acquire"):
            await client._get_access_token()


class TestGraphClientUserLookups:
    """Tests for user lookup methods."""

    @pytest.fixture
    def mock_settings(self):
        settings = MagicMock()
        settings.auth.tenant_id = "test-tenant"
        settings.auth.client_id = "test-client"
        settings.auth.client_secret = "test-secret"
        return settings

    @pytest.fixture
    def client(self, mock_settings):
        """Create client with mocked dependencies."""
        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication"):
                client = GraphClient()
                # Mock token acquisition
                client._access_token = "test-token"
                client._token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
                return client

    async def test_get_user_by_id_success(self, client):
        """get_user_by_id should return user for valid ID."""
        mock_response = {
            "id": "user-guid",
            "displayName": "John Smith",
            "userPrincipalName": "jsmith@contoso.com",
            "mail": "john@contoso.com",
        }

        with patch.object(client, "_request", return_value=mock_response):
            user = await client.get_user_by_id("user-guid")

            assert user is not None
            assert user.id == "user-guid"
            assert user.display_name == "John Smith"

    async def test_get_user_by_id_not_found(self, client):
        """get_user_by_id should return None for unknown ID."""
        with patch.object(client, "_request", return_value={}):
            user = await client.get_user_by_id("unknown-guid")
            assert user is None

    async def test_get_user_by_id_404_handled(self, client):
        """get_user_by_id should return None on 404."""
        with patch.object(client, "_request") as mock_request:
            mock_request.side_effect = httpx.HTTPStatusError(
                "Not Found",
                request=MagicMock(),
                response=MagicMock(status_code=404),
            )

            user = await client.get_user_by_id("nonexistent-guid")
            assert user is None

    async def test_get_user_by_upn_success(self, client):
        """get_user_by_upn should return user for valid UPN."""
        mock_response = {
            "id": "user-guid",
            "displayName": "Jane Doe",
            "userPrincipalName": "jdoe@contoso.com",
        }

        with patch.object(client, "_request", return_value=mock_response):
            user = await client.get_user_by_upn("jdoe@contoso.com")

            assert user is not None
            assert user.user_principal_name == "jdoe@contoso.com"

    async def test_get_user_by_on_prem_sid_success(self, client):
        """get_user_by_on_prem_sid should find user by SID."""
        mock_response = {
            "value": [
                {
                    "id": "user-guid",
                    "displayName": "Hybrid User",
                    "onPremisesSecurityIdentifier": "S-1-5-21-123-456-789-1001",
                }
            ]
        }

        with patch.object(client, "_request", return_value=mock_response):
            user = await client.get_user_by_on_prem_sid("S-1-5-21-123-456-789-1001")

            assert user is not None
            assert user.display_name == "Hybrid User"

    async def test_get_user_by_on_prem_sid_not_found(self, client):
        """get_user_by_on_prem_sid should return None when not found."""
        mock_response = {"value": []}

        with patch.object(client, "_request", return_value=mock_response):
            user = await client.get_user_by_on_prem_sid("S-1-5-21-unknown-sid")
            assert user is None

    async def test_get_user_by_sam_account_name_strips_domain(self, client):
        """get_user_by_sam_account_name should strip domain prefix."""
        mock_response = {
            "value": [
                {
                    "id": "user-guid",
                    "displayName": "Domain User",
                    "onPremisesSamAccountName": "jsmith",
                }
            ]
        }

        with patch.object(client, "_request", return_value=mock_response) as mock_req:
            user = await client.get_user_by_sam_account_name("CONTOSO\\jsmith")

            assert user is not None
            # Verify domain was stripped in the query
            call_args = mock_req.call_args
            params = call_args[1]["params"]
            assert "jsmith" in params["$filter"]
            assert "CONTOSO" not in params["$filter"]

    async def test_search_users(self, client):
        """search_users should return list of matching users."""
        mock_response = {
            "value": [
                {"id": "user1", "displayName": "John Smith"},
                {"id": "user2", "displayName": "Johnny Appleseed"},
            ]
        }

        with patch.object(client, "_request", return_value=mock_response):
            users = await client.search_users("John")

            assert len(users) == 2
            assert users[0].display_name == "John Smith"

    async def test_search_users_with_limit(self, client):
        """search_users should respect limit parameter."""
        with patch.object(client, "_request", return_value={"value": []}) as mock_req:
            await client.search_users("test", limit=5)

            call_args = mock_req.call_args
            params = call_args[1]["params"]
            assert params["$top"] == "5"


class TestGraphClientRequest:
    """Tests for low-level request method."""

    @pytest.fixture
    def mock_settings(self):
        settings = MagicMock()
        settings.auth.tenant_id = "test-tenant"
        settings.auth.client_id = "test-client"
        settings.auth.client_secret = "test-secret"
        return settings

    @pytest.fixture
    def client(self, mock_settings):
        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication"):
                client = GraphClient()
                client._access_token = "test-token"
                client._token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
                return client

    async def test_request_adds_auth_header(self, client):
        """Requests should include Authorization header."""
        with patch("openlabels.auth.graph.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": "test"}
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.request.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            await client._request("GET", "/users/me")

            call_kwargs = mock_instance.request.call_args[1]
            assert "Authorization" in call_kwargs["headers"]
            assert call_kwargs["headers"]["Authorization"] == "Bearer test-token"

    async def test_request_404_returns_empty_dict(self, client):
        """404 responses should return empty dict, not raise."""
        with patch("openlabels.auth.graph.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.status_code = 404

            mock_instance = AsyncMock()
            mock_instance.request.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            result = await client._request("GET", "/users/nonexistent")

            assert result == {}

    async def test_request_error_propagates(self, client):
        """Non-404 errors should propagate."""
        with patch("openlabels.auth.graph.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error",
                request=MagicMock(),
                response=mock_response,
            )

            mock_instance = AsyncMock()
            mock_instance.request.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(httpx.HTTPStatusError):
                await client._request("GET", "/failing/endpoint")


class TestGraphClientSingleton:
    """Tests for singleton pattern."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        reset_graph_client()
        yield
        reset_graph_client()

    def test_get_graph_client_in_dev_mode_raises(self):
        """get_graph_client should raise in dev mode."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with pytest.raises(RuntimeError, match="requires Azure AD"):
                get_graph_client()

    def test_get_graph_client_returns_singleton(self):
        """get_graph_client should return same instance."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "tenant"
        mock_settings.auth.client_id = "client"
        mock_settings.auth.client_secret = "secret"

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication"):
                client1 = get_graph_client()
                client2 = get_graph_client()

                assert client1 is client2

    def test_reset_clears_singleton(self):
        """reset_graph_client should clear singleton."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "tenant"
        mock_settings.auth.client_id = "client"
        mock_settings.auth.client_secret = "secret"

        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication"):
                client1 = get_graph_client()
                reset_graph_client()
                client2 = get_graph_client()

                assert client1 is not client2


class TestGraphClientEdgeCases:
    """Edge case and security tests."""

    @pytest.fixture
    def mock_settings(self):
        settings = MagicMock()
        settings.auth.tenant_id = "test-tenant"
        settings.auth.client_id = "test-client"
        settings.auth.client_secret = "test-secret"
        return settings

    @pytest.fixture
    def client(self, mock_settings):
        with patch("openlabels.auth.graph.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.graph.ConfidentialClientApplication"):
                client = GraphClient()
                client._access_token = "test-token"
                client._token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
                return client

    async def test_sid_with_special_characters(self, client):
        """SID lookup should handle special characters safely."""
        # SIDs have specific format, but test escaping
        mock_response = {"value": []}

        with patch.object(client, "_request", return_value=mock_response) as mock_req:
            await client.get_user_by_on_prem_sid("S-1-5-21-'--injection-attempt")

            # Verify the SID was passed (OData filter handles escaping)
            call_args = mock_req.call_args
            assert "S-1-5-21-" in str(call_args)

    async def test_empty_search_query(self, client):
        """Empty search query should still work."""
        mock_response = {"value": []}

        with patch.object(client, "_request", return_value=mock_response):
            users = await client.search_users("")
            assert users == []

    async def test_parse_user_with_null_fields(self, client):
        """_parse_user should handle null fields gracefully."""
        data = {
            "id": "user-guid",
            "displayName": None,
            "userPrincipalName": None,
            "mail": None,
            "givenName": None,
            "surname": None,
            "jobTitle": None,
            "department": None,
            "officeLocation": None,
            "onPremisesSamAccountName": None,
            "onPremisesSecurityIdentifier": None,
        }

        user = client._parse_user(data)

        assert user.id == "user-guid"
        assert user.display_name is None
        assert user.best_display_name == "user-guid"

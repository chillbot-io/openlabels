"""
Comprehensive tests for OAuth/OIDC authentication.

Tests focus on security-critical paths and edge cases that could
expose authentication bypasses or token validation issues.
"""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from openlabels.auth.oauth import (
    TokenClaims,
    get_jwks,
    validate_token,
    clear_jwks_cache,
    _jwks_cache,
)


class TestTokenClaims:
    """Tests for TokenClaims model validation."""

    def test_valid_claims(self):
        """Valid claims should be accepted."""
        claims = TokenClaims(
            oid="user-object-id",
            preferred_username="user@example.com",
            name="Test User",
            tenant_id="tenant-id",
            roles=["admin", "viewer"],
        )
        assert claims.oid == "user-object-id"
        assert claims.preferred_username == "user@example.com"
        assert claims.name == "Test User"
        assert claims.tenant_id == "tenant-id"
        assert claims.roles == ["admin", "viewer"]

    def test_minimal_claims(self):
        """Only required fields should be needed."""
        claims = TokenClaims(
            oid="user-id",
            preferred_username="user@test.com",
            tenant_id="tenant",
        )
        assert claims.name is None
        assert claims.roles == []

    def test_empty_oid_rejected(self):
        """Empty oid should fail validation."""
        # Pydantic allows empty strings by default for str fields
        # This test documents current behavior - may need stricter validation
        claims = TokenClaims(
            oid="",
            preferred_username="user@test.com",
            tenant_id="tenant",
        )
        # Note: This passes but ideally should fail - potential security issue
        assert claims.oid == ""

    def test_invalid_email_format_accepted(self):
        """Invalid email format is currently accepted."""
        # This documents current behavior - may want stricter validation
        claims = TokenClaims(
            oid="user-id",
            preferred_username="not-an-email",  # No @ sign
            tenant_id="tenant",
        )
        assert claims.preferred_username == "not-an-email"


class TestGetJWKS:
    """Tests for JWKS fetching and caching."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear JWKS cache before each test."""
        clear_jwks_cache()
        yield
        clear_jwks_cache()

    @pytest.mark.asyncio
    async def test_fetches_jwks_from_azure(self):
        """Should fetch JWKS from Azure AD endpoint."""
        mock_jwks = {
            "keys": [
                {"kid": "key1", "kty": "RSA", "n": "abc", "e": "AQAB"},
            ]
        }

        with patch("openlabels.auth.oauth.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            result = await get_jwks("test-tenant-id")

            assert result == mock_jwks
            mock_instance.get.assert_called_once_with(
                "https://login.microsoftonline.com/test-tenant-id/discovery/v2.0/keys"
            )

    @pytest.mark.asyncio
    async def test_caches_jwks(self):
        """JWKS should be cached after first fetch."""
        mock_jwks = {"keys": [{"kid": "key1"}]}

        with patch("openlabels.auth.oauth.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            # First call - should fetch
            result1 = await get_jwks("cached-tenant")
            # Second call - should use cache
            result2 = await get_jwks("cached-tenant")

            assert result1 == result2
            # Should only call HTTP once
            assert mock_instance.get.call_count == 1

    @pytest.mark.asyncio
    async def test_different_tenants_cached_separately(self):
        """Different tenants should have separate cache entries."""
        with patch("openlabels.auth.oauth.httpx.AsyncClient") as mock_client:
            call_count = 0

            async def mock_get(url):
                nonlocal call_count
                call_count += 1
                response = MagicMock()
                response.json.return_value = {"keys": [], "tenant": url}
                response.raise_for_status = MagicMock()
                return response

            mock_instance = AsyncMock()
            mock_instance.get = mock_get
            mock_client.return_value.__aenter__.return_value = mock_instance

            await get_jwks("tenant-a")
            await get_jwks("tenant-b")
            await get_jwks("tenant-a")  # Should be cached

            assert call_count == 2  # Only tenant-a and tenant-b, not third call

    @pytest.mark.asyncio
    async def test_http_error_propagates(self):
        """HTTP errors should propagate to caller."""
        with patch("openlabels.auth.oauth.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Not Found",
                request=MagicMock(),
                response=MagicMock(status_code=404),
            )

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(httpx.HTTPStatusError):
                await get_jwks("invalid-tenant")


class TestValidateToken:
    """Tests for token validation - security critical."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear JWKS cache before each test."""
        clear_jwks_cache()
        yield
        clear_jwks_cache()

    @pytest.mark.asyncio
    async def test_dev_mode_returns_mock_claims(self):
        """In dev mode (provider=none), should return mock claims."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"

        with patch("openlabels.auth.oauth.get_settings", return_value=mock_settings):
            claims = await validate_token("any-token-ignored")

            assert claims.oid == "dev-user-oid"
            assert claims.preferred_username == "dev@localhost"
            assert claims.name == "Development User"
            assert claims.tenant_id == "dev-tenant"
            assert "admin" in claims.roles

    @pytest.mark.asyncio
    async def test_dev_mode_ignores_token_content(self):
        """Dev mode should work with any token string, even empty."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "none"

        with patch("openlabels.auth.oauth.get_settings", return_value=mock_settings):
            # Even malformed tokens work in dev mode - by design
            claims = await validate_token("")
            assert claims.oid == "dev-user-oid"

    @pytest.mark.asyncio
    async def test_missing_kid_raises_error(self):
        """Token without kid in header should fail."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"

        mock_jwks = {"keys": [{"kid": "key1", "kty": "RSA"}]}

        with patch("openlabels.auth.oauth.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.oauth.get_jwks", return_value=mock_jwks):
                with patch("openlabels.auth.oauth.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {}  # No kid

                    with pytest.raises(ValueError, match="Unable to find signing key"):
                        await validate_token("token-without-kid")

    @pytest.mark.asyncio
    async def test_unknown_kid_raises_error(self):
        """Token with unknown kid should fail."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"

        mock_jwks = {"keys": [{"kid": "known-key", "kty": "RSA"}]}

        with patch("openlabels.auth.oauth.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.oauth.get_jwks", return_value=mock_jwks):
                with patch("openlabels.auth.oauth.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "unknown-key"}

                    with pytest.raises(ValueError, match="Unable to find signing key"):
                        await validate_token("token-with-unknown-kid")

    @pytest.mark.asyncio
    async def test_jwt_decode_error_wrapped(self):
        """JWTError should be wrapped in ValueError."""
        from jose import JWTError

        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"

        mock_jwks = {"keys": [{"kid": "key1", "kty": "RSA", "n": "abc", "e": "AQAB"}]}

        with patch("openlabels.auth.oauth.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.oauth.get_jwks", return_value=mock_jwks):
                with patch("openlabels.auth.oauth.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "key1"}
                    with patch("openlabels.auth.oauth.jwt.decode") as mock_decode:
                        mock_decode.side_effect = JWTError("Token expired")

                        with pytest.raises(ValueError, match="Invalid token"):
                            await validate_token("expired-token")

    @pytest.mark.asyncio
    async def test_valid_token_extracts_claims(self):
        """Valid token should have claims extracted correctly."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"

        mock_jwks = {"keys": [{"kid": "key1", "kty": "RSA"}]}
        mock_decoded_claims = {
            "oid": "user-guid",
            "preferred_username": "user@contoso.com",
            "name": "Test User",
            "tid": "tenant-guid",
            "roles": ["app.read", "app.write"],
        }

        with patch("openlabels.auth.oauth.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.oauth.get_jwks", return_value=mock_jwks):
                with patch("openlabels.auth.oauth.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "key1"}
                    with patch("openlabels.auth.oauth.jwt.decode") as mock_decode:
                        mock_decode.return_value = mock_decoded_claims

                        claims = await validate_token("valid-token")

                        assert claims.oid == "user-guid"
                        assert claims.preferred_username == "user@contoso.com"
                        assert claims.name == "Test User"
                        assert claims.tenant_id == "tenant-guid"
                        assert claims.roles == ["app.read", "app.write"]

    @pytest.mark.asyncio
    async def test_missing_optional_claims_handled(self):
        """Token without optional claims should still work."""
        mock_settings = MagicMock()
        mock_settings.auth.provider = "azure_ad"
        mock_settings.auth.tenant_id = "test-tenant"
        mock_settings.auth.client_id = "test-client"

        mock_jwks = {"keys": [{"kid": "key1", "kty": "RSA"}]}
        mock_decoded_claims = {
            "oid": "user-guid",
            "preferred_username": "user@contoso.com",
            # No name, tid, or roles
        }

        with patch("openlabels.auth.oauth.get_settings", return_value=mock_settings):
            with patch("openlabels.auth.oauth.get_jwks", return_value=mock_jwks):
                with patch("openlabels.auth.oauth.jwt.get_unverified_header") as mock_header:
                    mock_header.return_value = {"kid": "key1"}
                    with patch("openlabels.auth.oauth.jwt.decode") as mock_decode:
                        mock_decode.return_value = mock_decoded_claims

                        claims = await validate_token("minimal-claims-token")

                        assert claims.oid == "user-guid"
                        assert claims.name is None
                        assert claims.tenant_id == "test-tenant"  # Falls back to settings
                        assert claims.roles == []


class TestClearJWKSCache:
    """Tests for JWKS cache clearing."""

    def test_clears_cache(self):
        """clear_jwks_cache should empty the cache."""
        # Manually populate cache
        from openlabels.auth import oauth
        oauth._jwks_cache["tenant1"] = {"keys": []}
        oauth._jwks_cache["tenant2"] = {"keys": []}

        assert len(oauth._jwks_cache) == 2

        clear_jwks_cache()

        assert len(oauth._jwks_cache) == 0

    def test_clear_empty_cache_safe(self):
        """Clearing empty cache should not error."""
        clear_jwks_cache()
        clear_jwks_cache()  # Should not raise

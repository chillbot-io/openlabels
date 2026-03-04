"""
Comprehensive tests for the generic OIDC authentication provider.

Tests cover security-critical paths:
- OIDC discovery document fetching and caching
- JWKS key fetching, caching, and key rotation
- JWT id_token validation (signature, issuer, audience, expiration)
- Authorization code exchange
- Token refresh
- Claim extraction and normalization
- End-session URL generation
- Error handling edge cases
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr

from openlabels.auth.oidc_provider import (
    OIDCTokenClaims,
    _discovery_cache,
    _find_signing_key,
    _get_jwks,
    _jwks_cache,
    _stable_hash,
    clear_oidc_cache,
    exchange_code,
    extract_claims,
    get_authorization_url,
    get_discovery,
    get_end_session_url,
    refresh_token,
    validate_id_token,
)
from openlabels.exceptions import AuthError, TokenExpiredError, TokenInvalidError
from openlabels.server.config import OIDCProviderSettings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_oidc_config(**overrides) -> OIDCProviderSettings:
    """Create a minimal OIDCProviderSettings for testing."""
    defaults = {
        "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
        "client_id": "test-client-id",
        "client_secret": SecretStr("test-client-secret"),
        "scopes": "openid profile email",
        "claim_sub": "sub",
        "claim_email": "email",
        "claim_name": "name",
        "claim_tenant": "",
        "claim_roles": "roles",
    }
    defaults.update(overrides)
    return OIDCProviderSettings(**defaults)


SAMPLE_DISCOVERY = {
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
    "issuer": "https://idp.example.com",
    "end_session_endpoint": "https://idp.example.com/logout",
    "userinfo_endpoint": "https://idp.example.com/userinfo",
}

SAMPLE_JWKS = {
    "keys": [
        {
            "kid": "key-1",
            "kty": "RSA",
            "use": "sig",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV"
                 "T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ"
                 "_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz"
                 "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI"
                 "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBni"
                 "Iqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
        },
        {
            "kid": "key-2",
            "kty": "RSA",
            "use": "enc",  # Not a signing key
            "n": "abc",
            "e": "AQAB",
        },
    ]
}


# ---------------------------------------------------------------------------
# Test: OIDC Discovery
# ---------------------------------------------------------------------------

class TestGetDiscovery:
    """Tests for OIDC discovery document fetching and caching."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear all OIDC caches before and after each test."""
        clear_oidc_cache()
        yield
        clear_oidc_cache()

    async def test_fetches_discovery_document(self):
        """Should fetch and return the discovery document."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_DISCOVERY
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            result = await get_discovery("https://idp.example.com/.well-known/openid-configuration")

            assert result["issuer"] == "https://idp.example.com"
            assert result["authorization_endpoint"] == "https://idp.example.com/authorize"
            assert result["token_endpoint"] == "https://idp.example.com/token"
            assert result["jwks_uri"] == "https://idp.example.com/.well-known/jwks.json"
            mock_instance.get.assert_called_once()

    async def test_caches_discovery_document(self):
        """Second call should use cached result, not re-fetch."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_DISCOVERY
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            url = "https://idp.example.com/.well-known/openid-configuration"
            result1 = await get_discovery(url)
            result2 = await get_discovery(url)

            assert result1 == result2
            assert mock_instance.get.call_count == 1

    async def test_different_urls_cached_separately(self):
        """Different discovery URLs should have separate cache entries."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            call_count = 0

            async def mock_get(url):
                nonlocal call_count
                call_count += 1
                response = MagicMock()
                response.json.return_value = {**SAMPLE_DISCOVERY, "issuer": url}
                response.raise_for_status = MagicMock()
                return response

            mock_instance = AsyncMock()
            mock_instance.get = mock_get
            mock_client.return_value.__aenter__.return_value = mock_instance

            await get_discovery("https://idp1.example.com/.well-known/openid-configuration")
            await get_discovery("https://idp2.example.com/.well-known/openid-configuration")

            assert call_count == 2

    async def test_validates_required_fields(self):
        """Discovery documents missing required fields should raise ValueError."""
        incomplete_doc = {
            "authorization_endpoint": "https://idp.example.com/authorize",
            # Missing: token_endpoint, jwks_uri, issuer
        }

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = incomplete_doc
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(ValueError, match="missing required fields"):
                await get_discovery("https://bad-idp.example.com/.well-known/openid-configuration")

    async def test_http_error_propagates(self):
        """HTTP errors from the IdP should propagate."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
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
                await get_discovery("https://bad-idp.example.com/.well-known/openid-configuration")

    async def test_cache_expires_after_ttl(self):
        """Cached discovery document should be re-fetched after TTL expires."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_DISCOVERY
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            url = "https://idp.example.com/.well-known/openid-configuration"
            await get_discovery(url)

            # Manually expire the cache entry
            if url in _discovery_cache:
                doc, _ = _discovery_cache[url]
                _discovery_cache[url] = (doc, time.monotonic() - 7200)  # 2 hours ago

            await get_discovery(url)

            assert mock_instance.get.call_count == 2


# ---------------------------------------------------------------------------
# Test: JWKS fetching
# ---------------------------------------------------------------------------

class TestGetJWKS:
    """Tests for JWKS fetching and caching."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        clear_oidc_cache()
        yield
        clear_oidc_cache()

    async def test_fetches_jwks(self):
        """Should fetch JWKS from the provider's jwks_uri."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_JWKS
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            result = await _get_jwks("https://idp.example.com/.well-known/jwks.json")

            assert len(result["keys"]) == 2
            assert result["keys"][0]["kid"] == "key-1"

    async def test_caches_jwks(self):
        """JWKS should be cached after first fetch."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_JWKS
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            uri = "https://idp.example.com/.well-known/jwks.json"
            await _get_jwks(uri)
            await _get_jwks(uri)

            assert mock_instance.get.call_count == 1

    async def test_cache_expires_after_ttl(self):
        """Expired JWKS cache should trigger re-fetch."""
        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_JWKS
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            uri = "https://idp.example.com/.well-known/jwks.json"
            await _get_jwks(uri)

            # Expire the cache
            if uri in _jwks_cache:
                data, _ = _jwks_cache[uri]
                _jwks_cache[uri] = (data, time.monotonic() - 7200)

            await _get_jwks(uri)

            assert mock_instance.get.call_count == 2


# ---------------------------------------------------------------------------
# Test: Find Signing Key
# ---------------------------------------------------------------------------

class TestFindSigningKey:
    """Tests for signing key lookup from JWKS."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        clear_oidc_cache()
        yield
        clear_oidc_cache()

    async def test_finds_key_by_kid(self):
        """Should find the correct key by kid."""
        with patch("openlabels.auth.oidc_provider._get_jwks", return_value=SAMPLE_JWKS):
            key = await _find_signing_key("key-1", "https://idp.example.com/.well-known/jwks.json")
            assert key["kid"] == "key-1"

    async def test_unknown_kid_refreshes_cache_then_fails(self):
        """Unknown kid should trigger cache refresh, then raise if still not found."""
        with patch("openlabels.auth.oidc_provider._get_jwks", return_value=SAMPLE_JWKS) as mock_get:
            with pytest.raises(TokenInvalidError, match="Unable to find signing key"):
                await _find_signing_key("unknown-kid", "https://idp.example.com/.well-known/jwks.json")

            # Should have been called twice: initial lookup + refresh
            assert mock_get.call_count == 2

    async def test_no_kid_with_single_signing_key(self):
        """When kid is None and there's exactly one signing key, use it."""
        single_key_jwks = {
            "keys": [
                {"kid": "only-key", "kty": "RSA", "use": "sig", "n": "abc", "e": "AQAB"},
            ]
        }
        with patch("openlabels.auth.oidc_provider._get_jwks", return_value=single_key_jwks):
            key = await _find_signing_key(None, "https://idp.example.com/.well-known/jwks.json")
            assert key["kid"] == "only-key"

    async def test_no_kid_with_multiple_signing_keys_fails(self):
        """When kid is None and there are multiple signing keys, raise error."""
        multi_key_jwks = {
            "keys": [
                {"kid": "key-a", "kty": "RSA", "use": "sig", "n": "abc", "e": "AQAB"},
                {"kid": "key-b", "kty": "RSA", "use": "sig", "n": "def", "e": "AQAB"},
            ]
        }
        with patch("openlabels.auth.oidc_provider._get_jwks", return_value=multi_key_jwks):
            with pytest.raises(TokenInvalidError, match="no 'kid' header"):
                await _find_signing_key(None, "https://idp.example.com/.well-known/jwks.json")

    async def test_no_kid_with_no_signing_keys_fails(self):
        """When kid is None and there are no signing keys, raise error."""
        no_sig_jwks = {
            "keys": [
                {"kid": "enc-key", "kty": "RSA", "use": "enc", "n": "abc", "e": "AQAB"},
            ]
        }
        with patch("openlabels.auth.oidc_provider._get_jwks", return_value=no_sig_jwks):
            with pytest.raises(TokenInvalidError, match="0 signing keys"):
                await _find_signing_key(None, "https://idp.example.com/.well-known/jwks.json")

    async def test_key_without_use_defaults_to_sig(self):
        """Keys without 'use' field should default to 'sig'."""
        implicit_sig_jwks = {
            "keys": [
                {"kid": "implicit-sig", "kty": "RSA", "n": "abc", "e": "AQAB"},
                # No "use" field -- defaults to sig
            ]
        }
        with patch("openlabels.auth.oidc_provider._get_jwks", return_value=implicit_sig_jwks):
            key = await _find_signing_key(None, "https://idp.example.com/.well-known/jwks.json")
            assert key["kid"] == "implicit-sig"

    async def test_key_rotation_detected(self):
        """When a kid is not found, JWKS cache is cleared and re-fetched."""
        old_jwks = {"keys": [{"kid": "old-key", "kty": "RSA", "use": "sig"}]}
        new_jwks = {"keys": [{"kid": "new-key", "kty": "RSA", "use": "sig"}]}

        call_count = 0

        async def mock_get_jwks(uri):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return old_jwks
            return new_jwks

        with patch("openlabels.auth.oidc_provider._get_jwks", side_effect=mock_get_jwks):
            key = await _find_signing_key("new-key", "https://idp.example.com/.well-known/jwks.json")
            assert key["kid"] == "new-key"
            assert call_count == 2  # First fetch (miss) + refresh (hit)


# ---------------------------------------------------------------------------
# Test: Authorization URL
# ---------------------------------------------------------------------------

class TestGetAuthorizationUrl:
    """Tests for authorization URL construction."""

    def test_builds_authorization_url(self):
        """Should build a valid authorization URL with all required params."""
        config = _make_oidc_config()
        url = get_authorization_url(
            discovery=SAMPLE_DISCOVERY,
            config=config,
            state="random-state-value",
            redirect_uri="https://app.example.com/callback",
        )

        assert "https://idp.example.com/authorize" in url
        assert "response_type=code" in url
        assert "client_id=test-client-id" in url
        assert "state=random-state-value" in url
        assert "redirect_uri=" in url

    def test_includes_nonce_when_provided(self):
        """Nonce should be included when passed."""
        config = _make_oidc_config()
        url = get_authorization_url(
            discovery=SAMPLE_DISCOVERY,
            config=config,
            state="state",
            redirect_uri="https://app.example.com/callback",
            nonce="random-nonce",
        )

        assert "nonce=random-nonce" in url

    def test_omits_nonce_when_none(self):
        """Nonce should not appear in URL when not provided."""
        config = _make_oidc_config()
        url = get_authorization_url(
            discovery=SAMPLE_DISCOVERY,
            config=config,
            state="state",
            redirect_uri="https://app.example.com/callback",
            nonce=None,
        )

        assert "nonce" not in url

    def test_includes_configured_scopes(self):
        """Should include the configured scopes."""
        config = _make_oidc_config(scopes="openid profile email groups")
        url = get_authorization_url(
            discovery=SAMPLE_DISCOVERY,
            config=config,
            state="state",
            redirect_uri="https://app.example.com/callback",
        )

        assert "scope=openid" in url


# ---------------------------------------------------------------------------
# Test: Code Exchange
# ---------------------------------------------------------------------------

class TestExchangeCode:
    """Tests for authorization code exchange."""

    async def test_successful_exchange(self):
        """Should exchange code for tokens successfully."""
        config = _make_oidc_config()
        token_response = {
            "access_token": "access-token-value",
            "id_token": "id-token-value",
            "refresh_token": "refresh-token-value",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = token_response

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            result = await exchange_code(
                discovery=SAMPLE_DISCOVERY,
                config=config,
                code="auth-code-123",
                redirect_uri="https://app.example.com/callback",
            )

            assert result["access_token"] == "access-token-value"
            assert result["id_token"] == "id-token-value"
            assert result["refresh_token"] == "refresh-token-value"

            # Verify the POST was made with correct data
            mock_instance.post.assert_called_once()
            call_kwargs = mock_instance.post.call_args
            assert call_kwargs[1]["data"]["grant_type"] == "authorization_code"
            assert call_kwargs[1]["data"]["code"] == "auth-code-123"
            assert call_kwargs[1]["data"]["client_id"] == "test-client-id"
            assert call_kwargs[1]["data"]["client_secret"] == "test-client-secret"

    async def test_exchange_error_raises_auth_error(self):
        """Non-200 response should raise AuthError."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                "error": "invalid_grant",
                "error_description": "The authorization code has expired",
            }

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(AuthError, match="invalid_grant"):
                await exchange_code(
                    discovery=SAMPLE_DISCOVERY,
                    config=config,
                    code="expired-code",
                    redirect_uri="https://app.example.com/callback",
                )

    async def test_exchange_non_json_error_handled(self):
        """Non-JSON error responses should be handled gracefully."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.json.side_effect = ValueError("Not JSON")
            mock_response.text = "Internal Server Error"

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            with pytest.raises(AuthError, match="token exchange failed"):
                await exchange_code(
                    discovery=SAMPLE_DISCOVERY,
                    config=config,
                    code="code",
                    redirect_uri="https://app.example.com/callback",
                )

    async def test_exchange_posts_to_token_endpoint(self):
        """Should POST to the discovery document's token_endpoint."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"access_token": "tok"}

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await exchange_code(
                discovery=SAMPLE_DISCOVERY,
                config=config,
                code="code",
                redirect_uri="https://app.example.com/callback",
            )

            call_args = mock_instance.post.call_args
            assert call_args[0][0] == "https://idp.example.com/token"


# ---------------------------------------------------------------------------
# Test: ID Token Validation
# ---------------------------------------------------------------------------

class TestValidateIdToken:
    """Tests for JWT id_token validation -- security critical."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        clear_oidc_cache()
        yield
        clear_oidc_cache()

    async def test_valid_token_returns_claims(self):
        """Valid token should return decoded claims."""
        config = _make_oidc_config()
        expected_claims = {
            "sub": "user-123",
            "email": "user@example.com",
            "name": "Test User",
            "iss": "https://idp.example.com",
            "aud": "test-client-id",
            "nonce": "test-nonce",
        }

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK") as mock_pyjwk, \
             patch("openlabels.auth.oidc_provider.jwt.decode") as mock_decode:

            mock_header.return_value = {"kid": "key-1", "alg": "RS256"}
            mock_find_key.return_value = {"kid": "key-1", "kty": "RSA"}
            mock_pyjwk.return_value = MagicMock()
            mock_decode.return_value = expected_claims

            claims = await validate_id_token("valid.jwt.token", SAMPLE_DISCOVERY, config)

            assert claims["sub"] == "user-123"
            assert claims["email"] == "user@example.com"
            mock_decode.assert_called_once()
            decode_kwargs = mock_decode.call_args
            assert decode_kwargs[1]["audience"] == "test-client-id"
            assert decode_kwargs[1]["issuer"] == "https://idp.example.com"

    async def test_expired_token_raises_token_expired_error(self):
        """Expired tokens should raise TokenExpiredError."""
        from jwt.exceptions import ExpiredSignatureError

        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK"), \
             patch("openlabels.auth.oidc_provider.jwt.decode") as mock_decode:

            mock_header.return_value = {"kid": "key-1", "alg": "RS256"}
            mock_find_key.return_value = {"kid": "key-1", "kty": "RSA"}
            mock_decode.side_effect = ExpiredSignatureError("Token has expired")

            with pytest.raises(TokenExpiredError, match="ID token expired"):
                await validate_id_token("expired.jwt.token", SAMPLE_DISCOVERY, config)

    async def test_invalid_signature_raises_token_invalid_error(self):
        """Tokens with invalid signatures should raise TokenInvalidError."""
        from jwt.exceptions import InvalidSignatureError

        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK"), \
             patch("openlabels.auth.oidc_provider.jwt.decode") as mock_decode:

            mock_header.return_value = {"kid": "key-1", "alg": "RS256"}
            mock_find_key.return_value = {"kid": "key-1", "kty": "RSA"}
            mock_decode.side_effect = InvalidSignatureError("Signature verification failed")

            with pytest.raises(TokenInvalidError, match="Invalid signature"):
                await validate_id_token("tampered.jwt.token", SAMPLE_DISCOVERY, config)

    async def test_generic_jwt_error_raises_token_invalid_error(self):
        """Generic PyJWTError should raise TokenInvalidError."""
        from jwt.exceptions import PyJWTError

        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK"), \
             patch("openlabels.auth.oidc_provider.jwt.decode") as mock_decode:

            mock_header.return_value = {"kid": "key-1", "alg": "RS256"}
            mock_find_key.return_value = {"kid": "key-1", "kty": "RSA"}
            mock_decode.side_effect = PyJWTError("Malformed JWT")

            with pytest.raises(TokenInvalidError, match="Invalid token"):
                await validate_id_token("malformed.jwt.token", SAMPLE_DISCOVERY, config)

    async def test_unsupported_algorithm_rejected(self):
        """Tokens using unsupported algorithms should be rejected."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK"):

            mock_header.return_value = {"kid": "key-1", "alg": "HS256"}  # HMAC - not allowed
            mock_find_key.return_value = {"kid": "key-1", "kty": "RSA"}

            with pytest.raises(TokenInvalidError, match="Unsupported algorithm"):
                await validate_id_token("hmac.jwt.token", SAMPLE_DISCOVERY, config)

    async def test_none_algorithm_rejected(self):
        """The 'none' algorithm must ALWAYS be rejected (critical security)."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK"):

            mock_header.return_value = {"kid": "key-1", "alg": "none"}
            mock_find_key.return_value = {"kid": "key-1", "kty": "RSA"}

            with pytest.raises(TokenInvalidError, match="Unsupported algorithm"):
                await validate_id_token("none.alg.token", SAMPLE_DISCOVERY, config)

    async def test_supported_algorithms_accepted(self):
        """All listed supported algorithms should be accepted."""
        config = _make_oidc_config()
        supported_algs = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"]

        for alg in supported_algs:
            with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
                 patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
                 patch("openlabels.auth.oidc_provider.jwt.PyJWK") as mock_pyjwk, \
                 patch("openlabels.auth.oidc_provider.jwt.decode") as mock_decode:

                mock_header.return_value = {"kid": "key-1", "alg": alg}
                mock_find_key.return_value = {"kid": "key-1"}
                mock_pyjwk.return_value = MagicMock()
                mock_decode.return_value = {"sub": "user", "iss": "https://idp.example.com"}

                claims = await validate_id_token(f"token.{alg}", SAMPLE_DISCOVERY, config)
                assert claims is not None, f"Algorithm {alg} should be accepted"

    async def test_token_without_kid_header(self):
        """Token without kid should be handled (some providers omit it)."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK") as mock_pyjwk, \
             patch("openlabels.auth.oidc_provider.jwt.decode") as mock_decode:

            mock_header.return_value = {"alg": "RS256"}  # No kid
            mock_find_key.return_value = {"kid": "only-key"}
            mock_pyjwk.return_value = MagicMock()
            mock_decode.return_value = {"sub": "user"}

            await validate_id_token("no.kid.token", SAMPLE_DISCOVERY, config)
            # _find_signing_key called with None kid
            mock_find_key.assert_called_once_with(None, SAMPLE_DISCOVERY["jwks_uri"])

    async def test_default_algorithm_when_missing(self):
        """Token without alg header should default to RS256."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.jwt.get_unverified_header") as mock_header, \
             patch("openlabels.auth.oidc_provider._find_signing_key") as mock_find_key, \
             patch("openlabels.auth.oidc_provider.jwt.PyJWK") as mock_pyjwk, \
             patch("openlabels.auth.oidc_provider.jwt.decode") as mock_decode:

            mock_header.return_value = {"kid": "key-1"}  # No alg
            mock_find_key.return_value = {"kid": "key-1"}
            mock_pyjwk.return_value = MagicMock()
            mock_decode.return_value = {"sub": "user"}

            await validate_id_token("no.alg.token", SAMPLE_DISCOVERY, config)

            # jwt.decode should be called with RS256 as default
            decode_call = mock_decode.call_args
            assert decode_call[1]["algorithms"] == ["RS256"]


# ---------------------------------------------------------------------------
# Test: Extract Claims
# ---------------------------------------------------------------------------

class TestExtractClaims:
    """Tests for claim extraction and normalization."""

    def test_extracts_standard_claims(self):
        """Should extract and normalize standard OIDC claims."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
            "name": "Test User",
            "iss": "https://idp.example.com",
            "roles": ["admin", "viewer"],
        }

        result = extract_claims(raw, config)

        assert isinstance(result, OIDCTokenClaims)
        assert result.sub == "user-123"
        assert result.email == "user@example.com"
        assert result.name == "Test User"
        assert result.roles == ["admin", "viewer"]
        assert result.raw_claims == raw

    def test_missing_sub_raises_error(self):
        """Missing subject claim should raise TokenInvalidError."""
        config = _make_oidc_config()
        raw = {
            "email": "user@example.com",
            # No "sub" claim
        }

        with pytest.raises(TokenInvalidError, match="sub.*missing or empty"):
            extract_claims(raw, config)

    def test_empty_sub_raises_error(self):
        """Empty subject claim should raise TokenInvalidError."""
        config = _make_oidc_config()
        raw = {
            "sub": "",
            "email": "user@example.com",
        }

        with pytest.raises(TokenInvalidError, match="sub.*missing or empty"):
            extract_claims(raw, config)

    def test_missing_email_raises_error(self):
        """Missing email claim should raise TokenInvalidError."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            # No "email" claim
        }

        with pytest.raises(TokenInvalidError, match="email.*missing or empty"):
            extract_claims(raw, config)

    def test_email_fallback_to_preferred_username(self):
        """Should fall back to preferred_username if email is missing."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "preferred_username": "user@example.com",
            # No "email" claim
        }

        result = extract_claims(raw, config)
        assert result.email == "user@example.com"

    def test_email_fallback_to_upn(self):
        """Should fall back to 'upn' if both email and preferred_username are missing."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "upn": "user@contoso.com",
        }

        result = extract_claims(raw, config)
        assert result.email == "user@contoso.com"

    def test_custom_claim_mapping(self):
        """Should respect custom claim mappings from config."""
        config = _make_oidc_config(
            claim_sub="user_id",
            claim_email="mail",
            claim_name="display_name",
            claim_tenant="org_id",
            claim_roles="groups",
        )
        raw = {
            "user_id": "custom-123",
            "mail": "custom@example.com",
            "display_name": "Custom User",
            "org_id": "org-456",
            "groups": ["admins"],
        }

        result = extract_claims(raw, config)

        assert result.sub == "custom-123"
        assert result.email == "custom@example.com"
        assert result.name == "Custom User"
        assert result.tenant_id == "org-456"
        assert result.roles == ["admins"]

    def test_tenant_fallback_to_issuer_hash(self):
        """When no tenant claim, should derive tenant from issuer hash."""
        config = _make_oidc_config(claim_tenant="")
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
            "iss": "https://idp.example.com",
        }

        result = extract_claims(raw, config)

        assert result.tenant_id.startswith("oidc-")
        assert len(result.tenant_id) > 5

    def test_roles_as_comma_separated_string(self):
        """Roles provided as comma-separated string should be parsed."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
            "roles": "admin,viewer,editor",
        }

        result = extract_claims(raw, config)
        assert result.roles == ["admin", "viewer", "editor"]

    def test_roles_as_space_separated_string(self):
        """Roles provided as space-separated string should be parsed."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
            "roles": "admin viewer",
        }

        result = extract_claims(raw, config)
        assert result.roles == ["admin", "viewer"]

    def test_roles_as_list(self):
        """Roles provided as list should be preserved."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
            "roles": ["admin", "viewer"],
        }

        result = extract_claims(raw, config)
        assert result.roles == ["admin", "viewer"]

    def test_roles_missing_returns_empty_list(self):
        """Missing roles claim should return empty list."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
        }

        result = extract_claims(raw, config)
        assert result.roles == []

    def test_roles_non_standard_type_returns_empty_list(self):
        """Non-string/non-list roles should return empty list."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
            "roles": 42,  # Unexpected type
        }

        result = extract_claims(raw, config)
        assert result.roles == []

    def test_name_is_optional(self):
        """Name claim is optional and should return None if missing."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
        }

        result = extract_claims(raw, config)
        assert result.name is None

    def test_raw_claims_preserved(self):
        """The raw claims dict should be preserved on the result."""
        config = _make_oidc_config()
        raw = {
            "sub": "user-123",
            "email": "user@example.com",
            "custom_field": "custom_value",
        }

        result = extract_claims(raw, config)
        assert result.raw_claims["custom_field"] == "custom_value"

    def test_sub_converted_to_string(self):
        """Numeric sub claims should be converted to string."""
        config = _make_oidc_config()
        raw = {
            "sub": 12345,
            "email": "user@example.com",
        }

        result = extract_claims(raw, config)
        assert result.sub == "12345"
        assert isinstance(result.sub, str)


# ---------------------------------------------------------------------------
# Test: Token Refresh
# ---------------------------------------------------------------------------

class TestRefreshToken:
    """Tests for token refresh flow."""

    async def test_successful_refresh(self):
        """Should refresh token successfully."""
        config = _make_oidc_config()
        refresh_response = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
        }

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = refresh_response

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            result = await refresh_token(
                discovery=SAMPLE_DISCOVERY,
                config=config,
                refresh_token_value="old-refresh-token",
            )

            assert result["access_token"] == "new-access-token"
            assert result["refresh_token"] == "new-refresh-token"

            # Verify correct POST data
            call_kwargs = mock_instance.post.call_args
            assert call_kwargs[1]["data"]["grant_type"] == "refresh_token"
            assert call_kwargs[1]["data"]["refresh_token"] == "old-refresh-token"
            assert call_kwargs[1]["data"]["client_id"] == "test-client-id"
            assert call_kwargs[1]["data"]["client_secret"] == "test-client-secret"

    async def test_refresh_failure_returns_error(self):
        """Failed refresh should return error dict (not raise)."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                "error": "invalid_grant",
                "error_description": "Refresh token has expired",
            }

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            result = await refresh_token(
                discovery=SAMPLE_DISCOVERY,
                config=config,
                refresh_token_value="expired-refresh-token",
            )

            assert "error" in result
            assert result["error"] == "invalid_grant"

    async def test_refresh_non_json_error_handled(self):
        """Non-JSON error response during refresh should be handled."""
        config = _make_oidc_config()

        with patch("openlabels.auth.oidc_provider.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.json.side_effect = ValueError("Not JSON")

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            result = await refresh_token(
                discovery=SAMPLE_DISCOVERY,
                config=config,
                refresh_token_value="some-token",
            )

            assert "error" in result


# ---------------------------------------------------------------------------
# Test: End Session URL
# ---------------------------------------------------------------------------

class TestGetEndSessionUrl:
    """Tests for logout/end-session URL generation."""

    def test_returns_end_session_url(self):
        """Should return end session URL with correct params."""
        config = _make_oidc_config()
        url = get_end_session_url(
            discovery=SAMPLE_DISCOVERY,
            config=config,
            post_logout_redirect_uri="https://app.example.com/",
        )

        assert url is not None
        assert "https://idp.example.com/logout" in url
        assert "client_id=test-client-id" in url
        assert "post_logout_redirect_uri=" in url

    def test_includes_id_token_hint(self):
        """Should include id_token_hint when provided."""
        config = _make_oidc_config()
        url = get_end_session_url(
            discovery=SAMPLE_DISCOVERY,
            config=config,
            post_logout_redirect_uri="https://app.example.com/",
            id_token_hint="the-id-token",
        )

        assert "id_token_hint=the-id-token" in url

    def test_omits_id_token_hint_when_none(self):
        """Should not include id_token_hint when not provided."""
        config = _make_oidc_config()
        url = get_end_session_url(
            discovery=SAMPLE_DISCOVERY,
            config=config,
            post_logout_redirect_uri="https://app.example.com/",
            id_token_hint=None,
        )

        assert "id_token_hint" not in url

    def test_returns_none_when_no_end_session_endpoint(self):
        """Should return None if provider doesn't support end_session."""
        config = _make_oidc_config()
        discovery_without_logout = {
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
            "issuer": "https://idp.example.com",
            # No end_session_endpoint
        }

        url = get_end_session_url(
            discovery=discovery_without_logout,
            config=config,
            post_logout_redirect_uri="https://app.example.com/",
        )

        assert url is None


# ---------------------------------------------------------------------------
# Test: Stable Hash
# ---------------------------------------------------------------------------

class TestStableHash:
    """Tests for the _stable_hash utility."""

    def test_returns_consistent_hash(self):
        """Same input should always produce the same hash."""
        h1 = _stable_hash("https://idp.example.com")
        h2 = _stable_hash("https://idp.example.com")
        assert h1 == h2

    def test_different_inputs_produce_different_hashes(self):
        """Different inputs should produce different hashes."""
        h1 = _stable_hash("https://idp1.example.com")
        h2 = _stable_hash("https://idp2.example.com")
        assert h1 != h2

    def test_returns_12_char_string(self):
        """Hash should be 12 characters (hex truncation)."""
        h = _stable_hash("test")
        assert len(h) == 12
        # Should be valid hex
        int(h, 16)


# ---------------------------------------------------------------------------
# Test: Clear Cache
# ---------------------------------------------------------------------------

class TestClearOidcCache:
    """Tests for cache clearing utility."""

    def test_clears_both_caches(self):
        """clear_oidc_cache should clear both discovery and JWKS caches."""
        _discovery_cache["test"] = ({"issuer": "test"}, time.monotonic())
        _jwks_cache["test"] = ({"keys": []}, time.monotonic())

        assert len(_discovery_cache) > 0
        assert len(_jwks_cache) > 0

        clear_oidc_cache()

        assert len(_discovery_cache) == 0
        assert len(_jwks_cache) == 0


# ---------------------------------------------------------------------------
# Test: OIDCTokenClaims
# ---------------------------------------------------------------------------

class TestOIDCTokenClaims:
    """Tests for the OIDCTokenClaims data class."""

    def test_stores_all_fields(self):
        """Should store all provided fields."""
        raw = {"sub": "123", "email": "u@e.com", "extra": "field"}
        claims = OIDCTokenClaims(
            sub="123",
            email="u@e.com",
            name="User",
            tenant_id="t-1",
            roles=["admin"],
            raw_claims=raw,
        )

        assert claims.sub == "123"
        assert claims.email == "u@e.com"
        assert claims.name == "User"
        assert claims.tenant_id == "t-1"
        assert claims.roles == ["admin"]
        assert claims.raw_claims["extra"] == "field"

    def test_name_can_be_none(self):
        """Name field should accept None."""
        claims = OIDCTokenClaims(
            sub="123",
            email="u@e.com",
            name=None,
            tenant_id="t-1",
            roles=[],
            raw_claims={},
        )
        assert claims.name is None

    def test_empty_roles_list(self):
        """Roles can be an empty list."""
        claims = OIDCTokenClaims(
            sub="123",
            email="u@e.com",
            name=None,
            tenant_id="t-1",
            roles=[],
            raw_claims={},
        )
        assert claims.roles == []

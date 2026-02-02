"""Tests for SID resolver module."""

import sys
import os

# Add src to path for direct import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# Import directly to avoid loading oauth which has cryptography dependencies
from openlabels.auth.sid_resolver import (
    SIDResolver,
    ResolvedUser,
    WELL_KNOWN_SIDS,
    is_system_account_sid,
    resolve_sid_sync,
    get_sid_resolver,
    reset_sid_resolver,
)


class TestWellKnownSIDs:
    """Tests for well-known SID detection."""

    def test_system_sid(self):
        """SYSTEM SID should be recognized."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-18")
        assert result.display_name == "Local System"
        assert result.is_system_account is True
        assert result.is_well_known is True
        assert result.resolution_source == "well_known"

    def test_local_service_sid(self):
        """LOCAL SERVICE SID should be recognized."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-19")
        assert result.display_name == "NT Authority\\Local Service"
        assert result.is_system_account is True

    def test_network_service_sid(self):
        """NETWORK SERVICE SID should be recognized."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-20")
        assert result.display_name == "NT Authority\\Network Service"
        assert result.is_system_account is True

    def test_everyone_sid(self):
        """Everyone SID should be recognized but not system."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-1-0")
        assert result.display_name == "Everyone"
        assert result.is_system_account is False
        assert result.is_well_known is True

    def test_authenticated_users_sid(self):
        """Authenticated Users SID should be recognized."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-11")
        assert result.display_name == "Authenticated Users"
        assert result.is_system_account is False

    def test_builtin_administrators_sid(self):
        """BUILTIN\\Administrators SID should be recognized."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-32-544")
        assert result.display_name == "BUILTIN\\Administrators"
        assert result.is_system_account is True

    def test_builtin_users_sid(self):
        """BUILTIN\\Users SID should be recognized."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-32-545")
        assert result.display_name == "BUILTIN\\Users"
        assert result.is_system_account is False


class TestDomainAccountSIDs:
    """Tests for domain account SID patterns."""

    def test_domain_administrator_rid(self):
        """Domain Administrator RID (-500) should be detected."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-21-3623811015-3361044348-30300820-500")
        assert result.display_name == "Administrator"
        assert result.is_system_account is True
        assert result.is_well_known is True

    def test_domain_guest_rid(self):
        """Domain Guest RID (-501) should be detected."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-21-3623811015-3361044348-30300820-501")
        assert result.display_name == "Guest"
        assert result.is_system_account is True

    def test_domain_admins_rid(self):
        """Domain Admins RID (-512) should be detected."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("S-1-5-21-3623811015-3361044348-30300820-512")
        assert result.display_name == "Domain Admins"
        assert result.is_system_account is True

    def test_regular_user_rid(self):
        """Regular user RID should not be detected as well-known."""
        resolver = SIDResolver(enable_graph=False)
        # RID 1234 is a regular user
        result = resolver.resolve_sync("S-1-5-21-3623811015-3361044348-30300820-1234")
        assert result.is_well_known is False
        assert result.resolution_source == "fallback_sync"


class TestIsSystemAccountSID:
    """Tests for is_system_account_sid helper function."""

    def test_system_account(self):
        """SYSTEM should be detected as system account."""
        assert is_system_account_sid("S-1-5-18") is True

    def test_local_service(self):
        """LOCAL SERVICE should be detected as system account."""
        assert is_system_account_sid("S-1-5-19") is True

    def test_everyone(self):
        """Everyone should not be a system account."""
        assert is_system_account_sid("S-1-1-0") is False

    def test_regular_user(self):
        """Regular user SID should not be system account."""
        assert is_system_account_sid("S-1-5-21-123-456-789-1234") is False

    def test_domain_admin(self):
        """Domain Administrator (-500) should be system account."""
        assert is_system_account_sid("S-1-5-21-123-456-789-500") is True


class TestSIDNormalization:
    """Tests for SID normalization."""

    def test_lowercase_sid(self):
        """Lowercase SID should be normalized."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("s-1-5-18")
        assert result.display_name == "Local System"

    def test_whitespace_trimmed(self):
        """Whitespace should be trimmed."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("  S-1-5-18  ")
        assert result.display_name == "Local System"

    def test_invalid_sid_format(self):
        """Invalid SID format should return SID as display name (uppercase normalized)."""
        resolver = SIDResolver(enable_graph=False)
        result = resolver.resolve_sync("not-a-sid")
        # SIDs are normalized to uppercase, unrecognized SIDs use fallback
        assert result.display_name == "NOT-A-SID"
        assert result.resolution_source == "fallback_sync"


class TestCaching:
    """Tests for SID resolution caching."""

    def test_cache_stores_result(self):
        """Resolved SIDs should be cached."""
        resolver = SIDResolver(enable_graph=False)

        # First resolution
        result1 = resolver.resolve_sync("S-1-5-21-123-456-789-1234")
        assert result1.resolution_source == "fallback_sync"

        # Manually add to cache (simulate async resolution)
        cached_user = ResolvedUser(
            sid="S-1-5-21-123-456-789-1234",
            display_name="John Smith",
            user_principal_name="jsmith@contoso.com",
            resolution_source="graph_api",
        )
        resolver._cache["S-1-5-21-123-456-789-1234"] = (cached_user, datetime.now(timezone.utc))

        # Second resolution should hit cache
        result2 = resolver.resolve_sync("S-1-5-21-123-456-789-1234")
        assert result2.display_name == "John Smith"
        assert result2.resolution_source == "cache"

    def test_cache_expiration(self):
        """Expired cache entries should not be returned."""
        resolver = SIDResolver(cache_ttl_hours=1, enable_graph=False)

        # Add expired entry
        old_user = ResolvedUser(
            sid="S-1-5-21-123-456-789-1234",
            display_name="Old Name",
            resolution_source="graph_api",
        )
        expired_time = datetime.now(timezone.utc) - timedelta(hours=2)
        resolver._cache["S-1-5-21-123-456-789-1234"] = (old_user, expired_time)

        # Should not hit cache
        result = resolver.resolve_sync("S-1-5-21-123-456-789-1234")
        assert result.resolution_source == "fallback_sync"
        assert result.display_name == "S-1-5-21-123-456-789-1234"

    def test_cache_stats(self):
        """Cache stats should be accurate."""
        resolver = SIDResolver(enable_graph=False)

        # Add some entries
        for i in range(5):
            user = ResolvedUser(sid=f"S-1-5-21-{i}", display_name=f"User {i}")
            resolver._cache[f"S-1-5-21-{i}"] = (user, datetime.now(timezone.utc))

        # Add expired entry
        old_user = ResolvedUser(sid="S-1-5-21-old", display_name="Old")
        expired_time = datetime.now(timezone.utc) - timedelta(hours=100)
        resolver._cache["S-1-5-21-old"] = (old_user, expired_time)

        stats = resolver.get_cache_stats()
        assert stats["total_entries"] == 6
        assert stats["valid_entries"] == 5
        assert stats["expired_entries"] == 1

    def test_cache_clear(self):
        """Cache should be clearable."""
        resolver = SIDResolver(enable_graph=False)

        # Add entry
        user = ResolvedUser(sid="S-1-5-21-test", display_name="Test")
        resolver._cache["S-1-5-21-test"] = (user, datetime.now(timezone.utc))

        assert len(resolver._cache) == 1

        resolver.clear_cache()
        assert len(resolver._cache) == 0


class TestResolvedUser:
    """Tests for ResolvedUser dataclass."""

    def test_best_name_display_name(self):
        """best_name should prefer display_name."""
        user = ResolvedUser(
            sid="S-1-5-21-test",
            display_name="John Smith",
            user_principal_name="jsmith@contoso.com",
            domain_username="CONTOSO\\jsmith",
        )
        assert user.best_name == "John Smith"

    def test_best_name_domain_username(self):
        """best_name should fallback to domain_username."""
        user = ResolvedUser(
            sid="S-1-5-21-test",
            domain_username="CONTOSO\\jsmith",
        )
        assert user.best_name == "CONTOSO\\jsmith"

    def test_best_name_upn(self):
        """best_name should fallback to user_principal_name."""
        user = ResolvedUser(
            sid="S-1-5-21-test",
            user_principal_name="jsmith@contoso.com",
        )
        assert user.best_name == "jsmith@contoso.com"

    def test_best_name_sid_fallback(self):
        """best_name should fallback to SID."""
        user = ResolvedUser(sid="S-1-5-21-test")
        assert user.best_name == "S-1-5-21-test"


class TestSingleton:
    """Tests for singleton pattern."""

    def test_get_resolver_returns_same_instance(self):
        """get_sid_resolver should return same instance."""
        reset_sid_resolver()
        resolver1 = get_sid_resolver()
        resolver2 = get_sid_resolver()
        assert resolver1 is resolver2

    def test_reset_clears_singleton(self):
        """reset_sid_resolver should clear singleton."""
        reset_sid_resolver()
        resolver1 = get_sid_resolver()
        reset_sid_resolver()
        resolver2 = get_sid_resolver()
        assert resolver1 is not resolver2


class TestAsyncResolution:
    """Tests for async resolution (mocked Graph API)."""

    @pytest.mark.asyncio
    async def test_resolve_well_known_async(self):
        """Async resolve should handle well-known SIDs."""
        resolver = SIDResolver(enable_graph=False)
        result = await resolver.resolve("S-1-5-18")
        assert result.display_name == "Local System"

    @pytest.mark.asyncio
    async def test_resolve_with_graph_mock(self):
        """Async resolve should use Graph API when available."""
        resolver = SIDResolver(enable_graph=True)

        # Mock the graph client
        mock_graph_user = MagicMock()
        mock_graph_user.id = "user-guid"
        mock_graph_user.display_name = "Jane Doe"
        mock_graph_user.user_principal_name = "jdoe@contoso.com"
        mock_graph_user.on_premises_sam_account_name = "CONTOSO\\jdoe"
        mock_graph_user.department = "Engineering"
        mock_graph_user.job_title = "Software Engineer"

        mock_client = MagicMock()
        mock_client.get_user_by_on_prem_sid = AsyncMock(return_value=mock_graph_user)

        resolver._graph_client = mock_client
        resolver.enable_graph = True

        result = await resolver.resolve("S-1-5-21-123-456-789-1234")

        assert result.display_name == "Jane Doe"
        assert result.user_principal_name == "jdoe@contoso.com"
        assert result.domain_username == "CONTOSO\\jdoe"
        assert result.entra_object_id == "user-guid"
        assert result.resolution_source == "graph_api"

    @pytest.mark.asyncio
    async def test_resolve_graph_not_found(self):
        """Async resolve should fallback when user not found in Graph."""
        resolver = SIDResolver(enable_graph=True)

        # Mock the graph client returning None
        mock_client = MagicMock()
        mock_client.get_user_by_on_prem_sid = AsyncMock(return_value=None)

        resolver._graph_client = mock_client
        resolver.enable_graph = True

        result = await resolver.resolve("S-1-5-21-123-456-789-9999")

        assert result.resolution_source == "fallback"
        assert result.display_name == "S-1-5-21-123-456-789-9999"

    @pytest.mark.asyncio
    async def test_resolve_batch(self):
        """Batch resolution should resolve multiple SIDs."""
        resolver = SIDResolver(enable_graph=False)

        sids = ["S-1-5-18", "S-1-5-19", "S-1-5-21-123-456-789-1234"]
        results = await resolver.resolve_batch(sids)

        assert len(results) == 3
        assert results["S-1-5-18"].display_name == "Local System"
        assert results["S-1-5-19"].display_name == "NT Authority\\Local Service"

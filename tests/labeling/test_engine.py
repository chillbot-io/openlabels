"""
Tests for labeling engine.

Tests cover LabelCache, LabelResult, TokenCache, and LabelingEngine behavior.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock, patch

import pytest


# =============================================================================
# LABEL CACHE TESTS
# =============================================================================


class TestLabelCache:
    """Tests for LabelCache singleton and caching behavior."""

    def test_singleton_pattern(self):
        """LabelCache should be a singleton."""
        from openlabels.labeling.engine import LabelCache

        cache1 = LabelCache()
        cache2 = LabelCache()

        assert cache1 is cache2

    def test_starts_expired(self):
        """Cache should start in expired state."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.invalidate()  # Reset state

        assert cache.is_expired() is True

    def test_set_marks_not_expired(self):
        """Setting labels should mark cache as not expired."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.set([{"id": "1", "name": "Test"}])

        assert cache.is_expired() is False

    def test_get_returns_none_when_expired(self):
        """Get should return None when cache is expired."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.invalidate()

        result = cache.get("any-id")

        assert result is None

    def test_get_returns_cached_label(self):
        """Get should return cached label by ID."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.set([
            {"id": "label-123", "name": "Confidential", "description": "Secret stuff"}
        ])

        result = cache.get("label-123")

        assert result is not None
        assert result.id == "label-123"
        assert result.name == "Confidential"

    def test_get_by_name_returns_cached_label(self):
        """Get by name should return cached label."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.set([
            {"id": "label-abc", "name": "Public", "description": ""}
        ])

        result = cache.get_by_name("Public")

        assert result is not None
        assert result.id == "label-abc"

    def test_get_all_returns_empty_when_expired(self):
        """Get all should return empty list when expired."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.invalidate()

        result = cache.get_all()

        assert result == []

    def test_invalidate_clears_cache(self):
        """Invalidate should clear all cached labels."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.set([{"id": "1", "name": "Test"}])

        cache.invalidate()

        assert cache.is_expired() is True
        assert cache.get_all() == []

    def test_configure_sets_ttl(self):
        """Configure should set TTL."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.configure(ttl_seconds=600)

        assert cache._ttl_seconds == 600

    def test_stats_includes_label_count(self):
        """Stats should include label count."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.set([
            {"id": "1", "name": "A"},
            {"id": "2", "name": "B"},
        ])

        stats = cache.stats

        assert stats["label_count"] == 2


# =============================================================================
# CACHED LABEL TESTS
# =============================================================================


class TestCachedLabel:
    """Tests for CachedLabel dataclass."""

    def test_to_dict(self):
        """to_dict should return label fields."""
        from openlabels.labeling.engine import CachedLabel

        label = CachedLabel(
            id="label-123",
            name="Confidential",
            description="Secret documents",
            color="#FF0000",
            priority=10,
            parent_id="parent-456",
        )

        result = label.to_dict()

        assert result["id"] == "label-123"
        assert result["name"] == "Confidential"
        assert result["description"] == "Secret documents"
        assert result["color"] == "#FF0000"
        assert result["priority"] == 10
        assert result["parent_id"] == "parent-456"


# =============================================================================
# LABEL RESULT TESTS
# =============================================================================


class TestLabelResult:
    """Tests for LabelResult dataclass."""

    def test_successful_result(self):
        """Successful result should have success=True and label info."""
        from openlabels.labeling.engine import LabelResult

        result = LabelResult(
            success=True,
            label_id="label-123",
            label_name="Confidential",
            method="graph_api",
        )

        assert result.success is True
        assert result.label_id == "label-123"
        assert result.label_name == "Confidential"
        assert result.method == "graph_api"
        assert result.error is None

    def test_failed_result(self):
        """Failed result should have success=False and error."""
        from openlabels.labeling.engine import LabelResult

        result = LabelResult(
            success=False,
            error="File not found",
        )

        assert result.success is False
        assert result.error == "File not found"
        assert result.label_id is None

    def test_defaults(self):
        """Optional fields should default to None."""
        from openlabels.labeling.engine import LabelResult

        result = LabelResult(success=True)

        assert result.label_id is None
        assert result.label_name is None
        assert result.method is None
        assert result.error is None


# =============================================================================
# TOKEN CACHE TESTS
# =============================================================================


class TestTokenCache:
    """Tests for TokenCache."""

    def test_is_valid_false_when_empty(self):
        """Empty token should be invalid."""
        from openlabels.labeling.engine import TokenCache

        cache = TokenCache()

        assert cache.is_valid() is False

    def test_is_valid_false_when_expired(self):
        """Expired token should be invalid."""
        from openlabels.labeling.engine import TokenCache

        cache = TokenCache(
            access_token="some-token",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )

        assert cache.is_valid() is False

    def test_is_valid_true_when_fresh(self):
        """Fresh token should be valid."""
        from openlabels.labeling.engine import TokenCache

        cache = TokenCache(
            access_token="some-token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )

        assert cache.is_valid() is True

    def test_is_valid_accounts_for_buffer(self):
        """Token expiring within 5 minutes should be considered invalid."""
        from openlabels.labeling.engine import TokenCache

        # Expires in 3 minutes - should be invalid due to 5 min buffer
        cache = TokenCache(
            access_token="some-token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=3)
        )

        assert cache.is_valid() is False


# =============================================================================
# LABELING ENGINE CONFIGURATION TESTS
# =============================================================================


class TestLabelingEngineConfiguration:
    """Tests for LabelingEngine configuration."""

    def test_stores_tenant_id(self):
        """Engine should store tenant_id."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="my-tenant",
            client_id="my-client",
            client_secret="my-secret",
        )

        assert engine.tenant_id == "my-tenant"

    def test_stores_client_id(self):
        """Engine should store client_id."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="my-tenant",
            client_id="my-client",
            client_secret="my-secret",
        )

        assert engine.client_id == "my-client"

    def test_stores_client_secret(self):
        """Engine should store client_secret."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="my-tenant",
            client_id="my-client",
            client_secret="my-secret",
        )

        assert engine.client_secret == "my-secret"

    def test_has_retry_configuration(self):
        """Engine should have retry configuration."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert engine._max_retries > 0
        assert engine._base_delay > 0

    def test_token_cache_starts_invalid(self):
        """Token cache should start in invalid state."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert engine._token_cache.is_valid() is False


# =============================================================================
# LABELING ENGINE ROUTING TESTS
# =============================================================================


class TestLabelingEngineRouting:
    """Tests for labeling engine routing logic."""

    @pytest.mark.asyncio
    async def test_apply_label_routes_filesystem_to_local(self):
        """Filesystem files should route to local labeling."""
        from openlabels.labeling.engine import LabelingEngine
        from openlabels.adapters.base import FileInfo

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        file_info = FileInfo(
            path="/test/file.txt",
            name="file.txt",
            size=100,
            modified=datetime.now(),
            adapter="filesystem",
        )

        # Mock the local labeling method
        with patch.object(engine, '_apply_local_label') as mock_local:
            mock_local.return_value = MagicMock(success=True)

            await engine.apply_label(file_info, "label-123")

            mock_local.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_label_routes_sharepoint_to_graph(self):
        """SharePoint files should route to Graph API."""
        from openlabels.labeling.engine import LabelingEngine
        from openlabels.adapters.base import FileInfo

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        file_info = FileInfo(
            path="/test/file.txt",
            name="file.txt",
            size=100,
            modified=datetime.now(),
            adapter="sharepoint",
            site_id="site-123",
            item_id="item-456",
        )

        with patch.object(engine, '_apply_graph_label') as mock_graph:
            mock_graph.return_value = MagicMock(success=True)

            await engine.apply_label(file_info, "label-123")

            mock_graph.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_label_routes_onedrive_to_graph(self):
        """OneDrive files should route to Graph API."""
        from openlabels.labeling.engine import LabelingEngine
        from openlabels.adapters.base import FileInfo

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        file_info = FileInfo(
            path="/test/file.txt",
            name="file.txt",
            size=100,
            modified=datetime.now(),
            adapter="onedrive",
            user_id="user@example.com",
            item_id="item-789",
        )

        with patch.object(engine, '_apply_graph_label') as mock_graph:
            mock_graph.return_value = MagicMock(success=True)

            await engine.apply_label(file_info, "label-123")

            mock_graph.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_label_fails_for_unknown_adapter(self):
        """Unknown adapter should return failure."""
        from openlabels.labeling.engine import LabelingEngine
        from openlabels.adapters.base import FileInfo

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        file_info = FileInfo(
            path="/test/file.txt",
            name="file.txt",
            size=100,
            modified=datetime.now(),
            adapter="unknown_adapter",
        )

        result = await engine.apply_label(file_info, "label-123")

        assert result.success is False
        assert "Unknown adapter" in result.error


# =============================================================================
# LABELING ENGINE METHODS TESTS
# =============================================================================


class TestLabelingEngineMethods:
    """Tests verifying engine has required methods."""

    def test_has_apply_label_method(self):
        """Engine should have async apply_label method."""
        from openlabels.labeling.engine import LabelingEngine
        import inspect

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(engine, 'apply_label')
        assert inspect.iscoroutinefunction(engine.apply_label)

    def test_has_remove_label_method(self):
        """Engine should have async remove_label method."""
        from openlabels.labeling.engine import LabelingEngine
        import inspect

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(engine, 'remove_label')
        assert inspect.iscoroutinefunction(engine.remove_label)

    def test_has_get_available_labels_method(self):
        """Engine should have async get_available_labels method."""
        from openlabels.labeling.engine import LabelingEngine
        import inspect

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(engine, 'get_available_labels')
        assert inspect.iscoroutinefunction(engine.get_available_labels)

    def test_has_get_current_label_method(self):
        """Engine should have async get_current_label method."""
        from openlabels.labeling.engine import LabelingEngine
        import inspect

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(engine, 'get_current_label')
        assert inspect.iscoroutinefunction(engine.get_current_label)

    def test_has_invalidate_cache_method(self):
        """Engine should have invalidate_label_cache method."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert hasattr(engine, 'invalidate_label_cache')
        assert callable(engine.invalidate_label_cache)

    def test_has_label_cache_stats_property(self):
        """Engine should have label_cache_stats property."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        stats = engine.label_cache_stats

        assert isinstance(stats, dict)
        assert "label_count" in stats


# =============================================================================
# GET LABEL CACHE FUNCTION TESTS
# =============================================================================


class TestGetLabelCache:
    """Tests for get_label_cache function."""

    def test_returns_cache_instance(self):
        """get_label_cache should return LabelCache instance."""
        from openlabels.labeling.engine import get_label_cache, LabelCache

        cache = get_label_cache()

        assert isinstance(cache, LabelCache)

    def test_returns_same_instance(self):
        """get_label_cache should return same singleton instance."""
        from openlabels.labeling.engine import get_label_cache

        cache1 = get_label_cache()
        cache2 = get_label_cache()

        assert cache1 is cache2

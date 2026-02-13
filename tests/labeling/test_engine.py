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

        assert result.id == "label-123"
        assert result.name == "Confidential"
        assert result.description == "Secret stuff"

    def test_get_by_name_returns_cached_label(self):
        """Get by name should return cached label."""
        from openlabels.labeling.engine import LabelCache

        cache = LabelCache()
        cache.set([
            {"id": "label-abc", "name": "Public", "description": ""}
        ])

        result = cache.get_by_name("Public")

        assert result.id == "label-abc"
        assert result.name == "Public"

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
# LABELING ENGINE CONFIGURATION TESTS
# =============================================================================


class TestLabelingEngineConfiguration:
    """Tests for LabelingEngine configuration."""

    def test_graph_client_starts_none_when_not_provided(self):
        """GraphClient should be None until first Graph API call."""
        from openlabels.labeling.engine import LabelingEngine

        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s"
        )

        assert engine._graph_client is None
        assert engine._owns_graph_client is True

    def test_graph_client_injected(self):
        """Injected GraphClient should be used directly."""
        from openlabels.labeling.engine import LabelingEngine
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        engine = LabelingEngine(
            tenant_id="t", client_id="c", client_secret="s",
            graph_client=mock_client,
        )

        assert engine._graph_client is mock_client
        assert engine._owns_graph_client is False


# =============================================================================
# LABELING ENGINE ROUTING TESTS
# =============================================================================


class TestLabelingEngineRouting:
    """Tests for labeling engine routing logic."""

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

            # _apply_local_label receives (file_path_str, label_id, label_name)
            mock_local.assert_called_once_with("/test/file.txt", "label-123", None)

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

            # _apply_graph_label receives (file_info, label_id, label_name)
            mock_graph.assert_called_once_with(file_info, "label-123", None)

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

            # _apply_graph_label receives (file_info, label_id, label_name)
            mock_graph.assert_called_once_with(file_info, "label-123", None)

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




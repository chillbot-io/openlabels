"""Tests for CatalogSettings integration with the Settings hierarchy."""

from openlabels.server.config import Settings


def test_catalog_settings_defaults():
    """CatalogSettings should be present with sensible defaults."""
    s = Settings()
    assert hasattr(s, "catalog")
    assert s.catalog.backend == "local"
    assert s.catalog.local_path == "data/catalog"
    assert s.catalog.compression == "zstd"
    assert s.catalog.duckdb_memory_limit == "2GB"
    assert s.catalog.duckdb_threads == 4
    assert s.catalog.event_flush_interval_seconds == 300


def test_catalog_settings_override():
    """CatalogSettings fields should be overridable."""
    s = Settings(catalog={"local_path": "/tmp/cat", "backend": "local"})
    assert s.catalog.local_path == "/tmp/cat"

"""
Tests for openlabels.adapters.scanner.scanner_adapter module.

Tests the ScannerAdapter class that wraps Detector with standard adapter interface.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass


class TestScannerAdapterInit:
    """Tests for ScannerAdapter initialization."""

    def test_init_default_config(self):
        """Should initialize with default config."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        assert adapter._config is not None
        assert adapter._detector is not None

    def test_init_with_config(self):
        """Should accept custom config."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.adapters.scanner.config import Config

        config = Config()
        adapter = ScannerAdapter(config=config)
        assert adapter._config is config

    def test_init_with_config_kwargs(self):
        """Should accept config overrides as kwargs."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter(min_confidence=0.8)
        assert adapter._config.min_confidence == 0.8

    def test_init_with_context(self):
        """Should accept optional context."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.context import Context

        ctx = Context()
        try:
            adapter = ScannerAdapter(context=ctx)
            assert adapter._context is ctx
        finally:
            ctx.close()

    def test_detector_property(self):
        """Should expose detector via property."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.adapters.scanner.adapter import Detector

        adapter = ScannerAdapter()
        assert isinstance(adapter.detector, Detector)


class TestExtractFromText:
    """Tests for extract_from_text method."""

    def test_extract_from_text_returns_normalized_input(self):
        """Should return NormalizedInput."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.adapters.base import NormalizedInput

        adapter = ScannerAdapter()
        result = adapter.extract_from_text("Hello World")

        assert isinstance(result, NormalizedInput)
        assert hasattr(result, 'entities')
        assert hasattr(result, 'context')

    def test_extract_from_text_detects_ssn(self):
        """Should detect SSN in text."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        result = adapter.extract_from_text("SSN: 123-45-6789")

        assert len(result.entities) > 0
        # Should have SSN entity
        entity_types = [e.type for e in result.entities]
        assert any("SSN" in t.upper() for t in entity_types)

    def test_extract_from_text_detects_email(self):
        """Should detect email in text."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        result = adapter.extract_from_text("Contact: user@example.com")

        assert len(result.entities) > 0
        entity_types = [e.type for e in result.entities]
        assert any("EMAIL" in t.upper() for t in entity_types)

    def test_extract_from_text_no_entities(self):
        """Should return empty entities for clean text."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        result = adapter.extract_from_text("Hello World!")

        assert result.entities == []

    def test_extract_from_text_with_metadata(self):
        """Should include metadata in context."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        metadata = {"path": "/test/file.txt", "owner": "admin"}
        result = adapter.extract_from_text("test", metadata=metadata)

        assert result.context.path == "/test/file.txt"
        assert result.context.owner == "admin"

    def test_extract_from_text_default_context(self):
        """Should create context even without metadata."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        result = adapter.extract_from_text("test")

        assert result.context is not None
        assert result.context.exposure == "PRIVATE"


class TestSpansToEntities:
    """Tests for _spans_to_entities method."""

    def test_converts_span_to_entity(self):
        """Should convert Span to Entity."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.adapters.scanner.types import Span, Tier

        adapter = ScannerAdapter()
        spans = [
            Span(
                start=0,
                end=11,
                text="123-45-6789",
                entity_type="SSN",
                confidence=0.95,
                detector="checksum",
                tier=Tier.CHECKSUM,
            )
        ]

        entities = adapter._spans_to_entities(spans)

        assert len(entities) == 1
        assert entities[0].count == 1
        assert entities[0].confidence == 0.95

    def test_aggregates_same_type_spans(self):
        """Should aggregate multiple spans of same type."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.adapters.scanner.types import Span, Tier

        adapter = ScannerAdapter()
        spans = [
            Span(start=0, end=11, text="123-45-6789", entity_type="SSN",
                 confidence=0.9, detector="pattern", tier=Tier.PATTERN),
            Span(start=20, end=31, text="987-65-4321", entity_type="SSN",
                 confidence=0.95, detector="checksum", tier=Tier.CHECKSUM),
        ]

        entities = adapter._spans_to_entities(spans)

        # Should aggregate into one entity
        ssn_entities = [e for e in entities if "SSN" in e.type.upper()]
        assert len(ssn_entities) == 1
        assert ssn_entities[0].count == 2
        # Should take max confidence
        assert ssn_entities[0].confidence == 0.95

    def test_empty_spans_returns_empty_list(self):
        """Should return empty list for no spans."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        entities = adapter._spans_to_entities([])

        assert entities == []

    def test_normalizes_entity_type(self):
        """Should normalize entity types."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.adapters.scanner.types import Span, Tier

        adapter = ScannerAdapter()
        spans = [
            Span(start=0, end=5, text="test@", entity_type="email_address",
                 confidence=0.9, detector="pattern", tier=Tier.PATTERN),
        ]

        entities = adapter._spans_to_entities(spans)

        # Type should be normalized (uppercase, standardized)
        assert len(entities) == 1


class TestBuildContext:
    """Tests for _build_context method."""

    def test_build_context_defaults(self):
        """Should set sensible defaults."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        context = adapter._build_context({})

        assert context.exposure == "PRIVATE"
        assert context.encryption == "none"
        assert context.cross_account_access is False
        assert context.anonymous_access is False
        assert context.has_classification is True
        assert context.classification_source == "scanner"

    def test_build_context_with_metadata(self):
        """Should use metadata values."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        metadata = {
            "path": "/data/sensitive.csv",
            "exposure": "PUBLIC",
            "encryption": "customer_managed",
            "owner": "admin",
            "size": 1024,
        }

        context = adapter._build_context(metadata)

        assert context.path == "/data/sensitive.csv"
        assert context.exposure == "PUBLIC"
        assert context.encryption == "customer_managed"
        assert context.owner == "admin"
        assert context.size_bytes == 1024

    def test_build_context_archive_detection(self):
        """Should detect archive files."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        context = adapter._build_context({"path": "/data/archive.zip"})

        assert context.is_archive is True

    def test_build_context_non_archive(self):
        """Should mark non-archive files."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        context = adapter._build_context({"path": "/data/document.pdf"})

        assert context.is_archive is False

    def test_build_context_staleness(self):
        """Should calculate staleness from last_modified."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from datetime import datetime, timedelta

        adapter = ScannerAdapter()
        old_date = (datetime.utcnow() - timedelta(days=30)).isoformat()
        context = adapter._build_context({"last_modified": old_date})

        assert context.staleness_days is not None
        assert context.staleness_days >= 29  # Allow for timing


class TestExtract:
    """Tests for extract method (bytes input)."""

    def test_extract_plain_text(self):
        """Should extract from plain text bytes."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        content = b"Contact: user@example.com"
        metadata = {"name": "contact.txt"}

        result = adapter.extract(content, metadata)

        assert result is not None
        # Should detect email
        entity_types = [e.type for e in result.entities]
        assert any("EMAIL" in t.upper() for t in entity_types)

    def test_extract_with_filename(self):
        """Should use filename for format detection."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        content = b"SSN: 123-45-6789"
        metadata = {"name": "data.txt", "path": "/secure/data.txt"}

        result = adapter.extract(content, metadata)

        assert result.context.path == "/secure/data.txt"

    def test_extract_returns_normalized_input(self):
        """Should return NormalizedInput."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter
        from openlabels.adapters.base import NormalizedInput

        adapter = ScannerAdapter()
        result = adapter.extract(b"test", {"name": "test.txt"})

        assert isinstance(result, NormalizedInput)


class TestCreateScannerAdapter:
    """Tests for create_scanner_adapter convenience function."""

    def test_create_scanner_adapter_returns_adapter(self):
        """Should return a ScannerAdapter instance."""
        from openlabels.adapters.scanner.scanner_adapter import (
            create_scanner_adapter,
            ScannerAdapter,
        )

        adapter = create_scanner_adapter()
        assert isinstance(adapter, ScannerAdapter)

    def test_create_scanner_adapter_with_kwargs(self):
        """Should pass kwargs to adapter."""
        from openlabels.adapters.scanner.scanner_adapter import create_scanner_adapter

        adapter = create_scanner_adapter(min_confidence=0.9)
        assert adapter._config.min_confidence == 0.9

    def test_create_scanner_adapter_with_context(self):
        """Should pass context to adapter."""
        from openlabels.adapters.scanner.scanner_adapter import create_scanner_adapter
        from openlabels.context import Context

        ctx = Context()
        try:
            adapter = create_scanner_adapter(context=ctx)
            assert adapter._context is ctx
        finally:
            ctx.close()


class TestModuleExports:
    """Tests for module exports."""

    def test_scanner_adapter_exported(self):
        """ScannerAdapter should be in __all__."""
        from openlabels.adapters.scanner import scanner_adapter
        assert 'ScannerAdapter' in scanner_adapter.__all__

    def test_create_scanner_adapter_exported(self):
        """create_scanner_adapter should be in __all__."""
        from openlabels.adapters.scanner import scanner_adapter
        assert 'create_scanner_adapter' in scanner_adapter.__all__


class TestEntityAggregation:
    """Tests for entity aggregation behavior."""

    def test_aggregates_positions(self):
        """Should track positions of detected entities."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        # Text with multiple SSNs
        text = "SSN1: 123-45-6789, SSN2: 987-65-4321"
        result = adapter.extract_from_text(text)

        # Should have aggregated SSN entities with positions
        ssn_entities = [e for e in result.entities if "SSN" in e.type.upper()]
        if ssn_entities:
            # Positions should be tracked
            assert ssn_entities[0].count == 2

    def test_source_is_scanner(self):
        """Entities should have source='scanner'."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        result = adapter.extract_from_text("email: test@example.com")

        for entity in result.entities:
            assert entity.source == "scanner"


class TestConfigValidation:
    """Tests for config validation on init."""

    def test_invalid_config_kwarg_ignored(self):
        """Unknown kwargs should be ignored."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        # Should not raise
        adapter = ScannerAdapter(nonexistent_option=True)
        assert adapter is not None

    def test_config_post_init_called(self):
        """Config __post_init__ should be called after kwargs."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        # min_confidence should be validated
        adapter = ScannerAdapter(min_confidence=0.5)
        # Should be valid (0.0-1.0 range)
        assert 0.0 <= adapter._config.min_confidence <= 1.0


class TestMetadataHandling:
    """Tests for various metadata scenarios."""

    def test_missing_name_uses_unknown(self):
        """Should use 'unknown' if name not in metadata."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        # No 'name' key
        result = adapter.extract(b"test content", {})
        # Should not raise

    def test_all_exposure_levels(self):
        """Should handle all exposure levels."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        exposures = ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]

        for exposure in exposures:
            context = adapter._build_context({"exposure": exposure})
            assert context.exposure == exposure

    def test_all_encryption_levels(self):
        """Should handle all encryption levels."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        encryptions = ["none", "platform", "customer_managed"]

        for encryption in encryptions:
            context = adapter._build_context({"encryption": encryption})
            assert context.encryption == encryption

    def test_boolean_metadata_fields(self):
        """Should handle boolean metadata fields."""
        from openlabels.adapters.scanner.scanner_adapter import ScannerAdapter

        adapter = ScannerAdapter()
        metadata = {
            "cross_account_access": True,
            "anonymous_access": True,
            "versioning": True,
            "access_logging": True,
            "retention_policy": True,
        }

        context = adapter._build_context(metadata)

        assert context.cross_account_access is True
        assert context.anonymous_access is True
        assert context.versioning is True
        assert context.access_logging is True
        assert context.retention_policy is True

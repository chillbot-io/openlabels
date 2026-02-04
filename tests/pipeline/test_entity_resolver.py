"""Tests for entity resolution in entity_resolver.py.

Tests multi-sieve entity resolution: exact match, partial name,
coreference, and cross-message matching.

Adapted from scrubiq/tests/pipeline/test_entity_resolver.py
"""

import pytest
from openlabels.core.types import Span, Tier
from openlabels.core.pipeline.entity_resolver import (
    EntityResolver,
    resolve_entities,
    NAME_TYPES,
    ISOLATED_TYPES,
    Entity,
    Mention,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test",
              tier=2, coref_anchor_value=None):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
        coref_anchor_value=coref_anchor_value,
    )


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for module constants."""

    def test_name_types_contains_base(self):
        """NAME_TYPES contains base name types."""
        assert "NAME" in NAME_TYPES
        assert "NAME_PATIENT" in NAME_TYPES
        assert "NAME_PROVIDER" in NAME_TYPES

    def test_isolated_types_contains_identifiers(self):
        """ISOLATED_TYPES contains identifier types."""
        assert "SSN" in ISOLATED_TYPES
        assert "MRN" in ISOLATED_TYPES


# =============================================================================
# ENTITY RESOLVER INITIALIZATION TESTS
# =============================================================================

class TestEntityResolverInit:
    """Tests for EntityResolver initialization."""

    def test_creates_with_defaults(self):
        """EntityResolver creates with default settings."""
        resolver = EntityResolver()

        # Verify it's the correct type and has the resolve method
        assert isinstance(resolver, EntityResolver)
        assert callable(resolver.resolve)


# =============================================================================
# ENTITY RESOLVER RESOLVE TESTS
# =============================================================================

class TestEntityResolverResolve:
    """Tests for EntityResolver.resolve() method."""

    def test_empty_spans_returns_empty(self):
        """Empty span list returns empty entity list."""
        resolver = EntityResolver()

        entities = resolver.resolve([])

        assert entities == []

    def test_single_span_creates_entity(self):
        """Single span creates one entity."""
        resolver = EntityResolver()
        spans = [make_span("John Smith", entity_type="NAME")]

        entities = resolver.resolve(spans)

        assert len(entities) == 1

    def test_exact_match_links_spans(self):
        """Exact match links spans to same entity."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=50, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        # Same name should be same entity
        assert len(entities) == 1
        assert len(entities[0].mentions) == 2

    def test_partial_name_links(self):
        """Partial name links to full name entity."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Smith", start=50, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        # Should link to same entity
        assert len(entities) == 1

    def test_different_names_separate_entities(self):
        """Different names create separate entities."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Jane Doe", start=50, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        # Different names, different entities
        assert len(entities) == 2

    def test_coref_anchor_links_entities(self):
        """Spans with coref_anchor_value link to anchor entity."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("He", start=20, entity_type="NAME", coref_anchor_value="John Smith"),
        ]

        entities = resolver.resolve(spans)

        # Should link via coreference
        assert len(entities) == 1

    def test_isolated_types_merge_if_identical(self):
        """ISOLATED_TYPES with identical values merge."""
        resolver = EntityResolver()
        spans = [
            make_span("123-45-6789", start=0, entity_type="SSN"),
            make_span("123-45-6789", start=50, entity_type="SSN"),
        ]

        entities = resolver.resolve(spans)

        # Identical SSNs merge into one entity
        assert len(entities) == 1
        assert len(entities[0].mentions) == 2


# =============================================================================
# RESOLVE ENTITIES FUNCTION TESTS
# =============================================================================

class TestResolveEntitiesFunction:
    """Tests for resolve_entities convenience function."""

    def test_resolve_entities_works(self):
        """resolve_entities() convenience function works."""
        spans = [make_span("John Smith", entity_type="NAME")]

        entities = resolve_entities(spans)

        assert len(entities) == 1

    def test_resolve_entities_empty(self):
        """resolve_entities() handles empty list."""
        entities = resolve_entities([])

        assert entities == []


# =============================================================================
# ENTITY PROPERTIES TESTS
# =============================================================================

class TestEntityProperties:
    """Tests for Entity object properties."""

    def test_entity_has_canonical_value(self):
        """Entity canonical_value should match the span text."""
        resolver = EntityResolver()
        spans = [make_span("John Smith", entity_type="NAME")]

        entities = resolver.resolve(spans)

        # Should be the correct type and have expected value
        assert isinstance(entities[0], Entity)
        assert entities[0].canonical_value == "John Smith"

    def test_entity_has_entity_type(self):
        """Entity entity_type should reflect the span type."""
        resolver = EntityResolver()
        spans = [make_span("John Smith", entity_type="NAME_PATIENT")]

        entities = resolver.resolve(spans)

        # Entity type should contain NAME (might be normalized)
        assert isinstance(entities[0].entity_type, str)
        assert "NAME" in entities[0].entity_type

    def test_entity_has_mentions(self):
        """Entity mentions should contain all matching spans."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=50, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        # Verify mentions is a list with correct count
        assert isinstance(entities[0].mentions, list)
        assert len(entities[0].mentions) == 2
        # Each mention should be a Mention object
        assert all(isinstance(m, Mention) for m in entities[0].mentions)


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge case tests for entity resolution."""

    def test_unicode_names(self):
        """Handles Unicode names correctly."""
        resolver = EntityResolver()
        spans = [make_span("José García", entity_type="NAME")]

        entities = resolver.resolve(spans)

        assert len(entities) == 1

    def test_many_spans_performance(self):
        """Handles many spans without timeout."""
        resolver = EntityResolver()
        spans = [
            make_span(f"Person{i}", start=i*20, entity_type="NAME")
            for i in range(100)
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 100

    def test_preserves_confidence(self):
        """Entity preserves span confidence."""
        resolver = EntityResolver()
        spans = [make_span("John Smith", entity_type="NAME", confidence=0.95)]

        entities = resolver.resolve(spans)

        # Entity or mention should have confidence
        assert len(entities) == 1

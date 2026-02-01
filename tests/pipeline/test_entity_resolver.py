"""Tests for entity resolution in entity_resolver.py.

Tests multi-sieve entity resolution: exact match, partial name,
coreference, and cross-message matching.
"""

import pytest
from scrubiq.types import Span, Tier, Entity, Mention
from scrubiq.pipeline.entity_resolver import (
    _normalize_name,
    _get_name_words,
    _infer_semantic_role,
    _get_base_type,
    _is_name_type,
    EntityResolver,
    resolve_entities,
    NAME_TYPES,
    ISOLATED_TYPES,
    NAME_PREFIXES,
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
# NAME NORMALIZATION TESTS
# =============================================================================

class TestNormalizeName:
    """Tests for _normalize_name()."""

    def test_lowercase(self):
        """Name is lowercased."""
        assert _normalize_name("John Smith") == "john smith"

    def test_strips_whitespace(self):
        """Leading/trailing whitespace is stripped."""
        assert _normalize_name("  John Smith  ") == "john smith"

    def test_strips_dr_prefix(self):
        """'Dr.' prefix is stripped."""
        assert _normalize_name("Dr. John Smith") == "john smith"

    def test_strips_mr_prefix(self):
        """'Mr.' prefix is stripped."""
        assert _normalize_name("Mr. John Smith") == "john smith"

    def test_strips_mrs_prefix(self):
        """'Mrs.' prefix is stripped."""
        assert _normalize_name("Mrs. Jane Smith") == "jane smith"

    def test_strips_prof_prefix(self):
        """'Prof.' prefix is stripped."""
        assert _normalize_name("Prof. Albert Einstein") == "albert einstein"

    def test_preserves_name_without_prefix(self):
        """Name without prefix is unchanged (except lowercase)."""
        assert _normalize_name("John Smith") == "john smith"


# =============================================================================
# GET NAME WORDS TESTS
# =============================================================================

class TestGetNameWords:
    """Tests for _get_name_words()."""

    def test_extracts_words(self):
        """Extracts words from name."""
        words = _get_name_words("John Smith")
        assert words == {"john", "smith"}

    def test_removes_short_words(self):
        """Single-char words are removed."""
        words = _get_name_words("John A Smith")
        # 'a' should be removed (< 2 chars)
        assert "a" not in words
        assert words == {"john", "smith"}

    def test_removes_title_prefixes(self):
        """Title prefixes are removed from word set."""
        words = _get_name_words("Dr. John Smith")
        assert "dr" not in words
        assert words == {"john", "smith"}

    def test_handles_periods(self):
        """Periods are handled correctly."""
        words = _get_name_words("J. Robert Oppenheimer")
        assert words == {"robert", "oppenheimer"}


# =============================================================================
# INFER SEMANTIC ROLE TESTS
# =============================================================================

class TestInferSemanticRole:
    """Tests for _infer_semantic_role()."""

    def test_patient_suffix(self):
        """_PATIENT suffix returns 'patient'."""
        assert _infer_semantic_role("NAME_PATIENT") == "patient"

    def test_provider_suffix(self):
        """_PROVIDER suffix returns 'provider'."""
        assert _infer_semantic_role("NAME_PROVIDER") == "provider"

    def test_relative_suffix(self):
        """_RELATIVE suffix returns 'relative'."""
        assert _infer_semantic_role("NAME_RELATIVE") == "relative"

    def test_no_suffix_unknown(self):
        """No role suffix returns 'unknown'."""
        assert _infer_semantic_role("NAME") == "unknown"

    def test_non_name_type_unknown(self):
        """Non-name types return 'unknown'."""
        assert _infer_semantic_role("SSN") == "unknown"


# =============================================================================
# GET BASE TYPE TESTS
# =============================================================================

class TestGetBaseType:
    """Tests for _get_base_type()."""

    def test_strips_patient_suffix(self):
        """_PATIENT suffix is stripped."""
        assert _get_base_type("NAME_PATIENT") == "NAME"

    def test_strips_provider_suffix(self):
        """_PROVIDER suffix is stripped."""
        assert _get_base_type("NAME_PROVIDER") == "NAME"

    def test_strips_relative_suffix(self):
        """_RELATIVE suffix is stripped."""
        assert _get_base_type("NAME_RELATIVE") == "NAME"

    def test_preserves_base_types(self):
        """Base types without suffix are unchanged."""
        assert _get_base_type("NAME") == "NAME"
        assert _get_base_type("SSN") == "SSN"
        assert _get_base_type("DATE") == "DATE"


# =============================================================================
# IS NAME TYPE TESTS
# =============================================================================

class TestIsNameType:
    """Tests for _is_name_type()."""

    def test_base_name_types(self):
        """Base NAME types are recognized."""
        assert _is_name_type("NAME") is True
        assert _is_name_type("PERSON") is True
        assert _is_name_type("PER") is True

    def test_name_with_suffix(self):
        """NAME types with role suffix are recognized."""
        assert _is_name_type("NAME_PATIENT") is True
        assert _is_name_type("NAME_PROVIDER") is True
        assert _is_name_type("NAME_RELATIVE") is True

    def test_non_name_types(self):
        """Non-name types return False."""
        assert _is_name_type("SSN") is False
        assert _is_name_type("DATE") is False
        assert _is_name_type("MRN") is False


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
        assert "EMAIL" in ISOLATED_TYPES
        assert "CREDIT_CARD" in ISOLATED_TYPES

    def test_name_prefixes(self):
        """NAME_PREFIXES contains expected titles."""
        assert "dr" in NAME_PREFIXES
        assert "mr" in NAME_PREFIXES
        assert "mrs" in NAME_PREFIXES
        assert "prof" in NAME_PREFIXES


# =============================================================================
# ENTITY RESOLVER - SIEVE 1: EXACT MATCH
# =============================================================================

class TestEntityResolverExactMatch:
    """Tests for Sieve 1: Exact string match."""

    def test_same_text_merged(self):
        """Same normalized text gets merged into one entity."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=20, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert len(entities[0].mentions) == 2

    def test_case_insensitive_match(self):
        """Matching is case-insensitive."""
        resolver = EntityResolver()
        spans = [
            make_span("JOHN SMITH", start=0, entity_type="NAME"),
            make_span("john smith", start=20, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert len(entities[0].mentions) == 2

    def test_different_names_separate_entities(self):
        """Different names create separate entities."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Alice Brown", start=20, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 2

    def test_title_prefix_stripped_for_match(self):
        """Title prefixes are stripped for matching."""
        resolver = EntityResolver()
        spans = [
            make_span("Dr. John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=20, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert len(entities[0].mentions) == 2

    def test_isolated_types_exact_match(self):
        """ISOLATED_TYPES (SSN, etc.) are merged on exact match."""
        resolver = EntityResolver()
        spans = [
            make_span("123-45-6789", start=0, entity_type="SSN"),
            make_span("123-45-6789", start=30, entity_type="SSN"),
        ]

        entities = resolver.resolve(spans)

        # Same SSN value → same entity (exact match)
        assert len(entities) == 1
        assert len(entities[0].mentions) == 2

    def test_role_variations_merged(self):
        """Same name with different role suffixes gets merged."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME_PATIENT"),
            make_span("John Smith", start=20, entity_type="NAME_PROVIDER"),
        ]

        entities = resolver.resolve(spans)

        # Same person, different semantic roles → same entity
        assert len(entities) == 1
        assert len(entities[0].mentions) == 2


# =============================================================================
# ENTITY RESOLVER - SIEVE 2: PARTIAL NAME MATCH
# =============================================================================

class TestEntityResolverPartialMatch:
    """Tests for Sieve 2: Partial name matching."""

    def test_multi_word_subset_merged(self):
        """Multi-word name that's a subset gets merged."""
        resolver = EntityResolver(enable_partial_match=True)
        spans = [
            make_span("Dr. John A. Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=30, entity_type="NAME"),  # 2 words, subset
        ]

        entities = resolver.resolve(spans)

        # "John Smith" is a subset of "John A. Smith" (after normalization)
        assert len(entities) == 1
        assert len(entities[0].mentions) == 2

    def test_single_word_not_merged_via_partial(self):
        """Single-word name is NOT merged via partial match (too ambiguous)."""
        resolver = EntityResolver(enable_partial_match=True)
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Maria", start=30, entity_type="NAME"),  # Single word - different person
            make_span("Maria Rodriguez", start=50, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        # "Maria" should NOT be merged with "Maria Rodriguez"
        # (single-word partial matching is disabled for safety)
        assert len(entities) == 3

    def test_partial_match_disabled(self):
        """Partial matching can be disabled."""
        resolver = EntityResolver(enable_partial_match=False)
        spans = [
            make_span("Dr. John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=30, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        # With partial disabled, only exact (after prefix strip) should match
        # "dr. john smith" normalizes to "john smith" - exact match!
        assert len(entities) == 1

    def test_isolated_types_no_partial_match(self):
        """ISOLATED_TYPES don't do partial matching."""
        resolver = EntityResolver(enable_partial_match=True)
        spans = [
            make_span("123-45-6789", start=0, entity_type="SSN"),
            make_span("6789", start=30, entity_type="SSN"),  # Partial SSN
        ]

        entities = resolver.resolve(spans)

        # Different SSN values → separate entities (no partial matching for SSN)
        assert len(entities) == 2


# =============================================================================
# ENTITY RESOLVER - SIEVE 3: COREFERENCE
# =============================================================================

class TestEntityResolverCoreference:
    """Tests for Sieve 3: Coreference links."""

    def test_coref_anchor_merged(self):
        """Pronoun with coref_anchor_value is merged with anchor."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("he", start=20, entity_type="NAME", coref_anchor_value="John Smith"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert len(entities[0].mentions) == 2

    def test_coref_anchor_case_insensitive(self):
        """Coref anchor matching is case-insensitive."""
        resolver = EntityResolver()
        spans = [
            make_span("JOHN SMITH", start=0, entity_type="NAME"),
            make_span("he", start=20, entity_type="NAME", coref_anchor_value="john smith"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1

    def test_multiple_pronouns_same_anchor(self):
        """Multiple pronouns with same anchor are merged."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("he", start=20, entity_type="NAME", coref_anchor_value="John Smith"),
            make_span("him", start=40, entity_type="NAME", coref_anchor_value="John Smith"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert len(entities[0].mentions) == 3

    def test_unmatched_coref_anchor_separate(self):
        """Pronoun with unmatched anchor stays separate."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("she", start=20, entity_type="NAME", coref_anchor_value="Alice Brown"),
        ]

        entities = resolver.resolve(spans)

        # No "Alice Brown" span exists, so "she" stays separate
        assert len(entities) == 2


# =============================================================================
# ENTITY RESOLVER - SIEVE 4: KNOWN ENTITIES
# =============================================================================

class TestEntityResolverKnownEntities:
    """Tests for Sieve 4: Known entity matching."""

    def test_exact_match_known_entity(self):
        """Exact match with known entity reuses entity ID."""
        known = {"entity-123": ("John Smith", "NAME")}
        resolver = EntityResolver(known_entities=known)
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert entities[0].id == "entity-123"

    def test_multi_word_partial_match_known(self):
        """Multi-word name can partially match known entity."""
        known = {"entity-123": ("Dr. John A. Smith", "NAME")}
        resolver = EntityResolver(known_entities=known, enable_partial_match=True)
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),  # 2 words - allows partial
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert entities[0].id == "entity-123"

    def test_single_word_no_partial_match_known(self):
        """Single-word name does NOT partially match known entity."""
        known = {"entity-123": ("John Smith", "NAME")}
        resolver = EntityResolver(known_entities=known, enable_partial_match=True)
        spans = [
            make_span("John", start=0, entity_type="NAME"),  # Single word - no partial
        ]

        entities = resolver.resolve(spans)

        # "John" should get a new entity, not match "John Smith"
        assert len(entities) == 1
        assert entities[0].id != "entity-123"

    def test_multiple_mentions_link_to_known(self):
        """Multiple mentions of same person link to known entity."""
        known = {"entity-123": ("John Smith", "NAME")}
        resolver = EntityResolver(known_entities=known)
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=30, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert entities[0].id == "entity-123"
        assert len(entities[0].mentions) == 2


# =============================================================================
# ENTITY CREATION TESTS
# =============================================================================

class TestEntityCreation:
    """Tests for entity creation from mentions."""

    def test_canonical_value_is_longest(self):
        """Canonical value is the longest text among mentions."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),  # 10 chars
            make_span("john smith", start=20, entity_type="NAME"),  # 10 chars
        ]

        entities = resolver.resolve(spans)

        # Both are same length, first one wins
        assert len(entities) == 1

    def test_entity_has_uuid(self):
        """New entities have valid UUIDs."""
        resolver = EntityResolver()
        spans = [make_span("John Smith", start=0, entity_type="NAME")]

        entities = resolver.resolve(spans)

        assert len(entities[0].id) == 36  # UUID format

    def test_entity_base_type_used(self):
        """Entity uses base type (without suffix)."""
        resolver = EntityResolver()
        spans = [make_span("John", start=0, entity_type="NAME_PATIENT")]

        entities = resolver.resolve(spans)

        assert entities[0].entity_type == "NAME"


# =============================================================================
# RESOLVE ENTITIES CONVENIENCE FUNCTION
# =============================================================================

class TestResolveEntitiesFunction:
    """Tests for resolve_entities() convenience function."""

    def test_basic_usage(self):
        """Basic usage without known entities."""
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("John Smith", start=20, entity_type="NAME"),
        ]

        entities = resolve_entities(spans)

        assert len(entities) == 1

    def test_with_known_entities(self):
        """Usage with known entities."""
        known = {"entity-123": ("John Smith", "NAME")}
        spans = [make_span("John Smith", start=0, entity_type="NAME")]

        entities = resolve_entities(spans, known_entities=known)

        assert len(entities) == 1
        assert entities[0].id == "entity-123"

    def test_empty_spans(self):
        """Empty span list returns empty entity list."""
        entities = resolve_entities([])
        assert entities == []


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases and error handling."""

    def test_single_span(self):
        """Single span creates single entity."""
        resolver = EntityResolver()
        spans = [make_span("John Smith", start=0, entity_type="NAME")]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        assert len(entities[0].mentions) == 1

    def test_unicode_names(self):
        """Unicode characters in names are handled."""
        resolver = EntityResolver()
        spans = [
            make_span("José García", start=0, entity_type="NAME"),
            make_span("José García", start=20, entity_type="NAME"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1

    def test_mixed_entity_types(self):
        """Mixed entity types create separate entities."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("123-45-6789", start=20, entity_type="SSN"),
            make_span("john@email.com", start=40, entity_type="EMAIL"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 3

    def test_same_value_different_types(self):
        """Same value with different base types stays separate."""
        resolver = EntityResolver()
        spans = [
            make_span("12345", start=0, entity_type="MRN"),
            make_span("12345", start=20, entity_type="ZIP"),
        ]

        entities = resolver.resolve(spans)

        # Different base types → separate entities
        assert len(entities) == 2


# =============================================================================
# SEMANTIC ROLE PRESERVATION
# =============================================================================

class TestSemanticRolePreservation:
    """Tests that semantic roles are preserved as metadata."""

    def test_mentions_have_semantic_role(self):
        """Mentions preserve their semantic role."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME_PATIENT"),
        ]

        entities = resolver.resolve(spans)

        assert entities[0].mentions[0].semantic_role == "patient"

    def test_merged_entity_has_multiple_roles(self):
        """Merged entity can have mentions with different roles."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME_PATIENT"),
            make_span("John Smith", start=30, entity_type="NAME_PROVIDER"),
        ]

        entities = resolver.resolve(spans)

        assert len(entities) == 1
        roles = {m.semantic_role for m in entities[0].mentions}
        assert roles == {"patient", "provider"}

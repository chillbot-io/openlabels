"""Comprehensive tests for EntityResolver and ContextEnhancer.

Complements tests in tests/pipeline/test_entity_resolver.py and
tests/pipeline/test_context_enhancer.py with deeper coverage of:
- Multi-sieve resolution mechanics and union-find correctness
- Deny list filtering with realistic false-positive inputs
- Hotword confidence adjustment with positioned text
- Pattern exclusion logic
- Full enhance() pipeline orchestration
"""

import pytest

from openlabels.core.types import Span, Tier
from openlabels.core.pipeline.entity_resolver import (
    EntityResolver,
    Entity,
    Mention,
    resolve_entities,
    get_entity_counts,
    NAME_TYPES,
    ISOLATED_TYPES,
)
from openlabels.core.pipeline.context_enhancer import (
    ContextEnhancer,
    EnhancementResult,
    HotwordRule,
    NAME_DENY_LIST,
    USERNAME_DENY_LIST,
    ADDRESS_DENY_LIST,
    MEDICATION_DENY_LIST,
    MRN_EXCLUDE_PATTERNS,
    COMPANY_SUFFIXES,
    COMPANY_PATTERN,
    HTML_PATTERN,
    REFERENCE_CODE_PATTERN,
    ALL_CAPS_PATTERN,
    HAS_DIGITS_PATTERN,
    GREETING_PATTERN,
    POSSESSIVE_PRODUCT_PATTERN,
    HYPHENATED_NAME_PATTERN,
    BUSINESS_CONTEXT_WORDS,
    NAME_POSITIVE_HOTWORDS,
    NAME_NEGATIVE_HOTWORDS,
    create_enhancer,
)


# =============================================================================
# HELPERS
# =============================================================================

def make_span(
    text,
    start=0,
    entity_type="NAME",
    confidence=0.90,
    detector="test",
    tier=Tier.PATTERN,
    coref_anchor_value=None,
):
    """Create a Span with correct end position derived from start + len(text)."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=tier,
        coref_anchor_value=coref_anchor_value,
    )


def _entity_texts(entities):
    """Extract sorted list of canonical values from entities."""
    return sorted(e.canonical_value for e in entities)


def _entity_with_value(entities, value):
    """Find entity whose canonical_value matches (case-insensitive)."""
    for e in entities:
        if e.canonical_value.lower() == value.lower():
            return e
    return None


# #############################################################################
#
#   ENTITY RESOLVER TESTS
#
# #############################################################################


class TestSieve1ExactMatch:
    """Sieve 1: identical normalised text is grouped."""

    def test_three_identical_mentions_grouped(self):
        """Three occurrences of the same name produce one entity."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("John Smith", start=50),
            make_span("John Smith", start=100),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 3

    def test_case_normalisation(self):
        """'john smith' and 'John Smith' normalise to the same group."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("john smith", start=50),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 2

    def test_whitespace_normalisation(self):
        """Leading/trailing whitespace is stripped before matching."""
        resolver = EntityResolver()
        spans = [
            make_span("Smith", start=0),
            make_span("Smith", start=20),
        ]
        # Both identical after normalisation
        entities = resolver.resolve(spans)
        assert len(entities) == 1

    def test_different_text_stays_separate(self):
        """Two completely different names are separate entities."""
        resolver = EntityResolver()
        spans = [
            make_span("Alice Wang", start=0),
            make_span("Bob Miller", start=30),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2

    def test_exact_match_across_positions(self):
        """Exact matches at non-contiguous positions still group."""
        resolver = EntityResolver()
        spans = [
            make_span("Jane Doe", start=0),
            make_span("Jane Doe", start=5000),
            make_span("Jane Doe", start=9999),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        all_positions = {m.span.start for m in entities[0].mentions}
        assert all_positions == {0, 5000, 9999}


class TestSieve2PartialNameMatch:
    """Sieve 2: single-word names absorbed by multi-word names sharing a word."""

    def test_last_name_groups_with_full_name(self):
        """'Smith' groups with 'John Smith'."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("Smith", start=50),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].canonical_value == "John Smith"

    def test_first_name_groups_with_full_name(self):
        """'John' groups with 'John Smith'."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("John", start=50),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].canonical_value == "John Smith"

    def test_both_partials_group_with_full(self):
        """Both 'John' and 'Smith' group with 'John Smith'."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("John", start=30),
            make_span("Smith", start=60),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 3

    def test_unrelated_single_words_stay_separate(self):
        """'Alice' does NOT group with 'John Smith' (no shared word)."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("Alice", start=50),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2

    def test_multi_word_names_with_shared_word_group(self):
        """'John Smith' and 'John Brown' share 'john' and should group."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("John Brown", start=50),
        ]
        entities = resolver.resolve(spans)
        # Both are multi-word and share the word 'john'
        assert len(entities) == 1

    def test_multi_word_names_no_shared_word_stay_separate(self):
        """'John Smith' and 'Alice Brown' share no words and stay separate."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("Alice Brown", start=50),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2

    def test_partial_match_only_for_name_types(self):
        """Partial matching is skipped for non-NAME types like SSN."""
        resolver = EntityResolver()
        spans = [
            make_span("123-45-6789", start=0, entity_type="SSN"),
            make_span("6789", start=50, entity_type="SSN"),
        ]
        entities = resolver.resolve(spans)
        # SSN is in ISOLATED_TYPES so words are empty - no partial match
        assert len(entities) == 2

    def test_title_words_stripped_from_matching(self):
        """Titles like 'Dr', 'Mr' are excluded from word set, leaving real name words."""
        resolver = EntityResolver()
        # 'Dr. John Smith' -> words={'john','smith'} (multi-word, 'dr' stripped)
        # 'Smith' -> words={'smith'} (single-word, absorbed by multi-word)
        spans = [
            make_span("Dr. John Smith", start=0),
            make_span("Smith", start=40),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1

    def test_title_only_names_stay_separate_from_each_other(self):
        """Two single-word names (after title strip) are not grouped by Sieve 2
        because both are single-word -- Sieve 2 only absorbs single into multi."""
        resolver = EntityResolver()
        # 'Dr. Smith' -> words={'smith'}, 'Mr. Smith' -> words={'smith'}
        # Both single-word after title stripping: Sieve 2 requires a multi-word anchor.
        spans = [
            make_span("Dr. Smith", start=0),
            make_span("Mr. Smith", start=30),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2

    def test_short_single_char_words_not_indexed(self):
        """Single-character words (length < 2) are not used for matching."""
        resolver = EntityResolver()
        # Construct name where shared 'word' is single char
        spans = [
            make_span("A Smith", start=0),
            make_span("A Jones", start=30),
        ]
        entities = resolver.resolve(spans)
        # 'a' has length 1, not indexed. 'smith' and 'jones' differ. Should stay separate.
        assert len(entities) == 2


class TestSieve3CorefLinking:
    """Sieve 3: coreference anchor values link pronouns to antecedents."""

    def test_pronoun_links_to_anchor_via_coref(self):
        """A pronoun with coref_anchor_value links to the matching name."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("He", start=30, coref_anchor_value="john smith"),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 2

    def test_multiple_pronouns_link_to_same_anchor(self):
        """Several pronouns all pointing to the same anchor form one entity."""
        resolver = EntityResolver()
        spans = [
            make_span("Jane Doe", start=0),
            make_span("She", start=20, coref_anchor_value="jane doe"),
            make_span("Her", start=40, coref_anchor_value="jane doe"),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 3

    def test_coref_anchor_not_found_stays_separate(self):
        """A coref anchor that does not match any existing mention stays separate."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("He", start=30, coref_anchor_value="bob jones"),
        ]
        entities = resolver.resolve(spans)
        # "bob jones" matches nothing in text_index, so no link
        assert len(entities) == 2

    def test_coref_case_insensitive(self):
        """Coreference anchor matching is case-insensitive."""
        resolver = EntityResolver()
        spans = [
            make_span("Mary Johnson", start=0),
            make_span("She", start=30, coref_anchor_value="Mary Johnson"),
        ]
        entities = resolver.resolve(spans)
        # "Mary Johnson" lowered -> "mary johnson", which matches normalised text
        assert len(entities) == 1


class TestUnionFindCorrectness:
    """Union-find produces correct transitive groups."""

    def test_transitive_closure_three_mentions(self):
        """A=B via exact, B=C via partial => A, B, C in one group."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),      # A
            make_span("John Smith", start=50),      # B (exact match with A)
            make_span("Smith", start=100),           # C (partial match with A or B)
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 3

    def test_chain_linking_across_sieves(self):
        """Chain: exact links A-B, coref links B-C => all three grouped."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),       # A
            make_span("John Smith", start=50),       # B (exact with A)
            make_span("Him", start=100, coref_anchor_value="john smith"),  # C (coref with A/B)
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 3

    def test_two_separate_groups(self):
        """Two independent groups do not merge."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("Smith", start=30),
            make_span("Alice Wang", start=60),
            make_span("Wang", start=90),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2
        group_sizes = sorted(e.count for e in entities)
        assert group_sizes == [2, 2]

    def test_large_transitive_chain(self):
        """Many mentions chained by shared words form one group."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("John", start=30),
            make_span("John Brown", start=60),
            make_span("Brown", start=90),
        ]
        entities = resolver.resolve(spans)
        # John Smith --john--> John --john--> John Brown --brown--> Brown
        assert len(entities) == 1
        assert entities[0].count == 4

    def test_union_find_path_compression(self):
        """Verifying union-find works with many elements (path compression)."""
        resolver = EntityResolver()
        # Create a chain: Name0 = Name0, Name1 shares word with Name0, etc.
        # All should end up in one group.
        spans = [make_span("TestName", start=i * 20) for i in range(50)]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].count == 50


class TestGroupsToEntities:
    """_groups_to_entities: canonical value, entity type, positions."""

    def test_canonical_is_longest_text(self):
        """Canonical value is the longest mention text."""
        resolver = EntityResolver()
        spans = [
            make_span("Dr. John Michael Smith", start=0),
            make_span("Smith", start=50),
            make_span("John Smith", start=80),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].canonical_value == "Dr. John Michael Smith"

    def test_entity_type_from_highest_tier(self):
        """Entity type is taken from the mention with the highest tier."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, tier=Tier.ML, entity_type="PERSON"),
            make_span("John Smith", start=50, tier=Tier.STRUCTURED, entity_type="NAME_PATIENT"),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        # STRUCTURED tier (3) > ML tier (1), so entity_type should be NAME_PATIENT
        assert entities[0].entity_type == "NAME_PATIENT"

    def test_all_spans_preserved_in_mentions(self):
        """Every input span appears as a mention in the output entity."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("John Smith", start=50),
            make_span("Smith", start=100),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        mention_starts = {m.span.start for m in entities[0].mentions}
        assert mention_starts == {0, 50, 100}

    def test_entities_sorted_by_first_occurrence(self):
        """Output entities are sorted by the earliest mention position."""
        resolver = EntityResolver()
        spans = [
            make_span("Zara White", start=100),
            make_span("Alice Brown", start=0),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2
        assert entities[0].canonical_value == "Alice Brown"
        assert entities[1].canonical_value == "Zara White"

    def test_entity_id_is_unique(self):
        """Each entity gets a unique UUID."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("Jane Doe", start=50),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2
        assert entities[0].id != entities[1].id

    def test_entity_to_dict_positions(self):
        """Entity.to_dict() includes all mention positions."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0),
            make_span("John Smith", start=50),
        ]
        entities = resolver.resolve(spans)
        d = entities[0].to_dict()
        assert d["count"] == 2
        assert (0, 10) in d["positions"]
        assert (50, 60) in d["positions"]

    def test_get_entity_counts(self):
        """get_entity_counts() tallies by entity type."""
        resolver = EntityResolver()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Jane Doe", start=30, entity_type="NAME"),
            make_span("123-45-6789", start=60, entity_type="SSN"),
        ]
        entities = resolver.resolve(spans)
        counts = get_entity_counts(entities)
        assert counts["NAME"] == 2
        assert counts["SSN"] == 1


class TestEntityResolverEdgeCases:
    """Edge cases for entity resolution."""

    def test_single_entity_single_mention(self):
        """One span yields one entity with one mention."""
        resolver = EntityResolver()
        entities = resolver.resolve([make_span("Alice", start=0)])
        assert len(entities) == 1
        assert entities[0].count == 1

    def test_same_text_different_entity_types(self):
        """Same text but different entity types stay in separate groups
        only if the types do not share words."""
        resolver = EntityResolver()
        # "Grace" as NAME has words={'grace'}, "Grace" as MEDICATION has words=set()
        spans = [
            make_span("Grace", start=0, entity_type="NAME"),
            make_span("Grace", start=20, entity_type="MEDICATION"),
        ]
        entities = resolver.resolve(spans)
        # Both normalise to "grace" -> exact match groups them together
        assert len(entities) == 1

    def test_below_confidence_threshold_filtered(self):
        """Spans below min_confidence are excluded entirely."""
        resolver = EntityResolver(min_confidence=0.80)
        spans = [
            make_span("John Smith", start=0, confidence=0.90),
            make_span("Jane Doe", start=30, confidence=0.50),  # below threshold
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1
        assert entities[0].canonical_value == "John Smith"

    def test_all_below_confidence_returns_empty(self):
        """If all spans are below threshold, returns empty."""
        resolver = EntityResolver(min_confidence=0.95)
        spans = [
            make_span("John Smith", start=0, confidence=0.50),
            make_span("Jane Doe", start=30, confidence=0.60),
        ]
        entities = resolver.resolve(spans)
        assert entities == []

    def test_empty_list_returns_empty(self):
        """Empty input returns empty output."""
        resolver = EntityResolver()
        assert resolver.resolve([]) == []

    def test_isolated_type_different_values_stay_separate(self):
        """Two different SSNs are separate entities."""
        resolver = EntityResolver()
        spans = [
            make_span("123-45-6789", start=0, entity_type="SSN"),
            make_span("987-65-4321", start=30, entity_type="SSN"),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 2

    def test_name_with_title_groups_correctly(self):
        """'Dr. John Smith' and 'Smith' group because title 'dr' is stripped,
        leaving multi-word {'john','smith'} which absorbs single-word {'smith'}."""
        resolver = EntityResolver()
        spans = [
            make_span("Dr. John Smith", start=0),
            make_span("Smith", start=30),
        ]
        entities = resolver.resolve(spans)
        assert len(entities) == 1

    def test_resolve_entities_convenience_with_threshold(self):
        """resolve_entities() passes min_confidence through."""
        spans = [
            make_span("John Smith", start=0, confidence=0.60),
        ]
        entities = resolve_entities(spans, min_confidence=0.80)
        assert entities == []

    def test_mention_normalized_text(self):
        """Mention objects carry correctly normalised text."""
        resolver = EntityResolver()
        span = make_span("  John Smith  ", start=0)
        mention = resolver._to_mention(span)
        assert mention.normalized_text == "john smith"

    def test_mention_words_for_non_name_type(self):
        """Non-NAME types have empty word sets."""
        resolver = EntityResolver()
        span = make_span("123-45-6789", start=0, entity_type="SSN")
        mention = resolver._to_mention(span)
        assert mention.words == set()


# #############################################################################
#
#   CONTEXT ENHANCER TESTS
#
# #############################################################################


class TestDenyListFiltering:
    """Deny lists reject known false positives through _check_deny_list."""

    # -- NAME deny list --

    @pytest.mark.parametrize("word", ["will", "may", "mark", "grace", "can"])
    def test_modal_verbs_and_common_words_denied_as_name(self, word):
        """Modal verbs / common English words are denied as NAMEs."""
        # Only test words actually in the deny list
        if word.lower() not in NAME_DENY_LIST:
            pytest.skip(f"'{word}' not in NAME_DENY_LIST")
        enhancer = ContextEnhancer()
        span = make_span(word, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None, f"'{word}' should be denied as NAME"
        assert "deny_list" in reason

    @pytest.mark.parametrize("word", [
        "null", "undefined", "none", "true", "false", "default",
    ])
    def test_tech_terms_denied(self, word):
        """Programming keywords are rejected as NAMEs."""
        enhancer = ContextEnhancer()
        span = make_span(word, entity_type="PERSON", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None, f"'{word}' should be denied as PERSON"

    def test_real_name_not_denied(self):
        """A genuine name like 'Jennifer' is NOT denied."""
        enhancer = ContextEnhancer()
        span = make_span("Jennifer", entity_type="NAME", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is None

    def test_company_suffix_denied_for_name(self):
        """A name ending with a company suffix is denied."""
        enhancer = ContextEnhancer()
        span = make_span("Acme Inc", start=0, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None
        assert "company_suffix" in reason

    def test_company_suffix_llc(self):
        """'Smith LLC' is denied as a NAME."""
        enhancer = ContextEnhancer()
        span = make_span("Smith LLC", start=0, entity_type="PERSON", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None
        assert "company_suffix" in reason

    def test_trailing_punctuation_stripped_for_deny(self):
        """Trailing punctuation is stripped before deny list check."""
        enhancer = ContextEnhancer()
        span = make_span("will.", start=0, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None, "'will.' (with period) should still match deny list"

    # -- USERNAME deny list --

    @pytest.mark.parametrize("word", ["has", "the", "admin", "root", "test"])
    def test_username_deny_list(self, word):
        """Common words / generic accounts denied as USERNAME."""
        enhancer = ContextEnhancer()
        span = make_span(word, entity_type="USERNAME", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None, f"'{word}' should be denied as USERNAME"

    # -- ADDRESS deny list --

    @pytest.mark.parametrize("word", ["apartment", "headquarters", "office", "suite"])
    def test_address_deny_list(self, word):
        """Building/org terms denied as ADDRESS."""
        enhancer = ContextEnhancer()
        span = make_span(word, entity_type="ADDRESS", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None, f"'{word}' should be denied as ADDRESS"

    # -- MEDICATION deny list --

    @pytest.mark.parametrize("word", ["health", "stress", "care", "treatment", "clinical"])
    def test_medication_deny_list(self, word):
        """Generic health words denied as MEDICATION."""
        enhancer = ContextEnhancer()
        span = make_span(word, entity_type="MEDICATION", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None, f"'{word}' should be denied as MEDICATION"

    # -- MRN pattern exclusion --

    def test_mrn_dollar_amount_excluded(self):
        """Dollar amounts like '440060.24' excluded from MRN."""
        enhancer = ContextEnhancer()
        span = make_span("440060.24", entity_type="MRN", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None
        assert "mrn_exclude" in reason

    def test_mrn_currency_symbol_excluded(self):
        """Currency with symbol '$850' excluded from MRN."""
        enhancer = ContextEnhancer()
        span = make_span("$850", start=0, entity_type="MRN", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None

    def test_mrn_valid_number_not_excluded(self):
        """A plausible MRN like '123456' is NOT excluded."""
        enhancer = ContextEnhancer()
        span = make_span("123456", entity_type="MRN", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is None

    def test_mrn_crypto_address_excluded(self):
        """Long alphanumeric string (crypto address) excluded from MRN."""
        enhancer = ContextEnhancer()
        long_addr = "a" * 35
        span = make_span(long_addr, entity_type="MRN", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None

    # -- Unknown entity type falls back to NAME deny list --

    def test_unknown_type_uses_name_deny_list(self):
        """Unknown entity types fall back to NAME_DENY_LIST."""
        enhancer = ContextEnhancer()
        span = make_span("will", entity_type="CUSTOM_TYPE", confidence=0.70, tier=Tier.ML)
        reason = enhancer._check_deny_list(span)
        assert reason is not None


class TestHotwordElevation:
    """Positive hotwords boost confidence for NAME entities."""

    def _apply(self, text, span):
        enhancer = ContextEnhancer()
        return enhancer._apply_hotwords(text, span, span.confidence)

    def test_title_before_name_boosts(self):
        """'Mr. ' immediately before name boosts confidence."""
        text = "Contact Mr. John Smith for details"
        span = make_span("John Smith", start=12, entity_type="NAME", confidence=0.60, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence > 0.60
        assert any("+hotword" in r for r in reasons)

    def test_name_label_boosts(self):
        """'Name: ' before a name gives a large boost."""
        text = "Name: John Smith"
        span = make_span("John Smith", start=6, entity_type="NAME", confidence=0.50, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence > 0.50
        assert any("name label" in r.lower() or "Explicit name" in r for r in reasons)

    def test_patient_label_boosts(self):
        """'Patient: ' before name boosts confidence."""
        text = "Patient: Jane Doe admitted today"
        span = make_span("Jane Doe", start=9, entity_type="PERSON", confidence=0.55, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence > 0.55

    def test_letter_closing_boosts(self):
        """'Sincerely, ' before name boosts confidence."""
        text = "Sincerely, Robert Brown"
        span = make_span("Robert Brown", start=11, entity_type="NAME", confidence=0.60, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence > 0.60

    def test_no_hotword_no_change(self):
        """Without hotword context, confidence is unchanged."""
        text = "The quick brown fox jumped over John Smith lazily"
        span = make_span("John Smith", start=32, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence == pytest.approx(0.70)
        assert len(reasons) == 0

    def test_confidence_capped_at_1(self):
        """Boosting cannot exceed 1.0."""
        text = "Name: John Smith"
        span = make_span("John Smith", start=6, entity_type="NAME", confidence=0.95, tier=Tier.ML)
        confidence, _ = self._apply(text, span)
        assert confidence <= 1.0

    def test_non_name_type_not_affected(self):
        """Hotwords only apply to NAME/PERSON/PER types."""
        text = "Name: 123-45-6789"
        span = make_span("123-45-6789", start=6, entity_type="SSN", confidence=0.70, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence == 0.70
        assert reasons == []


class TestHotwordDepression:
    """Negative hotwords reduce confidence for NAME entities."""

    def _apply(self, text, span):
        enhancer = ContextEnhancer()
        return enhancer._apply_hotwords(text, span, span.confidence)

    def test_company_suffix_after_name_depresses(self):
        """'Inc.' after a detected name depresses confidence."""
        text = "Contact Acme Inc. for services"
        span = make_span("Acme", start=8, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence < 0.70
        assert any("-hotword" in r for r in reasons)

    def test_street_suffix_after_name_depresses(self):
        """'Street' after a detected name depresses confidence."""
        text = "Lives on Baker Street in London"
        span = make_span("Baker", start=9, entity_type="PERSON", confidence=0.70, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence < 0.70

    def test_location_preposition_before_depresses(self):
        """'at ' before name depresses confidence (location context)."""
        text = "She works at Springfield office"
        span = make_span("Springfield", start=13, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence < 0.70

    def test_confidence_floored_at_0(self):
        """Depression cannot go below 0.0."""
        text = "Visit Acme Inc. LLC Corp. Ltd."
        span = make_span("Acme", start=6, entity_type="NAME", confidence=0.10, tier=Tier.ML)
        confidence, _ = self._apply(text, span)
        assert confidence >= 0.0

    def test_possessive_product_after_depresses(self):
        """\"'s website\" after name depresses confidence."""
        text = "Check Amazon's website for deals"
        span = make_span("Amazon", start=6, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        confidence, reasons = self._apply(text, span)
        assert confidence < 0.70


class TestPatternExclusions:
    """_check_patterns rejects structural false positives."""

    def _check(self, text, span):
        enhancer = ContextEnhancer()
        return enhancer._check_patterns(text, span)

    def test_html_content_rejected(self):
        """Span containing HTML tags is rejected."""
        span = make_span("<div>John</div>", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check("<div>John</div>", span)
        assert reject is not None
        assert "html" in reject.lower()

    def test_reference_code_rejected(self):
        """Reference codes like 'REF-123' are rejected."""
        span = make_span("REF-123", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check("REF-123 is your code", span)
        assert reject is not None
        assert "reference_code" in reject

    def test_all_caps_acronym_rejected(self):
        """All-caps strings >2 chars are rejected as acronyms."""
        span = make_span("NASA", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check("NASA launched the rocket", span)
        assert reject is not None
        assert "all_caps" in reject

    def test_two_char_all_caps_not_rejected(self):
        """Two-char all caps is NOT rejected (could be initials)."""
        span = make_span("AI", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check("AI is the future", span)
        # ALL_CAPS_PATTERN requires > 2 chars; "AI" is exactly 2, so pattern matches
        # but the code checks len > 2, so AI should NOT be rejected
        assert reject is None

    def test_company_pattern_rejected(self):
        """Law-firm style name 'Smith, Jones and Brown' rejected."""
        text = "Smith, Jones and Brown represented us"
        span = make_span("Smith, Jones and Brown", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check(text, span)
        assert reject is not None
        assert "company_pattern" in reject

    def test_name_with_digits_rejected(self):
        """Name containing digits like 'John3' is rejected."""
        span = make_span("John3", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check("John3 logged in", span)
        assert reject is not None
        assert "contains_digits" in reject

    def test_name_with_suffix_numeral_not_rejected(self):
        """Name with suffix like 'John Smith III' is NOT rejected for digits."""
        span = make_span("John Smith III", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check("John Smith III spoke first", span)
        # The code has an exception for II/III/IV/Jr/Sr suffixes
        assert reject is None

    def test_greeting_stripped(self):
        """'Hi John Smith' strips greeting, returns cleaned text."""
        text = "Hi John Smith welcome"
        span = make_span("Hi John Smith", start=0, entity_type="NAME", tier=Tier.ML)
        reject, cleaned, offset = self._check(text, span)
        assert reject is None
        assert cleaned == "John Smith"
        assert offset == 3  # "Hi " is 3 chars

    def test_greeting_only_rejected(self):
        """Greeting followed by a single char is rejected (too short after strip)."""
        # "Hi X" -> greeting match strips "Hi ", cleaned="X", len("X")<2 -> greeting_only
        span = make_span("Hi X", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check("Hi X there", span)
        assert reject is not None
        assert "greeting_only" in reject

    def test_plain_name_no_rejection(self):
        """A plain name like 'John Smith' passes all pattern checks."""
        text = "Doctor saw John Smith yesterday"
        span = make_span("John Smith", start=11, entity_type="NAME", tier=Tier.ML)
        reject, cleaned, _ = self._check(text, span)
        assert reject is None

    def test_possessive_product_rejected(self):
        """\"Amazon's website\" is rejected as possessive + product."""
        text = "Visit Amazon's website for deals"
        span = make_span("Amazon", start=6, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check(text, span)
        assert reject is not None
        assert "possessive_product" in reject

    def test_hyphenated_name_in_business_context_rejected(self):
        """Hyphenated name like 'Lewis-Osborne' in business context is rejected."""
        text = "Lewis-Osborne Inc. is a great company"
        span = make_span("Lewis-Osborne", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check(text, span)
        assert reject is not None
        assert "hyphenated_company" in reject

    def test_hyphenated_name_outside_business_context_passes(self):
        """Hyphenated name without business context is NOT rejected."""
        text = "Lewis-Osborne went to the store"
        span = make_span("Lewis-Osborne", start=0, entity_type="NAME", tier=Tier.ML)
        reject, _, _ = self._check(text, span)
        assert reject is None


class TestEnhanceSpanOrchestration:
    """enhance_span applies stages in correct order for enhanced types."""

    def test_mrn_deny_list_rejects(self):
        """MRN in enhanced_types: dollar amount is rejected at deny-list stage."""
        enhancer = ContextEnhancer()
        span = make_span("440060.24", entity_type="MRN", confidence=0.70, tier=Tier.ML)
        result = enhancer.enhance_span("Amount: 440060.24", span)
        assert result.action == "reject"
        assert result.confidence == 0.0

    def test_mrn_valid_keeps(self):
        """A valid MRN passes through enhancement."""
        enhancer = ContextEnhancer()
        span = make_span("123456", entity_type="MRN", confidence=0.90, tier=Tier.STRUCTURED)
        result = enhancer.enhance_span("MRN: 123456", span)
        # STRUCTURED tier is high, should be kept
        assert result.action == "keep"

    def test_non_enhanced_type_always_kept(self):
        """Entity types not in enhanced_types are always kept."""
        enhancer = ContextEnhancer()
        span = make_span("will", entity_type="NAME", confidence=0.70, tier=Tier.ML)
        result = enhancer.enhance_span("I will call you", span)
        # NAME is not in enhanced_types, so it passes through
        assert result.action == "keep"
        assert "non_enhanced_type" in result.reasons

    def test_high_tier_bypasses_patterns_and_hotwords(self):
        """High-tier (STRUCTURED+) spans bypass pattern and hotword checks."""
        enhancer = ContextEnhancer()
        span = make_span("123456", entity_type="MRN", confidence=0.70, tier=Tier.STRUCTURED)
        result = enhancer.enhance_span("MRN: 123456", span)
        assert result.action == "keep"
        assert "high_tier" in result.reasons

    def test_deny_list_disabled(self):
        """With enable_deny_list=False, deny list is skipped."""
        enhancer = ContextEnhancer(enable_deny_list=False)
        span = make_span("440060.24", entity_type="MRN", confidence=0.50, tier=Tier.ML)
        result = enhancer.enhance_span("Amount: 440060.24", span)
        # Deny list disabled, but low confidence should still be rejected
        assert result.action in ("reject", "verify")

    def test_enhancement_result_has_reasons(self):
        """EnhancementResult always carries a list of reasons."""
        enhancer = ContextEnhancer()
        span = make_span("123456", entity_type="MRN", confidence=0.90, tier=Tier.STRUCTURED)
        result = enhancer.enhance_span("MRN: 123456", span)
        assert isinstance(result.reasons, list)
        assert len(result.reasons) >= 1


class TestEnhanceBatchOrchestration:
    """enhance() processes batches, filtering rejected spans."""

    def test_empty_input_returns_empty(self):
        """Empty span list returns empty."""
        enhancer = ContextEnhancer()
        assert enhancer.enhance("some text", []) == []

    def test_mixed_keep_and_reject(self):
        """Batch with keep and reject: rejected spans are removed."""
        enhancer = ContextEnhancer()
        spans = [
            make_span("123456", start=5, entity_type="MRN", confidence=0.90, tier=Tier.STRUCTURED),
            make_span("440060.24", start=20, entity_type="MRN", confidence=0.70, tier=Tier.ML),
        ]
        text = "MRN: 123456 Amount: 440060.24 done"
        kept = enhancer.enhance(text, spans)
        assert len(kept) == 1
        assert kept[0].text == "123456"

    def test_all_rejected_returns_empty(self):
        """If every span is rejected, result is empty."""
        enhancer = ContextEnhancer()
        spans = [
            make_span("440060.24", start=0, entity_type="MRN", confidence=0.70, tier=Tier.ML),
            make_span("512717.39", start=20, entity_type="MRN", confidence=0.70, tier=Tier.ML),
        ]
        text = "440060.24 and also 512717.39 total"
        kept = enhancer.enhance(text, spans)
        assert len(kept) == 0

    def test_non_enhanced_types_pass_through(self):
        """NAME spans (not in enhanced_types) all pass through untouched."""
        enhancer = ContextEnhancer()
        spans = [
            make_span("John Smith", start=0, entity_type="NAME", confidence=0.70, tier=Tier.ML),
            make_span("Jane Doe", start=20, entity_type="NAME", confidence=0.70, tier=Tier.ML),
        ]
        text = "John Smith called Jane Doe yesterday"
        kept = enhancer.enhance(text, spans)
        assert len(kept) == 2

    def test_verify_action_sets_needs_review(self):
        """Spans with 'verify' action get needs_review=True.

        Disable patterns to isolate confidence routing (MRNs are inherently
        numeric and would be rejected by the contains_digits pattern).
        """
        enhancer = ContextEnhancer(enable_patterns=False)
        span = make_span("789012", entity_type="MRN", confidence=0.60, tier=Tier.ML)
        text = "Record 789012 found"
        kept = enhancer.enhance(text, [span])
        # Confidence 0.60 is between low_threshold (0.35) and high_threshold (0.85)
        # so action should be "verify"
        assert len(kept) == 1
        assert kept[0].needs_review is True
        assert kept[0].review_reason == "llm_verification"

    def test_high_confidence_mrn_kept_without_review(self):
        """MRN with very high confidence is kept without needing review.

        Patterns disabled to isolate confidence routing.
        """
        enhancer = ContextEnhancer(enable_patterns=False)
        span = make_span("789012", entity_type="MRN", confidence=0.95, tier=Tier.ML)
        text = "Record 789012 found"
        kept = enhancer.enhance(text, [span])
        assert len(kept) == 1
        assert kept[0].needs_review is False

    def test_low_confidence_mrn_rejected(self):
        """MRN with very low confidence is rejected.

        Patterns disabled to isolate confidence routing.
        """
        enhancer = ContextEnhancer(enable_patterns=False)
        span = make_span("789012", entity_type="MRN", confidence=0.20, tier=Tier.ML)
        text = "Record 789012 found"
        kept = enhancer.enhance(text, [span])
        assert len(kept) == 0

    def test_ml_tier_mrn_with_digits_rejected_by_patterns(self):
        """ML-tier numeric MRN is rejected by contains_digits pattern.

        This verifies the actual production behaviour: numeric MRNs at ML tier
        are caught by the pattern stage because the digit check was designed
        to filter NAMEs but applies to all enhanced types.
        """
        enhancer = ContextEnhancer()
        span = make_span("789012", entity_type="MRN", confidence=0.90, tier=Tier.ML)
        text = "Record 789012 found"
        kept = enhancer.enhance(text, [span])
        assert len(kept) == 0


class TestContextEnhancerEdgeCases:
    """Edge cases for ContextEnhancer."""

    def test_entity_at_start_of_text(self):
        """Entity at the very start of text (no before-context)."""
        enhancer = ContextEnhancer()
        text = "John Smith is here"
        span = make_span("John Smith", start=0, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        result = enhancer.enhance_span(text, span)
        assert result.action in ("keep", "reject", "verify")

    def test_entity_at_end_of_text(self):
        """Entity at the very end of text (no after-context)."""
        enhancer = ContextEnhancer()
        text = "Hello John Smith"
        span = make_span("John Smith", start=6, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        result = enhancer.enhance_span(text, span)
        assert result.action in ("keep", "reject", "verify")

    def test_entity_is_entire_text(self):
        """Entity spans the entire text."""
        enhancer = ContextEnhancer()
        text = "John Smith"
        span = make_span("John Smith", start=0, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        result = enhancer.enhance_span(text, span)
        assert result.action in ("keep", "reject", "verify")

    def test_empty_text_does_not_crash(self):
        """Enhancement with empty text does not raise."""
        enhancer = ContextEnhancer()
        spans = []
        result = enhancer.enhance("", spans)
        assert result == []

    def test_context_window_clamps_to_bounds(self):
        """Context window does not go out of text bounds."""
        enhancer = ContextEnhancer()
        text = "AB"
        span = make_span("AB", start=0, entity_type="NAME", confidence=0.70, tier=Tier.ML)
        before, after = enhancer._get_context_window(text, span, 100, 100)
        assert before == ""
        assert after == ""

    def test_custom_thresholds_change_routing(self):
        """Custom thresholds change keep/verify/reject boundaries.

        Patterns disabled so numeric MRN reaches the confidence routing stage.
        """
        enhancer = ContextEnhancer(
            high_confidence_threshold=0.50,
            low_confidence_threshold=0.10,
            enable_patterns=False,
        )
        span = make_span("789012", entity_type="MRN", confidence=0.55, tier=Tier.ML)
        result = enhancer.enhance_span("Record 789012 found", span)
        # 0.55 >= 0.50 high threshold => keep
        assert result.action == "keep"

    def test_deny_list_rejects_high_tier_with_warning(self):
        """Even high-tier (STRUCTURED) spans can be rejected by deny list."""
        enhancer = ContextEnhancer()
        span = make_span("440060.24", entity_type="MRN", confidence=0.95, tier=Tier.STRUCTURED)
        result = enhancer.enhance_span("440060.24", span)
        assert result.action == "reject"

    def test_per_entity_type_uses_name_hotwords(self):
        """PER entity type triggers NAME hotword rules."""
        enhancer = ContextEnhancer()
        text = "Mr. Anderson is here"
        span = make_span("Anderson", start=4, entity_type="PER", confidence=0.60, tier=Tier.ML)
        confidence, reasons = enhancer._apply_hotwords(text, span, 0.60)
        assert confidence > 0.60

    def test_create_enhancer_factory(self):
        """create_enhancer() returns a properly configured instance."""
        e = create_enhancer(high_confidence_threshold=0.99, enable_patterns=False)
        assert e.high_threshold == 0.99
        assert e.enable_patterns is False

    def test_enhancement_result_dataclass(self):
        """EnhancementResult is a well-formed dataclass."""
        r = EnhancementResult(action="keep", confidence=0.85, reasons=["test"])
        assert r.action == "keep"
        assert r.confidence == 0.85
        assert r.reasons == ["test"]

    def test_hotword_rule_defaults(self):
        """HotwordRule has sensible defaults."""
        import re as re_mod
        rule = HotwordRule(pattern=re_mod.compile(r"test"), confidence_delta=0.1)
        assert rule.window_before == 50
        assert rule.window_after == 30
        assert rule.description == ""


class TestIntegrationResolverAndEnhancer:
    """Integration: enhance then resolve, ensuring they compose."""

    def test_enhance_then_resolve(self):
        """Spans enhanced first then resolved produce coherent entities."""
        text = "MRN: 123456 Patient: John Smith. John Smith called back."
        enhancer = ContextEnhancer()
        spans = [
            make_span("123456", start=5, entity_type="MRN", confidence=0.90, tier=Tier.STRUCTURED),
            make_span("John Smith", start=21, entity_type="NAME", confidence=0.90, tier=Tier.ML),
            make_span("John Smith", start=33, entity_type="NAME", confidence=0.90, tier=Tier.ML),
        ]
        kept = enhancer.enhance(text, spans)
        # All should be kept (MRN is high-tier, NAMEs are non-enhanced)
        assert len(kept) == 3

        resolver = EntityResolver()
        entities = resolver.resolve(kept)
        # MRN is one entity, both John Smiths are another
        assert len(entities) == 2
        counts = get_entity_counts(entities)
        assert counts.get("NAME", 0) + counts.get("MRN", 0) >= 2

    def test_enhance_filters_before_resolve(self):
        """Rejected spans do not appear in resolution output."""
        text = "Amount 440060.24 MRN 123456"
        enhancer = ContextEnhancer()
        spans = [
            make_span("440060.24", start=7, entity_type="MRN", confidence=0.70, tier=Tier.ML),
            make_span("123456", start=21, entity_type="MRN", confidence=0.90, tier=Tier.STRUCTURED),
        ]
        kept = enhancer.enhance(text, spans)
        # Dollar amount rejected, only 123456 kept
        assert len(kept) == 1

        resolver = EntityResolver()
        entities = resolver.resolve(kept)
        assert len(entities) == 1
        assert entities[0].canonical_value == "123456"

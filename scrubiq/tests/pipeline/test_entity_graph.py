"""Tests for zero-PHI entity tracking in entity_graph.py.

Tests the EntityGraph dataclass for entity registration, pronoun
resolution, relationship tracking, and serialization.
"""

import sys
import pytest
from unittest.mock import MagicMock

# Mock the storage module before importing
mock_token_store = MagicMock()
sys.modules['scrubiq.storage'] = MagicMock()
sys.modules['scrubiq.storage.tokens'] = MagicMock()
sys.modules['scrubiq.storage.tokens'].TokenStore = mock_token_store

from scrubiq.pipeline.entity_graph import EntityGraph


def make_mock_store():
    """Create a mock TokenStore that assigns incrementing tokens."""
    store = MagicMock()
    store._counters = {}

    def get_or_create(value, entity_type):
        if entity_type not in store._counters:
            store._counters[entity_type] = 0
        store._counters[entity_type] += 1
        return f"[{entity_type}_{store._counters[entity_type]}]"

    store.get_or_create = MagicMock(side_effect=get_or_create)
    return store


# =============================================================================
# ENTITY GRAPH INITIALIZATION TESTS
# =============================================================================

class TestEntityGraphInit:
    """Tests for EntityGraph initialization."""

    def test_creates_with_session_id(self):
        """Creates graph with session_id."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test-123", token_store=store)

        assert graph.session_id == "test-123"

    def test_starts_with_empty_tokens(self):
        """Starts with empty token set."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert len(graph.tokens) == 0

    def test_starts_with_empty_edges(self):
        """Starts with empty edge dict."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert len(graph.edges) == 0

    def test_has_default_focus_slots(self):
        """Has default focus slots for PERSON, ORG, AMOUNT, LOCATION."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert "PERSON" in graph.focus
        assert "ORG" in graph.focus
        assert "AMOUNT" in graph.focus
        assert "LOCATION" in graph.focus

    def test_starts_at_turn_zero(self):
        """Starts at turn 0."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph.current_turn == 0


# =============================================================================
# REGISTER TESTS
# =============================================================================

class TestRegister:
    """Tests for register() method."""

    def test_returns_token(self):
        """Returns token from TokenStore."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John Smith", "NAME")

        assert token == "[NAME_1]"

    def test_adds_token_to_set(self):
        """Adds token to graph.tokens."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John Smith", "NAME")

        assert token in graph.tokens

    def test_stores_metadata(self):
        """Stores metadata for token."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John Smith", "NAME", {"gender": "M"})

        meta = graph.token_metadata[token]
        assert meta["type"] == "NAME"
        assert meta["gender"] == "M"

    def test_stores_turn_registered(self):
        """Stores turn number when registered."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)
        graph.current_turn = 5

        token = graph.register("John Smith", "NAME")

        assert graph.token_metadata[token]["turn_registered"] == 5

    def test_filters_unsafe_metadata(self):
        """Filters out non-safe metadata keys."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John Smith", "NAME", {
            "gender": "M",  # Safe
            "phi_value": "secret",  # Not safe
            "other_key": "value",  # Not safe
        })

        meta = graph.token_metadata[token]
        assert "gender" in meta
        assert "phi_value" not in meta
        assert "other_key" not in meta

    def test_updates_focus_for_person(self):
        """Updates PERSON focus slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John Smith", "NAME")

        assert graph.focus["PERSON"] == token

    def test_updates_focus_for_org(self):
        """Updates ORG focus slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("Acme Corp", "ORG")

        assert graph.focus["ORG"] == token

    def test_does_not_duplicate_token(self):
        """Same token is not added twice."""
        store = make_mock_store()
        # Make store return same token for same value
        store.get_or_create = MagicMock(return_value="[NAME_1]")
        graph = EntityGraph(session_id="test", token_store=store)

        graph.register("John Smith", "NAME")
        graph.register("John Smith", "NAME")  # Same value

        assert len(graph.tokens) == 1


# =============================================================================
# FOCUS AND PRONOUN RESOLUTION TESTS
# =============================================================================

class TestPronounResolution:
    """Tests for pronoun resolution."""

    def test_he_resolves_to_male(self):
        """'he' resolves to male person."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John Smith", "NAME", {"gender": "M"})

        assert graph.resolve_pronoun("he") == token
        assert graph.resolve_pronoun("him") == token
        assert graph.resolve_pronoun("his") == token

    def test_she_resolves_to_female(self):
        """'she' resolves to female person."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("Jane Doe", "NAME", {"gender": "F"})

        assert graph.resolve_pronoun("she") == token
        assert graph.resolve_pronoun("her") == token
        assert graph.resolve_pronoun("hers") == token

    def test_they_resolves_to_org_if_recent(self):
        """'they' prefers ORG if recent."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        graph.register("John", "NAME")
        org_token = graph.register("Acme Corp", "ORG")

        assert graph.resolve_pronoun("they") == org_token

    def test_it_resolves_to_org(self):
        """'it' resolves to ORG."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        org_token = graph.register("Acme Corp", "ORG")

        assert graph.resolve_pronoun("it") == org_token

    def test_there_resolves_to_location(self):
        """'there' resolves to LOCATION."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        loc_token = graph.register("123 Main St", "ADDRESS")

        assert graph.resolve_pronoun("there") == loc_token

    def test_unknown_pronoun_returns_none(self):
        """Unknown pronoun returns None."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph.resolve_pronoun("xyz") is None

    def test_no_match_returns_none(self):
        """No matching entity returns None."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        # No male registered
        assert graph.resolve_pronoun("he") is None

    def test_case_insensitive(self):
        """Pronoun matching is case-insensitive."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John", "NAME", {"gender": "M"})

        assert graph.resolve_pronoun("HE") == token
        assert graph.resolve_pronoun("He") == token

    def test_get_focus(self):
        """get_focus returns current focus for slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John", "NAME")

        assert graph.get_focus("PERSON") == token
        assert graph.get_focus("ORG") is None

    def test_set_focus(self):
        """set_focus manually sets focus slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Jane", "NAME")

        graph.set_focus("PERSON", t1)
        assert graph.focus["PERSON"] == t1

    def test_set_focus_ignores_unknown_token(self):
        """set_focus ignores unknown tokens."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        graph.set_focus("PERSON", "[UNKNOWN_99]")
        assert graph.focus["PERSON"] is None


# =============================================================================
# EDGE TESTS
# =============================================================================

class TestEdges:
    """Tests for relationship edges."""

    def test_link_creates_edge(self):
        """link() creates directed edge."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Acme Corp", "ORG")

        graph.link(t1, t2, "works_at")

        assert ("works_at", t2) in graph.edges[t1]

    def test_link_ignores_unknown_source(self):
        """link() ignores unknown source token."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")

        graph.link("[UNKNOWN_1]", t1, "rel")
        assert "[UNKNOWN_1]" not in graph.edges

    def test_link_ignores_unknown_target(self):
        """link() ignores unknown target token."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")

        graph.link(t1, "[UNKNOWN_1]", "rel")
        assert t1 not in graph.edges

    def test_link_no_duplicates(self):
        """link() doesn't create duplicate edges."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Acme Corp", "ORG")

        graph.link(t1, t2, "works_at")
        graph.link(t1, t2, "works_at")

        assert len(graph.edges[t1]) == 1

    def test_unlink_removes_edge(self):
        """unlink() removes edge."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Acme Corp", "ORG")

        graph.link(t1, t2, "works_at")
        result = graph.unlink(t1, t2, "works_at")

        assert result is True
        assert ("works_at", t2) not in graph.edges.get(t1, [])

    def test_unlink_returns_false_if_not_found(self):
        """unlink() returns False if edge not found."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")

        result = graph.unlink(t1, "[OTHER]", "rel")
        assert result is False

    def test_traverse_follows_edge(self):
        """traverse() follows edge to target."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Acme Corp", "ORG")
        graph.link(t1, t2, "works_at")

        result = graph.traverse(t1, "works_at")
        assert result == t2

    def test_traverse_returns_none_if_no_edge(self):
        """traverse() returns None if no matching edge."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")

        result = graph.traverse(t1, "works_at")
        assert result is None

    def test_traverse_all_returns_all_targets(self):
        """traverse_all() returns all targets for relation."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Acme", "ORG")
        t3 = graph.register("Beta", "ORG")

        graph.link(t1, t2, "works_at")
        graph.link(t1, t3, "works_at")

        results = graph.traverse_all(t1, "works_at")
        assert t2 in results
        assert t3 in results

    def test_related_returns_all_edges(self):
        """related() returns all edges for token."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Acme", "ORG")
        t3 = graph.register("$100k", "SALARY")

        graph.link(t1, t2, "works_at")
        graph.link(t1, t3, "earns")

        results = graph.related(t1)
        assert ("works_at", t2) in results
        assert ("earns", t3) in results

    def test_find_by_relation(self):
        """find_by_relation() finds sources for target."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Jane", "NAME")
        t3 = graph.register("Acme", "ORG")

        graph.link(t1, t3, "works_at")
        graph.link(t2, t3, "works_at")

        results = graph.find_by_relation("works_at", t3)
        assert t1 in results
        assert t2 in results


# =============================================================================
# TURN MANAGEMENT TESTS
# =============================================================================

class TestTurnManagement:
    """Tests for turn management."""

    def test_advance_turn_increments(self):
        """advance_turn() increments current_turn."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph.current_turn == 0
        graph.advance_turn()
        assert graph.current_turn == 1
        graph.advance_turn()
        assert graph.current_turn == 2


# =============================================================================
# QUERY TESTS
# =============================================================================

class TestQueries:
    """Tests for query methods."""

    def test_get_metadata(self):
        """get_metadata() returns token metadata."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John", "NAME", {"gender": "M"})
        meta = graph.get_metadata(token)

        assert meta["type"] == "NAME"
        assert meta["gender"] == "M"

    def test_get_metadata_returns_none_for_unknown(self):
        """get_metadata() returns None for unknown token."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph.get_metadata("[UNKNOWN_1]") is None

    def test_get_type(self):
        """get_type() returns entity type."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John", "NAME")
        assert graph.get_type(token) == "NAME"

    def test_get_tokens_by_type(self):
        """get_tokens_by_type() returns all tokens of type."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Jane", "NAME")
        t3 = graph.register("Acme", "ORG")

        names = graph.get_tokens_by_type("NAME")
        assert t1 in names
        assert t2 in names
        assert t3 not in names

    def test_get_all_people(self):
        """get_all_people() returns all person tokens."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Dr. Smith", "NAME_PROVIDER")
        t3 = graph.register("Acme", "ORG")

        people = graph.get_all_people()
        assert t1 in people
        assert t2 in people
        assert t3 not in people


# =============================================================================
# ENTITY ID TESTS (PHASE 2)
# =============================================================================

class TestEntityId:
    """Tests for Phase 2 entity_id operations."""

    def test_register_entity_with_id(self):
        """register_entity() stores entity_id."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        graph.register_entity(
            token="[NAME_1]",
            entity_id="uuid-123",
            entity_type="NAME",
        )

        assert "[NAME_1]" in graph.tokens
        assert graph.entity_to_token["uuid-123"] == "[NAME_1]"

    def test_get_token_by_entity_id(self):
        """get_token_by_entity_id() returns token."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        graph.register_entity("[NAME_1]", "uuid-123", "NAME")

        assert graph.get_token_by_entity_id("uuid-123") == "[NAME_1]"

    def test_get_entity_id(self):
        """get_entity_id() returns entity_id for token."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        graph.register_entity("[NAME_1]", "uuid-123", "NAME")

        assert graph.get_entity_id("[NAME_1]") == "uuid-123"

    def test_get_all_entity_ids(self):
        """get_all_entity_ids() returns all entity_ids."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        graph.register_entity("[NAME_1]", "uuid-1", "NAME")
        graph.register_entity("[NAME_2]", "uuid-2", "NAME")

        ids = graph.get_all_entity_ids()
        assert "uuid-1" in ids
        assert "uuid-2" in ids


# =============================================================================
# SERIALIZATION TESTS
# =============================================================================

class TestSerialization:
    """Tests for graph serialization."""

    def test_to_dict_includes_all_fields(self):
        """to_dict() includes all graph state."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test-123", token_store=store)

        t1 = graph.register("John", "NAME", {"gender": "M"})
        t2 = graph.register("Acme", "ORG")
        graph.link(t1, t2, "works_at")
        graph.advance_turn()

        data = graph.to_dict()

        assert data["session_id"] == "test-123"
        assert t1 in data["tokens"]
        assert t2 in data["tokens"]
        assert "PERSON" in data["focus"]
        assert t1 in data["token_metadata"]
        assert data["current_turn"] == 1

    def test_from_dict_restores_state(self):
        """from_dict() restores graph state."""
        store = make_mock_store()
        original = EntityGraph(session_id="test-123", token_store=store)

        t1 = original.register("John", "NAME", {"gender": "M"})
        t2 = original.register("Acme", "ORG")
        original.link(t1, t2, "works_at")

        data = original.to_dict()

        # Restore
        restored = EntityGraph.from_dict(data, store)

        assert restored.session_id == "test-123"
        assert t1 in restored.tokens
        assert t2 in restored.tokens
        assert restored.traverse(t1, "works_at") == t2
        assert restored.token_metadata[t1]["gender"] == "M"

    def test_from_dict_handles_missing_fields(self):
        """from_dict() handles missing optional fields."""
        store = make_mock_store()
        data = {
            "session_id": "test",
            # Missing tokens, edges, etc.
        }

        graph = EntityGraph.from_dict(data, store)

        assert graph.session_id == "test"
        assert len(graph.tokens) == 0
        assert graph.current_turn == 0


# =============================================================================
# UTILITY TESTS
# =============================================================================

class TestUtilities:
    """Tests for utility methods."""

    def test_len_returns_token_count(self):
        """len() returns number of tokens."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert len(graph) == 0

        graph.register("John", "NAME")
        assert len(graph) == 1

        graph.register("Jane", "NAME")
        assert len(graph) == 2

    def test_contains_checks_token(self):
        """'in' operator checks token membership."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        token = graph.register("John", "NAME")

        assert token in graph
        assert "[UNKNOWN_99]" not in graph

    def test_clear_resets_state(self):
        """clear() resets all graph state."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        t1 = graph.register("John", "NAME")
        t2 = graph.register("Acme", "ORG")
        graph.link(t1, t2, "works_at")
        graph.advance_turn()

        graph.clear()

        assert len(graph.tokens) == 0
        assert len(graph.edges) == 0
        assert graph.focus["PERSON"] is None
        assert len(graph.token_metadata) == 0
        assert graph.current_turn == 0


# =============================================================================
# TYPE TO SLOT MAPPING TESTS
# =============================================================================

class TestTypeToSlot:
    """Tests for _type_to_slot() mapping."""

    def test_person_types_map_to_person(self):
        """Person types map to PERSON slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph._type_to_slot("NAME") == "PERSON"
        assert graph._type_to_slot("NAME_PATIENT") == "PERSON"
        assert graph._type_to_slot("NAME_PROVIDER") == "PERSON"
        assert graph._type_to_slot("NAME_RELATIVE") == "PERSON"
        assert graph._type_to_slot("PERSON") == "PERSON"

    def test_org_types_map_to_org(self):
        """Organization types map to ORG slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph._type_to_slot("ORG") == "ORG"
        assert graph._type_to_slot("ORGANIZATION") == "ORG"
        assert graph._type_to_slot("EMPLOYER") == "ORG"
        assert graph._type_to_slot("FACILITY") == "ORG"

    def test_amount_types_map_to_amount(self):
        """Amount types map to AMOUNT slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph._type_to_slot("SALARY") == "AMOUNT"
        assert graph._type_to_slot("AMOUNT") == "AMOUNT"
        assert graph._type_to_slot("ACCOUNT_NUMBER") == "AMOUNT"
        assert graph._type_to_slot("CREDIT_CARD") == "AMOUNT"

    def test_location_types_map_to_location(self):
        """Location types map to LOCATION slot."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph._type_to_slot("ADDRESS") == "LOCATION"
        assert graph._type_to_slot("CITY") == "LOCATION"
        assert graph._type_to_slot("STATE") == "LOCATION"
        assert graph._type_to_slot("ZIP") == "LOCATION"
        assert graph._type_to_slot("GPS_COORDINATE") == "LOCATION"

    def test_unknown_type_returns_none(self):
        """Unknown types return None."""
        store = make_mock_store()
        graph = EntityGraph(session_id="test", token_store=store)

        assert graph._type_to_slot("UNKNOWN") is None
        assert graph._type_to_slot("SSN") is None

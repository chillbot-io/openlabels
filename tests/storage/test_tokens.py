"""Tests for token storage module.

Tests TokenStore, token prefixes, encryption, and entity-based lookup.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Set up environment for unencrypted testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

from scrubiq.storage.database import Database
from scrubiq.storage.tokens import (
    TokenStore,
    TOKEN_PREFIX,
    NAME_TYPES,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_keys():
    """Create a mock KeyManager."""
    keys = MagicMock()
    # Simple encrypt/decrypt that just wraps in marker bytes
    keys.encrypt.side_effect = lambda data: b"ENC:" + data + b":END"
    keys.decrypt.side_effect = lambda data: data[4:-4] if data.startswith(b"ENC:") else data
    return keys


@pytest.fixture
def db_and_store(mock_keys):
    """Create a database and token store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path)
        db.connect()

        store = TokenStore(db, mock_keys, "session_1")

        yield db, store

        db.close()


# =============================================================================
# TOKEN PREFIX TESTS
# =============================================================================

class TestTokenPrefix:
    """Tests for TOKEN_PREFIX mapping."""

    def test_name_types_mapped(self):
        """NAME types are mapped to proper prefixes."""
        assert TOKEN_PREFIX["NAME"] == "NAME"
        assert TOKEN_PREFIX["NAME_PATIENT"] == "PATIENT"
        assert TOKEN_PREFIX["NAME_PROVIDER"] == "PROVIDER"
        assert TOKEN_PREFIX["NAME_RELATIVE"] == "RELATIVE"

    def test_date_types_mapped(self):
        """Date types are mapped to proper prefixes."""
        assert TOKEN_PREFIX["DATE"] == "DATE"
        assert TOKEN_PREFIX["DOB"] == "DOB"
        assert TOKEN_PREFIX["DATETIME"] == "DATETIME"

    def test_identifier_types_mapped(self):
        """Identifier types are mapped to proper prefixes."""
        assert TOKEN_PREFIX["SSN"] == "SSN"
        assert TOKEN_PREFIX["MRN"] == "MRN"
        assert TOKEN_PREFIX["CREDIT_CARD"] == "CC"

    def test_contact_types_mapped(self):
        """Contact types are mapped to proper prefixes."""
        assert TOKEN_PREFIX["PHONE"] == "PHONE"
        assert TOKEN_PREFIX["EMAIL"] == "EMAIL"

    def test_comprehensive_mapping(self):
        """TOKEN_PREFIX covers many entity types."""
        assert len(TOKEN_PREFIX) > 100


class TestNameTypes:
    """Tests for NAME_TYPES constant."""

    def test_is_set(self):
        """NAME_TYPES is a set."""
        assert isinstance(NAME_TYPES, set)

    def test_contains_name_types(self):
        """Contains expected name types."""
        assert "NAME" in NAME_TYPES
        assert "NAME_PATIENT" in NAME_TYPES
        assert "NAME_PROVIDER" in NAME_TYPES
        assert "NAME_RELATIVE" in NAME_TYPES
        assert "PERSON" in NAME_TYPES


# =============================================================================
# TOKEN STORE BASIC TESTS
# =============================================================================

class TestTokenStoreBasic:
    """Basic tests for TokenStore."""

    def test_create_store(self, db_and_store):
        """Can create a TokenStore."""
        db, store = db_and_store
        assert store is not None
        assert store._session_id == "session_1"

    def test_conversation_id_default(self, db_and_store):
        """Default conversation_id is None."""
        db, store = db_and_store
        assert store.conversation_id is None

    def test_conversation_id_set(self, mock_keys):
        """conversation_id is set when provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            store = TokenStore(db, mock_keys, "session_1", "conv_123")
            assert store.conversation_id == "conv_123"

            db.close()


# =============================================================================
# GET OR CREATE TESTS
# =============================================================================

class TestGetOrCreate:
    """Tests for get_or_create method."""

    def test_creates_new_token(self, db_and_store):
        """Creates new token for new value."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")

        assert token == "[NAME_1]"

    def test_returns_existing_token(self, db_and_store):
        """Returns existing token for same value."""
        db, store = db_and_store

        token1 = store.get_or_create("John Smith", "NAME")
        token2 = store.get_or_create("John Smith", "NAME")

        assert token1 == token2

    def test_case_insensitive_lookup(self, db_and_store):
        """Lookup is case-insensitive."""
        db, store = db_and_store

        token1 = store.get_or_create("John Smith", "NAME")
        token2 = store.get_or_create("JOHN SMITH", "NAME")

        assert token1 == token2

    def test_whitespace_normalized(self, db_and_store):
        """Whitespace is normalized in lookup."""
        db, store = db_and_store

        token1 = store.get_or_create("  John Smith  ", "NAME")
        token2 = store.get_or_create("John Smith", "NAME")

        assert token1 == token2

    def test_different_values_get_different_tokens(self, db_and_store):
        """Different values get different tokens."""
        db, store = db_and_store

        token1 = store.get_or_create("John Smith", "NAME")
        token2 = store.get_or_create("Jane Doe", "NAME")

        assert token1 != token2
        assert token1 == "[NAME_1]"
        assert token2 == "[NAME_2]"

    def test_different_types_get_different_tokens(self, db_and_store):
        """Same value with different types gets different tokens."""
        db, store = db_and_store

        token1 = store.get_or_create("John Smith", "NAME_PATIENT")
        token2 = store.get_or_create("John Smith", "NAME_PROVIDER")

        assert token1 != token2

    def test_counter_increments(self, db_and_store):
        """Counter increments for each new token."""
        db, store = db_and_store

        tokens = [
            store.get_or_create(f"Person {i}", "NAME")
            for i in range(5)
        ]

        assert tokens == [
            "[NAME_1]", "[NAME_2]", "[NAME_3]", "[NAME_4]", "[NAME_5]"
        ]

    def test_custom_safe_harbor_value(self, db_and_store):
        """Can set custom safe harbor value."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME", safe_harbor_value="J. S.")
        value = store.get(token, use_safe_harbor=True)

        assert value == "J. S."

    def test_none_value_raises_type_error(self, db_and_store):
        """None value raises TypeError."""
        db, store = db_and_store

        with pytest.raises(TypeError, match="cannot be None"):
            store.get_or_create(None, "NAME")

    def test_empty_value_raises_value_error(self, db_and_store):
        """Empty value raises ValueError."""
        db, store = db_and_store

        with pytest.raises(ValueError, match="empty"):
            store.get_or_create("", "NAME")

    def test_whitespace_only_raises_value_error(self, db_and_store):
        """Whitespace-only value raises ValueError."""
        db, store = db_and_store

        with pytest.raises(ValueError, match="empty"):
            store.get_or_create("   ", "NAME")


# =============================================================================
# GET TESTS
# =============================================================================

class TestGet:
    """Tests for get method."""

    def test_get_returns_value(self, db_and_store):
        """get() returns original value."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")
        value = store.get(token)

        assert value == "John Smith"

    def test_get_unknown_token_returns_none(self, db_and_store):
        """get() returns None for unknown token."""
        db, store = db_and_store

        value = store.get("[UNKNOWN_99]")
        assert value is None

    def test_get_with_safe_harbor(self, db_and_store):
        """get() with use_safe_harbor returns safe harbor value."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME", safe_harbor_value="J***")
        value = store.get(token, use_safe_harbor=True)

        assert value == "J***"

    def test_get_safe_harbor_defaults_to_token(self, db_and_store):
        """Safe harbor defaults to token when not provided."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")
        # When safe_harbor_value is not provided, it defaults to the token
        value = store.get(token, use_safe_harbor=True)

        assert value == token


# =============================================================================
# GET ENTRY TESTS
# =============================================================================

class TestGetEntry:
    """Tests for get_entry method."""

    def test_get_entry_returns_token_entry(self, db_and_store):
        """get_entry() returns TokenEntry."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")
        entry = store.get_entry(token)

        assert entry is not None
        assert entry.token == token
        assert entry.entity_type == "NAME"
        assert entry.original_value == "John Smith"

    def test_get_entry_unknown_returns_none(self, db_and_store):
        """get_entry() returns None for unknown token."""
        db, store = db_and_store

        entry = store.get_entry("[UNKNOWN_99]")
        assert entry is None


# =============================================================================
# LIST TOKENS TESTS
# =============================================================================

class TestListTokens:
    """Tests for list_tokens method."""

    def test_list_tokens_empty(self, db_and_store):
        """list_tokens() returns empty list initially."""
        db, store = db_and_store

        tokens = store.list_tokens()
        assert tokens == []

    def test_list_tokens_returns_all(self, db_and_store):
        """list_tokens() returns all tokens."""
        db, store = db_and_store

        store.get_or_create("John", "NAME")
        store.get_or_create("Jane", "NAME")
        store.get_or_create("123-456-7890", "PHONE")

        tokens = store.list_tokens()

        assert len(tokens) == 3
        assert "[NAME_1]" in tokens
        assert "[NAME_2]" in tokens
        assert "[PHONE_1]" in tokens


# =============================================================================
# ADD VARIANT TESTS
# =============================================================================

class TestAddVariant:
    """Tests for add_variant method."""

    def test_add_variant(self, db_and_store):
        """add_variant() adds alternative lookup."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")
        store.add_variant(token, "Smith", "NAME")

        # Should find same token via variant
        token2 = store.get_or_create("Smith", "NAME")
        assert token2 == token

    def test_add_variant_idempotent(self, db_and_store):
        """add_variant() is idempotent."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")

        # Adding same variant twice should not error
        store.add_variant(token, "Smith", "NAME")
        store.add_variant(token, "Smith", "NAME")

        tokens = store.list_tokens()
        assert tokens == [token]


# =============================================================================
# DELETE TESTS
# =============================================================================

class TestDelete:
    """Tests for delete method."""

    def test_delete_token(self, db_and_store):
        """delete() removes token."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")
        deleted = store.delete(token)

        assert deleted is True
        assert store.get(token) is None

    def test_delete_nonexistent_returns_false(self, db_and_store):
        """delete() returns False for nonexistent token."""
        db, store = db_and_store

        deleted = store.delete("[UNKNOWN_99]")
        assert deleted is False


# =============================================================================
# COUNT TESTS
# =============================================================================

class TestCount:
    """Tests for count method."""

    def test_count_empty(self, db_and_store):
        """count() returns 0 initially."""
        db, store = db_and_store

        assert store.count() == 0
        assert len(store) == 0

    def test_count_after_inserts(self, db_and_store):
        """count() returns correct count."""
        db, store = db_and_store

        store.get_or_create("John", "NAME")
        store.get_or_create("Jane", "NAME")
        store.get_or_create("123-456-7890", "PHONE")

        assert store.count() == 3
        assert len(store) == 3


# =============================================================================
# SESSION SCOPING TESTS
# =============================================================================

class TestSessionScoping:
    """Tests for session-based token scoping."""

    def test_different_sessions_isolated(self, mock_keys):
        """Tokens are isolated between sessions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            store1 = TokenStore(db, mock_keys, "session_1")
            store2 = TokenStore(db, mock_keys, "session_2")

            token1 = store1.get_or_create("John Smith", "NAME")
            token2 = store2.get_or_create("John Smith", "NAME")

            # Same token format but stored separately
            assert token1 == "[NAME_1]"
            assert token2 == "[NAME_1]"

            # store2 shouldn't be able to lookup store1's token value
            # (they have separate counters and data)
            assert store1.count() == 1
            assert store2.count() == 1

            db.close()


# =============================================================================
# CONVERSATION SCOPING TESTS
# =============================================================================

class TestConversationScoping:
    """Tests for conversation-based token scoping."""

    def test_different_conversations_isolated(self, mock_keys):
        """Tokens are isolated between conversations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            store1 = TokenStore(db, mock_keys, "session_1", "conv_1")
            store2 = TokenStore(db, mock_keys, "session_1", "conv_2")

            token1 = store1.get_or_create("John Smith", "NAME")
            token2 = store2.get_or_create("John Smith", "NAME")

            # Same value gets same token format but separate storage
            assert token1 == "[NAME_1]"
            assert token2 == "[NAME_1]"

            # Each conversation has its own count
            assert store1.count() == 1
            assert store2.count() == 1

            db.close()

    def test_session_wide_tokens(self, mock_keys):
        """Session-wide tokens (no conversation_id) are shared."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            # Both use session-wide scope (no conversation_id)
            store1 = TokenStore(db, mock_keys, "session_1")
            store2 = TokenStore(db, mock_keys, "session_1")

            token1 = store1.get_or_create("John Smith", "NAME")
            token2 = store2.get_or_create("John Smith", "NAME")

            # Same value in session-wide scope returns same token
            assert token1 == token2

            db.close()


# =============================================================================
# ENTITY-BASED API TESTS
# =============================================================================

class TestEntityBasedAPI:
    """Tests for entity-based token API."""

    def test_get_or_create_by_entity(self, db_and_store):
        """get_or_create_by_entity() creates token by entity_id."""
        db, store = db_and_store

        token = store.get_or_create_by_entity(
            entity_id="entity-uuid-123",
            value="John Smith",
            entity_type="NAME"
        )

        assert token == "[NAME_1]"

    def test_same_entity_id_returns_same_token(self, db_and_store):
        """Same entity_id returns same token."""
        db, store = db_and_store

        token1 = store.get_or_create_by_entity(
            entity_id="entity-uuid-123",
            value="John Smith",
            entity_type="NAME"
        )
        token2 = store.get_or_create_by_entity(
            entity_id="entity-uuid-123",
            value="J. Smith",  # Different value, same entity
            entity_type="NAME"
        )

        assert token1 == token2

    def test_empty_entity_id_raises(self, db_and_store):
        """Empty entity_id raises ValueError."""
        db, store = db_and_store

        with pytest.raises(ValueError, match="entity_id cannot be empty"):
            store.get_or_create_by_entity("", "John Smith", "NAME")

    def test_empty_value_raises(self, db_and_store):
        """Empty value raises ValueError."""
        db, store = db_and_store

        with pytest.raises(ValueError, match="value cannot be empty"):
            store.get_or_create_by_entity("entity-123", "", "NAME")

    def test_register_entity_variant(self, db_and_store):
        """register_entity_variant() adds variant for entity."""
        db, store = db_and_store

        token = store.get_or_create_by_entity(
            entity_id="entity-uuid-123",
            value="John Smith",
            entity_type="NAME"
        )

        store.register_entity_variant("entity-uuid-123", "Smith", "NAME")

        # Should find via variant
        token2 = store.get_or_create("Smith", "NAME")
        assert token2 == token

    def test_get_all_variants(self, db_and_store):
        """get_all_variants() returns all stored values."""
        db, store = db_and_store

        token = store.get_or_create("John Smith", "NAME")
        store.add_variant(token, "Smith", "NAME")
        store.add_variant(token, "John", "NAME")

        variants = store.get_all_variants(token)

        assert "John Smith" in variants
        assert "Smith" in variants
        assert "John" in variants


# =============================================================================
# NAME TOKEN MAPPINGS TESTS
# =============================================================================

class TestNameTokenMappings:
    """Tests for get_name_token_mappings method."""

    def test_returns_name_type_tokens(self, db_and_store):
        """get_name_token_mappings() returns NAME-type tokens."""
        db, store = db_and_store

        store.get_or_create("John Smith", "NAME")
        store.get_or_create("Dr. Jones", "NAME_PROVIDER")
        store.get_or_create("123-456-7890", "PHONE")

        mappings = store.get_name_token_mappings()

        assert "[NAME_1]" in mappings
        assert "[PROVIDER_1]" in mappings
        assert "[PHONE_1]" not in mappings  # Not a name type

    def test_mapping_contains_value_and_type(self, db_and_store):
        """Mappings contain (value, entity_type) tuples."""
        db, store = db_and_store

        store.get_or_create("John Smith", "NAME")

        mappings = store.get_name_token_mappings()

        assert mappings["[NAME_1]"] == ("John Smith", "NAME")


# =============================================================================
# COUNTER PERSISTENCE TESTS
# =============================================================================

class TestCounterPersistence:
    """Tests for counter persistence across reloads."""

    def test_counters_loaded_on_init(self, mock_keys):
        """Counters are loaded from database on init."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = Database(db_path)
            db.connect()

            # Create tokens with first store
            store1 = TokenStore(db, mock_keys, "session_1")
            store1.get_or_create("Person 1", "NAME")
            store1.get_or_create("Person 2", "NAME")

            # Create new store instance
            store2 = TokenStore(db, mock_keys, "session_1")

            # Counter should continue from where store1 left off
            token = store2.get_or_create("Person 3", "NAME")
            assert token == "[NAME_3]"

            db.close()

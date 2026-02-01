"""Tests for conversation context tracking.

Tests the ConversationContext class in scrubiq/pipeline/conversation_context.py:
- Token observation and tracking
- Focus slot management
- Recent mention retrieval
- Gender-based lookups
- Serialization/deserialization
- Turn management
"""

import pytest

from scrubiq.pipeline.conversation_context import (
    ConversationContext,
    MentionRecord,
    TYPE_TO_SLOT,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def context():
    """Create a fresh ConversationContext."""
    return ConversationContext(
        session_id="test-session",
        conversation_id="test-conversation",
    )


@pytest.fixture
def populated_context():
    """Create a ConversationContext with some data."""
    ctx = ConversationContext(
        session_id="test-session",
        conversation_id="test-conversation",
    )
    # Add some mentions
    ctx.observe("[NAME_1]", "NAME", {"gender": "M"})
    ctx.observe("[NAME_2]", "NAME_PATIENT", {"gender": "F"})
    ctx.observe("[ORG_1]", "ORG", {"is_org": True})
    ctx.observe("[ADDRESS_1]", "ADDRESS", {})
    ctx.observe("[DATE_1]", "DATE_DOB", {})
    return ctx


# =============================================================================
# INITIALIZATION TESTS
# =============================================================================

class TestInitialization:
    """Tests for ConversationContext initialization."""

    def test_init_with_ids(self):
        """Initializes with session and conversation IDs."""
        ctx = ConversationContext(
            session_id="session-123",
            conversation_id="conv-456",
        )
        assert ctx.session_id == "session-123"
        assert ctx.conversation_id == "conv-456"

    def test_init_empty_state(self, context):
        """Initializes with empty state."""
        assert len(context._recent_mentions) == 0
        assert len(context._focus) == 0
        assert len(context._token_metadata) == 0
        assert len(context._tokens) == 0
        assert context.current_turn == 0

    def test_init_default_max_mentions(self, context):
        """Has default max mentions limit."""
        assert context._max_mentions == 100


# =============================================================================
# OBSERVE TESTS
# =============================================================================

class TestObserve:
    """Tests for observe() method."""

    def test_observe_adds_token(self, context):
        """observe() adds token to set."""
        context.observe("[NAME_1]", "NAME")
        assert "[NAME_1]" in context._tokens

    def test_observe_creates_mention_record(self, context):
        """observe() creates MentionRecord."""
        context.observe("[NAME_1]", "NAME", {"gender": "M"})

        assert len(context._recent_mentions) == 1
        record = context._recent_mentions[0]
        assert record.token == "[NAME_1]"
        assert record.entity_type == "NAME"
        assert record.turn == 0
        assert record.metadata == {"gender": "M"}

    def test_observe_updates_focus_slot(self, context):
        """observe() updates focus slot for matching type."""
        context.observe("[NAME_1]", "NAME")
        assert context._focus.get("PERSON") == "[NAME_1]"

    def test_observe_overwrites_focus_slot(self, context):
        """Later observations overwrite focus slot."""
        context.observe("[NAME_1]", "NAME")
        context.observe("[NAME_2]", "NAME")
        assert context._focus.get("PERSON") == "[NAME_2]"

    def test_observe_with_metadata(self, context):
        """observe() stores metadata."""
        context.observe("[NAME_1]", "NAME", {"gender": "M", "confidence": 0.95})

        meta = context._token_metadata["[NAME_1]"]
        assert meta["gender"] == "M"
        assert meta["confidence"] == 0.95
        assert meta["type"] == "NAME"
        assert meta["turn_first_seen"] == 0
        assert meta["turn_last_seen"] == 0

    def test_observe_updates_turn_last_seen(self, context):
        """observe() updates turn_last_seen on repeat observation."""
        context.observe("[NAME_1]", "NAME")
        context.advance_turn()
        context.observe("[NAME_1]", "NAME")

        meta = context._token_metadata["[NAME_1]"]
        assert meta["turn_first_seen"] == 0
        assert meta["turn_last_seen"] == 1

    def test_observe_without_metadata(self, context):
        """observe() works without metadata."""
        context.observe("[NAME_1]", "NAME")

        meta = context._token_metadata["[NAME_1]"]
        assert meta["type"] == "NAME"
        assert meta["turn_first_seen"] == 0

    def test_observe_prunes_old_mentions(self, context):
        """observe() prunes when exceeding max_mentions."""
        context._max_mentions = 5

        for i in range(10):
            context.observe(f"[NAME_{i}]", "NAME")

        assert len(context._recent_mentions) == 5
        # Should keep the most recent 5
        assert context._recent_mentions[-1].token == "[NAME_9]"

    def test_observe_multiple_types(self, context):
        """observe() handles different entity types."""
        context.observe("[NAME_1]", "NAME")
        context.observe("[ORG_1]", "ORG")
        context.observe("[ADDRESS_1]", "ADDRESS")

        assert context._focus.get("PERSON") == "[NAME_1]"
        assert context._focus.get("ORG") == "[ORG_1]"
        assert context._focus.get("LOCATION") == "[ADDRESS_1]"


# =============================================================================
# EXTRACT SAFE METADATA TESTS
# =============================================================================

class TestExtractSafeMetadata:
    """Tests for _extract_safe_metadata() method."""

    def test_extracts_safe_keys(self, context):
        """Extracts only safe metadata keys."""
        metadata = {
            "gender": "M",
            "is_plural": False,
            "is_org": True,
            "entity_id": "123",
            "confidence": 0.95,
            "detector": "ml",
            "semantic_role": "patient",
            # These should be filtered out:
            "original_text": "John Smith",
            "ssn": "123-45-6789",
            "random_field": "value",
        }

        safe = context._extract_safe_metadata(metadata)

        assert safe["gender"] == "M"
        assert safe["is_plural"] is False
        assert safe["is_org"] is True
        assert safe["entity_id"] == "123"
        assert safe["confidence"] == 0.95
        assert safe["detector"] == "ml"
        assert safe["semantic_role"] == "patient"

        # PHI should be filtered
        assert "original_text" not in safe
        assert "ssn" not in safe
        assert "random_field" not in safe

    def test_handles_empty_metadata(self, context):
        """Handles empty metadata dict."""
        safe = context._extract_safe_metadata({})
        assert safe == {}

    def test_handles_no_safe_keys(self, context):
        """Handles metadata with no safe keys."""
        metadata = {"phi_field": "sensitive", "other": "data"}
        safe = context._extract_safe_metadata(metadata)
        assert safe == {}


# =============================================================================
# GET FOCUS TESTS
# =============================================================================

class TestGetFocus:
    """Tests for get_focus() method."""

    def test_get_focus_person(self, populated_context):
        """Gets focused person token."""
        # NAME_2 was observed last among person types
        assert populated_context.get_focus("PERSON") == "[NAME_2]"

    def test_get_focus_org(self, populated_context):
        """Gets focused org token."""
        assert populated_context.get_focus("ORG") == "[ORG_1]"

    def test_get_focus_location(self, populated_context):
        """Gets focused location token."""
        assert populated_context.get_focus("LOCATION") == "[ADDRESS_1]"

    def test_get_focus_date(self, populated_context):
        """Gets focused date token."""
        assert populated_context.get_focus("DATE") == "[DATE_1]"

    def test_get_focus_unknown_slot(self, populated_context):
        """Returns None for unknown slot."""
        assert populated_context.get_focus("UNKNOWN") is None

    def test_get_focus_empty_context(self, context):
        """Returns None when no observations."""
        assert context.get_focus("PERSON") is None


# =============================================================================
# GET RECENT TESTS
# =============================================================================

class TestGetRecent:
    """Tests for get_recent() method."""

    def test_get_recent_by_type(self, context):
        """Gets recent tokens of specific type."""
        context.observe("[NAME_1]", "NAME")
        context.observe("[NAME_2]", "NAME")
        context.observe("[ORG_1]", "ORG")

        recent = context.get_recent("NAME")
        assert "[NAME_1]" in recent
        assert "[NAME_2]" in recent
        assert "[ORG_1]" not in recent

    def test_get_recent_most_recent_first(self, context):
        """Returns tokens with most recent first."""
        context.observe("[NAME_1]", "NAME")
        context.observe("[NAME_2]", "NAME")
        context.observe("[NAME_3]", "NAME")

        recent = context.get_recent("NAME")
        assert recent == ["[NAME_3]", "[NAME_2]", "[NAME_1]"]

    def test_get_recent_respects_turn_cutoff(self, context):
        """Respects max_turns_back parameter."""
        context.observe("[NAME_1]", "NAME")
        context.advance_turn()
        context.observe("[NAME_2]", "NAME")
        context.advance_turn()
        context.observe("[NAME_3]", "NAME")
        context.advance_turn()
        context.observe("[NAME_4]", "NAME")

        # Only tokens from last 2 turns (current_turn=3, cutoff=3-2=1)
        # Tokens at turn >= 1 are included
        recent = context.get_recent("NAME", max_turns_back=2)
        assert "[NAME_4]" in recent  # turn 3 (current)
        assert "[NAME_3]" in recent  # turn 2
        assert "[NAME_2]" in recent  # turn 1 (at cutoff, included)
        assert "[NAME_1]" not in recent  # turn 0 (too old)

    def test_get_recent_deduplicates(self, context):
        """Deduplicates repeated tokens."""
        context.observe("[NAME_1]", "NAME")
        context.observe("[NAME_1]", "NAME")  # duplicate
        context.observe("[NAME_1]", "NAME")  # duplicate

        recent = context.get_recent("NAME")
        assert len(recent) == 1
        assert recent == ["[NAME_1]"]

    def test_get_recent_matches_base_type(self, context):
        """Matches NAME for NAME_PATIENT, NAME_PROVIDER, etc."""
        context.observe("[NAME_1]", "NAME_PATIENT")
        context.observe("[NAME_2]", "NAME_PROVIDER")
        context.observe("[NAME_3]", "NAME_RELATIVE")

        recent = context.get_recent("NAME")
        assert len(recent) == 3
        assert "[NAME_1]" in recent
        assert "[NAME_2]" in recent
        assert "[NAME_3]" in recent

    def test_get_recent_empty(self, context):
        """Returns empty list when no matches."""
        context.observe("[ORG_1]", "ORG")
        recent = context.get_recent("NAME")
        assert recent == []


# =============================================================================
# BASE TYPE TESTS
# =============================================================================

class TestBaseType:
    """Tests for _base_type() method."""

    def test_base_type_patient(self, context):
        """NAME_PATIENT -> NAME."""
        assert context._base_type("NAME_PATIENT") == "NAME"

    def test_base_type_provider(self, context):
        """NAME_PROVIDER -> NAME."""
        assert context._base_type("NAME_PROVIDER") == "NAME"

    def test_base_type_relative(self, context):
        """NAME_RELATIVE -> NAME."""
        assert context._base_type("NAME_RELATIVE") == "NAME"

    def test_base_type_no_suffix(self, context):
        """Type without suffix returns unchanged."""
        assert context._base_type("NAME") == "NAME"
        assert context._base_type("ORG") == "ORG"
        assert context._base_type("DATE") == "DATE"


# =============================================================================
# GET TOKEN METADATA TESTS
# =============================================================================

class TestGetTokenMetadata:
    """Tests for get_token_metadata() method."""

    def test_get_token_metadata(self, context):
        """Gets metadata for observed token."""
        context.observe("[NAME_1]", "NAME", {"gender": "M", "confidence": 0.9})

        meta = context.get_token_metadata("[NAME_1]")
        assert meta is not None
        assert meta["gender"] == "M"
        assert meta["confidence"] == 0.9
        assert meta["type"] == "NAME"

    def test_get_token_metadata_unknown(self, context):
        """Returns None for unknown token."""
        assert context.get_token_metadata("[UNKNOWN]") is None


# =============================================================================
# GET GENDER TESTS
# =============================================================================

class TestGetGender:
    """Tests for get_gender() method."""

    def test_get_gender_male(self, context):
        """Gets male gender."""
        context.observe("[NAME_1]", "NAME", {"gender": "M"})
        assert context.get_gender("[NAME_1]") == "M"

    def test_get_gender_female(self, context):
        """Gets female gender."""
        context.observe("[NAME_1]", "NAME", {"gender": "F"})
        assert context.get_gender("[NAME_1]") == "F"

    def test_get_gender_no_gender(self, context):
        """Returns None when no gender metadata."""
        context.observe("[NAME_1]", "NAME", {})
        assert context.get_gender("[NAME_1]") is None

    def test_get_gender_unknown_token(self, context):
        """Returns None for unknown token."""
        assert context.get_gender("[UNKNOWN]") is None


# =============================================================================
# GET RECENT BY GENDER TESTS
# =============================================================================

class TestGetRecentByGender:
    """Tests for get_recent_by_gender() method."""

    def test_get_recent_by_gender_male(self, context):
        """Gets most recent male token."""
        context.observe("[NAME_1]", "NAME", {"gender": "M"})
        context.observe("[NAME_2]", "NAME", {"gender": "F"})
        context.observe("[NAME_3]", "NAME", {"gender": "M"})

        result = context.get_recent_by_gender("M")
        assert result == "[NAME_3]"  # Most recent male

    def test_get_recent_by_gender_female(self, context):
        """Gets most recent female token."""
        context.observe("[NAME_1]", "NAME", {"gender": "F"})
        context.observe("[NAME_2]", "NAME", {"gender": "M"})
        context.observe("[NAME_3]", "NAME", {"gender": "F"})

        result = context.get_recent_by_gender("F")
        assert result == "[NAME_3]"  # Most recent female

    def test_get_recent_by_gender_respects_turn_cutoff(self, context):
        """Respects max_turns_back parameter."""
        context.observe("[NAME_1]", "NAME", {"gender": "M"})
        context.advance_turn()
        context.advance_turn()
        context.advance_turn()
        context.observe("[NAME_2]", "NAME", {"gender": "F"})

        # NAME_1 is too old
        result = context.get_recent_by_gender("M", max_turns_back=2)
        assert result is None

    def test_get_recent_by_gender_includes_name_variants(self, context):
        """Includes NAME_PATIENT, NAME_PROVIDER, etc."""
        context.observe("[NAME_1]", "NAME_PATIENT", {"gender": "M"})
        context.observe("[NAME_2]", "NAME_PROVIDER", {"gender": "F"})

        assert context.get_recent_by_gender("M") == "[NAME_1]"
        assert context.get_recent_by_gender("F") == "[NAME_2]"

    def test_get_recent_by_gender_no_match(self, context):
        """Returns None when no gender match."""
        context.observe("[NAME_1]", "NAME", {"gender": "F"})
        assert context.get_recent_by_gender("M") is None

    def test_get_recent_by_gender_no_gender_metadata(self, context):
        """Skips tokens without gender metadata."""
        context.observe("[NAME_1]", "NAME", {})  # No gender
        context.observe("[NAME_2]", "NAME", {"gender": "M"})

        result = context.get_recent_by_gender("M")
        assert result == "[NAME_2]"


# =============================================================================
# GET ALL TOKENS TESTS
# =============================================================================

class TestGetAllTokens:
    """Tests for get_all_tokens() method."""

    def test_get_all_tokens(self, populated_context):
        """Gets all observed tokens."""
        tokens = populated_context.get_all_tokens()
        assert "[NAME_1]" in tokens
        assert "[NAME_2]" in tokens
        assert "[ORG_1]" in tokens
        assert "[ADDRESS_1]" in tokens
        assert "[DATE_1]" in tokens

    def test_get_all_tokens_returns_copy(self, context):
        """Returns a copy, not the internal set."""
        context.observe("[NAME_1]", "NAME")
        tokens = context.get_all_tokens()
        tokens.add("[FAKE]")

        assert "[FAKE]" not in context._tokens

    def test_get_all_tokens_empty(self, context):
        """Returns empty set when no observations."""
        assert context.get_all_tokens() == set()


# =============================================================================
# ADVANCE TURN TESTS
# =============================================================================

class TestAdvanceTurn:
    """Tests for advance_turn() method."""

    def test_advance_turn(self, context):
        """Advances turn counter."""
        assert context.current_turn == 0
        context.advance_turn()
        assert context.current_turn == 1
        context.advance_turn()
        assert context.current_turn == 2

    def test_advance_turn_affects_observations(self, context):
        """Turn affects observation recording."""
        context.observe("[NAME_1]", "NAME")
        context.advance_turn()
        context.observe("[NAME_2]", "NAME")

        assert context._recent_mentions[0].turn == 0
        assert context._recent_mentions[1].turn == 1


# =============================================================================
# CLEAR TESTS
# =============================================================================

class TestClear:
    """Tests for clear() method."""

    def test_clear_resets_all_state(self, populated_context):
        """Clears all state."""
        populated_context.advance_turn()
        populated_context.advance_turn()

        populated_context.clear()

        assert len(populated_context._recent_mentions) == 0
        assert len(populated_context._focus) == 0
        assert len(populated_context._token_metadata) == 0
        assert len(populated_context._tokens) == 0
        assert populated_context.current_turn == 0

    def test_clear_preserves_ids(self, populated_context):
        """Clear preserves session/conversation IDs."""
        populated_context.clear()

        assert populated_context.session_id == "test-session"
        assert populated_context.conversation_id == "test-conversation"


# =============================================================================
# SERIALIZATION TESTS
# =============================================================================

class TestSerialization:
    """Tests for to_dict() and from_dict() methods."""

    def test_to_dict(self, populated_context):
        """Serializes to dictionary."""
        populated_context.advance_turn()
        data = populated_context.to_dict()

        assert data["session_id"] == "test-session"
        assert data["conversation_id"] == "test-conversation"
        assert data["current_turn"] == 1
        assert len(data["recent_mentions"]) == 5
        assert len(data["tokens"]) == 5
        assert "PERSON" in data["focus"]

    def test_to_dict_mention_format(self, context):
        """Mentions are serialized correctly."""
        context.observe("[NAME_1]", "NAME", {"gender": "M"})
        data = context.to_dict()

        mention = data["recent_mentions"][0]
        assert mention["token"] == "[NAME_1]"
        assert mention["entity_type"] == "NAME"
        assert mention["turn"] == 0
        assert mention["metadata"] == {"gender": "M"}

    def test_from_dict(self, populated_context):
        """Deserializes from dictionary."""
        populated_context.advance_turn()
        data = populated_context.to_dict()

        restored = ConversationContext.from_dict(data)

        assert restored.session_id == "test-session"
        assert restored.conversation_id == "test-conversation"
        assert restored.current_turn == 1
        assert len(restored._recent_mentions) == 5
        assert len(restored._tokens) == 5
        assert "[NAME_1]" in restored._tokens

    def test_roundtrip(self, populated_context):
        """Roundtrip serialization preserves data."""
        populated_context.advance_turn()
        populated_context.observe("[NAME_3]", "NAME", {"gender": "M"})

        data = populated_context.to_dict()
        restored = ConversationContext.from_dict(data)

        assert restored.get_focus("PERSON") == populated_context.get_focus("PERSON")
        assert restored.get_all_tokens() == populated_context.get_all_tokens()
        assert restored.get_gender("[NAME_1]") == populated_context.get_gender("[NAME_1]")

    def test_from_dict_handles_missing_fields(self):
        """Handles missing optional fields."""
        data = {
            "session_id": "test",
            "conversation_id": "test",
        }

        restored = ConversationContext.from_dict(data)
        assert restored.current_turn == 0
        assert len(restored._tokens) == 0


# =============================================================================
# MAGIC METHOD TESTS
# =============================================================================

class TestMagicMethods:
    """Tests for __len__ and __contains__ methods."""

    def test_len(self, populated_context):
        """__len__ returns number of tokens."""
        assert len(populated_context) == 5

    def test_len_empty(self, context):
        """__len__ returns 0 when empty."""
        assert len(context) == 0

    def test_contains_true(self, populated_context):
        """__contains__ returns True for observed tokens."""
        assert "[NAME_1]" in populated_context
        assert "[ORG_1]" in populated_context

    def test_contains_false(self, populated_context):
        """__contains__ returns False for unobserved tokens."""
        assert "[FAKE_TOKEN]" not in populated_context


# =============================================================================
# TYPE TO SLOT MAPPING TESTS
# =============================================================================

class TestTypeToSlotMapping:
    """Tests for TYPE_TO_SLOT mapping."""

    def test_person_types(self):
        """Person types map to PERSON slot."""
        for t in ["NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE", "PERSON", "PER"]:
            assert TYPE_TO_SLOT.get(t) == "PERSON"

    def test_org_types(self):
        """Organization types map to ORG slot."""
        for t in ["ORG", "ORGANIZATION", "EMPLOYER", "FACILITY", "COMPANY"]:
            assert TYPE_TO_SLOT.get(t) == "ORG"

    def test_location_types(self):
        """Location types map to LOCATION slot."""
        for t in ["ADDRESS", "CITY", "STATE", "ZIP", "GPS_COORDINATE", "LOCATION"]:
            assert TYPE_TO_SLOT.get(t) == "LOCATION"

    def test_date_types(self):
        """Date types map to DATE slot."""
        for t in ["DATE", "DATE_DOB", "DOB"]:
            assert TYPE_TO_SLOT.get(t) == "DATE"


# =============================================================================
# MENTION RECORD TESTS
# =============================================================================

class TestMentionRecord:
    """Tests for MentionRecord dataclass."""

    def test_mention_record_creation(self):
        """Creates MentionRecord with all fields."""
        record = MentionRecord(
            token="[NAME_1]",
            entity_type="NAME",
            turn=5,
            metadata={"gender": "M"},
        )

        assert record.token == "[NAME_1]"
        assert record.entity_type == "NAME"
        assert record.turn == 5
        assert record.metadata == {"gender": "M"}

    def test_mention_record_default_metadata(self):
        """Default metadata is empty dict."""
        record = MentionRecord(
            token="[NAME_1]",
            entity_type="NAME",
            turn=0,
        )
        assert record.metadata == {}

"""Tests for ScrubIQ core types.

Tests for enums, dataclasses, and utility functions.
"""

from datetime import datetime
from unittest.mock import patch

import pytest

from scrubiq.types import (
    # Enums
    Tier,
    PrivacyMode,
    ReviewReason,
    AuditEventType,
    # Constants
    KNOWN_ENTITY_TYPES,
    CLINICAL_CONTEXT_TYPES,
    # Functions
    validate_entity_type,
    is_clinical_context_type,
    # Data classes
    Span,
    Mention,
    Entity,
    TokenEntry,
    AuditEntry,
    ReviewItem,
    UploadResult,
    RedactionResult,
    RestorationResult,
    ChatResult,
)


# =============================================================================
# TIER ENUM TESTS
# =============================================================================

class TestTier:
    """Tests for Tier enum."""

    def test_ml_value(self):
        """ML tier has value 1."""
        assert Tier.ML == 1
        assert Tier.ML.value == 1

    def test_pattern_value(self):
        """PATTERN tier has value 2."""
        assert Tier.PATTERN == 2
        assert Tier.PATTERN.value == 2

    def test_structured_value(self):
        """STRUCTURED tier has value 3."""
        assert Tier.STRUCTURED == 3
        assert Tier.STRUCTURED.value == 3

    def test_checksum_value(self):
        """CHECKSUM tier has value 4."""
        assert Tier.CHECKSUM == 4
        assert Tier.CHECKSUM.value == 4

    def test_tier_ordering(self):
        """Higher tier has higher authority."""
        assert Tier.ML < Tier.PATTERN < Tier.STRUCTURED < Tier.CHECKSUM

    def test_from_value_valid(self):
        """from_value converts valid int to Tier."""
        assert Tier.from_value(1) == Tier.ML
        assert Tier.from_value(2) == Tier.PATTERN
        assert Tier.from_value(3) == Tier.STRUCTURED
        assert Tier.from_value(4) == Tier.CHECKSUM

    def test_from_value_invalid_zero(self):
        """from_value rejects 0."""
        with pytest.raises(ValueError, match="Invalid Tier value"):
            Tier.from_value(0)

    def test_from_value_invalid_negative(self):
        """from_value rejects negative values."""
        with pytest.raises(ValueError, match="Invalid Tier value"):
            Tier.from_value(-1)

    def test_from_value_invalid_five(self):
        """from_value rejects 5."""
        with pytest.raises(ValueError, match="Invalid Tier value"):
            Tier.from_value(5)

    def test_is_int_enum(self):
        """Tier is IntEnum."""
        from enum import IntEnum
        assert issubclass(Tier, IntEnum)

    def test_usable_in_comparisons(self):
        """Tier can be compared with int."""
        assert Tier.ML < 2
        assert Tier.CHECKSUM > 3
        assert Tier.PATTERN == 2


# =============================================================================
# PRIVACYMODE ENUM TESTS
# =============================================================================

class TestPrivacyMode:
    """Tests for PrivacyMode enum."""

    def test_redacted_value(self):
        """REDACTED mode value."""
        assert PrivacyMode.REDACTED.value == "redacted"

    def test_safe_harbor_value(self):
        """SAFE_HARBOR mode value."""
        assert PrivacyMode.SAFE_HARBOR.value == "safe_harbor"

    def test_research_value(self):
        """RESEARCH mode value."""
        assert PrivacyMode.RESEARCH.value == "research"

    def test_all_modes_exist(self):
        """All expected modes exist."""
        modes = [m.value for m in PrivacyMode]
        assert "redacted" in modes
        assert "safe_harbor" in modes
        assert "research" in modes


# =============================================================================
# REVIEWREASON ENUM TESTS
# =============================================================================

class TestReviewReason:
    """Tests for ReviewReason enum."""

    def test_low_confidence_value(self):
        """LOW_CONFIDENCE reason value."""
        assert ReviewReason.LOW_CONFIDENCE.value == "low_confidence"

    def test_ambiguous_context_value(self):
        """AMBIGUOUS_CONTEXT reason value."""
        assert ReviewReason.AMBIGUOUS_CONTEXT.value == "ambiguous_context"

    def test_allowlist_edge_value(self):
        """ALLOWLIST_EDGE reason value."""
        assert ReviewReason.ALLOWLIST_EDGE.value == "allowlist_edge"

    def test_coref_uncertain_value(self):
        """COREF_UNCERTAIN reason value."""
        assert ReviewReason.COREF_UNCERTAIN.value == "coref_uncertain"

    def test_ml_only_value(self):
        """ML_ONLY reason value."""
        assert ReviewReason.ML_ONLY.value == "ml_only"

    def test_new_pattern_value(self):
        """NEW_PATTERN reason value."""
        assert ReviewReason.NEW_PATTERN.value == "new_pattern"


# =============================================================================
# AUDITEVENTTYPE ENUM TESTS
# =============================================================================

class TestAuditEventType:
    """Tests for AuditEventType enum."""

    def test_session_events(self):
        """Session event types exist."""
        assert AuditEventType.SESSION_START.value == "SESSION_START"
        assert AuditEventType.SESSION_END.value == "SESSION_END"
        assert AuditEventType.SESSION_UNLOCK.value == "SESSION_UNLOCK"
        assert AuditEventType.SESSION_LOCK.value == "SESSION_LOCK"

    def test_phi_events(self):
        """PHI event types exist."""
        assert AuditEventType.PHI_DETECTED.value == "PHI_DETECTED"
        assert AuditEventType.PHI_REDACTED.value == "PHI_REDACTED"
        assert AuditEventType.PHI_RESTORED.value == "PHI_RESTORED"

    def test_file_events(self):
        """File event types exist."""
        assert AuditEventType.IMAGE_REDACTED.value == "IMAGE_REDACTED"
        assert AuditEventType.FILE_PROCESSED.value == "FILE_PROCESSED"

    def test_review_events(self):
        """Review event types exist."""
        assert AuditEventType.REVIEW_APPROVED.value == "REVIEW_APPROVED"
        assert AuditEventType.REVIEW_REJECTED.value == "REVIEW_REJECTED"

    def test_system_events(self):
        """System event types exist."""
        assert AuditEventType.ERROR.value == "ERROR"
        assert AuditEventType.CHAIN_FORK.value == "CHAIN_FORK"


# =============================================================================
# KNOWN_ENTITY_TYPES TESTS
# =============================================================================

class TestKnownEntityTypes:
    """Tests for KNOWN_ENTITY_TYPES constant."""

    def test_is_frozenset(self):
        """KNOWN_ENTITY_TYPES is frozenset."""
        assert isinstance(KNOWN_ENTITY_TYPES, frozenset)

    def test_contains_name_types(self):
        """Contains name entity types."""
        name_types = ["NAME", "PERSON", "PATIENT", "DOCTOR", "FIRSTNAME", "LASTNAME"]
        for etype in name_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_contains_date_types(self):
        """Contains date entity types."""
        date_types = ["DATE", "DOB", "DATETIME", "BIRTHDAY"]
        for etype in date_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_contains_location_types(self):
        """Contains location entity types."""
        location_types = ["ADDRESS", "ZIP", "CITY", "STATE", "COUNTRY"]
        for etype in location_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_contains_identifier_types(self):
        """Contains identifier entity types."""
        id_types = ["SSN", "MRN", "NPI", "PASSPORT", "DRIVER_LICENSE"]
        for etype in id_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_contains_contact_types(self):
        """Contains contact entity types."""
        contact_types = ["PHONE", "EMAIL", "FAX", "URL"]
        for etype in contact_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_contains_financial_types(self):
        """Contains financial entity types."""
        financial_types = ["CREDIT_CARD", "ACCOUNT_NUMBER", "IBAN", "CUSIP", "BITCOIN_ADDRESS"]
        for etype in financial_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_contains_secret_types(self):
        """Contains secret entity types."""
        secret_types = ["AWS_ACCESS_KEY", "GITHUB_TOKEN", "API_KEY", "PASSWORD"]
        for etype in secret_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_contains_government_types(self):
        """Contains government entity types."""
        gov_types = ["CLASSIFICATION_LEVEL", "CAGE_CODE", "CLEARANCE_LEVEL"]
        for etype in gov_types:
            assert etype in KNOWN_ENTITY_TYPES

    def test_immutable(self):
        """KNOWN_ENTITY_TYPES cannot be modified."""
        with pytest.raises(AttributeError):
            KNOWN_ENTITY_TYPES.add("NEW_TYPE")


# =============================================================================
# CLINICAL_CONTEXT_TYPES TESTS
# =============================================================================

class TestClinicalContextTypes:
    """Tests for CLINICAL_CONTEXT_TYPES constant."""

    def test_is_frozenset(self):
        """CLINICAL_CONTEXT_TYPES is frozenset."""
        assert isinstance(CLINICAL_CONTEXT_TYPES, frozenset)

    def test_contains_expected_types(self):
        """Contains expected clinical types."""
        expected = ["LAB_TEST", "DIAGNOSIS", "MEDICATION", "DRUG", "PROCEDURE", "PAYER"]
        for etype in expected:
            assert etype in CLINICAL_CONTEXT_TYPES

    def test_contains_physical_desc(self):
        """Contains PHYSICAL_DESC type."""
        assert "PHYSICAL_DESC" in CLINICAL_CONTEXT_TYPES

    def test_subset_of_known_types(self):
        """Clinical types are subset of known types."""
        assert CLINICAL_CONTEXT_TYPES.issubset(KNOWN_ENTITY_TYPES)

    def test_immutable(self):
        """CLINICAL_CONTEXT_TYPES cannot be modified."""
        with pytest.raises(AttributeError):
            CLINICAL_CONTEXT_TYPES.add("NEW_TYPE")


# =============================================================================
# VALIDATE_ENTITY_TYPE TESTS
# =============================================================================

class TestValidateEntityType:
    """Tests for validate_entity_type function."""

    def test_known_type_returns_true(self):
        """Returns True for known type."""
        assert validate_entity_type("NAME") is True
        assert validate_entity_type("SSN") is True
        assert validate_entity_type("EMAIL") is True

    def test_unknown_type_returns_false(self):
        """Returns False for unknown type."""
        assert validate_entity_type("UNKNOWN_TYPE") is False
        assert validate_entity_type("MADE_UP") is False

    def test_case_sensitive(self):
        """Validation is case sensitive."""
        assert validate_entity_type("name") is False
        assert validate_entity_type("NAME") is True

    def test_empty_string(self):
        """Empty string returns False."""
        assert validate_entity_type("") is False


# =============================================================================
# IS_CLINICAL_CONTEXT_TYPE TESTS
# =============================================================================

class TestIsClinicalContextType:
    """Tests for is_clinical_context_type function."""

    def test_clinical_type_returns_true(self):
        """Returns True for clinical type."""
        assert is_clinical_context_type("LAB_TEST") is True
        assert is_clinical_context_type("MEDICATION") is True
        assert is_clinical_context_type("DIAGNOSIS") is True

    def test_non_clinical_type_returns_false(self):
        """Returns False for non-clinical type."""
        assert is_clinical_context_type("NAME") is False
        assert is_clinical_context_type("SSN") is False

    def test_unknown_type_returns_false(self):
        """Returns False for unknown type."""
        assert is_clinical_context_type("UNKNOWN") is False

    def test_case_sensitive(self):
        """Function is case sensitive."""
        assert is_clinical_context_type("lab_test") is False
        assert is_clinical_context_type("LAB_TEST") is True


# =============================================================================
# SPAN DATACLASS TESTS
# =============================================================================

class TestSpan:
    """Tests for Span dataclass."""

    def test_create_valid_span(self):
        """Can create valid Span."""
        span = Span(
            start=0,
            end=4,
            text="John",
            entity_type="NAME",
            confidence=0.95,
            detector="pattern",
            tier=Tier.PATTERN,
        )

        assert span.start == 0
        assert span.end == 4
        assert span.text == "John"
        assert span.entity_type == "NAME"
        assert span.confidence == 0.95
        assert span.detector == "pattern"
        assert span.tier == Tier.PATTERN

    def test_optional_fields_default(self):
        """Optional fields have correct defaults."""
        span = Span(
            start=0, end=3, text="Bob",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )

        assert span.safe_harbor_value is None
        assert span.needs_review is False
        assert span.review_reason is None
        assert span.coref_anchor_value is None
        assert span.token is None

    def test_validates_negative_start(self):
        """Rejects negative start."""
        with pytest.raises(ValueError, match="cannot be negative"):
            Span(
                start=-1, end=4, text="John",
                entity_type="NAME", confidence=0.9,
                detector="ml", tier=Tier.ML,
            )

    def test_validates_start_equals_end(self):
        """Rejects start == end."""
        with pytest.raises(ValueError, match="start=0 >= end=0"):
            Span(
                start=0, end=0, text="",
                entity_type="NAME", confidence=0.9,
                detector="ml", tier=Tier.ML,
            )

    def test_validates_start_greater_than_end(self):
        """Rejects start > end."""
        with pytest.raises(ValueError, match="start=5 >= end=3"):
            Span(
                start=5, end=3, text="Jo",
                entity_type="NAME", confidence=0.9,
                detector="ml", tier=Tier.ML,
            )

    def test_validates_confidence_below_zero(self):
        """Rejects confidence < 0."""
        with pytest.raises(ValueError, match="Invalid confidence"):
            Span(
                start=0, end=4, text="John",
                entity_type="NAME", confidence=-0.1,
                detector="ml", tier=Tier.ML,
            )

    def test_validates_confidence_above_one(self):
        """Rejects confidence > 1."""
        with pytest.raises(ValueError, match="Invalid confidence"):
            Span(
                start=0, end=4, text="John",
                entity_type="NAME", confidence=1.5,
                detector="ml", tier=Tier.ML,
            )

    def test_validates_text_length(self):
        """Rejects text length mismatch."""
        with pytest.raises(ValueError, match="text length .* != span length"):
            Span(
                start=0, end=4, text="Jo",  # 2 chars, not 4
                entity_type="NAME", confidence=0.9,
                detector="ml", tier=Tier.ML,
            )

    def test_converts_int_tier_to_enum(self):
        """Converts int tier to Tier enum."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=2,  # int, not Tier
        )

        assert span.tier == Tier.PATTERN
        assert isinstance(span.tier, Tier)

    def test_warns_unknown_entity_type(self):
        """Warns on unknown entity type."""
        import logging

        with patch.object(logging, "getLogger") as mock_get_logger:
            mock_logger = mock_get_logger.return_value

            Span(
                start=0, end=4, text="test",
                entity_type="UNKNOWN_TYPE", confidence=0.9,
                detector="ml", tier=Tier.ML,
            )

            mock_logger.warning.assert_called_once()
            assert "Unknown entity type" in str(mock_logger.warning.call_args)

    def test_overlaps_true(self):
        """overlaps returns True for overlapping spans."""
        span1 = Span(
            start=0, end=10, text="0123456789",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )
        span2 = Span(
            start=5, end=15, text="5678901234",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )

        assert span1.overlaps(span2) is True
        assert span2.overlaps(span1) is True

    def test_overlaps_false_adjacent(self):
        """overlaps returns False for adjacent spans."""
        span1 = Span(
            start=0, end=5, text="01234",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )
        span2 = Span(
            start=5, end=10, text="56789",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )

        assert span1.overlaps(span2) is False

    def test_overlaps_false_separate(self):
        """overlaps returns False for separate spans."""
        span1 = Span(
            start=0, end=5, text="01234",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )
        span2 = Span(
            start=10, end=15, text="abcde",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )

        assert span1.overlaps(span2) is False

    def test_len_returns_span_length(self):
        """__len__ returns span length."""
        span = Span(
            start=5, end=15, text="0123456789",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )

        assert len(span) == 10

    def test_repr_does_not_expose_text(self):
        """__repr__ does not expose PHI text."""
        span = Span(
            start=0, end=8, text="John Doe",
            entity_type="NAME", confidence=0.95,
            detector="pattern", tier=Tier.PATTERN,
        )

        repr_str = repr(span)

        assert "John Doe" not in repr_str
        assert "start=0" in repr_str
        assert "end=8" in repr_str
        assert "NAME" in repr_str


# =============================================================================
# MENTION DATACLASS TESTS
# =============================================================================

class TestMention:
    """Tests for Mention dataclass."""

    def test_create_mention(self):
        """Can create Mention."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.95,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span, semantic_role="patient")

        assert mention.span is span
        assert mention.semantic_role == "patient"

    def test_defaults_confidence_from_span(self):
        """Confidence defaults from span."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span)

        assert mention.confidence == 0.85

    def test_defaults_source_from_span(self):
        """Source defaults from span detector."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.85,
            detector="pattern_detector", tier=Tier.PATTERN,
        )
        mention = Mention(span=span)

        assert mention.source == "pattern_detector"

    def test_validates_semantic_role(self):
        """Invalid semantic role defaults to unknown."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span, semantic_role="invalid_role")

        assert mention.semantic_role == "unknown"

    def test_valid_semantic_roles(self):
        """Valid semantic roles are preserved."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )

        for role in ["patient", "provider", "relative", "unknown"]:
            mention = Mention(span=span, semantic_role=role)
            assert mention.semantic_role == role

    def test_text_property(self):
        """text property returns span text."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span)

        assert mention.text == "John"

    def test_text_property_empty_span(self):
        """text property returns empty for None span."""
        mention = Mention(span=None)

        assert mention.text == ""

    def test_entity_type_property(self):
        """entity_type property returns base type."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span)

        assert mention.entity_type == "NAME"

    def test_entity_type_strips_patient_suffix(self):
        """entity_type strips _PATIENT suffix."""
        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME_PATIENT", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span)

        assert mention.entity_type == "NAME"

    def test_entity_type_strips_provider_suffix(self):
        """entity_type strips _PROVIDER suffix."""
        span = Span(
            start=0, end=8, text="Dr. Jane",
            entity_type="NAME_PROVIDER", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span)

        assert mention.entity_type == "NAME"

    def test_repr_safe(self):
        """__repr__ does not expose PHI."""
        span = Span(
            start=0, end=8, text="John Doe",
            entity_type="NAME", confidence=0.85,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span, semantic_role="patient")

        repr_str = repr(mention)

        assert "John Doe" not in repr_str
        assert "start=0" in repr_str
        assert "patient" in repr_str


# =============================================================================
# ENTITY DATACLASS TESTS
# =============================================================================

class TestEntity:
    """Tests for Entity dataclass."""

    def test_create_entity(self):
        """Can create Entity."""
        entity = Entity(
            id="uuid-123",
            entity_type="NAME",
            canonical_value="John Smith",
        )

        assert entity.id == "uuid-123"
        assert entity.entity_type == "NAME"
        assert entity.canonical_value == "John Smith"

    def test_default_mentions_empty(self):
        """Mentions default to empty list."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="Test")

        assert entity.mentions == []

    def test_default_token_none(self):
        """Token defaults to None."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="Test")

        assert entity.token is None

    def test_default_metadata_empty(self):
        """Metadata defaults to empty dict."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="Test")

        assert entity.metadata == {}

    def test_add_mention(self):
        """add_mention adds mention and sets entity_id."""
        entity = Entity(id="uuid-123", entity_type="NAME", canonical_value="John")

        span = Span(
            start=0, end=4, text="John",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span)

        entity.add_mention(mention)

        assert len(entity.mentions) == 1
        assert mention.entity_id == "uuid-123"

    def test_add_mention_updates_canonical(self):
        """add_mention updates canonical if mention is longer."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="John")

        span = Span(
            start=0, end=10, text="John Smith",
            entity_type="NAME", confidence=0.9,
            detector="ml", tier=Tier.ML,
        )
        mention = Mention(span=span)

        entity.add_mention(mention)

        assert entity.canonical_value == "John Smith"

    def test_all_values_property(self):
        """all_values returns all mention texts."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="John")

        span1 = Span(start=0, end=4, text="John", entity_type="NAME",
                     confidence=0.9, detector="ml", tier=Tier.ML)
        span2 = Span(start=0, end=2, text="JD", entity_type="NAME",
                     confidence=0.8, detector="ml", tier=Tier.ML)

        entity.add_mention(Mention(span=span1))
        entity.add_mention(Mention(span=span2))

        assert entity.all_values == ["John", "JD"]

    def test_roles_property(self):
        """roles returns all semantic roles."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="John")

        span = Span(start=0, end=4, text="John", entity_type="NAME",
                    confidence=0.9, detector="ml", tier=Tier.ML)

        entity.add_mention(Mention(span=span, semantic_role="patient"))
        entity.add_mention(Mention(span=span, semantic_role="provider"))

        assert entity.roles == {"patient", "provider"}

    def test_highest_confidence_property(self):
        """highest_confidence returns max confidence."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="John")

        span1 = Span(start=0, end=4, text="John", entity_type="NAME",
                     confidence=0.7, detector="ml", tier=Tier.ML)
        span2 = Span(start=0, end=4, text="John", entity_type="NAME",
                     confidence=0.95, detector="pattern", tier=Tier.PATTERN)

        entity.add_mention(Mention(span=span1))
        entity.add_mention(Mention(span=span2))

        assert entity.highest_confidence == 0.95

    def test_highest_confidence_empty(self):
        """highest_confidence returns 0 for no mentions."""
        entity = Entity(id="uuid", entity_type="NAME", canonical_value="John")

        assert entity.highest_confidence == 0.0

    def test_repr_safe(self):
        """__repr__ does not expose PHI."""
        entity = Entity(
            id="uuid-123",
            entity_type="NAME",
            canonical_value="John Smith",
            token="[NAME_1]",
        )

        repr_str = repr(entity)

        assert "John Smith" not in repr_str
        assert "uuid-123" in repr_str
        assert "NAME" in repr_str
        assert "[NAME_1]" in repr_str


# =============================================================================
# TOKENENTRY DATACLASS TESTS
# =============================================================================

class TestTokenEntry:
    """Tests for TokenEntry dataclass."""

    def test_create_token_entry(self):
        """Can create TokenEntry."""
        entry = TokenEntry(
            token="[NAME_1]",
            entity_type="NAME",
            original_value="John Doe",
            safe_harbor_value="Patient",
            session_id="sess-123",
        )

        assert entry.token == "[NAME_1]"
        assert entry.entity_type == "NAME"
        assert entry.original_value == "John Doe"
        assert entry.safe_harbor_value == "Patient"
        assert entry.session_id == "sess-123"

    def test_created_at_default(self):
        """created_at defaults to now."""
        before = datetime.now()
        entry = TokenEntry(
            token="[NAME_1]",
            entity_type="NAME",
            original_value="Test",
            safe_harbor_value="Test",
            session_id="sess",
        )
        after = datetime.now()

        assert before <= entry.created_at <= after

    def test_repr_safe(self):
        """__repr__ does not expose PHI."""
        entry = TokenEntry(
            token="[NAME_1]",
            entity_type="NAME",
            original_value="John Doe",  # PHI
            safe_harbor_value="Patient",  # Also sensitive
            session_id="sess-123",
        )

        repr_str = repr(entry)

        assert "John Doe" not in repr_str
        assert "Patient" not in repr_str
        assert "[NAME_1]" in repr_str
        assert "sess-123" in repr_str


# =============================================================================
# AUDITENTRY DATACLASS TESTS
# =============================================================================

class TestAuditEntry:
    """Tests for AuditEntry dataclass."""

    def test_create_audit_entry(self):
        """Can create AuditEntry."""
        now = datetime.now()
        entry = AuditEntry(
            sequence=1,
            event_type=AuditEventType.SESSION_START,
            timestamp=now,
            session_id="sess-123",
            data={"key": "value"},
            prev_hash="abc123",
            entry_hash="def456",
        )

        assert entry.sequence == 1
        assert entry.event_type == AuditEventType.SESSION_START
        assert entry.timestamp == now
        assert entry.session_id == "sess-123"
        assert entry.data == {"key": "value"}
        assert entry.prev_hash == "abc123"
        assert entry.entry_hash == "def456"


# =============================================================================
# REVIEWITEM DATACLASS TESTS
# =============================================================================

class TestReviewItem:
    """Tests for ReviewItem dataclass."""

    def test_create_review_item(self):
        """Can create ReviewItem."""
        item = ReviewItem(
            id="review-123",
            token="[PHONE_1]",
            entity_type="PHONE",
            confidence=0.75,
            reason=ReviewReason.LOW_CONFIDENCE,
            context="Call [PHONE_1] for info",
            suggested_action="approve",
        )

        assert item.id == "review-123"
        assert item.token == "[PHONE_1]"
        assert item.entity_type == "PHONE"
        assert item.confidence == 0.75
        assert item.reason == ReviewReason.LOW_CONFIDENCE
        assert item.suggested_action == "approve"

    def test_default_values(self):
        """Default values are correct."""
        item = ReviewItem(
            id="id",
            token="[T]",
            entity_type="TYPE",
            confidence=0.5,
            reason=ReviewReason.ML_ONLY,
            context="ctx",
            suggested_action="reject",
        )

        assert item.decision is None
        assert item.decided_at is None
        assert isinstance(item.created_at, datetime)


# =============================================================================
# UPLOADRESULT DATACLASS TESTS
# =============================================================================

class TestUploadResult:
    """Tests for UploadResult dataclass."""

    def test_create_upload_result(self):
        """Can create UploadResult."""
        result = UploadResult(
            job_id="job-123",
            filename="test.pdf",
            original_text="Original content",
            redacted_text="[NAME_1] content",
            spans=[],
        )

        assert result.job_id == "job-123"
        assert result.filename == "test.pdf"
        assert result.original_text == "Original content"
        assert result.redacted_text == "[NAME_1] content"

    def test_default_values(self):
        """Default values are correct."""
        result = UploadResult(
            job_id="job",
            filename="f.txt",
            original_text="t",
            redacted_text="t",
            spans=[],
        )

        assert result.pages == 1
        assert result.processing_time_ms == 0.0
        assert isinstance(result.created_at, datetime)


# =============================================================================
# REDACTIONRESULT DATACLASS TESTS
# =============================================================================

class TestRedactionResult:
    """Tests for RedactionResult dataclass."""

    def test_create_redaction_result(self):
        """Can create RedactionResult."""
        result = RedactionResult(
            redacted="[NAME_1] said hello",
            spans=[],
            tokens_created=["[NAME_1]"],
            needs_review=[],
            processing_time_ms=50.5,
        )

        assert result.redacted == "[NAME_1] said hello"
        assert result.tokens_created == ["[NAME_1]"]
        assert result.processing_time_ms == 50.5

    def test_default_values(self):
        """Default values are correct."""
        result = RedactionResult(
            redacted="text",
            spans=[],
            tokens_created=[],
            needs_review=[],
            processing_time_ms=10.0,
        )

        assert result.input_hash == ""
        assert result.normalized_input == ""

    def test_repr_safe(self):
        """__repr__ does not expose normalized_input (which may contain PHI)."""
        result = RedactionResult(
            redacted="[NAME_1] said hello",
            spans=[],
            tokens_created=["[NAME_1]"],
            needs_review=[],
            processing_time_ms=50.5,
            normalized_input="John said hello",  # This is PHI
        )

        repr_str = repr(result)

        assert "John said hello" not in repr_str
        assert "chars" in repr_str


# =============================================================================
# RESTORATIONRESULT DATACLASS TESTS
# =============================================================================

class TestRestorationResult:
    """Tests for RestorationResult dataclass."""

    def test_create_restoration_result(self):
        """Can create RestorationResult."""
        result = RestorationResult(
            original="[NAME_1] said hello",
            restored="John said hello",
            tokens_found=["[NAME_1]"],
            tokens_unknown=[],
        )

        assert result.original == "[NAME_1] said hello"
        assert result.restored == "John said hello"
        assert result.tokens_found == ["[NAME_1]"]
        assert result.tokens_unknown == []

    def test_repr_safe(self):
        """__repr__ does not expose PHI in restored text."""
        result = RestorationResult(
            original="[NAME_1] said hello",
            restored="John Doe said hello",  # PHI
            tokens_found=["[NAME_1]"],
            tokens_unknown=[],
        )

        repr_str = repr(result)

        assert "John Doe" not in repr_str
        assert "chars" in repr_str


# =============================================================================
# CHATRESULT DATACLASS TESTS
# =============================================================================

class TestChatResult:
    """Tests for ChatResult dataclass."""

    def test_create_chat_result(self):
        """Can create ChatResult."""
        result = ChatResult(
            request_text="Hello John",
            redacted_request="Hello [NAME_1]",
            response_text="Hi there",
            restored_response="Hi there",
            model="claude-3",
            provider="anthropic",
            tokens_used=100,
            latency_ms=500.0,
            spans=[],
        )

        assert result.request_text == "Hello John"
        assert result.model == "claude-3"
        assert result.tokens_used == 100

    def test_default_values(self):
        """Default values are correct."""
        result = ChatResult(
            request_text="req",
            redacted_request="req",
            response_text="resp",
            restored_response="resp",
            model="m",
            provider="p",
            tokens_used=0,
            latency_ms=0.0,
            spans=[],
        )

        assert result.conversation_id is None
        assert result.error is None
        assert result.normalized_input == ""

    def test_repr_safe(self):
        """__repr__ does not expose PHI in request/response text."""
        result = ChatResult(
            request_text="Hello John Doe",  # PHI
            redacted_request="Hello [NAME_1]",
            response_text="Hi John",  # PHI
            restored_response="Hi John",
            model="claude-3",
            provider="anthropic",
            tokens_used=100,
            latency_ms=500.0,
            spans=[],
        )

        repr_str = repr(result)

        assert "John Doe" not in repr_str
        assert "claude-3" in repr_str
        assert "anthropic" in repr_str


# =============================================================================
# MODULE EXPORTS TESTS
# =============================================================================

class TestModuleExports:
    """Tests for module __all__ exports."""

    def test_all_exports_importable(self):
        """All __all__ exports are importable."""
        from scrubiq import types

        for name in types.__all__:
            assert hasattr(types, name)

    def test_expected_enums_exported(self):
        """Expected enums are exported."""
        from scrubiq import types

        assert "Tier" in types.__all__
        assert "PrivacyMode" in types.__all__
        assert "ReviewReason" in types.__all__
        assert "AuditEventType" in types.__all__

    def test_expected_dataclasses_exported(self):
        """Expected dataclasses are exported."""
        from scrubiq import types

        expected = [
            "Span", "Mention", "Entity", "TokenEntry",
            "AuditEntry", "ReviewItem", "UploadResult",
            "RedactionResult", "RestorationResult", "ChatResult",
        ]

        for name in expected:
            assert name in types.__all__

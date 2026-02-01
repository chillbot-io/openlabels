"""Tests for SDK module.

Tests for Redactor, RedactorConfig, result types, and module-level functions.
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Set up environment for testing
os.environ["SCRUBIQ_ALLOW_UNENCRYPTED_DB"] = "true"

# Pre-mock the storage module tree to avoid SQLCipher requirement
# This must be done before any scrubiq imports
_mock_storage = MagicMock()
_mock_storage.Database = MagicMock()
_mock_storage.TokenStore = MagicMock()
_mock_storage.ImageFileType = MagicMock()

_mock_tokens = MagicMock()
_mock_tokens.TokenStore = MagicMock()

_mock_database = MagicMock()
_mock_database.Database = MagicMock()

_mock_audit = MagicMock()
_mock_audit.AuditLog = MagicMock()

_mock_images = MagicMock()
_mock_images.ImageStore = MagicMock()

_mock_conversations = MagicMock()
_mock_conversations.ConversationStore = MagicMock()

_mock_memory = MagicMock()
_mock_memory.MemoryStore = MagicMock()

# Patch all storage submodules
for mod_name, mock_mod in [
    ("scrubiq.storage", _mock_storage),
    ("scrubiq.storage.tokens", _mock_tokens),
    ("scrubiq.storage.database", _mock_database),
    ("scrubiq.storage.audit", _mock_audit),
    ("scrubiq.storage.images", _mock_images),
    ("scrubiq.storage.conversations", _mock_conversations),
    ("scrubiq.storage.memory", _mock_memory),
]:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = mock_mod

# Import core module to make it available for patching
import scrubiq.core


# =============================================================================
# ENVIRONMENT HELPER TESTS
# =============================================================================

class TestEnvBool:
    """Tests for _env_bool() helper."""

    def test_true_values(self):
        """True values are recognized."""
        from scrubiq.sdk import _env_bool

        for val in ("1", "true", "TRUE", "yes", "YES", "on", "ON"):
            with patch.dict(os.environ, {"TEST_KEY": val}):
                assert _env_bool("TEST_KEY") is True

    def test_false_values(self):
        """False values are recognized."""
        from scrubiq.sdk import _env_bool

        for val in ("0", "false", "FALSE", "no", "NO", "off", "OFF"):
            with patch.dict(os.environ, {"TEST_KEY": val}):
                assert _env_bool("TEST_KEY") is False

    def test_unset_returns_default(self):
        """Unset variable returns default."""
        from scrubiq.sdk import _env_bool

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("TEST_KEY_UNSET", None)
            assert _env_bool("TEST_KEY_UNSET") is False
            assert _env_bool("TEST_KEY_UNSET", True) is True

    def test_invalid_value_returns_default(self):
        """Invalid value returns default."""
        from scrubiq.sdk import _env_bool

        with patch.dict(os.environ, {"TEST_KEY": "maybe"}):
            assert _env_bool("TEST_KEY") is False
            assert _env_bool("TEST_KEY", True) is True


class TestEnvFloat:
    """Tests for _env_float() helper."""

    def test_valid_float(self):
        """Valid float is parsed."""
        from scrubiq.sdk import _env_float

        with patch.dict(os.environ, {"TEST_KEY": "0.85"}):
            assert _env_float("TEST_KEY", 0.5) == 0.85

    def test_integer_as_float(self):
        """Integer is converted to float."""
        from scrubiq.sdk import _env_float

        with patch.dict(os.environ, {"TEST_KEY": "1"}):
            assert _env_float("TEST_KEY", 0.5) == 1.0

    def test_unset_returns_default(self):
        """Unset variable returns default."""
        from scrubiq.sdk import _env_float

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("TEST_KEY_UNSET", None)
            assert _env_float("TEST_KEY_UNSET", 0.85) == 0.85

    def test_invalid_value_returns_default(self):
        """Invalid value returns default."""
        from scrubiq.sdk import _env_float

        with patch.dict(os.environ, {"TEST_KEY": "not_a_number"}):
            assert _env_float("TEST_KEY", 0.85) == 0.85


class TestEnvInt:
    """Tests for _env_int() helper."""

    def test_valid_int(self):
        """Valid integer is parsed."""
        from scrubiq.sdk import _env_int

        with patch.dict(os.environ, {"TEST_KEY": "42"}):
            assert _env_int("TEST_KEY", 1) == 42

    def test_unset_returns_default(self):
        """Unset variable returns default."""
        from scrubiq.sdk import _env_int

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("TEST_KEY_UNSET", None)
            assert _env_int("TEST_KEY_UNSET", 4) == 4

    def test_invalid_value_returns_default(self):
        """Invalid value returns default."""
        from scrubiq.sdk import _env_int

        with patch.dict(os.environ, {"TEST_KEY": "not_int"}):
            assert _env_int("TEST_KEY", 4) == 4

    def test_float_string_returns_default(self):
        """Float string returns default (can't convert to int)."""
        from scrubiq.sdk import _env_int

        with patch.dict(os.environ, {"TEST_KEY": "4.5"}):
            assert _env_int("TEST_KEY", 4) == 4


class TestEnvList:
    """Tests for _env_list() helper."""

    def test_comma_separated_list(self):
        """Comma-separated values are parsed."""
        from scrubiq.sdk import _env_list

        with patch.dict(os.environ, {"TEST_KEY": "a,b,c"}):
            assert _env_list("TEST_KEY") == ["a", "b", "c"]

    def test_strips_whitespace(self):
        """Whitespace is stripped from items."""
        from scrubiq.sdk import _env_list

        with patch.dict(os.environ, {"TEST_KEY": " a , b , c "}):
            assert _env_list("TEST_KEY") == ["a", "b", "c"]

    def test_empty_items_filtered(self):
        """Empty items are filtered."""
        from scrubiq.sdk import _env_list

        with patch.dict(os.environ, {"TEST_KEY": "a,,b,  ,c"}):
            assert _env_list("TEST_KEY") == ["a", "b", "c"]

    def test_unset_returns_default(self):
        """Unset variable returns default."""
        from scrubiq.sdk import _env_list

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("TEST_KEY_UNSET", None)
            assert _env_list("TEST_KEY_UNSET") is None
            assert _env_list("TEST_KEY_UNSET", ["default"]) == ["default"]


# =============================================================================
# REDACTORCONFIG TESTS
# =============================================================================

class TestRedactorConfig:
    """Tests for RedactorConfig dataclass."""

    def test_default_values(self):
        """Default values are set correctly."""
        from scrubiq.sdk import RedactorConfig

        config = RedactorConfig()

        assert config.confidence_threshold == 0.85
        assert config.thresholds is None
        assert config.entity_types is None
        assert config.exclude_types is None
        assert config.allowlist is None
        assert config.allowlist_file is None
        assert config.patterns is None
        assert config.safe_harbor is True
        assert config.coreference is True
        assert config.device == "auto"
        assert config.workers == 1
        assert config.review_threshold == 0.7

    def test_custom_values(self):
        """Custom values can be set."""
        from scrubiq.sdk import RedactorConfig

        config = RedactorConfig(
            confidence_threshold=0.9,
            thresholds={"NAME": 0.7},
            entity_types=["NAME", "SSN"],
            exclude_types=["EMAIL"],
            allowlist=["Mayo Clinic"],
            patterns={"MRN": r"MRN-\d+"},
            safe_harbor=False,
            coreference=False,
            device="cuda",
            workers=4,
            review_threshold=0.5,
        )

        assert config.confidence_threshold == 0.9
        assert config.thresholds == {"NAME": 0.7}
        assert config.entity_types == ["NAME", "SSN"]
        assert config.exclude_types == ["EMAIL"]
        assert config.allowlist == ["Mayo Clinic"]
        assert config.patterns == {"MRN": r"MRN-\d+"}
        assert config.safe_harbor is False
        assert config.coreference is False
        assert config.device == "cuda"
        assert config.workers == 4
        assert config.review_threshold == 0.5

    def test_from_env_defaults(self):
        """from_env() with no env vars uses defaults."""
        from scrubiq.sdk import RedactorConfig

        # Clear relevant env vars
        env_vars = {
            k: v for k, v in os.environ.items()
            if not k.startswith("SCRUBIQ_") or k == "SCRUBIQ_ALLOW_UNENCRYPTED_DB"
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = RedactorConfig.from_env()

            assert config.confidence_threshold == 0.85
            assert config.safe_harbor is True
            assert config.coreference is True
            assert config.device == "auto"
            assert config.workers == 1

    def test_from_env_overrides(self):
        """from_env() picks up environment variables."""
        from scrubiq.sdk import RedactorConfig

        with patch.dict(os.environ, {
            "SCRUBIQ_THRESHOLD": "0.9",
            "SCRUBIQ_SAFE_HARBOR": "false",
            "SCRUBIQ_COREFERENCE": "false",
            "SCRUBIQ_DEVICE": "cpu",
            "SCRUBIQ_WORKERS": "8",
            "SCRUBIQ_REVIEW_THRESHOLD": "0.5",
            "SCRUBIQ_ALLOWLIST": "Mayo Clinic,Tylenol",
            "SCRUBIQ_ENTITY_TYPES": "NAME,SSN",
            "SCRUBIQ_EXCLUDE_TYPES": "EMAIL",
        }):
            config = RedactorConfig.from_env()

            assert config.confidence_threshold == 0.9
            assert config.safe_harbor is False
            assert config.coreference is False
            assert config.device == "cpu"
            assert config.workers == 8
            assert config.review_threshold == 0.5
            assert config.allowlist == ["Mayo Clinic", "Tylenol"]
            assert config.entity_types == ["NAME", "SSN"]
            assert config.exclude_types == ["EMAIL"]


# =============================================================================
# ENTITY TESTS
# =============================================================================

class TestEntity:
    """Tests for Entity dataclass."""

    def test_default_values(self):
        """Entity has correct defaults."""
        from scrubiq.sdk import Entity

        entity = Entity(text="John", type="NAME", confidence=0.95)

        assert entity.text == "John"
        assert entity.type == "NAME"
        assert entity.confidence == 0.95
        assert entity.token is None
        assert entity.start == 0
        assert entity.end == 0
        assert entity.detector == ""

    def test_all_values(self):
        """Entity can be created with all values."""
        from scrubiq.sdk import Entity

        entity = Entity(
            text="John Smith",
            type="NAME",
            confidence=0.95,
            token="[NAME_1]",
            start=10,
            end=20,
            detector="ner_model",
        )

        assert entity.text == "John Smith"
        assert entity.type == "NAME"
        assert entity.confidence == 0.95
        assert entity.token == "[NAME_1]"
        assert entity.start == 10
        assert entity.end == 20
        assert entity.detector == "ner_model"

    def test_entity_type_property(self):
        """entity_type property returns type."""
        from scrubiq.sdk import Entity

        entity = Entity(text="John", type="NAME", confidence=0.9)
        assert entity.entity_type == "NAME"

    def test_to_dict(self):
        """to_dict() serializes entity."""
        from scrubiq.sdk import Entity

        entity = Entity(
            text="John",
            type="NAME",
            confidence=0.95,
            token="[NAME_1]",
            start=0,
            end=4,
            detector="test",
        )

        d = entity.to_dict()

        assert d["text"] == "John"
        assert d["type"] == "NAME"
        assert d["confidence"] == 0.95
        assert d["token"] == "[NAME_1]"
        assert d["start"] == 0
        assert d["end"] == 4
        assert d["detector"] == "test"

    def test_repr(self):
        """repr() shows useful info."""
        from scrubiq.sdk import Entity

        entity = Entity(text="John", type="NAME", confidence=0.95)
        r = repr(entity)

        assert "Entity" in r
        assert "NAME" in r
        assert "John" in r
        assert "95%" in r

    def test_from_span(self):
        """from_span() creates Entity from Span."""
        from scrubiq.sdk import Entity
        from scrubiq.types import Span, Tier

        span = Span(
            start=0,
            end=4,
            text="John",
            entity_type="NAME",
            confidence=0.95,
            detector="ner",
            tier=Tier.ML,
            token="[NAME_1]",
        )

        entity = Entity.from_span(span)

        assert entity.text == "John"
        assert entity.type == "NAME"
        assert entity.confidence == 0.95
        assert entity.token == "[NAME_1]"
        assert entity.start == 0
        assert entity.end == 4
        assert entity.detector == "ner"


# =============================================================================
# REVIEW ITEM TESTS
# =============================================================================

class TestReviewItem:
    """Tests for ReviewItem dataclass."""

    def test_creation(self):
        """ReviewItem can be created."""
        from scrubiq.sdk import ReviewItem

        item = ReviewItem(
            id="rev_123",
            token="[NAME_1]",
            type="NAME",
            confidence=0.6,
            reason="low_confidence",
            context="Patient [NAME_1] was seen...",
            suggested_action="review",
        )

        assert item.id == "rev_123"
        assert item.token == "[NAME_1]"
        assert item.type == "NAME"
        assert item.confidence == 0.6
        assert item.reason == "low_confidence"
        assert item.context == "Patient [NAME_1] was seen..."
        assert item.suggested_action == "review"

    def test_to_dict(self):
        """to_dict() serializes review item."""
        from scrubiq.sdk import ReviewItem

        item = ReviewItem(
            id="rev_123",
            token="[NAME_1]",
            type="NAME",
            confidence=0.6,
            reason="low_confidence",
            context="...",
            suggested_action="review",
        )

        d = item.to_dict()

        assert d["id"] == "rev_123"
        assert d["token"] == "[NAME_1]"
        assert d["type"] == "NAME"
        assert d["confidence"] == 0.6
        assert d["reason"] == "low_confidence"
        assert d["suggested_action"] == "review"


# =============================================================================
# REDACTION RESULT TESTS
# =============================================================================

class TestRedactionResult:
    """Tests for RedactionResult class."""

    @pytest.fixture
    def sample_result(self):
        """Create a sample RedactionResult."""
        from scrubiq.sdk import RedactionResult, Entity

        entities = [
            Entity(text="John", type="NAME", confidence=0.95, token="[NAME_1]"),
            Entity(text="123-45-6789", type="SSN", confidence=0.99, token="[SSN_1]"),
        ]

        return RedactionResult(
            text="Patient [NAME_1], SSN [SSN_1]",
            entities=entities,
            tokens=["[NAME_1]", "[SSN_1]"],
            needs_review=[],
            stats={"time_ms": 10.5, "entities_found": 2},
            _mapping={"[NAME_1]": "John", "[SSN_1]": "123-45-6789"},
        )

    # --- String-like behavior ---

    def test_str(self, sample_result):
        """str() returns redacted text."""
        assert str(sample_result) == "Patient [NAME_1], SSN [SSN_1]"

    def test_len(self, sample_result):
        """len() returns text length."""
        assert len(sample_result) == len("Patient [NAME_1], SSN [SSN_1]")

    def test_contains(self, sample_result):
        """in operator checks text."""
        assert "[NAME_1]" in sample_result
        assert "[SSN_1]" in sample_result
        assert "John" not in sample_result

    def test_iter(self, sample_result):
        """Iteration yields characters."""
        chars = list(sample_result)
        assert chars[0] == "P"
        assert len(chars) == len(sample_result)

    def test_eq_string(self, sample_result):
        """Equality with string."""
        assert sample_result == "Patient [NAME_1], SSN [SSN_1]"
        assert sample_result != "different"

    def test_eq_result(self, sample_result):
        """Equality with another RedactionResult."""
        from scrubiq.sdk import RedactionResult

        other = RedactionResult(
            text="Patient [NAME_1], SSN [SSN_1]",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        assert sample_result == other

    def test_hash(self, sample_result):
        """Hash based on text."""
        assert hash(sample_result) == hash("Patient [NAME_1], SSN [SSN_1]")

    def test_add(self, sample_result):
        """Concatenation with +."""
        result = sample_result + " more text"
        assert result == "Patient [NAME_1], SSN [SSN_1] more text"

    def test_radd(self, sample_result):
        """Reverse concatenation."""
        result = "prefix: " + sample_result
        assert result == "prefix: Patient [NAME_1], SSN [SSN_1]"

    def test_repr(self, sample_result):
        """repr() shows preview."""
        r = repr(sample_result)
        assert "RedactionResult" in r
        assert "entities=2" in r

    def test_repr_long_text(self):
        """repr() truncates long text."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="a" * 100,
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        r = repr(result)
        assert "..." in r

    # --- Properties ---

    def test_text_property(self, sample_result):
        """text property returns redacted text."""
        assert sample_result.text == "Patient [NAME_1], SSN [SSN_1]"

    def test_redacted_property(self, sample_result):
        """redacted property is alias for text."""
        assert sample_result.redacted == sample_result.text

    def test_entities_property(self, sample_result):
        """entities property returns list."""
        assert len(sample_result.entities) == 2
        assert sample_result.entities[0].type == "NAME"

    def test_spans_property(self, sample_result):
        """spans property is alias for entities."""
        assert sample_result.spans == sample_result.entities

    def test_tokens_property(self, sample_result):
        """tokens property returns token list."""
        assert sample_result.tokens == ["[NAME_1]", "[SSN_1]"]

    def test_has_phi(self, sample_result):
        """has_phi is True when entities exist."""
        assert sample_result.has_phi is True

    def test_has_phi_empty(self):
        """has_phi is False when no entities."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="no phi here",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
        )

        assert result.has_phi is False

    def test_needs_review_property(self, sample_result):
        """needs_review returns review items."""
        assert sample_result.needs_review == []

    def test_stats_property(self, sample_result):
        """stats property returns stats dict."""
        assert sample_result.stats["time_ms"] == 10.5
        assert sample_result.stats["entities_found"] == 2

    def test_mapping_property_security(self, sample_result):
        """mapping property doesn't expose raw PHI."""
        mapping = sample_result.mapping

        # Should have token keys but not raw PHI values
        assert "[NAME_1]" in mapping
        assert "John" not in str(mapping)
        assert "[REDACTED:" in mapping["[NAME_1]"]

    def test_error_property(self):
        """error property returns error."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
            error="Something failed",
        )

        assert result.error == "Something failed"

    def test_warning_property(self):
        """warning property returns warning."""
        from scrubiq.sdk import RedactionResult

        result = RedactionResult(
            text="",
            entities=[],
            tokens=[],
            needs_review=[],
            stats={},
            warning="Empty input",
        )

        assert result.warning == "Empty input"

    def test_entity_types_property(self, sample_result):
        """entity_types returns set of types."""
        types = sample_result.entity_types

        assert isinstance(types, set)
        assert "NAME" in types
        assert "SSN" in types

    # --- Methods ---

    def test_restore_with_mapping(self, sample_result):
        """restore() uses internal mapping."""
        # Without a _redactor, falls back to mapping
        sample_result._redactor = None
        restored = sample_result.restore()

        assert "John" in restored
        assert "123-45-6789" in restored
        assert "[NAME_1]" not in restored

    def test_to_dict(self, sample_result):
        """to_dict() serializes result."""
        d = sample_result.to_dict()

        assert d["text"] == "Patient [NAME_1], SSN [SSN_1]"
        assert len(d["entities"]) == 2
        assert d["tokens"] == ["[NAME_1]", "[SSN_1]"]
        assert d["has_phi"] is True
        assert d["token_count"] == 2
        assert "stats" in d

    def test_to_json(self, sample_result):
        """to_json() returns valid JSON."""
        j = sample_result.to_json()

        # Should be valid JSON
        parsed = json.loads(j)
        assert parsed["text"] == "Patient [NAME_1], SSN [SSN_1]"


# =============================================================================
# SCAN RESULT TESTS
# =============================================================================

class TestScanResult:
    """Tests for ScanResult class."""

    @pytest.fixture
    def sample_scan(self):
        """Create a sample ScanResult."""
        from scrubiq.sdk import ScanResult, Entity

        entities = [
            Entity(text="John", type="NAME", confidence=0.95),
            Entity(text="123-45-6789", type="SSN", confidence=0.99),
        ]

        return ScanResult(
            entities=entities,
            stats={"time_ms": 5.0, "entities_found": 2},
        )

    def test_has_phi(self, sample_scan):
        """has_phi is True when entities found."""
        assert sample_scan.has_phi is True

    def test_has_phi_empty(self):
        """has_phi is False when no entities."""
        from scrubiq.sdk import ScanResult

        result = ScanResult(entities=[], stats={})
        assert result.has_phi is False

    def test_entities_property(self, sample_scan):
        """entities property returns list."""
        assert len(sample_scan.entities) == 2

    def test_spans_alias(self, sample_scan):
        """spans is alias for entities."""
        assert sample_scan.spans == sample_scan.entities

    def test_entity_types(self, sample_scan):
        """entity_types returns set."""
        types = sample_scan.entity_types

        assert "NAME" in types
        assert "SSN" in types

    def test_types_found_alias(self, sample_scan):
        """types_found is alias for entity_types."""
        assert sample_scan.types_found == sample_scan.entity_types

    def test_stats_property(self, sample_scan):
        """stats property returns stats."""
        assert sample_scan.stats["time_ms"] == 5.0

    def test_error_property(self):
        """error property returns error."""
        from scrubiq.sdk import ScanResult

        result = ScanResult(entities=[], stats={}, error="Failed")
        assert result.error == "Failed"

    def test_warning_property(self):
        """warning property returns warning."""
        from scrubiq.sdk import ScanResult

        result = ScanResult(entities=[], stats={}, warning="Empty input")
        assert result.warning == "Empty input"

    def test_to_dict(self, sample_scan):
        """to_dict() serializes result."""
        d = sample_scan.to_dict()

        assert d["has_phi"] is True
        assert len(d["entities"]) == 2
        assert d["entity_types"] == ["NAME", "SSN"] or set(d["entity_types"]) == {"NAME", "SSN"}
        assert "stats" in d

    def test_to_json(self, sample_scan):
        """to_json() returns valid JSON."""
        j = sample_scan.to_json()
        parsed = json.loads(j)

        assert parsed["has_phi"] is True

    def test_repr(self, sample_scan):
        """repr() shows info."""
        r = repr(sample_scan)

        assert "ScanResult" in r
        assert "has_phi=True" in r
        assert "entities=2" in r

    def test_bool_truthy(self, sample_scan):
        """ScanResult is truthy when has PHI."""
        assert bool(sample_scan) is True

    def test_bool_falsy(self):
        """ScanResult is falsy when no PHI."""
        from scrubiq.sdk import ScanResult

        result = ScanResult(entities=[], stats={})
        assert bool(result) is False


# =============================================================================
# CHAT RESULT TESTS
# =============================================================================

class TestChatResult:
    """Tests for ChatResult dataclass."""

    def test_creation(self):
        """ChatResult can be created."""
        from scrubiq.sdk import ChatResult, Entity

        result = ChatResult(
            response="The patient John Smith takes aspirin.",
            redacted_prompt="What medications does [NAME_1] take?",
            redacted_response="[NAME_1] takes aspirin.",
            model="claude-3-sonnet",
            provider="anthropic",
            tokens_used=150,
            latency_ms=500.0,
            entities=[Entity(text="John Smith", type="NAME", confidence=0.95)],
            conversation_id="conv_123",
        )

        assert result.response == "The patient John Smith takes aspirin."
        assert result.model == "claude-3-sonnet"
        assert result.tokens_used == 150
        assert len(result.entities) == 1

    def test_spans_alias(self):
        """spans is alias for entities."""
        from scrubiq.sdk import ChatResult, Entity

        entities = [Entity(text="test", type="NAME", confidence=0.9)]
        result = ChatResult(
            response="", redacted_prompt="", redacted_response="",
            model="", provider="", tokens_used=0, latency_ms=0,
            entities=entities,
        )

        assert result.spans == result.entities

    def test_to_dict(self):
        """to_dict() serializes result."""
        from scrubiq.sdk import ChatResult

        result = ChatResult(
            response="response",
            redacted_prompt="prompt",
            redacted_response="redacted",
            model="model",
            provider="provider",
            tokens_used=100,
            latency_ms=50.0,
            entities=[],
            error="none",
        )

        d = result.to_dict()

        assert d["response"] == "response"
        assert d["model"] == "model"
        assert d["tokens_used"] == 100

    def test_to_json(self):
        """to_json() returns valid JSON."""
        from scrubiq.sdk import ChatResult

        result = ChatResult(
            response="r", redacted_prompt="p", redacted_response="rr",
            model="m", provider="p", tokens_used=1, latency_ms=1.0,
            entities=[],
        )

        j = result.to_json()
        parsed = json.loads(j)
        assert parsed["response"] == "r"

    def test_repr(self):
        """repr() shows info."""
        from scrubiq.sdk import ChatResult

        result = ChatResult(
            response="r", redacted_prompt="p", redacted_response="rr",
            model="claude-3", provider="p", tokens_used=100, latency_ms=1.0,
            entities=[],
        )

        r = repr(result)
        assert "ChatResult" in r
        assert "claude-3" in r
        assert "100" in r


# =============================================================================
# FILE RESULT TESTS
# =============================================================================

class TestFileResult:
    """Tests for FileResult dataclass."""

    def test_creation(self):
        """FileResult can be created."""
        from scrubiq.sdk import FileResult, Entity

        result = FileResult(
            text="Redacted document content",
            entities=[Entity(text="John", type="NAME", confidence=0.9)],
            tokens=["[NAME_1]"],
            pages=5,
            job_id="job_123",
            filename="document.pdf",
        )

        assert result.text == "Redacted document content"
        assert result.pages == 5
        assert result.job_id == "job_123"
        assert result.filename == "document.pdf"

    def test_has_phi(self):
        """has_phi is True when entities exist."""
        from scrubiq.sdk import FileResult, Entity

        result = FileResult(
            text="",
            entities=[Entity(text="test", type="NAME", confidence=0.9)],
            tokens=[],
            pages=1,
            job_id="",
            filename="",
        )

        assert result.has_phi is True

    def test_has_phi_false(self):
        """has_phi is False when no entities."""
        from scrubiq.sdk import FileResult

        result = FileResult(
            text="",
            entities=[],
            tokens=[],
            pages=1,
            job_id="",
            filename="",
        )

        assert result.has_phi is False

    def test_spans_alias(self):
        """spans is alias for entities."""
        from scrubiq.sdk import FileResult, Entity

        entities = [Entity(text="test", type="NAME", confidence=0.9)]
        result = FileResult(
            text="", entities=entities, tokens=[], pages=1,
            job_id="", filename="",
        )

        assert result.spans == result.entities

    def test_to_dict(self):
        """to_dict() serializes result."""
        from scrubiq.sdk import FileResult

        result = FileResult(
            text="content",
            entities=[],
            tokens=["[NAME_1]"],
            pages=3,
            job_id="job_1",
            filename="test.pdf",
            stats={"time_ms": 100},
            error=None,
        )

        d = result.to_dict()

        assert d["text"] == "content"
        assert d["pages"] == 3
        assert d["job_id"] == "job_1"
        assert d["filename"] == "test.pdf"

    def test_to_json(self):
        """to_json() returns valid JSON."""
        from scrubiq.sdk import FileResult

        result = FileResult(
            text="t", entities=[], tokens=[], pages=1,
            job_id="j", filename="f",
        )

        j = result.to_json()
        parsed = json.loads(j)
        assert parsed["text"] == "t"


# =============================================================================
# TOKENS INTERFACE TESTS
# =============================================================================

class TestTokensInterface:
    """Tests for TokensInterface."""

    @pytest.fixture
    def mock_tokens_interface(self):
        """Create a mock TokensInterface with token methods."""
        from scrubiq.sdk import TokensInterface

        redactor = MagicMock()
        redactor._cr.get_tokens.return_value = [
            {"token": "[NAME_1]", "type": "NAME", "original": "John"},
            {"token": "[SSN_1]", "type": "SSN", "original": "123-45-6789"},
        ]
        redactor._cr.get_token_count.return_value = 2

        return TokensInterface(redactor)

    def test_iter(self, mock_tokens_interface):
        """Iteration yields token strings."""
        tokens = list(mock_tokens_interface)

        assert "[NAME_1]" in tokens
        assert "[SSN_1]" in tokens

    def test_len(self, mock_tokens_interface):
        """len() returns token count."""
        assert len(mock_tokens_interface) == 2

    def test_contains(self, mock_tokens_interface):
        """in operator checks token existence."""
        assert "[NAME_1]" in mock_tokens_interface
        assert "[UNKNOWN]" not in mock_tokens_interface

    def test_list(self, mock_tokens_interface):
        """list() returns all token strings."""
        tokens = mock_tokens_interface.list()

        assert tokens == ["[NAME_1]", "[SSN_1]"]

    def test_count_property(self, mock_tokens_interface):
        """count property returns count."""
        assert mock_tokens_interface.count == 2

    def test_lookup_found(self, mock_tokens_interface):
        """lookup() returns token info when found."""
        info = mock_tokens_interface.lookup("[NAME_1]")

        assert info is not None
        assert info["token"] == "[NAME_1]"
        assert info["type"] == "NAME"

    def test_lookup_not_found(self, mock_tokens_interface):
        """lookup() returns None when not found."""
        info = mock_tokens_interface.lookup("[UNKNOWN]")

        assert info is None

    def test_delete(self, mock_tokens_interface):
        """delete() calls redactor method."""
        mock_tokens_interface._redactor._cr.delete_token.return_value = True

        result = mock_tokens_interface.delete("[NAME_1]")

        assert result is True
        mock_tokens_interface._redactor._cr.delete_token.assert_called_once_with("[NAME_1]")

    def test_clear(self, mock_tokens_interface):
        """clear() returns count and creates new conversation."""
        mock_tokens_interface._redactor._cr.create_conversation = MagicMock()

        count = mock_tokens_interface.clear()

        assert count == 2
        mock_tokens_interface._redactor._cr.create_conversation.assert_called_once()

    def test_map(self, mock_tokens_interface):
        """map() returns token to original mapping."""
        mapping = mock_tokens_interface.map()

        assert mapping["[NAME_1]"] == "John"
        assert mapping["[SSN_1]"] == "123-45-6789"

    def test_entities(self, mock_tokens_interface):
        """entities() returns Entity objects."""
        from scrubiq.sdk import Entity

        entities = mock_tokens_interface.entities()

        assert len(entities) == 2
        assert all(isinstance(e, Entity) for e in entities)
        assert entities[0].text == "John"
        assert entities[0].type == "NAME"
        assert entities[0].token == "[NAME_1]"


# =============================================================================
# REDACTOR CLASS TESTS (Using manual mocking to avoid fixture context issues)
# =============================================================================

def _mock_scrubiq():
    """Create a fully mocked ScrubIQ instance."""
    mock_instance = MagicMock()
    mock_instance.is_models_ready.return_value = True
    mock_instance.is_unlocked = True
    mock_instance.get_token_count.return_value = 0
    mock_instance.get_tokens.return_value = []
    mock_instance._detectors = None
    return mock_instance


class TestRedactorInit:
    """Tests for Redactor initialization."""

    def test_default_initialization(self):
        """Redactor initializes with defaults."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor()

            assert r._threshold == 0.85
            assert r._safe_harbor is True
            assert r._coreference is True
            assert r._device == "auto"
            assert r._workers == 1

    def test_custom_threshold(self):
        """Custom threshold is set."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor(confidence_threshold=0.9)

            assert r._threshold == 0.9

    def test_threshold_alias(self):
        """threshold alias works."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor(threshold=0.75)

            assert r._threshold == 0.75

    def test_allowlist_from_list(self):
        """Allowlist from list."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor(allowlist=["Mayo Clinic", "Tylenol"])

            assert "Mayo Clinic" in r._allowlist
            assert "Tylenol" in r._allowlist

    def test_allowlist_from_file(self):
        """Allowlist from file."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("Mayo Clinic\n")
                f.write("# comment\n")
                f.write("Tylenol\n")
                f.flush()

                try:
                    r = Redactor(allowlist_file=f.name)

                    assert "Mayo Clinic" in r._allowlist
                    assert "Tylenol" in r._allowlist
                finally:
                    os.unlink(f.name)

    def test_custom_patterns_compiled(self):
        """Custom patterns are compiled."""
        from scrubiq.sdk import Redactor
        import re

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor(patterns={"MRN": r"MRN-\d{8}"})

            assert "MRN" in r._compiled_patterns
            assert isinstance(r._compiled_patterns["MRN"], re.Pattern)

    def test_invalid_pattern_handled(self):
        """Invalid pattern is logged but doesn't crash."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            # Invalid regex (unclosed group)
            r = Redactor(patterns={"BAD": r"(unclosed"})

            assert "BAD" not in r._compiled_patterns


class TestRedactorProperties:
    """Tests for Redactor property accessors."""

    def _make_redactor(self):
        """Create a Redactor with mocked internals."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_instance = MagicMock()
            mock_instance.is_models_ready.return_value = True
            mock_instance.is_unlocked = True
            mock_instance.get_token_count.return_value = 5
            mock_instance.get_tokens.return_value = []
            mock_instance._detectors = None
            mock_scrubiq.return_value = mock_instance

            r = Redactor()
            r._stats["errors"] = 0
            return r

    def test_is_ready(self):
        """is_ready checks models and unlock status."""
        r = self._make_redactor()
        assert r.is_ready is True

    def test_is_ready_models_not_loaded(self):
        """is_ready is False when models not loaded."""
        r = self._make_redactor()
        r._cr.is_models_ready.return_value = False
        assert r.is_ready is False

    def test_is_healthy(self):
        """is_healthy checks ready and no errors."""
        r = self._make_redactor()
        assert r.is_healthy is True

    def test_is_healthy_with_errors(self):
        """is_healthy is False with errors."""
        r = self._make_redactor()
        r._stats["errors"] = 1
        assert r.is_healthy is False

    def test_status(self):
        """status returns dict."""
        r = self._make_redactor()
        status = r.status

        assert status["ready"] is True
        assert status["healthy"] is True
        assert status["models_loaded"] is True

    def test_stats(self):
        """stats returns processing stats."""
        r = self._make_redactor()
        stats = r.stats

        assert "redactions_performed" in stats
        assert "entities_detected" in stats
        assert "tokens_stored" in stats
        assert "by_type" in stats

    def test_token_count(self):
        """token_count returns count."""
        r = self._make_redactor()
        assert r.token_count == 5

    def test_tokens_interface(self):
        """tokens property returns TokensInterface."""
        from scrubiq.sdk import TokensInterface

        r = self._make_redactor()
        assert isinstance(r.tokens, TokensInterface)

    def test_detectors_none(self):
        """detectors returns empty list when none."""
        r = self._make_redactor()
        assert r.detectors == []

    def test_config_property(self):
        """config property returns config."""
        from scrubiq.sdk import RedactorConfig

        r = self._make_redactor()
        assert isinstance(r.config, RedactorConfig)

    def test_supported_types(self):
        """supported_types returns list of types."""
        r = self._make_redactor()
        types = r.supported_types

        assert isinstance(types, list)
        assert "NAME" in types
        assert "SSN" in types

    def test_conversations_interface(self):
        """conversations property returns interface."""
        from scrubiq.sdk import ConversationsInterface

        r = self._make_redactor()
        assert isinstance(r.conversations, ConversationsInterface)

    def test_review_interface(self):
        """review property returns interface."""
        from scrubiq.sdk import ReviewInterface

        r = self._make_redactor()
        assert isinstance(r.review, ReviewInterface)

    def test_memory_interface(self):
        """memory property returns interface."""
        from scrubiq.sdk import MemoryInterface

        r = self._make_redactor()
        assert isinstance(r.memory, MemoryInterface)

    def test_audit_interface(self):
        """audit property returns interface."""
        from scrubiq.sdk import AuditInterface

        r = self._make_redactor()
        assert isinstance(r.audit, AuditInterface)


class TestRedactorRedact:
    """Tests for Redactor.redact() method."""

    def _make_redactor_with_mock_result(self):
        """Create a Redactor with mocked redact result."""
        from scrubiq.sdk import Redactor
        from scrubiq.types import Span, Tier

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_instance = MagicMock()
            mock_instance.is_models_ready.return_value = True
            mock_instance.is_unlocked = True
            mock_instance.get_token_count.return_value = 0
            mock_instance.get_tokens.return_value = []

            # Mock redact result
            mock_result = MagicMock()
            mock_result.redacted = "Patient [NAME_1], SSN [SSN_1]"
            mock_result.spans = [
                Span(start=8, end=18, text="John Smith", entity_type="NAME",
                     confidence=0.95, detector="ner", tier=Tier.ML, token="[NAME_1]"),
                Span(start=24, end=35, text="123-45-6789", entity_type="SSN",
                     confidence=0.99, detector="pattern", tier=Tier.PATTERN, token="[SSN_1]"),
            ]
            mock_result.tokens_created = ["[NAME_1]", "[SSN_1]"]
            mock_result.needs_review = []
            mock_result.normalized_input = "Patient John Smith, SSN 123-45-6789"
            mock_result.input_hash = "abc123"
            mock_instance.redact.return_value = mock_result

            mock_scrubiq.return_value = mock_instance

            r = Redactor()
            return r

    def test_redact_basic(self):
        """Basic redaction works."""
        r = self._make_redactor_with_mock_result()
        result = r.redact("Patient John Smith, SSN 123-45-6789")

        assert "[NAME_1]" in str(result)
        assert "[SSN_1]" in str(result)
        assert result.has_phi is True
        assert len(result.entities) == 2

    def test_redact_empty_input(self):
        """Empty input returns empty result."""
        r = self._make_redactor_with_mock_result()
        result = r.redact("")

        assert str(result) == ""
        assert result.has_phi is False
        assert result.warning == "Empty input"

    def test_redact_updates_stats(self):
        """Redaction updates stats."""
        r = self._make_redactor_with_mock_result()
        initial = r._stats["redactions_performed"]

        r.redact("test")

        assert r._stats["redactions_performed"] == initial + 1

    def test_redact_with_callback(self):
        """on_redact callback is called."""
        r = self._make_redactor_with_mock_result()
        callback = MagicMock()
        r._on_redact = callback

        result = r.redact("test")

        callback.assert_called_once_with(result)

    def test_redact_callback_error_handled(self):
        """on_redact callback error is handled."""
        r = self._make_redactor_with_mock_result()
        callback = MagicMock(side_effect=Exception("callback error"))
        r._on_redact = callback

        # Should not raise
        result = r.redact("test")

        assert result is not None

    def test_redact_error_returns_safe_result(self):
        """Error returns safe result without PHI."""
        r = self._make_redactor_with_mock_result()
        r._cr.redact.side_effect = Exception("Processing failed")

        result = r.redact("Patient John Smith")

        assert result.error == "Processing failed"
        assert result.text == "[REDACTION_FAILED]"
        assert "John" not in str(result)  # PHI not exposed

    def test_redact_error_calls_callback(self):
        """Error calls on_error callback."""
        r = self._make_redactor_with_mock_result()
        r._cr.redact.side_effect = Exception("fail")
        callback = MagicMock()
        r._on_error = callback

        r.redact("test")

        callback.assert_called_once()


class TestRedactorFilterEntities:
    """Tests for entity filtering."""

    def _make_redactor_with_filters(self):
        """Create a Redactor with filters configured."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor(
                confidence_threshold=0.8,
                entity_types=["NAME", "SSN"],
                exclude_types=["EMAIL"],
                allowlist=["Mayo Clinic"],
            )
            return r

    def test_filter_by_threshold(self):
        """Entities below threshold are filtered."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="John", type="NAME", confidence=0.9),  # Keep
            Entity(text="Maybe", type="NAME", confidence=0.5),  # Filter
        ]

        filtered = r._filter_entities(entities)

        assert len(filtered) == 1
        assert filtered[0].text == "John"

    def test_filter_by_entity_types(self):
        """Only specified entity types are kept."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="John", type="NAME", confidence=0.9),  # Keep
            Entity(text="123-45-6789", type="SSN", confidence=0.99),  # Keep
            Entity(text="test@example.com", type="EMAIL", confidence=0.99),  # Filter (excluded)
            Entity(text="123 Main St", type="ADDRESS", confidence=0.9),  # Filter (not in types)
        ]

        filtered = r._filter_entities(entities)

        assert len(filtered) == 2
        types = {e.type for e in filtered}
        assert types == {"NAME", "SSN"}

    def test_filter_by_exclude_types(self):
        """Excluded types are filtered."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="test@example.com", type="EMAIL", confidence=0.99),
        ]

        filtered = r._filter_entities(entities)

        assert len(filtered) == 0

    def test_filter_by_allowlist(self):
        """Allowlisted values are filtered."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="John", type="NAME", confidence=0.9),  # Keep
            Entity(text="Mayo Clinic", type="NAME", confidence=0.9),  # Filter
        ]

        filtered = r._filter_entities(entities)

        assert len(filtered) == 1
        assert filtered[0].text == "John"

    def test_allowlist_case_insensitive(self):
        """Allowlist matching is case-insensitive."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="MAYO CLINIC", type="NAME", confidence=0.9),
            Entity(text="mayo clinic", type="NAME", confidence=0.9),
        ]

        filtered = r._filter_entities(entities)

        assert len(filtered) == 0

    def test_allowlist_partial_match(self):
        """Allowlist matches partial words from multi-word entries."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="Mayo", type="NAME", confidence=0.9),  # Part of "Mayo Clinic"
        ]

        filtered = r._filter_entities(entities)

        # "Mayo" is a word in "Mayo Clinic", so it should be filtered
        assert len(filtered) == 0

    def test_per_call_override_threshold(self):
        """Per-call threshold overrides default."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="John", type="NAME", confidence=0.7),  # Below default, above override
        ]

        # Default 0.8 would filter, but override 0.5 should keep
        filtered = r._filter_entities(entities, threshold=0.5)

        assert len(filtered) == 1

    def test_per_call_override_allowlist(self):
        """Per-call allowlist extends default."""
        from scrubiq.sdk import Entity

        r = self._make_redactor_with_filters()
        entities = [
            Entity(text="Tylenol", type="NAME", confidence=0.9),  # Not in default allowlist
        ]

        # Without override, should be kept
        filtered1 = r._filter_entities(entities)
        assert len(filtered1) == 1

        # With override, should be filtered
        filtered2 = r._filter_entities(entities, allowlist=["Tylenol"])
        assert len(filtered2) == 0


class TestRedactorCustomPatterns:
    """Tests for custom pattern detection."""

    def _make_redactor_with_patterns(self):
        """Create Redactor with custom patterns."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor(patterns={
                "MRN": r"MRN-\d{8}",
                "CASE": r"CASE-[A-Z]{2}\d{4}",
            })
            return r

    def test_detect_custom_patterns(self):
        """Custom patterns are detected."""
        r = self._make_redactor_with_patterns()
        text = "Patient MRN-12345678 was seen for CASE-AB1234"

        spans = r._detect_custom_patterns(text)

        assert len(spans) == 2
        types = {s["type"] for s in spans}
        assert types == {"MRN", "CASE"}

    def test_custom_pattern_positions(self):
        """Custom patterns have correct positions."""
        r = self._make_redactor_with_patterns()
        text = "MRN-12345678"

        spans = r._detect_custom_patterns(text)

        assert len(spans) == 1
        assert spans[0]["start"] == 0
        assert spans[0]["end"] == 12
        assert spans[0]["text"] == "MRN-12345678"

    def test_multiple_matches_same_pattern(self):
        """Multiple matches of same pattern are found."""
        r = self._make_redactor_with_patterns()
        text = "MRN-11111111 and MRN-22222222"

        spans = r._detect_custom_patterns(text)

        assert len(spans) == 2
        assert all(s["type"] == "MRN" for s in spans)


class TestRedactorRestore:
    """Tests for Redactor.restore() method."""

    def _make_redactor_with_restore(self):
        """Create a Redactor with mocked restore."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_instance = MagicMock()
            mock_instance.is_models_ready.return_value = True
            mock_instance.is_unlocked = True
            mock_instance.get_token_count.return_value = 0
            mock_instance.get_tokens.return_value = []

            # Mock restore result
            mock_restore_result = MagicMock()
            mock_restore_result.restored = "Patient John Smith, SSN 123-45-6789"
            mock_instance.restore.return_value = mock_restore_result

            mock_scrubiq.return_value = mock_instance

            r = Redactor()
            return r

    def test_restore_with_mapping(self):
        """restore() with mapping doesn't call core."""
        r = self._make_redactor_with_restore()
        mapping = {"[NAME_1]": "John", "[SSN_1]": "123-45-6789"}

        result = r.restore(
            "Patient [NAME_1], SSN [SSN_1]",
            mapping=mapping,
        )

        assert result == "Patient John, SSN 123-45-6789"
        r._cr.restore.assert_not_called()

    def test_restore_without_mapping(self):
        """restore() without mapping calls core."""
        r = self._make_redactor_with_restore()
        result = r.restore("Patient [NAME_1]")

        r._cr.restore.assert_called_once()
        assert result == "Patient John Smith, SSN 123-45-6789"

    def test_restore_token_ordering(self):
        """restore() handles overlapping tokens correctly."""
        r = self._make_redactor_with_restore()
        # [NAME_10] must be replaced before [NAME_1]
        mapping = {
            "[NAME_1]": "John",
            "[NAME_10]": "Jane",
        }

        result = r.restore(
            "[NAME_10] met [NAME_1]",
            mapping=mapping,
        )

        assert result == "Jane met John"


class TestRedactorLifecycle:
    """Tests for Redactor lifecycle methods."""

    def _make_redactor(self):
        """Create a Redactor with mocked internals."""
        from scrubiq.sdk import Redactor

        with patch("scrubiq.core.ScrubIQ") as mock_scrubiq, \
             patch("scrubiq.config.validate_data_path", return_value=True):
            mock_scrubiq.return_value = _mock_scrubiq()

            r = Redactor()
            return r

    def test_close(self):
        """close() cleans up resources."""
        r = self._make_redactor()
        r.close()

        r._cr.close.assert_called_once()

    def test_context_manager(self):
        """Context manager calls close."""
        r = self._make_redactor()
        r._cr.close.reset_mock()

        with r:
            pass

        r._cr.close.assert_called_once()


# =============================================================================
# MODULE-LEVEL FUNCTION TESTS
# =============================================================================

class TestModuleLevelFunctions:
    """Tests for module-level convenience functions."""

    def test_session_is_redactor_alias(self):
        """Session is alias for Redactor."""
        from scrubiq.sdk import Session, Redactor

        assert Session is Redactor

    def test_redact_full_is_redact_alias(self):
        """redact_full is alias for redact."""
        from scrubiq.sdk import redact, redact_full

        assert redact_full is redact

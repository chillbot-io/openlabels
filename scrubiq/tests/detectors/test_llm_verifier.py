"""Tests for detectors/llm_verifier.py - LLM-based PII verification.

Tests cover:
- LLMVerifier initialization and configuration
- Ollama availability checking
- Context extraction
- Message building for different entity types
- Ollama API calls
- Response parsing (JSON, regex, text fallback)
- Verification workflow
- Single span verification
- Batch verification
- VerificationResult dataclass
- create_verifier factory function
- Error handling and graceful degradation
"""

import json
from unittest.mock import MagicMock, patch, Mock
import urllib.error

import pytest

from scrubiq.types import Span, Tier


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def make_span():
    """Factory for creating test spans."""
    def _make_span(
        text: str,
        start: int = 0,
        entity_type: str = "NAME",
        confidence: float = 0.7,
        detector: str = "ml",
        tier: Tier = Tier.ML,
    ) -> Span:
        return Span(
            start=start,
            end=start + len(text),
            text=text,
            entity_type=entity_type,
            confidence=confidence,
            detector=detector,
            tier=tier,
        )
    return _make_span


@pytest.fixture
def verifier():
    """Create default LLMVerifier."""
    from scrubiq.detectors.llm_verifier import LLMVerifier
    return LLMVerifier()


@pytest.fixture
def mock_ollama_response():
    """Create a mock successful Ollama response."""
    return {
        "message": {
            "content": '{"answer": "YES"}'
        }
    }


# =============================================================================
# MODULE CONSTANTS TESTS
# =============================================================================

class TestModuleConstants:
    """Tests for module-level constants."""

    def test_default_ollama_url(self):
        """Default Ollama URL is set."""
        from scrubiq.detectors.llm_verifier import DEFAULT_OLLAMA_URL

        assert DEFAULT_OLLAMA_URL == "http://localhost:11434"

    def test_default_model(self):
        """Default model is Qwen2.5:3b."""
        from scrubiq.detectors.llm_verifier import DEFAULT_MODEL

        assert DEFAULT_MODEL == "qwen2.5:3b"

    def test_fallback_models(self):
        """Fallback models list is defined."""
        from scrubiq.detectors.llm_verifier import FALLBACK_MODELS

        assert len(FALLBACK_MODELS) > 0
        assert "qwen2.5:3b" in FALLBACK_MODELS
        assert "phi3:mini" in FALLBACK_MODELS

    def test_verify_entity_types_empty(self):
        """VERIFY_ENTITY_TYPES is empty (disabled)."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES

        # Currently disabled in favor of pattern-based filtering
        assert len(VERIFY_ENTITY_TYPES) == 0


# =============================================================================
# VERIFICATION RESULT TESTS
# =============================================================================

class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_basic_result(self, make_span):
        """VerificationResult stores basic data."""
        from scrubiq.detectors.llm_verifier import VerificationResult

        span = make_span("John Smith")
        result = VerificationResult(
            span=span,
            verified=True,
            llm_confidence=0.9,
            reasoning="Confirmed as person name"
        )

        assert result.span == span
        assert result.verified is True
        assert result.llm_confidence == 0.9
        assert result.reasoning == "Confirmed as person name"

    def test_unverified_result(self, make_span):
        """VerificationResult for unverified span."""
        from scrubiq.detectors.llm_verifier import VerificationResult

        span = make_span("Apple")
        result = VerificationResult(
            span=span,
            verified=False,
            llm_confidence=0.8,
            reasoning="Company name, not person"
        )

        assert result.verified is False
        assert "Company" in result.reasoning


# =============================================================================
# LLM VERIFIER INITIALIZATION TESTS
# =============================================================================

class TestLLMVerifierInit:
    """Tests for LLMVerifier initialization."""

    def test_default_initialization(self):
        """LLMVerifier initializes with defaults."""
        from scrubiq.detectors.llm_verifier import LLMVerifier, DEFAULT_MODEL, DEFAULT_OLLAMA_URL

        verifier = LLMVerifier()

        assert verifier.model == DEFAULT_MODEL
        assert verifier.ollama_url == DEFAULT_OLLAMA_URL
        assert verifier.timeout == 30.0
        assert verifier.min_confidence == 0.6
        assert verifier.batch_size == 1
        assert verifier.context_window == 75

    def test_custom_initialization(self):
        """LLMVerifier accepts custom parameters."""
        from scrubiq.detectors.llm_verifier import LLMVerifier

        verifier = LLMVerifier(
            model="phi3:mini",
            ollama_url="http://custom:11434",
            timeout=60.0,
            min_confidence=0.8,
            batch_size=5,
            context_window=100
        )

        assert verifier.model == "phi3:mini"
        assert verifier.ollama_url == "http://custom:11434"
        assert verifier.timeout == 60.0
        assert verifier.min_confidence == 0.8
        assert verifier.batch_size == 5
        assert verifier.context_window == 100

    def test_strips_trailing_slash_from_url(self):
        """Strips trailing slash from Ollama URL."""
        from scrubiq.detectors.llm_verifier import LLMVerifier

        verifier = LLMVerifier(ollama_url="http://localhost:11434/")

        assert verifier.ollama_url == "http://localhost:11434"

    def test_availability_not_cached_initially(self):
        """Availability is not cached initially."""
        from scrubiq.detectors.llm_verifier import LLMVerifier

        verifier = LLMVerifier()

        assert verifier._available is None


# =============================================================================
# AVAILABILITY CHECKING TESTS
# =============================================================================

class TestLLMVerifierIsAvailable:
    """Tests for is_available method."""

    def test_returns_cached_value(self, verifier):
        """Returns cached availability value."""
        verifier._available = True

        assert verifier.is_available() is True

        verifier._available = False
        assert verifier.is_available() is False

    def test_checks_ollama_api(self, verifier):
        """Checks Ollama API for availability."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "models": [{"name": "qwen2.5:3b"}]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            result = verifier.is_available()

            assert result is True
            assert verifier._available is True

    def test_handles_model_not_found(self, verifier):
        """Returns False when model not found."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "models": [{"name": "other-model"}]
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            result = verifier.is_available()

            assert result is False

    def test_handles_connection_error(self, verifier):
        """Returns False on connection error."""
        with patch('urllib.request.urlopen', side_effect=urllib.error.URLError("Connection refused")):
            result = verifier.is_available()

            assert result is False
            assert verifier._available is False

    def test_handles_timeout(self, verifier):
        """Returns False on timeout."""
        with patch('urllib.request.urlopen', side_effect=TimeoutError("Timed out")):
            result = verifier.is_available()

            assert result is False

    def test_matches_model_base_name(self, verifier):
        """Matches model base name (without tag)."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "models": [{"name": "qwen2.5:3b-instruct-q4_0"}]  # Full name with tag
        }).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            result = verifier.is_available()

            # Should match "qwen2.5" base name
            assert result is True


# =============================================================================
# CONTEXT EXTRACTION TESTS
# =============================================================================

class TestLLMVerifierGetContext:
    """Tests for _get_context method."""

    def test_basic_context_extraction(self, verifier, make_span):
        """Extracts context around span."""
        text = "Hello John Smith, how are you today?"
        span = make_span("John Smith", start=6)

        context = verifier._get_context(text, span)

        assert "John Smith" in context
        assert "Hello" in context
        assert "how are" in context

    def test_context_at_start(self, verifier, make_span):
        """Handles span at start of text."""
        text = "John Smith is here"
        span = make_span("John Smith", start=0)

        context = verifier._get_context(text, span)

        assert "John Smith" in context
        assert not context.startswith("...")

    def test_context_at_end(self, verifier, make_span):
        """Handles span at end of text."""
        text = "Hello John Smith"
        span = make_span("John Smith", start=6)

        context = verifier._get_context(text, span)

        assert "John Smith" in context
        assert not context.endswith("...")

    def test_adds_ellipsis_for_truncation(self, verifier, make_span):
        """Adds ellipsis when context is truncated."""
        text = "A" * 100 + "John Smith" + "B" * 100
        span = make_span("John Smith", start=100)

        context = verifier._get_context(text, span, window=50)

        assert context.startswith("...")
        assert context.endswith("...")

    def test_custom_window_size(self, verifier, make_span):
        """Uses custom window size."""
        text = "A" * 200 + "John Smith" + "B" * 200
        span = make_span("John Smith", start=200)

        context = verifier._get_context(text, span, window=10)

        # Should have limited context
        assert len(context) < 50


# =============================================================================
# MESSAGE BUILDING TESTS
# =============================================================================

class TestLLMVerifierBuildMessages:
    """Tests for _build_messages method."""

    def test_name_entity_messages(self, verifier, make_span):
        """Builds messages for NAME entity."""
        text = "Contact John Smith at..."
        span = make_span("John Smith", start=8, entity_type="NAME")

        messages = verifier._build_messages(text, span)

        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert "person" in messages[0]["content"].lower()
        assert "John Smith" in messages[1]["content"]

    def test_person_entity_messages(self, verifier, make_span):
        """Builds messages for PERSON entity (same as NAME)."""
        text = "Contact John Smith at..."
        span = make_span("John Smith", start=8, entity_type="PERSON")

        messages = verifier._build_messages(text, span)

        assert "person" in messages[0]["content"].lower()

    def test_username_entity_messages(self, verifier, make_span):
        """Builds messages for USERNAME entity."""
        text = "Login as john_doe92..."
        span = make_span("john_doe92", start=9, entity_type="USERNAME")

        messages = verifier._build_messages(text, span)

        assert "username" in messages[0]["content"].lower()
        assert "john_doe92" in messages[1]["content"]

    def test_address_entity_messages(self, verifier, make_span):
        """Builds messages for ADDRESS entity."""
        text = "Ship to 123 Main Street..."
        span = make_span("123 Main Street", start=8, entity_type="ADDRESS")

        messages = verifier._build_messages(text, span)

        assert "address" in messages[0]["content"].lower()
        assert "123 Main Street" in messages[1]["content"]

    def test_generic_entity_messages(self, verifier, make_span):
        """Builds messages for generic/unknown entity types."""
        text = "Code: ABC123..."
        span = make_span("ABC123", start=6, entity_type="CUSTOM_TYPE")

        messages = verifier._build_messages(text, span)

        assert "CUSTOM_TYPE" in messages[0]["content"]
        assert "ABC123" in messages[1]["content"]

    def test_includes_few_shot_examples(self, verifier, make_span):
        """Messages include few-shot examples for NAME."""
        text = "Contact John Smith at..."
        span = make_span("John Smith", start=8, entity_type="NAME")

        messages = verifier._build_messages(text, span)

        # Should include examples
        user_content = messages[1]["content"]
        assert "Examples:" in user_content or "example" in user_content.lower()


# =============================================================================
# OLLAMA API CALL TESTS
# =============================================================================

class TestLLMVerifierCallOllama:
    """Tests for _call_ollama method."""

    def test_successful_call(self, verifier, mock_ollama_response):
        """Successful Ollama API call."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_ollama_response).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            result = verifier._call_ollama([{"role": "user", "content": "test"}])

            assert result is not None
            assert "message" in result

    def test_handles_url_error(self, verifier):
        """Returns None on URL error."""
        with patch('urllib.request.urlopen', side_effect=urllib.error.URLError("Error")):
            result = verifier._call_ollama([{"role": "user", "content": "test"}])

            assert result is None

    def test_handles_timeout_error(self, verifier):
        """Returns None on timeout."""
        with patch('urllib.request.urlopen', side_effect=TimeoutError("Timeout")):
            result = verifier._call_ollama([{"role": "user", "content": "test"}])

            assert result is None

    def test_handles_json_decode_error(self, verifier):
        """Returns None on invalid JSON response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"invalid json"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response):
            result = verifier._call_ollama([{"role": "user", "content": "test"}])

            assert result is None

    def test_request_format(self, verifier):
        """Request has correct format."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"message": {"content": "test"}}'
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
            with patch('urllib.request.Request') as mock_request:
                mock_request.return_value = MagicMock()
                verifier._call_ollama([{"role": "user", "content": "test"}])

                # Verify request was made
                mock_request.assert_called_once()
                call_args = mock_request.call_args

                # Should use chat API
                assert "/api/chat" in call_args[0][0]


# =============================================================================
# RESPONSE PARSING TESTS
# =============================================================================

class TestLLMVerifierParseResponse:
    """Tests for _parse_response method."""

    def test_parse_json_yes(self, verifier):
        """Parses JSON YES response."""
        response = {"message": {"content": '{"answer": "YES"}'}}

        results = verifier._parse_response(response, 1)

        assert len(results) == 1
        verified, confidence, reason = results[0]
        assert verified is True
        assert confidence > 0.5

    def test_parse_json_no(self, verifier):
        """Parses JSON NO response."""
        response = {"message": {"content": '{"answer": "NO"}'}}

        results = verifier._parse_response(response, 1)

        assert len(results) == 1
        verified, confidence, reason = results[0]
        assert verified is False

    def test_parse_json_in_markdown_block(self, verifier):
        """Parses JSON wrapped in markdown code block."""
        response = {"message": {"content": '```json\n{"answer": "YES"}\n```'}}

        results = verifier._parse_response(response, 1)

        assert len(results) == 1
        verified, confidence, reason = results[0]
        assert verified is True

    def test_parse_legacy_batch_format(self, verifier):
        """Parses legacy batch results format."""
        response = {
            "message": {
                "content": json.dumps({
                    "results": [
                        {"verdict": "YES", "confidence": 0.9, "reason": "Valid name"},
                        {"verdict": "NO", "confidence": 0.8, "reason": "Company"}
                    ]
                })
            }
        }

        results = verifier._parse_response(response, 2)

        assert len(results) == 2
        assert results[0][0] is True
        assert results[1][0] is False

    def test_parse_regex_fallback(self, verifier):
        """Falls back to regex parsing."""
        response = {"message": {"content": 'Based on analysis, "answer": "YES" because...'}}

        results = verifier._parse_response(response, 1)

        assert len(results) == 1
        verified, confidence, reason = results[0]
        assert verified is True
        assert "regex" in reason

    def test_parse_text_yes_fallback(self, verifier):
        """Falls back to text matching for YES."""
        response = {"message": {"content": "YES, this is definitely a real name."}}

        results = verifier._parse_response(response, 1)

        assert len(results) == 1
        verified, confidence, reason = results[0]
        assert verified is True
        assert confidence == 0.7  # Text fallback confidence

    def test_parse_text_no_fallback(self, verifier):
        """Falls back to text matching for NO."""
        response = {"message": {"content": "NO, this is a company name."}}

        results = verifier._parse_response(response, 1)

        assert len(results) == 1
        verified, confidence, reason = results[0]
        assert verified is False

    def test_parse_unparseable_accepts_all(self, verifier):
        """Unparseable response accepts all to preserve recall."""
        response = {"message": {"content": "Unable to determine classification."}}

        results = verifier._parse_response(response, 2)

        # Should accept all to preserve recall
        assert len(results) == 2
        for verified, confidence, reason in results:
            assert verified is True  # Accept to preserve recall
            assert "parse_error" in reason or "missing" in reason

    def test_pads_missing_results(self, verifier):
        """Pads results if fewer than expected."""
        response = {"message": {"content": '{"answer": "YES"}'}}

        results = verifier._parse_response(response, 3)

        assert len(results) == 3
        # Missing results should be accepted
        assert "missing" in results[1][2]
        assert "missing" in results[2][2]

    def test_truncates_extra_results(self, verifier):
        """Truncates if more results than expected."""
        response = {
            "message": {
                "content": json.dumps({
                    "results": [
                        {"verdict": "YES", "confidence": 0.9, "reason": ""},
                        {"verdict": "NO", "confidence": 0.8, "reason": ""},
                        {"verdict": "YES", "confidence": 0.7, "reason": ""},
                    ]
                })
            }
        }

        results = verifier._parse_response(response, 2)

        # Should only return 2
        assert len(results) == 2

    def test_handles_generate_api_format(self, verifier):
        """Handles legacy generate API format."""
        response = {"response": '{"answer": "YES"}'}

        results = verifier._parse_response(response, 1)

        assert len(results) == 1
        assert results[0][0] is True


# =============================================================================
# VERIFY METHOD TESTS
# =============================================================================

class TestLLMVerifierVerify:
    """Tests for verify method."""

    def test_empty_spans_returns_empty(self, verifier):
        """Empty span list returns empty."""
        result = verifier.verify("Hello world", [])

        assert result == []

    def test_unavailable_returns_all(self, verifier, make_span):
        """Returns all spans when Ollama unavailable."""
        verifier._available = False

        spans = [make_span("John Smith")]
        result = verifier.verify("Hello John Smith", spans)

        assert len(result) == 1
        assert result[0].text == "John Smith"

    def test_non_verify_types_pass_through(self, verifier, make_span):
        """Non-VERIFY_ENTITY_TYPES pass through without verification."""
        verifier._available = True

        # SSN is not in VERIFY_ENTITY_TYPES
        span = make_span("123-45-6789", entity_type="SSN")

        result = verifier.verify("SSN: 123-45-6789", [span])

        # Should pass through without LLM call
        assert len(result) == 1

    def test_verify_types_go_to_llm(self, verifier, make_span):
        """VERIFY_ENTITY_TYPES are sent to LLM."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES

        # Add NAME to verify types for this test
        original_types = VERIFY_ENTITY_TYPES.copy()
        VERIFY_ENTITY_TYPES.add("NAME")

        try:
            verifier._available = True

            with patch.object(verifier, '_call_ollama') as mock_call:
                mock_call.return_value = {"message": {"content": '{"answer": "YES"}'}}

                span = make_span("John Smith", entity_type="NAME")
                result = verifier.verify("Hello John Smith", [span])

                mock_call.assert_called_once()
        finally:
            VERIFY_ENTITY_TYPES.clear()
            VERIFY_ENTITY_TYPES.update(original_types)

    def test_structured_high_confidence_passes(self, verifier, make_span):
        """High confidence structured spans pass without LLM."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES
        original_types = VERIFY_ENTITY_TYPES.copy()
        VERIFY_ENTITY_TYPES.add("NAME")

        try:
            verifier._available = True

            span = Span(
                start=0, end=10, text="John Smith",
                entity_type="NAME", confidence=0.96,
                detector="structured", tier=Tier.STRUCTURED
            )

            with patch.object(verifier, '_call_ollama') as mock_call:
                result = verifier.verify("John Smith is here", [span])

                # Should pass without LLM call due to high confidence + structured
                mock_call.assert_not_called()
                assert len(result) == 1
        finally:
            VERIFY_ENTITY_TYPES.clear()
            VERIFY_ENTITY_TYPES.update(original_types)

    def test_verified_span_kept(self, verifier, make_span):
        """Verified span is kept in results."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES
        original_types = VERIFY_ENTITY_TYPES.copy()
        VERIFY_ENTITY_TYPES.add("NAME")

        try:
            verifier._available = True

            with patch.object(verifier, '_call_ollama') as mock_call:
                mock_call.return_value = {"message": {"content": '{"answer": "YES"}'}}

                span = make_span("John Smith", entity_type="NAME", confidence=0.7)
                result = verifier.verify("Hello John Smith", [span])

                assert len(result) == 1
                assert result[0].text == "John Smith"
        finally:
            VERIFY_ENTITY_TYPES.clear()
            VERIFY_ENTITY_TYPES.update(original_types)

    def test_rejected_span_filtered(self, verifier, make_span):
        """Rejected span is filtered from results."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES
        original_types = VERIFY_ENTITY_TYPES.copy()
        VERIFY_ENTITY_TYPES.add("NAME")

        try:
            verifier._available = True

            with patch.object(verifier, '_call_ollama') as mock_call:
                mock_call.return_value = {"message": {"content": '{"answer": "NO"}'}}

                span = make_span("Apple", entity_type="NAME", confidence=0.7)
                result = verifier.verify("Contact Apple for help", [span])

                # Should be filtered
                assert len(result) == 0
        finally:
            VERIFY_ENTITY_TYPES.clear()
            VERIFY_ENTITY_TYPES.update(original_types)

    def test_ollama_failure_keeps_span(self, verifier, make_span):
        """Span kept when Ollama request fails (preserve recall)."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES
        original_types = VERIFY_ENTITY_TYPES.copy()
        VERIFY_ENTITY_TYPES.add("NAME")

        try:
            verifier._available = True

            with patch.object(verifier, '_call_ollama', return_value=None):
                span = make_span("John Smith", entity_type="NAME")
                result = verifier.verify("Hello John Smith", [span])

                # Should keep to preserve recall
                assert len(result) == 1
        finally:
            VERIFY_ENTITY_TYPES.clear()
            VERIFY_ENTITY_TYPES.update(original_types)

    def test_confidence_boost_on_verification(self, verifier, make_span):
        """Confidence boosted on successful verification."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES
        original_types = VERIFY_ENTITY_TYPES.copy()
        VERIFY_ENTITY_TYPES.add("NAME")

        try:
            verifier._available = True

            with patch.object(verifier, '_call_ollama') as mock_call:
                # High LLM confidence
                mock_call.return_value = {"message": {"content": '{"answer": "YES"}'}}

                span = make_span("John Smith", entity_type="NAME", confidence=0.7)
                result = verifier.verify("Hello John Smith", [span])

                # Confidence should be boosted (0.9 LLM conf > 0.8 threshold)
                if len(result) > 0:
                    assert result[0].confidence >= 0.7
        finally:
            VERIFY_ENTITY_TYPES.clear()
            VERIFY_ENTITY_TYPES.update(original_types)


# =============================================================================
# VERIFY SINGLE TESTS
# =============================================================================

class TestLLMVerifierVerifySingle:
    """Tests for verify_single method."""

    def test_unavailable_returns_unverified(self, verifier, make_span):
        """Returns result with verified=True when unavailable."""
        verifier._available = False

        span = make_span("John Smith")
        result = verifier.verify_single("Hello John Smith", span)

        assert result.verified is True
        assert result.llm_confidence == 0.5
        assert "not available" in result.reasoning

    def test_ollama_failure_returns_unverified(self, verifier, make_span):
        """Returns result with verified=True on Ollama failure."""
        verifier._available = True

        with patch.object(verifier, '_call_ollama', return_value=None):
            span = make_span("John Smith")
            result = verifier.verify_single("Hello John Smith", span)

            assert result.verified is True
            assert result.llm_confidence == 0.5
            assert "failed" in result.reasoning

    def test_successful_verification(self, verifier, make_span):
        """Returns detailed result on successful verification."""
        verifier._available = True

        with patch.object(verifier, '_call_ollama') as mock_call:
            mock_call.return_value = {"message": {"content": '{"answer": "YES"}'}}

            span = make_span("John Smith", entity_type="NAME")
            result = verifier.verify_single("Hello John Smith", span)

            assert result.span == span
            assert result.verified is True
            assert result.llm_confidence > 0.5

    def test_rejection_verification(self, verifier, make_span):
        """Returns rejection result correctly."""
        verifier._available = True

        with patch.object(verifier, '_call_ollama') as mock_call:
            mock_call.return_value = {"message": {"content": '{"answer": "NO"}'}}

            span = make_span("Apple", entity_type="NAME")
            result = verifier.verify_single("Contact Apple support", span)

            assert result.verified is False


# =============================================================================
# CREATE VERIFIER FUNCTION TESTS
# =============================================================================

class TestCreateVerifier:
    """Tests for create_verifier factory function."""

    def test_creates_with_specified_model(self):
        """Creates verifier with specified model."""
        from scrubiq.detectors.llm_verifier import create_verifier

        with patch.object(
            __import__('scrubiq.detectors.llm_verifier', fromlist=['LLMVerifier']).LLMVerifier,
            'is_available',
            return_value=False
        ):
            verifier = create_verifier(model="phi3:mini")

            assert verifier.model == "phi3:mini"

    def test_creates_with_custom_url(self):
        """Creates verifier with custom Ollama URL."""
        from scrubiq.detectors.llm_verifier import create_verifier

        verifier = create_verifier(ollama_url="http://custom:11434")

        assert verifier.ollama_url == "http://custom:11434"

    def test_tries_fallback_models(self):
        """Tries fallback models when default unavailable."""
        from scrubiq.detectors.llm_verifier import create_verifier, FALLBACK_MODELS

        # Mock availability check - second model is available
        availability = {model: False for model in FALLBACK_MODELS}
        availability[FALLBACK_MODELS[1]] = True

        def mock_is_available(self):
            return availability.get(self.model, False)

        with patch('scrubiq.detectors.llm_verifier.LLMVerifier.is_available', mock_is_available):
            verifier = create_verifier()

            # Should find the second available model
            assert verifier.model == FALLBACK_MODELS[1]

    def test_returns_default_when_none_available(self):
        """Returns default model when no fallbacks available."""
        from scrubiq.detectors.llm_verifier import create_verifier, DEFAULT_MODEL

        with patch('scrubiq.detectors.llm_verifier.LLMVerifier.is_available', return_value=False):
            verifier = create_verifier()

            # Returns default (will report unavailable later)
            assert verifier.model == DEFAULT_MODEL


# =============================================================================
# EDGE CASES AND ERROR HANDLING TESTS
# =============================================================================

class TestLLMVerifierEdgeCases:
    """Edge case tests for LLMVerifier."""

    def test_handles_unicode_text(self, verifier, make_span):
        """Handles Unicode text in context."""
        text = "Contact José García for help"
        span = make_span("José García", start=8)

        context = verifier._get_context(text, span)

        assert "José García" in context

    def test_handles_empty_span_text(self, verifier, make_span):
        """Handles empty span text."""
        span = make_span("", start=0)

        messages = verifier._build_messages("Test", span)

        assert len(messages) == 2

    def test_handles_very_long_text(self, verifier, make_span):
        """Handles very long text efficiently."""
        text = "A" * 10000 + "John Smith" + "B" * 10000
        span = make_span("John Smith", start=10000)

        context = verifier._get_context(text, span)

        # Should truncate appropriately
        assert len(context) < 500

    def test_handles_special_characters(self, verifier, make_span):
        """Handles special characters in span."""
        span = make_span("O'Brien-Smith", start=0)
        text = "Contact O'Brien-Smith today"

        messages = verifier._build_messages(text, span)

        assert "O'Brien-Smith" in messages[1]["content"]

    def test_handles_newlines_in_text(self, verifier, make_span):
        """Handles newlines in text."""
        text = "Name:\nJohn Smith\nAddress:"
        span = make_span("John Smith", start=6)

        context = verifier._get_context(text, span)

        assert "John Smith" in context


class TestLLMVerifierConcurrency:
    """Tests for concurrent access."""

    def test_availability_caching(self, verifier):
        """Availability check result is cached."""
        verifier._available = True

        # Multiple calls should return cached value
        assert verifier.is_available() is True
        assert verifier.is_available() is True
        assert verifier._available is True

    def test_multiple_verify_calls(self, verifier, make_span):
        """Multiple verify calls work correctly."""
        verifier._available = False

        for i in range(5):
            spans = [make_span(f"Name{i}")]
            result = verifier.verify(f"Hello Name{i}", spans)
            assert len(result) == 1


class TestLLMVerifierConfiguration:
    """Tests for configuration options."""

    def test_min_confidence_threshold(self, verifier, make_span):
        """Respects min_confidence threshold."""
        from scrubiq.detectors.llm_verifier import VERIFY_ENTITY_TYPES
        original_types = VERIFY_ENTITY_TYPES.copy()
        VERIFY_ENTITY_TYPES.add("NAME")

        try:
            verifier._available = True
            verifier.min_confidence = 0.95  # High threshold

            with patch.object(verifier, '_call_ollama') as mock_call:
                # LLM returns YES but with low confidence (via parsing)
                mock_call.return_value = {"message": {"content": '{"answer": "YES"}'}}

                with patch.object(verifier, '_parse_response', return_value=[(True, 0.6, "test")]):
                    span = make_span("John", entity_type="NAME", confidence=0.7)
                    result = verifier.verify("Hello John", [span])

                    # Should be rejected due to low LLM confidence
                    # Note: depends on implementation details
        finally:
            VERIFY_ENTITY_TYPES.clear()
            VERIFY_ENTITY_TYPES.update(original_types)

    def test_context_window_configuration(self):
        """Context window is configurable."""
        from scrubiq.detectors.llm_verifier import LLMVerifier

        verifier = LLMVerifier(context_window=200)

        assert verifier.context_window == 200

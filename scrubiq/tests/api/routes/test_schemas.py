"""Tests for API Pydantic schemas (validation).

Tests all Pydantic models in scrubiq/api/routes/schemas.py:
- Field validation (max_length, min_length, pattern, range)
- Invalid input rejection
- Type coercion and defaults
"""

import pytest
from pydantic import ValidationError

from scrubiq.api.routes.schemas import (
    # Status
    StatusResponse,
    # Core
    RedactRequest,
    RedactResponse,
    SpanInfo,
    ReviewInfo,
    RestoreRequest,
    RestoreResponse,
    ChatRequest,
    ChatResponse,
    TokenInfo,
    # File uploads
    UploadResponse,
    UploadStatusResponse,
    UploadResultResponse,
    # Reviews & Audits
    ReviewItem,
    AuditEntry,
    AuditVerifyResponse,
    # Conversations
    ConversationCreate,
    ConversationUpdate,
    ConversationResponse,
    ConversationDetailResponse,
    MessageCreate,
    MessageResponse,
    # Admin
    GreetingResponse,
)
from scrubiq.constants import MAX_TEXT_LENGTH


# =============================================================================
# STATUS RESPONSE TESTS
# =============================================================================

class TestStatusResponse:
    """Tests for StatusResponse model."""

    def test_valid_status_response(self):
        """Creates valid StatusResponse."""
        status = StatusResponse(
            initialized=True,
            unlocked=True,
            timeout_remaining=300,
            tokens_count=50,
            review_pending=3,
        )
        assert status.initialized is True
        assert status.unlocked is True
        assert status.timeout_remaining == 300
        assert status.tokens_count == 50
        assert status.review_pending == 3

    def test_status_response_defaults(self):
        """StatusResponse has correct defaults."""
        status = StatusResponse(
            initialized=True,
            unlocked=False,
            timeout_remaining=None,
            tokens_count=0,
            review_pending=0,
        )
        assert status.models_ready is True
        assert status.models_loading is False
        assert status.preload_complete is False
        assert status.is_new_vault is False
        assert status.vault_needs_upgrade is False

    def test_status_response_optional_timeout(self):
        """timeout_remaining is optional."""
        status = StatusResponse(
            initialized=True,
            unlocked=False,
            timeout_remaining=None,
            tokens_count=0,
            review_pending=0,
        )
        assert status.timeout_remaining is None


# =============================================================================
# REDACT REQUEST TESTS
# =============================================================================

class TestRedactRequest:
    """Tests for RedactRequest model."""

    def test_valid_redact_request(self):
        """Creates valid RedactRequest."""
        req = RedactRequest(text="Hello, my name is John Doe")
        assert req.text == "Hello, my name is John Doe"

    def test_redact_request_empty_text(self):
        """Empty text is allowed."""
        req = RedactRequest(text="")
        assert req.text == ""

    def test_redact_request_max_length(self):
        """Text at max length is allowed."""
        long_text = "A" * MAX_TEXT_LENGTH
        req = RedactRequest(text=long_text)
        assert len(req.text) == MAX_TEXT_LENGTH

    def test_redact_request_exceeds_max_length(self):
        """Text exceeding max length is rejected."""
        too_long = "A" * (MAX_TEXT_LENGTH + 1)
        with pytest.raises(ValidationError) as exc_info:
            RedactRequest(text=too_long)
        assert "max_length" in str(exc_info.value).lower() or "string_too_long" in str(exc_info.value).lower()

    def test_redact_request_requires_text(self):
        """Text field is required."""
        with pytest.raises(ValidationError):
            RedactRequest()


# =============================================================================
# SPAN INFO TESTS
# =============================================================================

class TestSpanInfo:
    """Tests for SpanInfo model."""

    def test_valid_span_info(self):
        """Creates valid SpanInfo."""
        span = SpanInfo(
            start=0,
            end=10,
            text="John Doe",
            entity_type="NAME",
            confidence=0.95,
            detector="ml",
            token="[NAME_1]",
        )
        assert span.start == 0
        assert span.end == 10
        assert span.text == "John Doe"
        assert span.confidence == 0.95

    def test_span_info_confidence_min(self):
        """Confidence minimum is 0.0."""
        span = SpanInfo(
            start=0, end=5, text="test",
            entity_type="NAME", confidence=0.0, detector="ml"
        )
        assert span.confidence == 0.0

    def test_span_info_confidence_max(self):
        """Confidence maximum is 1.0."""
        span = SpanInfo(
            start=0, end=5, text="test",
            entity_type="NAME", confidence=1.0, detector="ml"
        )
        assert span.confidence == 1.0

    def test_span_info_confidence_below_min(self):
        """Confidence below 0.0 is rejected."""
        with pytest.raises(ValidationError):
            SpanInfo(
                start=0, end=5, text="test",
                entity_type="NAME", confidence=-0.1, detector="ml"
            )

    def test_span_info_confidence_above_max(self):
        """Confidence above 1.0 is rejected."""
        with pytest.raises(ValidationError):
            SpanInfo(
                start=0, end=5, text="test",
                entity_type="NAME", confidence=1.1, detector="ml"
            )

    def test_span_info_start_non_negative(self):
        """Start must be >= 0."""
        with pytest.raises(ValidationError):
            SpanInfo(
                start=-1, end=5, text="test",
                entity_type="NAME", confidence=0.9, detector="ml"
            )

    def test_span_info_end_non_negative(self):
        """End must be >= 0."""
        with pytest.raises(ValidationError):
            SpanInfo(
                start=0, end=-1, text="test",
                entity_type="NAME", confidence=0.9, detector="ml"
            )

    def test_span_info_optional_token(self):
        """Token is optional."""
        span = SpanInfo(
            start=0, end=5, text="test",
            entity_type="NAME", confidence=0.9, detector="ml"
        )
        assert span.token is None


# =============================================================================
# REVIEW INFO TESTS
# =============================================================================

class TestReviewInfo:
    """Tests for ReviewInfo model."""

    def test_valid_review_info(self):
        """Creates valid ReviewInfo."""
        review = ReviewInfo(
            id="review-123",
            token="[NAME_1]",
            type="NAME",
            confidence=0.65,
            reason="Low confidence detection",
            context_redacted="Hello, [NAME_1] said...",
            suggested="John",
        )
        assert review.id == "review-123"
        assert review.confidence == 0.65

    def test_review_info_confidence_bounds(self):
        """Confidence must be 0.0-1.0."""
        with pytest.raises(ValidationError):
            ReviewInfo(
                id="1", token="[NAME_1]", type="NAME",
                confidence=1.5,  # invalid
                reason="test", context_redacted="test", suggested="test"
            )


# =============================================================================
# REDACT RESPONSE TESTS
# =============================================================================

class TestRedactResponse:
    """Tests for RedactResponse model."""

    def test_valid_redact_response(self):
        """Creates valid RedactResponse."""
        resp = RedactResponse(
            redacted_text="Hello, [NAME_1]",
            normalized_input="Hello, John Doe",
            spans=[],
            tokens_created=["[NAME_1]"],
            needs_review=[],
            processing_time_ms=45.5,
        )
        assert resp.redacted_text == "Hello, [NAME_1]"
        assert resp.processing_time_ms == 45.5


# =============================================================================
# RESTORE REQUEST TESTS
# =============================================================================

class TestRestoreRequest:
    """Tests for RestoreRequest model."""

    def test_valid_restore_request(self):
        """Creates valid RestoreRequest."""
        req = RestoreRequest(text="Hello, [NAME_1]")
        assert req.text == "Hello, [NAME_1]"
        assert req.mode == "research"  # default

    def test_restore_request_mode_redacted(self):
        """Mode 'redacted' is valid."""
        req = RestoreRequest(text="test", mode="redacted")
        assert req.mode == "redacted"

    def test_restore_request_mode_safe_harbor(self):
        """Mode 'safe_harbor' is valid."""
        req = RestoreRequest(text="test", mode="safe_harbor")
        assert req.mode == "safe_harbor"

    def test_restore_request_mode_research(self):
        """Mode 'research' is valid."""
        req = RestoreRequest(text="test", mode="research")
        assert req.mode == "research"

    def test_restore_request_invalid_mode(self):
        """Invalid mode is rejected."""
        with pytest.raises(ValidationError):
            RestoreRequest(text="test", mode="invalid")

    def test_restore_request_max_length(self):
        """Text at max length is allowed."""
        req = RestoreRequest(text="A" * MAX_TEXT_LENGTH)
        assert len(req.text) == MAX_TEXT_LENGTH

    def test_restore_request_exceeds_max_length(self):
        """Text exceeding max length is rejected."""
        with pytest.raises(ValidationError):
            RestoreRequest(text="A" * (MAX_TEXT_LENGTH + 1))


# =============================================================================
# RESTORE RESPONSE TESTS
# =============================================================================

class TestRestoreResponse:
    """Tests for RestoreResponse model."""

    def test_valid_restore_response(self):
        """Creates valid RestoreResponse."""
        resp = RestoreResponse(
            restored_text="Hello, John Doe",
            tokens_restored=["[NAME_1]"],
            unknown_tokens=[],
        )
        assert resp.restored_text == "Hello, John Doe"


# =============================================================================
# CHAT REQUEST TESTS
# =============================================================================

class TestChatRequest:
    """Tests for ChatRequest model."""

    def test_valid_chat_request(self):
        """Creates valid ChatRequest."""
        req = ChatRequest(text="What is the patient's diagnosis?")
        assert req.text == "What is the patient's diagnosis?"
        assert req.model == "claude-sonnet-4"  # default

    def test_chat_request_custom_model(self):
        """Custom model is accepted."""
        req = ChatRequest(text="test", model="gpt-4")
        assert req.model == "gpt-4"

    def test_chat_request_model_pattern(self):
        """Model must match pattern."""
        # Valid patterns
        ChatRequest(text="test", model="gpt-4")
        ChatRequest(text="test", model="claude-3.5-sonnet")
        ChatRequest(text="test", model="llama_70b")
        ChatRequest(text="test", model="model-v1.0")

    def test_chat_request_invalid_model_pattern(self):
        """Invalid model pattern is rejected."""
        with pytest.raises(ValidationError):
            ChatRequest(text="test", model="Model With Spaces")

    def test_chat_request_model_max_length(self):
        """Model has max length of 64."""
        with pytest.raises(ValidationError):
            ChatRequest(text="test", model="a" * 65)

    def test_chat_request_provider_pattern(self):
        """Provider must match pattern."""
        req = ChatRequest(text="test", provider="openai")
        assert req.provider == "openai"

        req = ChatRequest(text="test", provider="anthropic_v2")
        assert req.provider == "anthropic_v2"

    def test_chat_request_invalid_provider_pattern(self):
        """Invalid provider pattern is rejected."""
        with pytest.raises(ValidationError):
            ChatRequest(text="test", provider="Provider With Spaces")

    def test_chat_request_provider_max_length(self):
        """Provider has max length of 32."""
        with pytest.raises(ValidationError):
            ChatRequest(text="test", provider="a" * 33)

    def test_chat_request_conversation_id(self):
        """Conversation ID is optional."""
        req = ChatRequest(text="test", conversation_id="conv-123")
        assert req.conversation_id == "conv-123"

    def test_chat_request_conversation_id_max_length(self):
        """Conversation ID has max length of 64."""
        with pytest.raises(ValidationError):
            ChatRequest(text="test", conversation_id="a" * 65)

    def test_chat_request_file_ids(self):
        """File IDs is optional list."""
        req = ChatRequest(text="test", file_ids=["file-1", "file-2"])
        assert req.file_ids == ["file-1", "file-2"]

    def test_chat_request_file_ids_max_length(self):
        """File IDs limited to 20."""
        with pytest.raises(ValidationError):
            ChatRequest(text="test", file_ids=["f" + str(i) for i in range(21)])

    def test_chat_request_text_max_length(self):
        """Text at max length is allowed."""
        req = ChatRequest(text="A" * MAX_TEXT_LENGTH)
        assert len(req.text) == MAX_TEXT_LENGTH


# =============================================================================
# CHAT RESPONSE TESTS
# =============================================================================

class TestChatResponse:
    """Tests for ChatResponse model."""

    def test_valid_chat_response(self):
        """Creates valid ChatResponse."""
        resp = ChatResponse(
            user_redacted="What is [NAME_1]'s diagnosis?",
            user_normalized="What is John's diagnosis?",
            assistant_redacted="[NAME_1] has condition X",
            assistant_restored="John has condition X",
            model="claude-sonnet-4",
            provider="anthropic",
            tokens_used=150,
            latency_ms=1200.5,
            spans=[],
        )
        assert resp.model == "claude-sonnet-4"
        assert resp.tokens_used == 150

    def test_chat_response_optional_fields(self):
        """Optional fields can be None."""
        resp = ChatResponse(
            user_redacted="test",
            user_normalized="test",
            assistant_redacted="response",
            assistant_restored="response",
            model="gpt-4",
            provider="openai",
            tokens_used=100,
            latency_ms=500.0,
            spans=[],
            conversation_id=None,
            error=None,
        )
        assert resp.conversation_id is None
        assert resp.error is None


# =============================================================================
# TOKEN INFO TESTS
# =============================================================================

class TestTokenInfo:
    """Tests for TokenInfo model."""

    def test_valid_token_info(self):
        """Creates valid TokenInfo."""
        token = TokenInfo(
            token="[NAME_1]",
            type="NAME",
            safe_harbor="Patient",
        )
        assert token.token == "[NAME_1]"
        assert token.type == "NAME"
        assert token.safe_harbor == "Patient"


# =============================================================================
# UPLOAD RESPONSE TESTS
# =============================================================================

class TestUploadResponse:
    """Tests for UploadResponse model."""

    def test_valid_upload_response(self):
        """Creates valid UploadResponse."""
        resp = UploadResponse(
            job_id="job-123",
            filename="document.pdf",
            status="processing",
        )
        assert resp.job_id == "job-123"
        assert resp.status == "processing"


# =============================================================================
# UPLOAD STATUS RESPONSE TESTS
# =============================================================================

class TestUploadStatusResponse:
    """Tests for UploadStatusResponse model."""

    def test_valid_upload_status(self):
        """Creates valid UploadStatusResponse."""
        resp = UploadStatusResponse(
            job_id="job-123",
            filename="document.pdf",
            status="processing",
            progress=0.5,
            pages_total=10,
            pages_processed=5,
            phi_count=15,
        )
        assert resp.progress == 0.5
        assert resp.pages_total == 10

    def test_upload_status_optional_fields(self):
        """Optional fields default to None."""
        resp = UploadStatusResponse(
            job_id="job-123",
            filename="doc.pdf",
            status="queued",
            progress=0.0,
        )
        assert resp.pages_total is None
        assert resp.pages_processed is None
        assert resp.phi_count is None
        assert resp.error is None


# =============================================================================
# UPLOAD RESULT RESPONSE TESTS
# =============================================================================

class TestUploadResultResponse:
    """Tests for UploadResultResponse model."""

    def test_valid_upload_result(self):
        """Creates valid UploadResultResponse."""
        resp = UploadResultResponse(
            job_id="job-123",
            filename="document.pdf",
            redacted_text="Hello, [NAME_1]",
            spans=[],
            pages=5,
            processing_time_ms=2500.0,
        )
        assert resp.pages == 5
        assert resp.has_redacted_image is False  # default

    def test_upload_result_with_ocr(self):
        """Includes OCR confidence when available."""
        resp = UploadResultResponse(
            job_id="job-123",
            filename="scan.pdf",
            redacted_text="Scanned text",
            spans=[],
            pages=1,
            processing_time_ms=5000.0,
            ocr_confidence=0.92,
            has_redacted_image=True,
        )
        assert resp.ocr_confidence == 0.92
        assert resp.has_redacted_image is True


# =============================================================================
# REVIEW ITEM TESTS
# =============================================================================

class TestReviewItem:
    """Tests for ReviewItem model."""

    def test_valid_review_item(self):
        """Creates valid ReviewItem."""
        item = ReviewItem(
            id="review-1",
            token="[NAME_1]",
            type="NAME",
            confidence=0.7,
            reason="Ambiguous context",
            context_redacted="The [NAME_1] said...",
            suggested="John",
        )
        assert item.confidence == 0.7


# =============================================================================
# AUDIT ENTRY TESTS
# =============================================================================

class TestAuditEntry:
    """Tests for AuditEntry model."""

    def test_valid_audit_entry(self):
        """Creates valid AuditEntry."""
        entry = AuditEntry(
            sequence=1,
            event="REDACT",
            timestamp="2024-01-15T10:30:00Z",
            data={"tokens": 5, "text_length": 100},
        )
        assert entry.sequence == 1
        assert entry.event == "REDACT"


# =============================================================================
# AUDIT VERIFY RESPONSE TESTS
# =============================================================================

class TestAuditVerifyResponse:
    """Tests for AuditVerifyResponse model."""

    def test_valid_verify_response(self):
        """Creates valid AuditVerifyResponse."""
        resp = AuditVerifyResponse(valid=True)
        assert resp.valid is True
        assert resp.error is None

    def test_verify_response_with_error(self):
        """Can include error message."""
        resp = AuditVerifyResponse(valid=False, error="Chain integrity violated")
        assert resp.valid is False
        assert resp.error == "Chain integrity violated"


# =============================================================================
# CONVERSATION CREATE TESTS
# =============================================================================

class TestConversationCreate:
    """Tests for ConversationCreate model."""

    def test_valid_conversation_create(self):
        """Creates valid ConversationCreate."""
        conv = ConversationCreate(title="New Chat")
        assert conv.title == "New Chat"

    def test_conversation_create_optional_title(self):
        """Title is optional."""
        conv = ConversationCreate()
        assert conv.title is None


# =============================================================================
# CONVERSATION UPDATE TESTS
# =============================================================================

class TestConversationUpdate:
    """Tests for ConversationUpdate model."""

    def test_valid_conversation_update(self):
        """Creates valid ConversationUpdate."""
        update = ConversationUpdate(title="Updated Title")
        assert update.title == "Updated Title"

    def test_conversation_update_min_length(self):
        """Title must have at least 1 character."""
        with pytest.raises(ValidationError):
            ConversationUpdate(title="")

    def test_conversation_update_max_length(self):
        """Title has max length of 500."""
        update = ConversationUpdate(title="A" * 500)
        assert len(update.title) == 500

        with pytest.raises(ValidationError):
            ConversationUpdate(title="A" * 501)


# =============================================================================
# CONVERSATION RESPONSE TESTS
# =============================================================================

class TestConversationResponse:
    """Tests for ConversationResponse model."""

    def test_valid_conversation_response(self):
        """Creates valid ConversationResponse."""
        resp = ConversationResponse(
            id="conv-123",
            title="Chat about patient",
            created_at="2024-01-15T10:00:00Z",
            updated_at="2024-01-15T10:30:00Z",
            message_count=5,
        )
        assert resp.id == "conv-123"
        assert resp.message_count == 5


# =============================================================================
# MESSAGE CREATE TESTS
# =============================================================================

class TestMessageCreate:
    """Tests for MessageCreate model."""

    def test_valid_message_create(self):
        """Creates valid MessageCreate."""
        msg = MessageCreate(
            role="user",
            content="What is the diagnosis?",
        )
        assert msg.role == "user"
        assert msg.content == "What is the diagnosis?"

    def test_message_create_role_user(self):
        """Role 'user' is valid."""
        msg = MessageCreate(role="user", content="test")
        assert msg.role == "user"

    def test_message_create_role_assistant(self):
        """Role 'assistant' is valid."""
        msg = MessageCreate(role="assistant", content="test")
        assert msg.role == "assistant"

    def test_message_create_role_system(self):
        """Role 'system' is valid."""
        msg = MessageCreate(role="system", content="test")
        assert msg.role == "system"

    def test_message_create_invalid_role(self):
        """Invalid role is rejected."""
        with pytest.raises(ValidationError):
            MessageCreate(role="invalid", content="test")

    def test_message_create_content_max_length(self):
        """Content has max length."""
        with pytest.raises(ValidationError):
            MessageCreate(role="user", content="A" * (MAX_TEXT_LENGTH + 1))

    def test_message_create_optional_fields(self):
        """Optional fields are None by default."""
        msg = MessageCreate(role="user", content="test")
        assert msg.redacted_content is None
        assert msg.model is None
        assert msg.provider is None


# =============================================================================
# MESSAGE RESPONSE TESTS
# =============================================================================

class TestMessageResponse:
    """Tests for MessageResponse model."""

    def test_valid_message_response(self):
        """Creates valid MessageResponse."""
        resp = MessageResponse(
            id="msg-123",
            conversation_id="conv-456",
            role="assistant",
            content="The diagnosis is...",
            created_at="2024-01-15T10:35:00Z",
        )
        assert resp.id == "msg-123"
        assert resp.role == "assistant"

    def test_message_response_optional_fields(self):
        """Optional fields default to None."""
        resp = MessageResponse(
            id="msg-1",
            conversation_id="conv-1",
            role="user",
            content="test",
            created_at="2024-01-01T00:00:00Z",
        )
        assert resp.redacted_content is None
        assert resp.normalized_content is None
        assert resp.spans is None
        assert resp.model is None
        assert resp.provider is None


# =============================================================================
# CONVERSATION DETAIL RESPONSE TESTS
# =============================================================================

class TestConversationDetailResponse:
    """Tests for ConversationDetailResponse model."""

    def test_valid_conversation_detail(self):
        """Creates valid ConversationDetailResponse."""
        resp = ConversationDetailResponse(
            id="conv-123",
            title="Chat",
            created_at="2024-01-15T10:00:00Z",
            updated_at="2024-01-15T10:30:00Z",
            message_count=2,
            messages=[
                MessageResponse(
                    id="msg-1",
                    conversation_id="conv-123",
                    role="user",
                    content="Hello",
                    created_at="2024-01-15T10:00:00Z",
                ),
                MessageResponse(
                    id="msg-2",
                    conversation_id="conv-123",
                    role="assistant",
                    content="Hi there!",
                    created_at="2024-01-15T10:01:00Z",
                ),
            ],
        )
        assert len(resp.messages) == 2


# =============================================================================
# GREETING RESPONSE TESTS
# =============================================================================

class TestGreetingResponse:
    """Tests for GreetingResponse model."""

    def test_valid_greeting_response(self):
        """Creates valid GreetingResponse."""
        resp = GreetingResponse(greeting="Hello! I'm ready to help.")
        assert resp.greeting == "Hello! I'm ready to help."
        assert resp.cached is False  # default

    def test_greeting_response_cached(self):
        """Can indicate cached response."""
        resp = GreetingResponse(greeting="Cached greeting", cached=True)
        assert resp.cached is True

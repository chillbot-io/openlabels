"""API schemas (Pydantic models) for ScrubIQ."""

from typing import Optional, List
from pydantic import BaseModel, Field

from ...constants import MAX_TEXT_LENGTH


# --- AUTH ---
# Note: Authentication is now handled via API keys (Bearer token)
# UnlockRequest/UnlockResponse removed - no longer needed

class StatusResponse(BaseModel):
    """Current system status."""
    initialized: bool
    unlocked: bool
    timeout_remaining: Optional[int]
    tokens_count: int
    review_pending: int
    models_ready: bool = True
    models_loading: bool = False
    preload_complete: bool = False
    is_new_vault: bool = False
    vault_needs_upgrade: bool = False


# --- CORE (REDACT / RESTORE / CHAT) ---
class RedactRequest(BaseModel):
    """Request to redact PHI from text."""
    text: str = Field(..., max_length=MAX_TEXT_LENGTH)


class SpanInfo(BaseModel):
    """Span detection info."""
    start: int = Field(..., ge=0)
    end: int = Field(..., ge=0)
    text: str
    entity_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    detector: str
    token: Optional[str] = None


class ReviewInfo(BaseModel):
    """Review item info - context is pre-redacted to avoid PHI exposure."""
    id: str
    token: str
    type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str
    context_redacted: str
    suggested: str


class RedactResponse(BaseModel):
    """Response containing redacted text and detection details."""
    redacted_text: str
    normalized_input: str
    spans: List[SpanInfo]
    tokens_created: List[str]
    needs_review: List[ReviewInfo]
    processing_time_ms: float


class RestoreRequest(BaseModel):
    """Request to restore original values from tokens."""
    text: str = Field(..., max_length=MAX_TEXT_LENGTH)
    mode: str = Field("research", pattern="^(redacted|safe_harbor|research)$")


class RestoreResponse(BaseModel):
    """Response with restored text."""
    restored_text: str
    tokens_restored: List[str]
    unknown_tokens: List[str]


class ChatRequest(BaseModel):
    """Request to chat with LLM using PHI-safe pipeline."""
    text: str = Field(..., max_length=MAX_TEXT_LENGTH)
    # SECURITY: Validate model/provider to prevent injection
    model: str = Field(default="claude-sonnet-4", pattern=r"^[a-z0-9._-]{1,64}$")
    provider: Optional[str] = Field(default=None, pattern=r"^[a-z0-9_-]{1,32}$")
    conversation_id: Optional[str] = Field(default=None, max_length=64)
    # SECURITY: Limit number of file IDs to prevent abuse
    file_ids: Optional[List[str]] = Field(default=None, max_length=20)


class ChatResponse(BaseModel):
    """Response from LLM chat with redaction metadata."""
    user_redacted: str
    user_normalized: str
    assistant_redacted: str
    assistant_restored: str
    model: str
    provider: str
    tokens_used: int
    latency_ms: float
    spans: List[SpanInfo]
    conversation_id: Optional[str] = None
    error: Optional[str] = None


class TokenInfo(BaseModel):
    """Token info - NO original PHI exposed."""
    token: str
    type: str
    safe_harbor: str


# --- FILE UPLOADS ---
class UploadResponse(BaseModel):
    """Response when upload starts (async)."""
    job_id: str
    filename: str
    status: str


class UploadStatusResponse(BaseModel):
    """Response for status polling."""
    job_id: str
    filename: str
    status: str
    progress: float
    pages_total: Optional[int] = None
    pages_processed: Optional[int] = None
    phi_count: Optional[int] = None
    error: Optional[str] = None


class UploadResultResponse(BaseModel):
    """Response when upload is complete."""
    job_id: str
    filename: str
    redacted_text: str
    spans: List[SpanInfo]
    pages: int
    processing_time_ms: float
    ocr_confidence: Optional[float] = None
    has_redacted_image: bool = False


# --- REVIEWS & AUDITS ---
class ReviewItem(BaseModel):
    """Item requiring human review (low confidence detection)."""
    id: str
    token: str
    type: str
    confidence: float
    reason: str
    context_redacted: str
    suggested: str


class AuditEntry(BaseModel):
    """Audit log entry with tamper-evident chain."""
    sequence: int
    event: str
    timestamp: str
    data: dict


class AuditVerifyResponse(BaseModel):
    """Response from audit chain verification."""
    valid: bool
    error: Optional[str] = None


# --- CONVERSATIONS ---
class ConversationCreate(BaseModel):
    """Request to create a new conversation."""
    title: Optional[str] = None


class ConversationUpdate(BaseModel):
    """Request to update conversation metadata."""
    title: str = Field(..., min_length=1, max_length=500)


class ConversationResponse(BaseModel):
    id: str
    title: str
    created_at: str
    updated_at: str
    message_count: int


class MessageCreate(BaseModel):
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str = Field(..., max_length=MAX_TEXT_LENGTH)
    redacted_content: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None


class MessageResponse(BaseModel):
    id: str
    conversation_id: str
    role: str
    content: str
    redacted_content: Optional[str] = None
    normalized_content: Optional[str] = None
    spans: Optional[List[SpanInfo]] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    created_at: str


class ConversationDetailResponse(ConversationResponse):
    messages: List[MessageResponse]


# --- ADMIN / MISC ---
class GreetingResponse(BaseModel):
    greeting: str
    cached: bool = False

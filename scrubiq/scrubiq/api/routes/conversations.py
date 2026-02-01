"""Conversation routes."""

from typing import List
from fastapi import APIRouter, Depends, Query, Request

from ...core import ScrubIQ
from ...constants import MAX_PAGINATION_LIMIT, MAX_PAGINATION_OFFSET, API_RATE_WINDOW_SECONDS
from ...rate_limiter import check_rate_limit
from ..dependencies import require_unlocked
from ..errors import not_found, ErrorCode
from .schemas import (
    ConversationCreate, ConversationUpdate, ConversationResponse,
    ConversationDetailResponse, MessageCreate, MessageResponse, SpanInfo,
)

# Rate limits for conversation operations
CONVERSATION_READ_RATE_LIMIT = 120  # Max reads per window
CONVERSATION_RATE_LIMIT = 30  # Max conversation mutations per window
MESSAGE_RATE_LIMIT = 60  # Max message operations per window

router = APIRouter(tags=["conversations"])


def _convert_spans(spans_list):
    """Convert span dicts to SpanInfo objects."""
    if not spans_list:
        return None
    return [
        SpanInfo(
            start=s.get("start", 0),
            end=s.get("end", 0),
            text=s.get("text", ""),
            entity_type=s.get("entity_type", "UNKNOWN"),
            confidence=s.get("confidence", 0.0),
            detector=s.get("detector", "unknown"),
            token=s.get("token"),
        )
        for s in spans_list
    ]


@router.get("/conversations", response_model=List[ConversationResponse])
def list_conversations(
    request: Request,
    limit: int = Query(default=50, ge=1, le=MAX_PAGINATION_LIMIT),
    offset: int = Query(default=0, ge=0, le=MAX_PAGINATION_OFFSET),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """List conversations, most recent first."""
    check_rate_limit(request, action="conversation_read", limit=CONVERSATION_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    convs = cr.list_conversations(limit=limit, offset=offset)
    return [
        ConversationResponse(
            id=c.id,
            title=c.title,
            created_at=c.created_at.isoformat(),
            updated_at=c.updated_at.isoformat(),
            message_count=c.message_count,
        )
        for c in convs
    ]


@router.post("/conversations", response_model=ConversationResponse, status_code=201)
def create_conversation(request: Request, req: ConversationCreate, cr: ScrubIQ = Depends(require_unlocked)):
    """Create a new conversation."""
    check_rate_limit(request, action="conversation", limit=CONVERSATION_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    conv = cr.create_conversation(title=req.title or "New conversation")
    return ConversationResponse(
        id=conv.id,
        title=conv.title,
        created_at=conv.created_at.isoformat(),
        updated_at=conv.updated_at.isoformat(),
        message_count=0,
    )


@router.get("/conversations/{conv_id}", response_model=ConversationDetailResponse)
def get_conversation(request: Request, conv_id: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Get a conversation with its messages."""
    check_rate_limit(request, action="conversation_read", limit=CONVERSATION_READ_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    conv = cr.get_conversation(conv_id)
    if not conv:
        raise not_found("Conversation not found", error_code=ErrorCode.CONVERSATION_NOT_FOUND)

    return ConversationDetailResponse(
        id=conv.id,
        title=conv.title,
        created_at=conv.created_at.isoformat(),
        updated_at=conv.updated_at.isoformat(),
        message_count=conv.message_count,
        messages=[
            MessageResponse(
                id=m.id,
                conversation_id=m.conversation_id,
                role=m.role,
                content=m.content,
                redacted_content=m.redacted_content,
                normalized_content=m.normalized_content,
                spans=_convert_spans(m.spans),
                model=m.model,
                provider=m.provider,
                created_at=m.created_at.isoformat(),
            )
            for m in conv.messages
        ],
    )


@router.patch("/conversations/{conv_id}", response_model=ConversationResponse)
def update_conversation(
    request: Request,
    conv_id: str,
    req: ConversationUpdate,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """Update conversation title."""
    check_rate_limit(request, action="conversation", limit=CONVERSATION_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    success = cr.update_conversation(conv_id, title=req.title)
    if not success:
        raise not_found("Conversation not found", error_code=ErrorCode.CONVERSATION_NOT_FOUND)

    conv = cr.get_conversation(conv_id)
    return ConversationResponse(
        id=conv.id,
        title=conv.title,
        created_at=conv.created_at.isoformat(),
        updated_at=conv.updated_at.isoformat(),
        message_count=conv.message_count,
    )


@router.delete("/conversations/{conv_id}")
def delete_conversation(request: Request, conv_id: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Delete a conversation and all its messages."""
    check_rate_limit(request, action="conversation", limit=CONVERSATION_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    success = cr.delete_conversation(conv_id)
    if not success:
        raise not_found("Conversation not found", error_code=ErrorCode.CONVERSATION_NOT_FOUND)
    return {"success": True}


@router.post("/conversations/{conv_id}/messages", response_model=MessageResponse, status_code=201)
def add_message(request: Request, conv_id: str, req: MessageCreate, cr: ScrubIQ = Depends(require_unlocked)):
    """Add a message to a conversation."""
    check_rate_limit(request, action="message", limit=MESSAGE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    conv = cr.get_conversation(conv_id, include_messages=False)
    if not conv:
        raise not_found("Conversation not found", error_code=ErrorCode.CONVERSATION_NOT_FOUND)

    msg = cr.add_message(
        conv_id=conv_id,
        role=req.role,
        content=req.content,
        redacted_content=req.redacted_content,
        model=req.model,
        provider=req.provider,
    )

    return MessageResponse(
        id=msg.id,
        conversation_id=msg.conversation_id,
        role=msg.role,
        content=msg.content,
        redacted_content=msg.redacted_content,
        model=msg.model,
        provider=msg.provider,
        created_at=msg.created_at.isoformat(),
    )


@router.delete("/conversations/{conv_id}/messages/{msg_id}")
def delete_message(request: Request, conv_id: str, msg_id: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Delete a specific message."""
    check_rate_limit(request, action="message", limit=MESSAGE_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    success = cr.delete_message(msg_id)
    if not success:
        raise not_found("Message not found", error_code=ErrorCode.MESSAGE_NOT_FOUND)
    return {"success": True}

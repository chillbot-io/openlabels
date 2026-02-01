"""Memory and search routes."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from ...core import ScrubIQ
from ...constants import API_RATE_WINDOW_SECONDS
from ...rate_limiter import check_rate_limit
from ..dependencies import require_unlocked
from ..errors import not_found, bad_request, service_unavailable, ErrorCode

# Rate limits for memory operations
SEARCH_RATE_LIMIT = 60  # Max searches per window
MEMORY_RATE_LIMIT = 30  # Max memory mutations per window


router = APIRouter(tags=["memory"])


# --- SCHEMAS ---
class MemoryResponse(BaseModel):
    """A stored memory/fact."""
    id: str
    conversation_id: str
    entity_token: Optional[str]
    fact: str
    category: str
    confidence: float
    source_message_id: Optional[str]
    created_at: str


class MemoryCreate(BaseModel):
    """Create a new memory manually."""
    fact: str = Field(..., min_length=5, max_length=500)
    category: str = Field(default="general")
    entity_token: Optional[str] = None
    confidence: float = Field(default=0.9, ge=0.5, le=1.0)


class SearchResult(BaseModel):
    """A search result from conversation history."""
    content: str
    conversation_id: str
    conversation_title: str
    role: str
    relevance: float
    created_at: str


class MemoryStats(BaseModel):
    """Memory system statistics."""
    total: int
    by_category: dict
    top_entities: dict


class ExtractResult(BaseModel):
    """Result of memory extraction."""
    conversation_id: str
    memories_extracted: int


# --- SEARCH ROUTES ---
@router.get("/search", response_model=List[SearchResult])
def search_conversations(
    request: Request,
    q: str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(default=10, ge=1, le=50),
    exclude_current: bool = Query(default=True),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Search across conversation history.

    Uses full-text search (FTS5) on redacted message content.
    Results are ranked by relevance.
    """
    check_rate_limit(request, action="search", limit=SEARCH_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    results = cr.search_conversations(
        query=q,
        exclude_current=exclude_current,
        limit=limit,
    )

    return [
        SearchResult(
            content=r["content"],
            conversation_id=r["conversation_id"],
            conversation_title=r["conversation_title"],
            role=r["role"],
            relevance=r["relevance"],
            created_at=r["created_at"],
        )
        for r in results
    ]


# --- MEMORY ROUTES ---
@router.get("/memories", response_model=List[MemoryResponse])
def list_memories(
    entity_token: Optional[str] = Query(default=None, description="Filter by entity token"),
    category: Optional[str] = Query(default=None, description="Filter by category"),
    limit: int = Query(default=50, ge=1, le=200),
    min_confidence: float = Query(default=0.7, ge=0.0, le=1.0),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    List stored memories/facts.

    Memories are facts extracted from conversations, stored for
    Claude-like recall across sessions.
    """
    if not hasattr(cr, '_memory') or not cr._memory:
        return []

    memories = cr._memory.get_memories(
        entity_token=entity_token,
        category=category,
        limit=limit,
        min_confidence=min_confidence,
    )

    return [
        MemoryResponse(
            id=m.id,
            conversation_id=m.conversation_id,
            entity_token=m.entity_token,
            fact=m.fact,
            category=m.category,
            confidence=m.confidence,
            source_message_id=m.source_message_id,
            created_at=m.created_at.isoformat(),
        )
        for m in memories
    ]


@router.post("/memories", response_model=MemoryResponse, status_code=201)
def create_memory(
    request: Request,
    req: MemoryCreate,
    conversation_id: Optional[str] = Query(default=None, description="Associated conversation"),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Manually add a memory/fact.

    Typically memories are extracted automatically, but this allows
    manual addition for corrections or explicit user instructions.
    """
    check_rate_limit(request, action="memory", limit=MEMORY_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not hasattr(cr, '_memory') or not cr._memory:
        raise service_unavailable("Memory system not available", error_code=ErrorCode.SERVICE_UNAVAILABLE)

    # Use current conversation or a placeholder
    conv_id = conversation_id or cr._current_conversation_id or "manual"

    memory = cr._memory.add_memory(
        conversation_id=conv_id,
        fact=req.fact,
        category=req.category,
        entity_token=req.entity_token,
        confidence=req.confidence,
    )

    return MemoryResponse(
        id=memory.id,
        conversation_id=memory.conversation_id,
        entity_token=memory.entity_token,
        fact=memory.fact,
        category=memory.category,
        confidence=memory.confidence,
        source_message_id=memory.source_message_id,
        created_at=memory.created_at.isoformat(),
    )


@router.delete("/memories/{memory_id}")
def delete_memory(
    request: Request,
    memory_id: str,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """Delete a specific memory."""
    check_rate_limit(request, action="memory", limit=MEMORY_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not hasattr(cr, '_memory') or not cr._memory:
        raise service_unavailable("Memory system not available", error_code=ErrorCode.SERVICE_UNAVAILABLE)

    success = cr._memory.delete_memory(memory_id)
    if not success:
        raise not_found("Memory not found", error_code=ErrorCode.MEMORY_NOT_FOUND)

    return {"success": True}


@router.delete("/memories")
def clear_memories(
    request: Request,
    conversation_id: Optional[str] = Query(default=None, description="Clear only for this conversation"),
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Clear memories.

    If conversation_id provided, clears only that conversation's memories.
    Otherwise clears all memories (use with caution).
    """
    check_rate_limit(request, action="memory", limit=MEMORY_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not hasattr(cr, '_memory') or not cr._memory:
        raise service_unavailable("Memory system not available", error_code=ErrorCode.SERVICE_UNAVAILABLE)

    if conversation_id:
        count = cr._memory.delete_memories_for_conversation(conversation_id)
        return {"success": True, "deleted": count}
    else:
        raise bad_request("Must specify conversation_id to clear memories", error_code=ErrorCode.MISSING_FIELD)


@router.get("/memories/stats", response_model=MemoryStats)
def get_memory_stats(
    request: Request,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """Get memory system statistics."""
    check_rate_limit(request, action="memory", limit=MEMORY_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    if not hasattr(cr, '_memory') or not cr._memory:
        return MemoryStats(total=0, by_category={}, top_entities={})

    stats = cr._memory.get_memory_stats()
    return MemoryStats(**stats)


# --- EXTRACTION ROUTES ---
@router.post("/memories/extract/{conversation_id}", response_model=ExtractResult)
async def extract_memories(
    request: Request,
    conversation_id: str,
    cr: ScrubIQ = Depends(require_unlocked),
):
    """
    Extract memories from a conversation.

    Uses LLM to analyze the conversation and extract structured facts.
    This is typically run automatically after conversations, but can
    be triggered manually.
    """
    check_rate_limit(request, action="memory_extract", limit=10, window_seconds=API_RATE_WINDOW_SECONDS)
    count = await cr.extract_memories_from_conversation(conversation_id)

    return ExtractResult(
        conversation_id=conversation_id,
        memories_extracted=count,
    )

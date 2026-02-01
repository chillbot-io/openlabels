"""API routes package.

Combines all route modules into a single router.
"""

from fastapi import APIRouter

from .auth import router as auth_router
from .core import router as core_router
from .reviews import router as reviews_router
from .files import router as files_router
from .conversations import router as conversations_router
from .admin import router as admin_router
from .memory import router as memory_router
from .config import router as config_router
from .keys import router as keys_router

# Main router that combines all sub-routers
router = APIRouter()

# Include all route modules
router.include_router(auth_router)
router.include_router(core_router)
router.include_router(reviews_router)
router.include_router(files_router)
router.include_router(conversations_router)
router.include_router(admin_router)
router.include_router(memory_router)
router.include_router(config_router)
router.include_router(keys_router)

# Re-export schemas for convenience
from .schemas import (
    StatusResponse,
    RedactRequest, RedactResponse, SpanInfo, ReviewInfo,
    RestoreRequest, RestoreResponse,
    ChatRequest, ChatResponse,
    TokenInfo,
    UploadResponse, UploadStatusResponse, UploadResultResponse,
    ReviewItem, AuditEntry, AuditVerifyResponse,
    ConversationCreate, ConversationUpdate, ConversationResponse,
    ConversationDetailResponse, MessageCreate, MessageResponse,
    GreetingResponse,
)

__all__ = [
    "router",
    # Schemas
    "StatusResponse",
    "RedactRequest", "RedactResponse", "SpanInfo", "ReviewInfo",
    "RestoreRequest", "RestoreResponse",
    "ChatRequest", "ChatResponse",
    "TokenInfo",
    "UploadResponse", "UploadStatusResponse", "UploadResultResponse",
    "ReviewItem", "AuditEntry", "AuditVerifyResponse",
    "ConversationCreate", "ConversationUpdate", "ConversationResponse",
    "ConversationDetailResponse", "MessageCreate", "MessageResponse",
    "GreetingResponse",
]

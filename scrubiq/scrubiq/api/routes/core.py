"""Core routes: redact, restore, chat, tokens."""

import json
import logging
import re
import time
from typing import List
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from ...core import ScrubIQ
from ...prompts import SYSTEM_PROMPT
from ...types import PrivacyMode
from ...rate_limiter import check_rate_limit
from ...constants import (
    MAX_CONTEXT_TOKENS, CHARS_PER_TOKEN, RESPONSE_TOKEN_RESERVE,
    REDACT_RATE_LIMIT, CHAT_RATE_LIMIT, API_RATE_WINDOW_SECONDS,
)
from ..dependencies import require_unlocked
from ..errors import not_found, bad_request, server_error, ErrorCode
from .schemas import (
    RedactRequest, RedactResponse, SpanInfo, ReviewInfo,
    RestoreRequest, RestoreResponse,
    ChatRequest, ChatResponse,
    TokenInfo,
)

# SSE stream safety limits
SSE_MAX_RESPONSE_CHARS = 500_000  # 500KB max response size
SSE_TIMEOUT_SECONDS = 300  # 5 minute timeout for streaming

logger = logging.getLogger(__name__)
router = APIRouter(tags=["core"])


@router.post("/redact", response_model=RedactResponse)
def redact(
    req: RedactRequest,
    request: Request,
    cr: ScrubIQ = Depends(require_unlocked)
):
    """Detect and redact PHI/PII from text."""
    check_rate_limit(request, action="redact", limit=REDACT_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)

    try:
        result = cr.redact(req.text)
    except ValueError as e:
        # Input validation errors
        logger.warning(f"Redaction validation error: {e}")
        raise bad_request(str(e), error_code=ErrorCode.VALIDATION_ERROR)
    except Exception as e:
        # Catch detector/pipeline errors to prevent stack trace exposure
        logger.exception("Redaction failed unexpectedly")
        raise server_error(
            detail="Redaction processing failed. Please try again.",
            error_code=ErrorCode.INTERNAL_ERROR,
        )

    return RedactResponse(
        redacted_text=result.redacted,
        normalized_input=result.normalized_input,
        spans=[SpanInfo(
            start=s.start,
            end=s.end,
            text=s.text,
            entity_type=s.entity_type,
            confidence=s.confidence,
            detector=s.detector,
            token=s.token,
        ) for s in result.spans],
        tokens_created=result.tokens_created,
        needs_review=[ReviewInfo(**r) for r in result.needs_review],
        processing_time_ms=result.processing_time_ms,
    )


@router.post("/restore", response_model=RestoreResponse)
def restore(req: RestoreRequest, cr: ScrubIQ = Depends(require_unlocked)):
    """Restore tokens to PHI values."""
    mode_map = {
        "redacted": PrivacyMode.REDACTED,
        "safe_harbor": PrivacyMode.SAFE_HARBOR,
        "research": PrivacyMode.RESEARCH,
    }
    mode = mode_map.get(req.mode, PrivacyMode.RESEARCH)
    result = cr.restore(req.text, mode)

    return RestoreResponse(
        restored_text=result.restored,
        tokens_restored=result.tokens_found,
        unknown_tokens=result.tokens_unknown,
    )


@router.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    request: Request,
    cr: ScrubIQ = Depends(require_unlocked)
):
    """Full chat flow: redact user message → LLM → restore response."""
    check_rate_limit(request, action="chat", limit=CHAT_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)
    message = req.text

    try:
        if req.file_ids:
            # PERFORMANCE FIX: Batch fetch all file results in single operation (N+1 fix)
            results = cr.get_upload_results_batch(req.file_ids)
            file_contents = []
            for job_id in req.file_ids:
                result = results.get(job_id)
                if result and result.get("redacted_text"):
                    filename = result.get("filename", "document")
                    file_contents.append(f"[{filename}]\n{result['redacted_text']}")

            if file_contents:
                files_section = "\n\n---\n".join(file_contents)
                message = f"Attached document(s):\n\n{files_section}\n\n---\n\nQuery: {req.text}"

        result = cr.chat(
            message=message,
            model=req.model,
            provider=req.provider,
            conversation_id=req.conversation_id,
        )
    except ValueError as e:
        # Input validation errors
        logger.warning(f"Chat validation error: {e}")
        raise bad_request(str(e), error_code=ErrorCode.VALIDATION_ERROR)
    except Exception as e:
        # Catch LLM/pipeline errors to prevent stack trace exposure
        logger.exception("Chat failed unexpectedly")
        raise server_error(
            detail="Chat processing failed. Please try again.",
            error_code=ErrorCode.INTERNAL_ERROR,
        )

    return ChatResponse(
        user_redacted=result.redacted_request,
        user_normalized=result.normalized_input,
        assistant_redacted=result.response_text,
        assistant_restored=result.restored_response,
        model=result.model,
        provider=result.provider,
        tokens_used=result.tokens_used,
        latency_ms=result.latency_ms,
        spans=[SpanInfo(
            start=s.start,
            end=s.end,
            text=s.text,
            entity_type=s.entity_type,
            confidence=s.confidence,
            detector=s.detector,
            token=s.token,
        ) for s in result.spans],
        conversation_id=result.conversation_id,
        error=result.error,
    )


@router.post("/chat/stream")
def chat_stream(
    req: ChatRequest,
    request: Request,
    cr: ScrubIQ = Depends(require_unlocked)
):
    """Streaming chat flow with SSE."""
    check_rate_limit(request, action="chat", limit=CHAT_RATE_LIMIT, window_seconds=API_RATE_WINDOW_SECONDS)

    def estimate_tokens(text: str) -> int:
        return len(text) // CHARS_PER_TOKEN
    
    def build_context_messages(conv_id: str, current_redacted: str, system_prompt: str) -> list:
        messages = [{"role": "system", "content": system_prompt}]
        
        conv = cr.get_conversation(conv_id, include_messages=True)
        if not conv or not conv.messages:
            messages.append({"role": "user", "content": current_redacted})
            return messages
        
        system_tokens = estimate_tokens(system_prompt)
        current_tokens = estimate_tokens(current_redacted)
        available_tokens = MAX_CONTEXT_TOKENS - system_tokens - current_tokens - RESPONSE_TOKEN_RESERVE
        
        history_messages = []
        total_tokens = 0
        
        for msg in reversed(conv.messages):
            content = msg.redacted_content or msg.content
            if not content:
                continue
            
            msg_tokens = estimate_tokens(content)
            if total_tokens + msg_tokens > available_tokens:
                break
            
            history_messages.append({"role": msg.role, "content": content})
            total_tokens += msg_tokens
        
        history_messages.reverse()
        messages.extend(history_messages)
        messages.append({"role": "user", "content": current_redacted})
        
        return messages
    
    def generate():
        try:
            message = req.text
            
            if req.file_ids:
                # PERFORMANCE FIX: Batch fetch all file results in single operation (N+1 fix)
                results = cr.get_upload_results_batch(req.file_ids)
                file_contents = []
                for job_id in req.file_ids:
                    result = results.get(job_id)
                    if result and result.get("redacted_text"):
                        filename = result.get("filename", "document")
                        redacted_text = result['redacted_text']
                        file_contents.append(f"[{filename}]\n{redacted_text}")

                if file_contents:
                    files_section = "\n\n---\n".join(file_contents)
                    message = f"Attached document(s):\n\n{files_section}\n\n---\n\nQuery: {req.text}"
            
            # Ensure conversation context
            if req.conversation_id:
                cr.set_current_conversation(req.conversation_id)
            elif cr._current_conversation_id is None:
                title_source = req.text.strip()
                if len(title_source) > 50:
                    title = title_source[:50].rsplit(' ', 1)[0] + '...'
                else:
                    title = title_source if title_source else "New conversation"
                cr.create_conversation(title)
            
            redaction = cr.redact(message)
            
            all_spans = [
                {
                    "start": s.start,
                    "end": s.end,
                    "text": s.text,
                    "entity_type": s.entity_type,
                    "confidence": s.confidence,
                    "detector": s.detector,
                    "token": s.token,
                }
                for s in redaction.spans
            ]
            
            # Send redaction info to frontend
            # Note: user_original is needed for "Show Original" toggle in UI
            redaction_event = {
                "type": "redaction",
                "user_original": message,  # Original text for privacy mode toggle
                "user_redacted": redaction.redacted,
                "user_normalized": redaction.normalized_input,
                "spans": all_spans,
                "conversation_id": cr._current_conversation_id,
                "has_phi": len(all_spans) > 0,
            }
            yield f"data: {json.dumps(redaction_event)}\n\n"
            
            messages = build_context_messages(
                conv_id=cr._current_conversation_id,
                current_redacted=redaction.redacted,
                system_prompt=SYSTEM_PROMPT
            )
            
            if cr._llm_loading:
                raise RuntimeError("MODELS_LOADING")
            
            llm_client = cr.get_llm_client(provider=req.provider, model=req.model)
            if not llm_client:
                raise RuntimeError("LLM client not initialized")
            if not llm_client.is_available():
                provider_name = req.provider or "inferred"
                raise RuntimeError(f"LLM provider '{provider_name}' not available - check API key")
            
            full_response = ""
            stream_start = time.monotonic()
            for chunk in llm_client.chat_stream(messages=messages, model=req.model):
                if chunk is None:
                    break
                full_response += chunk

                # Safety limits to prevent DoS via unbounded streams
                if len(full_response) > SSE_MAX_RESPONSE_CHARS:
                    logger.warning("SSE response exceeded max size, truncating")
                    truncate_event = {
                        "type": "truncated",
                        "reason": "max_size_exceeded",
                        "message": "Response exceeded maximum size limit and was truncated",
                    }
                    yield f"data: {json.dumps(truncate_event)}\n\n"
                    break
                if time.monotonic() - stream_start > SSE_TIMEOUT_SECONDS:
                    logger.warning("SSE stream timed out")
                    timeout_event = {
                        "type": "truncated",
                        "reason": "timeout",
                        "message": "Response stream timed out and was truncated",
                    }
                    yield f"data: {json.dumps(timeout_event)}\n\n"
                    break

                token_event = {"type": "token", "text": chunk}
                yield f"data: {json.dumps(token_event)}\n\n"
            
            restored = cr.restore(full_response, PrivacyMode.RESEARCH)
            
            token_pattern = re.compile(r'\[([A-Z][A-Z0-9_]*_\d+)\]')
            assistant_spans = []
            for match in token_pattern.finditer(full_response):
                token_name = f"[{match.group(1)}]"
                entity_type = match.group(1).rsplit('_', 1)[0]
                assistant_spans.append({
                    "start": match.start(),
                    "end": match.end(),
                    "text": token_name,
                    "entity_type": entity_type,
                    "confidence": 1.0,
                    "detector": "token_reference",
                    "token": token_name,
                })
            
            cr.add_message(
                conv_id=cr._current_conversation_id,
                role="user",
                content=message,
                redacted_content=redaction.redacted,
                normalized_content=redaction.normalized_input,
                spans=all_spans,
            )
            
            cr.add_message(
                conv_id=cr._current_conversation_id,
                role="assistant",
                content=restored.restored,
                redacted_content=full_response,
                model=req.model,
                provider=llm_client.provider,
                spans=assistant_spans,
            )
            
            done_event = {
                "type": "done",
                "assistant_redacted": full_response,
                "assistant_restored": restored.restored,
                "assistant_spans": assistant_spans,
            }
            yield f"data: {json.dumps(done_event)}\n\n"
            
        except Exception as e:
            # SECURITY: Log full error server-side, return generic message to client
            # Never expose raw error messages - they may leak internal state
            logger.error(f"Stream error: {type(e).__name__}: {e}")
            error_msg = str(e).lower()

            # Map to safe user-friendly messages only
            if "models_loading" in error_msg:
                user_error = "Models are still loading. Please wait a moment."
            elif "not initialized" in error_msg:
                user_error = "Service not ready. Please try again."
            elif "not available" in error_msg or "provider" in error_msg:
                # SECURITY: Don't expose which provider or why - just say unavailable
                user_error = "LLM service temporarily unavailable. Please try again."
            elif "api key" in error_msg or "authentication" in error_msg:
                user_error = "LLM service configuration error. Contact administrator."
            elif "rate limit" in error_msg:
                user_error = "Request rate limited. Please wait before retrying."
            elif "timeout" in error_msg:
                user_error = "Request timed out. Please try again."
            else:
                user_error = "An error occurred processing your request."

            error_event = {
                "type": "error",
                "error": user_error,
            }
            yield f"data: {json.dumps(error_event)}\n\n"
    
    return StreamingResponse(generate(), media_type="text/event-stream")


@router.get("/tokens", response_model=List[TokenInfo])
def list_tokens(cr: ScrubIQ = Depends(require_unlocked)):
    """List all tokens in session."""
    return [TokenInfo(**t) for t in cr.get_tokens()]


@router.delete("/tokens/{token}")
def delete_token(token: str, cr: ScrubIQ = Depends(require_unlocked)):
    """Delete a token (false positive correction)."""
    decoded_token = unquote(token)
    success = cr.delete_token(decoded_token)
    if not success:
        raise not_found("Token not found", error_code=ErrorCode.TOKEN_NOT_FOUND)
    return {"success": True}

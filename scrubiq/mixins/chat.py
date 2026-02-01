"""Chat and LLM interaction mixin for ScrubIQ."""

import logging
from typing import List, Dict, Optional, TYPE_CHECKING

from ..types import ChatResult, PrivacyMode
from ..prompts import SYSTEM_PROMPT
from ..constants import (
    CROSS_CONVERSATION_CONTEXT_COUNT,
    CONTEXT_PREVIEW_LENGTH,
    CONTEXT_CONVERSATIONS_LIMIT,
    MAX_TITLE_LENGTH,
    TITLE_CONTEXT_USER_LENGTH,
    TITLE_CONTEXT_ASSISTANT_LENGTH,
    TITLE_CONTEXT_SOLO_LENGTH,
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_ANTHROPIC_FAST_MODEL,
)
from ..llm_client import LLMResponse

if TYPE_CHECKING:
    from ..storage.memory import MemoryStore

logger = logging.getLogger(__name__)


class ChatMixin:
    """
    Chat operations including LLM calls.
    
    Requires these attributes on the class:
        _require_unlock: Callable
        _conversations: ConversationStore
        _llm_client: Optional[AnthropicClient]
        _gateway: Optional[GatewayClient]
        _llm_loading: bool
        _memory: Optional[MemoryStore]
        redact: Callable
        restore: Callable
        create_conversation: Callable
        set_current_conversation: Callable
    """

    def _get_memory_context(self) -> str:
        """Get extracted memories for context injection."""
        if not hasattr(self, '_memory') or not self._memory:
            return ""
        
        try:
            memories = self._memory.get_memories_for_context(limit=10)
            if not memories:
                return ""
            
            lines = []
            for mem in memories:
                if mem.entity_token:
                    lines.append(f"- {mem.entity_token}: {mem.fact}")
                else:
                    lines.append(f"- {mem.fact}")
            
            return "\n\nRelevant information from previous conversations:\n" + "\n".join(lines)
        except Exception as e:
            logger.warning(f"Failed to get memory context: {e}")
            return ""

    def _get_cross_conversation_context(self, exclude_conv_id: Optional[str] = None) -> List[Dict[str, str]]:
        """Get last N messages from previous conversations for context."""
        try:
            # Use memory store if available for better retrieval
            memory = getattr(self, '_memory', None)
            if memory is not None:
                return memory.get_recent_context(
                    exclude_conversation_id=exclude_conv_id,
                    limit=CROSS_CONVERSATION_CONTEXT_COUNT,
                )

            # Fallback to direct conversation query
            conversations = getattr(self, '_conversations', None)
            if conversations is None:
                return []

            messages = []
            convs = conversations.list(limit=10)

            for conv in convs:
                if exclude_conv_id and conv.id == exclude_conv_id:
                    continue

                conv_messages = conversations.get_messages(conv.id)
                for msg in conv_messages:
                    # SECURITY: Ensure redacted_content exists and is non-empty
                    if msg.redacted_content and msg.role in ('user', 'assistant'):
                        messages.append({
                            "role": msg.role,
                            "content": msg.redacted_content,
                        })
                        if len(messages) >= CROSS_CONVERSATION_CONTEXT_COUNT:
                            return messages

            return messages
        except Exception as e:
            logger.warning(f"Failed to get cross-conversation context: {e}")
            return []

    def _build_llm_messages(
        self,
        conv_id: Optional[str],
        new_message_redacted: str,
    ) -> List[Dict[str, str]]:
        """Build full message array for LLM request."""
        messages = []
        
        # Start with system prompt
        system_content = SYSTEM_PROMPT
        
        # Add extracted memories (Claude-style)
        memory_context = self._get_memory_context()
        if memory_context:
            system_content += memory_context
        
        # Add cross-conversation context if enabled
        if CROSS_CONVERSATION_CONTEXT_COUNT > 0:
            cross_context = self._get_cross_conversation_context(exclude_conv_id=conv_id)
            if cross_context:
                system_content += "\n\nRecent context from previous conversations:\n"
                for ctx_msg in cross_context:
                    role_label = "User" if ctx_msg["role"] == "user" else "Assistant"
                    content_preview = ctx_msg['content'][:CONTEXT_PREVIEW_LENGTH]
                    if len(ctx_msg['content']) > CONTEXT_PREVIEW_LENGTH:
                        content_preview += '...'
                    system_content += f"- {role_label}: {content_preview}\n"
        
        messages.append({"role": "system", "content": system_content})
        
        # Add current conversation history
        if conv_id and self._conversations:
            conv_messages = self._conversations.get_messages(conv_id)
            for msg in conv_messages:
                if msg.redacted_content and msg.role in ('user', 'assistant'):
                    messages.append({
                        "role": msg.role,
                        "content": msg.redacted_content,
                    })
        
        # Add new message
        messages.append({"role": "user", "content": new_message_redacted})
        
        return messages

    def generate_title(
        self,
        user_message: str,
        assistant_response: Optional[str] = None,
        max_length: int = MAX_TITLE_LENGTH
    ) -> str:
        """
        Generate a conversation title using LLM.
        
        Uses both the user's first message and assistant's response
        for better context when generating the title.
        
        Args:
            user_message: The user's first message (redacted)
            assistant_response: The assistant's response (redacted, optional)
            max_length: Maximum title length
        
        Returns:
            Generated title string
        """
        def truncate(s: str, n: int) -> str:
            if len(s) <= n:
                return s
            return s[:n-3].rsplit(' ', 1)[0] + '...'
        
        # Fallback if no LLM available
        if not self._llm_client or not self._llm_client.is_available():
            return truncate(user_message, max_length)
        
        # Build context for title generation
        if assistant_response:
            context = f"User: {user_message[:TITLE_CONTEXT_USER_LENGTH]}\n\nAssistant: {assistant_response[:TITLE_CONTEXT_ASSISTANT_LENGTH]}"
        else:
            context = user_message[:TITLE_CONTEXT_SOLO_LENGTH]
        
        try:
            response = self._llm_client.chat(
                messages=[{
                    "role": "user",
                    "content": f"""Generate a short, descriptive title for this conversation.

Rules:
- Maximum 6 words
- No punctuation at the end
- Capture the main topic or intent
- Use natural language, not technical jargon
- Don't include tokens like [PATIENT_1] in the title - describe the topic instead

Conversation:
{context}

Title:"""
                }],
                model=DEFAULT_ANTHROPIC_FAST_MODEL,
            )

            if response.success and response.text:
                title = response.text.strip()
                # Clean up common LLM quirks
                title = title.strip('"\'')
                title = title.rstrip('.')
                # Remove "Title:" prefix if LLM included it
                if title.lower().startswith('title:'):
                    title = title[6:].strip()
                return truncate(title, max_length)
        except Exception as e:
            logger.warning(f"Title generation failed: {e}")
        
        return truncate(user_message, max_length)

    def chat(
        self,
        message: str,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        provider: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> ChatResult:
        """
        End-to-end: redact → LLM → restore.
        
        Includes memory context injection for Claude-like recall.
        """
        self._require_unlock()
        
        if self._llm_loading:
            raise RuntimeError("MODELS_LOADING")

        conv_id = conversation_id
        is_new_conversation = False
        if not conv_id:
            conv = self.create_conversation(title="New conversation")
            conv_id = conv.id
            is_new_conversation = True
        else:
            self.set_current_conversation(conv_id)

        # Redact user message
        redaction = self.redact(message)
        
        # Build LLM messages with memory context
        llm_messages = self._build_llm_messages(conv_id, redaction.redacted)
        
        from ..logging_utils import get_phi_safe_logger
        _logger = get_phi_safe_logger(__name__)
        _logger.info_safe(
            "Chat request",
            tokens_created=len(redaction.tokens_created),
            spans_detected=len(redaction.spans),
            message_count=len(llm_messages),
        )

        # Call LLM
        if self._llm_client and self._llm_client.is_available():
            response = self._llm_client.chat(
                messages=llm_messages,
                model=model,
            )
        elif self._gateway is not None:
            gw_response = self._gateway.chat(
                messages=llm_messages,
                model=model,
            )
            response = LLMResponse(
                success=gw_response.success,
                text=gw_response.text,
                model=gw_response.model,
                provider="gateway",
                tokens_used=gw_response.tokens_used,
                latency_ms=gw_response.latency_ms,
                error=gw_response.error,
            )
        else:
            # No LLM provider - still store the user message before returning error
            if self._conversations:
                spans_data = [
                    {
                        "start": s.start,
                        "end": s.end,
                        "entity_type": s.entity_type,
                        "confidence": s.confidence,
                        "detector": s.detector,
                        "token": s.token,
                    }
                    for s in redaction.spans
                ] if redaction.spans else None

                self._conversations.add_message(
                    conv_id=conv_id,
                    role="user",
                    content=message,
                    redacted_content=redaction.redacted,
                    normalized_content=redaction.normalized_input,
                    spans=spans_data,
                    model=model,
                    provider="none",
                )

            return ChatResult(
                request_text=message,
                redacted_request=redaction.redacted,
                response_text="",
                restored_response="",
                model=model,
                provider="anthropic",
                tokens_used=0,
                latency_ms=0,
                spans=redaction.spans,
                conversation_id=conv_id,
                error="No LLM provider configured. Set ANTHROPIC_API_KEY.",
                normalized_input=redaction.normalized_input,
            )

        # Restore tokens in response
        restored = ""
        if response.success:
            restoration = self.restore(response.text, PrivacyMode.RESEARCH)
            restored = restoration.restored
            
            _logger.info_safe(
                "Chat response restored",
                tokens_found=len(restoration.tokens_found),
                tokens_unknown=len(restoration.tokens_unknown),
            )

        # Store messages in conversation
        if self._conversations:
            spans_data = [
                {
                    "start": s.start,
                    "end": s.end,
                    "entity_type": s.entity_type,
                    "confidence": s.confidence,
                    "detector": s.detector,
                    "token": s.token,
                }
                for s in redaction.spans
            ] if redaction.spans else None
            
            # Store user message
            self._conversations.add_message(
                conv_id=conv_id,
                role="user",
                content=message,
                redacted_content=redaction.redacted,
                normalized_content=redaction.normalized_input,
                spans=spans_data,
                model=model,
                provider=response.provider,
            )
            
            # Store assistant message
            if response.success:
                self._conversations.add_message(
                    conv_id=conv_id,
                    role="assistant",
                    content=restored,
                    redacted_content=response.text,
                    model=response.model,
                    provider=response.provider,
                )
            
            # Generate title for new conversations using both messages
            if is_new_conversation and response.success:
                title = self.generate_title(
                    user_message=redaction.redacted,
                    assistant_response=response.text,
                )
                self._conversations.update(conv_id, title=title)
                _logger.info_safe("Generated conversation title", title_length=len(title))

        return ChatResult(
            request_text=message,
            redacted_request=redaction.redacted,
            response_text=response.text,
            restored_response=restored,
            model=response.model,
            provider=response.provider,
            tokens_used=response.tokens_used,
            latency_ms=response.latency_ms,
            spans=redaction.spans,
            conversation_id=conv_id,
            error=response.error,
            normalized_input=redaction.normalized_input,
        )

    def search_conversations(
        self,
        query: str,
        exclude_current: bool = True,
        limit: int = 10,
    ) -> List[Dict]:
        """
        Search across conversation history.
        
        Args:
            query: Search query
            exclude_current: Exclude current conversation from results
            limit: Maximum results
        
        Returns:
            List of search results with content, conversation_id, and relevance
        """
        self._require_unlock()
        
        if not hasattr(self, '_memory') or not self._memory:
            return []
        
        exclude_id = None
        if exclude_current and hasattr(self, '_current_conversation_id'):
            exclude_id = self._current_conversation_id
        
        results = self._memory.search_messages(
            query=query,
            exclude_conversation_id=exclude_id,
            limit=limit,
        )
        
        return [
            {
                "content": r.content,
                "conversation_id": r.conversation_id,
                "conversation_title": r.conversation_title,
                "role": r.role,
                "relevance": r.relevance,
                "created_at": r.created_at.isoformat(),
            }
            for r in results
        ]

    async def extract_memories_from_conversation(self, conversation_id: str) -> int:
        """
        Extract and store memories from a conversation.
        
        Called after conversation ends or on-demand.
        
        Returns:
            Number of memories extracted
        """
        self._require_unlock()
        
        if not hasattr(self, '_memory_extractor') or not self._memory_extractor:
            return 0
        
        conv = self._conversations.get(conversation_id)
        if not conv or not conv.messages:
            return 0
        
        # Build message list (redacted content only)
        messages = [
            {"role": m.role, "content": m.redacted_content}
            for m in conv.messages
            if m.redacted_content and m.role in ('user', 'assistant')
        ]
        
        memories = await self._memory_extractor.extract_from_conversation(
            conversation_id=conversation_id,
            messages=messages,
        )
        
        return len(memories)

"""Human review queue for uncertain detections."""

import uuid
from datetime import datetime
from typing import List, Optional

from ..types import Span, ReviewItem, ReviewReason, Tier


class ReviewQueue:
    """
    Queue for detections that need human review.
    
    Items are flagged based on:
    - Low confidence (below threshold)
    - Ambiguous context
    - Allowlist edge cases
    - Coreference uncertainty
    - ML-only detection (no rule backup)
    
    M2 FIX: Queue now stores only token references, not original PHI.
    This prevents PHI exposure via memory dumps or unbounded queue growth.
    """

    def __init__(self, confidence_threshold: float = 0.95):
        self.threshold = confidence_threshold
        self._items: List[ReviewItem] = []
        self._id_set: set = set()  # Track IDs to prevent collision

    def _generate_id(self) -> str:
        """Generate unique ID. Uses full UUID to prevent collision."""
        # Use full UUID instead of truncated 8-char
        # 8 hex chars = 32 bits = 50% collision at ~77k items (birthday paradox)
        # Full UUID = 128 bits = collision-resistant
        while True:
            new_id = str(uuid.uuid4())
            if new_id not in self._id_set:
                self._id_set.add(new_id)
                return new_id

    def check_span(self, span: Span, text: str, token: str = None, context_window: int = 50) -> Optional[ReviewItem]:
        """
        Check if span needs review, create item if so.
        
        Args:
            span: The detected span
            text: Original text (for context extraction)
            token: The token assigned to this span (e.g., [NAME_1])
            context_window: Characters of context on each side
        
        Returns ReviewItem if flagged, None otherwise.
        """
        if span is None or text is None:
            return None
            
        reason = None
        suggested = "review"

        # Low confidence
        if span.confidence < self.threshold:
            reason = ReviewReason.LOW_CONFIDENCE
            if span.confidence < 0.70:
                suggested = "review"
            else:
                suggested = "approve"

        # ML-only detection
        elif span.tier == Tier.ML and not span.needs_review:
            reason = ReviewReason.ML_ONLY
            suggested = "review"

        # Already flagged
        elif span.needs_review:
            reason = ReviewReason(span.review_reason) if span.review_reason else ReviewReason.AMBIGUOUS_CONTEXT
            suggested = "review"

        if reason is None:
            return None

        # Extract context WITH THE DETECTION REDACTED
        # This prevents PHI exposure while still showing surrounding context
        start = max(0, span.start - context_window)
        end = min(len(text), span.end + context_window)
        
        # Build redacted context: prefix + [TOKEN] + suffix
        prefix = text[start:span.start]
        suffix = text[span.end:end]
        # Use provided token or generate placeholder
        display_token = token or f'[{span.entity_type}]'
        context_redacted = prefix + display_token + suffix

        # Create ReviewItem without storing the span (which contains PHI)
        item = ReviewItem(
            id=self._generate_id(),
            token=display_token,
            entity_type=span.entity_type,
            confidence=span.confidence,
            reason=reason,
            context=context_redacted,
            suggested_action=suggested,
        )

        self._items.append(item)
        return item

    def flag_spans(self, spans: List[Span], text: str, tokens: List[str] = None) -> List[ReviewItem]:
        """Check all spans and return items needing review.
        
        Args:
            spans: Detected spans
            text: Original text
            tokens: Optional list of tokens assigned to spans (parallel to spans list)
        """
        items = []
        for i, span in enumerate(spans):
            token = tokens[i] if tokens and i < len(tokens) else None
            item = self.check_span(span, text, token)
            if item:
                items.append(item)
        return items

    def get_pending(self) -> List[ReviewItem]:
        """Get items awaiting decision."""
        return [i for i in self._items if i.decision is None]

    def get_item(self, item_id: str) -> Optional[ReviewItem]:
        """Get item by ID."""
        for item in self._items:
            if item.id == item_id:
                return item
        return None

    def approve(self, item_id: str) -> bool:
        """Approve an item (confirm detection is correct)."""
        item = self.get_item(item_id)
        if item and item.decision is None:
            item.decision = "approved"
            item.decided_at = datetime.now()
            return True
        return False

    def reject(self, item_id: str) -> bool:
        """Reject an item (detection is false positive)."""
        item = self.get_item(item_id)
        if item and item.decision is None:
            item.decision = "rejected"
            item.decided_at = datetime.now()
            return True
        return False

    def clear_decided(self) -> int:
        """Remove decided items from queue. Returns count removed."""
        before = len(self._items)
        self._items = [i for i in self._items if i.decision is None]
        return before - len(self._items)

    def __len__(self) -> int:
        return len(self.get_pending())

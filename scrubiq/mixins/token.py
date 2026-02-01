"""Token and review management mixin for ScrubIQ."""

from typing import List

from ..types import AuditEventType


class TokenMixin:
    """
    Token and review queue operations.
    
    Requires these attributes on the class:
        _require_unlock: Callable
        _store: Optional[TokenStore]
        _review_queue: ReviewQueue
        _audit: AuditLog
    """

    def get_tokens(self) -> List[dict]:
        """List all tokens in current conversation (without exposing original PHI)."""
        self._require_unlock()
        
        if self._store is None:
            return []
        
        tokens = []
        for token in self._store.list_tokens():
            entry = self._store.get_entry(token)
            if entry:
                tokens.append({
                    "token": entry.token,
                    "type": entry.entity_type,
                    # "original" intentionally omitted - PHI protection
                    "safe_harbor": entry.safe_harbor_value,
                })
        return tokens

    def delete_token(self, token: str) -> bool:
        """Delete a token (false positive correction)."""
        self._require_unlock()
        
        if self._store is None:
            return False
        
        return self._store.delete(token)

    def get_pending_reviews(self) -> List[dict]:
        """Get items awaiting human review (without exposing PHI)."""
        return [{
            "id": r.id,
            "token": r.token,
            "type": r.entity_type,
            "confidence": r.confidence,
            "reason": r.reason.value,
            "context_redacted": r.context,
            "suggested": r.suggested_action,
        } for r in self._review_queue.get_pending()]

    def approve_review(self, item_id: str) -> bool:
        """Approve a review item."""
        success = self._review_queue.approve(item_id)
        if success and self._audit:
            self._audit.log(AuditEventType.REVIEW_APPROVED, {"item_id": item_id})
        return success

    def reject_review(self, item_id: str) -> bool:
        """Reject a review item."""
        success = self._review_queue.reject(item_id)
        if success and self._audit:
            self._audit.log(AuditEventType.REVIEW_REJECTED, {"item_id": item_id})
        return success

    def verify_audit_chain(self) -> tuple:
        """Verify audit log integrity."""
        self._require_unlock()
        return self._audit.verify_chain()

    def get_audit_entries(self, limit: int = 100) -> List[dict]:
        """Get recent audit entries."""
        self._require_unlock()
        entries = self._audit.get_entries(limit=limit)
        return [{
            "sequence": e.sequence,
            "event": e.event_type.value,
            "timestamp": e.timestamp.isoformat(),
            "data": e.data,
        } for e in entries]

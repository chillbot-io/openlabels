"""Token restoration - replace tokens with PHI."""

import re
from dataclasses import dataclass
from typing import Tuple, List

from ..storage.tokens import TokenStore


# Token pattern: [TYPE_N] where TYPE is uppercase letters/underscores, N is digits
TOKEN_PATTERN = re.compile(r'\[([A-Z][A-Z0-9_]*_\d+)\]')


@dataclass
class RestoreResult:
    """Result of token restoration."""
    restored: str
    tokens_found: List[str]
    tokens_unknown: List[str]


def restore(
    text: str,
    store: TokenStore,
    use_safe_harbor: bool = False
) -> Tuple[str, List[str], List[str]]:
    """
    Replace tokens with original or Safe Harbor values.
    
    Args:
        text: Text containing tokens
        store: Token store for lookups
        use_safe_harbor: Use Safe Harbor values instead of originals
    
    Returns:
        (restored_text, tokens_restored, unknown_tokens)
    """
    tokens_restored = []
    unknown_tokens = []

    def replace_token(match: re.Match) -> str:
        token = f"[{match.group(1)}]"
        value = store.get(token, use_safe_harbor=use_safe_harbor)

        if value is not None:
            tokens_restored.append(token)
            return value
        else:
            unknown_tokens.append(token)
            # SECURITY: Mask unknown tokens to prevent PHI type disclosure
            # Don't reveal that [NAME_1] or [SSN_2] existed - use generic mask
            return "[REDACTED]"

    restored = TOKEN_PATTERN.sub(replace_token, text)

    return restored, tokens_restored, unknown_tokens


def restore_tokens(
    text: str,
    store: TokenStore,
    use_safe_harbor: bool = False
) -> RestoreResult:
    """
    Replace tokens with original or Safe Harbor values.

    This is a convenience wrapper around restore() that returns a RestoreResult object.

    Args:
        text: Text containing tokens
        store: Token store for lookups
        use_safe_harbor: Use Safe Harbor values instead of originals

    Returns:
        RestoreResult with restored text and token lists
    """
    restored, tokens_found, tokens_unknown = restore(text, store, use_safe_harbor)
    return RestoreResult(
        restored=restored,
        tokens_found=tokens_found,
        tokens_unknown=tokens_unknown,
    )

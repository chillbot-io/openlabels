"""PHI tokenization - replace spans with tokens.

Phase 2 Update:
    Added tokenize_entities() which uses entity_id as the lookup key instead
    of (value, entity_type). This fixes the core identity problem where the
    same person detected with different semantic roles got different tokens.

    The original tokenize() function is preserved for backward compatibility.
"""

import logging
import re
from typing import List, Tuple, Dict, Optional

from ..types import Span, Entity, Mention
from ..storage.tokens import TokenStore

logger = logging.getLogger(__name__)


# =============================================================================
# POST-REDACTION VALIDATION (Defense Layer for Span Boundary Issues)
# =============================================================================

# Pattern to detect alphanumeric chars immediately adjacent to redaction tokens
# Catches issues like "[NAME_1]s" or "M[DOB_1]" where PHI chars leaked
# Extended to catch possessives like "[NAME_1]'s" and other attached punctuation
_LEAKAGE_AFTER_TOKEN = re.compile(r"(\[[A-Z_]+_\d+\])('[a-zA-Z]+|[A-Za-z0-9]+)")
_LEAKAGE_BEFORE_TOKEN = re.compile(r"([A-Za-z0-9]+)(\[[A-Z_]+_\d+\])")


def _validate_and_fix_leakage(redacted_text: str) -> str:
    """
    Post-redaction validator: detect and fix alphanumeric chars adjacent to tokens.

    This is a CRITICAL safety layer that catches span boundary bugs.
    If we see "[NAME_1]s" or "m[DOB_1]", those chars are likely leaked PHI.

    Fix strategy: Replace leaked chars with asterisks to prevent PHI exposure.
    This is safer than silently passing through partial PHI.

    Returns:
        Fixed text with leaked characters masked.
    """
    fixed = redacted_text
    leak_count = 0

    # Fix leakage AFTER tokens (e.g., "[NAME_1]son" -> "[NAME_1]***")
    def mask_after(match):
        nonlocal leak_count
        token = match.group(1)
        leaked_chars = match.group(2)
        leak_count += len(leaked_chars)
        logger.warning(
            f"Post-redaction fix: masked {len(leaked_chars)} leaked char(s) '{leaked_chars}' after {token}"
        )
        return token + ('*' * len(leaked_chars))

    fixed = _LEAKAGE_AFTER_TOKEN.sub(mask_after, fixed)

    # Fix leakage BEFORE tokens (e.g., "Joh[NAME_1]" -> "***[NAME_1]")
    def mask_before(match):
        nonlocal leak_count
        leaked_chars = match.group(1)
        token = match.group(2)
        leak_count += len(leaked_chars)
        logger.warning(
            f"Post-redaction fix: masked {len(leaked_chars)} leaked char(s) '{leaked_chars}' before {token}"
        )
        return ('*' * len(leaked_chars)) + token

    fixed = _LEAKAGE_BEFORE_TOKEN.sub(mask_before, fixed)

    if leak_count > 0:
        logger.warning(
            f"Post-redaction validator fixed {leak_count} character leakage(s). "
            f"This indicates a span boundary bug - please investigate."
        )

    return fixed

# Entity types that support partial name matching
NAME_TYPES = frozenset([
    "NAME",
    "NAME_PATIENT", 
    "NAME_PROVIDER",
    "NAME_RELATIVE",
])


def _normalize_name(text: str) -> str:
    """Normalize name for matching."""
    return text.lower().strip()


def _is_partial_name_match(name1: str, name2: str) -> bool:
    """
    Check if one name is a partial match of another.
    
    Examples:
        "Smith" matches "John Smith" -> True
        "John" matches "John Smith" -> True  
        "John Smith" matches "Smith" -> True
        "Johnson" matches "John Smith" -> False (not a word match)
    """
    n1 = _normalize_name(name1)
    n2 = _normalize_name(name2)
    
    if n1 == n2:
        return True
    
    # Check if one is a word-boundary substring of the other
    words1 = set(n1.split())
    words2 = set(n2.split())
    
    # If any word in the shorter name matches a word in the longer name
    if words1 & words2:  # Intersection
        return True
    
    return False


def _find_matching_token(
    value: str,
    entity_type: str,
    existing_mappings: Dict[Tuple[str, str], str],
    value_for_token: Dict[str, str],
) -> Optional[str]:
    """
    Find existing token for a value, including partial name matches.
    
    Args:
        value: The PHI value to find a token for
        entity_type: The entity type
        existing_mappings: Map of (normalized_value, type) -> token
        value_for_token: Map of token -> original full value
    
    Returns:
        Existing token if found, None otherwise
    """
    norm_value = _normalize_name(value)
    lookup_key = (norm_value, entity_type)
    
    # Exact match first
    if lookup_key in existing_mappings:
        return existing_mappings[lookup_key]
    
    # Partial name matching only for NAME types
    if entity_type not in NAME_TYPES:
        return None
    
    # Check for partial matches against existing NAME tokens
    for (existing_value, existing_type), token in existing_mappings.items():
        if existing_type not in NAME_TYPES:
            continue
        
        if _is_partial_name_match(norm_value, existing_value):
            logger.debug(
                f"Partial name match: '{value}' -> '{existing_value}' -> {token}"
            )
            return token
    
    return None


def tokenize(text: str, spans: List[Span], store: TokenStore) -> Tuple[str, List[Span]]:
    """
    Replace PHI spans with tokens.
    
    Preconditions:
    - Spans are non-overlapping and sorted by position
    - Spans have safe_harbor_value set
    
    Postconditions:
    - All spans replaced with tokens
    - Token store updated with new mappings
    - Each span has token field populated
    - Tokens are numbered in text order (first occurrence = _1)
    - Partial names share tokens with full names (e.g., "Smith" -> same token as "John Smith")
    
    Returns:
        Tuple of (redacted_text, spans_with_tokens)
    """
    if not spans:
        return text, spans

    # Step 1: Assign tokens in text order (by first occurrence)
    # This ensures NAME_1 is the first name to appear, NAME_2 is second, etc.
    token_map = _assign_tokens_in_text_order(spans, store)
    
    # Step 2: Apply tokens to spans and build replacement map
    for span in spans:
        lookup_value = span.coref_anchor_value if span.coref_anchor_value else span.text
        lookup_key = (_normalize_name(lookup_value), span.entity_type)
        span.token = token_map[lookup_key]

    # Step 3: Replace in reverse order (end-to-start) to preserve positions
    sorted_spans = sorted(spans, key=lambda s: s.end, reverse=True)
    result = text

    for span in sorted_spans:
        result = result[:span.start] + span.token + result[span.end:]

    # Step 4: Post-redaction validation - catch and fix any PHI leakage
    result = _validate_and_fix_leakage(result)

    return result, spans


def _assign_tokens_in_text_order(spans: List[Span], store: TokenStore) -> Dict[Tuple[str, str], str]:
    """
    Assign tokens to unique (value, entity_type) pairs in text order.
    
    Includes:
    - Pre-loading existing NAME tokens from store for cross-message partial matching
    - Validation to prevent the same token being assigned to different values
    - Partial name matching (e.g., "Smith" gets same token as "John Smith")
    - Coref anchor value support (pronouns get same token as their anchor)
    
    Returns:
        Dict mapping (normalized_value, entity_type) to token string
    """
    # Sort spans by start position
    sorted_by_position = sorted(spans, key=lambda s: s.start)
    
    # Track first occurrence of each unique value
    first_occurrence: Dict[Tuple[str, str], int] = {}  # (value, type) -> position
    span_for_value: Dict[Tuple[str, str], Span] = {}  # (value, type) -> first span
    
    for span in sorted_by_position:
        lookup_value = span.coref_anchor_value if span.coref_anchor_value else span.text
        lookup_key = (_normalize_name(lookup_value), span.entity_type)
        
        if lookup_key not in first_occurrence:
            first_occurrence[lookup_key] = span.start
            span_for_value[lookup_key] = span
    
    # Sort unique values by their first occurrence position
    ordered_keys = sorted(first_occurrence.keys(), key=lambda k: first_occurrence[k])
    
    # Assign tokens in order
    token_map: Dict[Tuple[str, str], str] = {}
    
    # Track token -> original value to detect collisions and enable partial matching
    token_to_value: Dict[str, str] = {}
    
    # Pre-load existing NAME tokens from store for cross-message partial matching
    # This allows "Smith" in message 2 to match "John Smith" from message 1
    preload_count = 0
    try:
        existing_name_tokens = store.get_name_token_mappings()
        for token, (value, entity_type) in existing_name_tokens.items():
            norm_value = _normalize_name(value)
            # Add to token_map so _find_matching_token can find partial matches
            token_map[(norm_value, entity_type)] = token
            token_to_value[token] = value
            preload_count += 1
        if preload_count > 0:
            logger.debug(f"Pre-loaded {preload_count} NAME tokens for cross-message matching")
    except Exception as e:
        # This is significant - cross-message name linking will not work
        logger.error(
            f"Failed to pre-load NAME tokens from store: {e}. "
            f"Cross-message partial name matching is DISABLED for this request."
        )
    
    for lookup_key in ordered_keys:
        norm_value, entity_type = lookup_key
        span = span_for_value[lookup_key]
        lookup_value = span.coref_anchor_value if span.coref_anchor_value else span.text
        
        # Check for existing token (exact or partial match)
        # This now includes tokens from previous messages via pre-loading
        existing_token = _find_matching_token(
            lookup_value, entity_type, token_map, token_to_value
        )
        
        if existing_token:
            token_map[lookup_key] = existing_token
            # Log token only, not the value (PHI protection)
            logger.debug(f"Reusing token {existing_token} for {entity_type}")
            continue
        
        # Get or create new token (store handles persistence and deduplication)
        token = store.get_or_create(
            value=lookup_value,
            entity_type=span.entity_type,
            safe_harbor_value=span.safe_harbor_value
        )
        
        # Verify no collision - same token should not map to different unrelated values
        if token in token_to_value:
            existing_value = token_to_value[token]
            # For NAME types, partial matches are OK (e.g., "John" and "John Smith")
            # For other types, exact match is required
            is_valid_match = (
                entity_type in NAME_TYPES and _is_partial_name_match(existing_value, lookup_value)
            ) or existing_value.lower() == lookup_value.lower()

            if not is_valid_match:
                # Collision detected! This shouldn't happen with proper hashing
                # SECURITY: Don't log PHI values - just log the token and type
                logger.error(
                    f"Token collision detected: {token} (type={entity_type}). "
                    f"Existing value differs from new value. "
                    f"This indicates a hashing bug. Forcing new token."
                )
                # Force a new token by appending disambiguator (with position to ensure uniqueness)
                # Note: This is defensive - collisions should never happen with proper store hashing
                disambiguated_value = f"{lookup_value}_collision_{span.start}"
                token = store.get_or_create(
                    value=disambiguated_value,
                    entity_type=span.entity_type,
                    safe_harbor_value=span.safe_harbor_value
                )
        
        token_to_value[token] = lookup_value
        token_map[lookup_key] = token

    return token_map


# =============================================================================
# PHASE 2: ENTITY-BASED TOKENIZATION
# =============================================================================

def tokenize_entities(
    text: str,
    entities: List[Entity],
    store: TokenStore,
) -> Tuple[str, List[Span]]:
    """
    Replace PHI spans with tokens using entity-based identity (Phase 2).

    This is the new tokenization API that fixes the core identity problem.
    Instead of using (value, entity_type) as the lookup key, it uses entity_id.

    Key difference from legacy tokenize():
    - tokenize() uses (value, entity_type) as key
      → "John" as NAME_PATIENT and NAME_PROVIDER get different tokens
      (LEGACY LIMITATION - kept for backward compatibility)
    - tokenize_entities() uses entity_id
      → "John" always gets the same token regardless of role (RECOMMENDED)

    Args:
        text: Original text to redact
        entities: List of Entity objects from EntityResolver
        store: TokenStore for token persistence

    Returns:
        Tuple of (redacted_text, all_spans_with_tokens)
    """
    if not entities:
        return text, []

    # Collect all spans from all entities
    all_spans: List[Span] = []

    # Process each entity
    for entity in entities:
        # Extract safe_harbor_value from mentions if available
        # For dates, this will be the year (e.g., "1985" from "03/15/1985")
        # All mentions of the same entity should have the same safe_harbor_value
        safe_harbor_value = None
        for mention in entity.mentions:
            if mention.span.safe_harbor_value:
                safe_harbor_value = mention.span.safe_harbor_value
                break  # Use first available

        # Get or create token for this entity (using entity_id as key)
        token = store.get_or_create_by_entity(
            entity_id=entity.id,
            value=entity.canonical_value,
            entity_type=entity.entity_type,
            safe_harbor_value=safe_harbor_value,
        )

        # Assign token to entity
        entity.token = token

        # Register all variant values for fast future lookup
        for mention in entity.mentions:
            if mention.text != entity.canonical_value:
                store.register_entity_variant(
                    entity_id=entity.id,
                    variant_value=mention.text,
                    entity_type=entity.entity_type,
                )

            # Update span with token
            mention.span.token = token
            all_spans.append(mention.span)

    # Sort spans by end position descending for safe replacement
    sorted_spans = sorted(all_spans, key=lambda s: s.end, reverse=True)

    # Replace spans with tokens
    result = text
    for span in sorted_spans:
        result = result[:span.start] + span.token + result[span.end:]

    # Post-redaction validation - catch and fix any PHI leakage
    result = _validate_and_fix_leakage(result)

    # Sort spans by start position for output
    all_spans.sort(key=lambda s: s.start)

    logger.debug(
        f"Tokenized {len(entities)} entities → {len(all_spans)} spans"
    )

    return result, all_spans


def entities_to_spans(entities: List[Entity]) -> List[Span]:
    """
    Extract all spans from a list of entities.

    Utility function for getting spans with tokens assigned
    after tokenize_entities() has been called.

    Args:
        entities: Entities with tokens assigned

    Returns:
        List of all Span objects from all mentions
    """
    spans = []
    for entity in entities:
        for mention in entity.mentions:
            spans.append(mention.span)
    return sorted(spans, key=lambda s: s.start)

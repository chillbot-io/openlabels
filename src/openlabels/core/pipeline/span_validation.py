"""Span position validation.

Validates spans have consistent positions after pipeline stages.
Called after coref resolution to catch position errors early.

Checks:
1. Position bounds: 0 <= start < end <= len(text)
2. Text consistency: span.text matches text[start:end]
3. No unexpected overlaps (coref shouldn't create overlapping spans)

Behavior:
- In strict mode (default=False): Raises ValueError on first error
- In lenient mode (default): Logs warnings and filters invalid spans
"""

import logging
from typing import List, Optional, Tuple

from ..types import Span

logger = logging.getLogger(__name__)


class SpanValidationError(Exception):
    """Raised when span validation fails in strict mode."""

    def __init__(self, message: str, span: Span, text_length: int):
        self.span = span
        self.text_length = text_length
        super().__init__(message)


def validate_span_positions(
    text: str,
    spans: List[Span],
    strict: bool = False,
    context: str = "unknown",
) -> List[Span]:
    """
    Validate span positions and filter or raise on errors.

    Args:
        text: The source text
        spans: Spans to validate
        strict: If True, raise on first error; if False, filter invalid spans
        context: Label for log messages (e.g., "after_coref", "after_merge")

    Returns:
        List of valid spans (in lenient mode, invalid spans are filtered out)

    Raises:
        SpanValidationError: In strict mode, on first validation error
    """
    if not spans:
        return []

    text_len = len(text)
    valid_spans: List[Span] = []
    errors: List[Tuple[str, Span]] = []

    for span in spans:
        error = _validate_single_span(span, text, text_len)

        if error is None:
            valid_spans.append(span)
        elif strict:
            raise SpanValidationError(error, span, text_len)
        else:
            errors.append((error, span))

    if errors:
        # Log summary of errors
        # SECURITY: Never log actual PHI text, only metadata
        logger.warning(
            f"[{context}] Span validation filtered {len(errors)} invalid spans "
            f"(kept {len(valid_spans)}/{len(spans)})"
        )
        for error_msg, span in errors[:5]:  # Log first 5 in detail
            logger.warning(
                f"  Invalid span: {error_msg} | "
                f"start={span.start}, end={span.end}, len={len(span.text)}, type={span.entity_type}"
            )
        if len(errors) > 5:
            logger.warning(f"  ... and {len(errors) - 5} more errors")

    return valid_spans


def _validate_single_span(span: Span, text: str, text_len: int) -> Optional[str]:
    """
    Validate a single span.

    Returns None if valid, or error message string if invalid.
    """
    # Check 1: Position bounds
    if span.start < 0:
        return f"start position negative ({span.start})"

    if span.end < 0:
        return f"end position negative ({span.end})"

    if span.start > text_len:
        return f"start position exceeds text length ({span.start} > {text_len})"

    if span.end > text_len:
        return f"end position exceeds text length ({span.end} > {text_len})"

    # Check 2: Position ordering
    if span.start >= span.end:
        return f"start >= end ({span.start} >= {span.end})"

    # Check 3: Text consistency
    actual_text = text[span.start:span.end]
    if actual_text.lower() != span.text.lower():
        if len(actual_text) != len(span.text):
            return (
                f"text length mismatch at [{span.start}:{span.end}]: "
                f"span.text len={len(span.text)} vs actual len={len(actual_text)}"
            )
        # Length matches but content differs - less serious
        logger.debug(
            f"Text content differs (case/normalization?) at [{span.start}:{span.end}], "
            f"type={span.entity_type}, detector={span.detector}"
        )

    return None


# =============================================================================
# RUST ACCELERATION (default — Python below is fallback only)
# =============================================================================

_USE_RUST_SPANS = False
try:
    from openlabels_matcher import check_overlaps as _rust_check_overlaps
    _USE_RUST_SPANS = True
    logger.info("Span operations: using Rust acceleration")
except ImportError:
    logger.info("Span operations: using Python fallback")


def check_for_overlaps(
    spans: List[Span],
    allow_identical: bool = True,
    context: str = "unknown",
) -> List[Tuple[Span, Span]]:
    """
    Find overlapping spans (diagnostic only, doesn't filter).

    Uses Rust O(n log n) sort-and-sweep when available,
    falls back to Python O(n²) nested loop otherwise.

    Args:
        spans: Spans to check
        allow_identical: If True, spans at exact same position are OK
        context: Label for log messages

    Returns:
        List of (span1, span2) tuples that overlap
    """
    if not spans or len(spans) < 2:
        return []

    if _USE_RUST_SPANS:
        # Convert spans to (start, end) tuples for Rust
        span_tuples = [(s.start, s.end) for s in spans]
        # Sort to get a consistent index mapping
        sorted_spans = sorted(range(len(spans)), key=lambda i: (spans[i].start, spans[i].end))
        sorted_span_list = [spans[i] for i in sorted_spans]
        sorted_tuples = [(s.start, s.end) for s in sorted_span_list]

        rust_overlaps = _rust_check_overlaps(sorted_tuples, allow_identical)

        overlaps = [(sorted_span_list[i], sorted_span_list[j]) for i, j in rust_overlaps]

        if overlaps:
            logger.debug(
                f"[{context}] Found {len(overlaps)} overlapping span pairs"
            )
        return overlaps

    # Python fallback: O(n²) nested loop
    overlaps: List[Tuple[Span, Span]] = []

    sorted_spans = sorted(spans, key=lambda s: (s.start, s.end))

    for i in range(len(sorted_spans)):
        for j in range(i + 1, len(sorted_spans)):
            s1, s2 = sorted_spans[i], sorted_spans[j]

            if s2.start >= s1.end:
                break

            if allow_identical and s1.start == s2.start and s1.end == s2.end:
                continue

            overlaps.append((s1, s2))

    if overlaps:
        logger.debug(
            f"[{context}] Found {len(overlaps)} overlapping span pairs"
        )

    return overlaps


def validate_after_coref(
    text: str,
    spans: List[Span],
    strict: bool = False,
) -> List[Span]:
    """
    Validate spans after coreference resolution.

    This is a convenience wrapper that:
    1. Validates position bounds
    2. Logs any overlaps (coref can legitimately create overlaps)
    3. Filters invalid spans

    Args:
        text: Source text
        spans: Spans after coref resolution
        strict: Raise on errors if True

    Returns:
        Valid spans (invalid ones filtered in lenient mode)
    """
    valid = validate_span_positions(text, spans, strict=strict, context="after_coref")

    # Check for overlaps (diagnostic only - coref can create valid overlaps)
    overlaps = check_for_overlaps(valid, allow_identical=True, context="after_coref")
    if overlaps:
        logger.info(
            f"[after_coref] {len(overlaps)} overlapping pairs detected "
            f"(this may be normal for pronoun expansions)"
        )

    return valid

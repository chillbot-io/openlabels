"""
Filter executor for OpenLabels CLI.

Executes parsed filter expressions against scan results.
"""

from __future__ import annotations

import re
import signal
from contextlib import contextmanager
from typing import Any

from openlabels.cli.filter_parser import (
    BinaryOp,
    Comparison,
    FilterExpression,
    FunctionCall,
    LexerError,
    ParseError,
    UnaryOp,
    parse_filter,
)

# Maximum length for regex patterns to prevent ReDoS
MAX_REGEX_PATTERN_LENGTH = 500
# Maximum time allowed for regex matching (seconds)
REGEX_TIMEOUT_SECONDS = 1


class RegexTimeoutError(Exception):
    """Raised when regex matching exceeds the timeout."""
    pass


def _regex_timeout_handler(signum, frame):
    """Signal handler for regex timeout."""
    raise RegexTimeoutError("Regex matching timed out")


@contextmanager
def _regex_timeout(seconds: int):
    """Context manager for regex timeout using SIGALRM (Unix only)."""
    # Only use signal-based timeout on Unix systems
    try:
        old_handler = signal.signal(signal.SIGALRM, _regex_timeout_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    except (AttributeError, ValueError):
        # signal.SIGALRM not available (Windows) - just execute without timeout
        yield


def _safe_regex_match(pattern: str, text: str) -> bool:
    """
    Safely perform regex matching with timeout and pattern validation.

    Security: Prevents ReDoS attacks by:
    1. Limiting pattern length
    2. Using timeout for matching
    3. Catching regex compilation errors

    Args:
        pattern: The regex pattern
        text: The text to match against

    Returns:
        True if pattern matches text, False otherwise
    """
    # Limit pattern length to prevent complex patterns
    if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
        return False

    try:
        # Compile pattern first to catch invalid patterns
        compiled = re.compile(pattern)

        # Use timeout for the actual matching
        with _regex_timeout(REGEX_TIMEOUT_SECONDS):
            return bool(compiled.search(text))
    except RegexTimeoutError:
        # Regex took too long - likely ReDoS attempt
        return False
    except re.error:
        # Invalid regex pattern
        return False
    except Exception as e:
        # Any other error - fail safely but log for debugging
        import logging
        logging.getLogger(__name__).debug(f"Regex match failed safely: {type(e).__name__}: {e}")
        return False


def _get_field_value(result: Any, field: str) -> Any:
    """
    Get a field value from a result object.

    Supports nested fields using dot notation.
    """
    # Normalize field names
    field_map = {
        "score": "risk_score",
        "tier": "risk_tier",
        "exposure": "exposure_level",
        "path": "file_path",
        "name": "file_name",
        "filename": "file_name",
        "entities": "total_entities",
        "total": "total_entities",
    }

    normalized = field_map.get(field.lower(), field)

    # Handle dict-like access
    if isinstance(result, dict):
        # Try normalized name first
        if normalized in result:
            return result[normalized]
        # Try original name
        if field in result:
            return result[field]
        # Handle nested with dots
        if "." in field:
            parts = field.split(".", 1)
            if parts[0] in result and isinstance(result[parts[0]], dict):
                return _get_field_value(result[parts[0]], parts[1])
        return None

    # Handle object access
    if hasattr(result, normalized):
        value = getattr(result, normalized)
        # Handle enum values
        if hasattr(value, "value"):
            return value.value
        return value
    if hasattr(result, field):
        value = getattr(result, field)
        if hasattr(value, "value"):
            return value.value
        return value

    return None


def _compare(left: Any, op: str, right: Any) -> bool:
    """Perform a comparison operation."""
    # Normalize tier/exposure values for comparison
    if isinstance(left, str):
        left = left.upper()
    if isinstance(right, str):
        right = right.upper()

    if op == "=":
        return left == right
    if op == "!=":
        return left != right
    if op == ">":
        return left is not None and left > right
    if op == "<":
        return left is not None and left < right
    if op == ">=":
        return left is not None and left >= right
    if op == "<=":
        return left is not None and left <= right
    if op == "~":
        # Regex match with ReDoS protection
        if left is None:
            return False
        return _safe_regex_match(str(right), str(left))
    if op == "contains":
        if left is None:
            return False
        return str(right).lower() in str(left).lower()

    return False


def _get_entity_count(result: Any, entity_type: str) -> int:
    """Get the count of a specific entity type."""
    entity_counts = _get_field_value(result, "entity_counts")
    if entity_counts is None:
        return 0

    # Normalize entity type
    entity_type_upper = entity_type.upper()

    if isinstance(entity_counts, dict):
        # Try exact match
        if entity_type in entity_counts:
            return entity_counts[entity_type]
        # Try uppercase match
        if entity_type_upper in entity_counts:
            return entity_counts[entity_type_upper]
        # Try case-insensitive
        for key, value in entity_counts.items():
            if key.upper() == entity_type_upper:
                return value
    return 0


def _evaluate(expr: FilterExpression, result: Any) -> bool:
    """
    Evaluate a filter expression against a result.

    Args:
        expr: The parsed filter expression.
        result: The result object to filter.

    Returns:
        True if the result matches the filter, False otherwise.
    """
    if isinstance(expr, BinaryOp):
        left_result = _evaluate(expr.left, result)

        # Short-circuit evaluation
        if expr.operator == "AND":
            if not left_result:
                return False
            return _evaluate(expr.right, result)
        elif expr.operator == "OR":
            if left_result:
                return True
            return _evaluate(expr.right, result)

    elif isinstance(expr, UnaryOp):
        if expr.operator == "NOT":
            return not _evaluate(expr.operand, result)

    elif isinstance(expr, Comparison):
        field_value = _get_field_value(result, expr.field)
        return _compare(field_value, expr.operator, expr.value)

    elif isinstance(expr, FunctionCall):
        if expr.function == "has":
            # has(ENTITY_TYPE) - returns true if entity type exists with count > 0
            return _get_entity_count(result, expr.argument) > 0

        elif expr.function == "missing":
            # missing(field) - returns true if field is None or empty
            value = _get_field_value(result, expr.argument)
            if value is None:
                return True
            if isinstance(value, str) and not value.strip():
                return True
            if isinstance(value, (list, dict)) and len(value) == 0:
                return True
            return False

        elif expr.function == "count":
            # count(ENTITY_TYPE) op value
            count = _get_entity_count(result, expr.argument)
            return _compare(count, expr.comparison_op, expr.comparison_value)

    return False


def execute_filter(expr: FilterExpression, result: Any) -> bool:
    """
    Execute a parsed filter expression against a result.

    Args:
        expr: The parsed FilterExpression AST.
        result: The result to evaluate (dict or object with filterable fields).

    Returns:
        True if the result matches the filter, False otherwise.

    Example:
        >>> expr = parse_filter("score > 75 AND has(SSN)")
        >>> execute_filter(expr, {"risk_score": 80, "entity_counts": {"SSN": 5}})
        True
    """
    return _evaluate(expr, result)


def filter_scan_results(
    results: list[Any],
    filter_str: str,
) -> list[Any]:
    """
    Filter a list of scan results using a filter expression.

    Args:
        results: List of scan results (dicts or objects).
        filter_str: The filter expression string.

    Returns:
        List of results that match the filter.

    Example:
        >>> results = [
        ...     {"file_path": "/a.txt", "risk_score": 80, "entity_counts": {"SSN": 5}},
        ...     {"file_path": "/b.txt", "risk_score": 30, "entity_counts": {}},
        ... ]
        >>> filter_scan_results(results, "score > 50")
        [{"file_path": "/a.txt", ...}]
    """
    expr = parse_filter(filter_str)
    return [r for r in results if execute_filter(expr, r)]


def validate_filter(filter_str: str) -> str | None:
    """
    Validate a filter expression string.

    Args:
        filter_str: The filter expression to validate.

    Returns:
        None if valid, error message if invalid.

    Example:
        >>> validate_filter("score > 75")
        None
        >>> validate_filter("score >")
        "Expected value at position 8"
    """
    try:
        parse_filter(filter_str)
        return None
    except (ValueError, SyntaxError, ParseError, LexerError) as e:
        # Expected validation errors - return message
        return str(e)
    except Exception as e:
        # Unexpected errors - log and return generic message
        import logging
        logging.getLogger(__name__).warning(f"Unexpected error validating filter '{filter_str}': {type(e).__name__}: {e}")
        return f"Invalid filter expression: {type(e).__name__}"

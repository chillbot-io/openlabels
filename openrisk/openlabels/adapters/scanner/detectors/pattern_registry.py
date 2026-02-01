"""Shared pattern registration utilities for detectors."""

import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import Callable, List, Optional, Tuple, Any

# Type alias for compiled pattern tuples
PatternTuple = Tuple[regex.Pattern, str, float, int]
PatternTupleWithValidator = Tuple[regex.Pattern, str, float, int, Optional[Callable]]


def create_pattern_adder(
    pattern_list: List,
    compile_pattern: bool = True,
    support_validator: bool = False,
) -> Callable:
    """
    Create an _add() helper for a pattern list.

    Args:
        pattern_list: List to append patterns to
        compile_pattern: If True, compile regex before appending
        support_validator: If True, include validator in tuple

    Returns:
        An _add() function configured for the pattern list
    """
    if support_validator:
        def _add(
            pattern: str,
            entity_type: str,
            confidence: float,
            group: int = 0,
            validator: Optional[Callable] = None,
            flags: int = 0,
        ) -> None:
            compiled = regex.compile(pattern, flags) if compile_pattern else pattern
            pattern_list.append((compiled, entity_type, confidence, group, validator))
        return _add
    else:
        def _add(
            pattern: str,
            entity_type: str,
            confidence: float,
            group: int = 0,
            flags: int = 0,
        ) -> None:
            if compile_pattern:
                pattern_list.append((regex.compile(pattern, flags), entity_type, confidence, group))
            else:
                pattern_list.append((pattern, entity_type, confidence, group, flags))
        return _add

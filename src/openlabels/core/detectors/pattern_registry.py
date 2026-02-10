"""Immutable pattern definitions for all detectors.

Patterns are frozen dataclasses stored in tuples — no mutation, no import-time
side effects, safe to share across instances and threads.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class PatternDefinition:
    """Immutable, hashable pattern definition."""

    pattern: re.Pattern[str]
    entity_type: str
    confidence: float
    group: int = 0
    validator: Callable[[str], bool] | None = None


def _p(
    regex: str,
    entity_type: str,
    confidence: float,
    group: int = 0,
    validator: Callable[[str], bool] | None = None,
    flags: int = 0,
) -> PatternDefinition:
    """Shorthand for defining a pattern."""
    return PatternDefinition(
        pattern=re.compile(regex, flags),
        entity_type=entity_type,
        confidence=confidence,
        group=group,
        validator=validator,
    )

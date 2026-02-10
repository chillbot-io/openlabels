"""
Rust core integration for high-performance pattern matching.

This module provides a Python wrapper around the Rust-based PatternMatcher.
If the Rust extension is not available, it falls back to a pure Python
implementation with reduced performance.
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import the Rust extension
_RUST_AVAILABLE = False
try:
    from openlabels_matcher import PatternMatcher as RustPatternMatcher
    from openlabels_matcher import RawMatch
    _RUST_AVAILABLE = True
    logger.info("Rust pattern matcher loaded successfully")
except ImportError:
    logger.warning("Rust pattern matcher not available, using Python fallback")
    RustPatternMatcher = None


@dataclass
class MatchResult:
    """A single pattern match result."""

    pattern_name: str
    start: int
    end: int
    matched_text: str
    confidence: float
    validator: str | None = None


class PatternMatcherWrapper:
    """
    Wrapper for the pattern matcher that uses Rust if available.

    Example:
        matcher = PatternMatcherWrapper.with_builtin_patterns()
        matches = matcher.find_matches("Call me at 555-123-4567")
    """

    def __init__(self, patterns: list[tuple[str, str, str | None, float]]):
        """
        Initialize the pattern matcher.

        Args:
            patterns: List of (name, regex, validator, confidence) tuples
        """
        self._patterns = patterns

        if _RUST_AVAILABLE:
            self._rust_matcher = RustPatternMatcher(patterns)
            self._use_rust = True
        else:
            self._rust_matcher = None
            self._use_rust = False
            self._init_python_matcher()

    def _init_python_matcher(self):
        """Initialize the Python fallback matcher."""
        import re
        self._compiled_patterns = []
        for name, pattern, validator, confidence in self._patterns:
            try:
                compiled = re.compile(pattern)
                self._compiled_patterns.append((name, compiled, validator, confidence))
            except re.error as e:
                logger.warning(f"Invalid pattern '{name}': {e}")

    @classmethod
    def with_builtin_patterns(cls) -> "PatternMatcherWrapper":
        """Create a matcher with built-in patterns."""
        if _RUST_AVAILABLE:
            # Use Rust's built-in patterns
            wrapper = cls.__new__(cls)
            wrapper._rust_matcher = RustPatternMatcher.with_builtin_patterns()
            wrapper._use_rust = True
            wrapper._patterns = []
            return wrapper
        else:
            # Fall back to Python built-in patterns
            from openlabels.core._rust.patterns_py import BUILTIN_PATTERNS
            return cls(BUILTIN_PATTERNS)

    def find_matches(self, text: str) -> list[MatchResult]:
        """
        Find all pattern matches in the text.

        Args:
            text: Text to search

        Returns:
            List of MatchResult objects
        """
        if self._use_rust:
            raw_matches = self._rust_matcher.find_matches(text)
            return [
                MatchResult(
                    pattern_name=m.pattern_name,
                    start=m.start,
                    end=m.end,
                    matched_text=m.matched_text,
                    confidence=m.confidence,
                    validator=m.validator,
                )
                for m in raw_matches
            ]
        else:
            return self._find_matches_python(text)

    def find_matches_batch(self, texts: list[str]) -> list[list[MatchResult]]:
        """
        Find matches in multiple texts (parallel if Rust available).

        Args:
            texts: List of texts to search

        Returns:
            List of match lists, one per input text
        """
        if self._use_rust:
            batch_results = self._rust_matcher.find_matches_batch(texts)
            return [
                [
                    MatchResult(
                        pattern_name=m.pattern_name,
                        start=m.start,
                        end=m.end,
                        matched_text=m.matched_text,
                        confidence=m.confidence,
                        validator=m.validator,
                    )
                    for m in matches
                ]
                for matches in batch_results
            ]
        else:
            return [self._find_matches_python(text) for text in texts]

    def _find_matches_python(self, text: str) -> list[MatchResult]:
        """Python fallback for pattern matching."""
        from openlabels.core._rust.validators_py import validate

        results = []
        for name, regex, validator, base_confidence in self._compiled_patterns:
            for match in regex.finditer(text):
                matched_text = match.group(0)

                # Run validator if specified
                is_valid, confidence_boost = True, 0.0
                if validator:
                    is_valid, confidence_boost = validate(matched_text, validator)

                if is_valid:
                    confidence = min(base_confidence + confidence_boost, 1.0)
                    results.append(MatchResult(
                        pattern_name=name,
                        start=match.start(),
                        end=match.end(),
                        matched_text=matched_text,
                        confidence=confidence,
                        validator=validator,
                    ))

        return results

    @property
    def pattern_count(self) -> int:
        """Get the number of patterns loaded."""
        if self._use_rust:
            return self._rust_matcher.pattern_count()
        return len(self._compiled_patterns)

    @property
    def pattern_names(self) -> list[str]:
        """Get the names of all loaded patterns."""
        if self._use_rust:
            return self._rust_matcher.pattern_names()
        return [name for name, _, _, _ in self._compiled_patterns]

    @property
    def is_rust(self) -> bool:
        """Check if using Rust implementation."""
        return self._use_rust


# Export the wrapper as the main class
PatternMatcher = PatternMatcherWrapper

__all__ = ["PatternMatcher", "PatternMatcherWrapper", "MatchResult", "_RUST_AVAILABLE"]

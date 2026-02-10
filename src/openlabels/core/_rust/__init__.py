"""Python wrapper around the Rust PatternMatcher, with pure-Python fallback."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

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
    """Pattern matcher that delegates to Rust when available."""

    def __init__(self, patterns: list[tuple[str, str, str | None, float]]):
        self._patterns = patterns

        if _RUST_AVAILABLE:
            self._rust_matcher = RustPatternMatcher(patterns)
            self._use_rust = True
        else:
            self._rust_matcher = None
            self._use_rust = False
            self._init_python_matcher()

    def _init_python_matcher(self):
        """Compile regex patterns for the Python fallback path."""
        import re
        self._compiled_patterns = []
        for name, pattern, validator, confidence in self._patterns:
            try:
                compiled = re.compile(pattern)
                self._compiled_patterns.append((name, compiled, validator, confidence))
            except re.error as e:
                logger.warning(f"Invalid pattern '{name}': {e}")

    @classmethod
    def with_builtin_patterns(cls) -> PatternMatcherWrapper:
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
        """Find all pattern matches in the text."""
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
        """Find matches in multiple texts (parallel when using Rust)."""
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
        """Number of loaded patterns."""
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

"""Type stubs for the Rust extension."""

from typing import List, Tuple

class RawMatch:
    """A raw match from pattern matching (before validation)."""

    pattern_id: int
    start: int
    end: int
    text: str
    entity_type: str
    confidence: float

class PatternMatcher:
    """High-performance pattern matcher using Rust regex."""

    pattern_count: int
    failed_count: int

    def __init__(self, patterns: List[Tuple[str, str, float, int]]) -> None:
        """
        Initialize the pattern matcher.

        Args:
            patterns: List of (regex, entity_type, confidence, group_idx) tuples
        """
        ...

    def find_matches(self, text: str) -> List[RawMatch]:
        """
        Find all pattern matches in text.

        This method releases the GIL during execution, allowing
        other Python threads to run concurrently.

        Args:
            text: The text to scan

        Returns:
            List of RawMatch objects
        """
        ...

    def has_pattern(self, index: int) -> bool:
        """Check if a specific pattern index is available."""
        ...

def validate_luhn(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    ...

def validate_ssn_format(ssn: str) -> bool:
    """Validate SSN format (not context)."""
    ...

def is_native_available() -> bool:
    """Check if native extension is working."""
    ...

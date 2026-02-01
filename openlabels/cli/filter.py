"""
OpenLabels Filter Parser.

Parses filter expressions for the CLI query language.

Grammar:
    <filter>     := <condition> (AND|OR <condition>)*
    <condition>  := <field> <operator> <value>
                 | has(<entity_type>)
                 | missing(<field>)

    <field>      := score | exposure | encryption | last_accessed
                 | last_modified | size | entity_count | source

    <operator>   := = | != | > | < | >= | <= | contains | matches

    <value>      := <number> | <duration> | <enum> | <string>
    <duration>   := <number>(d|w|m|y)  # days, weeks, months, years
    <enum>       := public | org_wide | internal | private
                 | none | platform | customer_managed

Examples:
    score > 75
    exposure = public AND has(SSN)
    last_accessed > 1y AND score >= 50
    encryption = none OR exposure = public
"""

import logging
import re
import warnings
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict, Set
from enum import Enum

from openlabels.adapters.scanner.constants import REGEX_TIMEOUT_MS

logger = logging.getLogger(__name__)

# Module-level flag to only warn once about missing regex module
_regex_import_warning_issued = False

# Track unknown fields we've already warned about (once per process)
_unknown_field_warnings_issued: Set[str] = set()

# Exposure level ordinal values for comparison
# Maps exposure level names to comparable integers
# "over_exposed" is kept as legacy alias for "org_wide"
EXPOSURE_LEVEL_VALUES = {
    "private": 0,
    "internal": 1,
    "org_wide": 2,
    "over_exposed": 2,  # Legacy alias
    "public": 3,
}

# Duration multipliers (in days)
DURATION_MULTIPLIERS = {
    "d": 1,      # days
    "w": 7,      # weeks
    "m": 30,     # months (approximate)
    "y": 365,    # years (approximate)
}


class TokenType(Enum):
    """Token types for the filter parser."""
    FIELD = "field"
    OPERATOR = "operator"
    VALUE = "value"
    AND = "and"
    OR = "or"
    HAS = "has"
    MISSING = "missing"
    LPAREN = "lparen"
    RPAREN = "rparen"
    EOF = "eof"


@dataclass
class Token:
    """A single token from the filter expression."""
    type: TokenType
    value: str
    position: int = 0


@dataclass
class Condition:
    """A single filter condition."""
    field: str
    operator: str
    value: Any

    def evaluate(self, result: Dict[str, Any]) -> bool:
        """Evaluate this condition against a result dict."""
        actual = self._get_field_value(result, self.field)

        if actual is None:
            return self.operator == "missing"

        return self._compare(actual, self.operator, self.value)

    def _get_field_value(self, result: Dict[str, Any], field: str) -> Any:
        """Get a field value from result, handling nested fields."""
        # Direct fields
        if field in result:
            return result[field]

        # Nested in context
        if "context" in result and field in result["context"]:
            return result["context"][field]

        # Entity-related fields
        if field == "entity_count":
            entities = result.get("entities", [])
            return sum(e.get("count", 1) for e in entities)

        if field == "has_entity":
            # Special handling for has() function
            entities = result.get("entities", [])
            return [e.get("type", "").upper() for e in entities]

        return None

    def _compare(self, actual: Any, operator: str, expected: Any) -> bool:
        """Compare actual value against expected using operator."""
        normalize = self._normalize
        to_comparable = self._to_comparable

        dispatch = {
            "=": lambda: normalize(actual) == normalize(expected),
            "!=": lambda: normalize(actual) != normalize(expected),
            ">": lambda: to_comparable(actual) > to_comparable(expected),
            "<": lambda: to_comparable(actual) < to_comparable(expected),
            ">=": lambda: to_comparable(actual) >= to_comparable(expected),
            "<=": lambda: to_comparable(actual) <= to_comparable(expected),
            "contains": lambda: str(expected).lower() in str(actual).lower(),
            "matches": lambda: self._safe_regex_match(str(expected), str(actual)),
            "has": lambda: isinstance(actual, list) and expected.upper() in [str(x).upper() for x in actual],
            "missing": lambda: actual is None,
        }

        if operator not in dispatch:
            return False
        return dispatch[operator]()

    def _normalize(self, value: Any) -> str:
        """Normalize value for comparison."""
        if value is None:
            return ""
        return str(value).lower().strip()

    def _to_comparable(self, value: Any) -> float:
        """Convert value to comparable number."""
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            # Handle duration strings
            if re.match(r'^\d+[dwmy]$', value):
                return self._duration_to_days(value)
            # Handle exposure levels
            lower = value.lower()
            if lower in EXPOSURE_LEVEL_VALUES:
                return EXPOSURE_LEVEL_VALUES[lower]
            # Try numeric conversion
            try:
                return float(value)
            except ValueError:
                return 0
        return 0

    def _duration_to_days(self, duration: str) -> float:
        """Convert duration string to days."""
        match = re.match(r'^(\d+)([dwmy])$', duration)
        if not match:
            return 0

        num = int(match.group(1))
        unit = match.group(2)
        return num * DURATION_MULTIPLIERS.get(unit, 0)

    def _safe_regex_match(self, pattern: str, text: str, timeout_ms: int = REGEX_TIMEOUT_MS) -> bool:
        """
        Safely execute regex match with protection against ReDoS.

        Uses multiple layers of protection:
        1. Pattern length limit
        2. Pattern complexity checks (nested quantifiers)
        3. Text length limit for regex operations
        4. Actual timeout enforcement (requires 'regex' module)

        Args:
            pattern: The regex pattern to match
            text: The text to search in
            timeout_ms: Timeout in milliseconds (enforced if regex module available)

        Returns:
            True if pattern matches, False otherwise (including on timeout)
        """
        global _regex_import_warning_issued

        MAX_PATTERN_LENGTH = 500
        MAX_TEXT_LENGTH_FOR_REGEX = 1_000_000  # 1MB text limit for regex ops

        if len(pattern) > MAX_PATTERN_LENGTH:
            logger.debug(f"Regex pattern rejected: exceeds {MAX_PATTERN_LENGTH} chars")
            return False

        # Limit text length to prevent slow regex on huge inputs
        if len(text) > MAX_TEXT_LENGTH_FOR_REGEX:
            logger.debug(f"Regex match skipped: text exceeds {MAX_TEXT_LENGTH_FOR_REGEX} chars")
            return False

        # Reject patterns with known ReDoS-prone constructs: nested quantifiers
        redos_patterns = [
            r'\([^)]*[+*][^)]*\)[+*]',  # (a+)+ or (a*)*
            r'\([^)]*\|[^)]*\)[+*]',     # (a|b)+
        ]
        for dangerous in redos_patterns:
            if re.search(dangerous, pattern):
                logger.debug("Regex pattern rejected: contains ReDoS-prone construct")
                return False

        try:  # CVE-READY-003: require 'regex' module for timeout
            import regex
            try:
                # regex module supports timeout parameter (in seconds)
                result = regex.search(
                    pattern, text,
                    flags=regex.IGNORECASE,
                    timeout=timeout_ms / 1000.0
                )
                return bool(result)
            except regex.error as e:
                logger.debug(f"Regex pattern error: {e}")
                return False
            except TimeoutError:
                logger.warning(f"Regex match timed out after {timeout_ms}ms")
                return False
        except ImportError:  # CVE-READY-003: reject without safe timeout support
            if not _regex_import_warning_issued:
                logger.error(
                    "SECURITY: ReDoS protection disabled - 'regex' module not installed. "
                    "Pattern matching with 'matches' operator is disabled. "
                    "Install with: pip install regex"
                )
                _regex_import_warning_issued = True

            # Reject pattern rather than risk ReDoS attack
            logger.warning(
                "Regex pattern rejected: 'regex' module required for safe execution. "
                "Install with: pip install regex"
            )
            return False


@dataclass
class Filter:
    """A complete filter expression."""
    conditions: List[Condition] = field(default_factory=list)
    operators: List[str] = field(default_factory=list)  # AND/OR between conditions

    def evaluate(self, result: Dict[str, Any]) -> bool:
        """Evaluate this filter against a result."""
        if not self.conditions:
            return True

        # Evaluate first condition
        current = self.conditions[0].evaluate(result)

        # Apply remaining conditions with AND/OR
        for i, (op, cond) in enumerate(zip(self.operators, self.conditions[1:])):
            cond_result = cond.evaluate(result)

            if op.upper() == "AND":
                current = current and cond_result
            else:  # OR
                current = current or cond_result

        return current

    @classmethod
    def parse(cls, expression: str) -> "Filter":
        """Parse a filter expression string."""
        if not expression or not expression.strip():
            return cls()

        parser = FilterParser(expression)
        return parser.parse()

    def to_dict(self) -> Dict[str, Any]:
        """Convert filter to dictionary representation."""
        return {
            "conditions": [
                {"field": c.field, "operator": c.operator, "value": c.value}
                for c in self.conditions
            ],
            "operators": self.operators,
        }


class FilterParser:
    """
    Recursive descent parser for filter expressions.

    Implements the grammar defined in the module docstring.
    Uses simple character-by-character parsing with lookahead.
    """

    # Valid field names for filter conditions
    FIELDS = frozenset({
        "score", "exposure", "encryption", "last_accessed",
        "last_modified", "size", "entity_count", "source",
        "staleness_days", "tier", "path", "owner", "file_type",
    })

    # Comparison operators
    OPERATORS = frozenset({"=", "!=", ">", "<", ">=", "<=", "contains", "matches"})

    # Valid enum values (derived from module constants)
    EXPOSURE_VALUES = frozenset(EXPOSURE_LEVEL_VALUES.keys())
    ENCRYPTION_VALUES = frozenset({"none", "platform", "customer_managed"})

    def __init__(self, expression: str):
        self.expression = expression.strip()
        self.pos = 0
        self.length = len(self.expression)

    def parse(self) -> Filter:
        """Parse the expression into a Filter object."""
        conditions = []
        operators = []

        # Parse first condition
        cond = self._parse_condition()
        if cond:
            conditions.append(cond)

        # Parse remaining conditions with AND/OR
        while self.pos < self.length:
            self._skip_whitespace()

            # Check for AND/OR
            op = self._parse_logical_operator()
            if not op:
                break

            operators.append(op)

            # Parse next condition
            cond = self._parse_condition()
            if cond:
                conditions.append(cond)
            else:
                raise ValueError(f"Expected condition after {op} at position {self.pos}")

        return Filter(conditions=conditions, operators=operators)

    def _skip_whitespace(self):
        """Skip whitespace and newlines."""
        while self.pos < self.length and self.expression[self.pos] in ' \t\n\r':
            self.pos += 1

    def _parse_logical_operator(self) -> Optional[str]:
        """Parse AND or OR."""
        self._skip_whitespace()

        # Check for AND
        if self.expression[self.pos:self.pos+3].upper() == "AND":
            next_char_pos = self.pos + 3
            if next_char_pos >= self.length or not self.expression[next_char_pos].isalnum():
                self.pos += 3
                return "AND"

        # Check for OR
        if self.expression[self.pos:self.pos+2].upper() == "OR":
            next_char_pos = self.pos + 2
            if next_char_pos >= self.length or not self.expression[next_char_pos].isalnum():
                self.pos += 2
                return "OR"

        return None

    def _parse_condition(self) -> Optional[Condition]:
        """Parse a single condition."""
        self._skip_whitespace()

        if self.pos >= self.length:
            return None

        # Check for has(entity_type)
        if self.expression[self.pos:self.pos+4].lower() == "has(":
            return self._parse_has_condition()

        # Check for missing(field)
        if self.expression[self.pos:self.pos+8].lower() == "missing(":
            return self._parse_missing_condition()

        # Parse field = operator = value
        field = self._parse_field()
        if not field:
            return None

        self._skip_whitespace()

        operator = self._parse_operator()
        if not operator:
            raise ValueError(f"Expected operator after '{field}' at position {self.pos}")

        self._skip_whitespace()

        value = self._parse_value()

        return Condition(field=field, operator=operator, value=value)

    def _parse_has_condition(self) -> Condition:
        """Parse has(entity_type) condition."""
        self.pos += 4  # Skip 'has('

        # Find closing paren
        end = self.expression.find(')', self.pos)
        if end == -1:
            raise ValueError("Unclosed has() at position " + str(self.pos - 4))

        entity_type = self.expression[self.pos:end].strip()
        self.pos = end + 1

        return Condition(field="has_entity", operator="has", value=entity_type)

    def _parse_missing_condition(self) -> Condition:
        """Parse missing(field) condition."""
        self.pos += 8  # Skip 'missing('

        # Find closing paren
        end = self.expression.find(')', self.pos)
        if end == -1:
            raise ValueError("Unclosed missing() at position " + str(self.pos - 8))

        field = self.expression[self.pos:end].strip()
        self.pos = end + 1

        return Condition(field=field, operator="missing", value=None)

    def _parse_field(self) -> Optional[str]:
        """Parse a field name."""
        self._skip_whitespace()

        start = self.pos
        while self.pos < self.length and (
            self.expression[self.pos].isalnum() or self.expression[self.pos] == '_'
        ):
            self.pos += 1

        if self.pos == start:
            return None

        field = self.expression[start:self.pos].lower()

        if field not in self.FIELDS:
            self._warn_unknown_field(field)

        return field

    def _warn_unknown_field(self, field: str) -> None:
        """Warn about unknown filter field (once per process to avoid spam)."""
        global _unknown_field_warnings_issued

        if field not in _unknown_field_warnings_issued:
            _unknown_field_warnings_issued.add(field)
            warnings.warn(
                f"Unknown filter field: '{field}'. This may be a typo. "
                f"Valid fields are: {sorted(self.FIELDS)}",
                UserWarning,
                stacklevel=4,  # Point to the caller's code
            )

    def _parse_operator(self) -> Optional[str]:
        """Parse an operator."""
        self._skip_whitespace()

        # Check two-character operators first
        if self.pos + 1 < self.length:
            two_char = self.expression[self.pos:self.pos+2]
            if two_char in (">=", "<=", "!="):
                self.pos += 2
                return two_char

        # Check single-character operators
        if self.pos < self.length:
            one_char = self.expression[self.pos]
            if one_char in ("=", ">", "<"):
                self.pos += 1
                return one_char

        # Check word operators
        for op in ("contains", "matches"):
            if self.expression[self.pos:self.pos+len(op)].lower() == op:
                next_pos = self.pos + len(op)
                if next_pos >= self.length or not self.expression[next_pos].isalnum():
                    self.pos = next_pos
                    return op

        return None

    def _parse_value(self) -> Any:
        """Parse a value (number, duration, enum, or string)."""
        self._skip_whitespace()

        if self.pos >= self.length:
            raise ValueError("Expected value at end of expression")

        # Check for quoted string
        if self.expression[self.pos] in ('"', "'"):
            return self._parse_quoted_string()

        # Parse unquoted value
        start = self.pos
        while self.pos < self.length and self.expression[self.pos] not in ' \t\n\r':
            # Stop at AND/OR
            remaining = self.expression[self.pos:].upper()
            if remaining.startswith("AND ") or remaining.startswith("OR "):
                break
            if remaining == "AND" or remaining == "OR":
                break
            self.pos += 1

        value = self.expression[start:self.pos].strip()

        # Try to convert to appropriate type
        return self._convert_value(value)

    def _parse_quoted_string(self) -> str:
        """Parse a quoted string value."""
        quote = self.expression[self.pos]
        self.pos += 1

        start = self.pos
        while self.pos < self.length and self.expression[self.pos] != quote:
            # Handle escape
            if self.expression[self.pos] == '\\' and self.pos + 1 < self.length:
                self.pos += 2
            else:
                self.pos += 1

        value = self.expression[start:self.pos]

        if self.pos < self.length:
            self.pos += 1  # Skip closing quote

        return value

    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate type."""
        # Check for duration
        if re.match(r'^\d+[dwmy]$', value):
            return value  # Keep as duration string

        # Check for integer
        try:
            return int(value)
        except ValueError:
            pass

        # Check for float
        try:
            return float(value)
        except ValueError:
            pass

        # Return as string (lowercase for enums)
        return value.lower() if value.lower() in (
            self.EXPOSURE_VALUES | self.ENCRYPTION_VALUES | {"critical", "high", "medium", "low", "minimal"}
        ) else value


def parse_filter(expression: str) -> Filter:
    """Parse a filter expression string."""
    return Filter.parse(expression)


def matches_filter(result: Dict[str, Any], filter_expr: str) -> bool:
    """Check if a result matches a filter expression."""
    if not filter_expr:
        return True

    filter_obj = Filter.parse(filter_expr)
    return filter_obj.evaluate(result)


# Helper for programmatic filter building
class FilterBuilder:
    """Fluent builder for constructing filters programmatically."""

    def __init__(self):
        self._conditions: List[Condition] = []
        self._operators: List[str] = []

    def where(self, field: str, operator: str, value: Any) -> "FilterBuilder":
        """Add a condition."""
        self._conditions.append(Condition(field=field, operator=operator, value=value))
        return self

    def and_(self, field: str, operator: str, value: Any) -> "FilterBuilder":
        """Add an AND condition."""
        if self._conditions:
            self._operators.append("AND")
        self._conditions.append(Condition(field=field, operator=operator, value=value))
        return self

    def or_(self, field: str, operator: str, value: Any) -> "FilterBuilder":
        """Add an OR condition."""
        if self._conditions:
            self._operators.append("OR")
        self._conditions.append(Condition(field=field, operator=operator, value=value))
        return self

    def has(self, entity_type: str) -> "FilterBuilder":
        """Add a has(entity_type) condition."""
        if self._conditions:
            self._operators.append("AND")
        self._conditions.append(
            Condition(field="has_entity", operator="has", value=entity_type)
        )
        return self

    def build(self) -> Filter:
        """Build the filter."""
        return Filter(conditions=self._conditions, operators=self._operators)

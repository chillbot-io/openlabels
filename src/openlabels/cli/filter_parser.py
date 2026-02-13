"""
Filter grammar parser for OpenLabels CLI.

Grammar:
    filter      = or_expr
    or_expr     = and_expr (OR and_expr)*
    and_expr    = condition (AND condition)*
    condition   = comparison | function_call | "(" filter ")" | NOT condition
    comparison  = field operator value
    field       = identifier
    operator    = "=" | "!=" | ">" | "<" | ">=" | "<=" | "~" | "contains"
    value       = string | number | identifier
    function_call = "has(" value ")" | "missing(" field ")" | "count(" field ")" operator value

Examples:
    score > 75
    has(SSN) AND tier = CRITICAL
    path ~ ".*\\.xlsx$" AND exposure = PUBLIC
    has(SSN) OR has(CREDIT_CARD)
    count(SSN) >= 10 AND tier != MINIMAL
    NOT has(SSN)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class TokenType(Enum):
    """Token types for the filter grammar."""
    # Literals
    STRING = "STRING"
    NUMBER = "NUMBER"
    IDENTIFIER = "IDENTIFIER"

    # Operators
    EQ = "="
    NE = "!="
    GT = ">"
    LT = "<"
    GE = ">="
    LE = "<="
    REGEX = "~"
    CONTAINS = "contains"

    # Logical
    AND = "AND"
    OR = "OR"
    NOT = "NOT"

    # Functions
    HAS = "has"
    MISSING = "missing"
    COUNT = "count"

    # Grouping
    LPAREN = "("
    RPAREN = ")"

    # Special
    EOF = "EOF"


@dataclass
class Token:
    """A lexical token."""
    type: TokenType
    value: Any
    position: int


class LexerError(Exception):
    """Raised when lexer encounters invalid input."""
    pass


class ParseError(Exception):
    """Raised when parser encounters invalid syntax."""
    pass


class Lexer:
    """Tokenizer for the filter grammar."""

    KEYWORDS = {
        "AND": TokenType.AND,
        "and": TokenType.AND,
        "OR": TokenType.OR,
        "or": TokenType.OR,
        "NOT": TokenType.NOT,
        "not": TokenType.NOT,
        "has": TokenType.HAS,
        "missing": TokenType.MISSING,
        "count": TokenType.COUNT,
        "contains": TokenType.CONTAINS,
    }

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)

    def _skip_whitespace(self):
        """Skip whitespace characters."""
        while self.pos < self.length and self.text[self.pos].isspace():
            self.pos += 1

    def _read_string(self) -> str:
        """Read a quoted string."""
        quote_char = self.text[self.pos]
        self.pos += 1  # Skip opening quote
        start = self.pos

        while self.pos < self.length:
            if self.text[self.pos] == '\\' and self.pos + 1 < self.length:
                self.pos += 2  # Skip escaped character
            elif self.text[self.pos] == quote_char:
                value = self.text[start:self.pos]
                self.pos += 1  # Skip closing quote
                # Unescape common sequences
                value = value.replace('\\n', '\n').replace('\\t', '\t')
                value = value.replace('\\"', '"').replace("\\'", "'")
                value = value.replace('\\\\', '\\')
                return value
            else:
                self.pos += 1

        raise LexerError(f"Unterminated string starting at position {start - 1}")

    def _read_number(self) -> int | float:
        """Read a numeric literal."""
        start = self.pos
        has_dot = False

        # Handle negative numbers
        if self.text[self.pos] == '-':
            self.pos += 1

        while self.pos < self.length:
            char = self.text[self.pos]
            if char.isdigit():
                self.pos += 1
            elif char == '.' and not has_dot:
                has_dot = True
                self.pos += 1
            else:
                break

        value = self.text[start:self.pos]
        return float(value) if has_dot else int(value)

    def _read_identifier(self) -> str:
        """Read an identifier (field name, enum value, etc.)."""
        start = self.pos

        while self.pos < self.length:
            char = self.text[self.pos]
            if char.isalnum() or char in ('_', '-', '.'):
                self.pos += 1
            else:
                break

        return self.text[start:self.pos]

    def next_token(self) -> Token:
        """Get the next token from the input."""
        self._skip_whitespace()

        if self.pos >= self.length:
            return Token(TokenType.EOF, None, self.pos)

        start_pos = self.pos
        char = self.text[self.pos]

        # String literals
        if char in ('"', "'"):
            value = self._read_string()
            return Token(TokenType.STRING, value, start_pos)

        # Numbers (including negative)
        if char.isdigit() or (char == '-' and self.pos + 1 < self.length and self.text[self.pos + 1].isdigit()):
            value = self._read_number()
            return Token(TokenType.NUMBER, value, start_pos)

        # Multi-character operators
        if self.pos + 1 < self.length:
            two_char = self.text[self.pos:self.pos + 2]
            if two_char == '!=':
                self.pos += 2
                return Token(TokenType.NE, '!=', start_pos)
            if two_char == '>=':
                self.pos += 2
                return Token(TokenType.GE, '>=', start_pos)
            if two_char == '<=':
                self.pos += 2
                return Token(TokenType.LE, '<=', start_pos)

        # Single-character operators
        if char == '=':
            self.pos += 1
            return Token(TokenType.EQ, '=', start_pos)
        if char == '>':
            self.pos += 1
            return Token(TokenType.GT, '>', start_pos)
        if char == '<':
            self.pos += 1
            return Token(TokenType.LT, '<', start_pos)
        if char == '~':
            self.pos += 1
            return Token(TokenType.REGEX, '~', start_pos)
        if char == '(':
            self.pos += 1
            return Token(TokenType.LPAREN, '(', start_pos)
        if char == ')':
            self.pos += 1
            return Token(TokenType.RPAREN, ')', start_pos)

        # Identifiers and keywords
        if char.isalpha() or char == '_':
            value = self._read_identifier()
            token_type = self.KEYWORDS.get(value, TokenType.IDENTIFIER)
            return Token(token_type, value, start_pos)

        raise LexerError(f"Unexpected character '{char}' at position {self.pos}")

    def tokenize(self) -> list[Token]:
        """Tokenize the entire input."""
        tokens = []
        while True:
            token = self.next_token()
            tokens.append(token)
            if token.type == TokenType.EOF:
                break
        return tokens


# AST Nodes
@dataclass
class FilterExpression:
    """Base class for filter expressions."""
    pass


@dataclass
class BinaryOp(FilterExpression):
    """Binary operation (AND, OR)."""
    left: FilterExpression
    operator: str  # "AND" or "OR"
    right: FilterExpression


@dataclass
class UnaryOp(FilterExpression):
    """Unary operation (NOT)."""
    operator: str  # "NOT"
    operand: FilterExpression


@dataclass
class Comparison(FilterExpression):
    """Comparison expression (field op value)."""
    field: str
    operator: str  # =, !=, >, <, >=, <=, ~, contains
    value: Any


@dataclass
class FunctionCall(FilterExpression):
    """Function call expression."""
    function: str  # has, missing, count
    argument: str
    # For count(), we need comparison
    comparison_op: str | None = None
    comparison_value: Any | None = None


# Parser
class Parser:
    """Recursive descent parser for the filter grammar."""

    COMPARISON_OPS = {
        TokenType.EQ, TokenType.NE, TokenType.GT, TokenType.LT,
        TokenType.GE, TokenType.LE, TokenType.REGEX, TokenType.CONTAINS,
    }

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def _current(self) -> Token:
        """Get the current token."""
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]  # EOF

    def _peek(self, offset: int = 0) -> Token:
        """Peek at a token without consuming it."""
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]  # EOF

    def _advance(self) -> Token:
        """Consume and return the current token."""
        token = self._current()
        self.pos += 1
        return token

    def _expect(self, token_type: TokenType) -> Token:
        """Expect a specific token type."""
        token = self._current()
        if token.type != token_type:
            raise ParseError(f"Expected {token_type.value}, got {token.type.value} at position {token.position}")
        return self._advance()

    def parse(self) -> FilterExpression:
        """Parse the filter expression."""
        expr = self._parse_or_expr()

        if self._current().type != TokenType.EOF:
            raise ParseError(f"Unexpected token {self._current().type.value} at position {self._current().position}")

        return expr

    def _parse_or_expr(self) -> FilterExpression:
        """Parse OR expression: and_expr (OR and_expr)*"""
        left = self._parse_and_expr()

        while self._current().type == TokenType.OR:
            self._advance()  # consume OR
            right = self._parse_and_expr()
            left = BinaryOp(left, "OR", right)

        return left

    def _parse_and_expr(self) -> FilterExpression:
        """Parse AND expression: condition (AND condition)*"""
        left = self._parse_condition()

        while self._current().type == TokenType.AND:
            self._advance()  # consume AND
            right = self._parse_condition()
            left = BinaryOp(left, "AND", right)

        return left

    def _parse_condition(self) -> FilterExpression:
        """Parse a condition: comparison | function_call | "(" filter ")" | NOT condition"""
        token = self._current()

        # NOT condition
        if token.type == TokenType.NOT:
            self._advance()
            operand = self._parse_condition()
            return UnaryOp("NOT", operand)

        # Grouped expression
        if token.type == TokenType.LPAREN:
            self._advance()  # consume (
            expr = self._parse_or_expr()
            self._expect(TokenType.RPAREN)
            return expr

        # Function calls: has(), missing(), count()
        if token.type in (TokenType.HAS, TokenType.MISSING, TokenType.COUNT):
            return self._parse_function_call()

        # Comparison: field op value
        if token.type == TokenType.IDENTIFIER:
            return self._parse_comparison()

        raise ParseError(f"Unexpected token {token.type.value} at position {token.position}")

    def _parse_function_call(self) -> FunctionCall:
        """Parse a function call: has(x), missing(x), count(x) op value"""
        func_token = self._advance()
        func_name = func_token.value

        self._expect(TokenType.LPAREN)

        # Get the argument
        arg_token = self._current()
        if arg_token.type == TokenType.IDENTIFIER:
            arg = self._advance().value
        elif arg_token.type == TokenType.STRING:
            arg = self._advance().value
        else:
            raise ParseError(f"Expected identifier or string in function call at position {arg_token.position}")

        self._expect(TokenType.RPAREN)

        # For count(), we expect a comparison
        if func_name == "count":
            op_token = self._current()
            if op_token.type not in self.COMPARISON_OPS:
                raise ParseError(f"count() must be followed by a comparison operator at position {op_token.position}")
            op = self._advance().value

            # Get value
            value = self._parse_value()
            return FunctionCall(func_name, arg, op, value)

        return FunctionCall(func_name, arg)

    def _parse_comparison(self) -> Comparison:
        """Parse a comparison: field op value"""
        field = self._advance().value  # IDENTIFIER

        op_token = self._current()
        if op_token.type not in self.COMPARISON_OPS:
            raise ParseError(f"Expected comparison operator at position {op_token.position}")
        op = self._advance().value

        value = self._parse_value()
        return Comparison(field, op, value)

    def _parse_value(self) -> Any:
        """Parse a value: string | number | identifier"""
        token = self._current()

        if token.type == TokenType.STRING:
            return self._advance().value
        if token.type == TokenType.NUMBER:
            return self._advance().value
        if token.type == TokenType.IDENTIFIER:
            return self._advance().value

        raise ParseError(f"Expected value at position {token.position}")


def parse_filter(filter_str: str) -> FilterExpression:
    """
    Parse a filter string into an AST.

    Args:
        filter_str: The filter expression string.

    Returns:
        The parsed FilterExpression AST.

    Raises:
        ParseError: If the filter string is invalid.
        LexerError: If the filter string contains invalid tokens.

    Examples:
        >>> parse_filter("score > 75")
        Comparison(field='score', operator='>', value=75)

        >>> parse_filter("has(SSN) AND tier = CRITICAL")
        BinaryOp(left=FunctionCall(...), operator='AND', right=Comparison(...))
    """
    if not filter_str or not filter_str.strip():
        raise ParseError("Empty filter expression")

    lexer = Lexer(filter_str)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    return parser.parse()

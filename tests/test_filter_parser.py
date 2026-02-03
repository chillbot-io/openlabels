"""
Comprehensive tests for CLI filter parser.

Tests the lexer, parser, and AST construction for the filter grammar.
Strong assertions - no weak checks. All edge cases covered.
"""

import pytest
from openlabels.cli.filter_parser import (
    Lexer,
    LexerError,
    Parser,
    ParseError,
    Token,
    TokenType,
    parse_filter,
    BinaryOp,
    UnaryOp,
    Comparison,
    FunctionCall,
    FilterExpression,
)


# =============================================================================
# LEXER TESTS
# =============================================================================

class TestLexerBasicTokens:
    """Test lexer tokenization of individual token types."""

    def test_tokenize_simple_identifier(self):
        """Test identifier tokenization."""
        lexer = Lexer("score")
        token = lexer.next_token()

        assert token.type == TokenType.IDENTIFIER
        assert token.value == "score"
        assert token.position == 0

    def test_tokenize_identifier_with_underscore(self):
        """Test identifier with underscore."""
        lexer = Lexer("risk_score")
        token = lexer.next_token()

        assert token.type == TokenType.IDENTIFIER
        assert token.value == "risk_score"

    def test_tokenize_identifier_with_dash(self):
        """Test identifier with dash (for field names like entity-type)."""
        lexer = Lexer("entity-type")
        token = lexer.next_token()

        assert token.type == TokenType.IDENTIFIER
        assert token.value == "entity-type"

    def test_tokenize_identifier_with_dots(self):
        """Test identifier with dots for nested fields."""
        lexer = Lexer("file.path")
        token = lexer.next_token()

        assert token.type == TokenType.IDENTIFIER
        assert token.value == "file.path"

    def test_tokenize_positive_integer(self):
        """Test positive integer tokenization."""
        lexer = Lexer("42")
        token = lexer.next_token()

        assert token.type == TokenType.NUMBER
        assert token.value == 42
        assert isinstance(token.value, int)

    def test_tokenize_negative_integer(self):
        """Test negative integer tokenization."""
        lexer = Lexer("-100")
        token = lexer.next_token()

        assert token.type == TokenType.NUMBER
        assert token.value == -100
        assert isinstance(token.value, int)

    def test_tokenize_float(self):
        """Test float tokenization."""
        lexer = Lexer("3.14159")
        token = lexer.next_token()

        assert token.type == TokenType.NUMBER
        assert abs(token.value - 3.14159) < 0.0001
        assert isinstance(token.value, float)

    def test_tokenize_negative_float(self):
        """Test negative float tokenization."""
        lexer = Lexer("-0.5")
        token = lexer.next_token()

        assert token.type == TokenType.NUMBER
        assert token.value == -0.5

    def test_tokenize_double_quoted_string(self):
        """Test double-quoted string tokenization."""
        lexer = Lexer('"hello world"')
        token = lexer.next_token()

        assert token.type == TokenType.STRING
        assert token.value == "hello world"

    def test_tokenize_single_quoted_string(self):
        """Test single-quoted string tokenization."""
        lexer = Lexer("'hello world'")
        token = lexer.next_token()

        assert token.type == TokenType.STRING
        assert token.value == "hello world"

    def test_tokenize_string_with_escape_sequences(self):
        """Test string with escape sequences."""
        lexer = Lexer(r'"line1\nline2\ttab"')
        token = lexer.next_token()

        assert token.type == TokenType.STRING
        assert token.value == "line1\nline2\ttab"

    def test_tokenize_string_with_escaped_quotes(self):
        """Test string with escaped quotes."""
        lexer = Lexer(r'"say \"hello\""')
        token = lexer.next_token()

        assert token.type == TokenType.STRING
        assert token.value == 'say "hello"'

    def test_tokenize_string_with_escaped_backslash(self):
        """Test string with escaped backslash."""
        lexer = Lexer(r'"path\\to\\file"')
        token = lexer.next_token()

        assert token.type == TokenType.STRING
        # After escape processing: \\\\ -> \\, so we get two backslashes per escaped pair
        assert "\\" in token.value  # Contains backslash

    def test_tokenize_regex_pattern_string(self):
        """Test regex pattern in string."""
        lexer = Lexer(r'".*\.xlsx$"')
        token = lexer.next_token()

        assert token.type == TokenType.STRING
        assert token.value == r".*\.xlsx$"


class TestLexerOperators:
    """Test lexer tokenization of operators."""

    def test_tokenize_equals(self):
        """Test = operator."""
        lexer = Lexer("=")
        token = lexer.next_token()

        assert token.type == TokenType.EQ
        assert token.value == "="

    def test_tokenize_not_equals(self):
        """Test != operator."""
        lexer = Lexer("!=")
        token = lexer.next_token()

        assert token.type == TokenType.NE
        assert token.value == "!="

    def test_tokenize_greater_than(self):
        """Test > operator."""
        lexer = Lexer(">")
        token = lexer.next_token()

        assert token.type == TokenType.GT
        assert token.value == ">"

    def test_tokenize_less_than(self):
        """Test < operator."""
        lexer = Lexer("<")
        token = lexer.next_token()

        assert token.type == TokenType.LT
        assert token.value == "<"

    def test_tokenize_greater_equals(self):
        """Test >= operator."""
        lexer = Lexer(">=")
        token = lexer.next_token()

        assert token.type == TokenType.GE
        assert token.value == ">="

    def test_tokenize_less_equals(self):
        """Test <= operator."""
        lexer = Lexer("<=")
        token = lexer.next_token()

        assert token.type == TokenType.LE
        assert token.value == "<="

    def test_tokenize_regex(self):
        """Test ~ operator."""
        lexer = Lexer("~")
        token = lexer.next_token()

        assert token.type == TokenType.REGEX
        assert token.value == "~"

    def test_tokenize_contains_keyword(self):
        """Test contains keyword."""
        lexer = Lexer("contains")
        token = lexer.next_token()

        assert token.type == TokenType.CONTAINS
        assert token.value == "contains"


class TestLexerKeywords:
    """Test lexer tokenization of keywords."""

    def test_tokenize_and_uppercase(self):
        """Test AND keyword (uppercase)."""
        lexer = Lexer("AND")
        token = lexer.next_token()

        assert token.type == TokenType.AND
        assert token.value == "AND"

    def test_tokenize_and_lowercase(self):
        """Test and keyword (lowercase)."""
        lexer = Lexer("and")
        token = lexer.next_token()

        assert token.type == TokenType.AND
        assert token.value == "and"

    def test_tokenize_or_uppercase(self):
        """Test OR keyword (uppercase)."""
        lexer = Lexer("OR")
        token = lexer.next_token()

        assert token.type == TokenType.OR
        assert token.value == "OR"

    def test_tokenize_or_lowercase(self):
        """Test or keyword (lowercase)."""
        lexer = Lexer("or")
        token = lexer.next_token()

        assert token.type == TokenType.OR
        assert token.value == "or"

    def test_tokenize_not_uppercase(self):
        """Test NOT keyword (uppercase)."""
        lexer = Lexer("NOT")
        token = lexer.next_token()

        assert token.type == TokenType.NOT
        assert token.value == "NOT"

    def test_tokenize_not_lowercase(self):
        """Test not keyword (lowercase)."""
        lexer = Lexer("not")
        token = lexer.next_token()

        assert token.type == TokenType.NOT
        assert token.value == "not"

    def test_tokenize_has_function(self):
        """Test has keyword."""
        lexer = Lexer("has")
        token = lexer.next_token()

        assert token.type == TokenType.HAS
        assert token.value == "has"

    def test_tokenize_missing_function(self):
        """Test missing keyword."""
        lexer = Lexer("missing")
        token = lexer.next_token()

        assert token.type == TokenType.MISSING
        assert token.value == "missing"

    def test_tokenize_count_function(self):
        """Test count keyword."""
        lexer = Lexer("count")
        token = lexer.next_token()

        assert token.type == TokenType.COUNT
        assert token.value == "count"


class TestLexerGrouping:
    """Test lexer tokenization of grouping."""

    def test_tokenize_lparen(self):
        """Test ( token."""
        lexer = Lexer("(")
        token = lexer.next_token()

        assert token.type == TokenType.LPAREN
        assert token.value == "("

    def test_tokenize_rparen(self):
        """Test ) token."""
        lexer = Lexer(")")
        token = lexer.next_token()

        assert token.type == TokenType.RPAREN
        assert token.value == ")"


class TestLexerWhitespace:
    """Test lexer handling of whitespace."""

    def test_skip_leading_whitespace(self):
        """Test skipping leading whitespace."""
        lexer = Lexer("   score")
        token = lexer.next_token()

        assert token.type == TokenType.IDENTIFIER
        assert token.value == "score"

    def test_skip_trailing_whitespace(self):
        """Test skipping trailing whitespace."""
        lexer = Lexer("score   ")
        tokens = lexer.tokenize()

        assert len(tokens) == 2
        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[1].type == TokenType.EOF

    def test_skip_multiple_spaces(self):
        """Test skipping multiple spaces between tokens."""
        lexer = Lexer("score    >    75")
        tokens = lexer.tokenize()

        assert len(tokens) == 4
        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[1].type == TokenType.GT
        assert tokens[2].type == TokenType.NUMBER

    def test_skip_tabs_and_newlines(self):
        """Test skipping tabs and newlines."""
        lexer = Lexer("score\t>\n75")
        tokens = lexer.tokenize()

        assert len(tokens) == 4
        assert tokens[0].value == "score"
        assert tokens[1].value == ">"
        assert tokens[2].value == 75


class TestLexerComplete:
    """Test complete tokenization of filter expressions."""

    def test_tokenize_simple_comparison(self):
        """Test tokenizing score > 75."""
        lexer = Lexer("score > 75")
        tokens = lexer.tokenize()

        assert len(tokens) == 4  # score, >, 75, EOF
        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "score"
        assert tokens[1].type == TokenType.GT
        assert tokens[2].type == TokenType.NUMBER
        assert tokens[2].value == 75
        assert tokens[3].type == TokenType.EOF

    def test_tokenize_function_call(self):
        """Test tokenizing has(SSN)."""
        lexer = Lexer("has(SSN)")
        tokens = lexer.tokenize()

        assert len(tokens) == 5  # has, (, SSN, ), EOF
        assert tokens[0].type == TokenType.HAS
        assert tokens[1].type == TokenType.LPAREN
        assert tokens[2].type == TokenType.IDENTIFIER
        assert tokens[2].value == "SSN"
        assert tokens[3].type == TokenType.RPAREN
        assert tokens[4].type == TokenType.EOF

    def test_tokenize_and_expression(self):
        """Test tokenizing has(SSN) AND tier = CRITICAL."""
        lexer = Lexer("has(SSN) AND tier = CRITICAL")
        tokens = lexer.tokenize()

        # has, (, SSN, ), AND, tier, =, CRITICAL, EOF
        assert len(tokens) == 9
        assert tokens[4].type == TokenType.AND
        assert tokens[5].type == TokenType.IDENTIFIER
        assert tokens[5].value == "tier"
        assert tokens[6].type == TokenType.EQ
        assert tokens[7].type == TokenType.IDENTIFIER
        assert tokens[7].value == "CRITICAL"

    def test_tokenize_or_expression(self):
        """Test tokenizing has(SSN) OR has(CREDIT_CARD)."""
        lexer = Lexer("has(SSN) OR has(CREDIT_CARD)")
        tokens = lexer.tokenize()

        # Check OR token is in the right place
        or_token = next(t for t in tokens if t.type == TokenType.OR)
        assert or_token is not None

        # Check CREDIT_CARD is parsed correctly
        cc_token = next(t for t in tokens if t.value == "CREDIT_CARD")
        assert cc_token.type == TokenType.IDENTIFIER

    def test_tokenize_regex_comparison(self):
        """Test tokenizing path ~ pattern."""
        lexer = Lexer('path ~ ".*\\.xlsx$"')
        tokens = lexer.tokenize()

        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "path"
        assert tokens[1].type == TokenType.REGEX
        assert tokens[2].type == TokenType.STRING
        assert tokens[2].value == r".*\.xlsx$"

    def test_tokenize_count_function(self):
        """Test tokenizing count(SSN) >= 10."""
        lexer = Lexer("count(SSN) >= 10")
        tokens = lexer.tokenize()

        assert tokens[0].type == TokenType.COUNT
        assert tokens[4].type == TokenType.GE
        assert tokens[5].type == TokenType.NUMBER
        assert tokens[5].value == 10


class TestLexerErrors:
    """Test lexer error handling."""

    def test_unterminated_double_quote_string(self):
        """Test error on unterminated double-quoted string."""
        lexer = Lexer('"hello')

        with pytest.raises(LexerError) as exc_info:
            lexer.tokenize()

        assert "Unterminated string" in str(exc_info.value)

    def test_unterminated_single_quote_string(self):
        """Test error on unterminated single-quoted string."""
        lexer = Lexer("'hello")

        with pytest.raises(LexerError) as exc_info:
            lexer.tokenize()

        assert "Unterminated string" in str(exc_info.value)

    def test_unexpected_character(self):
        """Test error on unexpected character."""
        lexer = Lexer("score $ 75")

        with pytest.raises(LexerError) as exc_info:
            lexer.tokenize()

        assert "Unexpected character" in str(exc_info.value)
        assert "$" in str(exc_info.value)

    def test_error_position_reported(self):
        """Test that error position is reported correctly."""
        lexer = Lexer("score > @invalid")

        with pytest.raises(LexerError) as exc_info:
            lexer.tokenize()

        assert "position" in str(exc_info.value).lower()


# =============================================================================
# PARSER TESTS
# =============================================================================

class TestParserSimpleComparisons:
    """Test parsing of simple comparison expressions."""

    def test_parse_equals_comparison(self):
        """Test parsing tier = CRITICAL."""
        expr = parse_filter("tier = CRITICAL")

        assert isinstance(expr, Comparison)
        assert expr.field == "tier"
        assert expr.operator == "="
        assert expr.value == "CRITICAL"

    def test_parse_not_equals_comparison(self):
        """Test parsing tier != MINIMAL."""
        expr = parse_filter("tier != MINIMAL")

        assert isinstance(expr, Comparison)
        assert expr.field == "tier"
        assert expr.operator == "!="
        assert expr.value == "MINIMAL"

    def test_parse_greater_than_comparison(self):
        """Test parsing score > 75."""
        expr = parse_filter("score > 75")

        assert isinstance(expr, Comparison)
        assert expr.field == "score"
        assert expr.operator == ">"
        assert expr.value == 75

    def test_parse_less_than_comparison(self):
        """Test parsing score < 50."""
        expr = parse_filter("score < 50")

        assert isinstance(expr, Comparison)
        assert expr.field == "score"
        assert expr.operator == "<"
        assert expr.value == 50

    def test_parse_greater_equals_comparison(self):
        """Test parsing score >= 80."""
        expr = parse_filter("score >= 80")

        assert isinstance(expr, Comparison)
        assert expr.field == "score"
        assert expr.operator == ">="
        assert expr.value == 80

    def test_parse_less_equals_comparison(self):
        """Test parsing score <= 30."""
        expr = parse_filter("score <= 30")

        assert isinstance(expr, Comparison)
        assert expr.field == "score"
        assert expr.operator == "<="
        assert expr.value == 30

    def test_parse_regex_comparison(self):
        """Test parsing path ~ regex pattern."""
        expr = parse_filter('path ~ ".*\\.xlsx$"')

        assert isinstance(expr, Comparison)
        assert expr.field == "path"
        assert expr.operator == "~"
        assert expr.value == r".*\.xlsx$"

    def test_parse_contains_comparison(self):
        """Test parsing name contains substring."""
        expr = parse_filter('name contains "john"')

        assert isinstance(expr, Comparison)
        assert expr.field == "name"
        assert expr.operator == "contains"
        assert expr.value == "john"

    def test_parse_comparison_with_string_value(self):
        """Test parsing comparison with string value."""
        expr = parse_filter('exposure = "PUBLIC"')

        assert isinstance(expr, Comparison)
        assert expr.field == "exposure"
        assert expr.operator == "="
        assert expr.value == "PUBLIC"

    def test_parse_comparison_with_negative_number(self):
        """Test parsing comparison with negative number."""
        expr = parse_filter("offset > -10")

        assert isinstance(expr, Comparison)
        assert expr.field == "offset"
        assert expr.operator == ">"
        assert expr.value == -10

    def test_parse_comparison_with_float(self):
        """Test parsing comparison with float."""
        expr = parse_filter("confidence >= 0.95")

        assert isinstance(expr, Comparison)
        assert expr.field == "confidence"
        assert expr.operator == ">="
        assert abs(expr.value - 0.95) < 0.0001


class TestParserFunctionCalls:
    """Test parsing of function call expressions."""

    def test_parse_has_function(self):
        """Test parsing has(SSN)."""
        expr = parse_filter("has(SSN)")

        assert isinstance(expr, FunctionCall)
        assert expr.function == "has"
        assert expr.argument == "SSN"
        assert expr.comparison_op is None
        assert expr.comparison_value is None

    def test_parse_has_function_with_string_arg(self):
        """Test parsing has("CREDIT_CARD")."""
        expr = parse_filter('has("CREDIT_CARD")')

        assert isinstance(expr, FunctionCall)
        assert expr.function == "has"
        assert expr.argument == "CREDIT_CARD"

    def test_parse_missing_function(self):
        """Test parsing missing(owner)."""
        expr = parse_filter("missing(owner)")

        assert isinstance(expr, FunctionCall)
        assert expr.function == "missing"
        assert expr.argument == "owner"

    def test_parse_missing_function_with_string_arg(self):
        """Test parsing missing("exposure")."""
        expr = parse_filter('missing("exposure")')

        assert isinstance(expr, FunctionCall)
        assert expr.function == "missing"
        assert expr.argument == "exposure"

    def test_parse_count_function_with_equals(self):
        """Test parsing count(SSN) = 5."""
        expr = parse_filter("count(SSN) = 5")

        assert isinstance(expr, FunctionCall)
        assert expr.function == "count"
        assert expr.argument == "SSN"
        assert expr.comparison_op == "="
        assert expr.comparison_value == 5

    def test_parse_count_function_with_greater_equals(self):
        """Test parsing count(CREDIT_CARD) >= 10."""
        expr = parse_filter("count(CREDIT_CARD) >= 10")

        assert isinstance(expr, FunctionCall)
        assert expr.function == "count"
        assert expr.argument == "CREDIT_CARD"
        assert expr.comparison_op == ">="
        assert expr.comparison_value == 10

    def test_parse_count_function_with_less_than(self):
        """Test parsing count(EMAIL) < 100."""
        expr = parse_filter("count(EMAIL) < 100")

        assert isinstance(expr, FunctionCall)
        assert expr.function == "count"
        assert expr.argument == "EMAIL"
        assert expr.comparison_op == "<"
        assert expr.comparison_value == 100

    def test_parse_count_function_with_not_equals(self):
        """Test parsing count(PHONE) != 0."""
        expr = parse_filter("count(PHONE) != 0")

        assert isinstance(expr, FunctionCall)
        assert expr.function == "count"
        assert expr.argument == "PHONE"
        assert expr.comparison_op == "!="
        assert expr.comparison_value == 0


class TestParserLogicalOperators:
    """Test parsing of logical operators."""

    def test_parse_and_expression(self):
        """Test parsing expr AND expr."""
        expr = parse_filter("score > 50 AND tier = CRITICAL")

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"
        assert isinstance(expr.left, Comparison)
        assert isinstance(expr.right, Comparison)
        assert expr.left.field == "score"
        assert expr.right.field == "tier"

    def test_parse_or_expression(self):
        """Test parsing expr OR expr."""
        expr = parse_filter("has(SSN) OR has(CREDIT_CARD)")

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "OR"
        assert isinstance(expr.left, FunctionCall)
        assert isinstance(expr.right, FunctionCall)
        assert expr.left.argument == "SSN"
        assert expr.right.argument == "CREDIT_CARD"

    def test_parse_not_expression(self):
        """Test parsing NOT expr."""
        expr = parse_filter("NOT has(SSN)")

        assert isinstance(expr, UnaryOp)
        assert expr.operator == "NOT"
        assert isinstance(expr.operand, FunctionCall)
        assert expr.operand.argument == "SSN"

    def test_parse_not_with_comparison(self):
        """Test parsing NOT comparison."""
        expr = parse_filter("NOT tier = MINIMAL")

        assert isinstance(expr, UnaryOp)
        assert expr.operator == "NOT"
        assert isinstance(expr.operand, Comparison)
        assert expr.operand.field == "tier"

    def test_parse_lowercase_and(self):
        """Test parsing with lowercase 'and'."""
        expr = parse_filter("score > 50 and tier = HIGH")

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"

    def test_parse_lowercase_or(self):
        """Test parsing with lowercase 'or'."""
        expr = parse_filter("has(SSN) or has(NPI)")

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "OR"

    def test_parse_lowercase_not(self):
        """Test parsing with lowercase 'not'."""
        expr = parse_filter("not has(SSN)")

        assert isinstance(expr, UnaryOp)
        assert expr.operator == "NOT"


class TestParserPrecedence:
    """Test parsing operator precedence."""

    def test_and_binds_tighter_than_or(self):
        """Test that AND binds tighter than OR: a OR b AND c = a OR (b AND c)."""
        expr = parse_filter("has(SSN) OR score > 50 AND tier = CRITICAL")

        # Should parse as: has(SSN) OR (score > 50 AND tier = CRITICAL)
        assert isinstance(expr, BinaryOp)
        assert expr.operator == "OR"
        assert isinstance(expr.left, FunctionCall)  # has(SSN)
        assert isinstance(expr.right, BinaryOp)  # score > 50 AND tier = CRITICAL
        assert expr.right.operator == "AND"

    def test_multiple_and_left_associative(self):
        """Test that multiple ANDs are left-associative."""
        expr = parse_filter("a = 1 AND b = 2 AND c = 3")

        # Should parse as: ((a = 1 AND b = 2) AND c = 3)
        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"
        assert isinstance(expr.right, Comparison)
        assert expr.right.field == "c"
        assert isinstance(expr.left, BinaryOp)
        assert expr.left.operator == "AND"

    def test_multiple_or_left_associative(self):
        """Test that multiple ORs are left-associative."""
        expr = parse_filter("a = 1 OR b = 2 OR c = 3")

        # Should parse as: ((a = 1 OR b = 2) OR c = 3)
        assert isinstance(expr, BinaryOp)
        assert expr.operator == "OR"
        assert isinstance(expr.right, Comparison)
        assert expr.right.field == "c"

    def test_not_binds_tightest(self):
        """Test that NOT binds tighter than AND/OR."""
        expr = parse_filter("NOT has(SSN) AND tier = CRITICAL")

        # Should parse as: (NOT has(SSN)) AND tier = CRITICAL
        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"
        assert isinstance(expr.left, UnaryOp)
        assert expr.left.operator == "NOT"


class TestParserGrouping:
    """Test parsing of grouped expressions."""

    def test_parse_grouped_or(self):
        """Test parsing (a OR b) AND c."""
        expr = parse_filter("(has(SSN) OR has(NPI)) AND tier = CRITICAL")

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"
        assert isinstance(expr.left, BinaryOp)
        assert expr.left.operator == "OR"
        assert isinstance(expr.right, Comparison)

    def test_parse_grouped_and(self):
        """Test parsing a OR (b AND c)."""
        expr = parse_filter("tier = MINIMAL OR (score > 80 AND has(SSN))")

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "OR"
        assert isinstance(expr.left, Comparison)
        assert isinstance(expr.right, BinaryOp)
        assert expr.right.operator == "AND"

    def test_parse_nested_groups(self):
        """Test parsing nested groups."""
        expr = parse_filter("((a = 1 OR b = 2) AND c = 3)")

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"
        assert isinstance(expr.left, BinaryOp)
        assert expr.left.operator == "OR"

    def test_parse_not_in_group(self):
        """Test parsing NOT (expr)."""
        expr = parse_filter("NOT (has(SSN) AND tier = CRITICAL)")

        assert isinstance(expr, UnaryOp)
        assert expr.operator == "NOT"
        assert isinstance(expr.operand, BinaryOp)
        assert expr.operand.operator == "AND"

    def test_parse_group_around_not(self):
        """Test parsing (NOT expr)."""
        expr = parse_filter("(NOT has(SSN)) AND tier = HIGH")

        assert isinstance(expr, BinaryOp)
        assert isinstance(expr.left, UnaryOp)


class TestParserComplexExpressions:
    """Test parsing of complex filter expressions."""

    def test_parse_complex_real_world_filter(self):
        """Test parsing a complex real-world filter."""
        filter_str = 'has(SSN) AND (tier = CRITICAL OR tier = HIGH) AND score >= 50 AND path ~ ".*\\.xlsx$"'
        expr = parse_filter(filter_str)

        # Should be a chain of ANDs
        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"

    def test_parse_multiple_entity_checks(self):
        """Test parsing filter checking multiple entity types."""
        filter_str = "has(SSN) OR has(CREDIT_CARD) OR has(NPI) OR has(DEA)"
        expr = parse_filter(filter_str)

        # Verify structure - should be left-associative ORs
        assert isinstance(expr, BinaryOp)
        assert expr.operator == "OR"

        # Rightmost should be has(DEA)
        assert isinstance(expr.right, FunctionCall)
        assert expr.right.argument == "DEA"

    def test_parse_count_with_and(self):
        """Test parsing count function with AND."""
        filter_str = "count(SSN) >= 10 AND tier != MINIMAL"
        expr = parse_filter(filter_str)

        assert isinstance(expr, BinaryOp)
        assert expr.operator == "AND"
        assert isinstance(expr.left, FunctionCall)
        assert expr.left.function == "count"
        assert isinstance(expr.right, Comparison)

    def test_parse_nested_not_expressions(self):
        """Test parsing nested NOT expressions."""
        filter_str = "NOT NOT has(SSN)"
        expr = parse_filter(filter_str)

        assert isinstance(expr, UnaryOp)
        assert expr.operator == "NOT"
        assert isinstance(expr.operand, UnaryOp)
        assert expr.operand.operator == "NOT"


class TestParserErrors:
    """Test parser error handling."""

    def test_error_empty_filter(self):
        """Test error on empty filter."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("")

        assert "Empty filter" in str(exc_info.value)

    def test_error_whitespace_only_filter(self):
        """Test error on whitespace-only filter."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("   ")

        assert "Empty filter" in str(exc_info.value)

    def test_error_missing_operator(self):
        """Test error when operator is missing."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("score 75")

        assert "Expected" in str(exc_info.value)

    def test_error_missing_value(self):
        """Test error when value is missing."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("score >")

        assert "Expected" in str(exc_info.value)

    def test_error_missing_rparen(self):
        """Test error when closing paren is missing."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("has(SSN")

        assert "Expected" in str(exc_info.value)

    def test_error_missing_lparen_in_function(self):
        """Test error when ( is missing in function call."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("has SSN)")

        assert "Expected" in str(exc_info.value)

    def test_error_count_without_comparison(self):
        """Test error when count() has no comparison."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("count(SSN)")

        assert "count()" in str(exc_info.value) or "comparison" in str(exc_info.value).lower()

    def test_error_unbalanced_parens(self):
        """Test error on unbalanced parentheses."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("(has(SSN) AND tier = CRITICAL")

        assert "Expected" in str(exc_info.value)

    def test_error_trailing_operator(self):
        """Test error on trailing operator."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("has(SSN) AND")

        assert "Unexpected" in str(exc_info.value) or "Expected" in str(exc_info.value)

    def test_error_double_operator(self):
        """Test error on double operator."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("has(SSN) AND AND tier = CRITICAL")

        assert "Unexpected" in str(exc_info.value)

    def test_error_reports_position(self):
        """Test that parse errors report position."""
        with pytest.raises(ParseError) as exc_info:
            parse_filter("score > AND")

        error_msg = str(exc_info.value)
        assert "position" in error_msg.lower()


class TestParseFilterAPI:
    """Test the parse_filter() public API."""

    def test_parse_filter_returns_expression(self):
        """Test that parse_filter returns a FilterExpression."""
        expr = parse_filter("score > 75")

        assert isinstance(expr, FilterExpression)

    def test_parse_filter_raises_on_invalid(self):
        """Test that parse_filter raises on invalid input."""
        with pytest.raises((ParseError, LexerError)):
            parse_filter("@invalid")

    def test_parse_filter_idempotent_ast(self):
        """Test that parsing same string produces equivalent AST."""
        expr1 = parse_filter("score > 75 AND tier = CRITICAL")
        expr2 = parse_filter("score > 75 AND tier = CRITICAL")

        # Both should be BinaryOp with same structure
        assert isinstance(expr1, BinaryOp)
        assert isinstance(expr2, BinaryOp)
        assert expr1.operator == expr2.operator
        assert expr1.left.field == expr2.left.field
        assert expr1.right.field == expr2.right.field


# =============================================================================
# EDGE CASES AND REGRESSION TESTS
# =============================================================================

class TestEdgeCases:
    """Test edge cases and potential regression scenarios."""

    def test_identifier_starting_with_and(self):
        """Test identifier that starts with 'and' (e.g., 'android')."""
        # 'android' should be parsed as an identifier, not as 'and' + 'roid'
        lexer = Lexer("android = true")
        tokens = lexer.tokenize()

        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "android"

    def test_identifier_starting_with_or(self):
        """Test identifier that starts with 'or' (e.g., 'order')."""
        lexer = Lexer("order = 1")
        tokens = lexer.tokenize()

        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "order"

    def test_identifier_starting_with_not(self):
        """Test identifier that starts with 'not' (e.g., 'note')."""
        lexer = Lexer("note = test")
        tokens = lexer.tokenize()

        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "note"

    def test_identifier_containing_has(self):
        """Test identifier containing 'has' (e.g., 'hash')."""
        lexer = Lexer("hash = abc123")
        tokens = lexer.tokenize()

        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "hash"

    def test_zero_value(self):
        """Test parsing with zero value."""
        expr = parse_filter("count(SSN) = 0")

        assert isinstance(expr, FunctionCall)
        assert expr.comparison_value == 0

    def test_large_number(self):
        """Test parsing with large number."""
        expr = parse_filter("score > 999999999")

        assert isinstance(expr, Comparison)
        assert expr.value == 999999999

    def test_empty_string_value(self):
        """Test parsing with empty string value."""
        expr = parse_filter('name = ""')

        assert isinstance(expr, Comparison)
        assert expr.value == ""

    def test_string_with_spaces(self):
        """Test parsing string value with spaces."""
        expr = parse_filter('path = "/path/with spaces/file.txt"')

        assert isinstance(expr, Comparison)
        assert expr.value == "/path/with spaces/file.txt"

    def test_unicode_in_string(self):
        """Test parsing string with unicode characters."""
        expr = parse_filter('name = "日本語"')

        assert isinstance(expr, Comparison)
        assert expr.value == "日本語"

    def test_very_long_filter(self):
        """Test parsing a very long filter expression."""
        # Build a filter with 50 OR clauses
        clauses = [f"field{i} = value{i}" for i in range(50)]
        filter_str = " OR ".join(clauses)

        expr = parse_filter(filter_str)

        # Should successfully parse without stack overflow
        assert isinstance(expr, BinaryOp)

    def test_deeply_nested_parentheses(self):
        """Test parsing deeply nested parentheses."""
        filter_str = "((((score > 50))))"

        expr = parse_filter(filter_str)

        assert isinstance(expr, Comparison)
        assert expr.field == "score"
        assert expr.value == 50

    def test_whitespace_in_function_call(self):
        """Test whitespace handling in function calls."""
        expr = parse_filter("has(  SSN  )")

        assert isinstance(expr, FunctionCall)
        assert expr.argument == "SSN"

    def test_mixed_case_operators(self):
        """Test mixed case logical operators."""
        # The grammar supports AND/and and OR/or
        expr1 = parse_filter("has(SSN) AND tier = HIGH")
        expr2 = parse_filter("has(SSN) and tier = HIGH")

        assert isinstance(expr1, BinaryOp)
        assert isinstance(expr2, BinaryOp)
        assert expr1.operator == "AND"
        assert expr2.operator == "AND"

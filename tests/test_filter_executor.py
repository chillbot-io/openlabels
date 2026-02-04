"""
Comprehensive tests for CLI filter executor.

Tests filter execution against scan results with strong assertions.
All comparison operators, functions, and logical operators are tested.
"""

import pytest
from dataclasses import dataclass
from typing import Dict, Optional

from openlabels.cli.filter_parser import parse_filter
from openlabels.cli.filter_executor import (
    execute_filter,
    filter_scan_results,
    validate_filter,
    _get_field_value,
    _compare,
    _get_entity_count,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@dataclass
class MockScanResult:
    """Mock scan result object for testing."""
    file_path: str
    file_name: str
    risk_score: int
    risk_tier: str
    entity_counts: Dict[str, int]
    exposure_level: Optional[str] = None
    owner: Optional[str] = None
    total_entities: int = 0


@pytest.fixture
def high_risk_result():
    """High-risk scan result with multiple entity types."""
    return MockScanResult(
        file_path="/data/sensitive/patient_records.xlsx",
        file_name="patient_records.xlsx",
        risk_score=85,
        risk_tier="CRITICAL",
        entity_counts={"SSN": 150, "NAME": 200, "DOB": 150, "CREDIT_CARD": 5},
        exposure_level="PUBLIC",
        owner="admin@example.com",
        total_entities=505,
    )


@pytest.fixture
def medium_risk_result():
    """Medium-risk scan result."""
    return MockScanResult(
        file_path="/data/reports/quarterly_report.pdf",
        file_name="quarterly_report.pdf",
        risk_score=45,
        risk_tier="MEDIUM",
        entity_counts={"EMAIL": 50, "PHONE": 30},
        exposure_level="INTERNAL",
        owner="analyst@example.com",
        total_entities=80,
    )


@pytest.fixture
def low_risk_result():
    """Low-risk scan result."""
    return MockScanResult(
        file_path="/data/public/readme.txt",
        file_name="readme.txt",
        risk_score=5,
        risk_tier="MINIMAL",
        entity_counts={},
        exposure_level="PUBLIC",
        owner=None,
        total_entities=0,
    )


@pytest.fixture
def dict_result():
    """Dictionary-based scan result."""
    return {
        "file_path": "/data/files/document.docx",
        "file_name": "document.docx",
        "risk_score": 65,
        "risk_tier": "HIGH",
        "entity_counts": {"SSN": 10, "NPI": 5, "DEA": 2},
        "exposure_level": "ORG_WIDE",
        "owner": "user@example.com",
        "total_entities": 17,
    }


# =============================================================================
# FIELD VALUE EXTRACTION TESTS
# =============================================================================

class TestGetFieldValue:
    """Test field value extraction from results."""

    def test_get_direct_field_from_object(self, high_risk_result):
        """Test getting a direct field from an object."""
        value = _get_field_value(high_risk_result, "risk_score")
        assert value == 85

    def test_get_direct_field_from_dict(self, dict_result):
        """Test getting a direct field from a dictionary."""
        value = _get_field_value(dict_result, "risk_score")
        assert value == 65

    def test_get_field_with_alias_score(self, high_risk_result):
        """Test 'score' alias for 'risk_score'."""
        value = _get_field_value(high_risk_result, "score")
        assert value == 85

    def test_get_field_with_alias_tier(self, high_risk_result):
        """Test 'tier' alias for 'risk_tier'."""
        value = _get_field_value(high_risk_result, "tier")
        assert value == "CRITICAL"

    def test_get_field_with_alias_exposure(self, high_risk_result):
        """Test 'exposure' alias for 'exposure_level'."""
        value = _get_field_value(high_risk_result, "exposure")
        assert value == "PUBLIC"

    def test_get_field_with_alias_path(self, high_risk_result):
        """Test 'path' alias for 'file_path'."""
        value = _get_field_value(high_risk_result, "path")
        assert value == "/data/sensitive/patient_records.xlsx"

    def test_get_field_with_alias_name(self, high_risk_result):
        """Test 'name' alias for 'file_name'."""
        value = _get_field_value(high_risk_result, "name")
        assert value == "patient_records.xlsx"

    def test_get_field_with_alias_entities(self, high_risk_result):
        """Test 'entities' alias for 'total_entities'."""
        value = _get_field_value(high_risk_result, "entities")
        assert value == 505

    def test_get_field_none_value(self, low_risk_result):
        """Test getting a field with None value."""
        value = _get_field_value(low_risk_result, "owner")
        assert value is None

    def test_get_nonexistent_field(self, high_risk_result):
        """Test getting a nonexistent field returns None."""
        value = _get_field_value(high_risk_result, "nonexistent_field")
        assert value is None

    def test_get_nested_field_from_dict(self):
        """Test getting nested field with dot notation."""
        result = {
            "metadata": {"author": "John Doe", "created": "2024-01-01"},
            "risk_score": 50,
        }
        value = _get_field_value(result, "metadata.author")
        assert value == "John Doe"

    def test_case_insensitive_alias(self, high_risk_result):
        """Test case-insensitive field aliases."""
        value_lower = _get_field_value(high_risk_result, "score")
        value_upper = _get_field_value(high_risk_result, "SCORE")

        assert value_lower == 85
        assert value_upper == 85


# =============================================================================
# COMPARISON OPERATOR TESTS
# =============================================================================

class TestCompareOperator:
    """Test the _compare function for all operators."""

    def test_compare_equals_strings(self):
        """Test = operator with strings."""
        assert _compare("CRITICAL", "=", "CRITICAL") is True
        assert _compare("HIGH", "=", "CRITICAL") is False

    def test_compare_equals_numbers(self):
        """Test = operator with numbers."""
        assert _compare(50, "=", 50) is True
        assert _compare(50, "=", 51) is False

    def test_compare_equals_case_insensitive(self):
        """Test = operator is case-insensitive for strings."""
        assert _compare("critical", "=", "CRITICAL") is True
        assert _compare("Critical", "=", "critical") is True

    def test_compare_not_equals_strings(self):
        """Test != operator with strings."""
        assert _compare("HIGH", "!=", "CRITICAL") is True
        assert _compare("CRITICAL", "!=", "CRITICAL") is False

    def test_compare_not_equals_numbers(self):
        """Test != operator with numbers."""
        assert _compare(50, "!=", 51) is True
        assert _compare(50, "!=", 50) is False

    def test_compare_greater_than(self):
        """Test > operator."""
        assert _compare(75, ">", 50) is True
        assert _compare(50, ">", 75) is False
        assert _compare(50, ">", 50) is False

    def test_compare_greater_than_with_none(self):
        """Test > operator with None left operand."""
        assert _compare(None, ">", 50) is False

    def test_compare_less_than(self):
        """Test < operator."""
        assert _compare(25, "<", 50) is True
        assert _compare(75, "<", 50) is False
        assert _compare(50, "<", 50) is False

    def test_compare_less_than_with_none(self):
        """Test < operator with None left operand."""
        assert _compare(None, "<", 50) is False

    def test_compare_greater_equals(self):
        """Test >= operator."""
        assert _compare(75, ">=", 50) is True
        assert _compare(50, ">=", 50) is True
        assert _compare(25, ">=", 50) is False

    def test_compare_greater_equals_with_none(self):
        """Test >= operator with None left operand."""
        assert _compare(None, ">=", 50) is False

    def test_compare_less_equals(self):
        """Test <= operator."""
        assert _compare(25, "<=", 50) is True
        assert _compare(50, "<=", 50) is True
        assert _compare(75, "<=", 50) is False

    def test_compare_less_equals_with_none(self):
        """Test <= operator with None left operand."""
        assert _compare(None, "<=", 50) is False

    def test_compare_regex_match(self):
        """Test ~ operator for regex matching."""
        assert _compare("/data/files/report.xlsx", "~", r".*\.xlsx$") is True
        assert _compare("/data/files/report.pdf", "~", r".*\.xlsx$") is False

    def test_compare_regex_partial_match(self):
        """Test ~ operator finds partial matches."""
        assert _compare("patient_records_2024.xlsx", "~", "patient") is True
        assert _compare("report.xlsx", "~", "patient") is False

    def test_compare_regex_with_none(self):
        """Test ~ operator with None left operand."""
        assert _compare(None, "~", "pattern") is False

    def test_compare_regex_invalid_pattern(self):
        """Test ~ operator with invalid regex pattern."""
        # Invalid regex should return False, not raise
        assert _compare("test", "~", "[invalid") is False

    def test_compare_contains(self):
        """Test contains operator."""
        assert _compare("/data/sensitive/file.txt", "contains", "sensitive") is True
        assert _compare("/data/public/file.txt", "contains", "sensitive") is False

    def test_compare_contains_case_insensitive(self):
        """Test contains operator is case-insensitive."""
        assert _compare("Sensitive Data", "contains", "sensitive") is True
        assert _compare("sensitive data", "contains", "SENSITIVE") is True

    def test_compare_contains_with_none(self):
        """Test contains operator with None left operand."""
        assert _compare(None, "contains", "text") is False

    def test_compare_unknown_operator(self):
        """Test unknown operator returns False."""
        assert _compare(50, "unknown", 50) is False


# =============================================================================
# ENTITY COUNT TESTS
# =============================================================================

class TestGetEntityCount:
    """Test entity count extraction."""

    def test_get_entity_count_existing(self, high_risk_result):
        """Test getting count of existing entity type."""
        count = _get_entity_count(high_risk_result, "SSN")
        assert count == 150

    def test_get_entity_count_nonexistent(self, high_risk_result):
        """Test getting count of nonexistent entity type returns 0."""
        count = _get_entity_count(high_risk_result, "IBAN")
        assert count == 0

    def test_get_entity_count_case_insensitive(self, high_risk_result):
        """Test entity type lookup is case-insensitive."""
        count_upper = _get_entity_count(high_risk_result, "SSN")
        count_lower = _get_entity_count(high_risk_result, "ssn")

        assert count_upper == 150
        assert count_lower == 150

    def test_get_entity_count_from_dict(self, dict_result):
        """Test getting entity count from dictionary result."""
        count = _get_entity_count(dict_result, "NPI")
        assert count == 5

    def test_get_entity_count_empty_counts(self, low_risk_result):
        """Test getting count from result with empty entity_counts."""
        count = _get_entity_count(low_risk_result, "SSN")
        assert count == 0


# =============================================================================
# EXECUTE FILTER - COMPARISON TESTS
# =============================================================================

class TestExecuteFilterComparisons:
    """Test execute_filter with comparison expressions."""

    def test_filter_score_greater_than_match(self, high_risk_result):
        """Test score > threshold matches high-risk result."""
        expr = parse_filter("score > 50")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_score_greater_than_no_match(self, low_risk_result):
        """Test score > threshold does not match low-risk result."""
        expr = parse_filter("score > 50")
        result = execute_filter(expr, low_risk_result)

        assert result is False

    def test_filter_tier_equals_match(self, high_risk_result):
        """Test tier = value matches."""
        expr = parse_filter("tier = CRITICAL")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_tier_equals_no_match(self, medium_risk_result):
        """Test tier = value does not match different tier."""
        expr = parse_filter("tier = CRITICAL")
        result = execute_filter(expr, medium_risk_result)

        assert result is False

    def test_filter_tier_not_equals(self, high_risk_result):
        """Test tier != value."""
        expr = parse_filter("tier != MINIMAL")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_exposure_equals(self, high_risk_result):
        """Test exposure = value."""
        expr = parse_filter("exposure = PUBLIC")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_path_regex_match(self, high_risk_result):
        """Test path ~ regex matches."""
        expr = parse_filter('path ~ ".*\\.xlsx$"')
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_path_regex_no_match(self, medium_risk_result):
        """Test path ~ regex does not match different extension."""
        expr = parse_filter('path ~ ".*\\.xlsx$"')
        result = execute_filter(expr, medium_risk_result)

        assert result is False

    def test_filter_name_contains(self, high_risk_result):
        """Test name contains substring."""
        expr = parse_filter('name contains "patient"')
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_name_contains_no_match(self, medium_risk_result):
        """Test name contains substring - no match."""
        expr = parse_filter('name contains "patient"')
        result = execute_filter(expr, medium_risk_result)

        assert result is False


# =============================================================================
# EXECUTE FILTER - FUNCTION TESTS
# =============================================================================

class TestExecuteFilterFunctions:
    """Test execute_filter with function call expressions."""

    def test_filter_has_entity_match(self, high_risk_result):
        """Test has(entity) matches when entity exists."""
        expr = parse_filter("has(SSN)")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_has_entity_no_match(self, medium_risk_result):
        """Test has(entity) does not match when entity missing."""
        expr = parse_filter("has(SSN)")
        result = execute_filter(expr, medium_risk_result)

        assert result is False

    def test_filter_has_entity_empty_counts(self, low_risk_result):
        """Test has(entity) with empty entity_counts."""
        expr = parse_filter("has(SSN)")
        result = execute_filter(expr, low_risk_result)

        assert result is False

    def test_filter_has_entity_case_insensitive(self, high_risk_result):
        """Test has() is case-insensitive for entity type."""
        expr_upper = parse_filter("has(SSN)")
        expr_lower = parse_filter("has(ssn)")

        assert execute_filter(expr_upper, high_risk_result) is True
        assert execute_filter(expr_lower, high_risk_result) is True

    def test_filter_missing_field_match(self, low_risk_result):
        """Test missing(field) matches when field is None."""
        expr = parse_filter("missing(owner)")
        result = execute_filter(expr, low_risk_result)

        assert result is True

    def test_filter_missing_field_no_match(self, high_risk_result):
        """Test missing(field) does not match when field has value."""
        expr = parse_filter("missing(owner)")
        result = execute_filter(expr, high_risk_result)

        assert result is False

    def test_filter_missing_empty_string(self):
        """Test missing() matches empty string."""
        result = MockScanResult(
            file_path="test.txt",
            file_name="test.txt",
            risk_score=0,
            risk_tier="MINIMAL",
            entity_counts={},
            owner="   ",  # Whitespace only
        )
        expr = parse_filter("missing(owner)")

        assert execute_filter(expr, result) is True

    def test_filter_missing_empty_list(self):
        """Test missing() matches empty list."""
        result = {"file_path": "test.txt", "tags": [], "entity_counts": {}}
        expr = parse_filter("missing(tags)")

        assert execute_filter(expr, result) is True

    def test_filter_count_equals(self, high_risk_result):
        """Test count(entity) = value."""
        expr = parse_filter("count(SSN) = 150")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_count_greater_equals(self, high_risk_result):
        """Test count(entity) >= value."""
        expr = parse_filter("count(SSN) >= 100")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_count_less_than(self, high_risk_result):
        """Test count(entity) < value."""
        expr = parse_filter("count(CREDIT_CARD) < 10")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_count_not_equals(self, high_risk_result):
        """Test count(entity) != value."""
        expr = parse_filter("count(SSN) != 0")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_count_zero_for_missing(self, medium_risk_result):
        """Test count() returns 0 for missing entity type."""
        expr = parse_filter("count(SSN) = 0")
        result = execute_filter(expr, medium_risk_result)

        assert result is True


# =============================================================================
# EXECUTE FILTER - LOGICAL OPERATOR TESTS
# =============================================================================

class TestExecuteFilterLogicalOperators:
    """Test execute_filter with logical operators."""

    def test_filter_and_both_true(self, high_risk_result):
        """Test AND when both conditions are true."""
        expr = parse_filter("score > 50 AND has(SSN)")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_and_first_false(self, low_risk_result):
        """Test AND when first condition is false."""
        expr = parse_filter("score > 50 AND tier = CRITICAL")
        result = execute_filter(expr, low_risk_result)

        assert result is False

    def test_filter_and_second_false(self, high_risk_result):
        """Test AND when second condition is false."""
        expr = parse_filter("score > 50 AND tier = MINIMAL")
        result = execute_filter(expr, high_risk_result)

        assert result is False

    def test_filter_and_short_circuit(self, high_risk_result):
        """Test AND short-circuits on first false."""
        # First condition is false, second would error if evaluated
        expr = parse_filter("score < 0 AND count(NONEXISTENT) > 999999")
        result = execute_filter(expr, high_risk_result)

        assert result is False

    def test_filter_or_both_true(self, high_risk_result):
        """Test OR when both conditions are true."""
        expr = parse_filter("has(SSN) OR has(NAME)")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_or_first_true(self, high_risk_result):
        """Test OR when first condition is true."""
        expr = parse_filter("has(SSN) OR tier = MINIMAL")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_or_second_true(self, high_risk_result):
        """Test OR when second condition is true."""
        expr = parse_filter("tier = MINIMAL OR has(SSN)")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_or_both_false(self, low_risk_result):
        """Test OR when both conditions are false."""
        expr = parse_filter("has(SSN) OR has(CREDIT_CARD)")
        result = execute_filter(expr, low_risk_result)

        assert result is False

    def test_filter_or_short_circuit(self, high_risk_result):
        """Test OR short-circuits on first true."""
        expr = parse_filter("has(SSN) OR count(NONEXISTENT) > 999999")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_not_true(self, low_risk_result):
        """Test NOT inverts true to false."""
        expr = parse_filter("NOT tier = MINIMAL")
        result = execute_filter(expr, low_risk_result)

        assert result is False

    def test_filter_not_false(self, high_risk_result):
        """Test NOT inverts false to true."""
        expr = parse_filter("NOT tier = MINIMAL")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_not_has(self, low_risk_result):
        """Test NOT has(entity)."""
        expr = parse_filter("NOT has(SSN)")
        result = execute_filter(expr, low_risk_result)

        assert result is True

    def test_filter_double_not(self, high_risk_result):
        """Test NOT NOT cancels out."""
        expr = parse_filter("NOT NOT has(SSN)")
        result = execute_filter(expr, high_risk_result)

        assert result is True


# =============================================================================
# EXECUTE FILTER - COMPLEX EXPRESSIONS
# =============================================================================

class TestExecuteFilterComplex:
    """Test execute_filter with complex expressions."""

    def test_filter_multiple_and(self, high_risk_result):
        """Test multiple AND conditions."""
        expr = parse_filter("score > 50 AND tier = CRITICAL AND has(SSN) AND has(CREDIT_CARD)")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_multiple_or(self, high_risk_result):
        """Test multiple OR conditions."""
        expr = parse_filter("has(SSN) OR has(NPI) OR has(DEA) OR has(IBAN)")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_mixed_and_or(self, high_risk_result):
        """Test mixed AND/OR with correct precedence."""
        # has(SSN) OR (score > 90 AND tier = HIGH)
        # First clause is true, so result should be true
        expr = parse_filter("has(SSN) OR score > 90 AND tier = HIGH")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_grouped_or_with_and(self, high_risk_result):
        """Test (A OR B) AND C pattern."""
        expr = parse_filter("(has(SSN) OR has(NPI)) AND tier = CRITICAL")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_grouped_and_with_or(self, high_risk_result):
        """Test A OR (B AND C) pattern."""
        expr = parse_filter("tier = MINIMAL OR (score > 50 AND has(SSN))")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_complex_real_world(self, high_risk_result):
        """Test complex real-world filter."""
        filter_str = (
            '(has(SSN) OR has(CREDIT_CARD)) AND tier = CRITICAL AND '
            'score >= 80 AND path ~ ".*\\.xlsx$"'
        )
        expr = parse_filter(filter_str)
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_complex_no_match(self, medium_risk_result):
        """Test complex filter that doesn't match."""
        filter_str = (
            'has(SSN) AND tier = CRITICAL AND score >= 80'
        )
        expr = parse_filter(filter_str)
        result = execute_filter(expr, medium_risk_result)

        assert result is False


# =============================================================================
# FILTER SCAN RESULTS TESTS
# =============================================================================

class TestFilterScanResults:
    """Test filter_scan_results function."""

    def test_filter_scan_results_match_one(
        self, high_risk_result, medium_risk_result, low_risk_result
    ):
        """Test filtering returns only matching results."""
        results = [high_risk_result, medium_risk_result, low_risk_result]

        filtered = filter_scan_results(results, "tier = CRITICAL")

        assert len(filtered) == 1
        assert filtered[0].risk_tier == "CRITICAL"

    def test_filter_scan_results_match_multiple(
        self, high_risk_result, medium_risk_result, low_risk_result
    ):
        """Test filtering can return multiple results."""
        results = [high_risk_result, medium_risk_result, low_risk_result]

        filtered = filter_scan_results(results, "score > 10")

        assert len(filtered) == 2
        assert high_risk_result in filtered
        assert medium_risk_result in filtered

    def test_filter_scan_results_match_none(
        self, high_risk_result, medium_risk_result, low_risk_result
    ):
        """Test filtering can return empty list."""
        results = [high_risk_result, medium_risk_result, low_risk_result]

        filtered = filter_scan_results(results, "has(IBAN)")

        assert len(filtered) == 0

    def test_filter_scan_results_match_all(
        self, high_risk_result, medium_risk_result, low_risk_result
    ):
        """Test filtering can return all results."""
        results = [high_risk_result, medium_risk_result, low_risk_result]

        filtered = filter_scan_results(results, "score >= 0")

        assert len(filtered) == 3

    def test_filter_scan_results_empty_input(self):
        """Test filtering empty list returns empty list."""
        filtered = filter_scan_results([], "score > 50")

        assert len(filtered) == 0

    def test_filter_scan_results_with_dict(self, dict_result):
        """Test filtering works with dictionary results."""
        results = [dict_result]

        filtered = filter_scan_results(results, "has(NPI)")

        assert len(filtered) == 1


# =============================================================================
# VALIDATE FILTER TESTS
# =============================================================================

class TestValidateFilter:
    """Test validate_filter function."""

    def test_validate_valid_filter(self):
        """Test validation returns None for valid filter."""
        result = validate_filter("score > 50 AND has(SSN)")

        assert result is None

    def test_validate_invalid_filter_syntax(self):
        """Test validation returns error message for invalid syntax."""
        result = validate_filter("score > ")

        assert result is not None, "Should return error for incomplete filter"
        assert isinstance(result, str), f"Error should be string, got {type(result)}"
        # Error message should indicate something about the syntax issue
        assert "error" in result.lower() or "expected" in result.lower() or "unexpected" in result.lower(), \
            f"Error message should describe syntax issue: {result}"

    def test_validate_invalid_filter_lexer_error(self):
        """Test validation returns error for lexer errors."""
        result = validate_filter('"unterminated')

        assert result is not None
        assert isinstance(result, str)

    def test_validate_empty_filter(self):
        """Test validation returns error for empty filter."""
        result = validate_filter("")

        assert result is not None
        assert "Empty" in result or "empty" in result.lower()

    def test_validate_complex_valid_filter(self):
        """Test validation of complex valid filter."""
        filter_str = (
            '(has(SSN) OR has(CREDIT_CARD)) AND tier != MINIMAL AND '
            'count(EMAIL) >= 10 AND path ~ ".*\\.xlsx$"'
        )
        result = validate_filter(filter_str)

        assert result is None


# =============================================================================
# EDGE CASES AND REGRESSION TESTS
# =============================================================================

class TestEdgeCases:
    """Test edge cases and potential issues."""

    def test_filter_with_zero_score(self):
        """Test filtering with score of exactly 0."""
        result = MockScanResult(
            file_path="test.txt",
            file_name="test.txt",
            risk_score=0,
            risk_tier="MINIMAL",
            entity_counts={},
        )
        expr = parse_filter("score = 0")

        assert execute_filter(expr, result) is True

    def test_filter_with_negative_in_comparison(self):
        """Test comparison with negative numbers in data."""
        result = {"risk_score": -5, "entity_counts": {}}
        expr = parse_filter("score < 0")

        assert execute_filter(expr, result) is True

    def test_filter_entity_type_with_underscore(self, high_risk_result):
        """Test entity types with underscores."""
        expr = parse_filter("has(CREDIT_CARD)")
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_string_comparison_with_special_chars(self):
        """Test string comparison with special characters."""
        result = {
            "file_path": "/data/files/report [2024].xlsx",
            "entity_counts": {},
        }
        expr = parse_filter('path ~ "\\[2024\\]"')

        assert execute_filter(expr, result) is True

    def test_filter_unicode_in_path(self):
        """Test filtering with unicode in paths."""
        result = {
            "file_path": "/data/ファイル/document.xlsx",
            "entity_counts": {},
        }
        expr = parse_filter('path contains "ファイル"')

        assert execute_filter(expr, result) is True

    def test_filter_very_large_count(self):
        """Test filtering with very large entity counts."""
        result = MockScanResult(
            file_path="big.xlsx",
            file_name="big.xlsx",
            risk_score=100,
            risk_tier="CRITICAL",
            entity_counts={"SSN": 1000000},
            total_entities=1000000,
        )
        expr = parse_filter("count(SSN) >= 1000000")

        assert execute_filter(expr, result) is True

    def test_filter_float_score(self):
        """Test filtering with float score (should work if data has floats)."""
        result = {"risk_score": 75.5, "entity_counts": {}}
        expr = parse_filter("score > 75.4")

        assert execute_filter(expr, result) is True

    def test_filter_case_sensitivity_entity_types(self, dict_result):
        """Test entity type case handling in counts."""
        # Entity counts might have mixed case keys
        result = {"entity_counts": {"Ssn": 5, "npi": 3}}

        expr_upper = parse_filter("has(SSN)")
        expr_lower = parse_filter("has(ssn)")

        assert execute_filter(expr_upper, result) is True
        assert execute_filter(expr_lower, result) is True

    def test_filter_empty_string_in_contains(self):
        """Test contains with empty string always matches."""
        result = {"file_path": "/any/path.txt", "entity_counts": {}}
        expr = parse_filter('path contains ""')

        assert execute_filter(expr, result) is True

    def test_filter_regex_anchors(self):
        """Test regex with anchors."""
        result = {"file_path": "document.xlsx", "entity_counts": {}}

        expr_start = parse_filter('path ~ "^document"')
        expr_end = parse_filter('path ~ "\\.xlsx$"')

        assert execute_filter(expr_start, result) is True
        assert execute_filter(expr_end, result) is True

    def test_filter_owner_is_email(self, high_risk_result):
        """Test filtering owner field with email format."""
        expr = parse_filter('owner ~ ".*@example\\.com$"')
        result = execute_filter(expr, high_risk_result)

        assert result is True

    def test_filter_chained_or_with_has(self):
        """Test chained OR with has() for multiple entity types."""
        result = {"entity_counts": {"EMAIL": 10}}

        expr = parse_filter("has(SSN) OR has(CREDIT_CARD) OR has(EMAIL)")

        assert execute_filter(expr, result) is True


class TestFilterWithEnumValues:
    """Test filtering with enum-like values."""

    def test_filter_tier_all_values(self):
        """Test filtering matches all tier values correctly."""
        tiers = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        for tier in tiers:
            result = MockScanResult(
                file_path="test.txt",
                file_name="test.txt",
                risk_score=50,
                risk_tier=tier,
                entity_counts={},
            )
            expr = parse_filter(f"tier = {tier}")

            assert execute_filter(expr, result) is True, f"Failed for tier {tier}"

    def test_filter_exposure_all_values(self):
        """Test filtering matches all exposure values correctly."""
        exposures = ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]

        for exposure in exposures:
            result = MockScanResult(
                file_path="test.txt",
                file_name="test.txt",
                risk_score=50,
                risk_tier="MEDIUM",
                entity_counts={},
                exposure_level=exposure,
            )
            expr = parse_filter(f"exposure = {exposure}")

            assert execute_filter(expr, result) is True, f"Failed for exposure {exposure}"

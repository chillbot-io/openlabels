"""Tests for gender inference in gender.py.

Tests heuristic-based gender inference for pronoun resolution.
This is for linguistic purposes, not gender classification.
"""

import pytest
from scrubiq.pipeline.gender import (
    infer_gender,
    infer_gender_from_context,
    infer_gender_with_confidence,
    is_name_entity_type,
    MALE_NAMES,
    FEMALE_NAMES,
    NEUTRAL_NAMES,
    MALE_TITLES,
    FEMALE_TITLES,
    MALE_SUFFIXES,
)


# =============================================================================
# NAME CONSTANTS TESTS
# =============================================================================

class TestNameConstants:
    """Tests for name set constants."""

    def test_male_names_not_empty(self):
        """MALE_NAMES set is populated."""
        assert len(MALE_NAMES) > 50

    def test_female_names_not_empty(self):
        """FEMALE_NAMES set is populated."""
        assert len(FEMALE_NAMES) > 50

    def test_neutral_names_not_empty(self):
        """NEUTRAL_NAMES set is populated."""
        assert len(NEUTRAL_NAMES) > 50

    def test_neutral_names_are_lowercase(self):
        """All names in NEUTRAL_NAMES are lowercase."""
        for name in NEUTRAL_NAMES:
            assert name == name.lower(), f"{name} not lowercase"

    def test_neutral_names_contains_common(self):
        """NEUTRAL_NAMES contains common gender-neutral names."""
        common = ["alex", "jordan", "taylor", "casey", "morgan", "riley", "avery"]
        for name in common:
            assert name in NEUTRAL_NAMES, f"{name} not in NEUTRAL_NAMES"

    def test_neutral_names_not_in_gendered_sets(self):
        """NEUTRAL_NAMES should not appear in MALE_NAMES or FEMALE_NAMES."""
        # This is critical - neutral names must not be assigned a gender
        male_overlap = NEUTRAL_NAMES & MALE_NAMES
        female_overlap = NEUTRAL_NAMES & FEMALE_NAMES
        assert len(male_overlap) == 0, f"Neutral names in MALE_NAMES: {male_overlap}"
        assert len(female_overlap) == 0, f"Neutral names in FEMALE_NAMES: {female_overlap}"

    def test_male_names_are_lowercase(self):
        """All names in MALE_NAMES are lowercase."""
        for name in MALE_NAMES:
            assert name == name.lower(), f"{name} not lowercase"

    def test_female_names_are_lowercase(self):
        """All names in FEMALE_NAMES are lowercase."""
        for name in FEMALE_NAMES:
            assert name == name.lower(), f"{name} not lowercase"

    def test_male_names_contains_common(self):
        """MALE_NAMES contains common male names."""
        common = ["john", "james", "michael", "david", "robert"]
        for name in common:
            assert name in MALE_NAMES

    def test_female_names_contains_common(self):
        """FEMALE_NAMES contains common female names."""
        common = ["mary", "jennifer", "elizabeth", "sarah", "jessica"]
        for name in common:
            assert name in FEMALE_NAMES

    def test_no_overlap(self):
        """MALE_NAMES and FEMALE_NAMES have some overlap for unisex names."""
        # Some names are genuinely unisex (Andrea, etc.)
        # The sets may have minimal overlap
        overlap = MALE_NAMES & FEMALE_NAMES
        # Could be empty or have a few unisex names
        assert len(overlap) < 20


# =============================================================================
# TITLE/SUFFIX PATTERNS TESTS
# =============================================================================

class TestTitlePatterns:
    """Tests for title regex patterns."""

    def test_male_title_mr(self):
        """MALE_TITLES matches 'Mr.' and 'Mr'."""
        assert MALE_TITLES.match("Mr. Smith")
        assert MALE_TITLES.match("Mr Smith")

    def test_male_title_sir(self):
        """MALE_TITLES matches 'Sir'."""
        assert MALE_TITLES.match("Sir John")

    def test_male_title_lord(self):
        """MALE_TITLES matches 'Lord'."""
        assert MALE_TITLES.match("Lord Byron")

    def test_male_title_master(self):
        """MALE_TITLES matches 'Master'."""
        assert MALE_TITLES.match("Master Tommy")

    def test_female_title_mrs(self):
        """FEMALE_TITLES matches 'Mrs.' and 'Mrs'."""
        assert FEMALE_TITLES.match("Mrs. Jones")
        assert FEMALE_TITLES.match("Mrs Jones")

    def test_female_title_ms(self):
        """FEMALE_TITLES matches 'Ms.' and 'Ms'."""
        assert FEMALE_TITLES.match("Ms. Chen")
        assert FEMALE_TITLES.match("Ms Chen")

    def test_female_title_miss(self):
        """FEMALE_TITLES matches 'Miss'."""
        assert FEMALE_TITLES.match("Miss Taylor")

    def test_female_title_madam(self):
        """FEMALE_TITLES matches 'Madam'."""
        assert FEMALE_TITLES.match("Madam Secretary")

    def test_female_title_lady(self):
        """FEMALE_TITLES matches 'Lady'."""
        assert FEMALE_TITLES.match("Lady Diana")

    def test_female_title_dame(self):
        """FEMALE_TITLES matches 'Dame'."""
        assert FEMALE_TITLES.match("Dame Judi Dench")

    def test_titles_case_insensitive(self):
        """Titles match case-insensitively."""
        assert MALE_TITLES.match("MR. SMITH")
        assert MALE_TITLES.match("mr. smith")
        assert FEMALE_TITLES.match("MRS. JONES")
        assert FEMALE_TITLES.match("mrs. jones")

    def test_male_suffix_jr(self):
        """MALE_SUFFIXES matches 'Jr.' and 'Jr'."""
        assert MALE_SUFFIXES.search("John Smith Jr.")
        assert MALE_SUFFIXES.search("John Smith Jr")

    def test_male_suffix_sr(self):
        """MALE_SUFFIXES matches 'Sr.'."""
        assert MALE_SUFFIXES.search("John Smith Sr.")

    def test_male_suffix_numerals(self):
        """MALE_SUFFIXES matches II, III, IV."""
        assert MALE_SUFFIXES.search("John Smith II")
        assert MALE_SUFFIXES.search("John Smith III")
        assert MALE_SUFFIXES.search("John Smith IV")

    def test_male_suffix_esq(self):
        """MALE_SUFFIXES matches 'Esq.'."""
        assert MALE_SUFFIXES.search("John Smith Esq.")
        assert MALE_SUFFIXES.search("John Smith, Esq.")


# =============================================================================
# INFER_GENDER TESTS
# =============================================================================

class TestInferGender:
    """Tests for infer_gender() function."""

    def test_empty_string_returns_none(self):
        """Empty string returns None."""
        assert infer_gender("") is None

    def test_none_returns_none(self):
        """None input returns None."""
        assert infer_gender(None) is None

    def test_whitespace_only_returns_none(self):
        """Whitespace-only returns None."""
        assert infer_gender("   ") is None

    def test_common_male_name(self):
        """Common male names return 'M'."""
        assert infer_gender("John") == "M"
        assert infer_gender("Michael") == "M"
        assert infer_gender("David") == "M"

    def test_common_female_name(self):
        """Common female names return 'F'."""
        assert infer_gender("Mary") == "F"
        assert infer_gender("Jennifer") == "F"
        assert infer_gender("Sarah") == "F"

    def test_case_insensitive_lookup(self):
        """Name lookup is case-insensitive."""
        assert infer_gender("JOHN") == "M"
        assert infer_gender("john") == "M"
        assert infer_gender("John") == "M"
        assert infer_gender("MARY") == "F"
        assert infer_gender("mary") == "F"

    def test_full_name_uses_first(self):
        """Full name extracts and checks first name."""
        assert infer_gender("John Smith") == "M"
        assert infer_gender("Mary Johnson") == "F"

    def test_mr_title_returns_male(self):
        """Mr. title returns 'M' regardless of name."""
        assert infer_gender("Mr. Unknown") == "M"
        assert infer_gender("Mr. Test") == "M"

    def test_mrs_title_returns_female(self):
        """Mrs. title returns 'F' regardless of name."""
        assert infer_gender("Mrs. Unknown") == "F"
        assert infer_gender("Mrs. Test") == "F"

    def test_ms_title_returns_female(self):
        """Ms. title returns 'F'."""
        assert infer_gender("Ms. Unknown") == "F"

    def test_miss_title_returns_female(self):
        """Miss title returns 'F'."""
        assert infer_gender("Miss Unknown") == "F"

    def test_sir_title_returns_male(self):
        """Sir title returns 'M'."""
        assert infer_gender("Sir Unknown") == "M"

    def test_suffix_stripped_for_lookup(self):
        """Suffixes like Jr. are stripped before lookup."""
        assert infer_gender("John Smith Jr.") == "M"
        assert infer_gender("Robert Wilson III") == "M"

    def test_unknown_name_returns_none(self):
        """Unknown names return None."""
        assert infer_gender("Xyzzy") is None
        assert infer_gender("Qwerty Uiop") is None

    def test_hyphenated_first_name(self):
        """Hyphenated names check first component."""
        assert infer_gender("Mary-Jane Watson") == "F"
        assert infer_gender("John-Paul Jones") == "M"

    def test_hyphenated_unknown_returns_none(self):
        """Hyphenated unknown name returns None."""
        assert infer_gender("Xyz-Abc Smith") is None

    def test_neutral_name_returns_none(self):
        """Gender-neutral names return None."""
        assert infer_gender("Alex") is None
        assert infer_gender("Jordan") is None
        assert infer_gender("Taylor") is None
        assert infer_gender("Casey") is None
        assert infer_gender("Morgan") is None

    def test_neutral_name_full_name_returns_none(self):
        """Full names with neutral first name return None."""
        assert infer_gender("Alex Smith") is None
        assert infer_gender("Jordan Lee") is None
        assert infer_gender("Taylor Johnson") is None

    def test_neutral_name_with_title_uses_title(self):
        """Neutral name with title uses title for gender."""
        assert infer_gender("Mr. Alex Smith") == "M"
        assert infer_gender("Mrs. Jordan Lee") == "F"
        assert infer_gender("Ms. Taylor Johnson") == "F"

    def test_hyphenated_neutral_first_returns_none(self):
        """Hyphenated name with neutral first component returns None."""
        assert infer_gender("Alex-Marie Smith") is None
        assert infer_gender("Jordan-Lee Williams") is None

    def test_international_male_names(self):
        """International male names are recognized."""
        assert infer_gender("Mohammed") == "M"
        assert infer_gender("Juan") == "M"
        assert infer_gender("Hans") == "M"
        assert infer_gender("Pierre") == "M"
        assert infer_gender("Giovanni") == "M"

    def test_international_female_names(self):
        """International female names are recognized."""
        assert infer_gender("Fatima") == "F"
        assert infer_gender("Maria") == "F"
        assert infer_gender("Ingrid") == "F"
        assert infer_gender("Marie") == "F"
        assert infer_gender("Giulia") == "F"

    def test_nickname_male(self):
        """Common male nicknames are recognized."""
        assert infer_gender("Bob") == "M"
        assert infer_gender("Jim") == "M"
        assert infer_gender("Mike") == "M"

    def test_nickname_female(self):
        """Common female nicknames are recognized."""
        assert infer_gender("Kate") == "F"
        assert infer_gender("Jenny") == "F"
        assert infer_gender("Beth") == "F"

    def test_leading_trailing_whitespace_handled(self):
        """Leading/trailing whitespace is stripped."""
        assert infer_gender("  John  ") == "M"
        assert infer_gender("\tMary\n") == "F"

    def test_first_name_with_period(self):
        """First name with trailing period is handled."""
        # e.g., "J." or "J. Smith"
        result = infer_gender("J. Smith")
        # "J" stripped of period, not in lists → None
        assert result is None


# =============================================================================
# INFER_GENDER_WITH_CONFIDENCE TESTS
# =============================================================================

class TestInferGenderWithConfidence:
    """Tests for infer_gender_with_confidence() function."""

    def test_returns_tuple(self):
        """Returns a (gender, confidence) tuple."""
        result = infer_gender_with_confidence("John")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_empty_string_returns_none_zero(self):
        """Empty string returns (None, 0.0)."""
        gender, confidence = infer_gender_with_confidence("")
        assert gender is None
        assert confidence == 0.0

    def test_none_returns_none_zero(self):
        """None input returns (None, 0.0)."""
        gender, confidence = infer_gender_with_confidence(None)
        assert gender is None
        assert confidence == 0.0

    def test_whitespace_returns_none_zero(self):
        """Whitespace-only returns (None, 0.0)."""
        gender, confidence = infer_gender_with_confidence("   ")
        assert gender is None
        assert confidence == 0.0

    def test_male_title_high_confidence(self):
        """Male title returns M with 0.95 confidence."""
        gender, confidence = infer_gender_with_confidence("Mr. Unknown")
        assert gender == "M"
        assert confidence == 0.95

    def test_female_title_high_confidence(self):
        """Female title returns F with 0.95 confidence."""
        gender, confidence = infer_gender_with_confidence("Mrs. Unknown")
        assert gender == "F"
        assert confidence == 0.95

    def test_ms_title_high_confidence(self):
        """Ms. title returns F with 0.95 confidence."""
        gender, confidence = infer_gender_with_confidence("Ms. Unknown")
        assert gender == "F"
        assert confidence == 0.95

    def test_sir_title_high_confidence(self):
        """Sir title returns M with 0.95 confidence."""
        gender, confidence = infer_gender_with_confidence("Sir Unknown")
        assert gender == "M"
        assert confidence == 0.95

    def test_male_name_medium_confidence(self):
        """Male name returns M with 0.85 confidence."""
        gender, confidence = infer_gender_with_confidence("John")
        assert gender == "M"
        assert confidence == 0.85

    def test_female_name_medium_confidence(self):
        """Female name returns F with 0.85 confidence."""
        gender, confidence = infer_gender_with_confidence("Mary")
        assert gender == "F"
        assert confidence == 0.85

    def test_neutral_name_returns_none_zero(self):
        """Neutral name returns (None, 0.0)."""
        gender, confidence = infer_gender_with_confidence("Alex")
        assert gender is None
        assert confidence == 0.0

    def test_unknown_name_returns_none_zero(self):
        """Unknown name returns (None, 0.0)."""
        gender, confidence = infer_gender_with_confidence("Xyzzy")
        assert gender is None
        assert confidence == 0.0

    def test_full_name_checks_first(self):
        """Full name checks first name."""
        gender, confidence = infer_gender_with_confidence("John Smith")
        assert gender == "M"
        assert confidence == 0.85

    def test_title_trumps_name(self):
        """Title takes precedence over name for confidence."""
        # Even with known name, title gives higher confidence
        gender, confidence = infer_gender_with_confidence("Mr. John Smith")
        assert gender == "M"
        assert confidence == 0.95

    def test_suffixes_stripped(self):
        """Suffixes are stripped before lookup."""
        gender, confidence = infer_gender_with_confidence("John Smith Jr.")
        assert gender == "M"
        assert confidence == 0.85

    def test_confidence_values_are_valid(self):
        """Confidence values are between 0 and 1."""
        test_names = ["John", "Mary", "Alex", "Unknown", "Mr. Test", "Mrs. Test", ""]
        for name in test_names:
            gender, confidence = infer_gender_with_confidence(name)
            assert 0.0 <= confidence <= 1.0, f"Invalid confidence {confidence} for {name}"


# =============================================================================
# INFER_GENDER_FROM_CONTEXT TESTS
# =============================================================================

class TestInferGenderFromContext:
    """Tests for infer_gender_from_context() function."""

    def test_empty_context_falls_back_to_name(self):
        """Empty context falls back to name-based inference."""
        assert infer_gender_from_context("John", "") == "M"
        assert infer_gender_from_context("Mary", "") == "F"

    def test_none_context_falls_back_to_name(self):
        """None context falls back to name-based inference."""
        assert infer_gender_from_context("John", None) == "M"

    def test_male_pronoun_he(self):
        """'he' pronoun after name indicates male."""
        context = "John said he was happy"
        assert infer_gender_from_context("John", context) == "M"

    def test_male_pronoun_his(self):
        """'his' pronoun after name indicates male."""
        context = "John took his medication"
        assert infer_gender_from_context("John", context) == "M"

    def test_male_pronoun_him(self):
        """'him' pronoun after name indicates male."""
        context = "They called Unknown and told him the news"
        assert infer_gender_from_context("Unknown", context) == "M"

    def test_female_pronoun_she(self):
        """'she' pronoun after name indicates female."""
        context = "Unknown said she was ready"
        assert infer_gender_from_context("Unknown", context) == "F"

    def test_female_pronoun_her(self):
        """'her' pronoun after name indicates female."""
        context = "Unknown brought her bag"
        assert infer_gender_from_context("Unknown", context) == "F"

    def test_male_relationship_father(self):
        """'father' relationship indicates male."""
        context = "Unknown is a father of two"
        assert infer_gender_from_context("Unknown", context) == "M"

    def test_male_relationship_son(self):
        """'son' relationship indicates male."""
        context = "Unknown is their son"
        assert infer_gender_from_context("Unknown", context) == "M"

    def test_male_relationship_brother(self):
        """'brother' relationship indicates male."""
        context = "Unknown is their brother and he works here"
        assert infer_gender_from_context("Unknown", context) == "M"

    def test_female_relationship_mother(self):
        """'mother' relationship indicates female."""
        context = "Unknown is a mother of three"
        assert infer_gender_from_context("Unknown", context) == "F"

    def test_female_relationship_daughter(self):
        """'daughter' relationship indicates female."""
        context = "Unknown is their daughter"
        assert infer_gender_from_context("Unknown", context) == "F"

    def test_female_relationship_sister(self):
        """'sister' relationship indicates female."""
        context = "Unknown is their sister and she lives nearby"
        assert infer_gender_from_context("Unknown", context) == "F"

    def test_male_label_male(self):
        """'male' label indicates male."""
        context = "Unknown is a male patient"
        assert infer_gender_from_context("Unknown", context) == "M"

    def test_female_label_female(self):
        """'female' label indicates female."""
        context = "Unknown is a female patient"
        assert infer_gender_from_context("Unknown", context) == "F"

    def test_name_not_in_context_falls_back(self):
        """If name not found in context, falls back to name-based."""
        context = "Someone said they were ready"
        assert infer_gender_from_context("John", context) == "M"

    def test_no_gender_signals_falls_back(self):
        """No gender signals falls back to name-based."""
        context = "Unknown arrived at the office today"
        # No pronouns or relationship words
        result = infer_gender_from_context("Unknown", context)
        # Falls back to name-based, "Unknown" not recognized
        assert result is None

    def test_mixed_signals_higher_count_wins(self):
        """When mixed signals, higher count wins."""
        # More male signals than female
        context = "Unknown said he took his medication and he felt better"
        assert infer_gender_from_context("Unknown", context) == "M"

        # More female signals
        context = "Unknown said she took her medication and she felt better"
        assert infer_gender_from_context("Unknown", context) == "F"

    def test_equal_signals_falls_back(self):
        """Equal signals falls back to name-based."""
        context = "Unknown said he or she was ready"
        # Equal signals, falls back to name
        result = infer_gender_from_context("John", context)
        assert result == "M"  # Name-based

    def test_case_insensitive_context(self):
        """Context search is case-insensitive."""
        context = "UNKNOWN said HE was ready"
        assert infer_gender_from_context("Unknown", context) == "M"

    def test_looks_after_name(self):
        """Primarily looks at text after the name."""
        # Pronouns before name might not be about that person
        context = "She told Unknown something"
        # "she" appears before "Unknown", not after
        # After "Unknown" there's no gender signal
        result = infer_gender_from_context("Unknown", context)
        # With no signals after name, falls back
        assert result is None


# =============================================================================
# IS_NAME_ENTITY_TYPE TESTS
# =============================================================================

class TestIsNameEntityType:
    """Tests for is_name_entity_type() function."""

    def test_name_is_name_type(self):
        """'NAME' is a name entity type."""
        assert is_name_entity_type("NAME") is True

    def test_name_patient_is_name_type(self):
        """'NAME_PATIENT' is a name entity type."""
        assert is_name_entity_type("NAME_PATIENT") is True

    def test_name_provider_is_name_type(self):
        """'NAME_PROVIDER' is a name entity type."""
        assert is_name_entity_type("NAME_PROVIDER") is True

    def test_name_relative_is_name_type(self):
        """'NAME_RELATIVE' is a name entity type."""
        assert is_name_entity_type("NAME_RELATIVE") is True

    def test_person_is_name_type(self):
        """'PERSON' is a name entity type."""
        assert is_name_entity_type("PERSON") is True

    def test_other_types_not_name_type(self):
        """Non-name types return False."""
        assert is_name_entity_type("SSN") is False
        assert is_name_entity_type("PHONE") is False
        assert is_name_entity_type("DATE") is False
        assert is_name_entity_type("ADDRESS") is False
        assert is_name_entity_type("EMAIL") is False

    def test_empty_string_not_name_type(self):
        """Empty string is not a name type."""
        assert is_name_entity_type("") is False

    def test_case_sensitive(self):
        """Type checking is case-sensitive."""
        assert is_name_entity_type("name") is False
        assert is_name_entity_type("Name") is False
        assert is_name_entity_type("NAME") is True


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for gender inference."""

    def test_single_character_name(self):
        """Single character name returns None."""
        assert infer_gender("J") is None
        assert infer_gender("M") is None

    def test_name_with_numbers(self):
        """Names with numbers handled gracefully."""
        # "John123" - extracts "john123", not in lists
        result = infer_gender("John123")
        # Depending on implementation, might match "john" or not
        # Current impl: "john123".lower() not in sets
        assert result is None

    def test_name_with_special_chars(self):
        """Names with special characters."""
        # O'Brien, McDonald
        assert infer_gender("O'Brien") is None  # Not in lists
        assert infer_gender("McDonald") is None

    def test_title_only_male(self):
        """Title without name returns None (no first name to extract)."""
        # Title pattern requires space + text after
        # "Mr. " alone leaves nothing to look up after stripping
        assert infer_gender("Mr.") is None

    def test_title_only_female(self):
        """Title without name returns None (no first name to extract)."""
        assert infer_gender("Mrs.") is None

    def test_compound_name_spaces(self):
        """Names with multiple spaces."""
        assert infer_gender("  John   Smith  ") == "M"

    def test_very_long_name(self):
        """Very long name handled."""
        long_name = "John " + "Smith " * 50
        assert infer_gender(long_name) == "M"

    def test_unicode_name(self):
        """Unicode characters in name."""
        # José - check if handled
        result = infer_gender("José")
        # May or may not be in lists
        assert result is None or result == "M"

    def test_context_with_name_multiple_times(self):
        """Context with name appearing multiple times."""
        context = "John told John that John said he was ready"
        # Should find first occurrence and look after it
        assert infer_gender_from_context("John", context) == "M"

    def test_context_pronoun_in_word(self):
        """Pronouns must be whole words."""
        # "shell" contains "she" but shouldn't match
        context = "Unknown picked up the shell"
        # No gender signals (shell shouldn't match she)
        result = infer_gender_from_context("Unknown", context)
        assert result is None

    def test_context_name_at_end(self):
        """Name at end of context with no text after."""
        context = "The patient was Unknown"
        # No text after name to check
        result = infer_gender_from_context("Unknown", context)
        assert result is None

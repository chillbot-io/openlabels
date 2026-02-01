"""Tests for type compatibility checking in merger.py.

Tests the types_compatible() function and COMPATIBLE_TYPE_GROUPS configuration.
"""

import pytest
from scrubiq.pipeline.merger import (
    types_compatible,
    COMPATIBLE_TYPE_GROUPS,
    _TYPE_TO_GROUP,
)


class TestTypesCompatibleBasics:
    """Basic type compatibility tests."""

    def test_identical_types_are_compatible(self):
        """Same type is always compatible with itself."""
        assert types_compatible("NAME", "NAME") is True
        assert types_compatible("SSN", "SSN") is True
        assert types_compatible("ADDRESS", "ADDRESS") is True
        assert types_compatible("UNKNOWN_TYPE", "UNKNOWN_TYPE") is True

    def test_prefix_matching_works(self):
        """Types with prefix relationships are compatible."""
        # NAME is prefix of NAME_PATIENT
        assert types_compatible("NAME", "NAME_PATIENT") is True
        assert types_compatible("NAME_PATIENT", "NAME") is True

        # NAME is prefix of NAME_PROVIDER
        assert types_compatible("NAME", "NAME_PROVIDER") is True
        assert types_compatible("NAME_PROVIDER", "NAME") is True

        # DATE is prefix of DATE_DOB
        assert types_compatible("DATE", "DATE_DOB") is True
        assert types_compatible("DATE_DOB", "DATE") is True

    def test_incompatible_types(self):
        """Unrelated types are not compatible."""
        assert types_compatible("NAME", "SSN") is False
        assert types_compatible("ADDRESS", "PHONE") is False
        assert types_compatible("EMAIL", "MRN") is False
        assert types_compatible("DATE", "NAME") is False


class TestCompatibilityGroups:
    """Tests for specific compatibility groups."""

    def test_name_group_compatibility(self):
        """All NAME variants are compatible."""
        name_types = ["NAME", "NAME_PATIENT", "NAME_PROVIDER", "NAME_RELATIVE", "NAME_FAMILY"]
        for t1 in name_types:
            for t2 in name_types:
                assert types_compatible(t1, t2) is True, f"{t1} should be compatible with {t2}"

    def test_address_group_compatibility(self):
        """All ADDRESS variants are compatible."""
        address_types = ["ADDRESS", "STREET", "STREET_ADDRESS", "CITY", "STATE", "ZIP", "LOCATION"]
        for t1 in address_types:
            for t2 in address_types:
                assert types_compatible(t1, t2) is True, f"{t1} should be compatible with {t2}"

    def test_date_group_compatibility(self):
        """All DATE variants are compatible."""
        date_types = ["DATE", "DOB", "DATE_DOB", "DATE_ADMISSION", "DATE_DISCHARGE"]
        for t1 in date_types:
            for t2 in date_types:
                assert types_compatible(t1, t2) is True, f"{t1} should be compatible with {t2}"

    def test_phone_group_compatibility(self):
        """PHONE and FAX are compatible."""
        phone_types = ["PHONE", "FAX", "PHONE_MOBILE", "PHONE_HOME", "PHONE_WORK"]
        for t1 in phone_types:
            for t2 in phone_types:
                assert types_compatible(t1, t2) is True, f"{t1} should be compatible with {t2}"

    def test_ssn_group_compatibility(self):
        """SSN and SSN_PARTIAL are compatible."""
        assert types_compatible("SSN", "SSN_PARTIAL") is True
        assert types_compatible("SSN_PARTIAL", "SSN") is True

    def test_mrn_group_compatibility(self):
        """MRN variants are compatible."""
        mrn_types = ["MRN", "PATIENT_ID", "MEDICAL_RECORD"]
        for t1 in mrn_types:
            for t2 in mrn_types:
                assert types_compatible(t1, t2) is True, f"{t1} should be compatible with {t2}"

    def test_health_plan_group_compatibility(self):
        """Health plan ID variants are compatible."""
        hp_types = ["HEALTH_PLAN_ID", "MEMBER_ID", "INSURANCE_ID"]
        for t1 in hp_types:
            for t2 in hp_types:
                assert types_compatible(t1, t2) is True, f"{t1} should be compatible with {t2}"

    def test_employer_group_compatibility(self):
        """Employer/organization types are compatible."""
        emp_types = ["EMPLOYER", "ORGANIZATION", "COMPANY", "COMPANYNAME"]
        for t1 in emp_types:
            for t2 in emp_types:
                assert types_compatible(t1, t2) is True, f"{t1} should be compatible with {t2}"


class TestCrossGroupIncompatibility:
    """Test that types from different groups are NOT compatible."""

    def test_name_not_compatible_with_address(self):
        assert types_compatible("NAME", "ADDRESS") is False
        assert types_compatible("NAME_PATIENT", "CITY") is False

    def test_ssn_not_compatible_with_mrn(self):
        assert types_compatible("SSN", "MRN") is False
        assert types_compatible("SSN_PARTIAL", "PATIENT_ID") is False

    def test_phone_not_compatible_with_email(self):
        assert types_compatible("PHONE", "EMAIL") is False
        assert types_compatible("FAX", "EMAIL") is False

    def test_date_not_compatible_with_name(self):
        assert types_compatible("DATE", "NAME") is False
        assert types_compatible("DOB", "NAME_PATIENT") is False


class TestPrecomputedMapping:
    """Test the precomputed _TYPE_TO_GROUP mapping."""

    def test_all_group_members_in_mapping(self):
        """Every type in COMPATIBLE_TYPE_GROUPS has a mapping entry."""
        for group_id, group in enumerate(COMPATIBLE_TYPE_GROUPS):
            for entity_type in group:
                assert entity_type in _TYPE_TO_GROUP, f"{entity_type} missing from _TYPE_TO_GROUP"
                assert _TYPE_TO_GROUP[entity_type] == group_id, \
                    f"{entity_type} mapped to wrong group"

    def test_mapping_size_matches_total_types(self):
        """Mapping contains exactly the right number of entries."""
        total_types = sum(len(group) for group in COMPATIBLE_TYPE_GROUPS)
        assert len(_TYPE_TO_GROUP) == total_types

    def test_unknown_types_not_in_mapping(self):
        """Unknown types return None from mapping."""
        assert _TYPE_TO_GROUP.get("UNKNOWN_TYPE") is None
        assert _TYPE_TO_GROUP.get("RANDOM_GARBAGE") is None


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_string_types(self):
        """Empty string is prefix of everything, so compatible with all types."""
        assert types_compatible("", "") is True
        # Empty string is a prefix of "NAME" via startswith, so they're compatible
        assert types_compatible("", "NAME") is True

    def test_case_sensitivity(self):
        """Type compatibility is case-sensitive."""
        # Lowercase "name" is NOT in our groups
        assert types_compatible("name", "NAME") is False
        assert types_compatible("Name", "NAME") is False

    def test_partial_prefix_not_enough(self):
        """Partial matches that aren't prefixes don't count."""
        # "AME" is not a prefix of "NAME"
        assert types_compatible("AME", "NAME") is False
        # "NA" is a prefix of "NAME" (startswith works both ways)
        assert types_compatible("NA", "NAME") is True

    def test_types_with_underscores(self):
        """Types with underscores work correctly."""
        assert types_compatible("NAME_PATIENT", "NAME_PROVIDER") is True  # Same group
        assert types_compatible("STREET_ADDRESS", "ADDRESS") is True  # Same group
        assert types_compatible("DATE_ADMISSION", "DATE_DISCHARGE") is True  # Same group

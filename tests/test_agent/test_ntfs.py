"""
Tests for NTFS permission handler.

Tests the NTFS ACL parsing and exposure level calculation logic.
On non-Windows systems, tests the stub implementations and the
exposure calculation algorithms that work cross-platform.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from openlabels.adapters.base import ExposureLevel
from openlabels.agent.ntfs import (
    NtfsAce,
    NtfsPermissions,
    WELL_KNOWN_SIDS,
    EXPOSURE_PATTERNS,
    get_ntfs_permissions,
    _get_stub_permissions,
    _calculate_exposure_from_aces,
    ntfs_exposure_to_recommended_acl,
    _IS_WINDOWS,
)


class TestNtfsAceDataclass:
    """Tests for the NtfsAce dataclass."""

    def test_create_basic_ace(self):
        """Should create an ACE with required fields."""
        ace = NtfsAce(
            principal="DOMAIN\\User",
            ace_type="allow",
            permissions=["READ_DATA", "WRITE_DATA"],
        )
        assert ace.principal == "DOMAIN\\User"
        assert ace.ace_type == "allow"
        assert ace.permissions == ["READ_DATA", "WRITE_DATA"]
        assert ace.is_inherited is False
        assert ace.principal_type == "unknown"

    def test_create_ace_with_all_fields(self):
        """Should create an ACE with all optional fields."""
        ace = NtfsAce(
            principal="S-1-5-32-544",
            ace_type="deny",
            permissions=["DELETE", "WRITE_DAC"],
            is_inherited=True,
            principal_type="group",
        )
        assert ace.principal == "S-1-5-32-544"
        assert ace.ace_type == "deny"
        assert ace.is_inherited is True
        assert ace.principal_type == "group"

    def test_ace_with_empty_permissions(self):
        """Should handle empty permissions list."""
        ace = NtfsAce(
            principal="User",
            ace_type="allow",
            permissions=[],
        )
        assert ace.permissions == []

    def test_ace_equality(self):
        """ACEs with same values should be equal."""
        ace1 = NtfsAce(principal="User", ace_type="allow", permissions=["READ"])
        ace2 = NtfsAce(principal="User", ace_type="allow", permissions=["READ"])
        assert ace1 == ace2


class TestNtfsPermissionsDataclass:
    """Tests for the NtfsPermissions dataclass."""

    def test_create_minimal_permissions(self):
        """Should create permissions with only required fields."""
        perms = NtfsPermissions(owner="Administrator")
        assert perms.owner == "Administrator"
        assert perms.owner_sid is None
        assert perms.group is None
        assert perms.aces == []
        assert perms.exposure == ExposureLevel.PRIVATE
        assert perms.inheritance_enabled is True
        assert perms.raw_sd is None

    def test_create_full_permissions(self):
        """Should create permissions with all fields."""
        aces = [
            NtfsAce("User1", "allow", ["READ"]),
            NtfsAce("User2", "deny", ["WRITE"]),
        ]
        perms = NtfsPermissions(
            owner="DOMAIN\\Admin",
            owner_sid="S-1-5-21-123",
            group="DOMAIN\\Users",
            group_sid="S-1-5-21-456",
            aces=aces,
            exposure=ExposureLevel.INTERNAL,
            inheritance_enabled=False,
            raw_sd="test-sd",
        )
        assert perms.owner == "DOMAIN\\Admin"
        assert perms.owner_sid == "S-1-5-21-123"
        assert perms.group == "DOMAIN\\Users"
        assert len(perms.aces) == 2
        assert perms.exposure == ExposureLevel.INTERNAL
        assert perms.inheritance_enabled is False


class TestWellKnownSids:
    """Tests for the WELL_KNOWN_SIDS mapping."""

    def test_creator_owner_is_private(self):
        """CREATOR OWNER should map to PRIVATE."""
        name, exposure = WELL_KNOWN_SIDS["S-1-3-0"]
        assert name == "CREATOR OWNER"
        assert exposure == ExposureLevel.PRIVATE

    def test_authenticated_users_is_internal(self):
        """Authenticated Users should map to INTERNAL."""
        name, exposure = WELL_KNOWN_SIDS["S-1-5-11"]
        assert name == "Authenticated Users"
        assert exposure == ExposureLevel.INTERNAL

    def test_builtin_users_is_org_wide(self):
        """BUILTIN\\Users should map to ORG_WIDE."""
        name, exposure = WELL_KNOWN_SIDS["S-1-5-32-545"]
        assert name == "BUILTIN\\Users"
        assert exposure == ExposureLevel.ORG_WIDE

    def test_anonymous_logon_is_public(self):
        """Anonymous Logon should map to PUBLIC."""
        name, exposure = WELL_KNOWN_SIDS["S-1-5-7"]
        assert name == "Anonymous Logon"
        assert exposure == ExposureLevel.PUBLIC

    def test_null_sid_is_public(self):
        """NULL SID should map to PUBLIC."""
        name, exposure = WELL_KNOWN_SIDS["S-1-0-0"]
        assert name == "NULL SID"
        assert exposure == ExposureLevel.PUBLIC

    def test_everyone_is_org_wide(self):
        """Everyone should map to ORG_WIDE (conservative default)."""
        name, exposure = WELL_KNOWN_SIDS["S-1-1-0"]
        assert name == "Everyone"
        assert exposure == ExposureLevel.ORG_WIDE


class TestExposurePatterns:
    """Tests for the EXPOSURE_PATTERNS mapping."""

    def test_private_patterns_empty(self):
        """PRIVATE should have no patterns (default)."""
        assert EXPOSURE_PATTERNS[ExposureLevel.PRIVATE] == []

    def test_internal_patterns(self):
        """INTERNAL should include domain groups."""
        patterns = EXPOSURE_PATTERNS[ExposureLevel.INTERNAL]
        assert "domain admins" in patterns
        assert "domain users" in patterns
        assert "authenticated users" in patterns

    def test_org_wide_patterns(self):
        """ORG_WIDE should include broad groups."""
        patterns = EXPOSURE_PATTERNS[ExposureLevel.ORG_WIDE]
        assert "everyone" in patterns
        assert "users" in patterns

    def test_public_patterns(self):
        """PUBLIC should include anonymous access."""
        patterns = EXPOSURE_PATTERNS[ExposureLevel.PUBLIC]
        assert "anonymous" in patterns
        assert "guest" in patterns


class TestGetStubPermissions:
    """Tests for the stub permissions function (used on non-Windows)."""

    def test_stub_returns_private_exposure(self, tmp_path):
        """Stub should always return PRIVATE exposure."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        perms = _get_stub_permissions(str(test_file))

        assert perms.exposure == ExposureLevel.PRIVATE
        assert perms.owner is not None

    def test_stub_gets_file_owner(self, tmp_path):
        """Stub should get the file owner from filesystem."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        perms = _get_stub_permissions(str(test_file))

        # Owner should be a non-empty string (current user on Unix)
        assert isinstance(perms.owner, str)
        assert len(perms.owner) > 0

    def test_stub_handles_nonexistent_file(self, tmp_path):
        """Stub should handle non-existent files gracefully."""
        nonexistent = str(tmp_path / "does_not_exist.txt")

        perms = _get_stub_permissions(nonexistent)

        assert perms.owner == "unknown"
        assert perms.exposure == ExposureLevel.PRIVATE

    def test_stub_returns_ntfs_permissions_type(self, tmp_path):
        """Stub should return NtfsPermissions instance."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        perms = _get_stub_permissions(str(test_file))

        assert isinstance(perms, NtfsPermissions)


class TestGetNtfsPermissions:
    """Tests for the main get_ntfs_permissions function."""

    def test_returns_stub_on_non_windows(self, tmp_path):
        """On non-Windows, should return stub permissions."""
        if _IS_WINDOWS:
            pytest.skip("Only runs on non-Windows")

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        perms = get_ntfs_permissions(str(test_file))

        assert isinstance(perms, NtfsPermissions)
        assert perms.exposure == ExposureLevel.PRIVATE

    @pytest.mark.skipif(not _IS_WINDOWS, reason="Windows-only test")
    def test_returns_actual_permissions_on_windows(self, tmp_path):
        """On Windows, should return actual NTFS permissions."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        perms = get_ntfs_permissions(str(test_file))

        assert isinstance(perms, NtfsPermissions)
        assert perms.owner is not None


class TestCalculateExposureFromAces:
    """Tests for the ACE-to-exposure calculation logic."""

    def test_empty_aces_returns_private(self):
        """No ACEs should result in PRIVATE exposure."""
        exposure = _calculate_exposure_from_aces([])
        assert exposure == ExposureLevel.PRIVATE

    def test_deny_ace_ignored(self):
        """Deny ACEs should not increase exposure."""
        aces = [
            NtfsAce(
                principal="Everyone",
                ace_type="deny",
                permissions=["READ_DATA", "GENERIC_ALL"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.PRIVATE

    def test_ace_without_read_ignored(self):
        """ACEs without read permissions should not increase exposure."""
        aces = [
            NtfsAce(
                principal="Everyone",
                ace_type="allow",
                permissions=["WRITE_DATA", "DELETE"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.PRIVATE

    def test_everyone_with_read_is_org_wide(self):
        """Everyone with read should be ORG_WIDE."""
        aces = [
            NtfsAce(
                principal="Everyone",
                ace_type="allow",
                permissions=["READ_DATA"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.ORG_WIDE

    def test_domain_admins_is_internal(self):
        """Domain Admins with read should be INTERNAL."""
        aces = [
            NtfsAce(
                principal="DOMAIN\\Domain Admins",
                ace_type="allow",
                permissions=["GENERIC_READ"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.INTERNAL

    def test_anonymous_is_public(self):
        """Anonymous Logon with read should be PUBLIC."""
        aces = [
            NtfsAce(
                principal="Anonymous Logon",
                ace_type="allow",
                permissions=["READ_DATA"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.PUBLIC

    def test_guest_is_public(self):
        """Guest account with read should be PUBLIC."""
        aces = [
            NtfsAce(
                principal="Guest",
                ace_type="allow",
                permissions=["GENERIC_ALL"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.PUBLIC

    def test_most_permissive_wins(self):
        """Most permissive exposure level should win."""
        aces = [
            NtfsAce(
                principal="DOMAIN\\Domain Users",  # INTERNAL
                ace_type="allow",
                permissions=["READ_DATA"],
            ),
            NtfsAce(
                principal="Anonymous Logon",  # PUBLIC
                ace_type="allow",
                permissions=["READ_DATA"],
            ),
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.PUBLIC

    def test_generic_all_grants_read(self):
        """GENERIC_ALL should imply read access."""
        aces = [
            NtfsAce(
                principal="Everyone",
                ace_type="allow",
                permissions=["GENERIC_ALL"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.ORG_WIDE

    def test_local_system_matches_internal_pattern(self):
        """Principals matching 'administrators' pattern should be INTERNAL."""
        aces = [
            NtfsAce(
                principal="NT AUTHORITY\\Administrators",
                ace_type="allow",
                permissions=["READ_DATA"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.INTERNAL

    def test_administrators_is_internal(self):
        """Administrators should be INTERNAL."""
        aces = [
            NtfsAce(
                principal="BUILTIN\\Administrators",
                ace_type="allow",
                permissions=["GENERIC_ALL"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.INTERNAL

    def test_builtin_users_is_org_wide(self):
        """BUILTIN\\Users should be ORG_WIDE."""
        aces = [
            NtfsAce(
                principal="BUILTIN\\Users",
                ace_type="allow",
                permissions=["READ_DATA"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.ORG_WIDE

    def test_case_insensitive_matching(self):
        """Principal matching should be case-insensitive."""
        aces = [
            NtfsAce(
                principal="EVERYONE",
                ace_type="allow",
                permissions=["READ_DATA"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.ORG_WIDE

    def test_specific_user_is_private(self):
        """Specific user (not matching patterns) should be PRIVATE."""
        aces = [
            NtfsAce(
                principal="DOMAIN\\JohnSmith",
                ace_type="allow",
                permissions=["GENERIC_ALL"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.PRIVATE


class TestNtfsExposureToRecommendedAcl:
    """Tests for the recommended ACL generator."""

    def test_private_acl(self):
        """PRIVATE should only include owner."""
        acl = ntfs_exposure_to_recommended_acl(ExposureLevel.PRIVATE, "DOMAIN\\Admin")
        assert len(acl) == 1
        assert acl[0]["principal"] == "DOMAIN\\Admin"
        assert acl[0]["type"] == "allow"
        assert "GENERIC_ALL" in acl[0]["permissions"]

    def test_internal_acl(self):
        """INTERNAL should include owner and Administrators."""
        acl = ntfs_exposure_to_recommended_acl(ExposureLevel.INTERNAL, "Admin")
        assert len(acl) == 2

        principals = [ace["principal"] for ace in acl]
        assert "Admin" in principals
        assert "BUILTIN\\Administrators" in principals

    def test_org_wide_acl(self):
        """ORG_WIDE should include owner, Admins, and Authenticated Users."""
        acl = ntfs_exposure_to_recommended_acl(ExposureLevel.ORG_WIDE, "Owner")
        assert len(acl) == 3

        principals = [ace["principal"] for ace in acl]
        assert "Owner" in principals
        assert "BUILTIN\\Administrators" in principals
        assert "Authenticated Users" in principals

        # Authenticated Users should only have read
        auth_users_ace = next(a for a in acl if a["principal"] == "Authenticated Users")
        assert auth_users_ace["permissions"] == ["GENERIC_READ"]

    def test_public_not_recommended(self):
        """PUBLIC should not add anonymous access (security risk)."""
        acl = ntfs_exposure_to_recommended_acl(ExposureLevel.PUBLIC, "Owner")
        # Should still only return PRIVATE level (owner only) for PUBLIC
        # since we don't recommend PUBLIC ACLs
        principals = [ace["principal"].lower() for ace in acl]
        assert "anonymous" not in principals
        assert "everyone" not in principals

    def test_all_aces_are_allow(self):
        """All recommended ACEs should be allow type."""
        for exposure in [ExposureLevel.PRIVATE, ExposureLevel.INTERNAL, ExposureLevel.ORG_WIDE]:
            acl = ntfs_exposure_to_recommended_acl(exposure, "Owner")
            for ace in acl:
                assert ace["type"] == "allow"


class TestDecodeAccessMask:
    """Tests for access mask decoding (limited without pywin32)."""

    def test_decode_without_pywin32(self):
        """Without pywin32, should return hex representation."""
        from openlabels.agent.ntfs import _decode_access_mask

        # When ntsecuritycon is not available, should fall back to hex
        with patch.dict('sys.modules', {'ntsecuritycon': None}):
            # Force reimport to get the fallback
            result = _decode_access_mask(0x001F01FF)
            # On non-Windows, this will hit the ImportError path
            assert isinstance(result, list)
            assert len(result) >= 1


class TestEdgeCases:
    """Edge case tests."""

    def test_ace_with_inherited_flag(self):
        """Inherited ACEs should be handled correctly."""
        aces = [
            NtfsAce(
                principal="Everyone",
                ace_type="allow",
                permissions=["READ_DATA"],
                is_inherited=True,
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.ORG_WIDE

    def test_mixed_allow_deny_aces(self):
        """Mix of allow and deny ACEs should only consider allow."""
        aces = [
            NtfsAce(
                principal="Everyone",
                ace_type="deny",
                permissions=["READ_DATA"],
            ),
            NtfsAce(
                principal="Domain Admins",
                ace_type="allow",
                permissions=["READ_DATA"],
            ),
        ]
        exposure = _calculate_exposure_from_aces(aces)
        # Deny Everyone is ignored, only Domain Admins allow is considered
        assert exposure == ExposureLevel.INTERNAL

    def test_enterprise_admins_is_internal(self):
        """Enterprise Admins should be INTERNAL."""
        aces = [
            NtfsAce(
                principal="DOMAIN\\Enterprise Admins",
                ace_type="allow",
                permissions=["GENERIC_ALL"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.INTERNAL

    def test_guests_group_is_public(self):
        """Guests group should be PUBLIC."""
        aces = [
            NtfsAce(
                principal="BUILTIN\\Guests",
                ace_type="allow",
                permissions=["READ_DATA"],
            )
        ]
        exposure = _calculate_exposure_from_aces(aces)
        assert exposure == ExposureLevel.PUBLIC

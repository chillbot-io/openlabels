"""Tests for remediation base types and utilities."""

import pytest
from datetime import datetime
from pathlib import Path

from openlabels.remediation.base import (
    RemediationResult,
    RemediationAction,
    RemediationError,
    QuarantineError,
    PermissionError,
    get_current_user,
)


class TestRemediationAction:
    """Tests for RemediationAction enum."""

    def test_quarantine_value(self):
        """Quarantine action has correct string value."""
        assert RemediationAction.QUARANTINE.value == "quarantine"

    def test_lockdown_value(self):
        """Lockdown action has correct string value."""
        assert RemediationAction.LOCKDOWN.value == "lockdown"

    def test_none_value(self):
        """None action has correct string value."""
        assert RemediationAction.NONE.value == "none"

    def test_is_string_enum(self):
        """Actions can be used as strings."""
        action = RemediationAction.QUARANTINE
        assert action == "quarantine"


class TestRemediationResult:
    """Tests for RemediationResult dataclass."""

    def test_create_basic_result(self):
        """Can create a basic result."""
        result = RemediationResult(
            success=True,
            action=RemediationAction.QUARANTINE,
            source_path=Path("/test/file.txt"),
        )
        assert result.success is True
        assert result.action == RemediationAction.QUARANTINE
        assert result.source_path == Path("/test/file.txt")

    def test_timestamp_auto_generated(self):
        """Timestamp is automatically generated."""
        result = RemediationResult(
            success=True,
            action=RemediationAction.QUARANTINE,
            source_path=Path("/test/file.txt"),
        )
        assert result.timestamp is not None
        assert isinstance(result.timestamp, datetime)

    def test_optional_fields_default_none(self):
        """Optional fields default to None."""
        result = RemediationResult(
            success=True,
            action=RemediationAction.QUARANTINE,
            source_path=Path("/test/file.txt"),
        )
        assert result.dest_path is None
        assert result.principals is None
        assert result.error is None

    def test_success_quarantine_factory(self):
        """success_quarantine creates correct result."""
        result = RemediationResult.success_quarantine(
            source=Path("/source/file.txt"),
            dest=Path("/dest/file.txt"),
            performed_by="testuser",
        )
        assert result.success is True
        assert result.action == RemediationAction.QUARANTINE
        assert result.source_path == Path("/source/file.txt")
        assert result.dest_path == Path("/dest/file.txt")
        assert result.performed_by == "testuser"

    def test_success_lockdown_factory(self):
        """success_lockdown creates correct result."""
        result = RemediationResult.success_lockdown(
            path=Path("/test/file.txt"),
            principals=["BUILTIN\\Administrators"],
            previous_acl="encoded_acl",
            performed_by="testuser",
        )
        assert result.success is True
        assert result.action == RemediationAction.LOCKDOWN
        assert result.principals == ["BUILTIN\\Administrators"]
        assert result.previous_acl == "encoded_acl"

    def test_failure_factory(self):
        """failure creates correct result."""
        result = RemediationResult.failure(
            action=RemediationAction.QUARANTINE,
            source=Path("/test/file.txt"),
            error="Something went wrong",
            error_code=1,
        )
        assert result.success is False
        assert result.error == "Something went wrong"
        assert result.error_code == 1

    def test_to_dict(self):
        """to_dict produces correct dictionary."""
        result = RemediationResult.success_quarantine(
            source=Path("/source/file.txt"),
            dest=Path("/dest/file.txt"),
        )
        d = result.to_dict()

        assert d["success"] is True
        assert d["action"] == "quarantine"
        assert d["source_path"] == "/source/file.txt"
        assert d["dest_path"] == "/dest/file.txt"
        assert "timestamp" in d

    def test_to_dict_with_none_values(self):
        """to_dict handles None values correctly."""
        result = RemediationResult(
            success=True,
            action=RemediationAction.QUARANTINE,
            source_path=Path("/test/file.txt"),
        )
        d = result.to_dict()

        assert d["dest_path"] is None
        assert d["principals"] is None


class TestRemediationErrors:
    """Tests for remediation error classes."""

    def test_remediation_error_basic(self):
        """RemediationError stores message."""
        error = RemediationError("Something failed")
        assert str(error) == "Something failed"

    def test_remediation_error_with_path(self):
        """RemediationError stores path."""
        error = RemediationError("Failed", path=Path("/test/file.txt"))
        assert error.path == Path("/test/file.txt")

    def test_remediation_error_with_code(self):
        """RemediationError stores error code."""
        error = RemediationError("Failed", code=42)
        assert error.code == 42

    def test_quarantine_error_is_remediation_error(self):
        """QuarantineError is a RemediationError."""
        error = QuarantineError("Quarantine failed")
        assert isinstance(error, RemediationError)

    def test_permission_error_is_remediation_error(self):
        """PermissionError is a RemediationError."""
        error = PermissionError("Permission change failed")
        assert isinstance(error, RemediationError)


class TestGetCurrentUser:
    """Tests for get_current_user utility."""

    def test_returns_string(self):
        """get_current_user returns a string."""
        user = get_current_user()
        assert isinstance(user, str)
        assert len(user) > 0

    def test_returns_nonempty(self):
        """get_current_user returns non-empty string."""
        user = get_current_user()
        assert user.strip() != ""

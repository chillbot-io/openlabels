"""Tests for monitoring base types."""

import pytest
from datetime import datetime
from pathlib import Path

from openlabels.monitoring.base import (
    AccessEvent,
    AccessAction,
    WatchedFile,
    MonitoringResult,
    MonitoringError,
    SACLError,
    AuditRuleError,
    WINDOWS_EVENT_IDS,
)


class TestAccessAction:
    """Tests for AccessAction enum."""

    def test_read_value(self):
        """Read action has correct value."""
        assert AccessAction.READ.value == "read"

    def test_write_value(self):
        """Write action has correct value."""
        assert AccessAction.WRITE.value == "write"

    def test_delete_value(self):
        """Delete action has correct value."""
        assert AccessAction.DELETE.value == "delete"

    def test_is_string_enum(self):
        """Actions can be used as strings."""
        action = AccessAction.READ
        assert action == "read"


class TestAccessEvent:
    """Tests for AccessEvent dataclass."""

    def test_create_basic_event(self):
        """Can create a basic event."""
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime.now(),
            action=AccessAction.READ,
        )
        assert event.path == Path("/test/file.txt")
        assert event.action == AccessAction.READ

    def test_optional_user_fields(self):
        """User fields are optional."""
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime.now(),
            action=AccessAction.READ,
        )
        assert event.user_sid is None
        assert event.user_name is None
        assert event.user_domain is None

    def test_user_display_with_domain(self):
        """user_display includes domain when available."""
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime.now(),
            action=AccessAction.READ,
            user_name="jsmith",
            user_domain="CORP",
        )
        assert event.user_display == "CORP\\jsmith"

    def test_user_display_without_domain(self):
        """user_display works without domain."""
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime.now(),
            action=AccessAction.READ,
            user_name="jsmith",
        )
        assert event.user_display == "jsmith"

    def test_user_display_falls_back_to_sid(self):
        """user_display falls back to SID if no username."""
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime.now(),
            action=AccessAction.READ,
            user_sid="S-1-5-21-123456789",
        )
        assert event.user_display == "S-1-5-21-123456789"

    def test_user_display_unknown_fallback(self):
        """user_display returns 'unknown' if no user info."""
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime.now(),
            action=AccessAction.READ,
        )
        assert event.user_display == "unknown"

    def test_to_dict(self):
        """to_dict produces correct dictionary."""
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=datetime(2026, 1, 15, 10, 30, 0),
            action=AccessAction.READ,
            user_name="jsmith",
            process_name="notepad.exe",
        )
        d = event.to_dict()

        assert d["path"] == "/test/file.txt"
        assert d["action"] == "read"
        assert d["user_name"] == "jsmith"
        assert d["process_name"] == "notepad.exe"
        assert "timestamp" in d


class TestWatchedFile:
    """Tests for WatchedFile dataclass."""

    def test_create_watched_file(self):
        """Can create a watched file entry."""
        wf = WatchedFile(
            path=Path("/test/file.txt"),
            risk_tier="HIGH",
        )
        assert wf.path == Path("/test/file.txt")
        assert wf.risk_tier == "HIGH"

    def test_added_at_auto_generated(self):
        """added_at is automatically set."""
        wf = WatchedFile(
            path=Path("/test/file.txt"),
            risk_tier="HIGH",
        )
        assert wf.added_at is not None
        assert isinstance(wf.added_at, datetime)

    def test_monitoring_status_defaults(self):
        """Monitoring status fields default to False/None."""
        wf = WatchedFile(
            path=Path("/test/file.txt"),
            risk_tier="HIGH",
        )
        assert wf.sacl_enabled is False
        assert wf.audit_rule_enabled is False
        assert wf.last_event_at is None
        assert wf.access_count == 0

    def test_to_dict(self):
        """to_dict produces correct dictionary."""
        wf = WatchedFile(
            path=Path("/test/file.txt"),
            risk_tier="CRITICAL",
            label_id="ol_abc123def456",
        )
        d = wf.to_dict()

        assert d["path"] == "/test/file.txt"
        assert d["risk_tier"] == "CRITICAL"
        assert d["label_id"] == "ol_abc123def456"
        assert "added_at" in d


class TestMonitoringResult:
    """Tests for MonitoringResult dataclass."""

    def test_create_success_result(self):
        """Can create a success result."""
        result = MonitoringResult(
            success=True,
            path=Path("/test/file.txt"),
            message="Monitoring enabled",
        )
        assert result.success is True
        assert result.message == "Monitoring enabled"

    def test_create_failure_result(self):
        """Can create a failure result."""
        result = MonitoringResult(
            success=False,
            path=Path("/test/file.txt"),
            error="Permission denied",
        )
        assert result.success is False
        assert result.error == "Permission denied"

    def test_sacl_enabled_flag(self):
        """SACL enabled flag can be set."""
        result = MonitoringResult(
            success=True,
            path=Path("/test/file.txt"),
            sacl_enabled=True,
        )
        assert result.sacl_enabled is True

    def test_to_dict(self):
        """to_dict produces correct dictionary."""
        result = MonitoringResult(
            success=True,
            path=Path("/test/file.txt"),
            sacl_enabled=True,
        )
        d = result.to_dict()

        assert d["success"] is True
        assert d["path"] == "/test/file.txt"
        assert d["sacl_enabled"] is True


class TestMonitoringErrors:
    """Tests for monitoring error classes."""

    def test_monitoring_error_basic(self):
        """MonitoringError stores message."""
        error = MonitoringError("Something failed")
        assert str(error) == "Something failed"

    def test_monitoring_error_with_path(self):
        """MonitoringError stores path."""
        error = MonitoringError("Failed", path=Path("/test/file.txt"))
        assert error.path == Path("/test/file.txt")

    def test_sacl_error_is_monitoring_error(self):
        """SACLError is a MonitoringError."""
        error = SACLError("SACL operation failed")
        assert isinstance(error, MonitoringError)

    def test_audit_rule_error_is_monitoring_error(self):
        """AuditRuleError is a MonitoringError."""
        error = AuditRuleError("Audit rule failed")
        assert isinstance(error, MonitoringError)


class TestWindowsEventIds:
    """Tests for Windows event ID constants."""

    def test_4663_is_object_access(self):
        """Event 4663 is object access attempt."""
        assert 4663 in WINDOWS_EVENT_IDS
        assert "access" in WINDOWS_EVENT_IDS[4663].lower()

    def test_4656_is_handle_requested(self):
        """Event 4656 is handle requested."""
        assert 4656 in WINDOWS_EVENT_IDS
        assert "handle" in WINDOWS_EVENT_IDS[4656].lower()

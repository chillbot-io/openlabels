"""Tests for monitoring base types."""

import pytest
from datetime import datetime
from pathlib import Path

from openlabels.monitoring.base import (
    AccessEvent,
    AccessAction,
    WatchedFile,
    MonitoringResult,
    WINDOWS_EVENT_IDS,
)
from openlabels.exceptions import (
    MonitoringError,
    SACLError,
    AuditRuleError,
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
        ts = datetime(2026, 1, 15, 10, 30, 0)
        event = AccessEvent(
            path=Path("/test/file.txt"),
            timestamp=ts,
            action=AccessAction.READ,
            user_name="jsmith",
            process_name="notepad.exe",
            user_sid="S-1-5-21-123",
            user_domain="CORP",
            process_id=1234,
            event_id=4663,
            success=True,
        )
        d = event.to_dict()

        assert d["path"] == "/test/file.txt"
        assert d["timestamp"] == ts.isoformat()
        assert d["action"] == "read"
        assert d["user_name"] == "jsmith"
        assert d["user_sid"] == "S-1-5-21-123"
        assert d["user_domain"] == "CORP"
        assert d["process_name"] == "notepad.exe"
        assert d["process_id"] == 1234
        assert d["event_id"] == 4663
        assert d["success"] is True


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
        """added_at is automatically set to approximately now."""
        before = datetime.now()
        wf = WatchedFile(
            path=Path("/test/file.txt"),
            risk_tier="HIGH",
        )
        after = datetime.now()
        assert before <= wf.added_at <= after

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
        """to_dict produces correct dictionary with all fields."""
        added = datetime(2026, 1, 15, 10, 0, 0)
        last_event = datetime(2026, 1, 15, 12, 0, 0)
        wf = WatchedFile(
            path=Path("/test/file.txt"),
            risk_tier="CRITICAL",
            added_at=added,
            sacl_enabled=True,
            audit_rule_enabled=False,
            last_event_at=last_event,
            access_count=42,
            label_id="ol_abc123def456",
        )
        d = wf.to_dict()

        assert d["path"] == "/test/file.txt"
        assert d["risk_tier"] == "CRITICAL"
        assert d["added_at"] == added.isoformat()
        assert d["sacl_enabled"] is True
        assert d["audit_rule_enabled"] is False
        assert d["last_event_at"] == last_event.isoformat()
        assert d["access_count"] == 42
        assert d["label_id"] == "ol_abc123def456"

    def test_to_dict_last_event_at_none(self):
        """to_dict handles None last_event_at correctly."""
        wf = WatchedFile(
            path=Path("/test/file.txt"),
            risk_tier="HIGH",
        )
        d = wf.to_dict()
        assert d["last_event_at"] is None


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
        """to_dict produces correct dictionary with all fields."""
        result = MonitoringResult(
            success=True,
            path=Path("/test/file.txt"),
            message="SACL audit rule added",
            error=None,
            sacl_enabled=True,
            audit_rule_enabled=False,
        )
        d = result.to_dict()

        assert d["success"] is True
        assert d["path"] == "/test/file.txt"
        assert d["message"] == "SACL audit rule added"
        assert d["error"] is None
        assert d["sacl_enabled"] is True
        assert d["audit_rule_enabled"] is False


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

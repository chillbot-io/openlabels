"""Tests for access history queries."""

import platform
import pytest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

from openlabels.monitoring.history import (
    get_access_history,
    _is_system_account,
    _parse_windows_access_mask,
    _parse_linux_event_type,
)
from openlabels.monitoring.base import AccessAction


class TestIsSystemAccount:
    """Tests for _is_system_account helper."""

    def test_system_username(self):
        """SYSTEM is a system account."""
        assert _is_system_account("SYSTEM", None) is True

    def test_local_service(self):
        """LOCAL SERVICE is a system account."""
        assert _is_system_account("LOCAL SERVICE", None) is True

    def test_network_service(self):
        """NETWORK SERVICE is a system account."""
        assert _is_system_account("NETWORK SERVICE", None) is True

    def test_system_sid(self):
        """S-1-5-18 (Local System) is a system account."""
        assert _is_system_account(None, "S-1-5-18") is True

    def test_root_is_system(self):
        """root is a system account."""
        assert _is_system_account("root", None) is True

    def test_regular_user_not_system(self):
        """Regular user is not a system account."""
        assert _is_system_account("jsmith", None) is False

    def test_empty_values_not_system(self):
        """Empty values are not system accounts."""
        assert _is_system_account(None, None) is False
        assert _is_system_account("", None) is False


class TestParseWindowsAccessMask:
    """Tests for Windows access mask parsing."""

    def test_read_mask(self):
        """ReadData (0x1) maps to READ."""
        assert _parse_windows_access_mask(0x1) == AccessAction.READ

    def test_write_mask(self):
        """WriteData (0x2) maps to WRITE."""
        assert _parse_windows_access_mask(0x2) == AccessAction.WRITE

    def test_delete_mask(self):
        """DELETE (0x10000) maps to DELETE."""
        assert _parse_windows_access_mask(0x10000) == AccessAction.DELETE

    def test_permission_change_mask(self):
        """WriteDacl (0x40000) maps to PERMISSION_CHANGE."""
        assert _parse_windows_access_mask(0x40000) == AccessAction.PERMISSION_CHANGE

    def test_unknown_mask(self):
        """Unknown mask maps to UNKNOWN."""
        assert _parse_windows_access_mask(0x80000000) == AccessAction.UNKNOWN

    def test_combined_mask_priority(self):
        """DELETE takes priority in combined masks."""
        # DELETE | READ
        assert _parse_windows_access_mask(0x10001) == AccessAction.DELETE


class TestParseLinuxEventType:
    """Tests for Linux audit event type parsing."""

    def test_read_event(self):
        """READ event maps to READ."""
        assert _parse_linux_event_type("SYSCALL_READ") == AccessAction.READ

    def test_open_event(self):
        """OPEN event maps to READ."""
        assert _parse_linux_event_type("OPEN") == AccessAction.READ

    def test_write_event(self):
        """WRITE event maps to WRITE."""
        assert _parse_linux_event_type("SYSCALL_WRITE") == AccessAction.WRITE

    def test_unlink_event(self):
        """UNLINK event maps to DELETE."""
        assert _parse_linux_event_type("UNLINK") == AccessAction.DELETE

    def test_rename_event(self):
        """RENAME event maps to RENAME."""
        assert _parse_linux_event_type("RENAME") == AccessAction.RENAME

    def test_chmod_event(self):
        """CHMOD event maps to PERMISSION_CHANGE."""
        assert _parse_linux_event_type("CHMOD") == AccessAction.PERMISSION_CHANGE

    def test_unknown_event(self):
        """Unknown event maps to UNKNOWN."""
        assert _parse_linux_event_type("UNKNOWN_EVENT") == AccessAction.UNKNOWN


class TestGetAccessHistoryBasic:
    """Basic tests for get_access_history."""

    def test_returns_empty_list_when_no_events(self, tmp_path):
        """Returns an empty list when platform function returns no events."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = []

            result = get_access_history(test_file)

            assert result == []
            # Verify the platform-specific function was called with correct args
            mock_history.assert_called_once()
            called_path = mock_history.call_args[0][0]
            assert called_path == test_file.resolve()

    def test_respects_limit(self, tmp_path):
        """Respects the limit parameter."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        from openlabels.monitoring.base import AccessEvent

        # Create more events than limit
        events = [
            AccessEvent(
                path=test_file,
                timestamp=datetime.now() - timedelta(hours=i),
                action=AccessAction.READ,
                user_name=f"user{i}",
            )
            for i in range(10)
        ]

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = events

            result = get_access_history(test_file, limit=5)

            assert len(result) == 5

    def test_filters_system_accounts(self, tmp_path):
        """Filters out system accounts by default."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        from openlabels.monitoring.base import AccessEvent

        events = [
            AccessEvent(
                path=test_file,
                timestamp=datetime.now(),
                action=AccessAction.READ,
                user_name="SYSTEM",
            ),
            AccessEvent(
                path=test_file,
                timestamp=datetime.now(),
                action=AccessAction.READ,
                user_name="jsmith",
            ),
        ]

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = events

            result = get_access_history(test_file, include_system=False)

            # Only jsmith should be included
            assert len(result) == 1
            assert result[0].user_name == "jsmith"

    def test_includes_system_when_requested(self, tmp_path):
        """Includes system accounts when requested."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        from openlabels.monitoring.base import AccessEvent

        events = [
            AccessEvent(
                path=test_file,
                timestamp=datetime.now(),
                action=AccessAction.READ,
                user_name="SYSTEM",
            ),
            AccessEvent(
                path=test_file,
                timestamp=datetime.now(),
                action=AccessAction.READ,
                user_name="jsmith",
            ),
        ]

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = events

            result = get_access_history(test_file, include_system=True)

            assert len(result) == 2

    def test_sorts_by_timestamp_descending(self, tmp_path):
        """Events are sorted most recent first."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        from openlabels.monitoring.base import AccessEvent

        events = [
            AccessEvent(
                path=test_file,
                timestamp=datetime.now() - timedelta(hours=2),
                action=AccessAction.READ,
                user_name="user1",
            ),
            AccessEvent(
                path=test_file,
                timestamp=datetime.now(),
                action=AccessAction.READ,
                user_name="user2",
            ),
            AccessEvent(
                path=test_file,
                timestamp=datetime.now() - timedelta(hours=1),
                action=AccessAction.READ,
                user_name="user3",
            ),
        ]

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = events

            result = get_access_history(test_file)

            # Should be sorted newest first
            assert result[0].user_name == "user2"
            assert result[1].user_name == "user3"
            assert result[2].user_name == "user1"


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
class TestGetAccessHistoryWindows:
    """Windows-specific access history tests."""

    def test_uses_powershell(self, tmp_path):
        """Uses PowerShell Get-WinEvent on Windows."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="[]",
                stderr="",
            )

            get_access_history(test_file)

            mock_run.assert_called()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "powershell"

    def test_parses_powershell_json(self, tmp_path):
        """Correctly parses PowerShell JSON output."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        sample_output = json.dumps([{
            "TimeCreated": "2026-01-15T10:30:00",
            "EventId": 4663,
            "UserSid": "S-1-5-21-123456",
            "UserName": "jsmith",
            "UserDomain": "CORP",
            "ObjectName": str(test_file),
            "AccessMask": "0x1",
            "ProcessName": "notepad.exe",
            "ProcessId": 1234,
        }])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=sample_output,
                stderr="",
            )

            result = get_access_history(test_file, include_system=True)

            assert len(result) == 1
            assert result[0].user_name == "jsmith"
            assert result[0].user_domain == "CORP"


@pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
class TestGetAccessHistoryLinux:
    """Linux-specific access history tests."""

    def test_uses_ausearch(self, tmp_path):
        """Uses ausearch on Linux with correct arguments."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/ausearch"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="",
                    stderr="",
                )

                get_access_history(test_file)

                mock_run.assert_called_once()
                cmd = mock_run.call_args[0][0]
                assert cmd[0] == "ausearch"
                # Verify the file path is included in the command
                assert str(test_file.resolve()) in " ".join(cmd)

    def test_ausearch_not_found(self, tmp_path):
        """Returns empty list if ausearch not found."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value=None):
            result = get_access_history(test_file)

            assert result == []

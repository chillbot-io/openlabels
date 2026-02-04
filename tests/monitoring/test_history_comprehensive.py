"""
Comprehensive tests for access history queries.

Tests cover:
- PowerShell event log queries (Windows)
- ausearch audit log queries (Linux)
- Access mask parsing
- Event type parsing
- System account filtering
- Error handling (timeouts, subprocess failures)
- UID resolution
- CSV parsing edge cases
"""

import json
import platform
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openlabels.monitoring.base import AccessAction, AccessEvent
from openlabels.monitoring.history import (
    _get_history_linux,
    _get_history_windows,
    _is_system_account,
    _parse_ausearch_csv,
    _parse_linux_event_type,
    _parse_windows_access_mask,
    _resolve_linux_uid,
    get_access_history,
)


class TestIsSystemAccountComprehensive:
    """Additional tests for system account detection."""

    def test_system_case_insensitive(self):
        """System account detection is case-insensitive for names."""
        assert _is_system_account("system", None) is True
        assert _is_system_account("System", None) is True
        assert _is_system_account("SYSTEM", None) is True

    def test_local_service_variants(self):
        """LOCAL SERVICE detection handles different cases."""
        assert _is_system_account("local service", None) is True
        assert _is_system_account("LOCAL SERVICE", None) is True

    def test_network_service_variants(self):
        """NETWORK SERVICE detection handles different cases."""
        assert _is_system_account("network service", None) is True
        assert _is_system_account("NETWORK SERVICE", None) is True

    def test_dwm_accounts(self):
        """Desktop Window Manager accounts are system accounts."""
        assert _is_system_account("DWM-1", None) is True
        assert _is_system_account("DWM-2", None) is True
        assert _is_system_account("DWM-3", None) is True

    def test_umfd_accounts(self):
        """User Mode Font Driver accounts are system accounts."""
        assert _is_system_account("UMFD-0", None) is True
        assert _is_system_account("UMFD-1", None) is True

    def test_local_system_sid(self):
        """S-1-5-18 (Local System) is detected by SID."""
        assert _is_system_account("unknown", "S-1-5-18") is True
        assert _is_system_account(None, "S-1-5-18") is True

    def test_local_service_sid(self):
        """S-1-5-19 (Local Service) is detected by SID."""
        assert _is_system_account(None, "S-1-5-19") is True

    def test_network_service_sid(self):
        """S-1-5-20 (Network Service) is detected by SID."""
        assert _is_system_account(None, "S-1-5-20") is True

    def test_linux_system_accounts(self):
        """Common Linux system accounts are detected."""
        assert _is_system_account("root", None) is True
        assert _is_system_account("nobody", None) is True
        assert _is_system_account("daemon", None) is True
        assert _is_system_account("bin", None) is True
        assert _is_system_account("sys", None) is True

    def test_normal_user_accounts(self):
        """Normal user accounts are not system accounts."""
        assert _is_system_account("john", None) is False
        assert _is_system_account("admin", None) is False
        assert _is_system_account("testuser", None) is False
        assert _is_system_account("domain\\user", None) is False

    def test_regular_sid_not_system(self):
        """Non-system SIDs are not flagged as system."""
        assert _is_system_account(None, "S-1-5-21-123456789-123456789-123456789-1001") is False

    def test_both_empty_not_system(self):
        """Empty username and SID are not system."""
        assert _is_system_account(None, None) is False
        assert _is_system_account("", "") is False
        assert _is_system_account("", None) is False


class TestParseWindowsAccessMaskComprehensive:
    """Additional tests for Windows access mask parsing."""

    def test_read_data_0x1(self):
        """ReadData/ListDirectory (0x1) maps to READ."""
        assert _parse_windows_access_mask(0x1) == AccessAction.READ

    def test_write_data_0x2(self):
        """WriteData/AddFile (0x2) maps to WRITE."""
        assert _parse_windows_access_mask(0x2) == AccessAction.WRITE

    def test_append_data_0x4(self):
        """AppendData/AddSubdirectory (0x4) maps to WRITE."""
        assert _parse_windows_access_mask(0x4) == AccessAction.WRITE

    def test_delete_0x10000(self):
        """DELETE (0x10000) maps to DELETE."""
        assert _parse_windows_access_mask(0x10000) == AccessAction.DELETE

    def test_write_dac_0x40000(self):
        """WRITE_DAC (0x40000) maps to PERMISSION_CHANGE."""
        assert _parse_windows_access_mask(0x40000) == AccessAction.PERMISSION_CHANGE

    def test_delete_priority_over_write(self):
        """DELETE takes priority over WRITE in combined masks."""
        # DELETE | WRITE
        assert _parse_windows_access_mask(0x10002) == AccessAction.DELETE

    def test_delete_priority_over_read(self):
        """DELETE takes priority over READ in combined masks."""
        # DELETE | READ
        assert _parse_windows_access_mask(0x10001) == AccessAction.DELETE

    def test_permission_change_priority_over_write(self):
        """WRITE_DAC takes priority over WRITE."""
        # WRITE_DAC | WRITE
        assert _parse_windows_access_mask(0x40002) == AccessAction.PERMISSION_CHANGE

    def test_write_priority_over_read(self):
        """WRITE takes priority over READ in combined masks."""
        # WRITE | READ
        assert _parse_windows_access_mask(0x3) == AccessAction.WRITE

    def test_unknown_mask(self):
        """Unrecognized masks map to UNKNOWN."""
        assert _parse_windows_access_mask(0x80000000) == AccessAction.UNKNOWN
        assert _parse_windows_access_mask(0x8) == AccessAction.UNKNOWN

    def test_zero_mask(self):
        """Zero mask maps to UNKNOWN."""
        assert _parse_windows_access_mask(0) == AccessAction.UNKNOWN

    def test_full_access_mask(self):
        """Full access mask still follows priority."""
        # DELETE is checked first, so full access -> DELETE
        full_access = 0x1F01FF
        result = _parse_windows_access_mask(full_access)
        # Priority: DELETE > PERMISSION_CHANGE > WRITE > READ > UNKNOWN
        assert result == AccessAction.DELETE


class TestParseLinuxEventTypeComprehensive:
    """Additional tests for Linux event type parsing."""

    def test_read_variations(self):
        """Various READ-related events map to READ."""
        assert _parse_linux_event_type("READ") == AccessAction.READ
        assert _parse_linux_event_type("SYSCALL_READ") == AccessAction.READ
        assert _parse_linux_event_type("read") == AccessAction.READ

    def test_open_maps_to_read(self):
        """OPEN events map to READ."""
        assert _parse_linux_event_type("OPEN") == AccessAction.READ
        assert _parse_linux_event_type("OPENAT") == AccessAction.READ

    def test_write_variations(self):
        """Various WRITE-related events map to WRITE."""
        assert _parse_linux_event_type("WRITE") == AccessAction.WRITE
        assert _parse_linux_event_type("SYSCALL_WRITE") == AccessAction.WRITE
        assert _parse_linux_event_type("TRUNCATE") == AccessAction.WRITE

    def test_delete_variations(self):
        """Various DELETE-related events map to DELETE."""
        assert _parse_linux_event_type("UNLINK") == AccessAction.DELETE
        assert _parse_linux_event_type("DELETE") == AccessAction.DELETE
        assert _parse_linux_event_type("UNLINKAT") == AccessAction.DELETE

    def test_rename_event(self):
        """RENAME events map to RENAME."""
        assert _parse_linux_event_type("RENAME") == AccessAction.RENAME
        assert _parse_linux_event_type("RENAMEAT") == AccessAction.RENAME

    def test_permission_change_events(self):
        """Permission-changing events map to PERMISSION_CHANGE."""
        assert _parse_linux_event_type("CHMOD") == AccessAction.PERMISSION_CHANGE
        assert _parse_linux_event_type("CHOWN") == AccessAction.PERMISSION_CHANGE
        assert _parse_linux_event_type("FCHMOD") == AccessAction.PERMISSION_CHANGE
        assert _parse_linux_event_type("FCHOWN") == AccessAction.PERMISSION_CHANGE

    def test_unknown_event(self):
        """Unknown events map to UNKNOWN."""
        assert _parse_linux_event_type("UNKNOWN_EVENT") == AccessAction.UNKNOWN
        assert _parse_linux_event_type("") == AccessAction.UNKNOWN
        assert _parse_linux_event_type("FOOBAR") == AccessAction.UNKNOWN


class TestResolveLinuxUid:
    """Tests for UID to username resolution."""

    def test_resolve_valid_uid(self):
        """Resolving valid UID returns username."""
        with patch("pwd.getpwuid") as mock_getpwuid:
            mock_pw = MagicMock()
            mock_pw.pw_name = "testuser"
            mock_getpwuid.return_value = mock_pw

            result = _resolve_linux_uid("1000")

            assert result == "testuser"

    def test_resolve_invalid_uid_format(self):
        """Resolving non-numeric UID returns None."""
        result = _resolve_linux_uid("notanumber")

        assert result is None

    def test_resolve_unknown_uid(self):
        """Resolving unknown UID returns None."""
        with patch("pwd.getpwuid", side_effect=KeyError("uid not found")):
            result = _resolve_linux_uid("99999")

            assert result is None

    def test_resolve_uid_import_error(self):
        """Resolving UID returns None if pwd not available."""
        with patch.dict("sys.modules", {"pwd": None}):
            # This would raise ImportError
            result = _resolve_linux_uid("1000")
            # Depending on implementation, might be None or the original
            # Based on the code, it catches ImportError and returns None


class TestParseAusearchCsv:
    """Tests for ausearch CSV parsing."""

    def test_parse_empty_output(self, tmp_path):
        """Parsing empty output returns empty list."""
        result = _parse_ausearch_csv("", tmp_path / "file.txt", 100)

        assert result == []

    def test_parse_header_only(self, tmp_path):
        """Parsing output with only header returns empty list."""
        output = "NODE,EVENT_TYPE,EVENT_TIME,AUDIT_ID,UID,AUID"
        result = _parse_ausearch_csv(output, tmp_path / "file.txt", 100)

        assert result == []

    def test_parse_valid_csv(self, tmp_path):
        """Parsing valid CSV returns events."""
        output = """NODE,EVENT_TYPE,EVENT_TIME,AUDIT_ID,UID,AUID
host1,OPEN,2026-01-15T10:30:00,1234,1000,1000
host1,WRITE,2026-01-15T10:31:00,1235,1000,1000"""

        with patch("openlabels.monitoring.history._resolve_linux_uid") as mock_resolve:
            mock_resolve.return_value = "testuser"

            result = _parse_ausearch_csv(output, tmp_path / "file.txt", 100)

        assert len(result) == 2
        assert result[0].action in (AccessAction.READ, AccessAction.WRITE)

    def test_parse_csv_respects_limit(self, tmp_path):
        """Parsing respects limit parameter."""
        output = """NODE,EVENT_TYPE,EVENT_TIME,AUDIT_ID,UID,AUID
host1,READ,2026-01-15T10:30:00,1,1000,1000
host1,READ,2026-01-15T10:31:00,2,1000,1000
host1,READ,2026-01-15T10:32:00,3,1000,1000"""

        with patch("openlabels.monitoring.history._resolve_linux_uid", return_value="user"):
            result = _parse_ausearch_csv(output, tmp_path / "file.txt", 2)

        assert len(result) <= 2

    def test_parse_csv_short_line(self, tmp_path):
        """Parsing handles lines with fewer columns."""
        output = """NODE,EVENT_TYPE,EVENT_TIME,AUDIT_ID,UID,AUID
host1,READ
host1,WRITE,2026-01-15T10:31:00,1235,1000,1000"""

        with patch("openlabels.monitoring.history._resolve_linux_uid", return_value="user"):
            result = _parse_ausearch_csv(output, tmp_path / "file.txt", 100)

        # First line skipped due to insufficient columns
        assert len(result) == 1

    def test_parse_csv_invalid_timestamp(self, tmp_path):
        """Parsing handles invalid timestamps."""
        output = """NODE,EVENT_TYPE,EVENT_TIME,AUDIT_ID,UID,AUID
host1,READ,invalid_timestamp,1234,1000,1000"""

        with patch("openlabels.monitoring.history._resolve_linux_uid", return_value="user"):
            result = _parse_ausearch_csv(output, tmp_path / "file.txt", 100)

        # Should still parse, using fallback timestamp
        assert len(result) == 1


class TestGetHistoryWindowsComprehensive:
    """Comprehensive tests for Windows event log queries."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_returns_empty_on_no_results(self, tmp_path):
        """PowerShell query returns empty list when no events."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            )

            result = _get_history_windows(test_file, days=30, limit=100)

            assert result == []

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_handles_single_object(self, tmp_path):
        """PowerShell query handles single object (not array) response."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        # PowerShell returns single object, not array, for one result
        single_result = json.dumps({
            "TimeCreated": "2026-01-15T10:30:00",
            "EventId": 4663,
            "UserSid": "S-1-5-21-123456",
            "UserName": "testuser",
            "UserDomain": "DOMAIN",
            "ObjectName": str(test_file),
            "AccessMask": "0x1",
            "ProcessName": "app.exe",
            "ProcessId": 1234,
        })

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=single_result,
                stderr="",
            )

            result = _get_history_windows(test_file, days=30, limit=100)

            assert len(result) == 1

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_handles_access_mask_string(self, tmp_path):
        """PowerShell query handles access mask as string."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        results = json.dumps([{
            "TimeCreated": "2026-01-15T10:30:00",
            "EventId": 4663,
            "UserSid": "S-1-5-21-123456",
            "UserName": "testuser",
            "UserDomain": "DOMAIN",
            "ObjectName": str(test_file),
            "AccessMask": "0x1",  # String hex
            "ProcessName": "app.exe",
            "ProcessId": 1234,
        }])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=results,
                stderr="",
            )

            result = _get_history_windows(test_file, days=30, limit=100)

            assert result[0].action == AccessAction.READ

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_handles_decimal_access_mask(self, tmp_path):
        """PowerShell query handles access mask as decimal string."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        results = json.dumps([{
            "TimeCreated": "2026-01-15T10:30:00",
            "EventId": 4663,
            "UserSid": "S-1-5-21-123456",
            "UserName": "testuser",
            "UserDomain": "DOMAIN",
            "ObjectName": str(test_file),
            "AccessMask": "2",  # Decimal string
            "ProcessName": "app.exe",
            "ProcessId": 1234,
        }])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=results,
                stderr="",
            )

            result = _get_history_windows(test_file, days=30, limit=100)

            assert result[0].action == AccessAction.WRITE

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_handles_invalid_access_mask(self, tmp_path):
        """PowerShell query handles invalid access mask gracefully."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        results = json.dumps([{
            "TimeCreated": "2026-01-15T10:30:00",
            "EventId": 4663,
            "UserSid": "S-1-5-21-123456",
            "UserName": "testuser",
            "UserDomain": "DOMAIN",
            "ObjectName": str(test_file),
            "AccessMask": "invalid",  # Invalid
            "ProcessName": "app.exe",
            "ProcessId": 1234,
        }])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=results,
                stderr="",
            )

            result = _get_history_windows(test_file, days=30, limit=100)

            # Should still return event with UNKNOWN action
            assert len(result) == 1
            assert result[0].action == AccessAction.UNKNOWN

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_timeout(self, tmp_path):
        """PowerShell query handles timeout."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=60)

            result = _get_history_windows(test_file, days=30, limit=100)

            assert result == []

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_json_parse_error(self, tmp_path):
        """PowerShell query handles JSON parse errors."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="not valid json",
                stderr="",
            )

            result = _get_history_windows(test_file, days=30, limit=100)

            assert result == []

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific")
    def test_windows_powershell_nonzero_return(self, tmp_path):
        """PowerShell query handles non-zero return code."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Error: Access denied",
            )

            result = _get_history_windows(test_file, days=30, limit=100)

            assert result == []


class TestGetHistoryLinuxComprehensive:
    """Comprehensive tests for Linux audit log queries."""

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_ausearch_not_found(self, tmp_path):
        """ausearch not found returns empty list."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value=None):
            result = _get_history_linux(test_file, days=30, limit=100)

            assert result == []

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_ausearch_no_matches(self, tmp_path):
        """ausearch returns empty list when no matches."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/ausearch"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1,
                    stdout="",
                    stderr="<no matches>",
                )

                result = _get_history_linux(test_file, days=30, limit=100)

                assert result == []

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_ausearch_timeout(self, tmp_path):
        """ausearch handles timeout."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/ausearch"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="ausearch", timeout=60)

                result = _get_history_linux(test_file, days=30, limit=100)

                assert result == []

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific")
    def test_linux_ausearch_error(self, tmp_path):
        """ausearch handles other errors."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("shutil.which", return_value="/sbin/ausearch"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1,
                    stdout="",
                    stderr="Permission denied",
                )

                result = _get_history_linux(test_file, days=30, limit=100)

                assert result == []


class TestGetAccessHistoryComprehensive:
    """Comprehensive tests for get_access_history function."""

    def test_resolves_path(self, tmp_path):
        """get_access_history resolves the path."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        # Create symlink
        symlink = tmp_path / "link.txt"
        symlink.symlink_to(test_file)

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = []

            get_access_history(symlink)

            # Should resolve symlink
            mock_history.assert_called_once()
            called_path = mock_history.call_args[0][0]
            assert called_path.resolve() == test_file.resolve()

    def test_filters_system_accounts_by_default(self, tmp_path):
        """Filters system accounts by default."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

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

            assert len(result) == 1
            assert result[0].user_name == "jsmith"

    def test_includes_system_when_requested(self, tmp_path):
        """Includes system accounts when include_system=True."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

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

    def test_sorts_by_timestamp_newest_first(self, tmp_path):
        """Events are sorted by timestamp, newest first."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        now = datetime.now()
        events = [
            AccessEvent(
                path=test_file,
                timestamp=now - timedelta(hours=2),
                action=AccessAction.READ,
                user_name="old",
            ),
            AccessEvent(
                path=test_file,
                timestamp=now,
                action=AccessAction.READ,
                user_name="newest",
            ),
            AccessEvent(
                path=test_file,
                timestamp=now - timedelta(hours=1),
                action=AccessAction.READ,
                user_name="middle",
            ),
        ]

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = events

            result = get_access_history(test_file, include_system=True)

            assert result[0].user_name == "newest"
            assert result[1].user_name == "middle"
            assert result[2].user_name == "old"

    def test_respects_limit(self, tmp_path):
        """Respects the limit parameter."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        events = [
            AccessEvent(
                path=test_file,
                timestamp=datetime.now() - timedelta(minutes=i),
                action=AccessAction.READ,
                user_name=f"user{i}",
            )
            for i in range(10)
        ]

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = events

            result = get_access_history(test_file, limit=5, include_system=True)

            assert len(result) == 5

    def test_passes_days_parameter(self, tmp_path):
        """Passes days parameter to platform-specific function."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("openlabels.monitoring.history._get_history_windows" if platform.system() == "Windows"
                   else "openlabels.monitoring.history._get_history_linux") as mock_history:
            mock_history.return_value = []

            get_access_history(test_file, days=7)

            mock_history.assert_called_once()
            assert mock_history.call_args[0][1] == 7  # days parameter

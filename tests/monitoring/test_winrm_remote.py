"""Tests for WinRM remote audit configuration and command injection prevention."""

import json
from unittest.mock import MagicMock, patch

import pytest

from openlabels.monitoring.winrm_remote import (
    WinRMResult,
    _get_winrm_session,
    configure_audit_policy,
    collect_events,
    test_connection as winrm_test_connection,
)


class TestGetWinrmSession:
    """Tests for WinRM session creation."""

    def test_http_endpoint(self):
        mock_winrm = MagicMock()
        mock_session = MagicMock()
        mock_winrm.Session.return_value = mock_session

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            session = _get_winrm_session("server1", "admin", "pass123")

        mock_winrm.Session.assert_called_once()
        call_args = mock_winrm.Session.call_args
        assert "http://server1:5985/wsman" in call_args[0]
        assert call_args[1]["auth"] == ("admin", "pass123")
        assert call_args[1]["transport"] == "ntlm"

    def test_https_endpoint(self):
        mock_winrm = MagicMock()
        mock_winrm.Session.return_value = MagicMock()

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session("server1", "admin", "pass123", use_ssl=True)

        call_args = mock_winrm.Session.call_args
        assert "https://server1:5986/wsman" in call_args[0]

    def test_kerberos_transport_for_upn(self):
        """Username with @ (UPN format) should use Kerberos."""
        mock_winrm = MagicMock()
        mock_winrm.Session.return_value = MagicMock()

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session("server1", "admin@domain.com", "pass123")

        call_args = mock_winrm.Session.call_args
        assert call_args[1]["transport"] == "kerberos"

    def test_ntlm_transport_for_domain_user(self):
        """Username with DOMAIN\\user format should use NTLM."""
        mock_winrm = MagicMock()
        mock_winrm.Session.return_value = MagicMock()

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session("server1", "DOMAIN\\admin@host", "pass123")

        call_args = mock_winrm.Session.call_args
        assert call_args[1]["transport"] == "ntlm"

    def test_cert_validation_default(self):
        mock_winrm = MagicMock()
        mock_winrm.Session.return_value = MagicMock()

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session("server1", "admin", "pass123")

        call_args = mock_winrm.Session.call_args
        assert call_args[1]["server_cert_validation"] == "validate"

    def test_cert_validation_ignore(self):
        mock_winrm = MagicMock()
        mock_winrm.Session.return_value = MagicMock()

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session(
                "server1", "admin", "pass123",
                server_cert_validation="ignore",
            )

        call_args = mock_winrm.Session.call_args
        assert call_args[1]["server_cert_validation"] == "ignore"

    def test_missing_pywinrm_raises_import_error(self):
        """Should raise ImportError if pywinrm is not installed."""
        with patch.dict("sys.modules", {"winrm": None}):
            with pytest.raises((ImportError, ModuleNotFoundError)):
                _get_winrm_session("server1", "admin", "pass123")


class TestTestConnection:
    """Tests for WinRM connection testing."""

    async def test_successful_connection(self):
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps({
            "hostname": "FILESERVER1",
            "os": "Windows Server 2022",
            "has_audit_privilege": True,
            "audit_policy_enabled": True,
        }).encode("utf-8")
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await winrm_test_connection("server1", "admin", "pass")

        assert result.success is True
        assert "FILESERVER1" in result.message

    async def test_connection_command_failure(self):
        mock_result = MagicMock()
        mock_result.status_code = 1
        mock_result.std_out = b""
        mock_result.std_err = b"Access denied"

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await winrm_test_connection("server1", "admin", "pass")

        assert result.success is False
        assert result.error is not None
        assert "Access denied" in result.error

    async def test_connection_pywinrm_not_installed(self):
        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            side_effect=ImportError("No module named 'winrm'"),
        ):
            result = await winrm_test_connection("server1", "admin", "pass")

        assert result.success is False
        assert "pywinrm" in result.message.lower()

    async def test_connection_network_error(self):
        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            side_effect=ConnectionError("Connection refused"),
        ):
            result = await winrm_test_connection("server1", "admin", "pass")

        assert result.success is False
        assert "Connection" in result.error

    async def test_connection_invalid_json_output(self):
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = b"not valid json output"
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await winrm_test_connection("server1", "admin", "pass")

        assert result.success is True
        assert result.data is not None
        assert "raw_output" in result.data


class TestCommandInjectionPrevention:
    """Tests for command injection prevention in audit configuration.

    These tests verify that malicious inputs are properly sanitized
    or rejected before being passed to PowerShell scripts.
    """

    async def test_path_with_semicolon_rejected(self):
        """Semicolons in paths could chain PowerShell commands."""
        result = await self._configure_with_paths(["D:\\Share; Remove-Item C:\\ -Recurse"])
        assert result.success is False
        assert "invalid characters" in result.error.lower()

    async def test_path_with_backtick_rejected(self):
        """Backticks are PowerShell escape characters."""
        result = await self._configure_with_paths(["D:\\Share`whoami"])
        assert result.success is False

    async def test_path_with_dollar_sign_rejected(self):
        """Dollar signs could inject PS variable expansion."""
        result = await self._configure_with_paths(["D:\\$env:USERNAME"])
        assert result.success is False

    async def test_path_with_pipe_rejected(self):
        """Pipes could chain commands."""
        result = await self._configure_with_paths(["D:\\Share | Get-Process"])
        assert result.success is False

    async def test_path_with_ampersand_rejected(self):
        """Ampersands could invoke additional commands."""
        result = await self._configure_with_paths(["D:\\Share & del *.*"])
        assert result.success is False

    async def test_path_with_double_quotes_rejected(self):
        """Double quotes could break out of string context."""
        result = await self._configure_with_paths(['D:\\Share"; Remove-Item C:\\'])
        assert result.success is False

    async def test_path_with_single_quotes_rejected(self):
        """Single quotes could break string delimiters."""
        result = await self._configure_with_paths(["D:\\Share'; Remove-Item C:\\"])
        assert result.success is False

    async def test_path_with_newline_rejected(self):
        """Newlines could inject additional script lines."""
        result = await self._configure_with_paths(["D:\\Share\nRemove-Item C:\\"])
        assert result.success is False

    async def test_path_with_carriage_return_rejected(self):
        """Carriage returns could inject additional script lines."""
        result = await self._configure_with_paths(["D:\\Share\rRemove-Item C:\\"])
        assert result.success is False

    async def test_all_paths_malicious_returns_error(self):
        """If every path is rejected, the function should return failure."""
        result = await self._configure_with_paths([
            "D:\\Share; whoami",
            "D:\\Share`id",
            "D:\\$env:PATH",
        ])
        assert result.success is False
        assert "All paths rejected" in result.message

    async def test_mixed_paths_only_valid_used(self):
        """Valid paths should be processed even if some are rejected."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps([
            {"path": "D:\\ValidShare", "status": "configured"},
        ]).encode("utf-8")
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await configure_audit_policy(
                "server1", "admin", "pass",
                share_paths=["D:\\ValidShare", "D:\\Bad;Path"],
            )

        assert result.success is True
        # The PowerShell script should only contain the valid path
        script_arg = mock_session.run_ps.call_args[0][0]
        assert "D:\\ValidShare" in script_arg
        assert "D:\\Bad;Path" not in script_arg

    async def test_legitimate_paths_accepted(self):
        """Normal Windows paths should pass validation."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps([
            {"path": "D:\\Shares\\Finance", "status": "configured"},
            {"path": "D:\\Shares\\HR", "status": "configured"},
        ]).encode("utf-8")
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await configure_audit_policy(
                "server1", "admin", "pass",
                share_paths=["D:\\Shares\\Finance", "D:\\Shares\\HR"],
            )

        assert result.success is True
        assert "2/2" in result.message

    async def _configure_with_paths(self, paths: list[str]) -> WinRMResult:
        """Helper: run configure_audit_policy with given paths, mocking WinRM."""
        mock_session = MagicMock()
        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            return await configure_audit_policy("server1", "admin", "pass", share_paths=paths)


class TestConfigureAuditPolicy:
    """Tests for audit policy configuration."""

    async def test_empty_paths_returns_error(self):
        result = await configure_audit_policy("server1", "admin", "pass", share_paths=[])
        assert result.success is False
        assert "no paths" in result.message.lower()

    async def test_pywinrm_not_installed(self):
        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            side_effect=ImportError("No module named 'winrm'"),
        ):
            result = await configure_audit_policy(
                "server1", "admin", "pass",
                share_paths=["D:\\Share"],
            )
        assert result.success is False
        assert "pywinrm" in result.message.lower()

    async def test_powershell_execution_failure(self):
        mock_result = MagicMock()
        mock_result.status_code = 1
        mock_result.std_out = b""
        mock_result.std_err = b"Execution policy restriction"

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await configure_audit_policy(
                "server1", "admin", "pass",
                share_paths=["D:\\Share"],
            )

        assert result.success is False
        assert "Execution policy" in result.error

    async def test_partial_path_configuration(self):
        """Some paths succeed, some fail — should report partial success."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps([
            {"path": "D:\\Share1", "status": "configured"},
            {"path": "D:\\Share2", "status": "not_found"},
        ]).encode("utf-8")
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await configure_audit_policy(
                "server1", "admin", "pass",
                share_paths=["D:\\Share1", "D:\\Share2"],
            )

        assert result.success is True
        assert "1/2" in result.message

    async def test_single_result_dict_wrapped_as_list(self):
        """PowerShell returns a dict for single results; should be wrapped."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps(
            {"path": "D:\\Share1", "status": "configured"}
        ).encode("utf-8")
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await configure_audit_policy(
                "server1", "admin", "pass",
                share_paths=["D:\\Share1"],
            )

        assert result.success is True
        assert "1/1" in result.message

    async def test_connection_error_during_audit(self):
        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            side_effect=ConnectionError("timeout"),
        ):
            result = await configure_audit_policy(
                "server1", "admin", "pass",
                share_paths=["D:\\Share"],
            )

        assert result.success is False
        assert "timeout" in result.error


class TestCollectEvents:
    """Tests for remote event collection."""

    async def test_collect_events_success(self):
        events = [
            {
                "time": "2026-01-15T12:00:00Z",
                "event_id": 4663,
                "user_sid": "S-1-5-21-123",
                "user_name": "jdoe",
                "domain": "CORP",
                "object_name": "D:\\Shares\\Finance\\report.xlsx",
                "access_mask": "0x1",
                "process": "explorer.exe",
            }
        ]
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps(events).encode("utf-8")
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await collect_events("server1", "admin", "pass")

        assert result.success is True
        assert len(result.data["events"]) == 1
        assert result.data["events"][0]["event_id"] == 4663

    async def test_collect_no_events(self):
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = b""
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await collect_events("server1", "admin", "pass")

        assert result.success is True
        assert result.data["events"] == []

    async def test_collect_invalid_since_hours(self):
        result = await collect_events("server1", "admin", "pass", since_hours=-1)
        assert result.success is False
        assert "since_hours" in result.error

    async def test_collect_invalid_since_hours_type(self):
        result = await collect_events("server1", "admin", "pass", since_hours="bad")
        assert result.success is False
        assert "since_hours" in result.error

    async def test_collect_invalid_max_events(self):
        result = await collect_events("server1", "admin", "pass", max_events=0)
        assert result.success is False
        assert "max_events" in result.error

    async def test_collect_invalid_max_events_negative(self):
        result = await collect_events("server1", "admin", "pass", max_events=-5)
        assert result.success is False
        assert "max_events" in result.error

    async def test_collect_pywinrm_not_installed(self):
        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            side_effect=ImportError("No module named 'winrm'"),
        ):
            result = await collect_events("server1", "admin", "pass")

        assert result.success is False
        assert "pywinrm" in result.message.lower()

    async def test_collect_connection_failure(self):
        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            side_effect=ConnectionError("Host unreachable"),
        ):
            result = await collect_events("server1", "admin", "pass")

        assert result.success is False
        assert "Host unreachable" in result.error

    async def test_collect_single_event_dict_wrapped(self):
        """PowerShell returns a dict for a single event; should be wrapped."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps({
            "time": "2026-01-15T12:00:00Z",
            "event_id": 4663,
        }).encode("utf-8")
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await collect_events("server1", "admin", "pass")

        assert result.success is True
        assert len(result.data["events"]) == 1

    async def test_collect_includes_host_in_data(self):
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = b""
        mock_result.std_err = b""

        mock_session = MagicMock()
        mock_session.run_ps.return_value = mock_result

        with patch(
            "openlabels.monitoring.winrm_remote._get_winrm_session",
            return_value=mock_session,
        ):
            result = await collect_events("myserver", "admin", "pass")

        assert result.data["host"] == "myserver"
        assert result.data["since_hours"] == 24


class TestWinRMResult:
    """Tests for WinRMResult dataclass."""

    def test_default_values(self):
        r = WinRMResult(success=True, message="ok")
        assert r.data is None
        assert r.error is None

    def test_with_all_fields(self):
        r = WinRMResult(
            success=False,
            message="failed",
            data={"key": "value"},
            error="some error",
        )
        assert r.success is False
        assert r.data == {"key": "value"}
        assert r.error == "some error"

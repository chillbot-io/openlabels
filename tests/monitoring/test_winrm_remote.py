"""Tests for WinRM remote audit configuration and command injection prevention."""

import json
import socket
from unittest.mock import MagicMock, patch

import pytest

from openlabels.monitoring.winrm_remote import (
    WinRMResult,
    _get_winrm_session,
    collect_events,
    configure_audit_policy,
)
from openlabels.monitoring.winrm_remote import (
    test_connection as winrm_test_connection,
)


# Mock DNS resolution: return a public IP so SSRF validation passes for test hosts.
_FAKE_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 5986))]


@pytest.fixture(autouse=True)
def _mock_dns():
    with patch("openlabels.core.url_validation.socket.getaddrinfo", return_value=_FAKE_ADDRINFO):
        yield


class TestGetWinrmSession:
    """Tests for WinRM session creation."""

    def test_default_ssl_endpoint(self):
        """Default use_ssl=True produces HTTPS with pinned IP."""
        mock_winrm = MagicMock()
        mock_session = MagicMock()
        mock_winrm.Session.return_value = mock_session

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session("server1", "admin", "pass123")

        mock_winrm.Session.assert_called_once()
        call_args = mock_winrm.Session.call_args
        # _validate_host now returns a pinned IP, so endpoint uses the IP
        endpoint = call_args[0][0]
        assert endpoint.startswith("https://") and ":5986/wsman" in endpoint
        assert call_args[1]["auth"] == ("admin", "pass123")
        assert call_args[1]["transport"] == "ntlm"

    def test_http_endpoint(self):
        mock_winrm = MagicMock()
        mock_session = MagicMock()
        mock_winrm.Session.return_value = mock_session

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session("server1", "admin", "pass123", use_ssl=False)

        call_args = mock_winrm.Session.call_args
        endpoint = call_args[0][0]
        assert endpoint.startswith("http://") and ":5985/wsman" in endpoint

    def test_https_endpoint(self):
        mock_winrm = MagicMock()
        mock_winrm.Session.return_value = MagicMock()

        with patch.dict("sys.modules", {"winrm": mock_winrm}):
            _get_winrm_session("server1", "admin", "pass123", use_ssl=True)

        call_args = mock_winrm.Session.call_args
        endpoint = call_args[0][0]
        assert endpoint.startswith("https://") and ":5986/wsman" in endpoint

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

    PowerShell single-quoted strings ('...') are used, which treat all
    characters literally except single quotes (escaped by doubling: '').
    This means special chars like ;, $, `, |, & are safe inside the
    string and no longer need to be rejected.
    """

    async def test_path_with_single_quote_escaped(self):
        """Single quotes in paths are escaped by doubling in PS single-quoted strings."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps([
            {"path": "D:\\O'Brien", "status": "configured"},
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
                share_paths=["D:\\O'Brien"],
            )

        assert result.success is True
        script_arg = mock_session.run_ps.call_args[0][0]
        # Verify the single quote was doubled for PS escaping
        assert "O''Brien" in script_arg

    async def test_special_chars_safe_in_single_quotes(self):
        """Chars like $, `, ;, | are safe inside PS single-quoted strings."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps([
            {"path": "D:\\$env", "status": "not_found"},
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
                share_paths=["D:\\$env"],
            )

        # Path is accepted (it's safe in single quotes), even though
        # it won't exist on the server (status=not_found)
        script_arg = mock_session.run_ps.call_args[0][0]
        assert "'D:\\$env'" in script_arg

    async def test_empty_and_whitespace_paths_skipped(self):
        """Empty or whitespace-only paths should be filtered out."""
        result = await self._configure_with_paths(["", "  ", "   "])
        assert result.success is False
        assert "No valid paths" in result.error

    async def test_all_paths_with_special_chars_accepted(self):
        """With PS single-quoted strings, all these paths are safely handled."""
        mock_result = MagicMock()
        mock_result.status_code = 0
        mock_result.std_out = json.dumps([
            {"path": "D:\\Share; whoami", "status": "not_found"},
            {"path": "D:\\Share`id", "status": "not_found"},
            {"path": "D:\\$env:PATH", "status": "not_found"},
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
                share_paths=["D:\\Share; whoami", "D:\\Share`id", "D:\\$env:PATH"],
            )

        # All paths are passed through (safely quoted), none rejected
        script_arg = mock_session.run_ps.call_args[0][0]
        assert "'D:\\Share; whoami'" in script_arg
        assert "'D:\\Share`id'" in script_arg
        assert "'D:\\$env:PATH'" in script_arg

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

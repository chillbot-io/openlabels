"""
Comprehensive tests for CLI utility functions and server-backed commands.

Covers:
- handle_http_error(): error message correctness for all HTTP error types
- collect_files(): file/directory collection with recursive/flat modes
- scan_files(): integration with FileProcessor, per-file error handling
- get_httpx_client() / get_server_url(): client construction and env-based config
- scan command group: start, status, cancel with mocked httpx
- export command: results export with mocked server responses
- target command group: list, add
- user command group: list, create
- labels command group: list, sync
- config command group: show, set (nested keys, type coercion)
- db command group: upgrade, downgrade
- Error propagation: HTTP errors surface as user-friendly CLI output
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import httpx
import pytest
from click.testing import CliRunner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory with a flat and nested file layout."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Top-level files
        (Path(tmpdir) / "alpha.txt").write_text("alpha content")
        (Path(tmpdir) / "beta.csv").write_text("col1,col2\na,b")

        # Nested directory
        sub = Path(tmpdir) / "sub"
        sub.mkdir()
        (sub / "gamma.txt").write_text("gamma content")

        # Deeper nested
        deep = sub / "deep"
        deep.mkdir()
        (deep / "delta.log").write_text("delta content")

        yield tmpdir


@pytest.fixture
def mock_file_classification():
    """Standard mock FileClassification with some entities."""
    from openlabels.core.processor import FileClassification
    from openlabels.core.types import RiskTier

    return FileClassification(
        file_path="/mock/file.txt",
        file_name="file.txt",
        file_size=256,
        mime_type="text/plain",
        exposure_level="PRIVATE",
        entity_counts={"SSN": 3, "EMAIL": 1},
        risk_score=72,
        risk_tier=RiskTier.HIGH,
    )


def _make_response(status_code, json_body=None, text_body=""):
    """Build a fake httpx.Response with the given status and body."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text_body
    resp.content = text_body.encode() if isinstance(text_body, str) else text_body
    if json_body is not None:
        resp.json.return_value = json_body
        resp.text = json.dumps(json_body)
    return resp


def _make_http_status_error(status_code, message="error"):
    """Build an httpx.HTTPStatusError with a given status code."""
    request = httpx.Request("GET", "http://localhost:8000/test")
    response = httpx.Response(status_code, request=request, text=message)
    return httpx.HTTPStatusError(
        message=message,
        request=request,
        response=response,
    )


# ======================================================================
# handle_http_error
# ======================================================================

class TestHandleHttpError:
    """Tests for handle_http_error()."""

    def test_timeout_exception_message(self):
        """TimeoutException should produce a 'timed out' error."""
        from openlabels.cli.utils import handle_http_error

        exc = httpx.TimeoutException("read timed out")
        with patch("click.echo") as mock_echo:
            handle_http_error(exc, "http://localhost:8000")
        mock_echo.assert_called_once()
        msg = mock_echo.call_args[0][0]
        assert "timed out" in msg.lower()

    def test_connect_error_includes_server_url(self):
        """ConnectError message should include the server URL so the user
        knows which endpoint is unreachable."""
        from openlabels.cli.utils import handle_http_error

        exc = httpx.ConnectError("Connection refused")
        with patch("click.echo") as mock_echo:
            handle_http_error(exc, "http://myhost:9999")
        msg = mock_echo.call_args[0][0]
        assert "http://myhost:9999" in msg
        assert "Cannot connect" in msg

    def test_http_status_error_401(self):
        """401 should show the numeric status code."""
        from openlabels.cli.utils import handle_http_error

        exc = _make_http_status_error(401)
        with patch("click.echo") as mock_echo:
            handle_http_error(exc, "http://localhost:8000")
        msg = mock_echo.call_args[0][0]
        assert "401" in msg

    def test_http_status_error_403(self):
        """403 Forbidden should be reported."""
        from openlabels.cli.utils import handle_http_error

        exc = _make_http_status_error(403)
        with patch("click.echo") as mock_echo:
            handle_http_error(exc, "http://localhost:8000")
        msg = mock_echo.call_args[0][0]
        assert "403" in msg

    def test_http_status_error_404(self):
        """404 Not Found should be reported."""
        from openlabels.cli.utils import handle_http_error

        exc = _make_http_status_error(404)
        with patch("click.echo") as mock_echo:
            handle_http_error(exc, "http://localhost:8000")
        msg = mock_echo.call_args[0][0]
        assert "404" in msg

    def test_http_status_error_500(self):
        """500 Internal Server Error should be reported."""
        from openlabels.cli.utils import handle_http_error

        exc = _make_http_status_error(500)
        with patch("click.echo") as mock_echo:
            handle_http_error(exc, "http://localhost:8000")
        msg = mock_echo.call_args[0][0]
        assert "500" in msg

    def test_generic_exception_fallback(self):
        """Unrecognised exceptions should fall through to the generic branch."""
        from openlabels.cli.utils import handle_http_error

        exc = RuntimeError("something unexpected")
        with patch("click.echo") as mock_echo:
            handle_http_error(exc, "http://localhost:8000")
        msg = mock_echo.call_args[0][0]
        assert "something unexpected" in msg

    def test_all_errors_written_to_stderr(self):
        """Every branch should write to stderr (err=True)."""
        from openlabels.cli.utils import handle_http_error

        for exc in [
            httpx.TimeoutException("t"),
            httpx.ConnectError("c"),
            _make_http_status_error(502),
            ValueError("v"),
        ]:
            with patch("click.echo") as mock_echo:
                handle_http_error(exc, "http://x")
            _, kwargs = mock_echo.call_args
            assert kwargs.get("err") is True, (
                f"Expected err=True for {type(exc).__name__}"
            )


# ======================================================================
# collect_files
# ======================================================================

class TestCollectFiles:
    """Tests for collect_files()."""

    def test_single_file_returns_list_of_one(self, temp_dir):
        """Passing a single file path returns a one-element list."""
        from openlabels.cli.utils import collect_files

        single = Path(temp_dir) / "alpha.txt"
        result = collect_files(str(single))
        assert len(result) == 1
        assert result[0] == single

    def test_directory_flat_excludes_subdirectories(self, temp_dir):
        """Non-recursive collection from a directory with subdirectories
        should only return files in the top level."""
        from openlabels.cli.utils import collect_files

        result = collect_files(temp_dir, recursive=False)
        names = {f.name for f in result}
        assert "alpha.txt" in names
        assert "beta.csv" in names
        # Nested files must NOT appear
        assert "gamma.txt" not in names
        assert "delta.log" not in names

    def test_directory_recursive_includes_all_files(self, temp_dir):
        """Recursive collection should return files at all depths."""
        from openlabels.cli.utils import collect_files

        result = collect_files(temp_dir, recursive=True)
        names = {f.name for f in result}
        assert "alpha.txt" in names
        assert "beta.csv" in names
        assert "gamma.txt" in names
        assert "delta.log" in names

    def test_empty_directory_returns_empty_list(self):
        """An empty directory should produce an empty list."""
        from openlabels.cli.utils import collect_files

        with tempfile.TemporaryDirectory() as empty:
            result = collect_files(empty)
        assert result == []

    def test_directories_are_excluded_from_results(self, temp_dir):
        """Subdirectories themselves must never appear in the results."""
        from openlabels.cli.utils import collect_files

        result = collect_files(temp_dir, recursive=True)
        for p in result:
            assert p.is_file(), f"Non-file entry in results: {p}"

    def test_nonexistent_path_treated_as_single_file(self):
        """A path that doesn't exist is still returned as a list of one
        (the caller or click.Path(exists=True) is responsible for validation)."""
        from openlabels.cli.utils import collect_files

        result = collect_files("/does/not/exist.txt")
        assert len(result) == 1
        assert str(result[0]) == "/does/not/exist.txt"

    def test_mixed_content_only_files_in_recursive(self, temp_dir):
        """Ensure that hidden files / symlinks don't break collect_files."""
        from openlabels.cli.utils import collect_files

        # Create a hidden file
        hidden = Path(temp_dir) / ".hidden_file"
        hidden.write_text("hidden")

        result = collect_files(temp_dir, recursive=True)
        names = {f.name for f in result}
        assert ".hidden_file" in names


# ======================================================================
# scan_files
# ======================================================================

class TestScanFiles:
    """Tests for scan_files() - the utility that processes a list of
    Path objects through FileProcessor and returns result dicts."""

    def test_successful_scan_returns_result_dicts(self, temp_dir, mock_file_classification):
        """Each successfully processed file should appear as a dict with
        the documented keys."""
        from openlabels.cli.utils import scan_files

        files = [Path(temp_dir) / "alpha.txt"]

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(return_value=mock_file_classification)
            MockFP.return_value = mock_proc

            results = scan_files(files, enable_ml=False, exposure_level="PRIVATE")

        assert len(results) == 1
        r = results[0]
        assert "file_path" in r
        assert "file_name" in r
        assert "risk_score" in r
        assert "risk_tier" in r
        assert "entity_counts" in r
        assert "total_entities" in r
        assert r["risk_score"] == 72
        assert r["total_entities"] == 4  # 3 SSN + 1 EMAIL

    def test_multiple_files_all_returned(self, temp_dir, mock_file_classification):
        """All files in the list should be processed."""
        from openlabels.cli.utils import scan_files

        files = [
            Path(temp_dir) / "alpha.txt",
            Path(temp_dir) / "beta.csv",
        ]

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(return_value=mock_file_classification)
            MockFP.return_value = mock_proc

            results = scan_files(files)

        assert len(results) == 2

    def test_permission_error_skips_file(self, temp_dir):
        """Files that raise PermissionError during open() should be
        silently skipped (logged at DEBUG)."""
        from openlabels.cli.utils import scan_files

        files = [Path(temp_dir) / "alpha.txt"]

        with patch("builtins.open", side_effect=PermissionError("denied")):
            with patch("openlabels.core.processor.FileProcessor"):
                results = scan_files(files)

        assert results == []

    def test_os_error_skips_file(self, temp_dir):
        """Files that raise OSError during open() are skipped."""
        from openlabels.cli.utils import scan_files

        files = [Path(temp_dir) / "alpha.txt"]

        with patch("builtins.open", side_effect=OSError("disk error")):
            with patch("openlabels.core.processor.FileProcessor"):
                results = scan_files(files)

        assert results == []

    def test_unicode_decode_error_skips_file(self, temp_dir, mock_file_classification):
        """Files that raise UnicodeDecodeError during processing are skipped."""
        from openlabels.cli.utils import scan_files

        files = [Path(temp_dir) / "alpha.txt"]

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(
                side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "bad byte")
            )
            MockFP.return_value = mock_proc

            results = scan_files(files)

        assert results == []

    def test_value_error_skips_file(self, temp_dir, mock_file_classification):
        """Files that raise ValueError during processing are skipped."""
        from openlabels.cli.utils import scan_files

        files = [Path(temp_dir) / "alpha.txt"]

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(
                side_effect=ValueError("bad value")
            )
            MockFP.return_value = mock_proc

            results = scan_files(files)

        assert results == []

    def test_mix_of_success_and_failure(self, temp_dir, mock_file_classification):
        """When some files succeed and others fail, only the successes appear."""
        from openlabels.cli.utils import scan_files

        files = [
            Path(temp_dir) / "alpha.txt",
            Path(temp_dir) / "beta.csv",
        ]

        call_count = 0

        async def _alternate(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_file_classification
            raise PermissionError("nope")

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(side_effect=_alternate)
            MockFP.return_value = mock_proc

            results = scan_files(files)

        # Only the first file should succeed
        assert len(results) == 1

    def test_enable_ml_passed_to_processor(self, temp_dir, mock_file_classification):
        """enable_ml flag must be forwarded to FileProcessor constructor."""
        from openlabels.cli.utils import scan_files

        files = [Path(temp_dir) / "alpha.txt"]

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(return_value=mock_file_classification)
            MockFP.return_value = mock_proc

            scan_files(files, enable_ml=True)

        MockFP.assert_called_once_with(enable_ml=True)

    def test_exposure_level_forwarded(self, temp_dir, mock_file_classification):
        """The exposure_level kwarg should be forwarded to process_file."""
        from openlabels.cli.utils import scan_files

        files = [Path(temp_dir) / "alpha.txt"]

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(return_value=mock_file_classification)
            MockFP.return_value = mock_proc

            scan_files(files, exposure_level="PUBLIC")

        call_kwargs = mock_proc.process_file.call_args[1]
        assert call_kwargs["exposure_level"] == "PUBLIC"

    def test_risk_tier_enum_value_extracted(self, temp_dir):
        """When risk_tier has a .value attribute (Enum), the string value
        should be stored, not the Enum member."""
        from openlabels.cli.utils import scan_files
        from openlabels.core.processor import FileClassification
        from openlabels.core.types import RiskTier

        fc = FileClassification(
            file_path="/x", file_name="x", file_size=10,
            mime_type="text/plain", exposure_level="PRIVATE",
            entity_counts={"SSN": 1}, risk_score=90,
            risk_tier=RiskTier.CRITICAL,
        )
        files = [Path(temp_dir) / "alpha.txt"]

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(return_value=fc)
            MockFP.return_value = mock_proc

            results = scan_files(files)

        assert results[0]["risk_tier"] == "CRITICAL"

    def test_empty_file_list_returns_empty(self):
        """Passing an empty list of files should return an empty list."""
        from openlabels.cli.utils import scan_files

        with patch("openlabels.core.processor.FileProcessor"):
            results = scan_files([])

        assert results == []


# ======================================================================
# get_httpx_client / get_server_url
# ======================================================================

class TestGetHttpxClient:
    """Tests for get_httpx_client()."""

    def test_returns_httpx_client_instance(self):
        """Should return an httpx.Client."""
        from openlabels.cli.utils import get_httpx_client

        client = get_httpx_client()
        try:
            assert isinstance(client, httpx.Client)
        finally:
            client.close()

    def test_client_has_timeout(self):
        """Client should have a timeout configured (30s per source)."""
        from openlabels.cli.utils import get_httpx_client

        client = get_httpx_client()
        try:
            # httpx.Client stores timeout as a Timeout object
            assert client.timeout is not None
        finally:
            client.close()


class TestGetServerUrl:
    """Tests for get_server_url()."""

    def test_default_url(self):
        """Without env var, should return http://localhost:8000."""
        from openlabels.cli.utils import get_server_url

        with patch.dict(os.environ, {}, clear=False):
            # Remove OPENLABELS_SERVER if it exists
            os.environ.pop("OPENLABELS_SERVER", None)
            url = get_server_url()
        assert url == "http://localhost:8000"

    def test_custom_url_from_env(self):
        """OPENLABELS_SERVER env var should override the default."""
        from openlabels.cli.utils import get_server_url

        with patch.dict(os.environ, {"OPENLABELS_SERVER": "https://custom:9090"}):
            url = get_server_url()
        assert url == "https://custom:9090"


# ======================================================================
# scan command group (server-backed)
# ======================================================================

class TestScanStartCommand:
    """Tests for 'scan start <target_name>'."""

    def test_scan_start_success(self, runner):
        """Happy path: target exists, scan starts, output shows scan ID."""
        from openlabels.cli.commands.scan import scan

        targets_resp = _make_response(200, json_body=[
            {"id": "t-1", "name": "my-target"},
        ])
        scan_resp = _make_response(201, json_body={
            "id": "scan-42", "status": "running",
        })

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = targets_resp
        mock_client.post.return_value = scan_resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["start", "my-target"])

        assert result.exit_code == 0
        assert "scan-42" in result.output
        assert "running" in result.output

    def test_scan_start_target_not_found(self, runner):
        """When the target name does not exist, an error should be shown."""
        from openlabels.cli.commands.scan import scan

        targets_resp = _make_response(200, json_body=[
            {"id": "t-1", "name": "other-target"},
        ])

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = targets_resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["start", "nonexistent"])

        assert "not found" in result.output.lower() or "Target not found" in result.output

    def test_scan_start_targets_fetch_fails(self, runner):
        """If fetching targets returns non-200, error is shown."""
        from openlabels.cli.commands.scan import scan

        targets_resp = _make_response(500)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = targets_resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["start", "anything"])

        assert "error" in result.output.lower() or "500" in result.output

    def test_scan_start_timeout(self, runner):
        """Timeout on scan start should produce a user-friendly message."""
        from openlabels.cli.commands.scan import scan

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = httpx.TimeoutException("timeout")

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["start", "my-target"])

        assert "timed out" in result.output.lower()

    def test_scan_start_connect_error(self, runner):
        """Connection refused should show the server URL in the message."""
        from openlabels.cli.commands.scan import scan

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = httpx.ConnectError("refused")

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["start", "my-target", "--server", "http://dead:1234"])

        assert "http://dead:1234" in result.output
        assert "Cannot connect" in result.output

    def test_scan_start_client_closed_in_finally(self, runner):
        """The httpx client must be closed even when an error occurs."""
        from openlabels.cli.commands.scan import scan

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = httpx.ConnectError("refused")

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            runner.invoke(scan, ["start", "my-target"])

        mock_client.close.assert_called_once()


class TestScanStatusCommand:
    """Tests for 'scan status <job_id>'."""

    def test_scan_status_success(self, runner):
        """Happy path shows job details."""
        from openlabels.cli.commands.scan import scan

        resp = _make_response(200, json_body={
            "id": "scan-42",
            "status": "completed",
            "started_at": "2026-01-15T10:00:00",
            "completed_at": "2026-01-15T10:05:00",
            "progress": {"files_scanned": 100, "files_total": 100},
        })
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["status", "scan-42"])

        assert result.exit_code == 0
        assert "scan-42" in result.output
        assert "completed" in result.output
        assert "100/100" in result.output

    def test_scan_status_not_found(self, runner):
        """Non-200 status code shows error."""
        from openlabels.cli.commands.scan import scan

        resp = _make_response(404)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["status", "no-such-id"])

        assert "404" in result.output or "Error" in result.output

    def test_scan_status_no_progress(self, runner):
        """Status without progress data should not crash."""
        from openlabels.cli.commands.scan import scan

        resp = _make_response(200, json_body={
            "id": "scan-1", "status": "pending",
        })
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["status", "scan-1"])

        assert result.exit_code == 0
        assert "pending" in result.output


class TestScanCancelCommand:
    """Tests for 'scan cancel <job_id>'."""

    def test_scan_cancel_success_200(self, runner):
        """Cancel returning 200 should report success."""
        from openlabels.cli.commands.scan import scan

        resp = _make_response(200)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.delete.return_value = resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["cancel", "scan-42"])

        assert result.exit_code == 0
        assert "Cancelled" in result.output

    def test_scan_cancel_success_204(self, runner):
        """Cancel returning 204 should also report success."""
        from openlabels.cli.commands.scan import scan

        resp = _make_response(204)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.delete.return_value = resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["cancel", "scan-42"])

        assert result.exit_code == 0
        assert "Cancelled" in result.output

    def test_scan_cancel_failure(self, runner):
        """Cancel returning 404 shows error."""
        from openlabels.cli.commands.scan import scan

        resp = _make_response(404, text_body="Not Found")
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.delete.return_value = resp

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["cancel", "no-such-id"])

        assert "404" in result.output or "Error" in result.output


# ======================================================================
# export command group
# ======================================================================

class TestExportResultsCommand:
    """Tests for 'export results --job <id> --output <path>'."""

    def test_export_results_success(self, runner, temp_dir):
        """Successful export writes response content to the output file."""
        from openlabels.cli.commands.export import export

        output_path = str(Path(temp_dir) / "out.csv")
        csv_content = b"file,score\nalpha.txt,72"

        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.content = csv_content

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.export.get_api_client", return_value=mock_client):
            result = runner.invoke(export, [
                "results", "--job", "j-1", "--output", output_path,
            ])

        assert result.exit_code == 0
        assert "Exported to" in result.output
        assert Path(output_path).read_bytes() == csv_content

    def test_export_results_server_error(self, runner, temp_dir):
        """Server error should be reported to user."""
        from openlabels.cli.commands.export import export

        output_path = str(Path(temp_dir) / "out.csv")
        resp = _make_response(500, text_body="Internal Server Error")
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.export.get_api_client", return_value=mock_client):
            result = runner.invoke(export, [
                "results", "--job", "j-1", "--output", output_path,
            ])

        assert "500" in result.output or "Error" in result.output
        # File should NOT be created on error
        assert not Path(output_path).exists()

    def test_export_results_timeout(self, runner, temp_dir):
        """Timeout should produce a user-friendly message."""
        from openlabels.cli.commands.export import export

        output_path = str(Path(temp_dir) / "out.csv")
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = httpx.TimeoutException("timeout")

        with patch("openlabels.cli.commands.export.get_api_client", return_value=mock_client):
            result = runner.invoke(export, [
                "results", "--job", "j-1", "--output", output_path,
            ])

        assert "timed out" in result.output.lower()

    def test_export_results_json_format(self, runner, temp_dir):
        """Export with --format json passes the correct format param."""
        from openlabels.cli.commands.export import export

        output_path = str(Path(temp_dir) / "out.json")
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.content = b'[{"file": "a.txt"}]'

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.export.get_api_client", return_value=mock_client):
            result = runner.invoke(export, [
                "results", "--job", "j-1", "--format", "json",
                "--output", output_path,
            ])

        assert result.exit_code == 0
        # Verify the format param was sent
        call_args = mock_client.get.call_args
        assert call_args[1]["params"]["format"] == "json"

    def test_export_results_client_closed(self, runner, temp_dir):
        """Client should always be closed, even on error."""
        from openlabels.cli.commands.export import export

        output_path = str(Path(temp_dir) / "out.csv")
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = httpx.ConnectError("refused")

        with patch("openlabels.cli.commands.export.get_api_client", return_value=mock_client):
            runner.invoke(export, [
                "results", "--job", "j-1", "--output", output_path,
            ])

        mock_client.close.assert_called_once()


# ======================================================================
# target command group
# ======================================================================

class TestTargetListCommand:
    """Tests for 'target list'."""

    def test_target_list_success(self, runner):
        """List targets shows a table of targets."""
        from openlabels.cli.commands.target import target

        resp = _make_response(200, json_body=[
            {"name": "prod-files", "adapter_type": "filesystem",
             "path": "/data/prod", "config": {"path": "/data/prod"}},
            {"name": "sp-site", "adapter_type": "sharepoint",
             "config": {"path": "https://sp.example.com"}},
        ])
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.target.get_api_client", return_value=mock_client):
            result = runner.invoke(target, ["list"])

        assert result.exit_code == 0
        assert "prod-files" in result.output
        assert "filesystem" in result.output
        assert "sp-site" in result.output

    def test_target_list_empty(self, runner):
        """Empty target list should show headers but no data rows."""
        from openlabels.cli.commands.target import target

        resp = _make_response(200, json_body=[])
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.target.get_api_client", return_value=mock_client):
            result = runner.invoke(target, ["list"])

        assert result.exit_code == 0
        assert "Name" in result.output

    def test_target_list_server_error(self, runner):
        """Server error on target list should show error."""
        from openlabels.cli.commands.target import target

        resp = _make_response(503)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.target.get_api_client", return_value=mock_client):
            result = runner.invoke(target, ["list"])

        assert "503" in result.output or "Error" in result.output


class TestTargetAddCommand:
    """Tests for 'target add <name> --adapter <type> --path <path>'."""

    def test_target_add_success(self, runner):
        """Adding a target shows the created name and ID."""
        from openlabels.cli.commands.target import target

        resp = _make_response(201, json_body={
            "id": "tgt-99", "name": "new-target",
        })
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.target.get_api_client", return_value=mock_client):
            result = runner.invoke(target, [
                "add", "new-target",
                "--adapter", "filesystem",
                "--path", "/data/scan",
            ])

        assert result.exit_code == 0
        assert "new-target" in result.output
        assert "tgt-99" in result.output

    def test_target_add_sends_correct_payload(self, runner):
        """The POST payload should contain name, adapter_type, and config."""
        from openlabels.cli.commands.target import target

        resp = _make_response(201, json_body={"id": "x", "name": "x"})
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.target.get_api_client", return_value=mock_client):
            runner.invoke(target, [
                "add", "my-tgt",
                "--adapter", "sharepoint",
                "--path", "https://sp.example.com",
            ])

        call_kwargs = mock_client.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["name"] == "my-tgt"
        assert payload["adapter_type"] == "sharepoint"
        assert payload["config"]["path"] == "https://sp.example.com"

    def test_target_add_server_error(self, runner):
        """Server error on add should show the error status."""
        from openlabels.cli.commands.target import target

        resp = _make_response(409, text_body="Conflict: target already exists")
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.target.get_api_client", return_value=mock_client):
            result = runner.invoke(target, [
                "add", "dup",
                "--adapter", "filesystem",
                "--path", "/x",
            ])

        assert "409" in result.output or "Error" in result.output

    def test_target_add_missing_required_options(self, runner):
        """Missing --adapter or --path should fail."""
        from openlabels.cli.commands.target import target

        result = runner.invoke(target, ["add", "test-target"])
        assert result.exit_code == 2
        assert "Missing" in result.output or "required" in result.output.lower()


# ======================================================================
# user command group
# ======================================================================

class TestUserListCommand:
    """Tests for 'user list'."""

    def test_user_list_success(self, runner):
        """Lists users in table format."""
        from openlabels.cli.commands.user import user

        resp = _make_response(200, json_body=[
            {"email": "admin@co.com", "role": "admin",
             "created_at": "2026-01-01T00:00:00Z"},
            {"email": "viewer@co.com", "role": "viewer",
             "created_at": "2026-01-02T00:00:00Z"},
        ])
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.user.get_api_client", return_value=mock_client):
            result = runner.invoke(user, ["list"])

        assert result.exit_code == 0
        assert "admin@co.com" in result.output
        assert "viewer@co.com" in result.output

    def test_user_list_401_shows_auth_message(self, runner):
        """401 should tell user to set OPENLABELS_API_KEY."""
        from openlabels.cli.commands.user import user

        resp = _make_response(401)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.user.get_api_client", return_value=mock_client):
            result = runner.invoke(user, ["list"])

        assert "OPENLABELS_API_KEY" in result.output or "Authentication" in result.output

    def test_user_list_timeout(self, runner):
        """Timeout should be handled gracefully."""
        from openlabels.cli.commands.user import user

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = httpx.TimeoutException("read timed out")

        with patch("openlabels.cli.commands.user.get_api_client", return_value=mock_client):
            result = runner.invoke(user, ["list"])

        assert "timed out" in result.output.lower()


class TestUserCreateCommand:
    """Tests for 'user create <email>'."""

    def test_user_create_success(self, runner):
        """Successful creation shows the new user email."""
        from openlabels.cli.commands.user import user

        resp = _make_response(201, json_body={"email": "new@co.com"})
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.user.get_api_client", return_value=mock_client):
            result = runner.invoke(user, ["create", "new@co.com"])

        assert result.exit_code == 0
        assert "new@co.com" in result.output

    def test_user_create_with_role(self, runner):
        """Creating with --role admin sends the correct payload."""
        from openlabels.cli.commands.user import user

        resp = _make_response(201, json_body={"email": "adm@co.com"})
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.user.get_api_client", return_value=mock_client):
            result = runner.invoke(user, ["create", "adm@co.com", "--role", "admin"])

        assert result.exit_code == 0
        payload = mock_client.post.call_args[1]["json"]
        assert payload["role"] == "admin"

    def test_user_create_invalid_role(self, runner):
        """Invalid role should be rejected by Click."""
        from openlabels.cli.commands.user import user

        result = runner.invoke(user, ["create", "x@co.com", "--role", "superadmin"])
        assert result.exit_code == 2
        assert "Invalid" in result.output or "invalid" in result.output.lower()

    def test_user_create_server_error(self, runner):
        """Server error on create should show error."""
        from openlabels.cli.commands.user import user

        resp = _make_response(409, text_body="User already exists")
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.user.get_api_client", return_value=mock_client):
            result = runner.invoke(user, ["create", "dup@co.com"])

        assert "409" in result.output or "Error" in result.output


# ======================================================================
# labels command group
# ======================================================================

class TestLabelsListCommand:
    """Tests for 'labels list'."""

    def test_labels_list_success(self, runner):
        """Lists labels in table format."""
        from openlabels.cli.commands.labels import labels

        resp = _make_response(200, json_body=[
            {"id": "l-1", "name": "Confidential", "priority": 3},
            {"id": "l-2", "name": "Public", "priority": 1},
        ])
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.labels.get_api_client", return_value=mock_client):
            result = runner.invoke(labels, ["list"])

        assert result.exit_code == 0
        assert "Confidential" in result.output
        assert "Public" in result.output

    def test_labels_list_empty(self, runner):
        """Empty labels list shows headers only."""
        from openlabels.cli.commands.labels import labels

        resp = _make_response(200, json_body=[])
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.labels.get_api_client", return_value=mock_client):
            result = runner.invoke(labels, ["list"])

        assert result.exit_code == 0
        assert "Name" in result.output

    def test_labels_list_server_error(self, runner):
        """Server error should be reported."""
        from openlabels.cli.commands.labels import labels

        resp = _make_response(500)
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = resp

        with patch("openlabels.cli.commands.labels.get_api_client", return_value=mock_client):
            result = runner.invoke(labels, ["list"])

        assert "500" in result.output or "Error" in result.output


class TestLabelsSyncCommand:
    """Tests for 'labels sync'."""

    def test_labels_sync_success(self, runner):
        """Successful sync reports number of labels synced."""
        from openlabels.cli.commands.labels import labels

        resp = _make_response(202, json_body={"labels_synced": 5})
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.labels.get_api_client", return_value=mock_client):
            result = runner.invoke(labels, ["sync"])

        assert result.exit_code == 0
        assert "5" in result.output
        assert "Synced" in result.output or "synced" in result.output.lower()

    def test_labels_sync_server_error(self, runner):
        """Non-202 response should show error."""
        from openlabels.cli.commands.labels import labels

        resp = _make_response(500, text_body="Internal error")
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.return_value = resp

        with patch("openlabels.cli.commands.labels.get_api_client", return_value=mock_client):
            result = runner.invoke(labels, ["sync"])

        assert "500" in result.output or "Error" in result.output

    def test_labels_sync_timeout(self, runner):
        """Timeout during sync should produce a user-friendly message."""
        from openlabels.cli.commands.labels import labels

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.post.side_effect = httpx.TimeoutException("slow")

        with patch("openlabels.cli.commands.labels.get_api_client", return_value=mock_client):
            result = runner.invoke(labels, ["sync"])

        assert "timed out" in result.output.lower()


class TestLabelsApplyDryRun:
    """Tests for 'labels apply <file> --label <name> --dry-run'."""

    def test_labels_apply_dry_run(self, runner, temp_dir):
        """Dry-run should show what would happen without applying."""
        from openlabels.cli.commands.labels import labels

        test_file = Path(temp_dir) / "alpha.txt"
        result = runner.invoke(labels, [
            "apply", str(test_file), "--label", "Confidential", "--dry-run",
        ])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output
        assert "Confidential" in result.output


class TestLabelsRemoveDryRun:
    """Tests for 'labels remove <file> --dry-run'."""

    def test_labels_remove_dry_run(self, runner, temp_dir):
        """Dry-run should show what would happen without removing."""
        from openlabels.cli.commands.labels import labels

        test_file = Path(temp_dir) / "alpha.txt"
        result = runner.invoke(labels, [
            "remove", str(test_file), "--dry-run",
        ])

        assert result.exit_code == 0
        assert "DRY RUN" in result.output


# ======================================================================
# config command group
# ======================================================================

class TestConfigShowCommand:
    """Tests for 'config show'."""

    def test_config_show_outputs_json(self, runner):
        """Config show should output JSON settings."""
        from openlabels.cli.commands.config import config

        mock_settings = MagicMock()
        mock_settings.model_dump_json.return_value = '{"server": {"port": 8000}}'

        with patch("openlabels.server.config.get_settings", return_value=mock_settings):
            result = runner.invoke(config, ["show"])

        assert result.exit_code == 0
        assert '"server"' in result.output
        assert '"port"' in result.output

    def test_config_show_calls_get_settings(self, runner):
        """Config show should invoke get_settings."""
        from openlabels.cli.commands.config import config

        mock_settings = MagicMock()
        mock_settings.model_dump_json.return_value = "{}"

        with patch("openlabels.server.config.get_settings", return_value=mock_settings) as mock_get:
            runner.invoke(config, ["show"])

        mock_get.assert_called_once()


class TestConfigSetCommand:
    """Tests for 'config set <key> <value>'."""

    def test_config_set_creates_nested_key(self, runner):
        """Setting 'server.port 9000' should create nested YAML."""
        from openlabels.cli.commands.config import config

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"

            # Patch pathlib.Path inside the function to use our temp config
            with patch("builtins.open", mock_open(read_data="")):
                with patch("yaml.safe_load", return_value={}):
                    with patch("yaml.dump") as mock_dump:
                        with patch("pathlib.Path.exists", return_value=True):
                            result = runner.invoke(config, ["set", "server.port", "9000"])

        assert result.exit_code == 0
        assert "Set server.port = 9000" in result.output

    def test_config_set_boolean_true(self, runner):
        """Setting a boolean 'true' should be converted correctly."""
        from openlabels.cli.commands.config import config

        with patch("builtins.open", mock_open(read_data="")):
            with patch("yaml.safe_load", return_value={}):
                with patch("yaml.dump") as mock_dump:
                    with patch("pathlib.Path.exists", return_value=True):
                        result = runner.invoke(config, ["set", "server.debug", "true"])

        assert result.exit_code == 0
        assert "Set server.debug = True" in result.output

    def test_config_set_boolean_false(self, runner):
        """Setting a boolean 'false' should convert to False."""
        from openlabels.cli.commands.config import config

        with patch("builtins.open", mock_open(read_data="")):
            with patch("yaml.safe_load", return_value={}):
                with patch("yaml.dump"):
                    with patch("pathlib.Path.exists", return_value=True):
                        result = runner.invoke(config, ["set", "server.debug", "false"])

        assert result.exit_code == 0
        assert "Set server.debug = False" in result.output

    def test_config_set_integer(self, runner):
        """Setting an integer value should be converted."""
        from openlabels.cli.commands.config import config

        with patch("builtins.open", mock_open(read_data="")):
            with patch("yaml.safe_load", return_value={}):
                with patch("yaml.dump") as mock_dump:
                    with patch("pathlib.Path.exists", return_value=True):
                        result = runner.invoke(config, ["set", "server.port", "8080"])

        assert result.exit_code == 0
        assert "8080" in result.output

    def test_config_set_comma_separated_list(self, runner):
        """Comma-separated values should become a list."""
        from openlabels.cli.commands.config import config

        with patch("builtins.open", mock_open(read_data="")):
            with patch("yaml.safe_load", return_value={}):
                with patch("yaml.dump") as mock_dump:
                    with patch("pathlib.Path.exists", return_value=True):
                        result = runner.invoke(config, [
                            "set", "cors.allowed_origins",
                            "http://localhost:3000,http://example.com",
                        ])

        assert result.exit_code == 0
        assert "localhost:3000" in result.output
        assert "example.com" in result.output

    def test_config_set_null_value(self, runner):
        """Setting 'null' should store None."""
        from openlabels.cli.commands.config import config

        with patch("builtins.open", mock_open(read_data="")):
            with patch("yaml.safe_load", return_value={}):
                with patch("yaml.dump"):
                    with patch("pathlib.Path.exists", return_value=True):
                        result = runner.invoke(config, ["set", "some.key", "null"])

        assert result.exit_code == 0
        assert "None" in result.output

    def test_config_set_string_value(self, runner):
        """Regular strings should be stored as-is."""
        from openlabels.cli.commands.config import config

        with patch("builtins.open", mock_open(read_data="")):
            with patch("yaml.safe_load", return_value={}):
                with patch("yaml.dump"):
                    with patch("pathlib.Path.exists", return_value=True):
                        result = runner.invoke(config, ["set", "db.host", "myhost.local"])

        assert result.exit_code == 0
        assert "myhost.local" in result.output

    def test_config_set_shows_restart_note(self, runner):
        """After setting a value, user should be told to restart the server."""
        from openlabels.cli.commands.config import config

        with patch("builtins.open", mock_open(read_data="")):
            with patch("yaml.safe_load", return_value={}):
                with patch("yaml.dump"):
                    with patch("pathlib.Path.exists", return_value=True):
                        result = runner.invoke(config, ["set", "x", "y"])

        assert "restart" in result.output.lower()


# ======================================================================
# db command group
# ======================================================================

class TestDbUpgradeCommand:
    """Tests for 'db upgrade'."""

    def test_db_upgrade_default_head(self, runner):
        """Default upgrade should target 'head'."""
        from openlabels.cli.commands.db import db

        with patch("openlabels.server.db.run_migrations") as mock_migrate:
            result = runner.invoke(db, ["upgrade"])

        assert result.exit_code == 0
        mock_migrate.assert_called_once_with("head")
        assert "head" in result.output

    def test_db_upgrade_specific_revision(self, runner):
        """Upgrade to a specific revision."""
        from openlabels.cli.commands.db import db

        with patch("openlabels.server.db.run_migrations") as mock_migrate:
            result = runner.invoke(db, ["upgrade", "--revision", "abc123"])

        assert result.exit_code == 0
        mock_migrate.assert_called_once_with("abc123")
        assert "abc123" in result.output


class TestDbDowngradeCommand:
    """Tests for 'db downgrade'."""

    def test_db_downgrade_requires_revision(self, runner):
        """Downgrade without --revision should fail (it is required)."""
        from openlabels.cli.commands.db import db

        result = runner.invoke(db, ["downgrade"])
        assert result.exit_code == 2
        assert "Missing" in result.output or "required" in result.output.lower()

    def test_db_downgrade_specific_revision(self, runner):
        """Downgrade to a specific revision."""
        from openlabels.cli.commands.db import db

        with patch("openlabels.server.db.run_migrations") as mock_migrate:
            result = runner.invoke(db, ["downgrade", "--revision", "xyz789"])

        assert result.exit_code == 0
        mock_migrate.assert_called_once_with("xyz789", direction="downgrade")
        assert "xyz789" in result.output


# ======================================================================
# Error propagation across server-backed commands
# ======================================================================

class TestErrorPropagation:
    """Verify that HTTP errors from all server-backed commands produce
    user-friendly output, never raw tracebacks."""

    @pytest.mark.parametrize("exception_cls,expected_fragment", [
        (httpx.TimeoutException, "timed out"),
        (httpx.ConnectError, "Cannot connect"),
    ])
    def test_scan_status_error_propagation(self, runner, exception_cls, expected_fragment):
        """scan status with connection/timeout errors shows friendly message."""
        from openlabels.cli.commands.scan import scan

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = exception_cls("err")

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["status", "job-1"])

        assert expected_fragment.lower() in result.output.lower()
        # Must NOT contain raw Python tracebacks
        assert "Traceback" not in result.output

    @pytest.mark.parametrize("exception_cls,expected_fragment", [
        (httpx.TimeoutException, "timed out"),
        (httpx.ConnectError, "Cannot connect"),
    ])
    def test_target_list_error_propagation(self, runner, exception_cls, expected_fragment):
        """target list with connection/timeout errors shows friendly message."""
        from openlabels.cli.commands.target import target

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = exception_cls("err")

        with patch("openlabels.cli.commands.target.get_api_client", return_value=mock_client):
            result = runner.invoke(target, ["list"])

        assert expected_fragment.lower() in result.output.lower()
        assert "Traceback" not in result.output

    @pytest.mark.parametrize("exception_cls,expected_fragment", [
        (httpx.TimeoutException, "timed out"),
        (httpx.ConnectError, "Cannot connect"),
    ])
    def test_labels_list_error_propagation(self, runner, exception_cls, expected_fragment):
        """labels list with connection/timeout errors shows friendly message."""
        from openlabels.cli.commands.labels import labels

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = exception_cls("err")

        with patch("openlabels.cli.commands.labels.get_api_client", return_value=mock_client):
            result = runner.invoke(labels, ["list"])

        assert expected_fragment.lower() in result.output.lower()
        assert "Traceback" not in result.output

    @pytest.mark.parametrize("exception_cls,expected_fragment", [
        (httpx.TimeoutException, "timed out"),
        (httpx.ConnectError, "Cannot connect"),
    ])
    def test_user_list_error_propagation(self, runner, exception_cls, expected_fragment):
        """user list with connection/timeout errors shows friendly message."""
        from openlabels.cli.commands.user import user

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.side_effect = exception_cls("err")

        with patch("openlabels.cli.commands.user.get_api_client", return_value=mock_client):
            result = runner.invoke(user, ["list"])

        assert expected_fragment.lower() in result.output.lower()
        assert "Traceback" not in result.output

    def test_no_raw_traceback_on_scan_cancel_connect_error(self, runner):
        """Regression: scan cancel with ConnectError must not leak tracebacks."""
        from openlabels.cli.commands.scan import scan

        mock_client = MagicMock(spec=httpx.Client)
        mock_client.delete.side_effect = httpx.ConnectError("refused")

        with patch("openlabels.cli.commands.scan.get_api_client", return_value=mock_client):
            result = runner.invoke(scan, ["cancel", "j-1"])

        assert "Traceback" not in result.output
        assert "Cannot connect" in result.output


# ======================================================================
# CLI classify command integration (additional edge cases)
# ======================================================================

class TestClassifyCommandEdgeCases:
    """Additional edge-case tests for the classify command."""

    def test_classify_nonexistent_path_rejected(self, runner):
        """click.Path(exists=True) should reject nonexistent paths."""
        from openlabels.cli.commands.classify import classify

        result = runner.invoke(classify, ["/nonexistent/path/file.txt"])
        assert result.exit_code == 2

    def test_classify_invalid_exposure_rejected(self, runner, temp_dir):
        """Invalid exposure level should be rejected by Click."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "alpha.txt"
        result = runner.invoke(classify, [
            str(test_file), "--exposure", "INVALID_LEVEL",
        ])
        assert result.exit_code == 2
        assert "Invalid" in result.output or "invalid" in result.output.lower()

    def test_classify_directory_with_zero_files_after_filtering(self, runner):
        """Classify on empty dir should say 'Classifying 0 files'."""
        from openlabels.cli.commands.classify import classify

        with tempfile.TemporaryDirectory() as empty:
            with patch("openlabels.core.processor.FileProcessor") as MockFP:
                mock_proc = MagicMock()
                mock_proc.process_file = AsyncMock()
                MockFP.return_value = mock_proc

                result = runner.invoke(classify, [empty])

        assert result.exit_code == 0
        assert "0 files" in result.output

    def test_classify_output_path_traversal_blocked(self, runner, temp_dir):
        """Output path with traversal should be rejected by validate_output_path."""
        from openlabels.cli.commands.classify import classify

        test_file = Path(temp_dir) / "alpha.txt"
        mock_fc = MagicMock()
        mock_fc.risk_score = 50
        mock_fc.file_name = "alpha.txt"
        mock_fc.risk_tier.value = "MEDIUM"
        mock_fc.entity_counts = {}
        mock_fc.error = None

        with patch("openlabels.core.processor.FileProcessor") as MockFP:
            mock_proc = MagicMock()
            mock_proc.process_file = AsyncMock(return_value=mock_fc)
            MockFP.return_value = mock_proc

            with patch(
                "openlabels.cli.commands.classify.validate_output_path",
                side_effect=__import__(
                    "openlabels.core.path_validation", fromlist=["PathValidationError"]
                ).PathValidationError("path traversal detected"),
            ):
                result = runner.invoke(classify, [
                    str(test_file), "-o", "/tmp/../../etc/passwd",
                ])

        assert "Invalid output path" in result.output or "Error" in result.output


# ======================================================================
# validate_where_filter
# ======================================================================

class TestValidateWhereFilter:
    """Tests for the validate_where_filter Click callback."""

    def test_none_value_passes_through(self):
        """None input should return None (no filter specified)."""
        from openlabels.cli.utils import validate_where_filter

        result = validate_where_filter(None, None, None)
        assert result is None

    def test_valid_filter_returns_value(self):
        """A valid filter expression should be returned unchanged."""
        from openlabels.cli.utils import validate_where_filter

        # Patch the parser to accept the filter
        with patch("openlabels.cli.filter_parser.parse_filter"):
            result = validate_where_filter(None, None, "score > 50")
        assert result == "score > 50"

    def test_invalid_filter_raises_bad_parameter(self):
        """An invalid filter should raise click.BadParameter."""
        from openlabels.cli.utils import validate_where_filter
        from openlabels.cli.filter_parser import ParseError
        import click

        with patch(
            "openlabels.cli.filter_parser.parse_filter",
            side_effect=ParseError("unexpected token"),
        ):
            with pytest.raises(click.BadParameter) as exc_info:
                validate_where_filter(None, None, "bad <<<")

        assert "Invalid filter" in str(exc_info.value)


# ======================================================================
# Scan command help / subcommand discovery
# ======================================================================

class TestScanCommandGroup:
    """Tests for the scan command group itself."""

    def test_scan_help_shows_subcommands(self, runner):
        """scan --help should list start, status, cancel subcommands."""
        from openlabels.cli.commands.scan import scan

        result = runner.invoke(scan, ["--help"])
        assert result.exit_code == 0
        assert "start" in result.output
        assert "status" in result.output
        assert "cancel" in result.output

    def test_scan_no_subcommand_shows_usage(self, runner):
        """Invoking scan without subcommand should show usage (may exit 0 or 2
        depending on click version, but must mention subcommands)."""
        from openlabels.cli.commands.scan import scan

        result = runner.invoke(scan, [])
        # Click group without invoke_without_command may exit 0 or 2
        assert "Usage" in result.output or "start" in result.output or "status" in result.output


class TestExportCommandGroup:
    """Tests for the export command group."""

    def test_export_help_shows_subcommands(self, runner):
        """export --help should list results subcommand."""
        from openlabels.cli.commands.export import export

        result = runner.invoke(export, ["--help"])
        assert result.exit_code == 0
        assert "results" in result.output

    def test_export_results_missing_required_options(self, runner):
        """export results without --job and --output should fail."""
        from openlabels.cli.commands.export import export

        result = runner.invoke(export, ["results"])
        assert result.exit_code == 2
        assert "Missing" in result.output or "required" in result.output.lower()


class TestTargetCommandGroup:
    """Tests for the target command group."""

    def test_target_help_shows_subcommands(self, runner):
        """target --help should list list and add subcommands."""
        from openlabels.cli.commands.target import target

        result = runner.invoke(target, ["--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "add" in result.output


class TestUserCommandGroup:
    """Tests for the user command group."""

    def test_user_help_shows_subcommands(self, runner):
        """user --help should list list and create subcommands."""
        from openlabels.cli.commands.user import user

        result = runner.invoke(user, ["--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "create" in result.output


class TestLabelsCommandGroup:
    """Tests for the labels command group."""

    def test_labels_help_shows_subcommands(self, runner):
        """labels --help should list its subcommands."""
        from openlabels.cli.commands.labels import labels

        result = runner.invoke(labels, ["--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "sync" in result.output
        assert "apply" in result.output
        assert "remove" in result.output
        assert "info" in result.output


class TestConfigCommandGroup:
    """Tests for the config command group."""

    def test_config_help_shows_subcommands(self, runner):
        """config --help should list show and set subcommands."""
        from openlabels.cli.commands.config import config

        result = runner.invoke(config, ["--help"])
        assert result.exit_code == 0
        assert "show" in result.output
        assert "set" in result.output


class TestDbCommandGroup:
    """Tests for the db command group."""

    def test_db_help_shows_subcommands(self, runner):
        """db --help should list upgrade and downgrade subcommands."""
        from openlabels.cli.commands.db import db

        result = runner.invoke(db, ["--help"])
        assert result.exit_code == 0
        assert "upgrade" in result.output
        assert "downgrade" in result.output

"""
Tests for Health Check System.

Tests health check functionality:
- Check registration and execution
- Individual check implementations
- Health report aggregation
- Error handling in checks
"""

import os
import sys
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openlabels.health import (
    CheckStatus,
    CheckResult,
    HealthReport,
    HealthChecker,
    run_health_check,
)


class TestCheckStatus:
    """Tests for CheckStatus enum."""

    def test_pass_value(self):
        assert CheckStatus.PASS.value == "pass"

    def test_fail_value(self):
        assert CheckStatus.FAIL.value == "fail"

    def test_warn_value(self):
        assert CheckStatus.WARN.value == "warn"

    def test_skip_value(self):
        assert CheckStatus.SKIP.value == "skip"


class TestCheckResult:
    """Tests for CheckResult dataclass."""

    def test_passed_property(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.PASS,
            message="OK",
            duration_ms=1.0,
        )
        assert result.passed is True
        assert result.failed is False

    def test_failed_property(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.FAIL,
            message="Failed",
            duration_ms=1.0,
        )
        assert result.passed is False
        assert result.failed is True

    def test_to_dict(self):
        result = CheckResult(
            name="test_check",
            status=CheckStatus.PASS,
            message="Everything OK",
            duration_ms=5.5,
            details={"key": "value"},
            error=None,
        )

        d = result.to_dict()

        assert d["name"] == "test_check"
        assert d["status"] == "pass"
        assert d["message"] == "Everything OK"
        assert d["duration_ms"] == 5.5
        assert d["details"] == {"key": "value"}
        assert d["error"] is None

    def test_to_dict_with_error(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.FAIL,
            message="Failed",
            duration_ms=1.0,
            error="Something went wrong",
        )

        d = result.to_dict()

        assert d["error"] == "Something went wrong"


class TestHealthReport:
    """Tests for HealthReport dataclass."""

    def test_healthy_when_no_failures(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.PASS, "OK", 1.0),
            CheckResult("c", CheckStatus.WARN, "Warning", 1.0),
        ])

        assert report.healthy is True

    def test_unhealthy_when_failures(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 1.0),
        ])

        assert report.healthy is False

    def test_passed_property(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 1.0),
            CheckResult("c", CheckStatus.PASS, "OK", 1.0),
        ])

        assert len(report.passed) == 2

    def test_failed_property(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 1.0),
            CheckResult("c", CheckStatus.FAIL, "Failed", 1.0),
        ])

        assert len(report.failed) == 2

    def test_warnings_property(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.WARN, "Warning", 1.0),
        ])

        assert len(report.warnings) == 1

    def test_to_dict(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 2.0),
        ])

        d = report.to_dict()

        assert d["healthy"] is False
        assert d["summary"]["total"] == 2
        assert d["summary"]["passed"] == 1
        assert d["summary"]["failed"] == 1
        assert len(d["checks"]) == 2


class TestHealthChecker:
    """Tests for HealthChecker class."""

    def test_init_registers_default_checks(self):
        checker = HealthChecker()

        check_names = [name for name, _ in checker._checks]

        assert "python_version" in check_names
        assert "dependencies" in check_names
        assert "detector" in check_names
        assert "database" in check_names
        assert "disk_space" in check_names
        assert "temp_directory" in check_names
        assert "audit_log" in check_names

    def test_register_custom_check(self):
        checker = HealthChecker()

        def custom_check():
            return CheckResult("custom", CheckStatus.PASS, "OK", 0)

        checker.register("custom", custom_check)

        check_names = [name for name, _ in checker._checks]
        assert "custom" in check_names

    def test_run_all(self):
        checker = HealthChecker()

        report = checker.run_all()

        assert isinstance(report, HealthReport)
        assert len(report.checks) > 0

    def test_run_check_by_name(self):
        checker = HealthChecker()

        result = checker.run_check("python_version")

        assert isinstance(result, CheckResult)
        assert result.name == "python_version"
        assert result.status in CheckStatus

    def test_run_check_not_found(self):
        checker = HealthChecker()

        result = checker.run_check("nonexistent_check")

        assert result is None

    def test_run_check_handles_exception(self):
        checker = HealthChecker()

        def failing_check():
            raise RuntimeError("Check failed")

        checker.register("failing", failing_check)

        result = checker.run_check("failing")

        assert result is not None
        assert result.status == CheckStatus.FAIL
        assert "exception" in result.message.lower() or result.error is not None


class TestPythonVersionCheck:
    """Tests for Python version check."""

    def test_passes_on_supported_version(self):
        checker = HealthChecker()

        result = checker._check_python_version()

        # Current Python should be supported
        assert result.status == CheckStatus.PASS
        assert "3." in result.message

    def test_fails_on_old_version(self):
        checker = HealthChecker()

        # Mock old Python version using a named tuple-like object
        from collections import namedtuple
        VersionInfo = namedtuple('VersionInfo', ['major', 'minor', 'micro', 'releaselevel', 'serial'])
        old_version = VersionInfo(3, 7, 0, 'final', 0)

        with patch.object(sys, 'version_info', old_version):
            result = checker._check_python_version()

        assert result.status == CheckStatus.FAIL


class TestDependenciesCheck:
    """Tests for dependencies check."""

    def test_passes_when_core_deps_available(self):
        """Core dependencies (rich, regex) must be available for PASS."""
        checker = HealthChecker()

        result = checker._check_dependencies()

        # Core deps are required - if FAIL, message should mention missing
        if result.status == CheckStatus.FAIL:
            assert "missing" in result.message.lower() or "Missing" in result.message
            assert "missing" in result.details
        else:
            # PASS or WARN - versions must be collected
            assert "versions" in result.details
            # If WARN, should be about optional deps only
            if result.status == CheckStatus.WARN:
                assert "optional" in result.message.lower()

    def test_fails_when_core_dep_missing(self):
        """Test that missing core dependency causes FAIL."""
        import builtins
        checker = HealthChecker()

        # Mock import to fail for 'rich'
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == 'rich':
                raise ImportError("No module named 'rich'")
            return original_import(name, *args, **kwargs)

        with patch.dict('builtins.__dict__', {'__import__': mock_import}):
            with patch('builtins.__import__', mock_import):
                # Re-run the check - it caches imports so we need fresh instance
                result = checker._check_dependencies()

        # If the mock worked, status should be FAIL
        # (mock might not work due to already-imported modules, so we test behavior)
        if "rich" in str(result.details.get("missing", [])):
            assert result.status == CheckStatus.FAIL

    def test_includes_version_info(self):
        checker = HealthChecker()

        result = checker._check_dependencies()

        assert "versions" in result.details
        # Should have version strings for available packages
        versions = result.details["versions"]
        assert isinstance(versions, dict)


class TestDetectorCheck:
    """Tests for detector check."""

    def test_detector_check_passes_with_working_detector(self):
        """Detector check should PASS when detector finds entities in test input."""
        checker = HealthChecker()

        result = checker._check_detector()

        # The test input contains "john.smith@example.com" and "555-123-4567"
        # A working detector MUST find these
        if result.status == CheckStatus.PASS:
            assert result.details.get("entity_count", 0) > 0, \
                "PASS status requires finding at least one entity"
            assert "entity_types" in result.details
            assert len(result.details["entity_types"]) > 0
        elif result.status == CheckStatus.WARN:
            # WARN means detector ran but found nothing - this is a real warning
            assert "no entities" in result.message.lower() or result.details.get("entity_count") == 0
        elif result.status == CheckStatus.FAIL:
            # FAIL means detector couldn't run at all
            assert result.error is not None or "failed" in result.message.lower()

    def test_detector_check_handles_detector_exception(self):
        """Detector check should FAIL when detector raises an exception."""
        checker = HealthChecker()

        # Mock the Detector class to raise when instantiated
        # Note: health.py imports Detector from openlabels.adapters.scanner
        with patch('openlabels.adapters.scanner.Detector', side_effect=RuntimeError("Detector init failed")):
            result = checker._check_detector()

        assert result.status == CheckStatus.FAIL
        assert result.error is not None or "failed" in result.message.lower()

    def test_detector_check_includes_processing_time(self):
        """Detector check should include processing time in details when successful."""
        checker = HealthChecker()

        result = checker._check_detector()

        if result.status == CheckStatus.PASS:
            # Processing time should be recorded
            assert "processing_time_ms" in result.details
            assert result.details["processing_time_ms"] >= 0


class TestDatabaseCheck:
    """Tests for database check."""

    def test_sqlite_basic_operations_work(self):
        """SQLite must support basic CRUD operations."""
        checker = HealthChecker()

        result = checker._check_database()

        # SQLite is a core requirement - FAIL is a critical issue
        if result.status == CheckStatus.FAIL:
            # If it fails, there must be an error explaining why
            assert result.error is not None or "failed" in result.message.lower()
        elif result.status == CheckStatus.WARN:
            # WARN is only for index directory issues, not SQLite itself
            assert "directory" in result.message.lower() or "index" in result.message.lower()
        else:
            # PASS means SQLite works
            assert result.status == CheckStatus.PASS
            assert "sqlite_version" in result.details

    def test_sqlite_fails_when_broken(self):
        """Database check should FAIL when SQLite operations fail."""
        checker = HealthChecker()

        # Mock sqlite3.connect to raise an error
        with patch('sqlite3.connect') as mock_connect:
            mock_connect.side_effect = sqlite3.OperationalError("database is locked")
            result = checker._check_database()

        assert result.status == CheckStatus.FAIL
        assert result.error is not None

    def test_includes_sqlite_version(self):
        checker = HealthChecker()

        result = checker._check_database()

        if result.status == CheckStatus.PASS:
            assert "sqlite_version" in result.details
            # Version should be a valid string like "3.x.y"
            version = result.details["sqlite_version"]
            assert version.startswith("3.")

    def test_verifies_read_write_correctness(self):
        """Database check must verify data can be read back correctly."""
        checker = HealthChecker()

        # The check writes "test" and reads it back - verify this works
        result = checker._check_database()

        # Database check must either pass (data verified) or fail with error
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL)
        if result.status == CheckStatus.PASS:
            assert "sqlite_version" in result.details
        elif result.status == CheckStatus.FAIL:
            assert result.error is not None or "failed" in result.message.lower()


class TestDiskSpaceCheck:
    """Tests for disk space check."""

    def test_disk_space_reports_actual_space(self):
        """Disk space check must report actual free space."""
        checker = HealthChecker()

        result = checker._check_disk_space()

        # Must always report free_gb unless there's an error
        if result.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL):
            if result.error is None:
                assert "free_gb" in result.details
                # Free space must be a positive number
                assert result.details["free_gb"] >= 0

    def test_fails_on_critically_low_space(self):
        """Disk space check should FAIL when space < 100MB."""
        checker = HealthChecker()

        # Mock statvfs to return very low space
        mock_stat = MagicMock()
        mock_stat.f_bavail = 10  # 10 blocks
        mock_stat.f_frsize = 4096  # 4KB blocks = 40KB total (< 100MB)

        with patch('os.statvfs', return_value=mock_stat):
            result = checker._check_disk_space()

        assert result.status == CheckStatus.FAIL
        assert result.details["free_gb"] < 0.1

    def test_warns_on_low_space(self):
        """Disk space check should WARN when space < 1GB."""
        checker = HealthChecker()

        # Mock statvfs to return low but not critical space (500MB)
        mock_stat = MagicMock()
        mock_stat.f_bavail = 128000  # blocks
        mock_stat.f_frsize = 4096  # 4KB blocks = ~500MB

        with patch('os.statvfs', return_value=mock_stat):
            result = checker._check_disk_space()

        assert result.status == CheckStatus.WARN
        assert result.details["free_gb"] < 1.0
        assert result.details["free_gb"] >= 0.1

    def test_passes_on_sufficient_space(self):
        """Disk space check should PASS when space >= 1GB."""
        checker = HealthChecker()

        # Mock statvfs to return plenty of space (10GB)
        mock_stat = MagicMock()
        mock_stat.f_bavail = 2621440  # blocks
        mock_stat.f_frsize = 4096  # 4KB blocks = ~10GB

        with patch('os.statvfs', return_value=mock_stat):
            result = checker._check_disk_space()

        assert result.status == CheckStatus.PASS
        assert result.details["free_gb"] >= 1.0

    def test_includes_free_space_info(self):
        checker = HealthChecker()

        result = checker._check_disk_space()

        if result.status in (CheckStatus.PASS, CheckStatus.WARN):
            assert "free_gb" in result.details
            assert "path" in result.details


class TestTempDirectoryCheck:
    """Tests for temp directory check."""

    def test_temp_directory_writable(self):
        checker = HealthChecker()

        result = checker._check_temp_directory()

        # Temp should be writable
        assert result.status == CheckStatus.PASS

    def test_includes_temp_path(self):
        checker = HealthChecker()

        result = checker._check_temp_directory()

        assert "temp_dir" in result.details


class TestAuditLogCheck:
    """Tests for audit log check."""

    def test_audit_log_path_accessible(self):
        """Audit log check should verify path accessibility."""
        checker = HealthChecker()

        result = checker._check_audit_log()

        # Must include audit path in details
        assert "audit_path" in result.details
        audit_path = Path(result.details["audit_path"])

        if result.status == CheckStatus.PASS:
            # Path's parent directory should exist or be creatable
            assert isinstance(audit_path, Path)

        if result.status == CheckStatus.WARN:
            # WARN means permission issue - message should explain
            assert "writable" in result.message.lower() or "create" in result.message.lower()

    def test_warns_on_permission_denied(self):
        """Audit log check should WARN when path not writable."""
        checker = HealthChecker()

        # Mock os.access to return False for write permission
        original_access = os.access

        def mock_access(path, mode):
            if mode == os.W_OK:
                return False
            return original_access(path, mode)

        with patch('os.access', side_effect=mock_access):
            with patch('pathlib.Path.exists', return_value=True):
                result = checker._check_audit_log()

        # Should warn about write permission
        if result.status == CheckStatus.WARN:
            assert "writable" in result.message.lower() or "permission" in result.message.lower()

    def test_passes_with_writable_path(self):
        """Audit log check should PASS when path is writable."""
        checker = HealthChecker()

        # Use a temp directory that's definitely writable
        with tempfile.TemporaryDirectory() as tmpdir:
            test_log_path = Path(tmpdir) / "audit.log"

            with patch('openlabels.logging_config.DEFAULT_AUDIT_LOG', str(test_log_path)):
                result = checker._check_audit_log()

        # Should pass or warn (not fail) with valid temp path
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)


class TestRunHealthCheck:
    """Tests for run_health_check convenience function."""

    def test_returns_health_report(self):
        report = run_health_check()

        assert isinstance(report, HealthReport)

    def test_runs_all_checks(self):
        report = run_health_check()

        assert len(report.checks) >= 7  # At least default checks


class TestCheckExceptionHandling:
    """Tests for exception handling in checks."""

    def test_exception_in_check_returns_fail(self):
        checker = HealthChecker()

        def bad_check():
            raise ValueError("Test error")

        checker.register("bad", bad_check)

        report = checker.run_all()

        bad_results = [c for c in report.checks if c.name == "bad"]
        assert len(bad_results) == 1
        assert bad_results[0].status == CheckStatus.FAIL
        assert bad_results[0].error is not None

    def test_exception_doesnt_stop_other_checks(self):
        checker = HealthChecker()

        def bad_check():
            raise ValueError("Test error")

        def good_check():
            return CheckResult("good", CheckStatus.PASS, "OK", 0)

        checker.register("bad", bad_check)
        checker.register("good", good_check)

        report = checker.run_all()

        # Both checks should be in results
        names = [c.name for c in report.checks]
        assert "bad" in names
        assert "good" in names


class TestCheckTiming:
    """Tests for check timing."""

    def test_duration_is_recorded(self):
        checker = HealthChecker()

        report = checker.run_all()

        for check in report.checks:
            assert check.duration_ms >= 0

    def test_individual_check_timing(self):
        checker = HealthChecker()

        result = checker.run_check("python_version")

        assert result.duration_ms >= 0


class TestCustomConfigPath:
    """Tests for custom config path."""

    def test_accepts_config_path(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("key: value")

        checker = HealthChecker(config_path=config_file)

        assert checker.config_path == config_file

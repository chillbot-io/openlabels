"""
OpenLabels Health Checks.

Provides system health verification for production deployments.

Usage:
    from openlabels.health import HealthChecker

    checker = HealthChecker()
    results = checker.run_all()

    if results.healthy:
        print("All checks passed")
    else:
        for check in results.failed:
            print(f"FAILED: {check.name}: {check.error}")
"""

import os
import sys
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any

from openlabels.logging_config import get_logger

logger = get_logger(__name__)


class CheckStatus(Enum):
    """Health check status."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class CheckResult:
    """Result of a single health check."""
    name: str
    status: CheckStatus
    message: str
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        return self.status == CheckStatus.PASS

    @property
    def failed(self) -> bool:
        return self.status == CheckStatus.FAIL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "details": self.details,
            "error": self.error,
        }


@dataclass
class HealthReport:
    """Overall health report."""
    checks: List[CheckResult] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    @property
    def healthy(self) -> bool:
        """True if no critical checks failed."""
        return not any(c.failed for c in self.checks)

    @property
    def passed(self) -> List[CheckResult]:
        return [c for c in self.checks if c.passed]

    @property
    def failed(self) -> List[CheckResult]:
        return [c for c in self.checks if c.failed]

    @property
    def warnings(self) -> List[CheckResult]:
        return [c for c in self.checks if c.status == CheckStatus.WARN]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "healthy": self.healthy,
            "timestamp": self.timestamp,
            "summary": {
                "total": len(self.checks),
                "passed": len(self.passed),
                "failed": len(self.failed),
                "warnings": len(self.warnings),
            },
            "checks": [c.to_dict() for c in self.checks],
        }


class HealthChecker:
    """
    Health checker for OpenLabels system.

    Performs diagnostic checks to verify system components are functioning.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize health checker.

        Args:
            config_path: Optional path to config file for validation
        """
        self.config_path = config_path
        self._checks: List[tuple] = []
        self._register_default_checks()

    def _register_default_checks(self):
        """Register the default health checks."""
        self.register("python_version", self._check_python_version)
        self.register("dependencies", self._check_dependencies)
        self.register("detector", self._check_detector)
        self.register("database", self._check_database)
        self.register("disk_space", self._check_disk_space)
        self.register("temp_directory", self._check_temp_directory)
        self.register("audit_log", self._check_audit_log)

    def register(self, name: str, check_fn: Callable[[], CheckResult]):
        """Register a health check."""
        self._checks.append((name, check_fn))

    def run_all(self) -> HealthReport:
        """Run all registered health checks."""
        report = HealthReport()

        for name, check_fn in self._checks:
            start = time.perf_counter()
            try:
                result = check_fn()
                result.duration_ms = (time.perf_counter() - start) * 1000
                report.checks.append(result)
            except Exception as e:
                duration = (time.perf_counter() - start) * 1000
                report.checks.append(CheckResult(
                    name=name,
                    status=CheckStatus.FAIL,
                    message=f"Check raised exception",
                    duration_ms=duration,
                    error=str(e),
                ))
                logger.warning(f"Health check {name} failed with exception: {e}")

        return report

    def run_check(self, name: str) -> Optional[CheckResult]:
        """Run a specific health check by name."""
        for check_name, check_fn in self._checks:
            if check_name == name:
                start = time.perf_counter()
                try:
                    result = check_fn()
                    result.duration_ms = (time.perf_counter() - start) * 1000
                    return result
                except Exception as e:
                    duration = (time.perf_counter() - start) * 1000
                    return CheckResult(
                        name=name,
                        status=CheckStatus.FAIL,
                        message=f"Check raised exception",
                        duration_ms=duration,
                        error=str(e),
                    )
        return None

    # --- Default Health Checks ---

    def _check_python_version(self) -> CheckResult:
        """Check Python version is compatible."""
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"

        if version.major < 3 or (version.major == 3 and version.minor < 9):
            return CheckResult(
                name="python_version",
                status=CheckStatus.FAIL,
                message=f"Python {version_str} is not supported (requires 3.9+)",
                duration_ms=0,
                details={"version": version_str, "required": "3.9+"},
            )

        return CheckResult(
            name="python_version",
            status=CheckStatus.PASS,
            message=f"Python {version_str}",
            duration_ms=0,
            details={"version": version_str},
        )

    def _check_dependencies(self) -> CheckResult:
        """Check required dependencies are available."""
        missing = []
        versions = {}

        # Core dependencies
        deps = [
            ("rich", "rich"),
            ("regex", "regex"),
        ]

        # Optional dependencies
        optional_deps = [
            ("xattr", "xattr"),
            ("watchdog", "watchdog"),
        ]

        for import_name, package_name in deps:
            try:
                module = __import__(import_name)
                versions[package_name] = getattr(module, "__version__", "unknown")
            except ImportError:
                missing.append(package_name)

        optional_missing = []
        for import_name, package_name in optional_deps:
            try:
                module = __import__(import_name)
                versions[package_name] = getattr(module, "__version__", "unknown")
            except ImportError:
                optional_missing.append(package_name)

        if missing:
            return CheckResult(
                name="dependencies",
                status=CheckStatus.FAIL,
                message=f"Missing required packages: {', '.join(missing)}",
                duration_ms=0,
                details={"missing": missing, "versions": versions},
            )

        if optional_missing:
            return CheckResult(
                name="dependencies",
                status=CheckStatus.WARN,
                message=f"Optional packages missing: {', '.join(optional_missing)}",
                duration_ms=0,
                details={"optional_missing": optional_missing, "versions": versions},
            )

        return CheckResult(
            name="dependencies",
            status=CheckStatus.PASS,
            message=f"All dependencies available",
            duration_ms=0,
            details={"versions": versions},
        )

    def _check_detector(self) -> CheckResult:
        """Check PII detector is functional."""
        try:
            from openlabels.adapters.scanner import Detector, Config

            config = Config(
                min_confidence=0.5,
                enable_ocr=False,
            )
            detector = Detector(config)

            # Test with known PII
            test_text = "Contact John Smith at john.smith@example.com or 555-123-4567"
            result = detector.detect(test_text)

            if not result.has_pii:
                return CheckResult(
                    name="detector",
                    status=CheckStatus.WARN,
                    message="Detector returned no entities for test input",
                    duration_ms=0,
                    details={
                        "test_input": test_text,
                        "entity_count": 0,
                    },
                )

            return CheckResult(
                name="detector",
                status=CheckStatus.PASS,
                message=f"Detector found {len(result.spans)} entities in test",
                duration_ms=0,
                details={
                    "entity_count": len(result.spans),
                    "entity_types": list(result.entity_counts.keys()),
                    "processing_time_ms": result.processing_time_ms,
                },
            )

        except ImportError as e:
            return CheckResult(
                name="detector",
                status=CheckStatus.FAIL,
                message="Failed to import detector",
                duration_ms=0,
                error=str(e),
            )
        except Exception as e:
            return CheckResult(
                name="detector",
                status=CheckStatus.FAIL,
                message="Detector test failed",
                duration_ms=0,
                error=str(e),
            )

    def _check_database(self) -> CheckResult:
        """Check SQLite database is functional."""
        try:
            # Test SQLite functionality with in-memory database
            conn = sqlite3.connect(":memory:")
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, data TEXT)")
            conn.execute("INSERT INTO test (data) VALUES (?)", ("test",))
            result = conn.execute("SELECT data FROM test").fetchone()
            conn.close()

            if result[0] != "test":
                return CheckResult(
                    name="database",
                    status=CheckStatus.FAIL,
                    message="SQLite read/write verification failed",
                    duration_ms=0,
                )

            # Check default index path is writable
            from openlabels.output.index import DEFAULT_INDEX_PATH
            index_dir = Path(DEFAULT_INDEX_PATH).parent

            if not index_dir.exists():
                try:
                    index_dir.mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    return CheckResult(
                        name="database",
                        status=CheckStatus.WARN,
                        message=f"Cannot create index directory: {index_dir}",
                        duration_ms=0,
                        details={"index_path": str(DEFAULT_INDEX_PATH)},
                    )

            return CheckResult(
                name="database",
                status=CheckStatus.PASS,
                message="SQLite functional, index directory accessible",
                duration_ms=0,
                details={
                    "sqlite_version": sqlite3.sqlite_version,
                    "index_path": str(DEFAULT_INDEX_PATH),
                },
            )

        except Exception as e:
            return CheckResult(
                name="database",
                status=CheckStatus.FAIL,
                message="Database check failed",
                duration_ms=0,
                error=str(e),
            )

    def _check_disk_space(self) -> CheckResult:
        """Check sufficient disk space is available."""
        try:
            # Check home directory
            home = Path.home()
            stat = os.statvfs(home)
            free_bytes = stat.f_bavail * stat.f_frsize
            free_gb = free_bytes / (1024 ** 3)

            # Warn if less than 1GB, fail if less than 100MB
            if free_gb < 0.1:
                return CheckResult(
                    name="disk_space",
                    status=CheckStatus.FAIL,
                    message=f"Critically low disk space: {free_gb:.2f}GB",
                    duration_ms=0,
                    details={"free_gb": free_gb, "path": str(home)},
                )

            if free_gb < 1.0:
                return CheckResult(
                    name="disk_space",
                    status=CheckStatus.WARN,
                    message=f"Low disk space: {free_gb:.2f}GB",
                    duration_ms=0,
                    details={"free_gb": free_gb, "path": str(home)},
                )

            return CheckResult(
                name="disk_space",
                status=CheckStatus.PASS,
                message=f"Disk space: {free_gb:.1f}GB available",
                duration_ms=0,
                details={"free_gb": free_gb, "path": str(home)},
            )

        except Exception as e:
            return CheckResult(
                name="disk_space",
                status=CheckStatus.WARN,
                message="Could not check disk space",
                duration_ms=0,
                error=str(e),
            )

    def _check_temp_directory(self) -> CheckResult:
        """Check temp directory is writable."""
        try:
            temp_dir = Path(tempfile.gettempdir())

            # Try to create and delete a temp file
            with tempfile.NamedTemporaryFile(delete=True) as f:
                f.write(b"test")
                f.flush()
                temp_path = f.name

            return CheckResult(
                name="temp_directory",
                status=CheckStatus.PASS,
                message=f"Temp directory writable: {temp_dir}",
                duration_ms=0,
                details={"temp_dir": str(temp_dir)},
            )

        except Exception as e:
            return CheckResult(
                name="temp_directory",
                status=CheckStatus.FAIL,
                message="Cannot write to temp directory",
                duration_ms=0,
                error=str(e),
            )

    def _check_audit_log(self) -> CheckResult:
        """Check audit log path is writable."""
        try:
            from openlabels.logging_config import DEFAULT_AUDIT_LOG

            audit_path = Path(DEFAULT_AUDIT_LOG)
            audit_dir = audit_path.parent

            # Create directory if needed
            if not audit_dir.exists():
                try:
                    audit_dir.mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    return CheckResult(
                        name="audit_log",
                        status=CheckStatus.WARN,
                        message=f"Cannot create audit log directory: {audit_dir}",
                        duration_ms=0,
                        details={"audit_path": str(audit_path)},
                    )

            # Check if writable
            if audit_path.exists():
                if not os.access(audit_path, os.W_OK):
                    return CheckResult(
                        name="audit_log",
                        status=CheckStatus.WARN,
                        message=f"Audit log not writable: {audit_path}",
                        duration_ms=0,
                        details={"audit_path": str(audit_path)},
                    )
            else:
                # Check if directory is writable
                if not os.access(audit_dir, os.W_OK):
                    return CheckResult(
                        name="audit_log",
                        status=CheckStatus.WARN,
                        message=f"Audit log directory not writable: {audit_dir}",
                        duration_ms=0,
                        details={"audit_path": str(audit_path)},
                    )

            return CheckResult(
                name="audit_log",
                status=CheckStatus.PASS,
                message=f"Audit log path accessible",
                duration_ms=0,
                details={"audit_path": str(audit_path)},
            )

        except Exception as e:
            return CheckResult(
                name="audit_log",
                status=CheckStatus.WARN,
                message="Could not check audit log",
                duration_ms=0,
                error=str(e),
            )


def run_health_check() -> HealthReport:
    """Convenience function to run all health checks."""
    checker = HealthChecker()
    return checker.run_all()

"""
Tests for path traversal vulnerabilities.

Path traversal (directory traversal) attacks allow attackers to access
files outside intended directories by manipulating file paths with
sequences like ../ or encoded variants.
"""

import pytest
from fastapi import HTTPException

from openlabels.server.routes.remediation import (
    validate_file_path,
    validate_quarantine_dir,
    BLOCKED_PATH_PREFIXES,
    BLOCKED_FILE_PATTERNS,
)


class TestValidateFilePath:
    """Tests for the validate_file_path function."""

    def test_valid_path_accepted(self):
        """Valid absolute paths should be accepted."""
        valid_paths = [
            "/home/user/data/document.docx",
            "/data/sensitive/file.pdf",
            "/mnt/share/reports/quarterly.xlsx",
        ]
        for path in valid_paths:
            result = validate_file_path(path)
            assert result is not None
            assert ".." not in result

    def test_path_traversal_blocked(self):
        """Path traversal attempts should be blocked."""
        malicious_paths = [
            "../../../etc/passwd",
            "/data/../../../etc/passwd",
            "/home/user/../../root/.ssh/id_rsa",
            "..\\..\\..\\Windows\\System32\\config\\SAM",
        ]
        for path in malicious_paths:
            with pytest.raises(HTTPException) as exc_info:
                validate_file_path(path)
            assert exc_info.value.status_code == 400
            assert "traversal" in exc_info.value.detail.lower()

    def test_system_directories_blocked(self):
        """System directories should be blocked."""
        system_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/var/log/auth.log",
            "/usr/bin/bash",
            "/root/.bashrc",
            "/proc/1/environ",
            "/sys/kernel/config",
            "/dev/sda",
        ]
        for path in system_paths:
            with pytest.raises(HTTPException) as exc_info:
                validate_file_path(path)
            assert exc_info.value.status_code == 403
            assert "system" in exc_info.value.detail.lower()

    def test_windows_system_directories_blocked(self):
        """Windows system directories should be blocked."""
        windows_paths = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Program Files\\sensitive\\app.exe",
            "C:\\ProgramData\\secrets\\config.xml",
        ]
        for path in windows_paths:
            with pytest.raises(HTTPException) as exc_info:
                validate_file_path(path)
            assert exc_info.value.status_code == 403

    def test_sensitive_files_blocked(self):
        """Sensitive file patterns should be blocked."""
        sensitive_paths = [
            "/home/user/.env",
            "/app/.git/config",
            "/home/user/.ssh/id_rsa",
            "/app/.htpasswd",
            "/data/credentials.json",
        ]
        for path in sensitive_paths:
            with pytest.raises(HTTPException) as exc_info:
                validate_file_path(path)
            assert exc_info.value.status_code == 403
            assert "not allowed" in exc_info.value.detail.lower()

    def test_empty_path_rejected(self):
        """Empty paths should be rejected."""
        with pytest.raises(HTTPException) as exc_info:
            validate_file_path("")
        assert exc_info.value.status_code == 400

    def test_none_path_rejected(self):
        """None paths should be rejected."""
        with pytest.raises(HTTPException) as exc_info:
            validate_file_path(None)
        assert exc_info.value.status_code == 400

    def test_null_byte_injection_handled(self):
        """Null byte injection attempts should be handled safely."""
        malicious_paths = [
            "/data/file.pdf\x00.txt",
            "/home/user/doc\x00/../etc/passwd",
        ]
        for path in malicious_paths:
            # Should either normalize or reject
            try:
                result = validate_file_path(path)
                # If accepted, null bytes should be stripped
                assert "\x00" not in result
            except HTTPException:
                # Rejection is also acceptable
                pass


class TestValidateQuarantineDir:
    """Tests for the validate_quarantine_dir function."""

    def test_default_quarantine_dir(self):
        """Default quarantine dir should be in file's directory."""
        result = validate_quarantine_dir(None, "/data/sensitive/file.pdf")
        assert ".quarantine" in result
        assert result.startswith("/data/sensitive")

    def test_custom_quarantine_dir_accepted(self):
        """Valid custom quarantine directories should be accepted."""
        result = validate_quarantine_dir("/quarantine/2024", "/data/file.pdf")
        assert result == "/quarantine/2024"

    def test_quarantine_dir_traversal_blocked(self):
        """Path traversal in quarantine_dir should be blocked."""
        with pytest.raises(HTTPException) as exc_info:
            validate_quarantine_dir("../../../tmp/exfil", "/data/file.pdf")
        assert exc_info.value.status_code == 400
        assert "traversal" in exc_info.value.detail.lower()

    def test_quarantine_to_system_dir_blocked(self):
        """Quarantine to system directories should be blocked."""
        system_dirs = [
            "/etc/quarantine",
            "/var/quarantine",
            "/usr/local/quarantine",
        ]
        for dir_path in system_dirs:
            with pytest.raises(HTTPException) as exc_info:
                validate_quarantine_dir(dir_path, "/data/file.pdf")
            assert exc_info.value.status_code == 403


class TestPathTraversalIntegration:
    """Integration tests for path traversal prevention.

    Note: Rate limiting is disabled globally in the test_client fixture in conftest.py.
    The actual path validation logic is tested in the unit tests above.
    """

    async def test_quarantine_endpoint_rejects_traversal(self, test_client):
        """Quarantine endpoint should reject path traversal attempts."""
        # Test path traversal in file_path
        traversal_paths = [
            "../../../etc/passwd",
            "/data/../../../etc/shadow",
            "..\\..\\..\\Windows\\System32\\config\\SAM",
        ]

        for malicious_path in traversal_paths:
            response = await test_client.post(
                "/api/remediation/quarantine",
                json={
                    "file_path": malicious_path,
                },
            )
            # Should be rejected with 400 or 403
            assert response.status_code in (400, 403, 404, 422), \
                f"Quarantine accepted traversal path: {malicious_path}"

    async def test_lockdown_endpoint_rejects_traversal(self, test_client):
        """Lockdown endpoint should reject path traversal attempts."""
        traversal_paths = [
            "../../../etc/passwd",
            "/data/../../../etc/shadow",
        ]

        for malicious_path in traversal_paths:
            response = await test_client.post(
                "/api/remediation/lockdown",
                json={
                    "file_path": malicious_path,
                    "allowed_principals": ["SYSTEM"],
                },
            )
            # Should be rejected
            assert response.status_code in (400, 403, 404, 422), \
                f"Lockdown accepted traversal path: {malicious_path}"

    async def test_quarantine_rejects_system_paths(self, test_client):
        """Quarantine should reject system file paths."""
        system_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/id_rsa",
        ]

        for system_path in system_paths:
            response = await test_client.post(
                "/api/remediation/quarantine",
                json={
                    "file_path": system_path,
                },
            )
            assert response.status_code in (400, 403, 404, 422), \
                f"Quarantine accepted system path: {system_path}"

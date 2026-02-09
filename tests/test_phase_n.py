"""
Phase N: Operational Hardening — tests.

Covers:
1. Settings persistence round-trip (web UI reads from TenantSettings DB)
2. restore_permissions() function
3. Health endpoint is accessible without authentication
4. WebSocket rate limiting constants and origin validation
5. scan_all_sites / scan_all_users wiring in scan task
6. System backup/restore CLI enhancements
7. Narrowed except Exception clauses
"""

import ast
import base64
import os
import stat
import tempfile
from pathlib import Path

import pytest


# ── Step 1: Settings Persistence Round-Trip ──────────────────────────

class TestSettingsPersistence:
    """Verify settings_page in web/routes.py reads from TenantSettings DB."""

    def test_settings_page_queries_tenant_settings(self):
        source = Path("src/openlabels/web/routes.py").read_text()
        assert "TenantSettings" in source
        assert "tenant_settings" in source
        # Verify it queries DB, not just static config
        assert "select(TenantSettings)" in source

    def test_settings_page_merges_with_defaults(self):
        source = Path("src/openlabels/web/routes.py").read_text()
        # Should fall back to config defaults when no tenant settings
        assert "config.detection.max_file_size_mb" in source
        assert "config.auth.tenant_id" in source


# ── Step 2: scan_all_sites / scan_all_users wiring ───────────────────

class TestScanAllWiring:
    """Verify scan task uses scan_all_sites/scan_all_users config."""

    def test_scan_task_references_scan_all_sites(self):
        source = Path("src/openlabels/jobs/tasks/scan.py").read_text()
        assert "scan_all_sites" in source
        assert "list_sites" in source

    def test_scan_task_references_scan_all_users(self):
        source = Path("src/openlabels/jobs/tasks/scan.py").read_text()
        assert "scan_all_users" in source
        assert "list_users" in source

    def test_scan_task_iterates_discovered_targets(self):
        source = Path("src/openlabels/jobs/tasks/scan.py").read_text()
        assert "scan_paths" in source
        assert "_iter_all_files" in source


# ── Step 3: restore_permissions() ─────────────────────────────────────

class TestRestorePermissions:
    """Test the restore_permissions function."""

    def test_restore_permissions_exported(self):
        """restore_permissions is exported from the remediation package."""
        source = Path("src/openlabels/remediation/__init__.py").read_text()
        assert "restore_permissions" in source

    def test_restore_permissions_exists(self):
        """restore_permissions function exists in permissions.py."""
        source = Path("src/openlabels/remediation/permissions.py").read_text()
        tree = ast.parse(source)
        func_names = [
            node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        ]
        assert "restore_permissions" in func_names
        assert "_restore_permissions_windows" in func_names
        assert "_restore_permissions_unix" in func_names

    def test_restore_permissions_unix_basic(self):
        """Test restoring Unix permissions from backup."""
        from openlabels.remediation.permissions import (
            lock_down,
            restore_permissions,
            get_current_acl,
        )

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test data")
            tmp_path = Path(tmp.name)

        try:
            # Set initial permissions to something non-default
            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 644

            # Lock down (which backs up ACL)
            result = lock_down(tmp_path, backup_acl=True)
            assert result.success
            assert result.previous_acl is not None

            # Verify lockdown changed permissions to 600
            current = os.stat(tmp_path).st_mode & 0o777
            assert current == 0o600

            # Restore from backup
            restore_result = restore_permissions(tmp_path, result.previous_acl)
            assert restore_result.success

            # Verify permissions were restored
            restored = os.stat(tmp_path).st_mode & 0o777
            assert restored == 0o644
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_restore_permissions_dry_run(self):
        """Verify dry_run doesn't modify permissions."""
        from openlabels.remediation.permissions import restore_permissions

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test")
            tmp_path = Path(tmp.name)

        try:
            os.chmod(tmp_path, 0o600)
            acl_backup = base64.b64encode(
                str({"mode": "0o644"}).encode()
            ).decode()

            result = restore_permissions(tmp_path, acl_backup, dry_run=True)
            assert result.success

            # Permissions should NOT have changed
            current = os.stat(tmp_path).st_mode & 0o777
            assert current == 0o600
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_restore_permissions_nonexistent_file(self):
        """Raise FileNotFoundError for missing file."""
        from openlabels.remediation.permissions import restore_permissions

        acl = base64.b64encode(b"{}").decode()
        with pytest.raises(FileNotFoundError):
            restore_permissions(Path("/nonexistent/file.txt"), acl)

    def test_restore_permissions_invalid_base64(self):
        """Raise RemediationPermissionError for invalid base64."""
        from openlabels.remediation.permissions import restore_permissions
        from openlabels.exceptions import RemediationPermissionError

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test")
            tmp_path = Path(tmp.name)

        try:
            with pytest.raises(RemediationPermissionError):
                restore_permissions(tmp_path, "not-valid-base64!!!")
        finally:
            tmp_path.unlink(missing_ok=True)


# ── Step 4: Health endpoint unauthenticated ──────────────────────────

class TestHealthEndpointAuth:
    """Verify health status endpoint uses optional auth."""

    def test_health_status_uses_optional_user(self):
        source = Path("src/openlabels/server/routes/health.py").read_text()
        assert "get_optional_user" in source
        # Should NOT require get_current_user for the status endpoint
        # (It may still be imported for other endpoints)

    def test_health_guards_tenant_stats(self):
        source = Path("src/openlabels/server/routes/health.py").read_text()
        assert "if user is not None:" in source


# ── Step 5-6: WebSocket rate limiting + dev hardcode removal ─────────

class TestWebSocketHardening:
    """Verify WebSocket security improvements."""

    def test_no_dev_origin_bypass(self):
        """Origin validation should not have unconditional dev bypass."""
        source = Path("src/openlabels/server/routes/ws.py").read_text()
        # The old pattern was: if settings.server.environment == "development": return True
        # in validate_websocket_origin — verify it's removed
        lines = source.split("\n")
        in_validate_fn = False
        for line in lines:
            if "def validate_websocket_origin" in line:
                in_validate_fn = True
            if in_validate_fn and line.strip() == "" and in_validate_fn:
                pass  # blank line
            if in_validate_fn and "def " in line and "validate_websocket_origin" not in line:
                break
            if in_validate_fn and 'environment == "development"' in line and "return True" in line:
                pytest.fail("Dev origin bypass still present in validate_websocket_origin")

    def test_no_dev_user_auto_creation(self):
        """WebSocket auth should not auto-create dev users."""
        source = Path("src/openlabels/server/routes/ws.py").read_text()
        # Should not contain auto-creation of User(email="dev@localhost")
        assert 'User(\n' not in source or 'email="dev@localhost"' not in source

    def test_rate_limiting_constants_defined(self):
        source = Path("src/openlabels/server/routes/ws.py").read_text()
        assert "WS_MAX_MESSAGE_SIZE" in source
        assert "WS_MAX_MESSAGES_PER_MINUTE" in source
        assert "WS_RATE_WINDOW_SECONDS" in source

    def test_rate_limiting_enforced_in_endpoint(self):
        source = Path("src/openlabels/server/routes/ws.py").read_text()
        assert "message_timestamps" in source
        assert "WS_MAX_MESSAGE_SIZE" in source


# ── Step 7: Narrowed except Exception clauses ────────────────────────

class TestNarrowedExceptions:
    """Verify critical paths no longer use bare except Exception."""

    @pytest.mark.parametrize("filepath", [
        "src/openlabels/jobs/tasks/scan.py",
        "src/openlabels/adapters/s3.py",
        "src/openlabels/adapters/gcs.py",
        "src/openlabels/export/engine.py",
    ])
    def test_critical_files_narrowed(self, filepath):
        source = Path(filepath).read_text()
        lines = source.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("except Exception") and "noqa" not in stripped:
                # Allow "except Exception as e:" only if it has a noqa comment
                # or is in a logging-only context
                pytest.fail(
                    f"{filepath}:{i}: bare 'except Exception' found: {stripped}"
                )


# ── Step 8-9: System backup/restore CLI enhancements ─────────────────

class TestSystemCLI:
    """Verify system backup/restore CLI enhancements."""

    def test_backup_has_include_db_option(self):
        source = Path("src/openlabels/cli/commands/system.py").read_text()
        assert "--include-db" in source
        assert "pg_dump" in source

    def test_backup_exports_config(self):
        source = Path("src/openlabels/cli/commands/system.py").read_text()
        assert "config.json" in source
        assert "load_yaml_config" in source

    def test_restore_has_include_db_option(self):
        source = Path("src/openlabels/cli/commands/system.py").read_text()
        assert "psql" in source

    def test_backup_has_policies_endpoint(self):
        source = Path("src/openlabels/cli/commands/system.py").read_text()
        assert '"policies"' in source

    def test_restore_skips_config_json(self):
        source = Path("src/openlabels/cli/commands/system.py").read_text()
        assert 'config.json' in source
        assert 'apply manually' in source

"""Phase K integration tests — config, setup, route structure, worker dispatch."""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch

import pytest


# ── Configuration ────────────────────────────────────────────────────

class TestSIEMExportSettings:
    def test_defaults(self):
        from openlabels.server.config import SIEMExportSettings

        cfg = SIEMExportSettings()
        assert cfg.enabled is False
        assert cfg.mode == "post_scan"
        assert cfg.periodic_interval_seconds == 300
        assert cfg.splunk_hec_url == ""
        assert cfg.sentinel_workspace_id == ""
        assert cfg.qradar_syslog_host == ""
        assert cfg.elastic_hosts == []
        assert cfg.syslog_host == ""
        assert cfg.export_record_types == ["scan_result", "policy_violation"]

    def test_in_main_settings(self):
        from openlabels.server.config import Settings

        # Verify siem_export field exists on Settings
        assert hasattr(Settings, "model_fields")
        assert "siem_export" in Settings.model_fields


# ── Adapter builder ──────────────────────────────────────────────────

class TestBuildAdaptersFromSettings:
    def test_no_adapters_when_empty(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        cfg = SIEMExportSettings()
        adapters = build_adapters_from_settings(cfg)
        assert adapters == []

    def test_splunk_adapter_created(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        cfg = SIEMExportSettings(
            splunk_hec_url="https://splunk:8088",
            splunk_hec_token="my-token",
        )
        adapters = build_adapters_from_settings(cfg)
        assert len(adapters) == 1
        assert adapters[0].format_name() == "splunk"

    def test_multiple_adapters_created(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        cfg = SIEMExportSettings(
            splunk_hec_url="https://splunk:8088",
            splunk_hec_token="tok",
            qradar_syslog_host="qradar.local",
            syslog_host="syslog.local",
        )
        adapters = build_adapters_from_settings(cfg)
        names = {a.format_name() for a in adapters}
        assert names == {"splunk", "qradar", "syslog_cef"}

    def test_sentinel_needs_both_fields(self):
        from openlabels.server.config import SIEMExportSettings
        from openlabels.export.setup import build_adapters_from_settings

        # Only workspace_id, no shared_key → no adapter
        cfg = SIEMExportSettings(sentinel_workspace_id="ws123")
        adapters = build_adapters_from_settings(cfg)
        assert len(adapters) == 0


# ── Route structure ──────────────────────────────────────────────────

class TestExportRouteStructure:
    def test_routes_file_parses(self):
        src = Path("src/openlabels/server/routes/export.py").read_text()
        tree = ast.parse(src)
        func_names = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        assert "trigger_siem_export" in func_names
        assert "test_siem_connections" in func_names
        assert "siem_export_status" in func_names

    def test_route_registered_in_app(self):
        src = Path("src/openlabels/server/app.py").read_text()
        assert "export" in src
        assert '"/export"' in src or "export" in src


# ── Worker dispatch ──────────────────────────────────────────────────

class TestWorkerDispatch:
    def test_export_task_type_handled(self):
        """Verify worker.py handles 'export' task type."""
        src = Path("src/openlabels/jobs/worker.py").read_text()
        assert 'job.task_type == "export"' in src
        assert "execute_export_task" in src


# ── Module structure ─────────────────────────────────────────────────

class TestModuleStructure:
    def test_export_package_exists(self):
        assert Path("src/openlabels/export/__init__.py").exists()
        assert Path("src/openlabels/export/engine.py").exists()
        assert Path("src/openlabels/export/setup.py").exists()

    def test_adapter_files_exist(self):
        adapters_dir = Path("src/openlabels/export/adapters")
        assert (adapters_dir / "__init__.py").exists()
        assert (adapters_dir / "base.py").exists()
        assert (adapters_dir / "splunk.py").exists()
        assert (adapters_dir / "sentinel.py").exists()
        assert (adapters_dir / "qradar.py").exists()
        assert (adapters_dir / "elastic.py").exists()
        assert (adapters_dir / "syslog_cef.py").exists()

    def test_all_adapters_importable(self):
        """All adapter modules parse as valid Python."""
        for name in ["base", "splunk", "sentinel", "qradar", "elastic", "syslog_cef"]:
            src = Path(f"src/openlabels/export/adapters/{name}.py").read_text()
            tree = ast.parse(src)  # Will raise SyntaxError if invalid
            class_defs = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            assert len(class_defs) > 0, f"{name}.py should define at least one class"

    def test_all_adapters_have_format_name(self):
        """Every adapter class implements format_name()."""
        expected = {
            "splunk": "SplunkAdapter",
            "sentinel": "SentinelAdapter",
            "qradar": "QRadarAdapter",
            "elastic": "ElasticAdapter",
            "syslog_cef": "SyslogCEFAdapter",
        }
        for module_name, class_name in expected.items():
            src = Path(f"src/openlabels/export/adapters/{module_name}.py").read_text()
            tree = ast.parse(src)
            classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == class_name]
            assert len(classes) == 1, f"Missing {class_name} in {module_name}.py"
            methods = [n.name for n in ast.walk(classes[0]) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            assert "format_name" in methods, f"{class_name} missing format_name()"
            assert "export_batch" in methods, f"{class_name} missing export_batch()"
            assert "test_connection" in methods, f"{class_name} missing test_connection()"


# ── CLI ──────────────────────────────────────────────────────────────

class TestCLIExportSIEM:
    def test_siem_command_exists(self):
        src = Path("src/openlabels/cli/commands/export.py").read_text()
        assert "export_siem" in src or "def export_siem" in src or '"siem"' in src

    def test_cli_parses(self):
        src = Path("src/openlabels/cli/commands/export.py").read_text()
        tree = ast.parse(src)
        func_names = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        assert len(func_names) > 0, "CLI export module should contain at least one function"


# ── Lifespan ─────────────────────────────────────────────────────────

class TestLifespan:
    def test_periodic_export_registered(self):
        src = Path("src/openlabels/server/lifespan.py").read_text()
        assert "periodic_siem_export" in src
        assert "siem_shutdown" in src

    def test_scan_hook_registered(self):
        src = Path("src/openlabels/jobs/tasks/scan.py").read_text()
        assert "siem_export" in src
        assert "post_scan" in src

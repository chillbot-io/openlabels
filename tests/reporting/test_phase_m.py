"""Phase M integration tests — reporting engine, templates, config, module structure."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


# ── Configuration ────────────────────────────────────────────────────


class TestReportingSettings:
    def test_defaults(self):
        from openlabels.server.config import ReportingSettings

        cfg = ReportingSettings()
        assert cfg.enabled is True
        assert cfg.storage_path == "/data/openlabels/reports"
        assert cfg.retention_days == 90
        assert cfg.smtp_host == ""
        assert cfg.smtp_port == 587
        assert cfg.smtp_use_tls is True
        assert cfg.schedule_enabled is False

    def test_in_main_settings(self):
        from openlabels.server.config import Settings

        settings = Settings()
        assert hasattr(settings, "reporting")
        assert settings.reporting.enabled is True


# ── Module structure ─────────────────────────────────────────────────


class TestModuleStructure:
    def test_reporting_package_importable(self):
        from openlabels.reporting import ReportEngine, ReportRenderer

        assert ReportEngine is not None
        assert ReportRenderer is not None

    def test_engine_has_required_methods(self):
        from openlabels.reporting.engine import ReportEngine

        assert hasattr(ReportEngine, "generate")
        assert hasattr(ReportEngine, "distribute_email")

    def test_renderer_has_required_methods(self):
        from openlabels.reporting.engine import ReportRenderer

        assert hasattr(ReportRenderer, "render_html")
        assert hasattr(ReportRenderer, "render_pdf")
        assert hasattr(ReportRenderer, "render_csv")
        assert hasattr(ReportRenderer, "render")

    def test_report_types_constant(self):
        from openlabels.reporting.engine import REPORT_TYPES

        assert "executive_summary" in REPORT_TYPES
        assert "compliance_report" in REPORT_TYPES
        assert "scan_detail" in REPORT_TYPES
        assert "access_audit" in REPORT_TYPES
        assert "sensitive_files" in REPORT_TYPES


# ── Templates ────────────────────────────────────────────────────────


class TestTemplates:
    def test_all_template_files_exist(self):
        from openlabels.reporting.engine import TEMPLATE_DIR, REPORT_TYPES

        for rt in REPORT_TYPES:
            assert (TEMPLATE_DIR / f"{rt}.html").exists(), f"Missing template: {rt}.html"

    def test_base_template_exists(self):
        from openlabels.reporting.engine import TEMPLATE_DIR

        assert (TEMPLATE_DIR / "base.html").exists()


# ── ReportRenderer ───────────────────────────────────────────────────


class TestReportRenderer:
    def _sample_data(self):
        return {
            "tenant_name": "Test Corp",
            "total_files": 100,
            "files_with_findings": 25,
            "total_entities": 150,
            "avg_risk_score": 42,
            "by_tier": {"CRITICAL": 5, "HIGH": 10, "MEDIUM": 5, "LOW": 3, "MINIMAL": 2},
            "by_entity": {"SSN": 50, "CREDIT_CARD": 30, "EMAIL": 70},
            "top_risk_files": [
                {"file_path": "/data/test.csv", "risk_score": 95, "risk_tier": "CRITICAL", "total_entities": 10},
            ],
            "findings": [
                {
                    "file_path": "/data/test.csv",
                    "risk_score": 95,
                    "risk_tier": "CRITICAL",
                    "entity_counts": {"SSN": 5, "EMAIL": 3},
                    "total_entities": 8,
                    "exposure_level": "PUBLIC",
                    "label_name": None,
                },
            ],
            # scan_detail
            "job_name": "Job-1",
            "target_name": "Finance Share",
            "files_scanned": 100,
            "files_with_pii": 25,
            "scan_duration": "45s",
            # compliance_report
            "total_policies": 3,
            "total_violations": 12,
            "compliance_rate": 88.0,
            "violations_by_policy": [
                {"name": "PII Policy", "count": 8, "severity": "high"},
            ],
            "violations_by_framework": {"GDPR": 7, "HIPAA": 5},
            "top_violating_files": [],
            # access_audit
            "total_events": 500,
            "unique_users": 20,
            "sensitive_accesses": 45,
            "top_users": [],
            "top_files": [],
            "events": [],
            "period": "2026-01-01 to 2026-02-09",
            # sensitive_files
            "total_sensitive": 25,
            "publicly_exposed": 3,
            "unlabeled": 15,
            "critical_count": 5,
            "by_entity_type": [
                {"entity_type": "SSN", "file_count": 10, "total_count": 50},
            ],
            "by_exposure": {"PUBLIC": 3, "INTERNAL": 12, "PRIVATE": 10},
        }

    def test_render_html_executive_summary(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        html = renderer.render_html("executive_summary", self._sample_data())

        assert "Executive Summary" in html
        assert "Test Corp" in html
        assert "100" in html  # total_files
        assert "CRITICAL" in html

    def test_render_html_compliance_report(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        html = renderer.render_html("compliance_report", self._sample_data())

        assert "Compliance Report" in html
        assert "88.0%" in html
        assert "GDPR" in html

    def test_render_html_scan_detail(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        html = renderer.render_html("scan_detail", self._sample_data())

        assert "Scan Detail" in html
        assert "Finance Share" in html
        assert "45s" in html

    def test_render_html_access_audit(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        html = renderer.render_html("access_audit", self._sample_data())

        assert "Access Audit" in html
        assert "500" in html  # total_events

    def test_render_html_sensitive_files(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        html = renderer.render_html("sensitive_files", self._sample_data())

        assert "Sensitive Files" in html
        assert "SSN" in html
        assert "PUBLIC" in html

    def test_render_csv(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        csv_output = renderer.render_csv("executive_summary", self._sample_data())

        assert "file_path,risk_score,risk_tier,entity_counts" in csv_output
        assert "/data/test.csv" in csv_output
        assert "SSN:5" in csv_output

    def test_render_dispatches_to_html(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        result = renderer.render("executive_summary", self._sample_data(), "html")
        assert isinstance(result, str)
        assert "<html" in result

    def test_render_dispatches_to_csv(self):
        from openlabels.reporting.engine import ReportRenderer

        renderer = ReportRenderer()
        result = renderer.render("executive_summary", self._sample_data(), "csv")
        assert isinstance(result, str)
        assert "file_path" in result


# ── ReportEngine ─────────────────────────────────────────────────────


class TestReportEngine:
    @pytest.mark.asyncio
    async def test_generate_creates_file(self, tmp_path):
        from openlabels.reporting.engine import ReportEngine, ReportRenderer

        engine = ReportEngine(storage_dir=tmp_path)
        data = TestReportRenderer()._sample_data()

        path = await engine.generate("executive_summary", data, "html")

        assert path.exists()
        assert path.suffix == ".html"
        content = path.read_text()
        assert "Executive Summary" in content

    @pytest.mark.asyncio
    async def test_generate_csv(self, tmp_path):
        from openlabels.reporting.engine import ReportEngine

        engine = ReportEngine(storage_dir=tmp_path)
        data = TestReportRenderer()._sample_data()

        path = await engine.generate("scan_detail", data, "csv")

        assert path.exists()
        assert path.suffix == ".csv"

    @pytest.mark.asyncio
    async def test_generate_with_custom_filename(self, tmp_path):
        from openlabels.reporting.engine import ReportEngine

        engine = ReportEngine(storage_dir=tmp_path)
        data = TestReportRenderer()._sample_data()

        path = await engine.generate("executive_summary", data, "html", filename="custom.html")

        assert path.name == "custom.html"
        assert path.exists()


# ── Optional dependencies ────────────────────────────────────────────


class TestOptionalDependencies:
    def test_pyproject_has_reports_extra(self):
        pyproject = Path("pyproject.toml").read_text()
        assert "reports = [" in pyproject or "[reports]" in pyproject
        assert "weasyprint" in pyproject

    def test_all_extra_includes_reports(self):
        pyproject = Path("pyproject.toml").read_text()
        assert "reports" in pyproject


# ── DB model ─────────────────────────────────────────────────────────


class TestReportModel:
    def test_report_model_importable(self):
        from openlabels.server.models import Report

        assert hasattr(Report, "__tablename__")
        assert Report.__tablename__ == "reports"

    def test_report_model_has_fields(self):
        from openlabels.server.models import Report

        expected_cols = [
            "id", "tenant_id", "name", "report_type", "format", "status",
            "filters", "result_path", "result_size_bytes", "error",
            "distributed_to", "distributed_at", "created_at", "generated_at",
            "created_by",
        ]
        table_cols = {c.name for c in Report.__table__.columns}
        for col in expected_cols:
            assert col in table_cols, f"Missing column: {col}"


# ── Migration ────────────────────────────────────────────────────────


class TestMigration:
    def test_phase_m_migration_exists(self):
        migration = Path("alembic/versions/d5e6f7a8b9c0_phase_m_reporting_and_distribution.py")
        assert migration.exists()
        source = migration.read_text()
        assert "'reports'" in source
        assert "ix_reports_tenant_type" in source
        assert "ix_reports_tenant_created" in source


# ── Routes ───────────────────────────────────────────────────────────


class TestRoutesRegistration:
    def test_reporting_route_module_exists(self):
        routes_py = Path("src/openlabels/server/routes/reporting.py").read_text()
        assert "router = APIRouter" in routes_py

    def test_reporting_in_lazy_imports(self):
        init_py = Path("src/openlabels/server/routes/__init__.py").read_text()
        assert "reporting" in init_py

    def test_app_includes_reporting(self):
        app_py = Path("src/openlabels/server/app.py").read_text()
        assert "reporting" in app_py

    def test_reporting_endpoints_defined(self):
        routes_py = Path("src/openlabels/server/routes/reporting.py").read_text()
        assert "generate_report" in routes_py
        assert "list_reports" in routes_py
        assert "get_report" in routes_py
        assert "download_report" in routes_py
        assert "distribute_report" in routes_py


# ── CLI ──────────────────────────────────────────────────────────────


class TestCLI:
    def test_report_is_group_with_generate(self):
        report_py = Path("src/openlabels/cli/commands/report.py").read_text()
        assert "click.group" in report_py
        assert "report_generate" in report_py
        assert "executive_summary" in report_py
        assert "sensitive_files" in report_py

    def test_report_generate_subcommand(self):
        report_py = Path("src/openlabels/cli/commands/report.py").read_text()
        tree = ast.parse(report_py)
        func_names = [
            node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        ]
        assert "report_generate" in func_names

"""Tests for the report rendering engine."""

import csv
import io
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openlabels.reporting.engine import (
    REPORT_TYPES,
    ReportEngine,
    ReportRenderer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_template_dir(tmp_path: Path) -> Path:
    """Create minimal Jinja2 templates for testing."""
    for rt in REPORT_TYPES:
        (tmp_path / f"{rt}.html").write_text(
            "<html><body>"
            "<h1>{{ generated_at }}</h1>"
            "{% for f in findings %}<p>{{ f.file_path }}</p>{% endfor %}"
            "</body></html>"
        )
    return tmp_path


# ---------------------------------------------------------------------------
# ReportRenderer
# ---------------------------------------------------------------------------


class TestValidateReportType:
    def test_valid_types_pass(self):
        renderer = ReportRenderer()
        for rt in REPORT_TYPES:
            renderer._validate_report_type(rt)  # Should not raise

    def test_invalid_type_raises(self):
        renderer = ReportRenderer()
        with pytest.raises(ValueError, match="Unknown report_type"):
            renderer._validate_report_type("nonexistent_report")


class TestRenderCSV:
    def test_access_audit_csv(self):
        renderer = ReportRenderer()
        data = {
            "events": [
                {"timestamp": "2025-01-01", "user": "alice", "action": "read", "file_path": "/a.txt"},
                {"timestamp": "2025-01-02", "user": "bob", "action": "write", "file_path": "/b.txt"},
            ]
        }
        result = renderer.render_csv("access_audit", data)

        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        assert rows[0] == ["timestamp", "user", "action", "file_path"]
        assert len(rows) == 3
        assert rows[1][1] == "alice"

    def test_compliance_report_csv(self):
        renderer = ReportRenderer()
        data = {
            "violations_by_policy": [
                {"name": "HIPAA", "count": 42, "severity": "high"},
            ]
        }
        result = renderer.render_csv("compliance_report", data)

        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        assert rows[0] == ["policy", "violations", "severity"]
        assert rows[1] == ["HIPAA", "42", "high"]

    def test_default_findings_csv(self):
        renderer = ReportRenderer()
        data = {
            "findings": [
                {"file_path": "/data/f.txt", "risk_score": 85, "risk_tier": "HIGH",
                 "entity_counts": {"SSN": 3, "EMAIL": 1}},
            ]
        }
        result = renderer.render_csv("executive_summary", data)

        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        assert rows[0] == ["file_path", "risk_score", "risk_tier", "entity_counts"]
        assert "SSN:3" in rows[1][3]

    def test_empty_events(self):
        renderer = ReportRenderer()
        result = renderer.render_csv("access_audit", {"events": []})

        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 1  # Header only


class TestRenderHTML:
    def test_renders_template(self, tmp_path):
        tpl_dir = _make_template_dir(tmp_path)
        renderer = ReportRenderer(template_dir=tpl_dir)

        html = renderer.render_html("executive_summary", {
            "findings": [{"file_path": "/secret.txt"}],
        })

        assert "<html>" in html
        assert "/secret.txt" in html
        assert "UTC" in html  # generated_at timestamp

    def test_invalid_type_raises(self, tmp_path):
        renderer = ReportRenderer(template_dir=_make_template_dir(tmp_path))
        with pytest.raises(ValueError):
            renderer.render_html("bad_type", {})


class TestCustomFilters:
    def test_pct_filter(self):
        renderer = ReportRenderer()
        assert renderer._env.filters["pct"](99.123) == "99.1%"
        assert renderer._env.filters["pct"](0.0) == "0.0%"

    def test_commafy_filter(self):
        renderer = ReportRenderer()
        assert renderer._env.filters["commafy"](1000000) == "1,000,000"
        assert renderer._env.filters["commafy"](42) == "42"


class TestRenderPDF:
    def test_import_error_when_weasyprint_missing(self, tmp_path):
        renderer = ReportRenderer(template_dir=_make_template_dir(tmp_path))
        with patch.dict("sys.modules", {"weasyprint": None}):
            with pytest.raises(ImportError, match="weasyprint"):
                renderer.render_pdf("executive_summary", {"findings": []})


class TestRenderDispatch:
    def test_dispatch_html(self, tmp_path):
        renderer = ReportRenderer(template_dir=_make_template_dir(tmp_path))
        result = renderer.render("executive_summary", {"findings": []}, fmt="html")
        assert "<html>" in result
        assert "UTC" in result  # generated_at timestamp

    def test_dispatch_csv(self):
        renderer = ReportRenderer()
        result = renderer.render("access_audit", {"events": []}, fmt="csv")
        assert "timestamp,user,action,file_path" in result


# ---------------------------------------------------------------------------
# ReportEngine
# ---------------------------------------------------------------------------


class TestReportEngine:
    @pytest.mark.asyncio
    async def test_generate_writes_html_file(self, tmp_path):
        tpl_dir = _make_template_dir(tmp_path)
        renderer = ReportRenderer(template_dir=tpl_dir)
        storage = tmp_path / "reports"
        engine = ReportEngine(renderer=renderer, storage_dir=storage)

        path = await engine.generate(
            "executive_summary",
            {"findings": [{"file_path": "/test.txt"}]},
            fmt="html",
            filename="test_report.html",
        )

        assert path.exists()
        assert path.name == "test_report.html"
        content = path.read_text()
        assert "/test.txt" in content

    @pytest.mark.asyncio
    async def test_generate_csv(self, tmp_path):
        storage = tmp_path / "reports"
        engine = ReportEngine(storage_dir=storage)

        path = await engine.generate(
            "access_audit",
            {"events": [{"timestamp": "t", "user": "u", "action": "a", "file_path": "p"}]},
            fmt="csv",
            filename="audit.csv",
        )

        assert path.exists()
        content = path.read_text()
        assert "timestamp" in content

    @pytest.mark.asyncio
    async def test_generate_auto_filename(self, tmp_path):
        storage = tmp_path / "reports"
        engine = ReportEngine(storage_dir=storage)

        path = await engine.generate(
            "access_audit",
            {"events": []},
            fmt="csv",
        )

        assert path.exists()
        assert "access_audit_" in path.name
        assert path.suffix == ".csv"

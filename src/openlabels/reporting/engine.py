"""
Report rendering engine — Jinja2 HTML templates to PDF / HTML / CSV.

Uses ``weasyprint`` for PDF generation (optional dependency).
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Supported report types (template base names)
REPORT_TYPES = (
    "executive_summary",
    "compliance_report",
    "scan_detail",
    "access_audit",
    "sensitive_files",
)

FormatType = Literal["html", "pdf", "csv"]


class ReportRenderer:
    """Render reports from Jinja2 templates.

    Parameters
    ----------
    template_dir:
        Override the default template directory (for testing).
    """

    def __init__(self, template_dir: Path | None = None) -> None:
        self._template_dir = template_dir or TEMPLATE_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            autoescape=select_autoescape(["html"]),
        )
        # Custom filters
        self._env.filters["pct"] = lambda v: f"{v:.1f}%"
        self._env.filters["commafy"] = lambda v: f"{v:,}"

    def _validate_report_type(self, report_type: str) -> None:
        """Raise ValueError if report_type is not supported."""
        if report_type not in REPORT_TYPES:
            raise ValueError(
                f"Unknown report_type {report_type!r}. "
                f"Must be one of: {', '.join(REPORT_TYPES)}"
            )

    def render_html(self, report_type: str, data: dict[str, Any]) -> str:
        """Render a report to HTML.

        Args:
            report_type: One of REPORT_TYPES.
            data: Template context variables.

        Returns:
            Rendered HTML string.
        """
        self._validate_report_type(report_type)
        template = self._env.get_template(f"{report_type}.html")
        return template.render(
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            **data,
        )

    def render_pdf(self, report_type: str, data: dict[str, Any]) -> bytes:
        """Render a report to PDF via weasyprint.

        Requires ``pip install openlabels[reports]``.
        """
        try:
            from weasyprint import HTML as WeasyprintHTML  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "PDF generation requires weasyprint. "
                "Install with: pip install openlabels[reports]"
            ) from None

        self._validate_report_type(report_type)
        html_str = self.render_html(report_type, data)
        return WeasyprintHTML(string=html_str).write_pdf()

    def render_csv(self, report_type: str, data: dict[str, Any]) -> str:
        """Render a flat CSV export appropriate for the report type."""
        self._validate_report_type(report_type)
        buf = io.StringIO()
        writer = csv.writer(buf)

        if report_type == "access_audit":
            writer.writerow(["timestamp", "user", "action", "file_path"])
            for e in data.get("events", []):
                writer.writerow([
                    e.get("timestamp", ""),
                    e.get("user", ""),
                    e.get("action", ""),
                    e.get("file_path", ""),
                ])
        elif report_type == "compliance_report":
            writer.writerow(["policy", "violations", "severity"])
            for v in data.get("violations_by_policy", []):
                writer.writerow([
                    v.get("name", ""),
                    v.get("count", ""),
                    v.get("severity", ""),
                ])
        else:
            # Default: findings-based CSV
            findings: list[dict] = data.get("findings", [])
            writer.writerow(["file_path", "risk_score", "risk_tier", "entity_counts"])
            for f in findings:
                entities = ";".join(
                    f"{k}:{v}" for k, v in (f.get("entity_counts") or {}).items()
                )
                writer.writerow([
                    f.get("file_path", ""),
                    f.get("risk_score", ""),
                    f.get("risk_tier", ""),
                    entities,
                ])

        return buf.getvalue()

    def render(
        self, report_type: str, data: dict[str, Any], fmt: FormatType = "html"
    ) -> str | bytes:
        """Render a report in the requested format."""
        if fmt == "pdf":
            return self.render_pdf(report_type, data)
        if fmt == "csv":
            return self.render_csv(report_type, data)
        return self.render_html(report_type, data)


class ReportEngine:
    """Orchestrates report generation, storage, and distribution.

    Parameters
    ----------
    renderer:
        ReportRenderer instance (auto-created if ``None``).
    storage_dir:
        Local directory for generated reports.
    """

    def __init__(
        self,
        renderer: ReportRenderer | None = None,
        storage_dir: Path | None = None,
    ) -> None:
        self.renderer = renderer or ReportRenderer()
        self.storage_dir = storage_dir or Path("/data/openlabels/reports")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    async def generate(
        self,
        report_type: str,
        data: dict[str, Any],
        fmt: FormatType = "html",
        filename: str | None = None,
    ) -> Path:
        """Generate a report and persist it to storage.

        Rendering (especially PDF via weasyprint) is offloaded to a thread
        to avoid blocking the event loop.

        Returns the path to the written file.
        """

        def _render_and_write() -> Path:
            content = self.renderer.render(report_type, data, fmt)

            nonlocal filename
            if filename is None:
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                filename = f"{report_type}_{ts}.{fmt}"

            dest = self.storage_dir / filename

            if isinstance(content, bytes):
                dest.write_bytes(content)
            else:
                dest.write_text(content, encoding="utf-8")

            logger.info("Generated report: %s (%s)", dest, fmt)
            return dest

        return await asyncio.to_thread(_render_and_write)

    async def distribute_email(
        self,
        report_path: Path,
        *,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        smtp_use_tls: bool = True,
        from_addr: str,
        to_addrs: list[str],
        subject: str = "OpenLabels Report",
    ) -> None:
        """Send a generated report as an email attachment via SMTP."""
        import mimetypes
        import smtplib
        from email.message import EmailMessage
        from email.utils import formatdate

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Date"] = formatdate(localtime=True)
        msg.set_content(
            f"Please find the attached OpenLabels report: {report_path.name}"
        )

        # Attach the report
        mime_type = mimetypes.guess_type(report_path.name)[0] or "application/octet-stream"
        maintype, subtype = mime_type.split("/", 1)
        msg.add_attachment(
            report_path.read_bytes(),
            maintype=maintype,
            subtype=subtype,
            filename=report_path.name,
        )

        def _send() -> None:
            if smtp_use_tls:
                ctx = ssl.create_default_context()
                with smtplib.SMTP(smtp_host, smtp_port) as s:
                    s.ehlo()
                    s.starttls(context=ctx)
                    if smtp_user:
                        s.login(smtp_user, smtp_password)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as s:
                    if smtp_user:
                        s.login(smtp_user, smtp_password)
                    s.send_message(msg)

        await asyncio.to_thread(_send)
        logger.info("Distributed report %s to %s", report_path.name, to_addrs)

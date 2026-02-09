"""
Reporting and distribution engine (Phase M).

Provides:
- ReportRenderer: Generates HTML/PDF/CSV reports from Jinja2 templates
- EmailDistributor: Sends reports via SMTP
- ReportEngine: Orchestrates rendering and distribution
"""

from openlabels.reporting.engine import ReportEngine, ReportRenderer

__all__ = ["ReportEngine", "ReportRenderer"]

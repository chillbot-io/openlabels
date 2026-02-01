"""
OpenLabels Report Generators.

Generate risk reports in various formats: JSON, CSV, HTML, Markdown.

Example:
    >>> from openlabels.output.report import (
    ...     ReportGenerator,
    ...     results_to_json,
    ...     results_to_csv,
    ...     results_to_html,
    ... )
    >>>
    >>> # Generate HTML report
    >>> html = ReportGenerator(results).to_html()
    >>>
    >>> # Or use convenience functions
    >>> json_str = results_to_json(results)
    >>> csv_str = results_to_csv(results)
"""

import html
import json
import csv
import io
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from collections import Counter

from ..core.types import ScanResult, ReportFormat, ReportConfig

logger = logging.getLogger(__name__)


@dataclass
class ReportSummary:
    """
    Summary statistics for a report.
    """
    total_files: int = 0
    total_size_bytes: int = 0

    # Score statistics
    average_score: float = 0.0
    median_score: float = 0.0
    max_score: int = 0
    min_score: int = 0

    # Tier distribution
    tier_distribution: Dict[str, int] = field(default_factory=dict)

    # Entity statistics
    entity_types_found: List[str] = field(default_factory=list)
    total_entities: int = 0
    entity_distribution: Dict[str, int] = field(default_factory=dict)

    # Error statistics
    error_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "average_score": round(self.average_score, 2),
            "median_score": round(self.median_score, 2),
            "max_score": self.max_score,
            "min_score": self.min_score,
            "tier_distribution": self.tier_distribution,
            "entity_types_found": self.entity_types_found,
            "total_entities": self.total_entities,
            "entity_distribution": self.entity_distribution,
            "error_count": self.error_count,
        }


class ReportGenerator:
    """
    Generates risk reports from scan results.

    Supports multiple output formats: JSON, CSV, HTML, Markdown, JSONL.
    """

    TIER_COLORS = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
        "MINIMAL": "#6c757d",
    }

    TIER_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]

    def __init__(
        self,
        results: List[Union[ScanResult, Dict[str, Any]]],
        config: Optional[ReportConfig] = None,
    ):
        """
        Initialize report generator.

        Args:
            results: List of ScanResult objects or dicts
            config: Optional report configuration
        """
        self.config = config or ReportConfig()
        self.results = self._normalize_results(results)
        self.summary = self._compute_summary()
        self.generated_at = datetime.utcnow().isoformat()

    def _normalize_results(
        self,
        results: List[Union[ScanResult, Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Normalize results to dicts."""
        normalized = []
        for r in results:
            if isinstance(r, ScanResult):
                normalized.append(r.to_dict())
            elif isinstance(r, dict):
                normalized.append(r)
            else:
                logger.warning(f"Unknown result type: {type(r)}")
        return normalized

    def _compute_summary(self) -> ReportSummary:
        """Compute summary statistics."""
        summary = ReportSummary()

        if not self.results:
            return summary

        scores = []
        tier_counts: Counter = Counter()
        entity_counts: Counter = Counter()
        total_size = 0
        error_count = 0

        for r in self.results:
            if r.get("error"):
                error_count += 1
                continue

            score = r.get("score", 0)
            scores.append(score)

            tier = r.get("tier", "MINIMAL").upper()
            tier_counts[tier] += 1

            total_size += r.get("size_bytes", 0)

            # Count entities
            entities = r.get("entities", [])
            for e in entities:
                if isinstance(e, dict):
                    etype = e.get("type", "UNKNOWN")
                    count = e.get("count", 1)
                else:
                    etype = getattr(e, "type", "UNKNOWN")
                    count = getattr(e, "count", 1)
                entity_counts[etype] += count

        summary.total_files = len(self.results)
        summary.total_size_bytes = total_size
        summary.error_count = error_count

        if scores:
            summary.average_score = sum(scores) / len(scores)
            summary.max_score = max(scores)
            summary.min_score = min(scores)

            # Calculate median
            sorted_scores = sorted(scores)
            mid = len(sorted_scores) // 2
            if len(sorted_scores) % 2 == 0:
                summary.median_score = (sorted_scores[mid - 1] + sorted_scores[mid]) / 2
            else:
                summary.median_score = sorted_scores[mid]

        summary.tier_distribution = dict(tier_counts)
        summary.entity_distribution = dict(entity_counts)
        summary.entity_types_found = list(entity_counts.keys())
        summary.total_entities = sum(entity_counts.values())

        return summary

    # --- Output Formats ---

    def to_json(self, indent: int = 2) -> str:
        """Generate JSON report."""
        report = self._build_report_dict()
        return json.dumps(report, indent=indent, ensure_ascii=False)

    def to_jsonl(self) -> str:
        """Generate JSON Lines report (one JSON object per line)."""
        lines = []
        for r in self._get_sorted_results():
            lines.append(json.dumps(r, ensure_ascii=False))
        return '\n'.join(lines)

    def to_csv(self) -> str:
        """Generate CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        headers = ["path", "score", "tier", "size_bytes", "file_type"]
        if self.config.include_entities:
            headers.append("entities")
        writer.writerow(headers)

        # Data rows
        for r in self._get_sorted_results():
            row = [
                r.get("path", ""),
                r.get("score", 0),
                r.get("tier", "MINIMAL"),
                r.get("size_bytes", 0),
                r.get("file_type", ""),
            ]
            if self.config.include_entities:
                entities = r.get("entities", [])
                entity_str = ", ".join(
                    f"{e.get('type', 'UNKNOWN')}:{e.get('count', 1)}"
                    for e in entities if isinstance(e, dict)
                )
                row.append(entity_str)
            writer.writerow(row)

        return output.getvalue()

    def to_markdown(self) -> str:
        """Generate Markdown report."""
        lines = [
            f"# {self.config.title}",
            "",
            f"Generated: {self.generated_at}",
            "",
            "## Summary",
            "",
            f"- **Total files:** {self.summary.total_files}",
            f"- **Total size:** {self._format_size(self.summary.total_size_bytes)}",
            f"- **Average score:** {self.summary.average_score:.1f}",
            f"- **Max score:** {self.summary.max_score}",
            "",
            "### Risk Distribution",
            "",
        ]

        for tier in self.TIER_ORDER:
            count = self.summary.tier_distribution.get(tier, 0)
            if count > 0:
                lines.append(f"- **{tier}:** {count} files")

        if self.summary.entity_types_found:
            lines.extend([
                "",
                "### Entity Types Found",
                "",
            ])
            for etype, count in sorted(
                self.summary.entity_distribution.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                lines.append(f"- {etype}: {count}")

        lines.extend([
            "",
            "## Files",
            "",
            "| Path | Score | Tier | Size |",
            "|------|-------|------|------|",
        ])

        for r in self._get_sorted_results():
            if self.config.limit and len(lines) > self.config.limit + 20:
                lines.append(f"| ... | ... | ... | ... |")
                lines.append(f"| *(truncated, showing first {self.config.limit} files)* |")
                break

            path = r.get("path", "")
            score = r.get("score", 0)
            tier = r.get("tier", "MINIMAL")
            size = self._format_size(r.get("size_bytes", 0))
            lines.append(f"| {path} | {score} | {tier} | {size} |")

        return '\n'.join(lines)

    def to_html(self) -> str:
        """Generate HTML report."""
        sorted_results = self._get_sorted_results()

        # Escape user-controlled data to prevent XSS
        safe_title = html.escape(self.config.title)

        # Build HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{safe_title}</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --minimal: #6c757d;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #f8f9fa;
            color: #333;
        }}
        h1 {{ color: #212529; border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }}
        h2 {{ color: #495057; margin-top: 30px; }}
        .meta {{ color: #6c757d; font-size: 0.9em; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{ margin: 0 0 10px 0; font-size: 0.9em; color: #6c757d; text-transform: uppercase; }}
        .stat-card .value {{ font-size: 2em; font-weight: bold; color: #212529; }}
        .tier-bar {{
            display: flex;
            height: 30px;
            border-radius: 4px;
            overflow: hidden;
            margin: 20px 0;
        }}
        .tier-segment {{
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .tier-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            color: white;
            font-size: 0.75em;
            font-weight: bold;
        }}
        .tier-CRITICAL {{ background: var(--critical); }}
        .tier-HIGH {{ background: var(--high); }}
        .tier-MEDIUM {{ background: var(--medium); color: #212529; }}
        .tier-LOW {{ background: var(--low); }}
        .tier-MINIMAL {{ background: var(--minimal); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        th, td {{ padding: 12px 15px; text-align: left; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #495057; }}
        tr:not(:last-child) td {{ border-bottom: 1px solid #dee2e6; }}
        tr:hover td {{ background: #f8f9fa; }}
        .score {{ font-weight: bold; font-family: monospace; }}
        .score-high {{ color: var(--critical); }}
        .score-medium {{ color: var(--high); }}
        .score-low {{ color: var(--low); }}
        .path {{ font-family: monospace; font-size: 0.9em; word-break: break-all; }}
        .size {{ color: #6c757d; white-space: nowrap; }}
        .entities {{ font-size: 0.85em; color: #495057; }}
        footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 0.85em; }}
    </style>
</head>
<body>
    <h1>{safe_title}</h1>
    <p class="meta">Generated: {html.escape(self.generated_at)}</p>

    <div class="summary">
        <div class="stat-card">
            <h3>Total Files</h3>
            <div class="value">{self.summary.total_files:,}</div>
        </div>
        <div class="stat-card">
            <h3>Total Size</h3>
            <div class="value">{self._format_size(self.summary.total_size_bytes)}</div>
        </div>
        <div class="stat-card">
            <h3>Average Score</h3>
            <div class="value">{self.summary.average_score:.1f}</div>
        </div>
        <div class="stat-card">
            <h3>Max Score</h3>
            <div class="value">{self.summary.max_score}</div>
        </div>
    </div>

    <h2>Risk Distribution</h2>
    {self._generate_tier_bar_html()}

    <h2>Files ({len(sorted_results):,})</h2>
    <table>
        <thead>
            <tr>
                <th>Path</th>
                <th>Score</th>
                <th>Tier</th>
                <th>Size</th>
                {"<th>Entities</th>" if self.config.include_entities else ""}
            </tr>
        </thead>
        <tbody>
"""
        for r in sorted_results:
            score = r.get("score", 0)
            score_class = "score-high" if score >= 70 else "score-medium" if score >= 40 else "score-low"
            tier = r.get("tier", "MINIMAL").upper()

            # Escape user-controlled data to prevent XSS
            safe_path = html.escape(str(r.get('path', '')))
            safe_tier = html.escape(tier)

            entities_html = ""
            if self.config.include_entities:
                entities = r.get("entities", [])
                if entities:
                    entity_strs = [
                        f"{html.escape(str(e.get('type', '?')))}({e.get('count', 1)})"
                        for e in entities if isinstance(e, dict)
                    ]
                    entities_html = f"<td class='entities'>{', '.join(entity_strs)}</td>"
                else:
                    entities_html = "<td class='entities'>-</td>"

            html_content += f"""            <tr>
                <td class="path">{safe_path}</td>
                <td class="score {score_class}">{score}</td>
                <td><span class="tier-badge tier-{safe_tier}">{safe_tier}</span></td>
                <td class="size">{self._format_size(r.get('size_bytes', 0))}</td>
                {entities_html}
            </tr>
"""

        html_content += """        </tbody>
    </table>

    <footer>
        <p>Generated by OpenLabels</p>
    </footer>
</body>
</html>"""

        return html_content

    def _generate_tier_bar_html(self) -> str:
        """Generate the tier distribution bar HTML."""
        total = sum(self.summary.tier_distribution.values())
        if total == 0:
            return "<p>No files scanned.</p>"

        segments = []
        for tier in self.TIER_ORDER:
            count = self.summary.tier_distribution.get(tier, 0)
            if count > 0:
                pct = (count / total) * 100
                safe_tier = html.escape(tier)
                segments.append(
                    f'<div class="tier-segment tier-{safe_tier}" style="width:{pct:.1f}%">'
                    f'{safe_tier}: {count}</div>'
                )

        return f'<div class="tier-bar">{"".join(segments)}</div>'

    # --- Helpers ---

    def _build_report_dict(self) -> Dict[str, Any]:
        """Build complete report as dictionary."""
        return {
            "title": self.config.title,
            "generated_at": self.generated_at,
            "summary": self.summary.to_dict(),
            "files": self._get_sorted_results(),
        }

    def _get_sorted_results(self) -> List[Dict[str, Any]]:
        """Get results sorted according to config."""
        results = [r for r in self.results if not r.get("error")]

        # Sort
        if self.config.sort_by == "score":
            results.sort(key=lambda r: r.get("score", 0), reverse=self.config.sort_descending)
        elif self.config.sort_by == "path":
            results.sort(key=lambda r: r.get("path", ""), reverse=self.config.sort_descending)
        elif self.config.sort_by == "tier":
            tier_values = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1}
            results.sort(
                key=lambda r: tier_values.get(r.get("tier", "MINIMAL").upper(), 0),
                reverse=self.config.sort_descending,
            )
        elif self.config.sort_by == "size":
            results.sort(key=lambda r: r.get("size_bytes", 0), reverse=self.config.sort_descending)

        # Limit
        if self.config.limit:
            results = results[:self.config.limit]

        return results

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes as human-readable size."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def save(self, path: Union[str, Path]) -> None:
        """
        Save report to file.

        Format is determined by file extension or config.format.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Determine format from extension
        ext = path.suffix.lower()
        format_map = {
            ".json": ReportFormat.JSON,
            ".csv": ReportFormat.CSV,
            ".html": ReportFormat.HTML,
            ".htm": ReportFormat.HTML,
            ".md": ReportFormat.MARKDOWN,
            ".jsonl": ReportFormat.JSONL,
        }
        fmt = format_map.get(ext, self.config.format)

        # Generate and save
        if fmt == ReportFormat.JSON:
            content = self.to_json()
        elif fmt == ReportFormat.CSV:
            content = self.to_csv()
        elif fmt == ReportFormat.HTML:
            content = self.to_html()
        elif fmt == ReportFormat.MARKDOWN:
            content = self.to_markdown()
        elif fmt == ReportFormat.JSONL:
            content = self.to_jsonl()
        else:
            content = self.to_json()

        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)



# --- Convenience Functions ---


def results_to_json(
    results: List[Union[ScanResult, Dict]],
    **kwargs,
) -> str:
    """Convert results to JSON string."""
    return ReportGenerator(results, ReportConfig(**kwargs)).to_json()


def results_to_csv(
    results: List[Union[ScanResult, Dict]],
    **kwargs,
) -> str:
    """Convert results to CSV string."""
    return ReportGenerator(results, ReportConfig(**kwargs)).to_csv()


def results_to_html(
    results: List[Union[ScanResult, Dict]],
    **kwargs,
) -> str:
    """Convert results to HTML string."""
    return ReportGenerator(results, ReportConfig(**kwargs)).to_html()


def results_to_markdown(
    results: List[Union[ScanResult, Dict]],
    **kwargs,
) -> str:
    """Convert results to Markdown string."""
    return ReportGenerator(results, ReportConfig(**kwargs)).to_markdown()


def generate_report(
    results: List[Union[ScanResult, Dict]],
    output_path: Union[str, Path],
    **kwargs,
) -> None:
    """Generate and save a report."""
    ReportGenerator(results, ReportConfig(**kwargs)).save(output_path)


__all__ = [
    "ReportGenerator",
    "ReportSummary",
    "results_to_json",
    "results_to_csv",
    "results_to_html",
    "results_to_markdown",
    "generate_report",
]

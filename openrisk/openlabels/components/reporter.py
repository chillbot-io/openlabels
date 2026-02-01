"""
OpenLabels Reporter Component.

Handles report generation in various formats.
"""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from ..core.types import ScanResult, ReportFormat, ReportConfig

if TYPE_CHECKING:
    from ..context import Context
    from .scanner import Scanner


class Reporter:
    """
    Report generation component.

    Handles:
    - report(): Generate risk reports in various formats

    Example:
        >>> from openlabels import Context
        >>> from openlabels.components import Scorer, Scanner, Reporter
        >>>
        >>> ctx = Context()
        >>> scorer = Scorer(ctx)
        >>> scanner = Scanner(ctx, scorer)
        >>> reporter = Reporter(ctx, scanner)
        >>> report = reporter.report("/data", format=ReportFormat.JSON)
    """

    def __init__(self, context: "Context", scanner: "Scanner"):
        self._ctx = context
        self._scanner = scanner

    def report(
        self,
        path: Union[str, Path],
        output: Optional[Union[str, Path]] = None,
        format: ReportFormat = ReportFormat.JSON,
        config: Optional[ReportConfig] = None,
        recursive: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a risk report for a path.

        Args:
            path: Path to scan for report
            output: Optional output file path
            format: Report format (JSON, CSV, HTML, JSONL, MARKDOWN)
            config: Optional report configuration
            recursive: Recurse into subdirectories

        Returns:
            Report data as dictionary
        """
        if config is None:
            config = ReportConfig(format=format)

        results: List[ScanResult] = []
        for result in self._scanner.scan(path, recursive=recursive):
            if not result.error:
                results.append(result)

        # Sort results
        if config.sort_by == "score":
            results.sort(key=lambda r: r.score, reverse=config.sort_descending)
        elif config.sort_by == "path":
            results.sort(key=lambda r: r.path, reverse=config.sort_descending)
        elif config.sort_by == "tier":
            tier_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1}
            results.sort(key=lambda r: tier_order.get(r.tier, 0), reverse=config.sort_descending)

        if config.limit:
            results = results[:config.limit]

        report = self._build_report(results, config)

        if output:
            self._write_report(report, output, config)

        return report

    def _build_report(
        self,
        results: List[ScanResult],
        config: ReportConfig,
    ) -> Dict[str, Any]:
        """Build report data structure."""
        total_files = len(results)
        total_size = sum(r.size_bytes for r in results)
        scores = [r.score for r in results]

        tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        for r in results:
            tier = r.tier.upper()
            if tier in tier_counts:
                tier_counts[tier] += 1

        summary = {
            "total_files": total_files,
            "total_size_bytes": total_size,
            "average_score": sum(scores) / len(scores) if scores else 0,
            "max_score": max(scores) if scores else 0,
            "min_score": min(scores) if scores else 0,
            "tier_distribution": tier_counts,
        }

        files = []
        for r in results:
            file_entry = {
                "path": r.path,
                "score": r.score,
                "tier": r.tier,
                "size_bytes": r.size_bytes,
                "file_type": r.file_type,
            }
            if config.include_entities and r.entities:
                file_entry["entities"] = [
                    {"type": e.type, "count": e.count, "confidence": e.confidence}
                    for e in r.entities
                ]
            files.append(file_entry)

        return {
            "title": config.title,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": summary,
            "files": files,
        }

    def _write_report(
        self,
        report: Dict[str, Any],
        output: Union[str, Path],
        config: ReportConfig,
    ) -> None:
        """Write report to file."""
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)

        if config.format == ReportFormat.JSON:
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)

        elif config.format == ReportFormat.JSONL:
            with open(output, 'w') as f:
                for file_entry in report.get("files", []):
                    f.write(json.dumps(file_entry) + '\n')

        elif config.format == ReportFormat.CSV:
            import csv
            with open(output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["path", "score", "tier", "size_bytes", "file_type"])
                for file_entry in report.get("files", []):
                    writer.writerow([
                        file_entry["path"],
                        file_entry["score"],
                        file_entry["tier"],
                        file_entry["size_bytes"],
                        file_entry["file_type"],
                    ])

        elif config.format == ReportFormat.MARKDOWN:
            with open(output, 'w') as f:
                f.write(f"# {report['title']}\n\n")
                f.write(f"Generated: {report['generated_at']}\n\n")
                f.write("## Summary\n\n")
                summary = report["summary"]
                f.write(f"- Total files: {summary['total_files']}\n")
                f.write(f"- Average score: {summary['average_score']:.1f}\n")
                f.write(f"- Max score: {summary['max_score']}\n\n")
                f.write("### Distribution\n\n")
                for tier, count in summary["tier_distribution"].items():
                    f.write(f"- {tier}: {count}\n")
                f.write("\n## Files\n\n")
                f.write("| Path | Score | Tier |\n")
                f.write("|------|-------|------|\n")
                for file_entry in report.get("files", []):
                    f.write(f"| {file_entry['path']} | {file_entry['score']} | {file_entry['tier']} |\n")

        elif config.format == ReportFormat.HTML:
            with open(output, 'w') as f:
                f.write(self._generate_html_report(report))

    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report content with XSS protection."""
        summary = report["summary"]
        tier_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "MINIMAL": "#6c757d",
        }

        # Escape user-controlled data to prevent XSS
        safe_title = html.escape(str(report.get('title', '')))
        safe_generated_at = html.escape(str(report.get('generated_at', '')))

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{safe_title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .tier {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <h1>{safe_title}</h1>
    <p>Generated: {safe_generated_at}</p>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total files:</strong> {summary['total_files']}</p>
        <p><strong>Average score:</strong> {summary['average_score']:.1f}</p>
        <p><strong>Max score:</strong> {summary['max_score']}</p>
    </div>

    <h2>Files</h2>
    <table>
        <tr><th>Path</th><th>Score</th><th>Tier</th><th>Size</th></tr>
"""
        for f in report.get("files", []):
            safe_tier = html.escape(str(f.get('tier', 'MINIMAL')))
            tier_color = tier_colors.get(f.get('tier', ''), '#6c757d')
            safe_path = html.escape(str(f.get('path', '')))
            html_content += f"""        <tr>
            <td>{safe_path}</td>
            <td>{f.get('score', 0)}</td>
            <td><span class="tier" style="background:{tier_color}">{safe_tier}</span></td>
            <td>{f.get('size_bytes', 0):,}</td>
        </tr>
"""
        html_content += """    </table>
</body>
</html>"""
        return html_content

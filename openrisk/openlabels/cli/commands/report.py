"""
OpenLabels report command.

Generate risk reports in various formats.

Usage:
    openlabels report <path> --format json|csv|html
    openlabels report ./data -f html -o report.html
"""

import csv
import io
import json
import stat as stat_module
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
from collections import Counter

from openlabels import Client
from openlabels.cli.commands.scan import scan_directory, scan_file, ScanResult
from openlabels.cli.output import echo, error, info, progress
from openlabels.logging_config import get_logger
from openlabels.core.scorer import TIER_THRESHOLDS

logger = get_logger(__name__)


def generate_summary(results: List[ScanResult]) -> Dict[str, Any]:
    """Generate summary statistics from scan results."""
    if not results:
        return {
            "total_files": 0,
            "files_at_risk": 0,
            "by_tier": {},
            "by_entity": {},
            "score_distribution": {},
        }

    tier_counts = Counter(r.tier for r in results)
    entity_counts: Counter = Counter()
    for r in results:
        for etype, count in r.entities.items():
            entity_counts[etype] += count

    # Use actual tier thresholds from scorer for consistent display
    crit = TIER_THRESHOLDS['critical']
    high = TIER_THRESHOLDS['high']
    med = TIER_THRESHOLDS['medium']
    low = TIER_THRESHOLDS['low']

    score_dist = {
        f"critical ({crit}-100)": sum(1 for r in results if r.score >= crit),
        f"high ({high}-{crit-1})": sum(1 for r in results if high <= r.score < crit),
        f"medium ({med}-{high-1})": sum(1 for r in results if med <= r.score < high),
        f"low ({low}-{med-1})": sum(1 for r in results if low <= r.score < med),
        f"minimal (0-{low-1})": sum(1 for r in results if r.score < low),
    }

    return {
        "total_files": len(results),
        "files_at_risk": sum(1 for r in results if r.score > 0),
        "max_score": max(r.score for r in results) if results else 0,
        "avg_score": sum(r.score for r in results) / len(results) if results else 0,
        "by_tier": dict(tier_counts),
        "by_entity": dict(entity_counts.most_common(20)),
        "score_distribution": score_dist,
    }


def results_to_json(results: List[ScanResult], summary: Dict[str, Any]) -> str:
    """Convert results to JSON format."""
    report = {
        "generated_at": datetime.now().isoformat(),
        "generator": "openlabels-cli",
        "summary": summary,
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(report, indent=2)


def results_to_csv(results: List[ScanResult]) -> str:
    """Convert results to CSV format."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "path", "score", "tier", "exposure",
        "entity_types", "entity_count", "error"
    ])

    for r in results:
        entity_types = "|".join(r.entities.keys()) if r.entities else ""
        entity_count = sum(r.entities.values()) if r.entities else 0

        writer.writerow([
            r.path,
            r.score,
            r.tier,
            r.exposure,
            entity_types,
            entity_count,
            r.error or "",
        ])

    return output.getvalue()


def results_to_html(results: List[ScanResult], summary: Dict[str, Any]) -> str:
    """Convert results to HTML format."""
    # Sort by score descending
    sorted_results = sorted(results, key=lambda r: r.score, reverse=True)

    tier_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
        "MINIMAL": "#6c757d",
    }

    # Build tier distribution bars dynamically
    tier_bar_colors = ["#dc3545", "#fd7e14", "#ffc107", "#28a745", "#6c757d"]
    tier_bar_styles = ["", "", "color: #333;", "", ""]
    score_dist = summary.get('score_distribution', {})
    tier_bars = []
    for i, (label, count) in enumerate(score_dist.items()):
        color = tier_bar_colors[i] if i < len(tier_bar_colors) else "#6c757d"
        style = tier_bar_styles[i] if i < len(tier_bar_styles) else ""
        tier_name = label.split()[0].capitalize()
        tier_bars.append(
            f'<div class="tier-bar" style="background: {color};{style}">{tier_name}: {count}</div>'
        )

    def get_color(tier: str) -> str:
        return tier_colors.get(tier.upper(), "#6c757d")

    rows = []
    for r in sorted_results:
        entities = ", ".join(f"{k}({v})" for k, v in r.entities.items()) if r.entities else "-"
        color = get_color(r.tier)
        rows.append(f"""
        <tr>
            <td><code>{r.path}</code></td>
            <td style="text-align: center;"><strong>{r.score}</strong></td>
            <td style="text-align: center; color: white; background-color: {color};">{r.tier}</td>
            <td>{r.exposure}</td>
            <td>{entities}</td>
        </tr>
        """)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenLabels Risk Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h3 {{ margin-top: 0; color: #7f8c8d; font-size: 14px; text-transform: uppercase; }}
        .card .value {{ font-size: 32px; font-weight: bold; color: #2c3e50; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #3498db;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{ background: #f8f9fa; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
        .tier-chart {{ display: flex; gap: 10px; flex-wrap: wrap; }}
        .tier-bar {{
            padding: 8px 16px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
        }}
        .timestamp {{ color: #7f8c8d; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>OpenLabels Risk Report</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="summary">
        <div class="card">
            <h3>Total Files</h3>
            <div class="value">{summary['total_files']}</div>
        </div>
        <div class="card">
            <h3>Files at Risk</h3>
            <div class="value">{summary['files_at_risk']}</div>
        </div>
        <div class="card">
            <h3>Max Score</h3>
            <div class="value">{summary['max_score']}</div>
        </div>
        <div class="card">
            <h3>Average Score</h3>
            <div class="value">{summary['avg_score']:.1f}</div>
        </div>
    </div>

    <h2>Risk Distribution</h2>
    <div class="tier-chart">
        {"".join(tier_bars)}
    </div>

    <h2>Top Entity Types</h2>
    <div class="tier-chart">
        {"".join(f'<div class="tier-bar" style="background: #3498db;">{etype}: {count}</div>' for etype, count in list(summary.get('by_entity', {}).items())[:10])}
    </div>

    <h2>All Results ({len(results)} files)</h2>
    <table>
        <thead>
            <tr>
                <th>Path</th>
                <th style="width: 80px;">Score</th>
                <th style="width: 100px;">Tier</th>
                <th style="width: 120px;">Exposure</th>
                <th>Entities</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 14px;">
        Generated by OpenLabels CLI | <a href="https://openlabels.dev">openlabels.dev</a>
    </footer>
</body>
</html>
"""
    return html


def cmd_report(args) -> int:
    """Execute the report command."""
    client = Client(default_exposure=args.exposure)
    path = Path(args.path) if not args.path.startswith(('s3://', 'gs://', 'azure://')) else args.path

    # Check for cloud paths
    if isinstance(path, str):
        error(f"Cloud storage not yet implemented: {path}")
        return 1

    if not path.exists():
        error(f"Path not found: {path}")
        return 1

    logger.info(f"Starting report generation", extra={
        "path": str(path),
        "format": args.format,
        "recursive": args.recursive,
    })

    # Collect results
    results = []
    extensions = args.extensions.split(",") if args.extensions else None

    def is_regular_file(p):  # TOCTOU-001: use lstat
        try:
            return stat_module.S_ISREG(p.lstat().st_mode)
        except OSError:
            return False

    if is_regular_file(path):
        result = scan_file(path, client, args.exposure)
        results.append(result)
    else:
        if not args.quiet:
            info(f"Scanning {path}...")

        # Count files for progress
        if args.recursive:
            all_files = list(path.rglob("*"))
        else:
            all_files = list(path.glob("*"))
        all_files = [f for f in all_files if is_regular_file(f)]
        if extensions:
            exts = {e.lower().lstrip(".") for e in extensions}
            all_files = [f for f in all_files if f.suffix.lower().lstrip(".") in exts]

        with progress("Scanning files", total=len(all_files)) as p:
            for result in scan_directory(
                path, client,
                recursive=args.recursive,
                exposure=args.exposure,
                extensions=extensions,
            ):
                results.append(result)
                p.advance()

    if not args.quiet:
        info(f"Scanned {len(results)} files, generating report...")

    # Generate summary
    summary = generate_summary(results)

    # Generate report
    if args.format == "json":
        content = results_to_json(results, summary)
    elif args.format == "csv":
        content = results_to_csv(results)
    elif args.format == "html":
        content = results_to_html(results, summary)
    else:
        content = results_to_json(results, summary)

    # Output
    if args.output:
        with open(args.output, "w") as f:
            f.write(content)
        echo(f"Report written to {args.output}")
        logger.info(f"Report written to {args.output}")
    else:
        echo(content)

    logger.info(f"Report generation complete", extra={
        "total_files": summary["total_files"],
        "files_at_risk": summary["files_at_risk"],
        "format": args.format,
    })

    return 0


def add_report_parser(subparsers):
    """Add the report subparser."""
    parser = subparsers.add_parser(
        "report",
        help="Generate risk report",
    )
    parser.add_argument(
        "path",
        help="Path to scan for report",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "html"],
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        default=True,
        help="Scan recursively (default: true)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_false",
        dest="recursive",
        help="Do not scan recursively",
    )
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help="Exposure level for scoring",
    )
    parser.add_argument(
        "--extensions",
        help="Comma-separated list of file extensions",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_report)

    return parser

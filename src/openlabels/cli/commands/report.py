"""
Report commands — local scanning and server-backed report generation.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import httpx

from openlabels.cli.base import get_api_client, server_options
from openlabels.cli.utils import handle_http_error, validate_where_filter
from openlabels.core.path_validation import validate_output_path, PathValidationError

logger = logging.getLogger(__name__)


@click.group(invoke_without_command=True)
@click.pass_context
@click.argument("path", required=False, type=click.Path(exists=True))
@click.option("--where", "where_filter", callback=validate_where_filter,
              help='Filter expression (e.g., "score > 75")')
@click.option("--recursive", "-r", is_flag=True, help="Search directories recursively")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json", "csv", "html"]),
              help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
@click.option("--title", default="OpenLabels Scan Report", help="Report title")
def report(ctx, path: Optional[str], where_filter: Optional[str], recursive: bool,
           fmt: str, output: Optional[str], title: str):
    """Generate a report of sensitive data findings.

    When called without a subcommand, scans local files and produces a report.

    \b
    Examples:
        openlabels report ./data -r --format html -o report.html
        openlabels report ./docs --where "tier = CRITICAL" --format json
        openlabels report generate --template executive_summary --format pdf
    """
    # If a subcommand was invoked, let click dispatch to it.
    if ctx.invoked_subcommand is not None:
        return

    # Otherwise run the legacy local-scan report.
    if path is None:
        click.echo(ctx.get_help())
        return

    _local_report(path, where_filter, recursive, fmt, output, title)


def _local_report(path: str, where_filter: Optional[str], recursive: bool,
                  fmt: str, output: Optional[str], title: str):
    """Original local-scan report logic."""
    from openlabels.cli.filter_executor import filter_scan_results

    target_path = Path(path)

    # Collect files
    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*"))
        else:
            files = list(target_path.glob("*"))
        files = [f for f in files if f.is_file()]
    else:
        files = [target_path]

    if not files:
        click.echo("No files found", err=True)
        return

    click.echo(f"Scanning {len(files)} files for report...", err=True)

    try:
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor()

        async def process_all():
            all_results = []
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level="PRIVATE",
                    )
                    all_results.append({
                        "file_path": str(file_path),
                        "file_name": result.file_name,
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                    })
                except PermissionError:
                    logger.debug(f"Permission denied: {file_path}")
                except OSError as e:
                    logger.debug(f"OS error processing {file_path}: {e}")
                except UnicodeDecodeError as e:
                    logger.debug(f"Encoding error processing {file_path}: {e}")
                except ValueError as e:
                    logger.debug(f"Value error processing {file_path}: {e}")
            return all_results

        results = asyncio.run(process_all())

        # Apply filter
        if where_filter:
            results = filter_scan_results(results, where_filter)

        # Sort by risk score descending
        results.sort(key=lambda x: x["risk_score"], reverse=True)

        # Calculate summary statistics
        summary = {
            "total_files": len(files),
            "files_with_findings": len([r for r in results if r["total_entities"] > 0]),
            "total_entities": sum(r["total_entities"] for r in results),
            "by_tier": {
                "CRITICAL": len([r for r in results if r["risk_tier"] == "CRITICAL"]),
                "HIGH": len([r for r in results if r["risk_tier"] == "HIGH"]),
                "MEDIUM": len([r for r in results if r["risk_tier"] == "MEDIUM"]),
                "LOW": len([r for r in results if r["risk_tier"] == "LOW"]),
                "MINIMAL": len([r for r in results if r["risk_tier"] == "MINIMAL"]),
            },
            "by_entity": {},
        }

        # Aggregate entity counts
        for r in results:
            for entity_type, count in r["entity_counts"].items():
                summary["by_entity"][entity_type] = summary["by_entity"].get(entity_type, 0) + count

        # Generate report
        report_data = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "scan_path": str(target_path),
            "filter": where_filter,
            "summary": summary,
            "findings": results,
        }

        def _generate_text():
            lines = []
            lines.append("=" * 70)
            lines.append(title.center(70))
            lines.append("=" * 70)
            lines.append(f"\nGenerated: {report_data['generated_at']}")
            lines.append(f"Scan Path: {report_data['scan_path']}")
            if where_filter:
                lines.append(f"Filter: {where_filter}")
            lines.append("\n" + "-" * 70)
            lines.append("SUMMARY")
            lines.append("-" * 70)
            lines.append(f"Total files scanned: {summary['total_files']}")
            lines.append(f"Files with findings: {summary['files_with_findings']}")
            lines.append(f"Total entities found: {summary['total_entities']}")
            lines.append("\nBy Risk Tier:")
            for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
                count = summary["by_tier"][tier]
                if count > 0:
                    lines.append(f"  {tier}: {count}")
            if summary["by_entity"]:
                lines.append("\nBy Entity Type:")
                for entity, count in sorted(summary["by_entity"].items(), key=lambda x: -x[1]):
                    lines.append(f"  {entity}: {count}")
            if results:
                lines.append("\n" + "-" * 70)
                lines.append("FINDINGS")
                lines.append("-" * 70)
                for r in results[:50]:  # Limit to top 50 in text format
                    lines.append(f"\n{r['file_path']}")
                    lines.append(f"  Risk: {r['risk_score']} ({r['risk_tier']})")
                    if r["entity_counts"]:
                        entities_str = ", ".join(f"{k}:{v}" for k, v in r["entity_counts"].items())
                        lines.append(f"  Entities: {entities_str}")
                if len(results) > 50:
                    lines.append(f"\n... and {len(results) - 50} more findings")
            lines.append("\n" + "=" * 70)
            return "\n".join(lines)

        def _generate_html():
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #4a90d9; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p>Generated: {report_data['generated_at']}<br>
    Scan Path: {report_data['scan_path']}</p>
    {"<p>Filter: " + where_filter + "</p>" if where_filter else ""}
    <div class="summary">
        <h2>Summary</h2>
        <p>Total files: {summary['total_files']}<br>
        Files with findings: {summary['files_with_findings']}<br>
        Total entities: {summary['total_entities']}</p>
        <p>
        <span class="critical">CRITICAL: {summary['by_tier']['CRITICAL']}</span> |
        <span class="high">HIGH: {summary['by_tier']['HIGH']}</span> |
        <span class="medium">MEDIUM: {summary['by_tier']['MEDIUM']}</span> |
        <span class="low">LOW: {summary['by_tier']['LOW']}</span>
        </p>
    </div>
    <h2>Findings</h2>
    <table>
        <tr><th>File</th><th>Score</th><th>Tier</th><th>Entities</th></tr>
"""
            for r in results:
                tier_class = r['risk_tier'].lower()
                entities = ", ".join(f"{k}:{v}" for k, v in r["entity_counts"].items()) or "-"
                html += f"        <tr><td>{r['file_path']}</td><td>{r['risk_score']}</td>"
                html += f"<td class='{tier_class}'>{r['risk_tier']}</td><td>{entities}</td></tr>\n"
            html += """    </table>
</body>
</html>"""
            return html

        # Generate output
        if fmt == "json":
            content = json.dumps(report_data, indent=2, default=str)
        elif fmt == "csv":
            import csv
            import io
            output_io = io.StringIO()
            writer = csv.writer(output_io)
            writer.writerow(["file_path", "risk_score", "risk_tier", "entity_counts"])
            for r in results:
                entities = ";".join(f"{k}:{v}" for k, v in r["entity_counts"].items())
                writer.writerow([r["file_path"], r["risk_score"], r["risk_tier"], entities])
            content = output_io.getvalue()
        elif fmt == "html":
            content = _generate_html()
        else:
            content = _generate_text()

        # Output
        if output:
            # Security: Validate output path to prevent path traversal
            try:
                validated_output = validate_output_path(output, create_parent=True)
            except PathValidationError as e:
                click.echo(f"Error: Invalid output path: {e}", err=True)
                return

            with open(validated_output, "w") as f:
                f.write(content)
            click.echo(f"Report written to: {validated_output}")
        else:
            click.echo(content)

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
        sys.exit(1)
    except OSError as e:
        click.echo(f"Error: File system error: {e}", err=True)
        sys.exit(1)


# ── Server-backed subcommands ───────────────────────────────────────


@report.command("generate")
@click.option(
    "--template", "-t", "template",
    required=True,
    type=click.Choice([
        "executive_summary", "compliance_report", "scan_detail",
        "access_audit", "sensitive_files",
    ]),
    help="Report template",
)
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "pdf", "csv"]))
@click.option("--job", default=None, help="Scope to a scan job ID")
@click.option("--output", "-o", type=click.Path(), help="Download to this path")
@server_options
def report_generate(
    template: str,
    fmt: str,
    job: Optional[str],
    output: Optional[str],
    server: str,
    token: Optional[str],
) -> None:
    """Generate a report on the server.

    \b
    Examples:
        openlabels report generate --template executive_summary --format pdf
        openlabels report generate -t scan_detail --job <id> --format html -o report.html
    """
    from openlabels.cli.base import spinner

    client = get_api_client(server, token)

    try:
        payload: dict = {
            "report_type": template,
            "format": fmt,
        }
        if job:
            payload["job_id"] = job

        with spinner("Generating report..."):
            response = client.post("/api/v1/reporting/generate", json=payload)

        if response.status_code != 201:
            click.echo(f"Error: {response.status_code} - {response.text}", err=True)
            return

        data = response.json()
        report_id = data["id"]
        click.echo(f"Report generated: {data['name']} (id={report_id}, status={data['status']})")

        if output and data["status"] == "generated":
            try:
                validated_output = validate_output_path(output, create_parent=True)
            except PathValidationError as e:
                click.echo(f"Error: Invalid output path: {e}", err=True)
                return

            with spinner("Downloading report..."):
                dl = client.get(f"/api/v1/reporting/{report_id}/download")

            if dl.status_code == 200:
                with open(validated_output, "wb") as f:
                    f.write(dl.content)
                size_kb = len(dl.content) / 1024
                click.echo(f"Downloaded to: {validated_output} ({size_kb:.1f} KB)")
            else:
                click.echo(f"Download failed: {dl.status_code} - {dl.text}", err=True)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as e:
        handle_http_error(e, server)
    finally:
        client.close()

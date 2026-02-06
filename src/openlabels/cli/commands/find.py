"""
Find command for searching sensitive files with filtering.
"""

import json
import sys
from typing import Optional

import click

from openlabels.cli.utils import collect_files, scan_files, validate_where_filter


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--where", "where_filter", callback=validate_where_filter,
              help='Filter expression (e.g., "score > 75 AND has(SSN)")')
@click.option("--recursive", "-r", is_flag=True, help="Search directories recursively")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json", "csv", "paths"]),
              help="Output format")
@click.option("--limit", default=100, type=int, help="Maximum results to return")
@click.option("--sort", "sort_by", default="score", type=click.Choice(["score", "path", "tier", "entities"]),
              help="Sort results by field")
@click.option("--desc/--asc", "descending", default=True, help="Sort direction")
def find(path: str, where_filter: Optional[str], recursive: bool, fmt: str,
         limit: int, sort_by: str, descending: bool):
    """Find sensitive files matching filter criteria.

    Scans files and applies the filter to find matches.

    Filter Grammar:
        score > 75              - Risk score comparison
        tier = CRITICAL         - Exact tier match
        has(SSN)                - Has entity type with count > 0
        count(SSN) >= 10        - Entity count comparison
        path ~ ".*\\.xlsx$"     - Regex path match
        missing(owner)          - Field is empty/null
        NOT has(CREDIT_CARD)    - Negation
        expr AND expr           - Logical AND
        expr OR expr            - Logical OR
        (expr)                  - Grouping

    Examples:
        openlabels find ./data --where "score > 75"
        openlabels find ./docs -r --where "has(SSN) AND tier = CRITICAL"
        openlabels find . -r --where "count(CREDIT_CARD) >= 5" --format json
        openlabels find ./files --where "path ~ '.*\\.xlsx$' AND exposure = PUBLIC"
    """
    from openlabels.cli.filter_executor import filter_scan_results

    target_path = Path(path)

    # Collect files to scan
    if target_path.is_dir():
        if recursive:
            files = list(target_path.rglob("*"))
        else:
            files = list(target_path.glob("*"))
        files = [f for f in files if f.is_file()]
    else:
        files = [target_path]

    if not files:
        click.echo("No files found")
        return

    click.echo(f"Scanning {len(files)} files...", err=True)

    try:
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(enable_ml=False)

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
                    # Convert to dict for filtering
                    all_results.append({
                        "file_path": str(file_path),
                        "file_name": result.file_name,
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
                        "entity_counts": result.entity_counts,
                        "total_entities": sum(result.entity_counts.values()),
                        "exposure_level": "PRIVATE",
                        "owner": None,
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

        # Apply filter if specified
        if where_filter:
            results = filter_scan_results(results, where_filter)

        # Sort results
        sort_key_map = {
            "score": lambda x: x["risk_score"],
            "path": lambda x: x["file_path"],
            "tier": lambda x: ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x["risk_tier"]),
            "entities": lambda x: x["total_entities"],
        }
        results.sort(key=sort_key_map[sort_by], reverse=descending)

        # Apply limit
        results = results[:limit]

        if not results:
            click.echo("No matching files found")
            return

        # Output in requested format
        if fmt == "json":
            click.echo(json.dumps(results, indent=2))
        elif fmt == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["file_path", "risk_score", "risk_tier", "total_entities"])
            writer.writeheader()
            for r in results:
                writer.writerow({k: r[k] for k in ["file_path", "risk_score", "risk_tier", "total_entities"]})
            click.echo(output.getvalue())
        elif fmt == "paths":
            for r in results:
                click.echo(r["file_path"])
        else:
            # Table format
            click.echo(f"\n{'Path':<50} {'Score':<7} {'Tier':<10} {'Entities':<10}")
            click.echo("-" * 80)
            for r in results:
                path_str = r["file_path"]
                if len(path_str) > 49:
                    path_str = "..." + path_str[-46:]
                click.echo(f"{path_str:<50} {r['risk_score']:<7} {r['risk_tier']:<10} {r['total_entities']:<10}")

            click.echo(f"\nFound {len(results)} matching files")

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
        sys.exit(1)
    except OSError as e:
        click.echo(f"Error: File system error: {e}", err=True)
        sys.exit(1)

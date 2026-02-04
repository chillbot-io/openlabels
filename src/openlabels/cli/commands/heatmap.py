"""
Heatmap command for risk visualization by directory.
"""

import asyncio
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path

import click

logger = logging.getLogger(__name__)


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Search directories recursively")
@click.option("--depth", default=2, type=int, help="Directory depth for aggregation")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json"]),
              help="Output format")
def heatmap(path: str, recursive: bool, depth: int, fmt: str):
    """Generate a risk heatmap by directory.

    Shows aggregated risk scores by directory path.

    Examples:
        openlabels heatmap ./data -r
        openlabels heatmap . -r --depth 3 --format json
    """
    target_path = Path(path).resolve()

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

    click.echo(f"Scanning {len(files)} files for heatmap...", err=True)

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
                    all_results.append({
                        "file_path": file_path,
                        "risk_score": result.risk_score,
                        "risk_tier": result.risk_tier.value if hasattr(result.risk_tier, 'value') else result.risk_tier,
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

        # Aggregate by directory
        dir_stats = defaultdict(lambda: {
            "files": 0,
            "total_score": 0,
            "max_score": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "entities": 0,
        })

        for r in results:
            # Get relative path from target
            try:
                rel_path = r["file_path"].relative_to(target_path)
            except ValueError:
                rel_path = r["file_path"]

            # Get directory at specified depth
            parts = rel_path.parts[:-1]  # Exclude filename
            if len(parts) > depth:
                parts = parts[:depth]
            dir_key = str(Path(*parts)) if parts else "."

            stats = dir_stats[dir_key]
            stats["files"] += 1
            stats["total_score"] += r["risk_score"]
            stats["max_score"] = max(stats["max_score"], r["risk_score"])
            stats["entities"] += r["total_entities"]
            if r["risk_tier"] == "CRITICAL":
                stats["critical"] += 1
            elif r["risk_tier"] == "HIGH":
                stats["high"] += 1
            elif r["risk_tier"] == "MEDIUM":
                stats["medium"] += 1

        # Calculate averages and sort
        heatmap_data = []
        for dir_path, stats in dir_stats.items():
            avg_score = stats["total_score"] / stats["files"] if stats["files"] > 0 else 0
            heatmap_data.append({
                "directory": dir_path,
                "files": stats["files"],
                "avg_score": round(avg_score, 1),
                "max_score": stats["max_score"],
                "critical": stats["critical"],
                "high": stats["high"],
                "medium": stats["medium"],
                "entities": stats["entities"],
            })

        # Sort by max score descending
        heatmap_data.sort(key=lambda x: (x["max_score"], x["avg_score"]), reverse=True)

        if fmt == "json":
            click.echo(json.dumps(heatmap_data, indent=2))
        else:
            # Text heatmap with visual indicators
            click.echo("\nRisk Heatmap by Directory")
            click.echo("=" * 80)
            click.echo(f"{'Directory':<35} {'Files':<7} {'Avg':<6} {'Max':<6} {'C':<4} {'H':<4} {'M':<4}")
            click.echo("-" * 80)

            for h in heatmap_data:
                # Visual risk indicator
                if h["max_score"] >= 80:
                    indicator = "[!!!!]"  # Critical
                elif h["max_score"] >= 55:
                    indicator = "[!!! ]"  # High
                elif h["max_score"] >= 31:
                    indicator = "[!!  ]"  # Medium
                elif h["max_score"] >= 11:
                    indicator = "[!   ]"  # Low
                else:
                    indicator = "[    ]"  # Minimal

                dir_str = h["directory"]
                if len(dir_str) > 34:
                    dir_str = "..." + dir_str[-31:]

                click.echo(f"{dir_str:<35} {h['files']:<7} {h['avg_score']:<6} {h['max_score']:<6} "
                          f"{h['critical']:<4} {h['high']:<4} {h['medium']:<4} {indicator}")

            click.echo("\nLegend: C=Critical, H=High, M=Medium")
            click.echo(f"Total: {len(results)} files in {len(heatmap_data)} directories")

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
        sys.exit(1)
    except OSError as e:
        click.echo(f"Error: File system error: {e}", err=True)
        sys.exit(1)

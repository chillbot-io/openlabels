"""
Classify command for local file classification.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import click

from openlabels.cli.utils import collect_files
from openlabels.core.path_validation import PathValidationError, validate_output_path


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--exposure", default="PRIVATE", type=click.Choice(["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]))
@click.option("--enable-ml", is_flag=True, help="Enable ML-based detectors")
@click.option("--recursive", "-r", is_flag=True, help="Scan directories recursively")
@click.option("--output", "-o", help="Output file for results (JSON)")
@click.option("--min-score", default=0, type=int, help="Minimum risk score to report")
def classify(path: str, exposure: str, enable_ml: bool, recursive: bool, output: str | None, min_score: int):
    """Classify files locally (no server required).

    Can classify a single file or a directory of files.

    Examples:
        openlabels classify ./document.docx
        openlabels classify ./data/ --recursive --output results.json
        openlabels classify ./folder/ -r --min-score 50
    """
    files = collect_files(path, recursive)
    if Path(path).is_dir():
        click.echo(f"Classifying {len(files)} files...")
    else:
        click.echo(f"Classifying: {path}")

    try:
        from openlabels.core.detectors.config import DetectionConfig
        from openlabels.core.processor import FileProcessor

        processor = FileProcessor(config=DetectionConfig(enable_ml=enable_ml))
        results = []

        async def process_all():
            all_results = []
            for file_path in files:
                try:
                    if os.path.getsize(file_path) > 200 * 1024 * 1024:
                        continue
                    with open(file_path, "rb") as f:
                        content = f.read()

                    result = await processor.process_file(
                        file_path=str(file_path),
                        content=content,
                        exposure_level=exposure,
                    )
                    all_results.append(result)
                except PermissionError:
                    click.echo(f"Error: Permission denied: {file_path}", err=True)
                except OSError as e:
                    click.echo(f"Error reading {file_path}: {e}", err=True)
                except UnicodeDecodeError as e:
                    click.echo(f"Error decoding {file_path}: {e}", err=True)
                except ValueError as e:
                    click.echo(f"Error processing {file_path}: {e}", err=True)
            return all_results

        results = asyncio.run(process_all())

        # Filter by min_score
        results = [r for r in results if r.risk_score >= min_score]

        # Output results
        if output:
            # Security: Validate output path to prevent path traversal
            try:
                validated_output = validate_output_path(output, create_parent=True)
            except PathValidationError as e:
                click.echo(f"Error: Invalid output path: {e}", err=True)
                return

            # JSON output
            output_data = []
            for result in results:
                output_data.append({
                    "file": result.file_name,
                    "risk_score": result.risk_score,
                    "risk_tier": result.risk_tier.value,
                    "entity_counts": result.entity_counts,
                    "error": result.error,
                })
            with open(validated_output, "w") as f:
                json.dump(output_data, f, indent=2)
            click.echo(f"\nResults written to: {validated_output}")
            click.echo(f"Files processed: {len(results)}")
            click.echo(f"Files with risk >= {min_score}: {len([r for r in results if r.risk_score >= min_score])}")
        else:
            # Console output
            for result in results:
                click.echo(f"\n{'=' * 50}")
                click.echo(f"File: {result.file_name}")
                click.echo("-" * 50)
                click.echo(f"Risk Score: {result.risk_score}")
                click.echo(f"Risk Tier:  {result.risk_tier.value}")
                click.echo(f"Entities:   {sum(result.entity_counts.values())}")

                if result.entity_counts:
                    click.echo("\nDetected Entities:")
                    for entity_type, count in sorted(result.entity_counts.items(), key=lambda x: -x[1]):
                        click.echo(f"  {entity_type}: {count}")

                if result.error:
                    click.echo(f"\nError: {result.error}", err=True)

            if len(results) > 1:
                click.echo(f"\n{'=' * 50}")
                click.echo(f"Summary: {len(results)} files processed")
                high_risk = [r for r in results if r.risk_score >= 55]
                if high_risk:
                    click.echo(f"High/Critical risk: {len(high_risk)} files")

    except ImportError as e:
        click.echo(f"Error: Required module not installed: {e}", err=True)
    except OSError as e:
        click.echo(f"Error: File system error: {e}", err=True)

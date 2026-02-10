"""CLI commands for managing ML models (download, list, check).

Usage:
    openlabels models list              # Show installed / available models
    openlabels models check             # Diagnose missing files
    openlabels models download all      # Download everything
    openlabels models download ner      # PHI-BERT + PII-BERT only
    openlabels models download ocr      # OCR models only
    openlabels models download phi_bert # Single model
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

logger = logging.getLogger(__name__)


@click.group()
def models():
    """Manage ML models for detection and OCR."""
    pass


@models.command("list")
@click.option("--models-dir", type=click.Path(path_type=Path), default=None,
              help="Models directory (default: .openlabels/models/)")
def list_models(models_dir: Path | None):
    """List available models and their installation status."""
    from openlabels.core.constants import DEFAULT_MODELS_DIR
    from openlabels.core.detectors.model_registry import MODEL_ALIASES
    from openlabels.core.detectors.model_registry import list_models as _list

    base = models_dir or DEFAULT_MODELS_DIR

    click.echo(f"Models directory: {base}")
    click.echo(f"Directory exists: {base.exists()}")
    click.echo()

    specs = _list()
    installed_count = 0

    for spec in specs:
        installed = spec.is_installed(base)
        if installed:
            installed_count += 1
        status = click.style("INSTALLED", fg="green") if installed else click.style("MISSING", fg="red")
        click.echo(f"  {spec.name:12s}  {status:s}  {spec.description}")

        if not installed:
            missing = spec.get_missing_files(base)
            for f in missing:
                click.echo(click.style(f"               needs: {f}", fg="yellow"))

    click.echo()
    click.echo(f"{installed_count}/{len(specs)} models installed")

    if installed_count < len(specs):
        click.echo()
        click.echo("To download missing models:")
        click.echo("  openlabels models download all")
        click.echo()
        click.echo(f"Aliases: {', '.join(f'{k}={v}' for k, v in MODEL_ALIASES.items())}")


@models.command()
@click.option("--models-dir", type=click.Path(path_type=Path), default=None,
              help="Models directory (default: .openlabels/models/)")
@click.option("--use-onnx/--use-hf", default=True,
              help="Check ONNX models (default) or HuggingFace models")
def check(models_dir: Path | None, use_onnx: bool):
    """Diagnose model availability (detailed file-level check)."""
    from openlabels.core.constants import DEFAULT_MODELS_DIR
    from openlabels.core.detectors.model_config import check_models_available
    from openlabels.core.ocr import OCREngine

    base = models_dir or DEFAULT_MODELS_DIR

    # ML model check (existing detailed checker)
    report = check_models_available(model_dir=base, use_onnx=use_onnx)
    click.echo(report.summary())
    click.echo()

    # OCR check
    ocr = OCREngine(models_dir=base)
    if ocr.has_custom_models:
        click.echo(click.style("OCR: INSTALLED (custom models)", fg="green"))
    elif ocr.is_available:
        click.echo(click.style("OCR: AVAILABLE (bundled rapidocr-onnxruntime)", fg="green"))
    else:
        click.echo(click.style("OCR: MISSING", fg="red"))
        click.echo("  Install rapidocr-onnxruntime or download OCR models:")
        click.echo("    pip install rapidocr-onnxruntime")
        click.echo("    openlabels models download ocr")

    # ONNX Runtime check
    click.echo()
    try:
        import onnxruntime as ort
        providers = ort.get_available_providers()
        has_cuda = "CUDAExecutionProvider" in providers
        click.echo(f"onnxruntime: {ort.__version__} (providers: {', '.join(providers)})")
        if has_cuda:
            click.echo(click.style("  GPU acceleration: AVAILABLE", fg="green"))
        else:
            click.echo("  GPU acceleration: not available (CPU inference)")
    except ImportError:
        click.echo(click.style("onnxruntime: NOT INSTALLED", fg="red"))
        click.echo("  pip install onnxruntime  # or onnxruntime-gpu for CUDA")


@models.command()
@click.argument("names", nargs=-1, required=True)
@click.option("--models-dir", type=click.Path(path_type=Path), default=None,
              help="Models directory (default: .openlabels/models/)")
@click.option("--force", is_flag=True, help="Re-download even if already installed")
def download(names: tuple[str, ...], models_dir: Path | None, force: bool):
    """Download models from HuggingFace Hub.

    NAMES can be model names (phi_bert, pii_bert, ocr) or aliases (all, ner).

    \b
    Examples:
        openlabels models download all         # Everything
        openlabels models download ner         # PHI-BERT + PII-BERT
        openlabels models download ocr         # OCR models
        openlabels models download phi_bert    # Single model
    """
    from openlabels.core.constants import DEFAULT_MODELS_DIR
    from openlabels.core.detectors.model_registry import (
        download_model,
        resolve_names,
    )

    base = models_dir or DEFAULT_MODELS_DIR

    try:
        resolved = resolve_names(list(names))
    except KeyError as e:
        raise click.BadParameter(str(e)) from e

    click.echo(f"Models directory: {base}")
    click.echo(f"Downloading: {', '.join(resolved)}")
    click.echo()

    errors = []
    for model_name in resolved:
        try:
            click.echo(f"[{model_name}]")
            path = download_model(
                model_name,
                models_dir=base,
                force=force,
                progress_callback=lambda fname, done, total: (
                    click.echo(f"  {fname} ... ", nl=False) if done == 0
                    else click.echo("done")
                ),
            )
            click.echo(click.style(f"  Installed to {path}", fg="green"))
        except ImportError as e:
            click.echo(click.style(f"  ERROR: {e}", fg="red"))
            errors.append(model_name)
        except OSError as e:
            click.echo(click.style(f"  ERROR: {e}", fg="red"))
            errors.append(model_name)

    click.echo()
    success = len(resolved) - len(errors)
    if errors:
        click.echo(click.style(f"{success}/{len(resolved)} models downloaded. Failed: {', '.join(errors)}", fg="yellow"))
        raise SystemExit(1)
    else:
        click.echo(click.style(f"{success}/{len(resolved)} models downloaded successfully.", fg="green"))

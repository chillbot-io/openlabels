"""CLI command for benchmarking the classification pipeline.

Usage:
    openlabels benchmark                                    # Default: 500 samples, ai4privacy
    openlabels benchmark --samples 1000                     # More samples
    openlabels benchmark --preset with_ml                   # With ML detectors
    openlabels benchmark --dataset gretel_pii -n 1000       # Gretel PII 1k
    openlabels benchmark --dataset gretel_finance --enable-ml
    openlabels benchmark sweep                              # Compare all presets
    openlabels benchmark tune                               # Threshold sweep
    openlabels benchmark tune --output tuning.json
"""

from __future__ import annotations

from pathlib import Path

import click

from openlabels.core.path_validation import PathValidationError, validate_output_path


DATASET_CHOICES = ["ai4privacy", "gretel_pii", "gretel_finance"]


@click.group(invoke_without_command=True)
@click.option("--samples", "-n", default=500, type=int, help="Number of samples to evaluate")
@click.option("--preset", "-p", default="patterns_only", help="Config preset name")
@click.option("--dataset", "-d", default="ai4privacy",
              type=click.Choice(DATASET_CHOICES, case_sensitive=False),
              help="Dataset to benchmark against")
@click.option("--seed", default=42, type=int, help="Random seed for reproducibility")
@click.option("--output", "-o", default=None, help="Save results to JSON file")
@click.option("--verbose", "-v", is_flag=True, help="Show per-category breakdown")
@click.option("--threshold", "-t", default=None, type=float, help="Override confidence threshold")
@click.option("--enable-ml", is_flag=True, help="Enable ML detectors")
@click.option("--tiered", is_flag=True, help="Use tiered pipeline")
@click.option("--model-dir", default=None, help="Path to ML model directory")
@click.pass_context
def benchmark(ctx, samples, preset, dataset, seed, output, verbose, threshold,
              enable_ml, tiered, model_dir):
    """Benchmark the classification pipeline against PII datasets."""
    ctx.ensure_object(dict)
    ctx.obj["samples"] = samples
    ctx.obj["seed"] = seed
    ctx.obj["output"] = output
    ctx.obj["verbose"] = verbose
    ctx.obj["model_dir"] = model_dir
    ctx.obj["dataset"] = dataset

    if ctx.invoked_subcommand is not None:
        return

    # Direct invocation: run a single benchmark
    from openlabels.core.benchmark.harness import (
        get_preset,
        run_benchmark,
        save_results,
    )

    try:
        config = get_preset(preset)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        return

    # Apply overrides
    if threshold is not None:
        config.confidence_threshold = threshold
    if enable_ml:
        config.enable_ml = True
    if tiered:
        config.use_tiered_pipeline = True
        config.auto_detect_medical = True
    if model_dir:
        config.ml_model_dir = model_dir

    # Show config name reflecting overrides
    config_desc = config.name
    if enable_ml and "ml" not in config.name:
        config_desc = f"{config.name}+ml"
    if tiered and "tiered" not in config.name:
        config_desc = f"{config_desc}+tiered"
    click.echo(f"Benchmark: {config_desc}")
    click.echo(f"Dataset: {dataset} | Samples: {samples} | "
               f"Threshold: {config.confidence_threshold}")
    ml_status = "ON" if config.enable_ml else "OFF"
    click.echo(f"ML: {ml_status} | "
               f"Pipeline: {'tiered' if config.use_tiered_pipeline else 'orchestrator'}")
    if config.enable_ml:
        _show_model_status(config)
    else:
        click.echo("  (name detection requires ML; use --enable-ml or --preset with_ml)")
    click.echo("-" * 60)

    # Load dataset
    loaded_samples = _load_dataset_samples(dataset, samples, seed)

    try:
        from openlabels.core.benchmark.dataset import DatasetLoadError
        if loaded_samples is not None:
            result = run_benchmark(
                samples=loaded_samples,
                config=config,
                seed=seed,
                progress_callback=_cli_progress,
            )
        else:
            result = run_benchmark(
                sample_size=samples,
                config=config,
                seed=seed,
                progress_callback=_cli_progress,
            )
    except DatasetLoadError as e:
        click.echo(f"\nDataset error: {e}", err=True)
        raise SystemExit(1)
    except ImportError as e:
        click.echo(f"\nError: {e}", err=True)
        return
    except Exception as e:
        click.echo(f"\nError during benchmark: {e}", err=True)
        return

    click.echo("")  # newline after progress
    click.echo(f"Dataset: {result.dataset_source}")
    _print_result(result, verbose)

    if output:
        try:
            validated = validate_output_path(output, create_parent=True)
        except PathValidationError as e:
            click.echo(f"Error: Invalid output path: {e}", err=True)
            return
        save_results(result, validated)
        click.echo(f"\nResults saved to: {validated}")


@benchmark.command()
@click.option("--presets", "-p", default=None, help="Comma-separated preset names")
@click.pass_context
def sweep(ctx, presets):
    """Compare multiple pipeline configurations side by side."""
    from openlabels.core.benchmark.harness import (
        run_sweep,
        save_results,
    )

    samples = ctx.obj["samples"]
    seed = ctx.obj["seed"]
    output = ctx.obj["output"]
    verbose = ctx.obj["verbose"]
    dataset = ctx.obj.get("dataset", "ai4privacy")

    if presets:
        preset_names = [p.strip() for p in presets.split(",")]
    else:
        preset_names = ["patterns_relaxed", "patterns_only", "patterns_strict"]

    click.echo(f"Sweep: {', '.join(preset_names)}")
    click.echo(f"Dataset: {dataset} | Samples: {samples}")
    click.echo("=" * 60)

    loaded_samples = _load_dataset_samples(dataset, samples, seed)

    try:
        results = run_sweep(
            samples=loaded_samples,
            sample_size=samples if loaded_samples is None else None,
            preset_names=preset_names,
            seed=seed,
        )
    except ImportError as e:
        click.echo(f"\nError: {e}", err=True)
        return
    except Exception as e:
        click.echo(f"\nError during sweep: {e}", err=True)
        return

    _print_comparison(results)

    if verbose:
        for result in results:
            click.echo(f"\n--- {result.config.name} ---")
            _print_categories(result)

    if output:
        try:
            validated = validate_output_path(output, create_parent=True)
        except PathValidationError as e:
            click.echo(f"Error: Invalid output path: {e}", err=True)
            return
        save_results(results, validated)
        click.echo(f"\nResults saved to: {validated}")


@benchmark.command()
@click.option("--thresholds", default=None, help="Comma-separated thresholds (e.g. 0.3,0.5,0.7,0.9)")
@click.option("--enable-ml", is_flag=True, help="Enable ML detectors for tuning")
@click.pass_context
def tune(ctx, thresholds, enable_ml):
    """Sweep confidence thresholds to find the optimal operating point."""
    from openlabels.core.benchmark.harness import (
        BenchmarkConfig,
        save_results,
        threshold_sweep,
    )

    samples = ctx.obj["samples"]
    seed = ctx.obj["seed"]
    output = ctx.obj["output"]
    dataset = ctx.obj.get("dataset", "ai4privacy")

    threshold_list = None
    if thresholds:
        threshold_list = [float(t.strip()) for t in thresholds.split(",")]

    model_dir = ctx.obj.get("model_dir")
    base = BenchmarkConfig(enable_ml=enable_ml, ml_model_dir=model_dir)

    click.echo(f"Threshold tuning | Dataset: {dataset} | Samples: {samples} | "
               f"ML: {'on' if enable_ml else 'off'}")
    click.echo("=" * 60)

    loaded_samples = _load_dataset_samples(dataset, samples, seed)

    try:
        results = threshold_sweep(
            samples=loaded_samples,
            sample_size=samples if loaded_samples is None else None,
            thresholds=threshold_list,
            base_config=base,
            seed=seed,
        )
    except ImportError as e:
        click.echo(f"\nError: {e}", err=True)
        return
    except Exception as e:
        click.echo(f"\nError during tuning: {e}", err=True)
        return

    _print_comparison(results)

    if results:
        best = results[0]
        click.echo(f"\nOptimal threshold: {best.config.confidence_threshold:.2f}")
        click.echo(f"Best F1: {best.overall.f1:.4f}")

    if output:
        try:
            validated = validate_output_path(output, create_parent=True)
        except PathValidationError as e:
            click.echo(f"Error: Invalid output path: {e}", err=True)
            return
        save_results(results, validated)
        click.echo(f"\nResults saved to: {validated}")


# ── Dataset loading ───────────────────────────────────────────────────

# Bundled Gretel dataset paths (relative to benchmark package)
_BENCHMARK_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "core" / "benchmark"


def _load_dataset_samples(dataset: str, sample_size: int, seed: int):
    """Load samples for the chosen dataset.

    Returns a list of BenchmarkSample for Gretel datasets, or None for
    ai4privacy (which is handled by the harness's default load_dataset).
    """
    if dataset == "ai4privacy":
        return None

    if dataset == "gretel_pii":
        from openlabels.core.benchmark.adapters import load_gretel_pii

        path = _BENCHMARK_DATA_DIR / "gretel_pii_test.jsonl"
        samples = load_gretel_pii(path, sample_size=sample_size, seed=seed)
        click.echo(f"Loaded {len(samples)} samples from gretel_pii")
        return samples

    if dataset == "gretel_finance":
        from openlabels.core.benchmark.adapters import load_gretel_finance

        path = _BENCHMARK_DATA_DIR / "gretel_finance_test.jsonl"
        samples = load_gretel_finance(path, sample_size=sample_size, seed=seed)
        click.echo(f"Loaded {len(samples)} samples from gretel_finance")
        return samples

    raise click.BadParameter(f"Unknown dataset: {dataset}")


# ── Output formatting ─────────────────────────────────────────────────

def _show_model_status(config) -> None:
    """Show ML model status."""
    from openlabels.core.detectors.gliner import DEFAULT_GLINER_MODEL

    click.echo(f"  GLiNER: {DEFAULT_GLINER_MODEL}")
    if getattr(config, "enable_spacy_ner", False):
        try:
            import spacy
            model = "en_core_web_lg"
            if spacy.util.is_package(model):
                click.echo(f"  spaCy NER: {model}")
            else:
                click.echo(f"  spaCy NER: {model} (NOT INSTALLED — run: python -m spacy download {model})")
        except ImportError:
            click.echo("  spaCy NER: disabled (spacy not installed)")


def _cli_progress(current: int, total: int) -> None:
    """Simple progress indicator."""
    pct = current * 100 // total
    bar = "#" * (pct // 2) + "-" * (50 - pct // 2)
    click.echo(f"\r  [{bar}] {current}/{total} ({pct}%)", nl=False)
    if current == total:
        click.echo("")


def _print_result(result, verbose: bool = False) -> None:
    """Print a single benchmark result."""
    s = result.summary()
    click.echo(f"Precision:  {s['precision']:.4f}")
    click.echo(f"Recall:     {s['recall']:.4f}")
    click.echo(f"F1 Score:   {s['f1']:.4f}")
    click.echo("")
    click.echo(f"TP: {s['true_positives']}  FP: {s['false_positives']}  FN: {s['false_negatives']}")
    click.echo(f"Exact: {s['exact_matches']}  Partial: {s['partial_matches']}  "
               f"Type mismatch: {s['type_mismatches']}")
    click.echo("")
    click.echo(f"Avg time/sample: {s['avg_time_ms']:.1f}ms")
    click.echo(f"Throughput: {s['throughput_sps']:.1f} samples/sec")
    click.echo(f"Total time: {s['total_time_s']:.1f}s")

    if verbose:
        _print_categories(result)


def _print_categories(result) -> None:
    """Print per-category breakdown."""
    click.echo("\nPer-category breakdown:")
    click.echo(f"{'Category':<20} {'Prec':>6} {'Recall':>6} {'F1':>6} "
               f"{'TP':>5} {'FP':>5} {'FN':>5}")
    click.echo("-" * 60)

    for cat, m in sorted(result.by_category.items(), key=lambda x: -x[1].f1):
        click.echo(
            f"{cat:<20} {m.precision:>6.3f} {m.recall:>6.3f} {m.f1:>6.3f} "
            f"{m.true_positives:>5} {m.false_positives:>5} {m.false_negatives:>5}"
        )


def _print_comparison(results) -> None:
    """Print a comparison table across configurations."""
    click.echo(f"\n{'Config':<25} {'Prec':>6} {'Recall':>6} {'F1':>6} "
               f"{'TP':>5} {'FP':>5} {'FN':>5} {'ms/s':>7}")
    click.echo("=" * 75)

    for r in results:
        s = r.summary()
        click.echo(
            f"{s['config']:<25} "
            f"{s['precision']:>6.3f} {s['recall']:>6.3f} {s['f1']:>6.3f} "
            f"{s['true_positives']:>5} {s['false_positives']:>5} "
            f"{s['false_negatives']:>5} {s['avg_time_ms']:>7.1f}"
        )

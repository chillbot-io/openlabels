"""CLI command for benchmarking the classification pipeline.

Usage:
    openlabels benchmark                        # Default: 500 samples, patterns_only
    openlabels benchmark --samples 1000         # More samples
    openlabels benchmark --preset with_ml       # With ML detectors
    openlabels benchmark sweep                  # Compare all presets
    openlabels benchmark tune                   # Threshold sweep
    openlabels benchmark tune --output tuning.json
"""

from __future__ import annotations

import click

from openlabels.core.path_validation import PathValidationError, validate_output_path


@click.group(invoke_without_command=True)
@click.option("--samples", "-n", default=500, type=int, help="Number of samples to evaluate")
@click.option("--preset", "-p", default="patterns_only", help="Config preset name")
@click.option("--seed", default=42, type=int, help="Random seed for reproducibility")
@click.option("--output", "-o", default=None, help="Save results to JSON file")
@click.option("--verbose", "-v", is_flag=True, help="Show per-category breakdown")
@click.option("--threshold", "-t", default=None, type=float, help="Override confidence threshold")
@click.option("--enable-ml", is_flag=True, help="Enable ML detectors")
@click.option("--tiered", is_flag=True, help="Use tiered pipeline")
@click.option("--model-dir", default=None, help="Path to ML model directory")
@click.pass_context
def benchmark(ctx, samples, preset, seed, output, verbose, threshold, enable_ml, tiered, model_dir):
    """Benchmark the classification pipeline against ai4privacy dataset."""
    ctx.ensure_object(dict)
    ctx.obj["samples"] = samples
    ctx.obj["seed"] = seed
    ctx.obj["output"] = output
    ctx.obj["verbose"] = verbose
    ctx.obj["model_dir"] = model_dir

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

    click.echo(f"Benchmark: {config.name}")
    click.echo(f"Samples: {samples} | Threshold: {config.confidence_threshold}")
    click.echo(f"ML: {'on' if config.enable_ml else 'off'} | "
               f"Pipeline: {'tiered' if config.use_tiered_pipeline else 'orchestrator'}")
    click.echo("-" * 60)

    try:
        result = run_benchmark(
            sample_size=samples,
            config=config,
            seed=seed,
            progress_callback=_cli_progress,
        )
    except ImportError as e:
        click.echo(f"\nError: {e}", err=True)
        return
    except Exception as e:
        click.echo(f"\nError during benchmark: {e}", err=True)
        return

    click.echo("")  # newline after progress
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

    if presets:
        preset_names = [p.strip() for p in presets.split(",")]
    else:
        preset_names = ["patterns_relaxed", "patterns_only", "patterns_strict"]

    click.echo(f"Sweep: {', '.join(preset_names)}")
    click.echo(f"Samples: {samples}")
    click.echo("=" * 60)

    try:
        results = run_sweep(
            sample_size=samples,
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

    threshold_list = None
    if thresholds:
        threshold_list = [float(t.strip()) for t in thresholds.split(",")]

    model_dir = ctx.obj.get("model_dir")
    base = BenchmarkConfig(enable_ml=enable_ml, ml_model_dir=model_dir)

    click.echo(f"Threshold tuning | Samples: {samples} | ML: {'on' if enable_ml else 'off'}")
    click.echo("=" * 60)

    try:
        results = threshold_sweep(
            sample_size=samples,
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


# ── Output formatting ─────────────────────────────────────────────────

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

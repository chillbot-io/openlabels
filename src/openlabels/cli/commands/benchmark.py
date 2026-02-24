"""CLI command for benchmarking the classification pipeline.

Usage:
    openlabels benchmark                                    # Default: 500 samples, ai4privacy
    openlabels benchmark --samples 1000                     # More samples
    openlabels benchmark --preset with_ml                   # With ML detectors
    openlabels benchmark --ml                               # Enable full ML stack
    openlabels benchmark --dataset nemotron_pii -n 1000      # NVIDIA Nemotron-PII
    openlabels benchmark --dataset gretel_pii -n 1000       # Gretel PII 1k
    openlabels benchmark --dataset gretel_finance --ml      # Full ML on Gretel finance
    openlabels benchmark sweep                              # Compare all presets
    openlabels benchmark tune --ml                          # Threshold sweep with ML
    openlabels benchmark tune --output tuning.json
"""

from __future__ import annotations

from pathlib import Path

import click

from openlabels.core.path_validation import PathValidationError, validate_output_path


DATASET_CHOICES = [
    "ai4privacy", "ai4privacy_multilingual",
    "nemotron_pii",
    "gretel_pii", "gretel_finance",
]


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
@click.option("--ml", is_flag=True, help="Enable all ML detectors (GLiNER + PHI + multilingual)")
@click.option("--enable-ml", is_flag=True, hidden=True, help="[Deprecated] Use --ml instead")
@click.option("--enable-phi", is_flag=True, hidden=True, help="[Deprecated] Use --ml instead")
@click.option("--tiered", is_flag=True, help="Use tiered pipeline")
@click.option("--model-dir", default=None, help="Path to ML model directory")
@click.option("--language", "-l", default=None,
              help="Filter to a specific language (ISO 639-1 code, e.g. 'fr')")
@click.option("--refresh-cache", is_flag=True,
              help="Delete cached dataset and re-download from HuggingFace")
@click.pass_context
def benchmark(ctx, samples, preset, dataset, seed, output, verbose, threshold,
              ml, enable_ml, enable_phi, tiered, model_dir, language,
              refresh_cache):
    """Benchmark the classification pipeline against PII datasets."""
    ctx.ensure_object(dict)
    ctx.obj["samples"] = samples
    ctx.obj["seed"] = seed
    ctx.obj["output"] = output
    ctx.obj["verbose"] = verbose
    ctx.obj["model_dir"] = model_dir
    ctx.obj["dataset"] = dataset
    ctx.obj["language"] = language
    ctx.obj["refresh_cache"] = refresh_cache

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

    # --ml enables the full ML stack; legacy flags still work
    use_ml = ml or enable_ml
    use_phi = ml or enable_phi

    # Apply overrides
    if threshold is not None:
        config.confidence_threshold = threshold
    if use_ml:
        config.enable_ml = True
    if use_phi:
        config.enable_phi = True
    if tiered:
        config.use_tiered_pipeline = True
        config.auto_detect_medical = True
    if model_dir:
        config.ml_model_dir = model_dir

    # Show config name reflecting overrides
    config_desc = config.name
    if use_ml and "ml" not in config.name:
        config_desc = f"{config.name}+ml"
    if tiered and "tiered" not in config.name:
        config_desc = f"{config_desc}+tiered"
    click.echo(f"Benchmark: {config_desc}")
    click.echo(f"Dataset: {dataset} | Samples: {samples} | "
               f"Threshold: {config.confidence_threshold}")
    ml_status = "ON" if config.enable_ml else "OFF"
    phi_status = "ON" if config.enable_phi else "OFF"
    click.echo(f"ML: {ml_status} | PHI: {phi_status} | "
               f"Pipeline: {'tiered' if config.use_tiered_pipeline else 'orchestrator'}")
    if config.enable_ml or config.enable_phi:
        _show_model_status(config)
    else:
        click.echo("  (name/PHI detection requires ML; use --ml or --preset with_ml)")
    click.echo("-" * 60)

    # Load dataset
    loaded_samples = _load_dataset_samples(
        dataset, samples, seed, language=language, refresh_cache=refresh_cache,
    )

    try:
        from openlabels.core.benchmark.dataset import DatasetLoadError
        result = run_benchmark(
            samples=loaded_samples,
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
    if result.detectors_loaded:
        click.echo(f"Detectors: {', '.join(result.detectors_loaded)}")
        ml_names = {"gliner", "multilingual_gliner", "phi"}
        has_ml = any(n in ml_names for n in result.detectors_loaded)
        if config.enable_ml and not has_ml:
            click.echo(
                click.style(
                    "WARNING: ML was requested but NO ML detectors loaded! "
                    "Results are pattern-only.",
                    fg="red", bold=True,
                ),
                err=True,
            )
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

    language = ctx.obj.get("language")
    refresh_cache = ctx.obj.get("refresh_cache", False)

    click.echo(f"Sweep: {', '.join(preset_names)}")
    click.echo(f"Dataset: {dataset} | Samples: {samples}")
    click.echo("=" * 60)

    loaded_samples = _load_dataset_samples(
        dataset, samples, seed, language=language, refresh_cache=refresh_cache,
    )

    try:
        results = run_sweep(
            samples=loaded_samples,
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
@click.option("--ml", is_flag=True, help="Enable all ML detectors for tuning")
@click.option("--enable-ml", is_flag=True, hidden=True, help="[Deprecated] Use --ml instead")
@click.option("--enable-phi", is_flag=True, hidden=True, help="[Deprecated] Use --ml instead")
@click.pass_context
def tune(ctx, thresholds, ml, enable_ml, enable_phi):
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

    # --ml enables the full ML stack; legacy flags still work
    use_ml = ml or enable_ml
    use_phi = ml or enable_phi

    threshold_list = None
    if thresholds:
        threshold_list = [float(t.strip()) for t in thresholds.split(",")]

    model_dir = ctx.obj.get("model_dir")
    base = BenchmarkConfig(enable_ml=use_ml, enable_phi=use_phi, ml_model_dir=model_dir)

    language = ctx.obj.get("language")
    refresh_cache = ctx.obj.get("refresh_cache", False)

    click.echo(f"Threshold tuning | Dataset: {dataset} | Samples: {samples} | "
               f"ML: {'on' if use_ml else 'off'} | PHI: {'on' if use_phi else 'off'}")
    click.echo("=" * 60)

    loaded_samples = _load_dataset_samples(
        dataset, samples, seed, language=language, refresh_cache=refresh_cache,
    )

    try:
        results = threshold_sweep(
            samples=loaded_samples,
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


@benchmark.command()
@click.option("--top", default=30, type=int, help="Number of top entries to show")
@click.pass_context
def diagnose(ctx, top):
    """Diagnose F1 score issues: find unmapped labels, phantom gold entities, and distribution gaps.

    This command loads the dataset and checks for:
    1. Labels that fall through the mapping (guaranteed false negatives)
    2. Gold entity type distribution
    3. Labels that detectors can never produce
    4. Comparison with EVAL_CATEGORIES coverage

    Example:
        openlabels benchmark diagnose -n 1000
        openlabels benchmark diagnose -n 5000 --top 50
    """
    from collections import Counter

    from openlabels.core.benchmark.entity_mapping import (
        AI4PRIVACY_TO_OPENLABELS,
        EVAL_CATEGORIES,
        UNMAPPED_PRED_TYPES,
        UNMAPPED_TYPES,
        audit_labels,
    )

    samples_n = ctx.obj["samples"]
    seed = ctx.obj["seed"]
    dataset = ctx.obj.get("dataset", "ai4privacy")
    language = ctx.obj.get("language")
    refresh_cache = ctx.obj.get("refresh_cache", False)

    click.echo(f"Diagnosing label mapping: {dataset} | {samples_n} samples")
    click.echo("=" * 70)

    loaded_samples = _load_dataset_samples(
        dataset, samples_n, seed, language=language, refresh_cache=refresh_cache,
    )

    # 1. Collect ALL original labels and mapped types
    original_labels: Counter = Counter()
    mapped_types: Counter = Counter()
    passthrough_labels: Counter = Counter()
    total_gold = 0

    for sample in loaded_samples:
        for g in sample.gold_spans:
            original_labels[g.original_label] += 1
            mapped_types[g.entity_type] += 1
            total_gold += 1
            # Check if this was a passthrough (not explicitly mapped)
            upper = g.original_label.upper().replace(" ", "").replace("-", "")
            if upper not in AI4PRIVACY_TO_OPENLABELS and upper not in UNMAPPED_TYPES:
                passthrough_labels[g.original_label] += 1

    click.echo(f"\nTotal gold spans: {total_gold}")
    click.echo(f"Unique original labels: {len(original_labels)}")
    click.echo(f"Unique mapped types: {len(mapped_types)}")

    # 2. CRITICAL: Show passthrough labels (guaranteed FN)
    if passthrough_labels:
        passthrough_total = sum(passthrough_labels.values())
        passthrough_pct = passthrough_total / total_gold * 100 if total_gold else 0
        click.echo(f"\n{'!'*70}")
        click.echo(f"CRITICAL: {len(passthrough_labels)} label(s) FALL THROUGH the mapping!")
        click.echo(f"These create {passthrough_total} guaranteed false negatives "
                   f"({passthrough_pct:.1f}% of all gold spans)")
        click.echo(f"{'!'*70}")
        click.echo(f"\n  {'Label':<30} {'Count':>6} {'% of Gold':>9}  Suggested fix")
        click.echo("  " + "-" * 75)
        for label, count in passthrough_labels.most_common():
            pct = count / total_gold * 100
            # Suggest the most likely mapping
            upper = label.upper().replace(" ", "").replace("-", "")
            suggestion = _suggest_mapping(upper)
            click.echo(f"  {label:<30} {count:>6} {pct:>8.1f}%  → {suggestion}")
        click.echo(f"\n  Fix: Add these to AI4PRIVACY_TO_OPENLABELS in entity_mapping.py")
    else:
        click.echo(f"\n✓ All labels are mapped (no passthrough labels)")

    # 3. Show gold entity type distribution
    click.echo(f"\nGold entity type distribution (top {top}):")
    click.echo(f"  {'Type':<25} {'Count':>6} {'% Gold':>7}  {'In EVAL_CAT':>11}")
    click.echo("  " + "-" * 55)
    for etype, count in mapped_types.most_common(top):
        pct = count / total_gold * 100
        in_eval = "✓" if etype in EVAL_CATEGORIES else "✗ MISSING"
        click.echo(f"  {etype:<25} {count:>6} {pct:>6.1f}%  {in_eval:>11}")

    # 4. Check for gold types not in EVAL_CATEGORIES
    missing_eval = {t for t in mapped_types if t not in EVAL_CATEGORIES}
    if missing_eval:
        missing_count = sum(mapped_types[t] for t in missing_eval)
        missing_pct = missing_count / total_gold * 100 if total_gold else 0
        click.echo(f"\nWARNING: {len(missing_eval)} gold type(s) not in EVAL_CATEGORIES "
                   f"({missing_count} spans, {missing_pct:.1f}% of gold)")
        click.echo("  These types cannot benefit from category-level type matching.")
        for t in sorted(missing_eval):
            click.echo(f"    {t} ({mapped_types[t]} spans)")

    # 5. Label audit summary
    all_original = list(original_labels.keys())
    audit = audit_labels(all_original)
    click.echo(f"\nLabel audit summary:")
    click.echo(f"  Mapped:      {len(audit['mapped'])} labels")
    click.echo(f"  Unmapped:    {len(audit['unmapped'])} labels (excluded from scoring)")
    click.echo(f"  Passthrough: {len(audit['passthrough'])} labels (NEEDS FIXING)")

    # 6. Check UNMAPPED_PRED_TYPES coverage
    click.echo(f"\nFiltered prediction types (UNMAPPED_PRED_TYPES):")
    for t in sorted(UNMAPPED_PRED_TYPES):
        click.echo(f"  {t}")

    click.echo(f"\nDone. Use 'openlabels benchmark -v' for per-category F1 breakdown.")


def _suggest_mapping(upper_label: str) -> str:
    """Suggest a likely OpenLabels mapping for an unmapped label."""
    suggestions = {
        "PASSPORTNUM": "PASSPORT",
        "CREDITCARDNUM": "CREDIT_CARD",
        "VEHICLEREGISTRATION": "LICENSE_PLATE",
        "BANKACCOUNTNUMBER": "ACCOUNT_NUMBER",
        "INSURANCENUMBER": "ACCOUNT_NUMBER",
        "INSURANCENUM": "ACCOUNT_NUMBER",
        "MORTGAGENUMBER": "ACCOUNT_NUMBER",
        "INVESTMENTACCOUNTNUMBER": "ACCOUNT_NUMBER",
        "LOANNUM": "ACCOUNT_NUMBER",
        "MEMBERID": "ACCOUNT_NUMBER",
        "MASKNUM": "ACCOUNT_NUMBER",
        "LICENSENUM": "DRIVER_LICENSE",
        "BROKERAGE": "COMPANY",
    }
    if upper_label in suggestions:
        return suggestions[upper_label]
    # Pattern-based guessing
    if "PHONE" in upper_label:
        return "PHONE"
    if "NAME" in upper_label and "COMPANY" not in upper_label:
        return "NAME (check if first/last)"
    if "ADDRESS" in upper_label:
        return "ADDRESS"
    if "NUM" in upper_label:
        return "(needs manual review — likely an ID type)"
    return "(unknown — needs manual review)"


@benchmark.command()
@click.option("--output", "-o", default="calibration.json", help="Save fitted calibration to JSON")
@click.option("--apply", "apply_cal", is_flag=True,
              help="Apply the fitted calibration as the active table")
@click.pass_context
def calibrate(ctx, output, apply_cal):
    """Fit GLiNER Platt scaling calibration from benchmark data.

    Runs the ML benchmark, collects (label, raw_score, is_correct) triples
    from the evaluation matches, and fits per-label Platt parameters using
    grid search to minimise log-loss.

    Example:
        openlabels benchmark calibrate -n 10000
        openlabels benchmark calibrate -n 10000 --apply
    """
    from openlabels.core.benchmark.evaluate import MatchType
    from openlabels.core.benchmark.harness import BenchmarkConfig, run_benchmark
    from openlabels.core.detectors.gliner_calibration import (
        GLINER_CALIBRATION,
        fit_calibration,
        load_calibration,
        reset_calibration,
        save_calibration,
    )
    from openlabels.core.types import normalize_entity_type

    samples_n = ctx.obj["samples"]
    seed = ctx.obj["seed"]
    dataset = ctx.obj.get("dataset", "ai4privacy")
    language = ctx.obj.get("language")
    model_dir = ctx.obj.get("model_dir")
    refresh_cache = ctx.obj.get("refresh_cache", False)

    click.echo(f"Calibration fitting | Dataset: {dataset} | Samples: {samples_n}")
    click.echo("=" * 60)

    # Build reverse map: canonical entity type -> primary GLiNER label
    from openlabels.core.detectors.gliner import GLINER_LABEL_MAP
    reverse_map: dict[str, str] = {}
    for gliner_label, canonical_type in GLINER_LABEL_MAP.items():
        if canonical_type not in reverse_map:
            reverse_map[canonical_type] = gliner_label

    # Configure: enable ML, lower thresholds to capture full score distribution.
    # Entity thresholds set to empty so only ml_confidence_threshold applies.
    config = BenchmarkConfig(
        name="calibrate",
        enable_ml=True,
        enable_phi=True,
        gliner_threshold=0.4,
        ml_confidence_threshold=0.01,
        confidence_threshold=0.01,
        entity_thresholds=(),
        enable_context_keywords=False,  # No score modification for clean raw data
        enable_proximity_boost=False,
        ml_model_dir=model_dir,
    )

    loaded_samples = _load_dataset_samples(
        dataset, samples_n, seed, language=language, refresh_cache=refresh_cache,
    )

    click.echo("Running benchmark with ML enabled...")
    try:
        result = run_benchmark(
            samples=loaded_samples,
            config=config,
            seed=seed,
            progress_callback=_cli_progress,
        )
    except Exception as e:
        click.echo(f"\nError during benchmark: {e}", err=True)
        return

    click.echo("")

    # Collect calibration triples from evaluation matches
    labels: list[str] = []
    raw_scores: list[float] = []
    is_correct: list[bool] = []
    skipped = 0

    for sr in result.sample_results:
        for m in sr.matches:
            if m.pred is None:
                continue
            # Only GLiNER spans have raw_confidence set
            if m.pred.raw_confidence is None or m.pred.detector_label is None:
                continue

            labels.append(m.pred.detector_label)
            raw_scores.append(m.pred.raw_confidence)

            if m.match_type in (MatchType.EXACT, MatchType.PARTIAL):
                is_correct.append(True)
            else:
                is_correct.append(False)

    if not labels:
        click.echo("No GLiNER predictions found — cannot fit calibration.", err=True)
        return

    # Count TP/FP per label for diagnostics
    tp_count: dict[str, int] = {}
    fp_count: dict[str, int] = {}
    for lbl, correct in zip(labels, is_correct):
        if correct:
            tp_count[lbl] = tp_count.get(lbl, 0) + 1
        else:
            fp_count[lbl] = fp_count.get(lbl, 0) + 1

    click.echo(f"Collected {len(labels)} predictions from GLiNER "
               f"({sum(1 for c in is_correct if c)} TP, "
               f"{sum(1 for c in is_correct if not c)} FP)")

    # Fit Platt parameters
    new_params = fit_calibration(labels, raw_scores, is_correct)

    # Save to JSON
    try:
        validated = validate_output_path(output, create_parent=True)
    except PathValidationError as e:
        click.echo(f"Error: Invalid output path: {e}", err=True)
        return
    save_calibration(new_params, validated)

    # Print comparison: old vs new
    click.echo(f"\nFitted {len(new_params)} labels | Saved to: {validated}")
    click.echo(f"\n{'Label':<30} {'Old T':>6} {'Old B':>7}  {'New T':>6} {'New B':>7}"
               f"  {'TP':>5} {'FP':>5}")
    click.echo("-" * 82)
    for label in sorted(new_params):
        old = GLINER_CALIBRATION.get(label, (1.0, 0.0))
        new = new_params[label]
        tp = tp_count.get(label, 0)
        fp = fp_count.get(label, 0)
        # Highlight labels with significant parameter changes
        t_delta = abs(new[0] - old[0])
        b_delta = abs(new[1] - old[1])
        marker = " *" if t_delta > 0.1 or b_delta > 0.05 else ""
        click.echo(f"{label:<30} {old[0]:>6.3f} {old[1]:>+7.4f}  "
                   f"{new[0]:>6.3f} {new[1]:>+7.4f}  {tp:>5} {fp:>5}{marker}")

    click.echo("\n  * = significant parameter shift (|dT|>0.1 or |dB|>0.05)")

    if apply_cal:
        load_calibration(validated)
        click.echo(f"\nApplied fitted calibration ({len(new_params)} labels active)")
    else:
        click.echo(f"\nTo apply: openlabels benchmark calibrate -n {samples_n} --apply")
        click.echo("To load manually: load_calibration('{output}')")


# ── Dataset loading ───────────────────────────────────────────────────

# Bundled Gretel dataset paths (relative to benchmark package)
_BENCHMARK_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "core" / "benchmark"


def _load_dataset_samples(
    dataset: str,
    sample_size: int,
    seed: int,
    *,
    language: str | None = None,
    refresh_cache: bool = False,
):
    """Load and return samples for the chosen dataset.

    Always returns a list of BenchmarkSample.  For ai4privacy, if more
    samples are requested than the bundled 1 k dataset provides, the full
    400 k dataset is automatically downloaded from HuggingFace.
    """
    if dataset == "ai4privacy" and language is None:
        from openlabels.core.benchmark.dataset import load_dataset as load_ai4privacy

        samples, source = load_ai4privacy(
            sample_size=sample_size, seed=seed, refresh_cache=refresh_cache,
        )
        click.echo(f"Loaded {len(samples)} samples from ai4privacy ({source})")
        return samples

    if dataset == "ai4privacy" and language is not None:
        # ai4privacy with language filter → use multilingual download
        from openlabels.core.benchmark.dataset import load_dataset as load_ai4privacy

        samples, source = load_ai4privacy(
            sample_size=sample_size, seed=seed,
            language=language, multilingual=True,
            refresh_cache=refresh_cache,
        )
        click.echo(f"Loaded {len(samples)} samples from ai4privacy [{language}] ({source})")
        return samples

    if dataset == "ai4privacy_multilingual":
        from openlabels.core.benchmark.dataset import load_dataset as load_ai4privacy

        samples, source = load_ai4privacy(
            sample_size=sample_size, seed=seed,
            language=language, multilingual=True,
            refresh_cache=refresh_cache,
        )
        lang_info = f" [{language}]" if language else " [all languages]"
        click.echo(f"Loaded {len(samples)} samples from ai4privacy{lang_info} ({source})")
        return samples

    if dataset == "nemotron_pii":
        from openlabels.core.benchmark.adapters import load_nemotron_pii

        samples, source = load_nemotron_pii(
            sample_size=sample_size, seed=seed, refresh_cache=refresh_cache,
        )
        click.echo(f"Loaded {len(samples)} samples from nemotron_pii ({source})")
        return samples

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
    if getattr(config, "enable_ml", False):
        from openlabels.core.detectors.gliner import DEFAULT_GLINER_MODEL
        click.echo(f"  GLiNER: {DEFAULT_GLINER_MODEL}")
        click.echo(f"  Multilingual GLiNER: E3-JSI/gliner-multi-pii-domains-v1 (language-gated)")
    if getattr(config, "enable_phi", False):
        click.echo(f"  Stanford PHI: {getattr(config, 'phi_model', 'StanfordAIMI/stanford-deidentifier-base')} (English-gated)")


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
        _print_type_mismatches(result)


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


def _print_type_mismatches(result) -> None:
    """Print type mismatch details when there are any."""
    from collections import Counter

    from openlabels.core.benchmark.evaluate import MatchType
    from openlabels.core.types import normalize_entity_type

    mismatch_pairs: Counter = Counter()
    miss_types: Counter = Counter()
    spurious_types: Counter = Counter()

    for sr in result.sample_results:
        for m in sr.matches:
            if m.match_type == MatchType.TYPE_MISMATCH and m.gold and m.pred:
                gold_t = normalize_entity_type(m.gold.entity_type)
                pred_t = normalize_entity_type(m.pred.entity_type)
                mismatch_pairs[(gold_t, pred_t)] += 1
            elif m.match_type == MatchType.MISS and m.gold:
                miss_types[m.gold.entity_type] += 1
            elif m.match_type == MatchType.SPURIOUS and m.pred:
                spurious_types[normalize_entity_type(m.pred.entity_type)] += 1

    if mismatch_pairs:
        click.echo(f"\nType mismatches ({sum(mismatch_pairs.values())} total):")
        click.echo(f"  {'Gold Type':<22} {'Pred Type':<22} {'Count':>5}")
        click.echo("  " + "-" * 52)
        for (gold, pred), count in mismatch_pairs.most_common(20):
            click.echo(f"  {gold:<22} -> {pred:<22} {count:>5}")

    if miss_types:
        click.echo(f"\nMisses by gold type ({sum(miss_types.values())} total):")
        for t, c in miss_types.most_common(15):
            click.echo(f"  {t:<25} {c:>4}")

    if spurious_types:
        click.echo(f"\nSpurious by pred type ({sum(spurious_types.values())} total):")
        for t, c in spurious_types.most_common(15):
            click.echo(f"  {t:<25} {c:>4}")


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


# ── Recalibrate subcommand ────────────────────────────────────────────

@benchmark.command()
@click.option("--output-dir", "-o", default="calibration_output",
              help="Directory to save calibration JSON files")
@click.option("--min-samples", default=10, type=int,
              help="Minimum predictions per label to fit calibration")
@click.pass_context
def recalibrate(ctx, output_dir, min_samples):
    """Fit Platt scaling calibration from benchmark predictions.

    Runs the benchmark with ML enabled, collects per-detector raw scores
    and match results, then fits optimal (temperature, bias) per label
    per detector using grid search over log-loss.

    Output files:
      calibration_output/gliner_calibration.json
      calibration_output/multilingual_calibration.json
      calibration_output/phi_calibration.json

    Load these into the pipeline with load_calibration() or
    load_multilingual_calibration().

    Example:
      openlabels benchmark recalibrate -d nemotron_pii -n 1000 --ml
    """
    import json

    from openlabels.core.benchmark.evaluate import MatchType
    from openlabels.core.benchmark.harness import (
        get_preset,
        run_benchmark,
    )

    samples_count = ctx.obj["samples"]
    seed = ctx.obj["seed"]
    dataset = ctx.obj.get("dataset", "ai4privacy")
    language = ctx.obj.get("language")
    refresh_cache = ctx.obj.get("refresh_cache", False)

    config = get_preset("with_ml")
    config.enable_ml = True
    config.enable_phi = True

    click.echo(f"Recalibration: dataset={dataset}, samples={samples_count}")
    click.echo(f"Min samples per label: {min_samples}")
    click.echo("-" * 60)

    loaded_samples = _load_dataset_samples(
        dataset, samples_count, seed,
        language=language, refresh_cache=refresh_cache,
    )

    result = run_benchmark(
        samples=loaded_samples,
        config=config,
        seed=seed,
        progress_callback=_cli_progress,
    )

    click.echo("")
    click.echo(f"Detectors: {', '.join(result.detectors_loaded)}")
    s = result.summary()
    click.echo(f"Baseline F1: {s['f1']:.4f} (P={s['precision']:.4f} R={s['recall']:.4f})")
    click.echo("")

    # Collect per-detector calibration data from match results.
    # Each prediction has: detector name, detector_label (GLiNER label),
    # raw_confidence, and whether it was a TP/partial/type_mismatch.
    detector_data: dict[str, dict[str, list[tuple[float, bool]]]] = {}

    for sr in result.sample_results:
        for match in sr.matches:
            if match.pred is None:
                continue
            detector = match.pred.detector
            label = match.pred.detector_label
            raw = match.pred.raw_confidence
            if label is None or raw is None:
                continue

            is_correct = match.match_type in (
                MatchType.EXACT, MatchType.PARTIAL,
            )

            detector_data.setdefault(detector, {}).setdefault(label, []).append(
                (raw, is_correct)
            )

    if not detector_data:
        click.echo("No ML predictions with raw_confidence found. "
                    "Ensure ML detectors are loaded (--ml).", err=True)
        return

    # Fit calibration per detector.
    from openlabels.core.detectors.gliner_calibration import fit_calibration

    out_path = Path(output_dir)
    try:
        validated = validate_output_path(str(out_path), create_parent=True)
        out_path = Path(validated) if validated != out_path else out_path
    except Exception:
        pass
    out_path.mkdir(parents=True, exist_ok=True)

    for detector_name, label_data in sorted(detector_data.items()):
        labels: list[str] = []
        raw_scores: list[float] = []
        is_correct: list[bool] = []

        for label, pairs in label_data.items():
            for raw, correct in pairs:
                labels.append(label)
                raw_scores.append(raw)
                is_correct.append(correct)

        total_preds = len(labels)
        total_tp = sum(is_correct)
        click.echo(f"Detector: {detector_name}")
        click.echo(f"  Predictions: {total_preds} ({total_tp} TP, "
                    f"{total_preds - total_tp} FP)")
        click.echo(f"  Unique labels: {len(label_data)}")

        calibration = fit_calibration(
            labels, raw_scores, is_correct,
            min_samples=min_samples,
        )

        # Show top results.
        click.echo(f"  Fitted {len(calibration)} labels:")
        for label, (temp, bias) in sorted(
            calibration.items(),
            key=lambda x: -x[1][0],  # Sort by temperature (most damped first)
        )[:10]:
            count = len(label_data.get(label, []))
            tp = sum(1 for _, c in label_data.get(label, []) if c)
            click.echo(f"    {label:<30} temp={temp:.2f} bias={bias:+.3f} "
                        f"({tp}/{count} TP)")
        if len(calibration) > 10:
            click.echo(f"    ... and {len(calibration) - 10} more")

        # Map detector name to output filename.
        file_map = {
            "gliner": "gliner_calibration.json",
            "gliner_multilingual": "multilingual_calibration.json",
            "stanford_phi": "phi_calibration.json",
        }
        fname = file_map.get(detector_name, f"{detector_name}_calibration.json")
        fpath = out_path / fname

        with open(fpath, "w") as f:
            json.dump(
                {k: list(v) for k, v in calibration.items()},
                f, indent=2, sort_keys=True,
            )
        click.echo(f"  Saved: {fpath}")
        click.echo("")

    click.echo("Done! Load calibration files with:")
    click.echo("  from openlabels.core.detectors.gliner_calibration import load_calibration")
    click.echo("  load_calibration('calibration_output/gliner_calibration.json')")

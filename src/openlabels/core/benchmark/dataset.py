"""Loader for the ai4privacy pii-masking-400k dataset.

Downloads and caches the dataset from Hugging Face, filters to English,
and converts annotations to a format compatible with the OpenLabels
evaluation harness.

The dataset ``privacy_mask`` field is a JSON-encoded list of dicts::

    [{"value": "John", "start": 10, "end": 14, "label": "FIRSTNAME"}, ...]

We parse these into ``GoldSpan`` dataclass instances with entity types
mapped through ``entity_mapping.map_entity_type``.
"""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path

from .entity_mapping import map_entity_type

logger = logging.getLogger(__name__)

# Default cache location
_CACHE_DIR = Path.home() / ".cache" / "openlabels" / "benchmark"

# Bundled dataset shipped with the package
_BUNDLED_PATH = Path(__file__).parent / "ai4privacy.jsonl"


@dataclass(frozen=True)
class GoldSpan:
    """A ground-truth PII annotation from the dataset."""

    start: int
    end: int
    text: str
    entity_type: str        # OpenLabels normalised type
    original_label: str     # Raw ai4privacy label


@dataclass
class BenchmarkSample:
    """A single text sample with its ground-truth annotations."""

    sample_id: int
    text: str
    gold_spans: list[GoldSpan] = field(default_factory=list)
    language: str = "en"

    @property
    def entity_types_present(self) -> set[str]:
        return {s.entity_type for s in self.gold_spans}


class DatasetLoadError(RuntimeError):
    """Raised when the ai4privacy dataset cannot be loaded."""


def load_dataset(
    *,
    sample_size: int | None = None,
    seed: int = 42,
    cache_dir: Path | None = None,
    min_entities: int = 1,
    max_text_length: int = 10_000,
) -> tuple[list[BenchmarkSample], str]:
    """Load samples from the ai4privacy PII dataset.

    Resolution order:
    1. HuggingFace cache (``~/.cache/openlabels/benchmark/ai4privacy_en.jsonl``)
    2. Bundled dataset shipped with the package
    3. Download from HuggingFace Hub (requires ``datasets`` package)

    Args:
        sample_size: Number of samples to return.  ``None`` = all.
        seed: Random seed for reproducible sub-sampling.
        cache_dir: Override default cache directory.
        min_entities: Minimum number of *mapped* gold entities per sample.
        max_text_length: Skip samples with text longer than this.

    Returns:
        Tuple of (list of ``BenchmarkSample`` instances, dataset source string).

    Raises:
        DatasetLoadError: If no ai4privacy samples can be loaded from any
            source.  This is intentionally a hard error — the benchmark must
            run against the real ai4privacy dataset.
    """
    cache_dir = cache_dir or _CACHE_DIR
    cache_path = cache_dir / "ai4privacy_en.jsonl"
    source = "unknown"

    if cache_path.exists():
        logger.info("Loading cached dataset from %s", cache_path)
        samples = _load_from_cache(cache_path)
        source = f"cache ({cache_path})"
        if not samples and _BUNDLED_PATH.exists():
            logger.warning(
                "Cache at %s returned 0 samples; falling back to bundled dataset",
                cache_path,
            )
            samples = _load_bundled(_BUNDLED_PATH)
            source = f"bundled ({_BUNDLED_PATH})"
    elif _BUNDLED_PATH.exists():
        logger.info("Loading bundled dataset from %s", _BUNDLED_PATH)
        samples = _load_bundled(_BUNDLED_PATH)
        source = f"bundled ({_BUNDLED_PATH})"
    else:
        logger.info("Downloading ai4privacy dataset (first run)...")
        samples = _download_and_cache(cache_dir, cache_path)
        source = f"huggingface (cached to {cache_path})"

    if not samples:
        raise DatasetLoadError(
            f"Failed to load ai4privacy dataset from any source.\n"
            f"  Cache path:   {cache_path} (exists={cache_path.exists()})\n"
            f"  Bundled path: {_BUNDLED_PATH} (exists={_BUNDLED_PATH.exists()})\n"
            f"Ensure the bundled ai4privacy.jsonl is present in the package, "
            f"or install the 'datasets' package to download from HuggingFace."
        )

    # Filter
    filtered: list[BenchmarkSample] = []
    skipped_text_len = 0
    skipped_min_ents = 0
    for s in samples:
        if len(s.text) > max_text_length:
            skipped_text_len += 1
            continue
        if len(s.gold_spans) < min_entities:
            skipped_min_ents += 1
            continue
        filtered.append(s)

    logger.info(
        "Dataset: %d total samples, %d after filtering "
        "(skipped %d too-long, %d below min_entities=%d)",
        len(samples),
        len(filtered),
        skipped_text_len,
        skipped_min_ents,
        min_entities,
    )

    if not filtered:
        raise DatasetLoadError(
            f"ai4privacy dataset loaded {len(samples)} samples but 0 passed "
            f"filtering (min_entities={min_entities}, "
            f"max_text_length={max_text_length}). "
            f"Check entity_mapping — all entity types may be unmapped."
        )

    if sample_size is not None and sample_size < len(filtered):
        rng = random.Random(seed)
        filtered = rng.sample(filtered, sample_size)

    return filtered, source


def _download_and_cache(
    cache_dir: Path,
    cache_path: Path,
) -> list[BenchmarkSample]:
    """Download dataset from Hugging Face and write English-only cache."""
    try:
        from datasets import load_dataset as hf_load
    except ImportError as exc:
        raise ImportError(
            "The 'datasets' package is required for benchmarking. "
            "Install it with: pip install datasets"
        ) from exc

    cache_dir.mkdir(parents=True, exist_ok=True)

    ds = hf_load("ai4privacy/pii-masking-400k", split="train")
    samples: list[BenchmarkSample] = []
    idx = 0

    for row in ds:
        if row.get("language") != "en":
            continue

        text = row.get("unmasked_text", "")
        if not text:
            continue

        privacy_mask_raw = row.get("privacy_mask", "[]")
        if isinstance(privacy_mask_raw, str):
            try:
                annotations = json.loads(privacy_mask_raw)
            except json.JSONDecodeError:
                continue
        elif isinstance(privacy_mask_raw, list):
            annotations = privacy_mask_raw
        else:
            continue

        gold_spans = _parse_annotations(text, annotations)

        samples.append(BenchmarkSample(
            sample_id=idx,
            text=text,
            gold_spans=gold_spans,
            language="en",
        ))
        idx += 1

    # Persist cache
    with open(cache_path, "w", encoding="utf-8") as f:
        for s in samples:
            record = {
                "id": s.sample_id,
                "text": s.text,
                "spans": [
                    {
                        "start": g.start,
                        "end": g.end,
                        "text": g.text,
                        "entity_type": g.entity_type,
                        "original_label": g.original_label,
                    }
                    for g in s.gold_spans
                ],
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    logger.info("Cached %d English samples to %s", len(samples), cache_path)
    return samples


def _load_bundled(path: Path) -> list[BenchmarkSample]:
    """Load the bundled ai4privacy JSONL dataset.

    Expects ``{"id": ..., "text": ..., "entities": [{"start", "end", "text", "label"}, ...]}``
    format.  Entity types are mapped through ``map_entity_type``.
    """
    samples: list[BenchmarkSample] = []
    with open(path, encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            text = record.get("text", "")
            if not text:
                continue
            entities = record.get("entities", [])
            gold_spans = _parse_annotations(text, entities)
            samples.append(BenchmarkSample(
                sample_id=idx,
                text=text,
                gold_spans=gold_spans,
                language="en",
            ))
    return samples


def _load_from_cache(cache_path: Path) -> list[BenchmarkSample]:
    """Read the JSONL cache file."""
    samples: list[BenchmarkSample] = []
    with open(cache_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            gold_spans = [
                GoldSpan(
                    start=s["start"],
                    end=s["end"],
                    text=s["text"],
                    entity_type=s["entity_type"],
                    original_label=s["original_label"],
                )
                for s in record["spans"]
            ]
            samples.append(BenchmarkSample(
                sample_id=record["id"],
                text=record["text"],
                gold_spans=gold_spans,
                language="en",
            ))
    return samples


def _parse_annotations(
    text: str,
    annotations: list[dict],
) -> list[GoldSpan]:
    """Convert raw ai4privacy ``privacy_mask`` entries to ``GoldSpan``s.

    Filters out unmapped entity types and validates character offsets.
    """
    gold: list[GoldSpan] = []
    for ann in annotations:
        raw_label = ann.get("label", "")
        start = ann.get("start")
        end = ann.get("end")
        value = ann.get("value", "") or ann.get("text", "")

        if start is None or end is None:
            continue
        start, end = int(start), int(end)

        # Skip unmapped types
        mapped = map_entity_type(raw_label)
        if mapped is None:
            continue

        # Validate offsets
        if start < 0 or end <= start or end > len(text):
            continue

        # Use text slice if value disagrees with offsets
        actual_text = text[start:end]
        if value and value != actual_text:
            # Trust offsets over the value field
            value = actual_text

        gold.append(GoldSpan(
            start=start,
            end=end,
            text=value or actual_text,
            entity_type=mapped,
            original_label=raw_label,
        ))

    return gold

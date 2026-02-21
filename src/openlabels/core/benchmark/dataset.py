"""Loader for the ai4privacy pii-masking-400k dataset.

Downloads and caches the dataset from Hugging Face.  Supports both
English-only mode (default, backwards-compatible) and multilingual mode
which preserves the language field for benchmarking language-gated detection.

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

# Languages in the ai4privacy dataset that the multilingual GLiNER supports.
SUPPORTED_LANGUAGES = frozenset({
    "en", "es", "fr", "pt", "de", "it", "el", "nl", "sl",
})


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
    language: str | None = None,
    multilingual: bool = False,
) -> tuple[list[BenchmarkSample], str]:
    """Load samples from the ai4privacy PII dataset.

    Resolution order:
    1. HuggingFace cache (``~/.cache/openlabels/benchmark/ai4privacy_*.jsonl``)
    2. Bundled dataset shipped with the package (English only)
    3. Download from HuggingFace Hub (requires ``datasets`` package)

    Args:
        sample_size: Number of samples to return.  ``None`` = all.
        seed: Random seed for reproducible sub-sampling.
        cache_dir: Override default cache directory.
        min_entities: Minimum number of *mapped* gold entities per sample.
        max_text_length: Skip samples with text longer than this.
        language: Filter to a specific ISO 639-1 language code (e.g. "fr").
            ``None`` with ``multilingual=False`` defaults to English.
        multilingual: If True, load all supported languages from HuggingFace.
            The bundled dataset only contains English, so multilingual mode
            requires the ``datasets`` package for first-time download.

    Returns:
        Tuple of (list of ``BenchmarkSample`` instances, dataset source string).

    Raises:
        DatasetLoadError: If no ai4privacy samples can be loaded from any
            source.
    """
    cache_dir = cache_dir or _CACHE_DIR

    if multilingual or (language is not None and language != "en"):
        # Multilingual path — download all supported languages from HF
        cache_path = cache_dir / "ai4privacy_multilingual.jsonl"
        samples, source = _load_multilingual(cache_dir, cache_path)
        # Filter to specific language if requested
        if language is not None:
            samples = [s for s in samples if s.language == language]
            source = f"{source} [lang={language}]"
    else:
        # English-only path (backwards compatible)
        cache_path = cache_dir / "ai4privacy_en.jsonl"
        samples, source = _load_english(cache_dir, cache_path)

    if not samples:
        raise DatasetLoadError(
            f"Failed to load ai4privacy dataset from any source.\n"
            f"  Cache path:   {cache_path} (exists={cache_path.exists()})\n"
            f"  Bundled path: {_BUNDLED_PATH} (exists={_BUNDLED_PATH.exists()})\n"
            f"Ensure the bundled ai4privacy.jsonl is present in the package, "
            f"or install the 'datasets' package to download from HuggingFace:\n"
            f"  pip install 'openlabels[benchmark]'"
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
    elif sample_size is not None and sample_size > len(filtered):
        logger.warning(
            "Requested %d samples but only %d available after filtering. "
            "Returning all %d.",
            sample_size,
            len(filtered),
            len(filtered),
        )

    return filtered, source


# ── English-only loading (backwards compatible) ─────────────────────


def _load_english(
    cache_dir: Path,
    cache_path: Path,
) -> tuple[list[BenchmarkSample], str]:
    """Load English-only samples, always preferring the full 400 k dataset.

    Resolution order:
    1. JSONL cache (full dataset, written after first download).
    2. Download from HuggingFace Hub (requires ``datasets`` package).
    3. Bundled ≈1 k sample dataset (last-resort fallback).
    """
    # 1. Cached full dataset
    if cache_path.exists():
        logger.info("Loading cached dataset from %s", cache_path)
        samples = _load_from_cache(cache_path)
        if samples:
            return samples, f"cache ({cache_path})"
        logger.warning(
            "Cache at %s returned 0 samples; will re-download", cache_path,
        )
        cache_path.unlink(missing_ok=True)

    # 2. Download full 400k from HuggingFace
    try:
        logger.info("Downloading full ai4privacy dataset from HuggingFace...")
        samples = _download_and_cache(cache_dir, cache_path, languages={"en"})
        if samples:
            return samples, f"huggingface (cached to {cache_path})"
    except ImportError:
        logger.warning(
            "The 'datasets' package is not installed — cannot download "
            "full dataset from HuggingFace.  Install with: "
            "pip install 'openlabels[benchmark]'"
        )

    # 3. Bundled fallback
    if _BUNDLED_PATH.exists():
        logger.warning(
            "Falling back to bundled dataset (%s). Install "
            "'openlabels[benchmark]' to download the full 400k dataset.",
            _BUNDLED_PATH,
        )
        samples = _load_bundled(_BUNDLED_PATH)
        return samples, f"bundled ({_BUNDLED_PATH})"

    return [], "none"


# ── Multilingual loading ────────────────────────────────────────────


def _load_multilingual(
    cache_dir: Path,
    cache_path: Path,
) -> tuple[list[BenchmarkSample], str]:
    """Load multilingual samples from HuggingFace, caching locally.

    Fallback chain:
    1. JSONL cache (``ai4privacy_multilingual.jsonl``)
    2. Download from HuggingFace (requires ``datasets`` package)
    3. Bundled English-only dataset (partial coverage, with warning)
    """
    # 1. Try cache
    if cache_path.exists():
        logger.info("Loading cached multilingual dataset from %s", cache_path)
        samples = _load_from_cache(cache_path)
        if samples:
            lang_counts = _count_languages(samples)
            logger.info("Multilingual cache: %s", lang_counts)
            return samples, f"cache ({cache_path})"
        # Cache file exists but is empty/corrupt — remove it so a future
        # run can re-download cleanly.
        logger.warning(
            "Cache at %s returned 0 samples; removing stale file", cache_path,
        )
        cache_path.unlink(missing_ok=True)

    # 2. Try downloading from HuggingFace
    try:
        logger.info("Downloading ai4privacy multilingual dataset...")
        samples = _download_and_cache(
            cache_dir, cache_path, languages=SUPPORTED_LANGUAGES,
        )
        if samples:
            lang_counts = _count_languages(samples)
            logger.info("Downloaded multilingual dataset: %s", lang_counts)
        return samples, f"huggingface multilingual (cached to {cache_path})"
    except ImportError:
        logger.warning(
            "The 'datasets' package is not installed — cannot download "
            "multilingual data from HuggingFace. Install with: "
            "pip install 'openlabels[benchmark]'"
        )

    # 3. Fall back to bundled English-only dataset
    if _BUNDLED_PATH.exists():
        logger.warning(
            "Falling back to bundled English-only dataset for multilingual "
            "benchmark.  Install 'openlabels[benchmark]' and re-run to get "
            "full multilingual coverage."
        )
        samples = _load_bundled(_BUNDLED_PATH)
        return samples, f"bundled-en-fallback ({_BUNDLED_PATH})"

    return [], "none"


def _count_languages(samples: list[BenchmarkSample]) -> dict[str, int]:
    """Count samples per language."""
    counts: dict[str, int] = {}
    for s in samples:
        counts[s.language] = counts.get(s.language, 0) + 1
    return dict(sorted(counts.items()))


# ── Download and cache ──────────────────────────────────────────────


def _download_and_cache(
    cache_dir: Path,
    cache_path: Path,
    *,
    languages: set[str] | None = None,
) -> list[BenchmarkSample]:
    """Download dataset from Hugging Face and write cache.

    Args:
        cache_dir: Directory for cache files.
        cache_path: Path to the JSONL cache file.
        languages: Set of ISO 639-1 codes to include.  ``None`` = all.
    """
    try:
        from datasets import load_dataset as hf_load
    except ImportError as exc:
        raise ImportError(
            "The 'datasets' package is required for downloading benchmark data. "
            "Install it with: pip install 'openlabels[benchmark]'"
        ) from exc

    cache_dir.mkdir(parents=True, exist_ok=True)

    ds = hf_load("ai4privacy/pii-masking-400k", split="train")
    samples: list[BenchmarkSample] = []
    idx = 0

    for row in ds:
        lang = row.get("language", "en")
        if languages is not None and lang not in languages:
            continue

        # The 400k dataset renamed "unmasked_text" → "source_text"
        text = row.get("source_text") or row.get("unmasked_text", "")
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
            language=lang,
        ))
        idx += 1

    # Persist cache (only if we got samples — avoid creating empty files
    # that would block future re-downloads)
    if not samples:
        logger.warning(
            "HuggingFace download returned 0 samples for languages=%s; "
            "skipping cache write",
            languages,
        )
        return samples

    with open(cache_path, "w", encoding="utf-8") as f:
        for s in samples:
            record = {
                "id": s.sample_id,
                "text": s.text,
                "language": s.language,
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

    logger.info("Cached %d samples to %s", len(samples), cache_path)
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
                language=record.get("language", "en"),
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
                language=record.get("language", "en"),
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

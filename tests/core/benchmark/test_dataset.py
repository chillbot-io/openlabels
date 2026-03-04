"""Tests for the benchmark dataset loader.

These tests do NOT download the full ai4privacy dataset.  They exercise
the parsing and caching logic using synthetic data.
"""

import json
import tempfile
from pathlib import Path

from openlabels.core.benchmark.dataset import (
    BenchmarkSample,
    GoldSpan,
    _load_from_cache,
    _load_multilingual,
    _parse_annotations,
    load_dataset,
)


class TestParseAnnotations:
    """Test annotation parsing from ai4privacy privacy_mask format."""

    def test_basic_annotation(self):
        text = "My name is John Smith and I live in NYC"
        annotations = [
            {"value": "John Smith", "start": 11, "end": 21, "label": "FIRSTNAME"},
            {"value": "NYC", "start": 35, "end": 38, "label": "CITY"},
        ]

        spans = _parse_annotations(text, annotations)

        assert len(spans) == 2
        assert spans[0].entity_type == "FIRSTNAME"
        assert spans[0].start == 11
        assert spans[0].end == 21
        assert spans[0].text == "John Smith"
        assert spans[1].entity_type == "CITY"

    def test_unmapped_types_filtered(self):
        text = "Gender: Male, Salary: $50000"
        annotations = [
            {"value": "Male", "start": 8, "end": 12, "label": "GENDER"},
            {"value": "$50000", "start": 21, "end": 27, "label": "SALARY"},
        ]

        spans = _parse_annotations(text, annotations)

        # Both GENDER and SALARY are in UNMAPPED_TYPES
        assert len(spans) == 0

    def test_invalid_offsets_skipped(self):
        text = "Short text"
        annotations = [
            {"value": "bad", "start": -1, "end": 5, "label": "NAME"},
            {"value": "bad", "start": 5, "end": 5, "label": "NAME"},  # start == end
            {"value": "bad", "start": 0, "end": 100, "label": "NAME"},  # beyond text
        ]

        spans = _parse_annotations(text, annotations)
        assert len(spans) == 0

    def test_missing_fields_skipped(self):
        text = "Some text here"
        annotations = [
            {"value": "text", "label": "NAME"},  # Missing start/end
            {"label": "NAME"},  # Missing everything
        ]

        spans = _parse_annotations(text, annotations)
        assert len(spans) == 0

    def test_entity_type_mapping(self):
        text = "SSN: 123-45-6789, Email: test@example.com"
        annotations = [
            {"value": "123-45-6789", "start": 5, "end": 16, "label": "SOCIALSECURITYNUMBER"},
            {"value": "test@example.com", "start": 25, "end": 41, "label": "EMAIL"},
        ]

        spans = _parse_annotations(text, annotations)

        assert len(spans) == 2
        assert spans[0].entity_type == "SSN"
        assert spans[0].original_label == "SOCIALSECURITYNUMBER"
        assert spans[1].entity_type == "EMAIL"

    def test_value_offset_mismatch_trusts_offsets(self):
        text = "My name is John Smith"
        annotations = [
            # Value doesn't match the actual text at those offsets
            {"value": "Wrong Value", "start": 11, "end": 21, "label": "FIRSTNAME"},
        ]

        spans = _parse_annotations(text, annotations)

        assert len(spans) == 1
        assert spans[0].text == "John Smith"  # Trusts the offsets


class TestBenchmarkSample:
    """Test the BenchmarkSample dataclass."""

    def test_entity_types_present(self):
        sample = BenchmarkSample(
            sample_id=0,
            text="test",
            gold_spans=[
                GoldSpan(0, 4, "John", "NAME", "FIRSTNAME"),
                GoldSpan(10, 21, "123-45-6789", "SSN", "SSN"),
            ],
        )

        assert sample.entity_types_present == {"NAME", "SSN"}


class TestCacheRoundTrip:
    """Test that writing to cache and reading back preserves data."""

    def test_cache_roundtrip(self):
        samples = [
            BenchmarkSample(
                sample_id=0,
                text="John Smith lives at 123 Main St",
                gold_spans=[
                    GoldSpan(0, 10, "John Smith", "FIRSTNAME", "FIRSTNAME"),
                    GoldSpan(20, 31, "123 Main St", "ADDRESS", "STREETADDRESS"),
                ],
            ),
            BenchmarkSample(
                sample_id=1,
                text="Call 555-1234",
                gold_spans=[
                    GoldSpan(5, 13, "555-1234", "PHONE", "PHONENUMBER"),
                ],
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "test_cache.jsonl"

            # Write
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
                    f.write(json.dumps(record) + "\n")

            # Read back
            loaded = _load_from_cache(cache_path)

            assert len(loaded) == 2
            assert loaded[0].sample_id == 0
            assert loaded[0].text == "John Smith lives at 123 Main St"
            assert len(loaded[0].gold_spans) == 2
            assert loaded[0].gold_spans[0].entity_type == "FIRSTNAME"
            assert loaded[0].gold_spans[0].start == 0
            assert loaded[0].gold_spans[0].end == 10

            assert loaded[1].sample_id == 1
            assert len(loaded[1].gold_spans) == 1
            assert loaded[1].gold_spans[0].entity_type == "PHONE"


class TestLoadDatasetFiltering:
    """Test dataset filtering logic (uses cached data)."""

    def test_min_entities_filter(self):
        """Samples with no mapped entities should be filtered out."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "ai4privacy_en.jsonl"

            # Write samples: one with entities, one without
            records = [
                {
                    "id": 0,
                    "text": "John Smith",
                    "spans": [{"start": 0, "end": 10, "text": "John Smith",
                              "entity_type": "FIRSTNAME", "original_label": "FIRSTNAME"}],
                },
                {
                    "id": 1,
                    "text": "No entities here",
                    "spans": [],
                },
            ]
            with open(cache_path, "w") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            samples, source = load_dataset(
                cache_dir=Path(tmpdir),
                min_entities=1,
            )

            assert len(samples) == 1
            assert samples[0].sample_id == 0
            assert "cache" in source

    def test_max_text_length_filter(self):
        """Samples exceeding max_text_length should be filtered out."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "ai4privacy_en.jsonl"

            records = [
                {
                    "id": 0,
                    "text": "Short",
                    "spans": [{"start": 0, "end": 5, "text": "Short",
                              "entity_type": "NAME", "original_label": "NAME"}],
                },
                {
                    "id": 1,
                    "text": "x" * 20000,
                    "spans": [{"start": 0, "end": 4, "text": "xxxx",
                              "entity_type": "NAME", "original_label": "NAME"}],
                },
            ]
            with open(cache_path, "w") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            samples, _source = load_dataset(
                cache_dir=Path(tmpdir),
                max_text_length=100,
            )

            assert len(samples) == 1
            assert samples[0].sample_id == 0

    def test_sample_size_subsampling(self):
        """sample_size should randomly subsample from filtered set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "ai4privacy_en.jsonl"

            records = []
            for i in range(10):
                records.append({
                    "id": i,
                    "text": f"Name{i}",
                    "spans": [{"start": 0, "end": 5, "text": f"Name{i}",
                              "entity_type": "NAME", "original_label": "NAME"}],
                })
            with open(cache_path, "w") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            samples, _source = load_dataset(
                cache_dir=Path(tmpdir),
                sample_size=3,
                seed=42,
            )

            assert len(samples) == 3

            # Same seed should give same samples
            samples2, _source2 = load_dataset(
                cache_dir=Path(tmpdir),
                sample_size=3,
                seed=42,
            )
            assert [s.sample_id for s in samples] == [s.sample_id for s in samples2]


class TestMultilingualFallback:
    """Test _load_multilingual fallback chain."""

    def test_multilingual_loads_from_cache(self):
        """Valid multilingual cache should be loaded directly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_path = cache_dir / "ai4privacy_multilingual.jsonl"

            records = [
                {
                    "id": 0,
                    "text": "Jean Dupont habite à Paris",
                    "language": "fr",
                    "spans": [{"start": 0, "end": 11, "text": "Jean Dupont",
                              "entity_type": "FIRSTNAME", "original_label": "FIRSTNAME"}],
                },
                {
                    "id": 1,
                    "text": "John Smith lives in NYC",
                    "language": "en",
                    "spans": [{"start": 0, "end": 10, "text": "John Smith",
                              "entity_type": "FIRSTNAME", "original_label": "FIRSTNAME"}],
                },
            ]
            with open(cache_path, "w") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            samples, source = _load_multilingual(cache_dir, cache_path)

            assert len(samples) == 2
            assert "cache" in source
            assert samples[0].language == "fr"
            assert samples[1].language == "en"

    def test_multilingual_removes_empty_cache(self):
        """Empty cache file should be removed so re-download can succeed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_path = cache_dir / "ai4privacy_multilingual.jsonl"

            # Create empty cache file
            cache_path.touch()
            assert cache_path.exists()

            # _load_multilingual should remove the empty cache and fall back
            # to bundled English data (since datasets isn't installed)
            samples, source = _load_multilingual(cache_dir, cache_path)

            assert not cache_path.exists(), "Empty cache file should have been removed"
            assert len(samples) > 0, "Should fall back to bundled English data"
            assert "bundled" in source

    def test_multilingual_falls_back_to_bundled_without_datasets(self):
        """Without datasets package and no cache, should fall back to bundled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_path = cache_dir / "ai4privacy_multilingual.jsonl"
            # No cache file exists, datasets not installed → bundled fallback

            samples, source = _load_multilingual(cache_dir, cache_path)

            assert len(samples) > 0, "Should fall back to bundled English data"
            assert "bundled" in source

    def test_multilingual_fallback_integrates_with_load_dataset(self):
        """load_dataset(multilingual=True) should not crash without datasets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # No cache, no datasets package → should fall back to bundled
            samples, source = load_dataset(
                cache_dir=Path(tmpdir),
                multilingual=True,
                sample_size=5,
            )

            assert len(samples) == 5
            # All samples from bundled are English
            assert all(s.language == "en" for s in samples)

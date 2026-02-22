"""Tests for the NVIDIA Nemotron-PII dataset adapter.

These tests exercise parsing, caching, and entity mapping logic
using synthetic data — no HuggingFace download required.
"""

import json
import tempfile
from pathlib import Path

import pytest

from openlabels.core.benchmark.adapters import (
    NEMOTRON_TO_OPENLABELS,
    _load_nemotron_cache,
    _map_entity,
    _parse_pii_spans,
    load_nemotron_pii,
)
from openlabels.core.benchmark.dataset import BenchmarkSample, GoldSpan


class TestNemotronEntityMapping:
    """Test NEMOTRON_TO_OPENLABELS entity type mapping."""

    def test_core_types_mapped(self):
        """Core PII types should map to OpenLabels equivalents."""
        expected = {
            "name": "NAME",
            "first_name": "FIRSTNAME",
            "last_name": "LASTNAME",
            "email": "EMAIL",
            "phone_number": "PHONE",
            "ssn": "SSN",
            "address": "ADDRESS",
            "credit_card_number": "CREDIT_CARD",
            "ip_address": "IP_ADDRESS",
            "user_name": "USERNAME",
            "date_of_birth": "DATE_DOB",
            "password": "PASSWORD",
            "api_key": "API_KEY",
            "url": "URL",
            "medical_record_number": "MRN",
            "national_id": "STATE_ID",
            "tax_id": "TAX_ID",
            "account_number": "ACCOUNT_NUMBER",
            "license_plate": "LICENSE_PLATE",
        }
        for nemotron_label, openlabels_type in expected.items():
            mapped = _map_entity(nemotron_label, NEMOTRON_TO_OPENLABELS)
            assert mapped == openlabels_type, (
                f"{nemotron_label!r} should map to {openlabels_type!r}, got {mapped!r}"
            )

    def test_excluded_types(self):
        """Types mapped to None should be excluded."""
        assert _map_entity("cvv", NEMOTRON_TO_OPENLABELS) is None

    def test_unknown_types_passthrough(self):
        """Unknown types should pass through as UPPER_CASE."""
        result = _map_entity("some_unknown_type", NEMOTRON_TO_OPENLABELS)
        assert result == "SOME_UNKNOWN_TYPE"


class TestNemotronSpanParsing:
    """Test parsing Nemotron-PII span annotations."""

    def test_basic_spans(self):
        text = "Contact johndoe88 at johnd@example.com or (555) 123-4567"
        spans = [
            {"start": 8, "end": 17, "text": "johndoe88", "label": "user_name"},
            {"start": 21, "end": 38, "text": "johnd@example.com", "label": "email"},
            {"start": 42, "end": 56, "text": "(555) 123-4567", "label": "phone_number"},
        ]

        gold = _parse_pii_spans(text, spans, NEMOTRON_TO_OPENLABELS)

        assert len(gold) == 3
        assert gold[0].entity_type == "USERNAME"
        assert gold[0].start == 8
        assert gold[0].end == 17
        assert gold[0].text == "johndoe88"
        assert gold[1].entity_type == "EMAIL"
        assert gold[2].entity_type == "PHONE"

    def test_excluded_types_filtered(self):
        text = "CVV is 123"
        spans = [
            {"start": 7, "end": 10, "text": "123", "label": "cvv"},
        ]

        gold = _parse_pii_spans(text, spans, NEMOTRON_TO_OPENLABELS)
        assert len(gold) == 0

    def test_invalid_offsets_skipped(self):
        text = "Short"
        spans = [
            {"start": 0, "end": 100, "text": "bad", "label": "name"},
            {"start": -1, "end": 3, "text": "bad", "label": "name"},
        ]

        gold = _parse_pii_spans(text, spans, NEMOTRON_TO_OPENLABELS)
        assert len(gold) == 0

    def test_missing_fields_skipped(self):
        text = "Some text"
        spans = [
            {"text": "Some", "label": "name"},  # missing start/end
            {"start": 0, "end": 4},  # missing label
        ]

        gold = _parse_pii_spans(text, spans, NEMOTRON_TO_OPENLABELS)
        assert len(gold) == 0


class TestNemotronCacheRoundTrip:
    """Test writing Nemotron-PII cache and reading it back."""

    def test_cache_roundtrip(self):
        samples = [
            BenchmarkSample(
                sample_id=0,
                text="Contact johndoe88 at johnd@example.com",
                gold_spans=[
                    GoldSpan(8, 17, "johndoe88", "USERNAME", "user_name"),
                    GoldSpan(21, 38, "johnd@example.com", "EMAIL", "email"),
                ],
            ),
            BenchmarkSample(
                sample_id=1,
                text="SSN: 123-45-6789",
                gold_spans=[
                    GoldSpan(5, 16, "123-45-6789", "SSN", "ssn"),
                ],
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "nemotron_pii.jsonl"

            # Write cache
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
                    f.write(json.dumps(record) + "\n")

            # Read back
            loaded = _load_nemotron_cache(cache_path)

            assert len(loaded) == 2
            assert loaded[0].sample_id == 0
            assert len(loaded[0].gold_spans) == 2
            assert loaded[0].gold_spans[0].entity_type == "USERNAME"
            assert loaded[0].gold_spans[0].original_label == "user_name"
            assert loaded[0].gold_spans[1].entity_type == "EMAIL"

            assert loaded[1].sample_id == 1
            assert len(loaded[1].gold_spans) == 1
            assert loaded[1].gold_spans[0].entity_type == "SSN"


class TestLoadNemotronPii:
    """Test the top-level load_nemotron_pii function."""

    def test_loads_from_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_path = cache_dir / "nemotron_pii.jsonl"

            records = [
                {
                    "id": i,
                    "text": f"Name{i} has SSN 123-45-678{i}",
                    "language": "en",
                    "spans": [
                        {"start": 0, "end": 5, "text": f"Name{i}",
                         "entity_type": "NAME", "original_label": "name"},
                        {"start": 15, "end": 26, "text": f"123-45-678{i}",
                         "entity_type": "SSN", "original_label": "ssn"},
                    ],
                }
                for i in range(10)
            ]
            with open(cache_path, "w") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            samples, source = load_nemotron_pii(
                cache_dir=cache_dir,
                sample_size=5,
                seed=42,
            )

            assert len(samples) == 5
            assert "cache" in source
            # All samples should have 2 gold spans
            for s in samples:
                assert len(s.gold_spans) == 2

    def test_min_entities_filter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_path = cache_dir / "nemotron_pii.jsonl"

            records = [
                {
                    "id": 0,
                    "text": "John Smith",
                    "language": "en",
                    "spans": [
                        {"start": 0, "end": 10, "text": "John Smith",
                         "entity_type": "NAME", "original_label": "name"},
                    ],
                },
                {
                    "id": 1,
                    "text": "No entities here",
                    "language": "en",
                    "spans": [],
                },
            ]
            with open(cache_path, "w") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            samples, source = load_nemotron_pii(
                cache_dir=cache_dir, min_entities=1,
            )

            assert len(samples) == 1
            assert samples[0].sample_id == 0

    def test_refresh_cache_deletes_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_path = cache_dir / "nemotron_pii.jsonl"

            # Create a cache file
            cache_path.write_text('{"id":0,"text":"x","language":"en","spans":[]}\n')
            assert cache_path.exists()

            # refresh_cache should delete it; without HF it will raise
            with pytest.raises(Exception):
                load_nemotron_pii(cache_dir=cache_dir, refresh_cache=True)

            assert not cache_path.exists()

    def test_remaps_on_cache_load(self):
        """Cache load should re-apply entity mapping from original_label."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_path = cache_dir / "nemotron_pii.jsonl"

            # Write cache with original_label that maps to a known type
            records = [
                {
                    "id": 0,
                    "text": "Call (555) 123-4567",
                    "language": "en",
                    "spans": [
                        {
                            "start": 5, "end": 19,
                            "text": "(555) 123-4567",
                            "entity_type": "OLD_TYPE",  # stale mapped type
                            "original_label": "phone_number",
                        },
                    ],
                },
            ]
            with open(cache_path, "w") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            samples, _ = load_nemotron_pii(cache_dir=cache_dir)

            # Should re-map phone_number → PHONE, not use stale OLD_TYPE
            assert samples[0].gold_spans[0].entity_type == "PHONE"

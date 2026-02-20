"""Tests for NER difficulty dimension classification.

Verifies that the Singh & Narayanan 2025 difficulty dimensions are
correctly assigned to benchmark samples.
"""

import pytest

from openlabels.core.benchmark.dataset import BenchmarkSample, GoldSpan
from openlabels.core.benchmark.dimensions import (
    NERDimension,
    classify_sample,
    classify_samples,
)


def _sample(
    sample_id=0,
    text="Contact John at john@example.com",
    gold_spans=None,
    language="en",
):
    if gold_spans is None:
        gold_spans = [
            GoldSpan(start=8, end=12, text="John", entity_type="NAME", original_label="FIRSTNAME"),
        ]
    return BenchmarkSample(
        sample_id=sample_id,
        text=text,
        gold_spans=gold_spans,
        language=language,
    )


class TestNERDimension:
    """Test the NERDimension enum."""

    def test_all_five_dimensions_exist(self):
        assert len(NERDimension) == 5
        assert NERDimension.BASIC.value == "basic"
        assert NERDimension.CONTEXTUAL.value == "contextual"
        assert NERDimension.NOISY.value == "noisy"
        assert NERDimension.NOVEL.value == "novel"
        assert NERDimension.CROSS_LINGUAL.value == "cross_lingual"


class TestClassifySample:
    """Test individual sample classification."""

    def test_basic_always_present(self):
        sample = _sample()
        dims = classify_sample(sample)
        assert NERDimension.BASIC in dims

    def test_contextual_with_ambiguous_name(self):
        """'May' is both a name and a month — should be CONTEXTUAL."""
        sample = _sample(
            text="May said hello",
            gold_spans=[
                GoldSpan(start=0, end=3, text="May", entity_type="NAME", original_label="FIRSTNAME"),
            ],
        )
        dims = classify_sample(sample)
        assert NERDimension.CONTEXTUAL in dims

    def test_contextual_with_will(self):
        """'will' is ambiguous (name vs modal verb)."""
        sample = _sample(
            text="Call Will tomorrow",
            gold_spans=[
                GoldSpan(start=5, end=9, text="Will", entity_type="NAME", original_label="FIRSTNAME"),
            ],
        )
        dims = classify_sample(sample)
        assert NERDimension.CONTEXTUAL in dims

    def test_not_contextual_with_clear_name(self):
        """'Sarah' is not ambiguous."""
        sample = _sample(
            text="Sarah is here",
            gold_spans=[
                GoldSpan(start=0, end=5, text="Sarah", entity_type="NAME", original_label="FIRSTNAME"),
            ],
        )
        dims = classify_sample(sample)
        assert NERDimension.CONTEXTUAL not in dims

    def test_noisy_with_excessive_whitespace(self):
        sample = _sample(text="Name:    John     Smith   is here")
        dims = classify_sample(sample)
        assert NERDimension.NOISY in dims

    def test_noisy_with_repeated_punctuation(self):
        sample = _sample(text="Contact John Smith..... at the office")
        dims = classify_sample(sample)
        assert NERDimension.NOISY in dims

    def test_not_noisy_with_clean_text(self):
        sample = _sample(text="Contact John Smith at the office")
        dims = classify_sample(sample)
        assert NERDimension.NOISY not in dims

    def test_novel_with_solana_address(self):
        sample = _sample(
            gold_spans=[
                GoldSpan(
                    start=0, end=44,
                    text="7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                    entity_type="SOLANA_ADDRESS",
                    original_label="SOLANA_ADDRESS",
                ),
            ],
        )
        dims = classify_sample(sample)
        assert NERDimension.NOVEL in dims

    def test_novel_with_aadhaar(self):
        sample = _sample(
            gold_spans=[
                GoldSpan(
                    start=0, end=14,
                    text="1234 5678 9012",
                    entity_type="AADHAAR",
                    original_label="AADHAAR",
                ),
            ],
        )
        dims = classify_sample(sample)
        assert NERDimension.NOVEL in dims

    def test_not_novel_with_standard_types(self):
        sample = _sample(
            gold_spans=[
                GoldSpan(start=0, end=4, text="John", entity_type="NAME", original_label="FIRSTNAME"),
            ],
        )
        dims = classify_sample(sample)
        assert NERDimension.NOVEL not in dims

    def test_cross_lingual_french(self):
        sample = _sample(
            text="Contactez Jean à jean@example.fr",
            language="fr",
        )
        dims = classify_sample(sample)
        assert NERDimension.CROSS_LINGUAL in dims

    def test_cross_lingual_german(self):
        sample = _sample(language="de")
        dims = classify_sample(sample)
        assert NERDimension.CROSS_LINGUAL in dims

    def test_not_cross_lingual_english(self):
        sample = _sample(language="en")
        dims = classify_sample(sample)
        assert NERDimension.CROSS_LINGUAL not in dims

    def test_multiple_dimensions(self):
        """A noisy, non-English sample with ambiguous name hits 4 dimensions."""
        sample = _sample(
            text="May    sagte hallo...",
            gold_spans=[
                GoldSpan(start=0, end=3, text="May", entity_type="NAME", original_label="FIRSTNAME"),
            ],
            language="de",
        )
        dims = classify_sample(sample)
        assert NERDimension.BASIC in dims
        assert NERDimension.CONTEXTUAL in dims
        assert NERDimension.NOISY in dims
        assert NERDimension.CROSS_LINGUAL in dims


class TestClassifySamples:
    """Test batch classification."""

    def test_returns_all_dimensions(self):
        samples = [_sample(sample_id=0)]
        result = classify_samples(samples)
        assert set(result.keys()) == set(NERDimension)

    def test_basic_contains_all_samples(self):
        samples = [_sample(sample_id=i) for i in range(3)]
        result = classify_samples(samples)
        assert len(result[NERDimension.BASIC]) == 3

    def test_empty_input(self):
        result = classify_samples([])
        for dim in NERDimension:
            assert result[dim] == []

    def test_mixed_languages(self):
        samples = [
            _sample(sample_id=0, language="en"),
            _sample(sample_id=1, language="fr"),
            _sample(sample_id=2, language="de"),
        ]
        result = classify_samples(samples)
        assert 0 not in result[NERDimension.CROSS_LINGUAL]
        assert 1 in result[NERDimension.CROSS_LINGUAL]
        assert 2 in result[NERDimension.CROSS_LINGUAL]

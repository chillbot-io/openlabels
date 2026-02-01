"""Tests for OpenLabels Client API."""

import tempfile
from pathlib import Path

import pytest

from openlabels import Client
from openlabels.core.scorer import ScoringResult, RiskTier
from openlabels.adapters.base import Entity, NormalizedContext, NormalizedInput


class TestScoreText:
    """Tests for Client.score_text()."""

    def test_with_ssn(self):
        """SSN should produce a positive score."""
        client = Client()
        result = client.score_text("Patient SSN: 123-45-6789")

        assert isinstance(result, ScoringResult)
        assert result.score > 0
        assert result.tier in RiskTier

    def test_with_credit_card(self):
        """Credit card should produce a positive score."""
        client = Client()
        result = client.score_text("Card: 4532015112830366")  # Valid Luhn checksum

        assert isinstance(result, ScoringResult)
        assert result.score > 0
        assert result.tier in RiskTier

    def test_no_pii(self):
        """Text without PII should have zero score."""
        client = Client()
        result = client.score_text("Hello, this is just a normal message.")

        assert isinstance(result, ScoringResult)
        assert result.score == 0
        assert result.tier == RiskTier.MINIMAL

    def test_exposure_affects_score(self):
        """Public exposure should have higher or equal score than private."""
        client = Client()
        text = "SSN: 123-45-6789"

        private_result = client.score_text(text, exposure="PRIVATE")
        public_result = client.score_text(text, exposure="PUBLIC")

        assert public_result.score >= private_result.score


class TestScoreFile:
    """Tests for Client.score_file()."""

    def test_file_with_pii(self, tmp_path):
        """File containing PII should produce a positive score."""
        client = Client()
        test_file = tmp_path / "test.txt"
        test_file.write_text(
            "Patient: John Doe\n"
            "SSN: 123-45-6789\n"
            "Email: john.doe@example.com\n"
        )

        result = client.score_file(str(test_file))

        assert isinstance(result, ScoringResult)
        assert result.score > 0

    def test_file_not_found(self):
        """Non-existent file should raise FileNotFoundError."""
        client = Client()

        with pytest.raises(FileNotFoundError):
            client.score_file("/nonexistent/path/file.txt")


class TestScoreFromAdapters:
    """Tests for Client.score_from_adapters()."""

    def test_single_input(self):
        """Single adapter input should produce a valid score."""
        client = Client()

        entities = [
            Entity(type="SSN", count=1, confidence=0.95, source="test"),
            Entity(type="EMAIL", count=2, confidence=0.90, source="test"),
        ]
        context = NormalizedContext(
            exposure="INTERNAL",
            encryption="none",
            owner="test_user",
            path="/test/file.txt",
            size_bytes=1024,
            last_modified="2025-01-01T00:00:00Z",
            file_type="text/plain",
            is_archive=False,
        )
        normalized = NormalizedInput(entities=entities, context=context)

        result = client.score_from_adapters([normalized])

        assert isinstance(result, ScoringResult)
        assert result.score > 0
        assert result.exposure == "INTERNAL"

    def test_merge_takes_max_exposure(self):
        """Merging multiple inputs should use the highest exposure level."""
        client = Client()

        # First input - low count, low confidence, PRIVATE
        entities1 = [Entity(type="SSN", count=1, confidence=0.80, source="adapter1")]
        context1 = NormalizedContext(
            exposure="PRIVATE",
            encryption="none",
            owner="user1",
            path="/file1.txt",
            size_bytes=512,
            last_modified="2025-01-01T00:00:00Z",
            file_type="text/plain",
            is_archive=False,
        )

        # Second input - higher count, higher confidence, PUBLIC
        entities2 = [
            Entity(type="SSN", count=3, confidence=0.95, source="adapter2"),
            Entity(type="CREDIT_CARD", count=2, confidence=0.90, source="adapter2"),
        ]
        context2 = NormalizedContext(
            exposure="PUBLIC",
            encryption="none",
            owner="user2",
            path="/file2.txt",
            size_bytes=1024,
            last_modified="2025-01-01T00:00:00Z",
            file_type="text/plain",
            is_archive=False,
        )

        input1 = NormalizedInput(entities=entities1, context=context1)
        input2 = NormalizedInput(entities=entities2, context=context2)

        result = client.score_from_adapters([input1, input2])

        assert isinstance(result, ScoringResult)
        assert result.exposure == "PUBLIC"

    def test_empty_inputs(self):
        """Empty inputs should produce zero score."""
        client = Client()

        result = client.score_from_adapters([])

        assert isinstance(result, ScoringResult)
        assert result.score == 0
        assert result.tier == RiskTier.MINIMAL


class TestClientConfig:
    """Tests for Client configuration."""

    def test_default_exposure(self):
        """Custom default exposure should be applied."""
        client = Client(default_exposure="INTERNAL")

        result = client.score_text("SSN: 123-45-6789")

        assert result.exposure == "INTERNAL"

"""
Comprehensive tests for the PresidioAdapter.

Tests entity type mapping, confidence handling, metadata normalization,
and edge cases for Microsoft Presidio integration.
"""

import pytest
from unittest.mock import MagicMock
from openlabels.adapters.presidio import PresidioAdapter
from openlabels.adapters.base import ExposureLevel


class TestPresidioAdapterEntityMapping:
    """Tests for entity type mapping."""

    @pytest.fixture
    def adapter(self):
        return PresidioAdapter()

    def test_maps_us_ssn(self, adapter):
        """Test US_SSN maps to SSN."""
        results = [{"entity_type": "US_SSN", "start": 0, "end": 11, "score": 0.95}]
        normalized = adapter.extract(results, {})

        assert len(normalized.entities) == 1
        assert normalized.entities[0].type == "SSN"

    def test_maps_credit_card(self, adapter):
        """Test CREDIT_CARD maps directly."""
        results = [{"entity_type": "CREDIT_CARD", "start": 0, "end": 16, "score": 0.99}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].type == "CREDIT_CARD"

    def test_maps_email_address(self, adapter):
        """Test EMAIL_ADDRESS maps to EMAIL."""
        results = [{"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 20, "score": 0.9}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].type == "EMAIL"

    def test_maps_phone_number(self, adapter):
        """Test PHONE_NUMBER maps to PHONE."""
        results = [{"entity_type": "PHONE_NUMBER", "start": 0, "end": 12, "score": 0.85}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].type == "PHONE"

    def test_maps_person_to_name(self, adapter):
        """Test PERSON maps to NAME."""
        results = [{"entity_type": "PERSON", "start": 0, "end": 10, "score": 0.8}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].type == "NAME"

    def test_maps_location_to_address(self, adapter):
        """Test LOCATION maps to ADDRESS."""
        results = [{"entity_type": "LOCATION", "start": 0, "end": 15, "score": 0.75}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].type == "ADDRESS"

    def test_maps_international_ids(self, adapter):
        """Test international ID type mappings."""
        test_cases = [
            ("UK_NHS", "NHS_NUMBER"),
            ("AU_TFN", "TFN_AU"),
            ("AU_MEDICARE", "MEDICARE_ID"),
            ("IN_AADHAAR", "AADHAAR_IN"),
            ("IN_PAN", "PAN_IN"),
            ("SG_NRIC_FIN", "MY_NRIC"),
        ]

        for presidio_type, expected_type in test_cases:
            results = [{"entity_type": presidio_type, "start": 0, "end": 10, "score": 0.9}]
            normalized = adapter.extract(results, {})
            assert normalized.entities[0].type == expected_type, f"Failed for {presidio_type}"

    def test_maps_financial_types(self, adapter):
        """Test financial type mappings."""
        test_cases = [
            ("US_BANK_NUMBER", "BANK_ACCOUNT"),
            ("IBAN_CODE", "IBAN"),
            ("CRYPTO", "BITCOIN_ADDRESS"),
        ]

        for presidio_type, expected_type in test_cases:
            results = [{"entity_type": presidio_type, "start": 0, "end": 10, "score": 0.9}]
            normalized = adapter.extract(results, {})
            assert normalized.entities[0].type == expected_type

    def test_maps_credential_types(self, adapter):
        """Test credential type mappings."""
        test_cases = [
            ("AWS_ACCESS_KEY", "AWS_ACCESS_KEY"),
            ("AZURE_AUTH_TOKEN", "BEARER_TOKEN"),
            ("GITHUB_TOKEN", "GITHUB_TOKEN"),
        ]

        for presidio_type, expected_type in test_cases:
            results = [{"entity_type": presidio_type, "start": 0, "end": 20, "score": 0.95}]
            normalized = adapter.extract(results, {})
            assert normalized.entities[0].type == expected_type

    def test_unknown_type_uses_registry(self, adapter):
        """Test unknown types fall back to registry normalization."""
        results = [{"entity_type": "UNKNOWN_TYPE", "start": 0, "end": 10, "score": 0.7}]
        normalized = adapter.extract(results, {})

        # Should still produce an entity (via registry normalization)
        assert len(normalized.entities) == 1


class TestPresidioAdapterConfidence:
    """Tests for confidence score handling."""

    @pytest.fixture
    def adapter(self):
        return PresidioAdapter()

    def test_preserves_confidence(self, adapter):
        """Test confidence score is preserved."""
        results = [{"entity_type": "US_SSN", "start": 0, "end": 11, "score": 0.87}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].confidence == 0.87

    def test_aggregates_max_confidence(self, adapter):
        """Test multiple same-type entities use max confidence."""
        results = [
            {"entity_type": "US_SSN", "start": 0, "end": 11, "score": 0.70},
            {"entity_type": "US_SSN", "start": 20, "end": 31, "score": 0.95},
            {"entity_type": "US_SSN", "start": 40, "end": 51, "score": 0.80},
        ]
        normalized = adapter.extract(results, {})

        assert len(normalized.entities) == 1
        assert normalized.entities[0].type == "SSN"
        assert normalized.entities[0].confidence == 0.95  # Max of all
        assert normalized.entities[0].count == 3

    def test_default_confidence(self, adapter):
        """Test default confidence when score not provided."""
        results = [{"entity_type": "US_SSN", "start": 0, "end": 11}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].confidence == 0.5


class TestPresidioAdapterAggregation:
    """Tests for entity aggregation."""

    @pytest.fixture
    def adapter(self):
        return PresidioAdapter()

    def test_aggregates_same_type(self, adapter):
        """Test entities of same type are aggregated."""
        results = [
            {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 20, "score": 0.9},
            {"entity_type": "EMAIL_ADDRESS", "start": 30, "end": 50, "score": 0.85},
        ]
        normalized = adapter.extract(results, {})

        assert len(normalized.entities) == 1
        assert normalized.entities[0].count == 2

    def test_tracks_positions(self, adapter):
        """Test positions are tracked for each occurrence."""
        results = [
            {"entity_type": "PHONE_NUMBER", "start": 5, "end": 17, "score": 0.8},
            {"entity_type": "PHONE_NUMBER", "start": 25, "end": 37, "score": 0.9},
        ]
        normalized = adapter.extract(results, {})

        assert len(normalized.entities[0].positions) == 2
        assert (5, 17) in normalized.entities[0].positions
        assert (25, 37) in normalized.entities[0].positions

    def test_multiple_types(self, adapter):
        """Test multiple entity types are kept separate."""
        results = [
            {"entity_type": "US_SSN", "start": 0, "end": 11, "score": 0.95},
            {"entity_type": "EMAIL_ADDRESS", "start": 20, "end": 40, "score": 0.9},
            {"entity_type": "PHONE_NUMBER", "start": 50, "end": 62, "score": 0.85},
        ]
        normalized = adapter.extract(results, {})

        assert len(normalized.entities) == 3
        types = {e.type for e in normalized.entities}
        assert types == {"SSN", "EMAIL", "PHONE"}


class TestPresidioAdapterRecognizerResultObjects:
    """Tests for handling RecognizerResult objects (not just dicts)."""

    @pytest.fixture
    def adapter(self):
        return PresidioAdapter()

    def test_handles_recognizer_result_object(self, adapter):
        """Test handling of RecognizerResult-like objects."""
        # Create mock RecognizerResult
        result = MagicMock()
        result.entity_type = "US_SSN"
        result.score = 0.92
        result.start = 0
        result.end = 11

        normalized = adapter.extract([result], {})

        assert len(normalized.entities) == 1
        assert normalized.entities[0].type == "SSN"
        assert normalized.entities[0].confidence == 0.92


class TestPresidioAdapterContext:
    """Tests for context normalization."""

    @pytest.fixture
    def adapter(self):
        return PresidioAdapter()

    def test_default_context(self, adapter):
        """Test default context when no metadata provided."""
        normalized = adapter.extract([], None)

        assert normalized.context.exposure == "PRIVATE"
        assert normalized.context.encryption == "none"
        assert normalized.context.classification_source == "presidio"
        assert normalized.context.has_classification is True

    def test_preserves_exposure(self, adapter):
        """Test exposure level is preserved from metadata."""
        metadata = {"exposure": "PUBLIC"}
        normalized = adapter.extract([], metadata)

        assert normalized.context.exposure == "PUBLIC"

    def test_normalizes_exposure_case(self, adapter):
        """Test exposure is normalized to uppercase."""
        metadata = {"exposure": "internal"}
        normalized = adapter.extract([], metadata)

        assert normalized.context.exposure == "INTERNAL"

    def test_invalid_exposure_defaults_private(self, adapter):
        """Test invalid exposure defaults to PRIVATE."""
        metadata = {"exposure": "INVALID_VALUE"}
        normalized = adapter.extract([], metadata)

        assert normalized.context.exposure == "PRIVATE"

    def test_preserves_file_info(self, adapter):
        """Test file info is preserved."""
        metadata = {
            "path": "/path/to/file.pdf",
            "size": 1024,
            "file_type": "application/pdf",
            "owner": "user@example.com",
        }
        normalized = adapter.extract([], metadata)

        assert normalized.context.path == "/path/to/file.pdf"
        assert normalized.context.size_bytes == 1024
        assert normalized.context.file_type == "application/pdf"
        assert normalized.context.owner == "user@example.com"

    def test_detects_archive(self, adapter):
        """Test archive detection from path."""
        metadata = {"path": "/path/to/archive.zip"}
        normalized = adapter.extract([], metadata)

        assert normalized.context.is_archive is True

    def test_not_archive(self, adapter):
        """Test non-archive path."""
        metadata = {"path": "/path/to/document.pdf"}
        normalized = adapter.extract([], metadata)

        assert normalized.context.is_archive is False

    def test_preserves_protection_settings(self, adapter):
        """Test protection settings are preserved."""
        metadata = {
            "encryption": "customer_managed",
            "versioning": True,
            "access_logging": True,
            "retention_policy": True,
        }
        normalized = adapter.extract([], metadata)

        assert normalized.context.encryption == "customer_managed"
        assert normalized.context.versioning is True
        assert normalized.context.access_logging is True
        assert normalized.context.retention_policy is True

    def test_public_exposure_sets_anonymous_access(self, adapter):
        """Test PUBLIC exposure sets anonymous_access flag."""
        metadata = {"exposure": "PUBLIC"}
        normalized = adapter.extract([], metadata)

        assert normalized.context.anonymous_access is True

    def test_private_exposure_no_anonymous_access(self, adapter):
        """Test PRIVATE exposure does not set anonymous_access."""
        metadata = {"exposure": "PRIVATE"}
        normalized = adapter.extract([], metadata)

        assert normalized.context.anonymous_access is False

    def test_staleness_calculation(self, adapter):
        """Test staleness days calculation."""
        # Use a date that will definitely be stale
        metadata = {"last_modified": "2020-01-01T00:00:00Z"}
        normalized = adapter.extract([], metadata)

        # Should be many days stale
        assert normalized.context.staleness_days > 1000


class TestPresidioAdapterSource:
    """Tests for source attribution."""

    @pytest.fixture
    def adapter(self):
        return PresidioAdapter()

    def test_entity_source_is_presidio(self, adapter):
        """Test entity source is set to presidio."""
        results = [{"entity_type": "US_SSN", "start": 0, "end": 11, "score": 0.9}]
        normalized = adapter.extract(results, {})

        assert normalized.entities[0].source == "presidio"

    def test_context_classification_source(self, adapter):
        """Test context classification source is presidio."""
        normalized = adapter.extract([], {})

        assert normalized.context.classification_source == "presidio"


class TestPresidioAdapterEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def adapter(self):
        return PresidioAdapter()

    def test_empty_results(self, adapter):
        """Test handling of empty results."""
        normalized = adapter.extract([], {})

        assert normalized.entities == []
        assert normalized.context is not None

    def test_none_metadata(self, adapter):
        """Test handling of None metadata."""
        results = [{"entity_type": "US_SSN", "start": 0, "end": 11, "score": 0.9}]
        normalized = adapter.extract(results, None)

        assert len(normalized.entities) == 1
        assert normalized.context.exposure == "PRIVATE"

    def test_empty_metadata(self, adapter):
        """Test handling of empty metadata dict."""
        normalized = adapter.extract([], {})

        assert normalized.context.path == ""
        assert normalized.context.size_bytes == 0

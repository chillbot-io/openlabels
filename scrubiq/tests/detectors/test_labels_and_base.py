"""
Comprehensive tests for scrubiq/detectors/labels.py and scrubiq/detectors/base.py.

Tests label mappings for ML detectors and the BaseDetector abstract class.
"""

import pytest
from abc import ABC
from typing import List

from scrubiq.detectors.labels import PHI_BERT_LABELS, PII_BERT_LABELS
from scrubiq.detectors.base import BaseDetector
from scrubiq.types import Span, Tier


# =============================================================================
# PHI_BERT_LABELS Tests
# =============================================================================
class TestPHIBertLabels:
    """Tests for PHI_BERT_LABELS mapping."""

    def test_phi_labels_is_dict(self):
        """PHI_BERT_LABELS should be a dictionary."""
        assert isinstance(PHI_BERT_LABELS, dict)

    def test_phi_labels_not_empty(self):
        """PHI_BERT_LABELS should not be empty."""
        assert len(PHI_BERT_LABELS) > 0

    def test_phi_labels_keys_are_strings(self):
        """All keys should be strings."""
        for key in PHI_BERT_LABELS.keys():
            assert isinstance(key, str), f"Key {key} is not a string"

    def test_phi_labels_values_are_strings(self):
        """All values should be strings."""
        for value in PHI_BERT_LABELS.values():
            assert isinstance(value, str), f"Value {value} is not a string"

    def test_phi_labels_keys_not_empty(self):
        """Keys should not be empty strings."""
        for key in PHI_BERT_LABELS.keys():
            assert len(key) > 0, "Found empty key"

    def test_phi_labels_values_not_empty(self):
        """Values should not be empty strings."""
        for value in PHI_BERT_LABELS.values():
            assert len(value) > 0, "Found empty value"

    def test_phi_patient_label(self):
        """PATIENT should map to NAME_PATIENT."""
        assert "PATIENT" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["PATIENT"] == "NAME_PATIENT"

    def test_phi_hcw_label(self):
        """HCW (Healthcare Worker) should map to NAME_PROVIDER."""
        assert "HCW" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["HCW"] == "NAME_PROVIDER"

    def test_phi_name_label(self):
        """NAME should map to NAME."""
        assert "NAME" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["NAME"] == "NAME"

    def test_phi_date_label(self):
        """DATE should map to DATE."""
        assert "DATE" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["DATE"] == "DATE"

    def test_phi_age_label(self):
        """AGE should map to AGE."""
        assert "AGE" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["AGE"] == "AGE"

    def test_phi_id_label(self):
        """ID should map to MRN."""
        assert "ID" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["ID"] == "MRN"

    def test_phi_mrn_label(self):
        """MRN should map to MRN."""
        assert "MRN" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["MRN"] == "MRN"

    def test_phi_phone_label(self):
        """PHONE should map to PHONE."""
        assert "PHONE" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["PHONE"] == "PHONE"

    def test_phi_vendor_label(self):
        """VENDOR should map to FACILITY (context-only)."""
        assert "VENDOR" in PHI_BERT_LABELS
        assert PHI_BERT_LABELS["VENDOR"] == "FACILITY"

    def test_phi_labels_expected_keys(self):
        """PHI_BERT_LABELS should contain expected keys."""
        expected_keys = {"PATIENT", "HCW", "NAME", "DATE", "AGE", "ID", "MRN", "PHONE", "VENDOR"}
        actual_keys = set(PHI_BERT_LABELS.keys())
        assert expected_keys == actual_keys


# =============================================================================
# PII_BERT_LABELS Tests
# =============================================================================
class TestPIIBertLabels:
    """Tests for PII_BERT_LABELS mapping."""

    def test_pii_labels_is_dict(self):
        """PII_BERT_LABELS should be a dictionary."""
        assert isinstance(PII_BERT_LABELS, dict)

    def test_pii_labels_not_empty(self):
        """PII_BERT_LABELS should not be empty."""
        assert len(PII_BERT_LABELS) > 0

    def test_pii_labels_keys_are_strings(self):
        """All keys should be strings."""
        for key in PII_BERT_LABELS.keys():
            assert isinstance(key, str), f"Key {key} is not a string"

    def test_pii_labels_values_are_strings(self):
        """All values should be strings."""
        for value in PII_BERT_LABELS.values():
            assert isinstance(value, str), f"Value {value} is not a string"

    def test_pii_uses_bio_tagging(self):
        """PII_BERT_LABELS should use BIO tagging scheme."""
        b_prefix_keys = [k for k in PII_BERT_LABELS.keys() if k.startswith("B-")]
        i_prefix_keys = [k for k in PII_BERT_LABELS.keys() if k.startswith("I-")]

        assert len(b_prefix_keys) > 0, "Should have B- prefix labels"
        assert len(i_prefix_keys) > 0, "Should have I- prefix labels"

    def test_pii_bio_pairs_match(self):
        """B- and I- labels for same entity should map to same canonical type."""
        b_labels = {k[2:]: v for k, v in PII_BERT_LABELS.items() if k.startswith("B-")}
        i_labels = {k[2:]: v for k, v in PII_BERT_LABELS.items() if k.startswith("I-")}

        for entity, b_type in b_labels.items():
            if entity in i_labels:
                assert b_type == i_labels[entity], (
                    f"B-{entity} maps to {b_type} but I-{entity} maps to {i_labels[entity]}"
                )

    def test_pii_name_labels(self):
        """NAME labels should be present and map correctly."""
        assert "B-NAME" in PII_BERT_LABELS
        assert "I-NAME" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-NAME"] == "NAME"
        assert PII_BERT_LABELS["I-NAME"] == "NAME"

    def test_pii_dob_labels(self):
        """DOB labels should be present and map to DATE_DOB."""
        assert "B-DOB" in PII_BERT_LABELS
        assert "I-DOB" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-DOB"] == "DATE_DOB"
        assert PII_BERT_LABELS["I-DOB"] == "DATE_DOB"

    def test_pii_ssn_labels(self):
        """SSN labels should be present and map correctly."""
        assert "B-SSN" in PII_BERT_LABELS
        assert "I-SSN" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-SSN"] == "SSN"
        assert PII_BERT_LABELS["I-SSN"] == "SSN"

    def test_pii_license_labels(self):
        """LICENSE labels should map to DRIVER_LICENSE."""
        assert "B-LICENSE" in PII_BERT_LABELS
        assert "I-LICENSE" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-LICENSE"] == "DRIVER_LICENSE"
        assert PII_BERT_LABELS["I-LICENSE"] == "DRIVER_LICENSE"

    def test_pii_passport_labels(self):
        """PASSPORT labels should be present."""
        assert "B-PASSPORT" in PII_BERT_LABELS
        assert "I-PASSPORT" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-PASSPORT"] == "PASSPORT"

    def test_pii_vin_labels(self):
        """VIN labels should be present."""
        assert "B-VIN" in PII_BERT_LABELS
        assert "I-VIN" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-VIN"] == "VIN"

    def test_pii_phone_labels(self):
        """PHONE labels should be present."""
        assert "B-PHONE" in PII_BERT_LABELS
        assert "I-PHONE" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-PHONE"] == "PHONE"

    def test_pii_email_labels(self):
        """EMAIL labels should be present."""
        assert "B-EMAIL" in PII_BERT_LABELS
        assert "I-EMAIL" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-EMAIL"] == "EMAIL"

    def test_pii_url_labels(self):
        """URL labels should be present."""
        assert "B-URL" in PII_BERT_LABELS
        assert "I-URL" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-URL"] == "URL"

    def test_pii_ip_labels(self):
        """IP labels should map to IP_ADDRESS."""
        assert "B-IP" in PII_BERT_LABELS
        assert "I-IP" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-IP"] == "IP_ADDRESS"

    def test_pii_mac_labels(self):
        """MAC labels should map to MAC_ADDRESS."""
        assert "B-MAC" in PII_BERT_LABELS
        assert "I-MAC" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-MAC"] == "MAC_ADDRESS"

    def test_pii_address_labels(self):
        """ADDRESS labels should be present."""
        assert "B-ADDRESS" in PII_BERT_LABELS
        assert "I-ADDRESS" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-ADDRESS"] == "ADDRESS"

    def test_pii_credit_card_labels(self):
        """CREDIT_CARD labels should be present."""
        assert "B-CREDIT_CARD" in PII_BERT_LABELS
        assert "I-CREDIT_CARD" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-CREDIT_CARD"] == "CREDIT_CARD"

    def test_pii_account_labels(self):
        """ACCOUNT labels should map to ACCOUNT_NUMBER."""
        assert "B-ACCOUNT" in PII_BERT_LABELS
        assert "I-ACCOUNT" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-ACCOUNT"] == "ACCOUNT_NUMBER"

    def test_pii_iban_labels(self):
        """IBAN labels should be present."""
        assert "B-IBAN" in PII_BERT_LABELS
        assert "I-IBAN" in PII_BERT_LABELS
        assert PII_BERT_LABELS["B-IBAN"] == "IBAN"


# =============================================================================
# Label Coverage and Consistency Tests
# =============================================================================
class TestLabelsCoverage:
    """Tests for label coverage and consistency."""

    def test_no_none_values(self):
        """Neither label dictionary should have None values."""
        for key, value in PHI_BERT_LABELS.items():
            assert value is not None, f"PHI label {key} has None value"

        for key, value in PII_BERT_LABELS.items():
            assert value is not None, f"PII label {key} has None value"

    def test_canonical_types_uppercase(self):
        """Canonical types should be uppercase."""
        for value in PHI_BERT_LABELS.values():
            assert value == value.upper(), f"PHI canonical type {value} not uppercase"

        for value in PII_BERT_LABELS.values():
            assert value == value.upper(), f"PII canonical type {value} not uppercase"

    def test_canonical_types_use_underscore(self):
        """Multi-word canonical types should use underscores."""
        all_values = list(PHI_BERT_LABELS.values()) + list(PII_BERT_LABELS.values())

        for value in all_values:
            # Should not contain spaces
            assert " " not in value, f"Canonical type {value} contains spaces"
            # Should not contain dashes (use underscore)
            assert "-" not in value, f"Canonical type {value} contains dashes"

    def test_no_duplicate_mappings(self):
        """Keys should be unique within each dictionary."""
        phi_keys = list(PHI_BERT_LABELS.keys())
        assert len(phi_keys) == len(set(phi_keys)), "PHI_BERT_LABELS has duplicate keys"

        pii_keys = list(PII_BERT_LABELS.keys())
        assert len(pii_keys) == len(set(pii_keys)), "PII_BERT_LABELS has duplicate keys"


# =============================================================================
# BaseDetector Abstract Class Tests
# =============================================================================
class TestBaseDetector:
    """Tests for the BaseDetector abstract base class."""

    def test_base_detector_is_abstract(self):
        """BaseDetector should be an abstract class."""
        assert issubclass(BaseDetector, ABC)

    def test_cannot_instantiate_base_detector(self):
        """Should not be able to instantiate BaseDetector directly."""
        with pytest.raises(TypeError):
            BaseDetector()

    def test_base_detector_has_name_attribute(self):
        """BaseDetector should have a name class attribute."""
        assert hasattr(BaseDetector, "name")
        assert BaseDetector.name == "base"

    def test_base_detector_has_tier_attribute(self):
        """BaseDetector should have a tier class attribute."""
        assert hasattr(BaseDetector, "tier")
        assert BaseDetector.tier == Tier.ML

    def test_base_detector_has_detect_method(self):
        """BaseDetector should have an abstract detect method."""
        assert hasattr(BaseDetector, "detect")
        # Check it's abstract
        assert getattr(BaseDetector.detect, "__isabstractmethod__", False)

    def test_base_detector_has_is_available_method(self):
        """BaseDetector should have an is_available method."""
        assert hasattr(BaseDetector, "is_available")

    def test_is_available_default_returns_true(self):
        """Default is_available should return True."""

        # Create a concrete implementation to test
        class TestDetector(BaseDetector):
            def detect(self, text: str) -> List[Span]:
                return []

        detector = TestDetector()
        assert detector.is_available() is True


# =============================================================================
# Concrete Detector Implementation Tests
# =============================================================================
class TestConcreteDetector:
    """Tests for concrete detector implementations."""

    def test_concrete_detector_implementation(self):
        """Concrete detector should be instantiable."""

        class MyDetector(BaseDetector):
            name = "my_detector"
            tier = Tier.PATTERN

            def detect(self, text: str) -> List[Span]:
                return []

        detector = MyDetector()
        assert detector.name == "my_detector"
        assert detector.tier == Tier.PATTERN

    def test_concrete_detector_detect_returns_list(self):
        """detect() should return a list."""

        class MyDetector(BaseDetector):
            def detect(self, text: str) -> List[Span]:
                return []

        detector = MyDetector()
        result = detector.detect("test")
        assert isinstance(result, list)

    def test_concrete_detector_can_return_spans(self):
        """detect() can return actual Span objects."""

        class MyDetector(BaseDetector):
            def detect(self, text: str) -> List[Span]:
                if "test" in text:
                    return [Span(
                        start=0,
                        end=4,
                        text="test",
                        entity_type="TEST",
                        confidence=0.95,
                        detector="my_detector",
                        tier=Tier.PATTERN
                    )]
                return []

        detector = MyDetector()
        result = detector.detect("test string")

        assert len(result) == 1
        assert result[0].text == "test"
        assert result[0].entity_type == "TEST"
        assert result[0].confidence == 0.95

    def test_concrete_detector_can_override_is_available(self):
        """Concrete detector can override is_available."""

        class ConditionalDetector(BaseDetector):
            def __init__(self, available: bool = True):
                self._available = available

            def detect(self, text: str) -> List[Span]:
                return []

            def is_available(self) -> bool:
                return self._available

        available_detector = ConditionalDetector(available=True)
        unavailable_detector = ConditionalDetector(available=False)

        assert available_detector.is_available() is True
        assert unavailable_detector.is_available() is False

    def test_concrete_detector_inherits_defaults(self):
        """Concrete detector without overrides uses defaults."""

        class MinimalDetector(BaseDetector):
            def detect(self, text: str) -> List[Span]:
                return []

        detector = MinimalDetector()
        assert detector.name == "base"  # Default
        assert detector.tier == Tier.ML  # Default

    def test_concrete_detector_can_override_name(self):
        """Concrete detector can override name."""

        class NamedDetector(BaseDetector):
            name = "custom_name"

            def detect(self, text: str) -> List[Span]:
                return []

        detector = NamedDetector()
        assert detector.name == "custom_name"

    def test_concrete_detector_can_override_tier(self):
        """Concrete detector can override tier."""

        class TieredDetector(BaseDetector):
            tier = Tier.STRUCTURED

            def detect(self, text: str) -> List[Span]:
                return []

        detector = TieredDetector()
        assert detector.tier == Tier.STRUCTURED


# =============================================================================
# Type Annotation Tests
# =============================================================================
class TestTypeAnnotations:
    """Tests for type annotations."""

    def test_detect_accepts_str(self):
        """detect() should accept str argument."""

        class TestDetector(BaseDetector):
            def detect(self, text: str) -> List[Span]:
                assert isinstance(text, str)
                return []

        detector = TestDetector()
        detector.detect("test")  # Should not raise

    def test_detect_returns_span_list(self):
        """detect() should return List[Span]."""

        class TestDetector(BaseDetector):
            def detect(self, text: str) -> List[Span]:
                return [Span(
                    start=0,
                    end=4,
                    text="test",
                    entity_type="TEST",
                    confidence=0.9,
                    detector="test",
                    tier=Tier.ML
                )]

        detector = TestDetector()
        result = detector.detect("test")

        assert isinstance(result, list)
        assert all(isinstance(s, Span) for s in result)

    def test_is_available_returns_bool(self):
        """is_available() should return bool."""

        class TestDetector(BaseDetector):
            def detect(self, text: str) -> List[Span]:
                return []

        detector = TestDetector()
        result = detector.is_available()
        assert isinstance(result, bool)

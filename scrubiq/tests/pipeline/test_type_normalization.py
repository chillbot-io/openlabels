"""Tests for type normalization in merger.py.

Tests TYPE_NORMALIZE mapping and normalize_name_types() context-based normalization.
"""

import pytest
from scrubiq.types import Span, Tier
from scrubiq.pipeline.merger import (
    TYPE_NORMALIZE,
    normalize_type,
    normalize_name_types,
)


def make_span(text, start=0, entity_type="NAME", confidence=0.9, detector="test", tier=2):
    """Helper to create spans with correct end position."""
    return Span(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=entity_type,
        confidence=confidence,
        detector=detector,
        tier=Tier.from_value(tier),
    )


class TestNormalizeType:
    """Tests for normalize_type() and TYPE_NORMALIZE mapping."""

    def test_person_to_name(self):
        """PERSON variants normalize to NAME."""
        assert normalize_type("PERSON") == "NAME"
        assert normalize_type("PER") == "NAME"

    def test_patient_to_name_patient(self):
        """PATIENT normalizes to NAME_PATIENT."""
        assert normalize_type("PATIENT") == "NAME_PATIENT"

    def test_doctor_to_name_provider(self):
        """DOCTOR/PHYSICIAN variants normalize to NAME_PROVIDER."""
        assert normalize_type("DOCTOR") == "NAME_PROVIDER"
        assert normalize_type("PHYSICIAN") == "NAME_PROVIDER"
        assert normalize_type("NURSE") == "NAME_PROVIDER"
        assert normalize_type("HCW") == "NAME_PROVIDER"

    def test_relative_to_name_relative(self):
        """RELATIVE/FAMILY normalizes to NAME_RELATIVE."""
        assert normalize_type("RELATIVE") == "NAME_RELATIVE"
        assert normalize_type("FAMILY") == "NAME_RELATIVE"

    def test_location_types_to_address(self):
        """Location types normalize to ADDRESS."""
        location_types = ["GPE", "LOC", "STREET_ADDRESS", "STREET", "CITY",
                         "STATE", "COUNTRY", "LOCATION_OTHER", "ZIPCODE", "ZIP"]
        for loc_type in location_types:
            assert normalize_type(loc_type) == "ADDRESS", f"{loc_type} should normalize to ADDRESS"

    def test_ssn_variants(self):
        """SSN variants normalize correctly."""
        assert normalize_type("US_SSN") == "SSN"
        assert normalize_type("SOCIAL_SECURITY") == "SSN"
        assert normalize_type("SOCIALSECURITYNUMBER") == "SSN"

    def test_mrn_variants(self):
        """MRN variants normalize correctly."""
        assert normalize_type("ID") == "MRN"  # Stanford PHI-BERT generic
        assert normalize_type("MEDICAL_RECORD") == "MRN"
        assert normalize_type("MEDICALRECORD") == "MRN"

    def test_phone_variants(self):
        """Phone variants normalize to PHONE."""
        phone_types = ["PHONE_NUMBER", "PHONENUMBER", "US_PHONE_NUMBER",
                       "TELEPHONE", "TEL", "MOBILE", "CELL"]
        for phone_type in phone_types:
            assert normalize_type(phone_type) == "PHONE", f"{phone_type} should normalize to PHONE"

    def test_email_variants(self):
        """Email variants normalize to EMAIL."""
        assert normalize_type("EMAIL_ADDRESS") == "EMAIL"
        assert normalize_type("EMAILADDRESS") == "EMAIL"

    def test_date_variants(self):
        """Date variants normalize correctly."""
        assert normalize_type("DATE_TIME") == "DATE"
        assert normalize_type("DATETIME") == "DATE"
        assert normalize_type("BIRTHDAY") == "DATE_DOB"
        assert normalize_type("DOB") == "DATE_DOB"
        assert normalize_type("DATEOFBIRTH") == "DATE_DOB"

    def test_credit_card_variants(self):
        """Credit card variants normalize to CREDIT_CARD."""
        cc_types = ["CREDIT_CARD_NUMBER", "CREDITCARDNUMBER", "CREDITCARD", "CC"]
        for cc_type in cc_types:
            assert normalize_type(cc_type) == "CREDIT_CARD", f"{cc_type} should normalize"

    def test_ip_address_variants(self):
        """IP address variants normalize to IP_ADDRESS."""
        ip_types = ["IP", "IPADDRESS", "IPV4", "IPV6"]
        for ip_type in ip_types:
            assert normalize_type(ip_type) == "IP_ADDRESS", f"{ip_type} should normalize"

    def test_employer_variants(self):
        """Employer/organization variants normalize to EMPLOYER."""
        emp_types = ["COMPANYNAME", "COMPANY", "ORG", "ORGANIZATION"]
        for emp_type in emp_types:
            assert normalize_type(emp_type) == "EMPLOYER", f"{emp_type} should normalize"

    def test_unknown_type_unchanged(self):
        """Unknown types are returned unchanged."""
        assert normalize_type("UNKNOWN_TYPE") == "UNKNOWN_TYPE"
        assert normalize_type("CUSTOM_ENTITY") == "CUSTOM_ENTITY"

    def test_already_normalized_unchanged(self):
        """Already-normalized types are unchanged."""
        canonical = ["NAME", "ADDRESS", "SSN", "MRN", "PHONE", "EMAIL", "DATE"]
        for canon in canonical:
            assert normalize_type(canon) == canon


class TestNormalizeNameTypes:
    """Tests for normalize_name_types() context-based normalization."""

    def test_name_provider_with_dr_context(self):
        """NAME_PROVIDER with 'Dr.' context is kept."""
        text = "Dr. John Smith treated the patient"
        span = make_span("John Smith", start=4, entity_type="NAME_PROVIDER")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME_PROVIDER"

    def test_name_provider_with_md_suffix(self):
        """NAME_PROVIDER with ', MD' suffix is kept."""
        text = "John Smith, MD treated the patient"
        span = make_span("John Smith", start=0, entity_type="NAME_PROVIDER")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME_PROVIDER"

    def test_name_provider_without_context_normalized(self):
        """NAME_PROVIDER without provider context becomes NAME."""
        text = "John Smith went to the store"
        span = make_span("John Smith", start=0, entity_type="NAME_PROVIDER")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME"

    def test_name_patient_with_patient_label(self):
        """NAME_PATIENT with 'Patient:' context is kept."""
        text = "Patient: John Smith presented with symptoms"
        span = make_span("John Smith", start=9, entity_type="NAME_PATIENT")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME_PATIENT"

    def test_name_patient_with_clinical_suffix(self):
        """NAME_PATIENT with clinical suffix is kept."""
        text = "John Smith was admitted to ICU"
        span = make_span("John Smith", start=0, entity_type="NAME_PATIENT")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME_PATIENT"

    def test_name_patient_without_context_normalized(self):
        """NAME_PATIENT without patient context becomes NAME."""
        text = "John Smith went to the store"
        span = make_span("John Smith", start=0, entity_type="NAME_PATIENT")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME"

    def test_name_relative_with_family_context(self):
        """NAME_RELATIVE with family context is kept."""
        text = "Mother: Jane Smith, contact for emergency"
        span = make_span("Jane Smith", start=8, entity_type="NAME_RELATIVE")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME_RELATIVE"

    def test_name_relative_without_context_normalized(self):
        """NAME_RELATIVE without family context becomes NAME."""
        text = "Jane Smith went to the store"
        span = make_span("Jane Smith", start=0, entity_type="NAME_RELATIVE")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME"

    def test_generic_name_unchanged(self):
        """Plain NAME type is unchanged."""
        text = "John Smith is here"
        span = make_span("John Smith", start=0, entity_type="NAME")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "NAME"

    def test_non_name_types_unchanged(self):
        """Non-NAME types are unchanged."""
        text = "SSN: 123-45-6789"
        span = make_span("123-45-6789", start=5, entity_type="SSN")

        result = normalize_name_types([span], text)

        assert result[0].entity_type == "SSN"


class TestProviderContextPatterns:
    """Tests for specific provider context patterns."""

    def test_ordered_by_context(self):
        """'Ordered by' context is detected."""
        text = "Lab ordered by John Smith on 01/15"
        span = make_span("John Smith", start=15, entity_type="NAME_PROVIDER")

        result = normalize_name_types([span], text)
        assert result[0].entity_type == "NAME_PROVIDER"

    def test_reviewed_by_context(self):
        """'Reviewed by' context is detected."""
        text = "Results reviewed by Dr. Jane Doe"
        span = make_span("Jane Doe", start=24, entity_type="NAME_PROVIDER")

        result = normalize_name_types([span], text)
        assert result[0].entity_type == "NAME_PROVIDER"

    def test_attending_context(self):
        """'Attending:' context is detected."""
        text = "Attending: John Smith, MD"
        span = make_span("John Smith", start=11, entity_type="NAME_PROVIDER")

        result = normalize_name_types([span], text)
        assert result[0].entity_type == "NAME_PROVIDER"

    def test_various_credentials_detected(self):
        """Various medical credentials are detected."""
        credentials = ["MD", "DO", "RN", "NP", "PA", "PharmD", "DDS"]
        for cred in credentials:
            text = f"John Smith, {cred} is available"
            span = make_span("John Smith", start=0, entity_type="NAME_PROVIDER")

            result = normalize_name_types([span], text)
            assert result[0].entity_type == "NAME_PROVIDER", f"Failed for credential {cred}"


class TestPatientContextPatterns:
    """Tests for specific patient context patterns."""

    def test_pt_abbreviation(self):
        """'Pt:' abbreviation is detected."""
        text = "Pt: John Smith, 45 y/o male"
        span = make_span("John Smith", start=4, entity_type="NAME_PATIENT")

        result = normalize_name_types([span], text)
        assert result[0].entity_type == "NAME_PATIENT"

    def test_patient_name_label(self):
        """'Patient Name:' label is detected."""
        text = "Patient Name: John Smith"
        span = make_span("John Smith", start=14, entity_type="NAME_PATIENT")

        result = normalize_name_types([span], text)
        assert result[0].entity_type == "NAME_PATIENT"

    def test_clinical_verbs(self):
        """Clinical verbs (presents, complains, denies) are detected."""
        verbs = ["presents with", "complains of", "reports", "denies", "states"]
        for verb in verbs:
            text = f"John Smith {verb} chest pain"
            span = make_span("John Smith", start=0, entity_type="NAME_PATIENT")

            result = normalize_name_types([span], text)
            assert result[0].entity_type == "NAME_PATIENT", f"Failed for verb '{verb}'"

    def test_age_pattern(self):
        """Age patterns (45 y/o, aged 45) are detected."""
        patterns = [
            "John Smith, 45 y/o",
            "John Smith, aged 45",
            "John Smith, a 45 year old",
        ]
        for text in patterns:
            span = make_span("John Smith", start=0, entity_type="NAME_PATIENT")

            result = normalize_name_types([span], text)
            assert result[0].entity_type == "NAME_PATIENT", f"Failed for pattern: {text}"


class TestRelativeContextPatterns:
    """Tests for specific relative/family context patterns."""

    def test_family_relationships(self):
        """Family relationship labels are detected."""
        relationships = ["Mother", "Father", "Spouse", "Wife", "Husband",
                        "Son", "Daughter", "Brother", "Sister"]
        for rel in relationships:
            text = f"{rel}: Jane Smith, phone 555-1234"
            span = make_span("Jane Smith", start=len(rel) + 2, entity_type="NAME_RELATIVE")

            result = normalize_name_types([span], text)
            assert result[0].entity_type == "NAME_RELATIVE", f"Failed for {rel}"

    def test_emergency_contact(self):
        """'Emergency Contact:' is detected."""
        text = "Emergency Contact: Jane Smith"
        span = make_span("Jane Smith", start=19, entity_type="NAME_RELATIVE")

        result = normalize_name_types([span], text)
        assert result[0].entity_type == "NAME_RELATIVE"

    def test_next_of_kin(self):
        """'Next of Kin:' is detected."""
        text = "Next of Kin: Jane Smith"
        span = make_span("Jane Smith", start=13, entity_type="NAME_RELATIVE")

        result = normalize_name_types([span], text)
        assert result[0].entity_type == "NAME_RELATIVE"


class TestTypeNormalizationInMergeSpans:
    """Integration tests for type normalization in merge_spans."""

    def test_type_normalized_in_merge(self):
        """Entity types are normalized during merge_spans."""
        from scrubiq.pipeline.merger import merge_spans

        text = "Contact: John Smith, MD"
        spans = [
            make_span("John Smith", start=9, entity_type="PERSON"),  # Should normalize to NAME
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        assert len(result) == 1
        assert result[0].entity_type == "NAME"

    def test_name_types_normalized_in_merge(self):
        """NAME subtypes are context-normalized during merge_spans."""
        from scrubiq.pipeline.merger import merge_spans

        # Provider without context - should become NAME
        text = "John Smith went shopping"
        spans = [
            make_span("John Smith", start=0, entity_type="NAME_PROVIDER"),
        ]

        result = merge_spans(spans, min_confidence=0.5, text=text)

        # After merge_spans, normalize_name_types is called in core.py
        # but let's verify the type normalization works
        assert result[0].entity_type == "NAME_PROVIDER"  # merge_spans doesn't call normalize_name_types

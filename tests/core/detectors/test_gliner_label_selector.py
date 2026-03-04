"""Tests for content-aware GLiNER label selection.

Tests cover:
- Category detection from keyword patterns
- Label selection for each content category
- Combined categories produce union of labels
- Fallback to all labels when too few selected
- Profiling uses only a sample of the text
"""

import pytest

from openlabels.core.detectors.gliner_label_selector import (
    _MIN_LABELS,
    ContentCategory,
    profile_content,
)


class TestContentProfiling:
    """Test that keyword heuristics activate the right categories."""

    def test_medical_document(self):
        text = (
            "PATIENT: John Smith\n"
            "DIAGNOSIS: Type 2 Diabetes\n"
            "Medication: Metformin 500mg b.i.d.\n"
            "Chief complaint: elevated blood sugar\n"
        )
        profile = profile_content(text)
        assert ContentCategory.MEDICAL in profile.categories
        assert ContentCategory.GENERAL in profile.categories

    def test_financial_document(self):
        text = (
            "ACCOUNT STATEMENT\n"
            "Bank account: 1234567890\n"
            "Wire transfer of $5,000 USD\n"
            "IBAN: DE89370400440532013000\n"
        )
        profile = profile_content(text)
        assert ContentCategory.FINANCIAL in profile.categories

    def test_personal_id_document(self):
        text = (
            "APPLICATION FORM\n"
            "SSN: 123-45-6789\n"
            "Driver's license: D1234567\n"
            "Date of birth: 01/15/1990\n"
        )
        profile = profile_content(text)
        assert ContentCategory.PERSONAL_ID in profile.categories

    def test_technical_document(self):
        text = (
            "# .env\n"
            "API_KEY=sk-abc123\n"
            "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG\n"
            "DATABASE_URL=postgres://user:PASSWORD@host/db\n"
        )
        profile = profile_content(text)
        assert ContentCategory.TECHNICAL in profile.categories

    def test_government_document(self):
        text = (
            "Classification: TOP SECRET//SCI//NOFORN\n"
            "DOD Contract #FA8721-05-C-0002\n"
            "CAGE Code: 1ABC2\n"
        )
        profile = profile_content(text)
        assert ContentCategory.GOVERNMENT in profile.categories

    def test_contact_document(self):
        text = (
            "Contact Directory\n"
            "Phone: (555) 123-4567\n"
            "Email: john@example.com\n"
            "Address: 123 Main Street\n"
            "City: Springfield, State: IL, Zip: 62701\n"
        )
        profile = profile_content(text)
        assert ContentCategory.CONTACT in profile.categories

    def test_combined_medical_financial(self):
        text = (
            "Patient billing record\n"
            "DIAGNOSIS: Appendicitis\n"
            "Medication: Amoxicillin\n"
            "Credit card: 4111-1111-1111-1111\n"
            "Bank account for direct payment\n"
            "Invoice total: $12,500 USD\n"
        )
        profile = profile_content(text)
        assert ContentCategory.MEDICAL in profile.categories
        assert ContentCategory.FINANCIAL in profile.categories

    def test_general_always_active(self):
        text = "Hello world, this is just plain text."
        profile = profile_content(text)
        assert ContentCategory.GENERAL in profile.categories

    def test_plain_text_no_extra_categories(self):
        text = "The quick brown fox jumps over the lazy dog."
        profile = profile_content(text)
        # Only GENERAL should be active
        non_general = profile.categories & ~ContentCategory.GENERAL
        assert not non_general


class TestLabelSelection:
    """Test that the correct labels are selected for each category."""

    def test_general_labels_always_present(self):
        text = "Some generic text with no PII keywords at all."
        profile = profile_content(text)
        # GENERAL labels should always be present (focused set for GLiNER)
        assert "person name" in profile.selected_labels
        assert "first name" in profile.selected_labels
        assert "date of birth" in profile.selected_labels
        # company/job are NOT in GENERAL — they're not PII and
        # were removed to free GLiNER's attention budget for real PII.
        assert "company name" not in profile.selected_labels
        assert "job title" not in profile.selected_labels
        # email/phone are NOT in GENERAL — they're in CONTACT category
        # because pattern detectors already handle them reliably
        assert "email address" not in profile.selected_labels

    def test_medical_includes_mrn(self):
        text = "Patient admitted with chief complaint, diagnosis pending. Medication prescribed."
        profile = profile_content(text)
        assert "medical record number" in profile.selected_labels

    def test_financial_includes_credit_card(self):
        text = "Bank account statement showing wire transfer of $10,000 payment."
        profile = profile_content(text)
        assert "credit card number" in profile.selected_labels
        assert "iban" in profile.selected_labels

    def test_personal_id_includes_ssn(self):
        text = "SSN required. Please provide driver's license and passport number."
        profile = profile_content(text)
        assert "social security number" in profile.selected_labels
        assert "driver license number" in profile.selected_labels
        assert "passport number" in profile.selected_labels

    def test_technical_includes_password(self):
        text = "AWS_SECRET_KEY=test\nAPI_KEY=sk-test\nPASSWORD=secret"
        profile = profile_content(text)
        assert "password" in profile.selected_labels
        assert "ip address" in profile.selected_labels

    def test_no_duplicate_labels(self):
        # Combined categories should not have duplicate labels
        text = (
            "Patient SSN: 123-45-6789\n"
            "Diagnosis: diabetes\n"
            "Credit card on file\n"
            "Phone: (555) 123-4567\n"
        )
        profile = profile_content(text)
        assert len(profile.selected_labels) == len(set(profile.selected_labels))


class TestFallbackBehavior:
    """Test fallback to all labels when too few are selected."""

    def test_minimum_label_count(self):
        # Any profile should have at least _MIN_LABELS labels
        text = ""
        profile = profile_content(text)
        assert len(profile.selected_labels) >= _MIN_LABELS

    def test_empty_text_gets_general_labels(self):
        profile = profile_content("")
        # Only GENERAL active, but its 7 labels >= _MIN_LABELS
        assert len(profile.selected_labels) >= _MIN_LABELS
        assert "person name" in profile.selected_labels

    def test_whitespace_text_gets_general_labels(self):
        profile = profile_content("   \n\t  ")
        assert len(profile.selected_labels) >= _MIN_LABELS
        assert "person name" in profile.selected_labels


class TestSampling:
    """Test that profiling only scans a sample of text."""

    def test_custom_sample_size(self):
        # Put keywords after the sample window — they should NOT be detected
        medical_keywords = "Patient diagnosis medication hospital clinical"
        text = ("x" * 100) + medical_keywords
        # With sample_size=50, the keywords are outside the sample
        profile = profile_content(text, sample_size=50)
        assert ContentCategory.MEDICAL not in profile.categories

    def test_default_sample_size_covers_headers(self):
        # Keywords in the first 5000 chars should be detected
        text = "Patient diagnosis medication hospital clinical" + ("x" * 10000)
        profile = profile_content(text)
        assert ContentCategory.MEDICAL in profile.categories


class TestContentProfile:
    """Test ContentProfile data structure."""

    def test_profile_has_scores(self):
        text = "Patient diagnosis medication hospital clinical"
        profile = profile_content(text)
        assert "MEDICAL" in profile.category_scores
        assert profile.category_scores["MEDICAL"] > 0

    def test_profile_is_frozen(self):
        text = "test"
        profile = profile_content(text)
        with pytest.raises(AttributeError):
            profile.categories = ContentCategory.GENERAL  # type: ignore[misc]

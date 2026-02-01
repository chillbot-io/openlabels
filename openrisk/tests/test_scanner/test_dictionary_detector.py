"""
Comprehensive tests for the DictionaryDetector.

Tests dictionary loading, Aho-Corasick vs fallback detection,
word boundary checking, deny list filtering, and all entity types.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from openlabels.adapters.scanner.detectors.dictionaries import (
    DictionaryDetector,
    DRUG_DENY_LIST,
    _AHOCORASICK_AVAILABLE,
)
from openlabels.adapters.scanner.detectors.constants import CONFIDENCE_WEAK


class TestDictionaryDetectorInit:
    """Tests for DictionaryDetector initialization."""

    def test_init_without_directory(self):
        """Test initialization without dictionary directory."""
        detector = DictionaryDetector()
        assert detector._loaded is False
        assert detector.is_available() is False

    def test_init_with_nonexistent_directory(self):
        """Test initialization with nonexistent directory."""
        detector = DictionaryDetector(Path("/nonexistent/path"))
        assert detector._loaded is False

    def test_init_with_valid_directory_loads(self):
        """Test initialization with valid directory triggers load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Create a minimal dictionary file
            (tmppath / "drugs.txt").write_text("aspirin\nibuprofen\n")

            detector = DictionaryDetector(tmppath)
            assert detector._loaded is True
            assert detector.is_available() is True


class TestDictionaryLoading:
    """Tests for dictionary file loading."""

    def test_load_drugs_file(self):
        """Test loading drugs dictionary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("aspirin\nibuprofen\nacetaminophen\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            result = detector.load()

            assert result is True
            assert "aspirin" in detector._drugs
            assert "ibuprofen" in detector._drugs
            assert "acetaminophen" in detector._drugs

    def test_load_filters_short_terms(self):
        """Test that short terms are filtered (min_length=4 for drugs)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("abc\naspirin\nxy\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()

            assert "abc" not in detector._drugs  # Too short
            assert "xy" not in detector._drugs   # Too short
            assert "aspirin" in detector._drugs  # Long enough

    def test_load_filters_deny_list(self):
        """Test that deny list terms are filtered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Include some deny list terms
            (tmppath / "drugs.txt").write_text("aspirin\nhealth\nsupport\nvicodin\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()

            assert "aspirin" in detector._drugs
            assert "vicodin" in detector._drugs
            assert "health" not in detector._drugs  # In deny list
            assert "support" not in detector._drugs  # In deny list

    def test_load_skips_comments(self):
        """Test that comment lines are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("# This is a comment\naspirin\n# Another comment\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()

            assert "aspirin" in detector._drugs
            assert "# this is a comment" not in detector._drugs

    def test_load_skips_empty_lines(self):
        """Test that empty lines are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("aspirin\n\n\nibuprofen\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()

            assert "" not in detector._drugs
            assert len(detector._drugs) == 2

    def test_load_lowercases_terms(self):
        """Test that terms are lowercased."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("ASPIRIN\nIbuprofen\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()

            assert "aspirin" in detector._drugs
            assert "ibuprofen" in detector._drugs
            assert "ASPIRIN" not in detector._drugs

    def test_load_all_dictionary_types(self):
        """Test loading all dictionary types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create all dictionary files
            (tmppath / "drugs.txt").write_text("aspirin\n")
            (tmppath / "diagnoses.txt").write_text("diabetes\n")
            (tmppath / "facilities.txt").write_text("massachusetts general hospital\n")
            (tmppath / "lab_tests.txt").write_text("cbc\n")
            (tmppath / "payers.txt").write_text("blue cross\n")
            (tmppath / "professions.txt").write_text("physician\n")

            # Create geo subdirectory
            geo_dir = tmppath / "geo"
            geo_dir.mkdir()
            (geo_dir / "cities.txt").write_text("boston\n")
            (geo_dir / "states.txt").write_text("ma\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            result = detector.load()

            assert result is True
            assert "aspirin" in detector._drugs
            assert "diabetes" in detector._diagnoses
            assert "massachusetts general hospital" in detector._facilities
            assert "cbc" in detector._lab_tests
            assert "blue cross" in detector._payers
            assert "physician" in detector._professions
            assert "boston" in detector._cities
            assert "ma" in detector._states

    def test_load_handles_unicode_error(self):
        """Test graceful handling of unicode decode errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Write binary data that's not valid UTF-8
            (tmppath / "drugs.txt").write_bytes(b"\xff\xfe invalid")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            # Should not raise, just return empty set
            detector.load()
            # May or may not load anything depending on error handling


class TestWordBoundaryChecking:
    """Tests for word boundary detection."""

    def test_word_at_start(self):
        """Test match at start of text."""
        detector = DictionaryDetector()
        assert detector._is_word_boundary("hello world", 0, 5) is True

    def test_word_at_end(self):
        """Test match at end of text."""
        detector = DictionaryDetector()
        assert detector._is_word_boundary("hello world", 6, 11) is True

    def test_word_in_middle(self):
        """Test match in middle of text."""
        detector = DictionaryDetector()
        assert detector._is_word_boundary("the aspirin works", 4, 11) is True

    def test_not_word_boundary_prefix(self):
        """Test match that's part of larger word (prefix)."""
        detector = DictionaryDetector()
        # "cat" in "category" should not match
        assert detector._is_word_boundary("category", 0, 3) is False

    def test_not_word_boundary_suffix(self):
        """Test match that's part of larger word (suffix)."""
        detector = DictionaryDetector()
        # "ion" in "medication" should not match
        assert detector._is_word_boundary("medication", 7, 10) is False

    def test_word_with_punctuation(self):
        """Test word boundary with punctuation."""
        detector = DictionaryDetector()
        # "aspirin." should match "aspirin"
        assert detector._is_word_boundary("take aspirin.", 5, 12) is True

    def test_word_with_comma(self):
        """Test word boundary with comma."""
        detector = DictionaryDetector()
        assert detector._is_word_boundary("aspirin, ibuprofen", 0, 7) is True


class TestDetectionWithFallback:
    """Tests for detection using fallback (non-Aho-Corasick) method."""

    @pytest.fixture
    def detector_with_drugs(self):
        """Create detector with drug dictionary loaded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("aspirin\nibuprofen\nacetaminophen\nmetformin\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()
            # Force fallback mode
            detector._use_automaton = False
            yield detector

    def test_detect_single_drug(self, detector_with_drugs):
        """Test detection of single drug mention."""
        text = "Patient takes aspirin daily."
        spans = detector_with_drugs.detect(text)

        drug_spans = [s for s in spans if s.entity_type == "MEDICATION"]
        assert len(drug_spans) == 1
        assert drug_spans[0].text == "aspirin"
        assert drug_spans[0].confidence == CONFIDENCE_WEAK

    def test_detect_multiple_drugs(self, detector_with_drugs):
        """Test detection of multiple drugs."""
        text = "Patient takes aspirin and ibuprofen."
        spans = detector_with_drugs.detect(text)

        drug_spans = [s for s in spans if s.entity_type == "MEDICATION"]
        assert len(drug_spans) == 2
        texts = {s.text for s in drug_spans}
        assert "aspirin" in texts
        assert "ibuprofen" in texts

    def test_detect_case_insensitive(self, detector_with_drugs):
        """Test case-insensitive detection."""
        text = "Patient takes ASPIRIN and Ibuprofen."
        spans = detector_with_drugs.detect(text)

        drug_spans = [s for s in spans if s.entity_type == "MEDICATION"]
        assert len(drug_spans) == 2

    def test_no_match_partial_word(self, detector_with_drugs):
        """Test no match on partial words."""
        text = "The aspirinoid compound was tested."
        spans = detector_with_drugs.detect(text)

        # Should not match "aspirin" as part of "aspirinoid"
        drug_spans = [s for s in spans if s.entity_type == "MEDICATION"]
        assert len(drug_spans) == 0

    def test_detect_preserves_original_case(self, detector_with_drugs):
        """Test that detected span preserves original case."""
        text = "Patient takes ASPIRIN daily."
        spans = detector_with_drugs.detect(text)

        drug_spans = [s for s in spans if s.entity_type == "MEDICATION"]
        assert len(drug_spans) == 1
        assert drug_spans[0].text == "ASPIRIN"  # Original case preserved

    def test_detect_empty_text(self, detector_with_drugs):
        """Test detection on empty text."""
        spans = detector_with_drugs.detect("")
        assert spans == []

    def test_detect_not_loaded(self):
        """Test detection when not loaded returns empty."""
        detector = DictionaryDetector()
        spans = detector.detect("aspirin ibuprofen")
        assert spans == []


class TestDetectionWithAhoCorasick:
    """Tests for detection using Aho-Corasick automaton."""

    @pytest.fixture
    def detector_with_automaton(self):
        """Create detector with Aho-Corasick enabled (if available)."""
        if not _AHOCORASICK_AVAILABLE:
            pytest.skip("pyahocorasick not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("aspirin\nibuprofen\n")
            (tmppath / "diagnoses.txt").write_text("diabetes\nhypertension\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()

            assert detector._use_automaton is True
            yield detector

    @pytest.mark.skipif(not _AHOCORASICK_AVAILABLE, reason="pyahocorasick not installed")
    def test_automaton_detects_drugs(self, detector_with_automaton):
        """Test Aho-Corasick detects drugs."""
        text = "Patient takes aspirin for headaches."
        spans = detector_with_automaton.detect(text)

        drug_spans = [s for s in spans if s.entity_type == "MEDICATION"]
        assert len(drug_spans) == 1
        assert drug_spans[0].text == "aspirin"

    @pytest.mark.skipif(not _AHOCORASICK_AVAILABLE, reason="pyahocorasick not installed")
    def test_automaton_detects_multiple_types(self, detector_with_automaton):
        """Test Aho-Corasick detects multiple entity types."""
        text = "Patient with diabetes takes aspirin."
        spans = detector_with_automaton.detect(text)

        types = {s.entity_type for s in spans}
        assert "MEDICATION" in types
        assert "DIAGNOSIS" in types

    @pytest.mark.skipif(not _AHOCORASICK_AVAILABLE, reason="pyahocorasick not installed")
    def test_automaton_word_boundary(self, detector_with_automaton):
        """Test Aho-Corasick respects word boundaries."""
        text = "The aspirinoid compound helps diabetics."
        spans = detector_with_automaton.detect(text)

        # Should not match partial words
        drug_spans = [s for s in spans if s.entity_type == "MEDICATION"]
        assert len(drug_spans) == 0


class TestAllEntityTypes:
    """Tests for detection of all entity types."""

    @pytest.fixture
    def full_detector(self):
        """Create detector with all dictionary types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            (tmppath / "drugs.txt").write_text("aspirin\nmetformin\n")
            (tmppath / "diagnoses.txt").write_text("diabetes\nhypertension\n")
            (tmppath / "facilities.txt").write_text("johns hopkins hospital\n")
            (tmppath / "lab_tests.txt").write_text("hemoglobin a1c\n")
            (tmppath / "payers.txt").write_text("blue cross blue shield\n")
            (tmppath / "professions.txt").write_text("registered nurse\n")

            geo_dir = tmppath / "geo"
            geo_dir.mkdir()
            (geo_dir / "cities.txt").write_text("baltimore\n")
            (geo_dir / "states.txt").write_text("maryland\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()
            # Use fallback for consistent testing
            detector._use_automaton = False
            yield detector

    def test_detect_medication(self, full_detector):
        """Test MEDICATION detection."""
        spans = full_detector.detect("prescribed aspirin")
        types = [s.entity_type for s in spans]
        assert "MEDICATION" in types

    def test_detect_diagnosis(self, full_detector):
        """Test DIAGNOSIS detection."""
        spans = full_detector.detect("diagnosed with diabetes")
        types = [s.entity_type for s in spans]
        assert "DIAGNOSIS" in types

    def test_detect_facility(self, full_detector):
        """Test FACILITY detection."""
        spans = full_detector.detect("treated at johns hopkins hospital")
        types = [s.entity_type for s in spans]
        assert "FACILITY" in types

    def test_detect_lab_test(self, full_detector):
        """Test LAB_TEST detection."""
        spans = full_detector.detect("hemoglobin a1c was elevated")
        types = [s.entity_type for s in spans]
        assert "LAB_TEST" in types

    def test_detect_payer(self, full_detector):
        """Test PAYER detection."""
        spans = full_detector.detect("insured by blue cross blue shield")
        types = [s.entity_type for s in spans]
        assert "PAYER" in types

    def test_detect_profession(self, full_detector):
        """Test PROFESSION detection."""
        spans = full_detector.detect("seen by registered nurse")
        types = [s.entity_type for s in spans]
        assert "PROFESSION" in types

    def test_detect_city(self, full_detector):
        """Test CITY detection."""
        spans = full_detector.detect("lives in baltimore")
        types = [s.entity_type for s in spans]
        assert "CITY" in types

    def test_detect_state(self, full_detector):
        """Test STATE detection."""
        spans = full_detector.detect("resident of maryland")
        types = [s.entity_type for s in spans]
        assert "STATE" in types


class TestDrugDenyList:
    """Tests for the drug deny list."""

    def test_deny_list_contains_common_words(self):
        """Test deny list contains expected common words."""
        assert "health" in DRUG_DENY_LIST
        assert "support" in DRUG_DENY_LIST
        assert "tablet" in DRUG_DENY_LIST
        assert "pain" in DRUG_DENY_LIST

    def test_deny_list_contains_lab_terms(self):
        """Test deny list contains lab test terms."""
        assert "glucose" in DRUG_DENY_LIST
        assert "cholesterol" in DRUG_DENY_LIST

    def test_deny_list_is_frozenset(self):
        """Test deny list is immutable."""
        assert isinstance(DRUG_DENY_LIST, frozenset)


class TestMaxMatchesLimit:
    """Tests for max matches per term limit."""

    def test_max_matches_limit(self):
        """Test that MAX_MATCHES_PER_TERM limits repeated matches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("test\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()
            detector._use_automaton = False

            # Create text with many repetitions
            text = " ".join(["test"] * 200)
            spans = detector.detect(text)

            # Should be limited to MAX_MATCHES_PER_TERM
            assert len(spans) <= detector.MAX_MATCHES_PER_TERM


class TestSpanAttributes:
    """Tests for span attribute correctness."""

    @pytest.fixture
    def detector(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "drugs.txt").write_text("aspirin\n")

            detector = DictionaryDetector()
            detector.dictionaries_dir = tmppath
            detector.load()
            detector._use_automaton = False
            yield detector

    def test_span_positions(self, detector):
        """Test span start/end positions are correct."""
        text = "The aspirin works well."
        spans = detector.detect(text)

        assert len(spans) == 1
        span = spans[0]
        assert span.start == 4
        assert span.end == 11
        assert text[span.start:span.end] == "aspirin"

    def test_span_detector_name(self, detector):
        """Test span has correct detector name."""
        spans = detector.detect("take aspirin")
        assert spans[0].detector == "dictionary"

    def test_span_confidence(self, detector):
        """Test span has weak confidence."""
        spans = detector.detect("take aspirin")
        assert spans[0].confidence == CONFIDENCE_WEAK

    def test_span_tier(self, detector):
        """Test span has ML tier (lowest)."""
        from openlabels.adapters.scanner.types import Tier
        spans = detector.detect("take aspirin")
        assert spans[0].tier == Tier.ML

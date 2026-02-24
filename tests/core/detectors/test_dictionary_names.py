"""Tests for dictionary-based name detection.

Covers the DictionaryNameDetector: standard name detection, 3-letter name
adjacency logic, address suffix suppression, confidence levels, and
ambiguous name filtering.
"""

import pytest

from openlabels.core.detectors.dictionary_names import DictionaryNameDetector


@pytest.fixture
def detector():
    return DictionaryNameDetector()


class TestStandardNameDetection:
    """Test detection of 4+ letter names (original behavior)."""

    def test_detects_first_name(self, detector):
        spans = detector.detect("Hello Michael here")
        assert any(s.text == "Michael" and s.entity_type == "FIRSTNAME" for s in spans)

    def test_detects_last_name(self, detector):
        spans = detector.detect("Hello Garcia here")
        assert any(s.text == "Garcia" and s.entity_type == "LASTNAME" for s in spans)

    def test_first_name_confidence(self, detector):
        spans = detector.detect("Hello Michael here")
        first = [s for s in spans if s.text == "Michael"]
        assert first[0].confidence == 0.65

    def test_last_name_confidence(self, detector):
        spans = detector.detect("Hello Garcia here")
        last = [s for s in spans if s.text == "Garcia"]
        assert last[0].confidence == 0.62

    def test_ignores_lowercase(self, detector):
        spans = detector.detect("hello michael here")
        assert len(spans) == 0

    def test_ignores_allcaps(self, detector):
        spans = detector.detect("Hello MICHAEL here")
        assert not any(s.text == "MICHAEL" for s in spans)


class TestThreeLetterNames:
    """Test 3-letter name detection with adjacency context requirement."""

    def test_three_letter_with_following_name(self, detector):
        """3-letter first name detected when followed by a known name."""
        spans = detector.detect("Lee Johnson arrived")
        assert any(s.text == "Lee" and s.entity_type == "FIRSTNAME" for s in spans)

    def test_three_letter_with_preceding_name(self, detector):
        """3-letter last name detected when preceded by a known name."""
        spans = detector.detect("Sarah Lee is here")
        assert any(s.text == "Lee" and s.entity_type == "FIRSTNAME" for s in spans)

    def test_three_letter_with_honorific(self, detector):
        """3-letter name detected after an honorific prefix (Dr., Mr., etc.)."""
        spans = detector.detect("I spoke with Dr. Lee today")
        assert any(s.text == "Lee" for s in spans)

    def test_three_letter_standalone_not_detected(self, detector):
        """3-letter name without adjacent name context is not detected."""
        spans = detector.detect("The Lee method works")
        assert not any(s.text == "Lee" for s in spans)

    def test_three_letter_after_common_word_not_detected(self, detector):
        """3-letter name after common title-cased word (not a name) is not detected."""
        spans = detector.detect("Our Sam project is great")
        assert not any(s.text == "Sam" for s in spans)

    def test_two_three_letter_names_mutual_context(self, detector):
        """Two adjacent 3-letter names provide context for each other."""
        spans = detector.detect("Kim Lee joined the team")
        texts = {s.text for s in spans}
        assert "Kim" in texts
        assert "Lee" in texts

    def test_three_letter_ali_with_context(self, detector):
        spans = detector.detect("Hello Ali Mohammed")
        assert any(s.text == "Ali" for s in spans)

    def test_two_letter_never_detected(self, detector):
        """Names with < 3 chars are never detected."""
        spans = detector.detect("Bo Jackson arrived")
        assert not any(s.text == "Bo" for s in spans)


class TestAddressSuffixSuppression:
    """Test that names before address suffixes are suppressed."""

    def test_name_before_street(self, detector):
        """Name followed by 'Street' is suppressed (address context)."""
        spans = detector.detect("Turner Street is nearby")
        assert not any(s.text == "Turner" for s in spans)

    def test_name_before_avenue(self, detector):
        spans = detector.detect("Jackson Avenue runs north")
        assert not any(s.text == "Jackson" for s in spans)


class TestPlacePrefixSuppression:
    """Test that names preceded by place prefixes are suppressed."""

    def test_fort_prefix(self, detector):
        spans = detector.detect("Visit Fort Michael today")
        assert not any(s.text == "Michael" for s in spans)

    def test_lake_prefix(self, detector):
        spans = detector.detect("Near Lake Sarah park")
        assert not any(s.text == "Sarah" for s in spans)


class TestAmbiguousNameFiltering:
    """Test that ambiguous names are excluded."""

    def test_ambiguous_first_name_not_detected(self, detector):
        """Words in _AMBIGUOUS_FIRST are not detected as first names."""
        # "summer" is in _AMBIGUOUS_FIRST
        spans = detector.detect("Hello Summer here")
        assert not any(s.text == "Summer" and s.entity_type == "FIRSTNAME" for s in spans)

    def test_never_names_not_detected(self, detector):
        """Words in _NEVER_NAMES are not detected."""
        # "Director" is in _NEVER_NAMES
        spans = detector.detect("The Director spoke")
        assert not any(s.text == "Director" for s in spans)


class TestDetectorMetadata:
    """Test detector metadata and span properties."""

    def test_detector_name(self, detector):
        assert detector.name == "dictionary_names"

    def test_span_detector_field(self, detector):
        spans = detector.detect("Hello Michael here")
        assert all(s.detector == "dictionary_names" for s in spans)

    def test_span_positions(self, detector):
        text = "Hello Michael here"
        spans = detector.detect(text)
        michael = [s for s in spans if s.text == "Michael"][0]
        assert michael.start == 6
        assert michael.end == 13
        assert text[michael.start:michael.end] == "Michael"

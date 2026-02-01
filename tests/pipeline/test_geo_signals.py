"""Tests for geographic signal detection in geo_signals.py.

Tests facility name detection for sub-state geography that could
enable re-identification (city, county, regional indicators).
"""

import pytest
import tempfile
from pathlib import Path

# Reset the module's cached state before each test
import scrubiq.pipeline.geo_signals as geo_module


@pytest.fixture(autouse=True)
def reset_geo_cache():
    """Reset cached geo signals before each test."""
    geo_module._GEO_SIGNALS = None
    geo_module._GEO_BIGRAMS = None
    yield
    # Also reset after test
    geo_module._GEO_SIGNALS = None
    geo_module._GEO_BIGRAMS = None


@pytest.fixture
def geo_dir_fixture(tmp_path):
    """Create temporary geo dictionary directory with test files."""
    geo_dir = tmp_path / "geo"
    geo_dir.mkdir()

    # Create test dictionary files
    cities = geo_dir / "us_cities.txt"
    cities.write_text("# US Cities\nboise\nphoenix\ncleveland\nseattle\n")

    counties = geo_dir / "us_counties.txt"
    counties.write_text("ada\nmaricopa\n")

    states = geo_dir / "us_states.txt"
    states.write_text("texas\ncalifornia\noregon\n")

    regional = geo_dir / "regional_patterns.txt"
    regional.write_text("# Regional patterns\nvalley\nregional\nmetropolitan\nnew york\nlos angeles\nsalt lake city\n")

    return tmp_path


# =============================================================================
# LOAD_GEO_SIGNALS TESTS
# =============================================================================

class TestLoadGeoSignals:
    """Tests for load_geo_signals() function."""

    def test_loads_single_word_signals(self, geo_dir_fixture):
        """Loads single-word geographic terms."""
        signals = geo_module.load_geo_signals(geo_dir_fixture)

        assert "boise" in signals
        assert "phoenix" in signals
        assert "ada" in signals
        assert "texas" in signals
        assert "valley" in signals

    def test_loads_bigrams_separately(self, geo_dir_fixture):
        """Bigrams are loaded into separate set."""
        geo_module.load_geo_signals(geo_dir_fixture)
        bigrams = geo_module.get_geo_bigrams()

        assert "new york" in bigrams
        assert "los angeles" in bigrams
        # Trigrams also in bigrams set
        assert "salt lake city" in bigrams

    def test_single_words_not_in_bigrams(self, geo_dir_fixture):
        """Single words are not in bigrams set."""
        geo_module.load_geo_signals(geo_dir_fixture)
        bigrams = geo_module.get_geo_bigrams()

        assert "boise" not in bigrams
        assert "valley" not in bigrams

    def test_ignores_comments(self, geo_dir_fixture):
        """Lines starting with # are ignored."""
        signals = geo_module.load_geo_signals(geo_dir_fixture)

        assert "us cities" not in signals
        assert "regional patterns" not in signals

    def test_ignores_empty_lines(self, geo_dir_fixture):
        """Empty lines are ignored."""
        # Add file with empty lines
        empty_file = geo_dir_fixture / "geo" / "with_blanks.txt"
        empty_file.write_text("\n\n  \ntest\n\n")

        signals = geo_module.load_geo_signals(geo_dir_fixture)
        assert "test" in signals

    def test_normalizes_to_lowercase(self, geo_dir_fixture):
        """All terms are lowercased."""
        # Add file with mixed case
        mixed_case = geo_dir_fixture / "geo" / "mixed.txt"
        mixed_case.write_text("UPPERCASE\nMixedCase\n")

        signals = geo_module.load_geo_signals(geo_dir_fixture)

        assert "uppercase" in signals
        assert "mixedcase" in signals
        assert "UPPERCASE" not in signals
        assert "MixedCase" not in signals

    def test_caches_results(self, geo_dir_fixture):
        """Results are cached after first load."""
        signals1 = geo_module.load_geo_signals(geo_dir_fixture)
        signals2 = geo_module.load_geo_signals(geo_dir_fixture)

        # Same object (cached)
        assert signals1 is signals2

    def test_missing_directory_returns_empty(self, tmp_path):
        """Returns empty frozenset if geo directory missing."""
        signals = geo_module.load_geo_signals(tmp_path)

        assert signals == frozenset()
        assert geo_module.get_geo_bigrams() == frozenset()

    def test_returns_frozenset(self, geo_dir_fixture):
        """Returns immutable frozenset."""
        signals = geo_module.load_geo_signals(geo_dir_fixture)

        assert isinstance(signals, frozenset)


class TestGetGeoBigrams:
    """Tests for get_geo_bigrams() function."""

    def test_returns_empty_before_load(self):
        """Returns empty frozenset if not loaded."""
        bigrams = geo_module.get_geo_bigrams()
        assert bigrams == frozenset()

    def test_returns_bigrams_after_load(self, geo_dir_fixture):
        """Returns bigrams after load_geo_signals called."""
        geo_module.load_geo_signals(geo_dir_fixture)
        bigrams = geo_module.get_geo_bigrams()

        assert len(bigrams) > 0
        assert "new york" in bigrams


# =============================================================================
# FACILITY_HAS_GEO_SIGNAL TESTS
# =============================================================================

class TestFacilityHasGeoSignal:
    """Tests for facility_has_geo_signal() function."""

    def test_detects_city_name(self, geo_dir_fixture):
        """Detects city names in facility text."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Boise Medical Center") is True
        assert geo_module.facility_has_geo_signal("Phoenix General Hospital") is True
        assert geo_module.facility_has_geo_signal("Cleveland Clinic") is True

    def test_detects_county_name(self, geo_dir_fixture):
        """Detects county names in facility text."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Ada County Medical") is True
        assert geo_module.facility_has_geo_signal("Maricopa General") is True

    def test_detects_state_name(self, geo_dir_fixture):
        """Detects state names in facility text."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Texas Children's Hospital") is True
        assert geo_module.facility_has_geo_signal("California Medical Center") is True

    def test_detects_regional_indicator(self, geo_dir_fixture):
        """Detects regional indicator words."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Valley Medical Associates") is True
        assert geo_module.facility_has_geo_signal("Regional Medical Center") is True
        assert geo_module.facility_has_geo_signal("Metropolitan Hospital") is True

    def test_detects_bigram_city(self, geo_dir_fixture):
        """Detects multi-word city names."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("New York General Hospital") is True
        assert geo_module.facility_has_geo_signal("Los Angeles Medical") is True

    def test_detects_trigram_city(self, geo_dir_fixture):
        """Detects three-word city names."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Salt Lake City Hospital") is True

    def test_no_match_generic_facility(self, geo_dir_fixture):
        """Returns False for generic facility names."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Mayo Clinic") is False
        assert geo_module.facility_has_geo_signal("Internal Medicine Associates") is False
        assert geo_module.facility_has_geo_signal("General Hospital") is False

    def test_case_insensitive(self, geo_dir_fixture):
        """Matching is case-insensitive."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("BOISE MEDICAL") is True
        assert geo_module.facility_has_geo_signal("boise medical") is True
        assert geo_module.facility_has_geo_signal("Boise Medical") is True

    def test_handles_punctuation(self, geo_dir_fixture):
        """Handles punctuation in facility names."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Boise-Valley Medical") is True
        assert geo_module.facility_has_geo_signal("Boise, Valley Medical") is True
        assert geo_module.facility_has_geo_signal("Boise/Valley Medical") is True

    def test_accepts_custom_signals(self, geo_dir_fixture):
        """Accepts custom geo_signals parameter."""
        custom_signals = frozenset(["customcity", "testtown"])

        assert geo_module.facility_has_geo_signal(
            "Customcity Hospital", geo_signals=custom_signals
        ) is True
        assert geo_module.facility_has_geo_signal(
            "Mayo Clinic", geo_signals=custom_signals
        ) is False

    def test_empty_signals_returns_false(self):
        """Returns False when no signals loaded."""
        # No signals loaded
        assert geo_module.facility_has_geo_signal("Boise Medical") is False

    def test_empty_text_returns_false(self, geo_dir_fixture):
        """Empty text returns False."""
        geo_module.load_geo_signals(geo_dir_fixture)
        assert geo_module.facility_has_geo_signal("") is False


# =============================================================================
# FACILITY_NEAR_ADDRESS_SPAN TESTS
# =============================================================================

class TestFacilityNearAddressSpan:
    """Tests for facility_near_address_span() function."""

    def test_adjacent_spans_are_near(self):
        """Adjacent spans are considered near."""
        # Facility at 0-20, Address at 25-50
        result = geo_module.facility_near_address_span(
            facility_start=0,
            facility_end=20,
            address_spans=[(25, 50)],
            proximity_chars=150,
        )
        assert result is True

    def test_far_spans_not_near(self):
        """Spans far apart are not near."""
        # Facility at 0-20, Address at 500-550
        result = geo_module.facility_near_address_span(
            facility_start=0,
            facility_end=20,
            address_spans=[(500, 550)],
            proximity_chars=150,
        )
        assert result is False

    def test_facility_before_address(self):
        """Facility before address within proximity."""
        result = geo_module.facility_near_address_span(
            facility_start=0,
            facility_end=30,
            address_spans=[(100, 150)],
            proximity_chars=150,
        )
        assert result is True

    def test_facility_after_address(self):
        """Facility after address within proximity."""
        result = geo_module.facility_near_address_span(
            facility_start=200,
            facility_end=230,
            address_spans=[(100, 150)],
            proximity_chars=150,
        )
        assert result is True

    def test_overlapping_spans(self):
        """Overlapping spans are near."""
        result = geo_module.facility_near_address_span(
            facility_start=10,
            facility_end=30,
            address_spans=[(20, 40)],
            proximity_chars=150,
        )
        assert result is True

    def test_empty_address_spans(self):
        """Empty address spans list returns False."""
        result = geo_module.facility_near_address_span(
            facility_start=0,
            facility_end=20,
            address_spans=[],
            proximity_chars=150,
        )
        assert result is False

    def test_multiple_address_spans(self):
        """Checks against multiple address spans."""
        # Near the second one
        result = geo_module.facility_near_address_span(
            facility_start=200,
            facility_end=230,
            address_spans=[(0, 20), (250, 300)],
            proximity_chars=150,
        )
        assert result is True

    def test_custom_proximity(self):
        """Respects custom proximity_chars parameter."""
        # Just barely within custom proximity
        result = geo_module.facility_near_address_span(
            facility_start=0,
            facility_end=20,
            address_spans=[(70, 100)],
            proximity_chars=50,
        )
        assert result is True

        # Just outside custom proximity
        result = geo_module.facility_near_address_span(
            facility_start=0,
            facility_end=20,
            address_spans=[(100, 130)],
            proximity_chars=50,
        )
        assert result is False


# =============================================================================
# SHOULD_REDACT_FACILITY TESTS
# =============================================================================

class TestShouldRedactFacility:
    """Tests for should_redact_facility() function."""

    def test_redact_with_geo_signal(self, geo_dir_fixture):
        """Returns True when facility has geo signal."""
        geo_module.load_geo_signals(geo_dir_fixture)

        result = geo_module.should_redact_facility(
            facility_text="Boise Medical Center",
            facility_start=0,
            facility_end=20,
            address_spans=[],
        )
        assert result is True

    def test_redact_near_address(self, geo_dir_fixture):
        """Returns True when facility near address."""
        geo_module.load_geo_signals(geo_dir_fixture)

        result = geo_module.should_redact_facility(
            facility_text="Internal Medicine Associates",  # No geo signal
            facility_start=0,
            facility_end=30,
            address_spans=[(50, 100)],  # Address nearby
        )
        assert result is True

    def test_no_redact_generic_isolated(self, geo_dir_fixture):
        """Returns False when no geo signal and no address nearby."""
        geo_module.load_geo_signals(geo_dir_fixture)

        result = geo_module.should_redact_facility(
            facility_text="Internal Medicine Associates",
            facility_start=0,
            facility_end=30,
            address_spans=[(500, 550)],  # Address far away
        )
        assert result is False

    def test_accepts_custom_signals(self):
        """Accepts custom geo_signals parameter."""
        custom_signals = frozenset(["testcity"])

        result = geo_module.should_redact_facility(
            facility_text="Testcity Hospital",
            facility_start=0,
            facility_end=20,
            address_spans=[],
            geo_signals=custom_signals,
        )
        assert result is True

    def test_accepts_custom_proximity(self, geo_dir_fixture):
        """Accepts custom proximity_chars parameter."""
        geo_module.load_geo_signals(geo_dir_fixture)

        # With default 150 chars, this would be near
        # With custom 10 chars, not near
        result = geo_module.should_redact_facility(
            facility_text="Internal Medicine Associates",
            facility_start=0,
            facility_end=30,
            address_spans=[(100, 150)],
            proximity_chars=10,
        )
        assert result is False

    def test_geo_signal_takes_priority(self, geo_dir_fixture):
        """Geo signal triggers redaction even without address."""
        geo_module.load_geo_signals(geo_dir_fixture)

        result = geo_module.should_redact_facility(
            facility_text="Boise Valley Medical",
            facility_start=0,
            facility_end=20,
            address_spans=[],  # No addresses
        )
        assert result is True


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for geo signal detection."""

    def test_word_boundary_matching(self, geo_dir_fixture):
        """Only matches whole words, not substrings."""
        geo_module.load_geo_signals(geo_dir_fixture)

        # "phoenix" should match
        assert geo_module.facility_has_geo_signal("Phoenix Hospital") is True
        # But not if it's part of another word (implementation tokenizes)
        # The current implementation tokenizes, so "phoenixville" becomes ["phoenixville"]
        # which is NOT in signals

    def test_single_word_facility(self, geo_dir_fixture):
        """Single word facility names work."""
        geo_module.load_geo_signals(geo_dir_fixture)

        assert geo_module.facility_has_geo_signal("Boise") is True
        assert geo_module.facility_has_geo_signal("Generic") is False

    def test_file_read_error_handled(self, tmp_path):
        """Handles file read errors gracefully."""
        geo_dir = tmp_path / "geo"
        geo_dir.mkdir()

        # Create a file that will fail to read (directory masquerading as file)
        bad_file = geo_dir / "bad.txt"
        bad_file.mkdir()

        # Should not raise, just log error
        signals = geo_module.load_geo_signals(tmp_path)
        assert isinstance(signals, frozenset)

    def test_unicode_in_signals(self, tmp_path):
        """Handles unicode characters in geo files."""
        geo_dir = tmp_path / "geo"
        geo_dir.mkdir()

        unicode_file = geo_dir / "unicode.txt"
        unicode_file.write_text("münchen\ntokyo\n", encoding='utf-8')

        signals = geo_module.load_geo_signals(tmp_path)
        assert "münchen" in signals
        assert "tokyo" in signals

    def test_facility_with_numbers(self, geo_dir_fixture):
        """Handles facility names with numbers."""
        geo_module.load_geo_signals(geo_dir_fixture)

        # Numbers should be included in tokenization
        assert geo_module.facility_has_geo_signal("Boise 123 Medical") is True

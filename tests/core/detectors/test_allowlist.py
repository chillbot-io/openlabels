"""Tests for allowlist-based false positive suppression.

Tests the Allowlist class and helper functions in
openlabels.core.detectors.allowlist, covering:
- Basic allowlist matching (exact match, dictionary-backed rules)
- Case sensitivity handling
- Empty allowlist behavior
- Custom allowlist with specific entity types and wildcard (all types)
- Suppression of spans that match allowlist entries
- Non-suppression of spans that do not match
- filter_spans bulk filtering
- Dictionary loading edge cases
"""

from pathlib import Path

from openlabels.core.detectors.allowlist import (
    Allowlist,
    _load_custom_allowlist,
    _load_terms,
)
from tests.conftest import make_span

# =============================================================================
# HELPER: Temporary dictionary files
# =============================================================================


def _write_file(path: Path, content: str) -> None:
    """Write content to a file, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# =============================================================================
# _load_terms TESTS
# =============================================================================


class TestLoadTerms:
    """Tests for the _load_terms helper function."""

    def test_load_basic_terms(self, tmp_path):
        f = tmp_path / "terms.txt"
        _write_file(f, "Aspirin\nIbuprofen\nTylenol\n")
        terms = _load_terms(f)
        assert "aspirin" in terms
        assert "ibuprofen" in terms
        assert "tylenol" in terms

    def test_load_terms_lowercases(self, tmp_path):
        f = tmp_path / "terms.txt"
        _write_file(f, "HOSPITAL\nClinic\nmri\n")
        terms = _load_terms(f)
        assert "hospital" in terms
        assert "clinic" in terms
        assert "mri" in terms

    def test_load_terms_skips_comments_and_blanks(self, tmp_path):
        f = tmp_path / "terms.txt"
        _write_file(f, "# This is a comment\n\nAspirin\n\n# Another comment\nTylenol\n")
        terms = _load_terms(f)
        assert len(terms) == 2
        assert "aspirin" in terms
        assert "tylenol" in terms

    def test_load_terms_strips_whitespace(self, tmp_path):
        f = tmp_path / "terms.txt"
        _write_file(f, "  Aspirin  \n  Tylenol  \n")
        terms = _load_terms(f)
        assert "aspirin" in terms
        assert "tylenol" in terms

    def test_load_terms_nonexistent_file(self, tmp_path):
        f = tmp_path / "nonexistent.txt"
        terms = _load_terms(f)
        assert len(terms) == 0

    def test_load_terms_empty_file(self, tmp_path):
        f = tmp_path / "terms.txt"
        _write_file(f, "")
        terms = _load_terms(f)
        assert len(terms) == 0

    def test_load_terms_returns_frozenset(self, tmp_path):
        f = tmp_path / "terms.txt"
        _write_file(f, "one\ntwo\n")
        terms = _load_terms(f)
        assert isinstance(terms, frozenset)


# =============================================================================
# _load_custom_allowlist TESTS
# =============================================================================


class TestLoadCustomAllowlist:
    """Tests for the _load_custom_allowlist helper function."""

    def test_load_term_all_types(self, tmp_path):
        """A term without a tab suppresses all entity types."""
        f = tmp_path / "allowlist.txt"
        _write_file(f, "aspirin\n")
        entries = _load_custom_allowlist(f)
        assert "aspirin" in entries
        assert entries["aspirin"] == frozenset()  # empty = all types

    def test_load_term_specific_types(self, tmp_path):
        """A term with tab-separated types suppresses only those types."""
        f = tmp_path / "allowlist.txt"
        _write_file(f, "aspirin\tNAME,FIRSTNAME\n")
        entries = _load_custom_allowlist(f)
        assert "aspirin" in entries
        assert entries["aspirin"] == frozenset({"NAME", "FIRSTNAME"})

    def test_load_custom_skips_comments_and_blanks(self, tmp_path):
        f = tmp_path / "allowlist.txt"
        _write_file(f, "# comment\n\naspirin\n\n# another\ntylenol\tNAME\n")
        entries = _load_custom_allowlist(f)
        assert len(entries) == 2

    def test_load_custom_lowercases_terms(self, tmp_path):
        f = tmp_path / "allowlist.txt"
        _write_file(f, "ASPIRIN\n")
        entries = _load_custom_allowlist(f)
        assert "aspirin" in entries

    def test_load_custom_uppercases_types(self, tmp_path):
        f = tmp_path / "allowlist.txt"
        _write_file(f, "aspirin\tname,firstname\n")
        entries = _load_custom_allowlist(f)
        assert entries["aspirin"] == frozenset({"NAME", "FIRSTNAME"})

    def test_load_custom_nonexistent_file(self, tmp_path):
        f = tmp_path / "nonexistent.txt"
        entries = _load_custom_allowlist(f)
        assert len(entries) == 0


# =============================================================================
# Allowlist.should_suppress TESTS
# =============================================================================


class TestShouldSuppress:
    """Tests for the Allowlist.should_suppress method."""

    def _make_allowlist_with_dict(self, tmp_path, filename, terms, suppress_types):
        """Create an Allowlist with a single dictionary rule."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / filename, "\n".join(terms))
        al = Allowlist(dict_dir=dict_dir)
        return al

    def test_suppress_matching_term_and_type(self, tmp_path):
        """Span matching both term and entity type is suppressed."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\nst. jude\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("Mercy Hospital", entity_type="NAME")
        assert al.should_suppress(span) is True

    def test_no_suppress_non_matching_type(self, tmp_path):
        """Span matching term but not entity type is NOT suppressed."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("Mercy Hospital", entity_type="ADDRESS")
        assert al.should_suppress(span) is False

    def test_no_suppress_non_matching_term(self, tmp_path):
        """Span with entity type in suppression set but not in dictionary."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("John Smith", entity_type="NAME")
        assert al.should_suppress(span) is False

    def test_case_insensitive_matching(self, tmp_path):
        """Matching is case-insensitive."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "MERCY HOSPITAL\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("mercy hospital", entity_type="NAME")
        assert al.should_suppress(span) is True

    def test_empty_text_not_suppressed(self, tmp_path):
        """Span with empty/whitespace text is never suppressed."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("  ", entity_type="NAME")
        assert al.should_suppress(span) is False

    def test_empty_allowlist(self, tmp_path):
        """An allowlist with no dictionaries suppresses nothing."""
        dict_dir = tmp_path / "empty_dicts"
        dict_dir.mkdir(exist_ok=True)
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("John Smith", entity_type="NAME")
        assert al.should_suppress(span) is False

    def test_custom_allowlist_all_types(self, tmp_path):
        """Custom allowlist entry with no type restriction suppresses all types."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "allowlist.txt", "aspirin\n")
        al = Allowlist(dict_dir=dict_dir)

        span_name = make_span("aspirin", entity_type="NAME")
        span_drug = make_span("aspirin", entity_type="DRUG")
        assert al.should_suppress(span_name) is True
        assert al.should_suppress(span_drug) is True

    def test_custom_allowlist_specific_types(self, tmp_path):
        """Custom allowlist with type restriction only suppresses those types."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "allowlist.txt", "aspirin\tNAME,FIRSTNAME\n")
        al = Allowlist(dict_dir=dict_dir)

        span_name = make_span("aspirin", entity_type="NAME")
        span_addr = make_span("aspirin", entity_type="ADDRESS")
        assert al.should_suppress(span_name) is True
        assert al.should_suppress(span_addr) is False

    def test_custom_allowlist_takes_priority(self, tmp_path):
        """Custom allowlist is checked before dictionary rules."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        # Not in any dictionary rule, but in custom allowlist
        _write_file(dict_dir / "allowlist.txt", "custom term\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("custom term", entity_type="SSN")
        assert al.should_suppress(span) is True

    def test_whitespace_stripped_from_span_text(self, tmp_path):
        """Leading/trailing whitespace in span text is stripped before matching."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("  Mercy Hospital  ", entity_type="NAME")
        assert al.should_suppress(span) is True

    def test_drugs_dictionary_suppression(self, tmp_path):
        """Drugs dictionary suppresses name-type entities."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "drugs.txt", "metformin\nlisinopril\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("metformin", entity_type="NAME")
        assert al.should_suppress(span) is True

    def test_professions_dictionary_suppression(self, tmp_path):
        """Professions dictionary suppresses name-type entities."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "professions.txt", "nurse\ndoctor\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("nurse", entity_type="FIRSTNAME")
        assert al.should_suppress(span) is True

    def test_lazy_loading(self, tmp_path):
        """Dictionaries are loaded lazily on first call."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        al = Allowlist(dict_dir=dict_dir)
        assert al._loaded is False

        al.should_suppress(make_span("anything"))
        assert al._loaded is True

    def test_loaded_only_once(self, tmp_path):
        """_ensure_loaded does not reload on subsequent calls."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        al = Allowlist(dict_dir=dict_dir)

        al.should_suppress(make_span("a"))
        al.should_suppress(make_span("b"))
        # Still loaded = True, rules unchanged
        assert al._loaded is True


# =============================================================================
# Allowlist.filter_spans TESTS
# =============================================================================


class TestFilterSpans:
    """Tests for the Allowlist.filter_spans method."""

    def test_filter_removes_matching_spans(self, tmp_path):
        """Matching spans are removed from the result list."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\n")
        al = Allowlist(dict_dir=dict_dir)

        spans = [
            make_span("Mercy Hospital", start=0, entity_type="NAME"),
            make_span("John Smith", start=20, entity_type="NAME"),
        ]
        filtered = al.filter_spans(spans)
        assert len(filtered) == 1
        assert filtered[0].text == "John Smith"

    def test_filter_keeps_non_matching_spans(self, tmp_path):
        """Non-matching spans are preserved."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        al = Allowlist(dict_dir=dict_dir)

        spans = [
            make_span("John Smith", start=0, entity_type="NAME"),
            make_span("Jane Doe", start=20, entity_type="NAME"),
        ]
        filtered = al.filter_spans(spans)
        assert len(filtered) == 2

    def test_filter_empty_list(self, tmp_path):
        """Filtering an empty list returns an empty list."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        al = Allowlist(dict_dir=dict_dir)
        assert al.filter_spans([]) == []

    def test_filter_all_suppressed(self, tmp_path):
        """When all spans match, result is empty."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "allowlist.txt", "foo\nbar\n")
        al = Allowlist(dict_dir=dict_dir)

        spans = [
            make_span("foo", start=0, entity_type="NAME"),
            make_span("bar", start=10, entity_type="NAME"),
        ]
        filtered = al.filter_spans(spans)
        assert len(filtered) == 0

    def test_filter_preserves_order(self, tmp_path):
        """Non-suppressed spans maintain their original order."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "allowlist.txt", "suppress_me\n")
        al = Allowlist(dict_dir=dict_dir)

        spans = [
            make_span("alpha", start=0, entity_type="NAME"),
            make_span("suppress_me", start=10, entity_type="NAME"),
            make_span("beta", start=30, entity_type="NAME"),
            make_span("gamma", start=40, entity_type="NAME"),
        ]
        filtered = al.filter_spans(spans)
        assert [s.text for s in filtered] == ["alpha", "beta", "gamma"]

    def test_filter_mixed_entity_types(self, tmp_path):
        """Dictionary rules only suppress spans with matching entity types."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\n")
        al = Allowlist(dict_dir=dict_dir)

        spans = [
            make_span("Mercy Hospital", start=0, entity_type="NAME"),       # suppressed
            make_span("Mercy Hospital", start=0, entity_type="ADDRESS"),    # kept
        ]
        filtered = al.filter_spans(spans)
        assert len(filtered) == 1
        assert filtered[0].entity_type == "ADDRESS"


# =============================================================================
# Multiple dictionary rules interaction
# =============================================================================


class TestMultipleDictionaryRules:
    """Tests for interactions between multiple dictionary files."""

    def test_multiple_dictionaries_checked(self, tmp_path):
        """Terms from different dictionaries are all checked."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "facilities.txt", "mercy hospital\n")
        _write_file(dict_dir / "drugs.txt", "aspirin\n")
        al = Allowlist(dict_dir=dict_dir)

        span_facility = make_span("Mercy Hospital", entity_type="NAME")
        span_drug = make_span("aspirin", entity_type="NAME")
        assert al.should_suppress(span_facility) is True
        assert al.should_suppress(span_drug) is True

    def test_clinical_stopwords_suppression(self, tmp_path):
        """Clinical stopwords suppress NAME/USERNAME types."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "clinical_stopwords.txt", "the\nand\nor\n")
        al = Allowlist(dict_dir=dict_dir)

        span = make_span("the", entity_type="USERNAME")
        assert al.should_suppress(span) is True

    def test_us_cities_only_suppress_username(self, tmp_path):
        """US cities dictionary only suppresses USERNAME, not NAME types."""
        dict_dir = tmp_path / "dicts"
        dict_dir.mkdir(exist_ok=True)
        _write_file(dict_dir / "us_cities.txt", "houston\nflorence\n")
        al = Allowlist(dict_dir=dict_dir)

        span_username = make_span("houston", entity_type="USERNAME")
        span_name = make_span("houston", entity_type="NAME")
        assert al.should_suppress(span_username) is True
        assert al.should_suppress(span_name) is False

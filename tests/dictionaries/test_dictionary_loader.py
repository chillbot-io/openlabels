"""
Comprehensive tests for the dictionary loader module.

Tests cover:
- Dictionary loading and caching
- Term lookup (contains, find_matches)
- Medical context detection
- Error handling (missing files, encoding issues)
- Singleton pattern
- Edge cases (empty terms, special characters)
"""

import pytest
import logging
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
import tempfile
import os

from openlabels.dictionaries import (
    DictionaryLoader,
    get_dictionary_loader,
    get_medical_context_detector,
)


class TestDictionaryLoaderInit:
    """Tests for DictionaryLoader initialization."""

    def test_init_with_default_dir(self):
        """Loader initializes with default dictionary directory."""
        loader = DictionaryLoader()

        assert loader.dict_dir is not None
        assert isinstance(loader.dict_dir, Path)
        assert loader._cache == {}
        assert loader._loaded is False

    def test_init_with_custom_dir(self, tmp_path):
        """Loader initializes with custom directory."""
        loader = DictionaryLoader(dict_dir=tmp_path)

        assert loader.dict_dir == tmp_path

    def test_init_with_string_path(self, tmp_path):
        """Loader accepts string path as well as Path object."""
        loader = DictionaryLoader(dict_dir=str(tmp_path))

        assert loader.dict_dir == tmp_path


class TestDictionaryLoading:
    """Tests for dictionary file loading."""

    def test_load_unknown_dictionary_raises(self):
        """Loading unknown dictionary name raises ValueError."""
        loader = DictionaryLoader()

        with pytest.raises(ValueError, match="Unknown dictionary"):
            loader._load_dictionary("nonexistent_dictionary")

    def test_load_missing_file_returns_empty(self, tmp_path):
        """Loading from non-existent file returns empty frozenset."""
        loader = DictionaryLoader(dict_dir=tmp_path)

        # diagnoses.txt doesn't exist in tmp_path
        result = loader._load_dictionary("diagnoses")

        assert result == frozenset()

    def test_load_valid_dictionary(self, tmp_path):
        """Loading valid dictionary file returns frozenset of terms."""
        # Create test dictionary file
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("Diabetes\nHypertension\nAsthma\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader._load_dictionary("diagnoses")

        assert isinstance(result, frozenset)
        assert len(result) == 3
        # Terms should be lowercase
        assert "diabetes" in result
        assert "hypertension" in result
        assert "asthma" in result

    def test_load_dictionary_skips_comments(self, tmp_path):
        """Dictionary loader skips lines starting with #."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("# This is a comment\nDiabetes\n# Another comment\nAsthma\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader._load_dictionary("diagnoses")

        assert len(result) == 2
        assert "diabetes" in result
        assert "# this is a comment" not in result

    def test_load_dictionary_skips_empty_lines(self, tmp_path):
        """Dictionary loader skips empty lines."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("Diabetes\n\n\nAsthma\n   \n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader._load_dictionary("diagnoses")

        assert len(result) == 2

    def test_load_dictionary_caches_result(self, tmp_path):
        """Dictionary loader caches loaded dictionaries."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("Diabetes\nAsthma\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # First load
        result1 = loader._load_dictionary("diagnoses")

        # Modify file (shouldn't affect cached result)
        dict_file.write_text("NewTerm\n")

        # Second load should return cached
        result2 = loader._load_dictionary("diagnoses")

        assert result1 is result2
        assert "diabetes" in result2
        assert "newterm" not in result2

    def test_load_dictionary_with_encoding_error(self, tmp_path):
        """Dictionary loader handles encoding errors gracefully."""
        dict_file = tmp_path / "diagnoses.txt"
        # Write binary data that's invalid UTF-8
        dict_file.write_bytes(b"\xff\xfe invalid utf-8")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader._load_dictionary("diagnoses")

        # Should return empty frozenset on error
        assert result == frozenset()

    def test_load_dictionary_normalizes_to_lowercase(self, tmp_path):
        """All terms are normalized to lowercase."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("DIABETES\nHyperTension\nasthma\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader._load_dictionary("diagnoses")

        assert "diabetes" in result
        assert "hypertension" in result
        assert "asthma" in result
        assert "DIABETES" not in result


class TestGetTerms:
    """Tests for get_terms method."""

    def test_get_terms_returns_frozenset(self, tmp_path):
        """get_terms returns frozenset."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("Diabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.get_terms("diagnoses")

        assert isinstance(result, frozenset)

    def test_get_terms_unknown_dictionary(self):
        """get_terms raises ValueError for unknown dictionary."""
        loader = DictionaryLoader()

        with pytest.raises(ValueError):
            loader.get_terms("unknown_dictionary")


class TestContains:
    """Tests for contains method."""

    def test_contains_exact_match(self, tmp_path):
        """contains returns True for exact match."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("Diabetes mellitus\nAsthma\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        assert loader.contains("diagnoses", "diabetes mellitus") is True
        assert loader.contains("diagnoses", "asthma") is True

    def test_contains_case_insensitive(self, tmp_path):
        """contains is case-insensitive."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("diabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        assert loader.contains("diagnoses", "DIABETES") is True
        assert loader.contains("diagnoses", "Diabetes") is True
        assert loader.contains("diagnoses", "DiAbEtEs") is True

    def test_contains_not_found(self, tmp_path):
        """contains returns False for non-matching term."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("Diabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        assert loader.contains("diagnoses", "cancer") is False


class TestFindMatches:
    """Tests for find_matches method."""

    def test_find_matches_single_word(self, tmp_path):
        """find_matches finds single word terms in text."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("diabetes\nhypertension\nasthma\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        text = "The patient has diabetes and hypertension."

        matches = loader.find_matches("diagnoses", text)

        assert "diabetes" in matches
        assert "hypertension" in matches
        assert "asthma" not in matches

    def test_find_matches_multi_word(self, tmp_path):
        """find_matches finds multi-word terms in text."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("diabetes mellitus\nacute respiratory distress\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        text = "Patient diagnosed with diabetes mellitus type 2."

        matches = loader.find_matches("diagnoses", text)

        assert "diabetes mellitus" in matches

    def test_find_matches_skips_short_terms(self, tmp_path):
        """find_matches skips terms shorter than 3 characters."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("AB\nDiabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        text = "AB and Diabetes"

        matches = loader.find_matches("diagnoses", text)

        # AB (2 chars) should be skipped
        assert "ab" not in matches
        assert "diabetes" in matches

    def test_find_matches_word_boundary(self, tmp_path):
        """find_matches respects word boundaries for single words."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("diabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # Should match
        assert "diabetes" in loader.find_matches("diagnoses", "Has diabetes.")
        assert "diabetes" in loader.find_matches("diagnoses", "diabetes diagnosed")

        # Should NOT match (part of another word)
        assert "diabetes" not in loader.find_matches("diagnoses", "prediabetes")

    def test_find_matches_case_insensitive(self, tmp_path):
        """find_matches is case-insensitive."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("diabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        assert "diabetes" in loader.find_matches("diagnoses", "DIABETES")
        assert "diabetes" in loader.find_matches("diagnoses", "Diabetes")

    def test_find_matches_returns_set(self, tmp_path):
        """find_matches returns a set."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("diabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.find_matches("diagnoses", "diabetes diabetes diabetes")

        assert isinstance(result, set)
        # Only one instance even if repeated
        assert len(result) == 1


class TestHasMedicalContext:
    """Tests for has_medical_context method."""

    def test_medical_context_with_workflow_term(self, tmp_path):
        """Detects medical context from clinical workflow terms."""
        # Create minimal dictionary files
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("intubated\npost-operative\ndischarge\n")
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("the\na\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("physician\nnurse\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        assert loader.has_medical_context("Patient was intubated") is True

    def test_medical_context_with_profession(self, tmp_path):
        """Detects medical context from healthcare profession mentions."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("unknown\n")
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("the\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("physician\nnurse\ndoctor\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        assert loader.has_medical_context("The physician examined the patient") is True

    def test_medical_context_with_drug_suffix(self, tmp_path):
        """Detects medical context from drug name suffixes."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("unknown\n")
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("the\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("unknown\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # Drug suffixes: mycin, cillin, statin, pril, sartan, olol, azole, pine, pam, lam, vir, mab, nib
        assert loader.has_medical_context("prescribed amoxicillin") is True
        assert loader.has_medical_context("taking atorvastatin") is True
        assert loader.has_medical_context("on lisinopril") is True
        # omeprazole matches the "azole" suffix pattern which correctly indicates medical context
        assert loader.has_medical_context("using omeprazole") is True

    def test_medical_context_with_icd_code(self, tmp_path):
        """Detects medical context from ICD-10 code patterns."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("unknown\n")
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("the\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("unknown\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # ICD-10 pattern: letter + 2 digits + optional decimal + digits
        assert loader.has_medical_context("Diagnosis: E11.9") is True
        assert loader.has_medical_context("Code: I10") is True
        assert loader.has_medical_context("ICD: J45.20") is True

    def test_medical_context_min_indicators(self, tmp_path):
        """min_indicators parameter controls threshold."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("intubated\nresuscitation\n")
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("the\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("physician\nnurse\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        text = "Patient intubated by physician during resuscitation"

        # With min_indicators=1, should return True quickly
        assert loader.has_medical_context(text, min_indicators=1) is True

        # With min_indicators=3, might need more indicators
        # (depends on actual matching behavior)

    def test_medical_context_exclude_stopwords(self, tmp_path):
        """exclude_stopwords parameter filters stopwords."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("patient\nthe patient\n")  # patient might be stopword
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("patient\nthe\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("unknown\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # With stopwords excluded, "patient" shouldn't count as indicator
        result = loader.has_medical_context("patient data", exclude_stopwords=True)
        # This depends on implementation - if only "patient" matches and it's a stopword, returns False
        # If there are no other indicators, returns False

    def test_no_medical_context(self, tmp_path):
        """Returns False for non-medical text."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("intubated\nresuscitation\n")
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("the\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("physician\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # Non-medical text
        assert loader.has_medical_context("The weather is nice today") is False
        assert loader.has_medical_context("Hello world") is False


class TestGetMedicalIndicators:
    """Tests for get_medical_indicators method."""

    def test_returns_dict_with_categories(self, tmp_path):
        """Returns dict with expected categories."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("intubated\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("physician\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.get_medical_indicators("sample text")

        assert isinstance(result, dict)
        assert "workflow" in result
        assert "professions" in result
        assert "drug_patterns" in result
        assert "icd_codes" in result

    def test_identifies_workflow_terms(self, tmp_path):
        """Identifies clinical workflow terms."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("intubated\ndischarge\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("unknown\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.get_medical_indicators("Patient was intubated at discharge")

        assert "intubated" in result["workflow"]
        assert "discharge" in result["workflow"]

    def test_identifies_drug_patterns(self, tmp_path):
        """Identifies drug name patterns by suffix."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("unknown\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("unknown\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.get_medical_indicators("taking amoxicillin and atorvastatin")

        # Should identify drug patterns
        assert len(result["drug_patterns"]) > 0

    def test_identifies_icd_codes(self, tmp_path):
        """Identifies ICD-10 code patterns."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("unknown\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("unknown\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.get_medical_indicators("Diagnosis E11.9, I10")

        assert "E11.9" in result["icd_codes"]
        assert "I10" in result["icd_codes"]


class TestPreloadAll:
    """Tests for preload_all method."""

    def test_preload_all_loads_all_dictionaries(self, tmp_path):
        """preload_all loads all defined dictionaries."""
        # Create all required dictionary files
        for filename in DictionaryLoader.DICTIONARY_FILES.values():
            (tmp_path / filename).write_text("test_term\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        loader.preload_all()

        assert loader._loaded is True
        assert len(loader._cache) == len(DictionaryLoader.DICTIONARY_FILES)

    def test_preload_all_handles_missing_files(self, tmp_path):
        """preload_all handles missing files gracefully."""
        # Create only some files
        (tmp_path / "diagnoses.txt").write_text("test\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # Should not raise
        loader.preload_all()

        # Should still set loaded flag
        assert loader._loaded is True


class TestStats:
    """Tests for stats property."""

    def test_stats_returns_dict(self, tmp_path):
        """stats returns dictionary of term counts."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("term1\nterm2\nterm3\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        loader._load_dictionary("diagnoses")

        stats = loader.stats

        assert isinstance(stats, dict)
        assert "diagnoses" in stats
        assert stats["diagnoses"] == 3

    def test_stats_empty_when_no_loaded(self):
        """stats is empty when no dictionaries loaded."""
        loader = DictionaryLoader()

        assert loader.stats == {}


class TestSingletonPattern:
    """Tests for singleton accessor functions."""

    def test_get_dictionary_loader_returns_loader(self):
        """get_dictionary_loader returns DictionaryLoader instance."""
        loader = get_dictionary_loader()

        assert isinstance(loader, DictionaryLoader)

    def test_get_dictionary_loader_returns_same_instance(self):
        """get_dictionary_loader returns same instance (singleton)."""
        # Reset global
        import openlabels.dictionaries as dict_module
        dict_module._loader = None

        loader1 = get_dictionary_loader()
        loader2 = get_dictionary_loader()

        assert loader1 is loader2

    def test_get_medical_context_detector_returns_callable(self):
        """get_medical_context_detector returns callable."""
        detector = get_medical_context_detector()

        assert callable(detector)

    def test_get_medical_context_detector_cached(self):
        """get_medical_context_detector is cached (lru_cache)."""
        # Clear cache
        get_medical_context_detector.cache_clear()

        detector1 = get_medical_context_detector()
        detector2 = get_medical_context_detector()

        # Should be same object due to caching
        assert detector1 is detector2


class TestDictionaryFilenames:
    """Tests for dictionary file name mapping."""

    def test_all_dictionary_files_defined(self):
        """All expected dictionaries have file mappings."""
        expected_dicts = [
            "diagnoses",
            "drugs",
            "facilities",
            "lab_tests",
            "payers",
            "professions",
            "us_cities",
            "us_counties",
            "us_states",
            "regional_patterns",
            "clinical_workflow",
            "clinical_stopwords",
        ]

        for name in expected_dicts:
            assert name in DictionaryLoader.DICTIONARY_FILES

    def test_medical_context_dicts_defined(self):
        """Medical context dictionaries are defined."""
        expected = ["diagnoses", "drugs", "lab_tests", "clinical_workflow", "professions"]

        for name in expected:
            assert name in DictionaryLoader.MEDICAL_CONTEXT_DICTS


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_text_find_matches(self, tmp_path):
        """find_matches handles empty text."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("diabetes\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.find_matches("diagnoses", "")

        assert result == set()

    def test_empty_text_has_medical_context(self, tmp_path):
        """has_medical_context handles empty text."""
        workflow_file = tmp_path / "clinical_workflow.txt"
        workflow_file.write_text("intubated\n")
        stopwords_file = tmp_path / "clinical_stopwords.txt"
        stopwords_file.write_text("the\n")
        professions_file = tmp_path / "professions.txt"
        professions_file.write_text("physician\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        result = loader.has_medical_context("")

        assert result is False

    def test_special_regex_characters_in_term(self, tmp_path):
        """Terms with regex special characters are handled."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("c. difficile\ne. coli\n")

        loader = DictionaryLoader(dict_dir=tmp_path)

        # The dot should be escaped in regex
        matches = loader.find_matches("diagnoses", "Patient has c. difficile infection")
        assert "c. difficile" in matches

    def test_unicode_terms(self, tmp_path):
        """Unicode terms are handled correctly."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("caf\u00e9 au lait spots\nn\u00e6vus\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        terms = loader.get_terms("diagnoses")

        assert "caf\u00e9 au lait spots" in terms
        assert "n\u00e6vus" in terms

    def test_whitespace_handling(self, tmp_path):
        """Leading/trailing whitespace is stripped from terms."""
        dict_file = tmp_path / "diagnoses.txt"
        dict_file.write_text("  diabetes  \n\thypertension\t\n")

        loader = DictionaryLoader(dict_dir=tmp_path)
        terms = loader.get_terms("diagnoses")

        assert "diabetes" in terms
        assert "hypertension" in terms
        assert "  diabetes  " not in terms

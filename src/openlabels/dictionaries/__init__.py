"""
Dictionary loader for OpenLabels detection pipeline.

Provides efficient loading and querying of medical/clinical dictionaries
for context detection and entity classification.

Dictionaries included:
- diagnoses: ICD-10-CM diagnosis names (~97K terms)
- drugs: FDA NDC drug names (~64K terms)
- facilities: CMS hospital/provider names (~66K terms)
- lab_tests: LOINC lab test names (~158K terms)
- payers: Insurance company names
- professions: Healthcare professions
- us_cities, us_counties, us_states: US geography
- clinical_workflow: High-signal medical workflow terms
- clinical_stopwords: Terms to exclude from matching
"""

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Set

from openlabels.core.constants import DEFAULT_DICTIONARIES_DIR

logger = logging.getLogger(__name__)

# Directory containing dictionary files
DICT_DIR = DEFAULT_DICTIONARIES_DIR


class DictionaryLoader:
    """
    Loads and provides access to dictionary files.

    Usage:
        loader = DictionaryLoader()

        # Check if term is in dictionary
        if loader.contains("diagnoses", "diabetes mellitus"):
            print("Found diagnosis")

        # Get all terms from a dictionary
        drugs = loader.get_terms("drugs")

        # Check medical context
        if loader.has_medical_context("patient was intubated"):
            print("Medical context detected")
    """

    # Dictionary files and their purposes
    DICTIONARY_FILES = {
        "diagnoses": "diagnoses.txt",
        "drugs": "drugs.txt",
        "facilities": "facilities.txt",
        "lab_tests": "lab_tests.txt",
        "payers": "payers.txt",
        "professions": "professions.txt",
        "us_cities": "us_cities.txt",
        "us_counties": "us_counties.txt",
        "us_states": "us_states.txt",
        "regional_patterns": "regional_patterns.txt",
        "clinical_workflow": "clinical_workflow.txt",
        "clinical_stopwords": "clinical_stopwords.txt",
    }

    # Dictionaries that indicate medical/healthcare context
    MEDICAL_CONTEXT_DICTS = [
        "diagnoses",
        "drugs",
        "lab_tests",
        "clinical_workflow",
        "professions",
    ]

    def __init__(self, dict_dir: Path | None = None):
        """
        Initialize the dictionary loader.

        Args:
            dict_dir: Optional custom directory containing dictionary files
        """
        self.dict_dir = Path(dict_dir) if dict_dir else DICT_DIR
        self._cache: dict[str, frozenset[str]] = {}
        self._loaded = False

    def _load_dictionary(self, name: str) -> frozenset[str]:
        """Load a dictionary file into a frozenset."""
        if name in self._cache:
            return self._cache[name]

        filename = self.DICTIONARY_FILES.get(name)
        if not filename:
            raise ValueError(f"Unknown dictionary: {name}")

        filepath = self.dict_dir / filename
        if not filepath.exists():
            logger.warning(f"Dictionary file not found: {filepath}")
            return frozenset()

        terms: set[str] = set()
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue
                    # Normalize to lowercase for case-insensitive matching
                    terms.add(line.lower())

            result = frozenset(terms)
            self._cache[name] = result
            logger.debug(f"Loaded {len(result)} terms from {name}")
            return result

        except Exception as e:
            logger.error(f"Error loading dictionary {name}: {e}")
            return frozenset()

    def get_terms(self, name: str) -> frozenset[str]:
        """
        Get all terms from a dictionary.

        Args:
            name: Dictionary name (diagnoses, drugs, etc.)

        Returns:
            Frozenset of normalized (lowercase) terms
        """
        return self._load_dictionary(name)

    def contains(self, name: str, term: str) -> bool:
        """
        Check if a term exists in a dictionary.

        Args:
            name: Dictionary name
            term: Term to check (case-insensitive)

        Returns:
            True if term is in dictionary
        """
        return term.lower() in self._load_dictionary(name)

    def find_matches(self, name: str, text: str) -> set[str]:
        """
        Find all dictionary terms that appear in text.

        Args:
            name: Dictionary name
            text: Text to search

        Returns:
            Set of matched terms (in their dictionary form)
        """
        terms = self._load_dictionary(name)
        text_lower = text.lower()
        matches = set()

        # For efficiency, check shorter terms with word boundaries
        for term in terms:
            if len(term) >= 3:  # Skip very short terms
                # Use word boundary matching for multi-word terms
                if " " in term:
                    if term in text_lower:
                        matches.add(term)
                else:
                    # Single word - use word boundary
                    pattern = rf"\b{re.escape(term)}\b"
                    if re.search(pattern, text_lower):
                        matches.add(term)

        return matches

    def has_medical_context(
        self,
        text: str,
        min_indicators: int = 1,
        exclude_stopwords: bool = True,
    ) -> bool:
        """
        Check if text contains indicators of medical/healthcare context.

        This is used by the tiered pipeline to determine when to escalate
        to PHI-BERT + PII-BERT processing.

        Args:
            text: Text to analyze
            min_indicators: Minimum number of medical terms required
            exclude_stopwords: Whether to exclude clinical stopwords

        Returns:
            True if medical context is detected
        """
        text_lower = text.lower()
        indicator_count = 0

        # Load stopwords if needed
        stopwords = self.get_terms("clinical_stopwords") if exclude_stopwords else frozenset()

        # Check clinical workflow terms first (high signal)
        workflow_terms = self.get_terms("clinical_workflow")
        for term in workflow_terms:
            if len(term) >= 4 and term not in stopwords:
                if " " in term:
                    if term in text_lower:
                        indicator_count += 1
                        if indicator_count >= min_indicators:
                            return True
                else:
                    pattern = rf"\b{re.escape(term)}\b"
                    if re.search(pattern, text_lower):
                        indicator_count += 1
                        if indicator_count >= min_indicators:
                            return True

        # Check professions (healthcare role mentions)
        professions = self.get_terms("professions")
        for term in professions:
            if len(term) >= 4 and term not in stopwords:
                pattern = rf"\b{re.escape(term)}\b"
                if re.search(pattern, text_lower):
                    indicator_count += 1
                    if indicator_count >= min_indicators:
                        return True

        # Check for drug names (strong medical indicator)
        # Only sample common drug patterns to avoid O(n*m) complexity
        common_drug_suffixes = [
            "mycin", "cillin", "statin", "pril", "sartan", "olol",
            "azole", "pine", "pam", "lam", "vir", "mab", "nib",
        ]
        for suffix in common_drug_suffixes:
            if suffix in text_lower:
                indicator_count += 1
                if indicator_count >= min_indicators:
                    return True

        # Check for diagnosis patterns (ICD-like references)
        if re.search(r"\b[A-Z]\d{2}\.?\d*\b", text):  # ICD-10 code pattern
            indicator_count += 1
            if indicator_count >= min_indicators:
                return True

        return False

    def get_medical_indicators(self, text: str) -> dict[str, set[str]]:
        """
        Get detailed breakdown of medical indicators found in text.

        Args:
            text: Text to analyze

        Returns:
            Dictionary mapping category to found terms
        """
        results: dict[str, set[str]] = {
            "workflow": set(),
            "professions": set(),
            "drug_patterns": set(),
            "icd_codes": set(),
        }

        text_lower = text.lower()

        # Clinical workflow terms
        results["workflow"] = self.find_matches("clinical_workflow", text)

        # Professions
        results["professions"] = self.find_matches("professions", text)

        # Drug suffix patterns
        drug_suffixes = [
            "mycin", "cillin", "statin", "pril", "sartan", "olol",
            "azole", "pine", "pam", "lam", "vir", "mab", "nib",
        ]
        for suffix in drug_suffixes:
            pattern = rf"\b\w*{suffix}\b"
            matches = re.findall(pattern, text_lower)
            results["drug_patterns"].update(matches)

        # ICD-10 codes
        icd_matches = re.findall(r"\b[A-Z]\d{2}\.?\d*\b", text)
        results["icd_codes"].update(icd_matches)

        return results

    def preload_all(self) -> None:
        """Preload all dictionaries into memory."""
        for name in self.DICTIONARY_FILES:
            self._load_dictionary(name)
        self._loaded = True
        logger.info(f"Preloaded {len(self._cache)} dictionaries")

    @property
    def stats(self) -> dict[str, int]:
        """Get statistics about loaded dictionaries."""
        return {name: len(terms) for name, terms in self._cache.items()}


# Singleton instance
_loader: DictionaryLoader | None = None


def get_dictionary_loader() -> DictionaryLoader:
    """Get the singleton dictionary loader instance."""
    global _loader
    if _loader is None:
        _loader = DictionaryLoader()
    return _loader


@lru_cache(maxsize=1)
def get_medical_context_detector():
    """
    Get a lightweight medical context detector function.

    Returns a callable that checks if text has medical context.

    Usage:
        detector = get_medical_context_detector()
        if detector("patient was intubated"):
            # Escalate to PHI+PII pipeline
    """
    loader = get_dictionary_loader()
    return loader.has_medical_context

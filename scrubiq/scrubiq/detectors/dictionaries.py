"""Dictionary detector for context awareness using Aho-Corasick for fast matching."""

from pathlib import Path
from typing import List, Set, Optional, Dict, Tuple
import logging

from ..types import Span, Tier
from .base import BaseDetector


logger = logging.getLogger(__name__)

# Common words that appear in drugs.txt but cause false positives
# These are real drug/supplement names but too ambiguous for detection
DRUG_DENY_LIST = frozenset({
    # Common English words that happen to be drug names
    "health", "burn", "stress", "focus", "aged", "major", "assist",
    "standardized", "balance", "support", "relief", "care", "plus",
    "complete", "advanced", "natural", "original", "active", "extra",
    "daily", "essential", "total", "ultra", "super", "mega", "premium",
    "basic", "gentle", "calm", "comfort", "fresh", "pure", "clear",
    "clean", "simple", "smart", "fast", "quick", "instant", "rapid",
    "power", "energy", "force", "strength", "vital", "life", "live",
    "living", "alive", "well", "wellness", "healthy", "good", "better",
    "best", "great", "choice", "select", "preferred", "classic", "gold",
    "silver", "platinum", "elite", "prime", "first", "one", "only",
    # Body parts / generic terms
    "joint", "bone", "skin", "hair", "nail", "heart", "brain", "liver",
    "kidney", "lung", "blood", "muscle", "nerve", "immune", "digest",
    # Actions / states
    "sleep", "rest", "relax", "ease", "soothe", "heal", "repair",
    "protect", "defend", "boost", "enhance", "improve", "increase",
    "reduce", "control", "manage", "maintain", "restore", "renew",
    # Time-related
    "morning", "night", "daily", "weekly", "monthly", "annual",
    # Misc common words
    "formula", "blend", "complex", "system", "solution", "therapy",
    "treatment", "supplement", "vitamin", "mineral", "herb", "herbal",
    "botanical", "organic", "vegan", "gluten", "free", "sugar",
    # Dosage forms - these appear in OpenFDA but aren't actual drug names
    "tablet", "tablets", "capsule", "capsules", "pill", "pills",
    "injection", "injections", "suspension", "syrup", "elixir",
    "cream", "ointment", "gel", "gels", "patch", "patches", "spray",
    "inhaler", "inhalers", "drops", "suppository", "suppositories",
    "powder", "powders", "liquid", "liquids", "lotion", "foam",
    # Units - not drug names
    "mg", "mcg", "ml", "cc", "unit", "units", "iu", "gram", "grams",
    # Generic pharma terms in databases
    "oral", "topical", "extended", "release", "delayed", "chewable",
    "enteric", "coated", "sustained", "controlled", "modified",
    "immediate", "film", "sugar-free", "dye-free", "preservative-free",
    # Common symptoms/conditions - not drug names
    "pain", "ache", "fever", "cough", "cold", "flu", "allergy",
    "nausea", "headache", "migraine", "anxiety", "depression",
    # Lab test names - these appear in drugs.txt but are more commonly lab results
    "glucose", "cholesterol", "triglycerides", "creatinine", "albumin",
    "bilirubin", "hemoglobin", "hematocrit", "platelet", "sodium",
    "potassium", "chloride", "calcium", "magnesium", "phosphorus",
    "urea", "nitrogen", "protein", "globulin", "alkaline", "phosphatase",
})

# Try to import Aho-Corasick for fast matching
try:
    import ahocorasick
    _AHOCORASICK_AVAILABLE = True
except ImportError:
    _AHOCORASICK_AVAILABLE = False
    logger.warning("pyahocorasick not installed - dictionary matching will be slower")


class DictionaryDetector(BaseDetector):
    """
    Context-only detector using medical dictionaries.
    
    Uses Aho-Corasick automaton for O(n) multi-pattern matching when available,
    falls back to O(n*m) naive search otherwise.
    
    Detects:
    - Drug names (OpenFDA NDC) → MEDICATION
    - Diagnoses (ICD-10-CM) - context-only
    - Facilities (CMS provider data) - context-only
    - Lab tests (LOINC) - context-only
    - Payers - context-only
    - Professions (i2b2) - OUTPUT (not context-only)
    - Cities (geo/cities.txt) → CITY
    - States (geo/states.txt) → STATE
    
    Context-only detections inform allowlist decisions but are 
    filtered before output. PROFESSION is a real PHI type.
    """

    name = "dictionary"
    tier = Tier.ML  # Lowest authority

    def __init__(self, dictionaries_dir: Optional[Path] = None):
        self.dictionaries_dir = dictionaries_dir
        self._drugs: Set[str] = set()
        self._diagnoses: Set[str] = set()
        self._facilities: Set[str] = set()
        self._lab_tests: Set[str] = set()
        self._payers: Set[str] = set()
        self._professions: Set[str] = set()
        # Geo sets
        self._cities: Set[str] = set()
        self._states: Set[str] = set()
        
        self._loaded = False
        
        # Aho-Corasick automaton for fast multi-pattern matching
        self._automaton = None
        self._use_automaton = False

        if dictionaries_dir:
            self.load()

    def is_available(self) -> bool:
        return self._loaded

    def load(self) -> bool:
        """
        Load dictionaries from files.
        
        Expected files in dictionaries_dir:
        - drugs.txt: One drug name per line
        - diagnoses.txt: One diagnosis per line
        - facilities.txt: One facility name per line
        - lab_tests.txt: One lab test per line
        - payers.txt: One payer name per line
        - professions.txt: One profession per line
        - geo/cities.txt: City names
        - geo/states.txt: State names
        
        Returns:
            True if at least one dictionary loaded
        """
        if not self.dictionaries_dir or not self.dictionaries_dir.exists():
            logger.warning(f"Dictionary detector disabled: directory not found at {self.dictionaries_dir}")
            return False

        loaded_any = False

        # Load drugs (min_length=4 to avoid "ABC", "Heart" false positives)
        # Also filter common words via DRUG_DENY_LIST
        drugs_file = self.dictionaries_dir / "drugs.txt"
        if drugs_file.exists():
            self._drugs = self._load_file(drugs_file, min_length=4, deny_list=DRUG_DENY_LIST)
            logger.info(f"Loaded {len(self._drugs)} drug names")
            loaded_any = True

        # Load diagnoses
        diagnoses_file = self.dictionaries_dir / "diagnoses.txt"
        if diagnoses_file.exists():
            self._diagnoses = self._load_file(diagnoses_file, min_length=4)
            logger.info(f"Loaded {len(self._diagnoses)} diagnoses")
            loaded_any = True

        # Load facilities (min_length=5 for better precision)
        facilities_file = self.dictionaries_dir / "facilities.txt"
        if facilities_file.exists():
            self._facilities = self._load_file(facilities_file, min_length=5)
            logger.info(f"Loaded {len(self._facilities)} facilities")
            loaded_any = True

        # Load lab tests
        lab_tests_file = self.dictionaries_dir / "lab_tests.txt"
        if lab_tests_file.exists():
            self._lab_tests = self._load_file(lab_tests_file, min_length=3)
            logger.info(f"Loaded {len(self._lab_tests)} lab tests")
            loaded_any = True

        # Load payers
        payers_file = self.dictionaries_dir / "payers.txt"
        if payers_file.exists():
            self._payers = self._load_file(payers_file, min_length=4)
            logger.info(f"Loaded {len(self._payers)} payers")
            loaded_any = True

        # Load professions (NOT context-only - real PHI per i2b2)
        professions_file = self.dictionaries_dir / "professions.txt"
        if professions_file.exists():
            self._professions = self._load_file(professions_file, min_length=4)
            logger.info(f"Loaded {len(self._professions)} professions")
            loaded_any = True

        # Load geo subdirectory
        geo_dir = self.dictionaries_dir / "geo"
        if geo_dir.is_dir():
            # Load cities (min_length=4 to avoid short common words)
            cities_file = geo_dir / "cities.txt"
            if cities_file.exists():
                self._cities = self._load_file(cities_file, min_length=4)
                logger.info(f"Loaded {len(self._cities)} cities")
                loaded_any = True
            
            # Load states (min_length=2 to include abbreviations like "CA")
            states_file = geo_dir / "states.txt"
            if states_file.exists():
                self._states = self._load_file(states_file, min_length=2)
                logger.info(f"Loaded {len(self._states)} states")
                loaded_any = True
        
        self._loaded = loaded_any
        
        # Build Aho-Corasick automaton for fast matching
        if loaded_any:
            self._build_automaton()
        
        return loaded_any

    def _load_file(
        self,
        path: Path,
        min_length: int = 4,
        deny_list: Optional[frozenset] = None
    ) -> Set[str]:
        """Load dictionary file (one term per line, lowercase).

        Args:
            path: Path to dictionary file
            min_length: Minimum term length to include (default 4).
                        Filters out short terms like "ABC", "Heart" that
                        cause false positives.
            deny_list: Optional set of terms to exclude (must be lowercase).

        Returns:
            Set of lowercase terms
        """
        terms = set()
        denied_count = 0
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    term = line.strip().lower()
                    # Skip comments, empty lines, and short terms
                    if term and not term.startswith('#') and len(term) >= min_length:
                        # Skip denied terms
                        if deny_list and term in deny_list:
                            denied_count += 1
                            continue
                        terms.add(term)
            if denied_count > 0:
                logger.debug(f"Filtered {denied_count} denied terms from {path.name}")
        except Exception as e:
            logger.error(f"Failed to load {path}: {e}")
        return terms

    def _build_automaton(self) -> None:
        """Build Aho-Corasick automaton from all dictionaries."""
        if not _AHOCORASICK_AVAILABLE:
            self._use_automaton = False
            return

        try:
            self._automaton = ahocorasick.Automaton()

            # Track terms already added to avoid overwrites
            # Priority order: MEDICATION > LAB_TEST (drugs should not be overwritten)
            added_terms: Set[str] = set()

            # Add all terms with their entity types
            # NOTE: Output as MEDICATION (not DRUG) to match corpus expectations
            # MEDICATION has highest priority - add first
            for term in self._drugs:
                self._automaton.add_word(term, (term, "MEDICATION"))
                added_terms.add(term)
            for term in self._diagnoses:
                if term not in added_terms:
                    self._automaton.add_word(term, (term, "DIAGNOSIS"))
                    added_terms.add(term)
            for term in self._facilities:
                if term not in added_terms:
                    self._automaton.add_word(term, (term, "FACILITY"))
                    added_terms.add(term)
            # LAB_TEST has lower priority - don't overwrite drugs
            for term in self._lab_tests:
                if term not in added_terms:
                    self._automaton.add_word(term, (term, "LAB_TEST"))
                    added_terms.add(term)
            for term in self._payers:
                if term not in added_terms:
                    self._automaton.add_word(term, (term, "PAYER"))
                    added_terms.add(term)
            for term in self._professions:
                if term not in added_terms:
                    self._automaton.add_word(term, (term, "PROFESSION"))
                    added_terms.add(term)
            # Geo types
            for term in self._cities:
                if term not in added_terms:
                    self._automaton.add_word(term, (term, "CITY"))
                    added_terms.add(term)
            for term in self._states:
                if term not in added_terms:
                    self._automaton.add_word(term, (term, "STATE"))
                    added_terms.add(term)

            self._automaton.make_automaton()
            self._use_automaton = True

            logger.info(f"Built Aho-Corasick automaton with {len(added_terms)} unique terms")
            
        except Exception as e:
            logger.warning(f"Failed to build Aho-Corasick automaton: {e}")
            self._use_automaton = False

    def _is_word_boundary(self, text: str, start: int, end: int) -> bool:
        """Check if match is at word boundaries (not in middle of word)."""
        # Check start boundary
        if start > 0:
            prev_char = text[start - 1]
            if prev_char.isalnum():
                return False
        
        # Check end boundary
        if end < len(text):
            next_char = text[end]
            if next_char.isalnum():
                return False
        
        return True

    def _detect_with_automaton(self, text: str, text_lower: str) -> List[Span]:
        """Fast O(n) detection using Aho-Corasick automaton."""
        spans = []
        
        for end_idx, (term, entity_type) in self._automaton.iter(text_lower):
            start_idx = end_idx - len(term) + 1
            
            # Only accept matches at word boundaries
            if self._is_word_boundary(text, start_idx, end_idx + 1):
                spans.append(Span(
                    start=start_idx,
                    end=end_idx + 1,
                    text=text[start_idx:end_idx + 1],
                    entity_type=entity_type,
                    confidence=0.80,
                    detector=self.name,
                    tier=self.tier,
                ))
        
        return spans

    def _find_terms(
        self,
        text: str,
        text_lower: str,
        terms: Set[str],
        entity_type: str
    ) -> List[Span]:
        """Find all occurrences of terms with word boundary checking (fallback)."""
        spans = []
        
        for term in terms:
            pos = 0
            while True:
                idx = text_lower.find(term, pos)
                if idx == -1:
                    break
                
                end_idx = idx + len(term)
                
                # Only accept matches at word boundaries
                if self._is_word_boundary(text, idx, end_idx):
                    spans.append(Span(
                        start=idx,
                        end=end_idx,
                        text=text[idx:end_idx],
                        entity_type=entity_type,
                        confidence=0.80,
                        detector=self.name,
                        tier=self.tier,
                    ))
                
                pos = idx + 1
        
        return spans

    def detect(self, text: str) -> List[Span]:
        """
        Detect dictionary terms in text.
        
        Uses Aho-Corasick for O(n) matching when available, falls back to
        O(n*m) naive search otherwise.
        
        Returns context-only spans (MEDICATION, DIAGNOSIS, FACILITY, LAB_TEST).
        These are filtered by merger before output.
        
        Only matches at word boundaries to avoid false positives
        like "cat" matching "category".
        """
        if not self._loaded:
            return []

        text_lower = text.lower()
        
        # Use fast Aho-Corasick if available
        if self._use_automaton and self._automaton:
            return self._detect_with_automaton(text, text_lower)
        
        # Fallback to naive O(n*m) search
        spans = []
        
        # Medical types - output as MEDICATION (not DRUG) to match corpus
        spans.extend(self._find_terms(text, text_lower, self._drugs, "MEDICATION"))
        spans.extend(self._find_terms(text, text_lower, self._diagnoses, "DIAGNOSIS"))
        spans.extend(self._find_terms(text, text_lower, self._facilities, "FACILITY"))
        spans.extend(self._find_terms(text, text_lower, self._lab_tests, "LAB_TEST"))
        spans.extend(self._find_terms(text, text_lower, self._payers, "PAYER"))
        
        # Real PHI types (not filtered)
        spans.extend(self._find_terms(text, text_lower, self._professions, "PROFESSION"))
        
        # Geo types
        if self._cities:
            spans.extend(self._find_terms(text, text_lower, self._cities, "CITY"))
        if self._states:
            spans.extend(self._find_terms(text, text_lower, self._states, "STATE"))

        return spans

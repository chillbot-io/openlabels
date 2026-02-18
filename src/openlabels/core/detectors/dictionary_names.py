"""Dictionary-based name detector.

Uses first-name and last-name dictionaries for O(1)-per-token lookup.
Detects bare capitalized words that match known names — the primary gap
left by pattern-only detection where names have no structural context.

Confidence is intentionally moderate (0.60) and the allowlist (professions,
drugs, facilities, clinical stopwords) suppresses common false positives.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..types import Span, Tier
from .base import BaseDetector
from .registry import register_detector

# Package-bundled dictionaries directory (same as allowlist fallback)
_PACKAGE_DICT_DIR = Path(__file__).resolve().parent.parent.parent / "dictionaries"

logger = logging.getLogger(__name__)

# Tokeniser: sequences of alpha characters (including accented Latin),
# apostrophes (O'Brien), and hyphens (Anne-Marie).
_WORD_RE = re.compile(r"\b([A-Z\u00C0-\u024F][a-z\u00C0-\u024F''\-]{1,30})\b")

# Address suffixes — when a title-case word is followed by one of these,
# it's likely a street/place name, not a person name.
_ADDRESS_SUFFIXES = frozenset({
    "street", "st", "road", "rd", "avenue", "ave", "boulevard", "blvd",
    "drive", "dr", "lane", "ln", "court", "ct", "place", "pl",
    "way", "circle", "cir", "terrace", "ter", "trail", "trl",
    "parkway", "pkwy", "highway", "hwy", "pike", "turnpike",
    "alley", "loop", "run", "pass", "crossing", "crescent",
    "commons", "common", "square", "plaza", "mall",
    "ridge", "heights", "hills", "springs", "meadows",
    "summit", "view", "vista", "point", "landing",
    "creek", "cove", "glen", "grove", "hollow",
    "junction", "fork", "forks", "bend", "rapids",
    "beach", "island", "isle", "harbor", "port",
    "bridge", "dam", "falls", "lake", "mount",
    "garden", "gardens", "park", "ranch", "estates",
    "station", "depot", "terminal",
    # Indian/South Asian suffixes
    "nagar", "puram", "pur", "abad", "ganj", "khel",
    # Apartment/unit suffixes
    "apt", "suite", "ste", "unit", "floor",
})

# Common English words that are also first names — suppress at low
# confidence to avoid flooding results with "May", "Art", "Joy", etc.
# Expanded from FP analysis on ai4privacy benchmark.
_AMBIGUOUS_FIRST = frozenset({
    # Original list
    "art", "august", "bill", "bob", "brook", "candy", "carol",
    "chance", "charity", "china", "clay", "cliff", "crystal",
    "dale", "dawn", "dean", "diamond", "don", "drew", "earl",
    "faith", "fern", "flora", "ford", "frank", "gene", "glen",
    "grace", "grant", "guy", "harmony", "harry", "heath", "holly",
    "hope", "hunter", "iris", "ivy", "jack", "jade", "jean",
    "jersey", "jewel", "jimmy", "joe", "john", "joy", "june",
    "king", "lance", "lily", "love", "mark", "mat", "max",
    "may", "mercy", "mike", "miles", "nick", "noble", "norm",
    "olive", "pat", "pearl", "penny", "peter", "pierre",
    "ray", "reed", "rob", "robin", "rod", "rose", "ruby",
    "sandy", "skip", "spring", "sterling", "sue", "summer",
    "tab", "terry", "tom", "tony", "troy", "val", "van",
    "victor", "violet", "wade", "ward", "will",
    # Common nouns/verbs/adjectives from FP analysis
    "male", "female", "can", "mac", "franc", "kip", "som",
    "brown", "green", "west", "north", "south", "east",
    "red", "white", "black", "blue", "pink", "grey", "gray",
    "river", "hills", "lake", "bay", "port", "field", "park",
    "media", "math", "server", "web", "net", "hub",
    "long", "young", "rich", "new", "old", "free", "fair",
    "ever", "hence", "just", "much", "near", "only",
    "golden", "silver", "bronze", "iron", "copper", "steel",
    # Animal/nature words that are also names
    "bear", "dove", "hawk", "falcon", "raven", "fox",
    "wolf", "lion", "tiger", "colt", "mare", "star",
    "storm", "rain", "snow", "sunny", "misty",
    # Technology/brands that are also names
    "safari", "pixel", "delta", "sigma", "alpha", "beta",
    "omega", "gamma", "echo", "nova", "aria",
    # Currency/finance terms
    "real", "lira", "rand", "peso", "euro",
    "tala", "won", "sol", "rial",
    # Food/drink words
    "berry", "ginger", "sage", "basil", "pepper", "olive",
    # Music/art terms
    "aria", "tempo", "solo", "forte",
    # Common words often title-cased at sentence start
    "also", "both", "each", "else", "here", "most", "next",
    "some", "such", "then", "very", "well", "when",
    "about", "after", "being", "could", "every",
    "other", "since", "still", "their", "there", "these",
    "those", "under", "until", "where", "which", "while",
    "above", "below", "soon", "made", "early", "late",
    "branch", "main", "minor", "major", "prior",
    # Nationalities/demonyms
    "omani", "thai", "czech", "irish", "welsh",
    "swiss", "dutch", "french", "german", "indian",
    "roman", "latin", "arab", "asian", "roman",
    # Technology/browser names
    "safari", "chrome", "firefox", "pixel", "android",
    # Misc common words from FP analysis
    "county", "advisory", "league", "guild", "forum",
    "manor", "ranch", "villa", "lodge", "haven",
    "isle", "cove", "mesa", "glen", "dale",
    "ridge", "creek", "grove", "knoll",
    # Gretel PII FP analysis — common words detected as names
    "loan", "reason", "room", "holder", "must",
    "case", "author", "price", "marine", "foster",
    "lead", "chief", "judge", "bond", "major",
    "bond", "chase", "cruz", "duke", "ember",
    "haven", "journey", "justice", "liberty", "mason",
    "nelson", "porter", "ranger", "reign", "royal",
    "scout", "sterling", "stone", "summit", "texas",
    "titan", "urban", "valor", "virtue", "walker",
    "warren", "wren", "drake", "genesis", "roman",
    "smith", "john", "jane", "gates", "bell",
    "parks", "numbers", "access", "level", "record",
    "energy", "system", "defendant", "type",
    "region", "domain", "sector", "zone", "area",
    "status", "phase", "stage", "grade", "rank",
    "note", "item", "unit", "part", "role",
    "cause", "issue", "event", "fact", "term",
    "feature", "point", "state", "form", "kind",
    # More Gretel FP words
    "line", "carrier", "amble", "christian", "woods",
    "nagar", "hanna", "reserved", "return", "miss",
    "given", "taken", "shown", "known", "sent",
    "paid", "told", "left", "held", "done",
    "born", "lost", "found", "gone", "came",
    "went", "fell", "kept", "meant", "brought",
    # AI4Privacy 10k FP analysis — top repeat offenders
    "more", "link", "english", "fair", "company",
    "read", "arts", "producer", "forward", "human",
    "york", "ireland", "france", "berlin", "london",
    "giulia", "eden", "madera", "lancaster", "colton",
    "bryan", "devon", "shannon", "montana", "virginia",
})

# Common English words that are also last names — more aggressive
# since last names overlap heavily with common nouns/adjectives.
_AMBIGUOUS_LAST = frozenset({
    "able", "air", "angel", "arch", "bail", "ball", "ban",
    "bar", "bass", "batch", "bean", "bell", "best", "bird",
    "block", "bond", "book", "boot", "born", "brand", "bridge",
    "brook", "buck", "bull", "bush", "camp", "card", "case",
    "cash", "castle", "child", "church", "close", "cloud",
    "cook", "corn", "crane", "cross", "dale", "day", "dear",
    "dial", "early", "field", "fish", "flag", "flood",
    "ford", "fox", "free", "frost", "glass", "gold", "good",
    "green", "grey", "gross", "hand", "hare", "head",
    "house", "ice", "key", "king", "land", "lane", "large",
    "law", "light", "link", "long", "love", "low", "man",
    "mark", "marsh", "may", "moon", "near", "new", "noble",
    "north", "page", "park", "path", "pine", "plant", "pool",
    "post", "power", "price", "prince", "rich", "ring", "rock",
    "rose", "sale", "sand", "sharp", "short", "silver",
    "small", "snow", "south", "spring", "star", "steel",
    "stone", "strong", "sweet", "swift", "wall", "ward",
    "water", "west", "white", "wild", "winter", "wise",
    "wolf", "wood", "young",
    # Additional from FP analysis
    "parent", "street", "hill", "hills", "river", "valley",
    "lake", "ocean", "gate", "town", "port", "mill",
    "turn", "end", "rest", "hope", "will", "may",
    "brown", "black", "red", "blue", "gray", "pink",
    "east", "west", "north", "south",
    "server", "media", "math", "web", "net",
    "franc", "real", "lira", "rand",
    # Browser/tech terms
    "safari", "chrome", "firefox", "android",
    # More common words from FP analysis
    "soon", "branch", "each", "made", "main",
    "late", "prior", "minor", "major",
    # Nationalities/demonyms
    "omani", "thai", "czech", "irish", "welsh",
    "swiss", "dutch", "french", "german", "indian",
    # Geographic/nature
    "county", "isle", "cove", "mesa", "ridge",
    "creek", "grove", "knoll", "manor", "ranch",
    "villa", "lodge", "haven", "league",
    # Gretel PII FP analysis — common words detected as lastnames
    "loan", "reason", "room", "holder", "must",
    "case", "author", "price", "marine", "foster",
    "parks", "gates", "bell", "smith", "john", "jane",
    "numbers", "access", "level", "record", "energy",
    "system", "defendant", "type", "summit",
    "region", "domain", "sector", "zone", "area",
    "status", "phase", "stage", "grade", "rank",
    "note", "item", "unit", "part", "role",
    "cause", "issue", "event", "fact", "term",
    "feature", "point", "state", "form", "kind",
    # More Gretel FP words
    "line", "carrier", "amble", "christian", "woods",
    "nagar", "hanna", "reserved",
    # AI4Privacy 10k FP analysis
    "more", "link", "english", "fair", "company",
    "read", "arts", "producer", "forward", "human",
    "york", "ireland", "france", "berlin", "london",
    "giulia", "eden", "madera", "lancaster", "colton",
    "bryan", "devon", "shannon", "montana", "virginia",
})

# Words that should NEVER match as names regardless of dictionary presence.
# Job titles, roles, structural terms, and common English words from FP analysis.
_NEVER_NAMES = frozenset({
    # Job titles and roles
    "agent", "analyst", "assistant", "associate", "attorney",
    "captain", "central", "chief", "client", "coach",
    "compliance", "consultant", "coordinator", "counsel",
    "department", "deputy", "detective", "director", "district",
    "division", "engineer", "executive", "general", "global",
    "head", "human", "inspector", "internal", "international",
    "junior", "lead", "legal", "lieutenant", "manager",
    "marketing", "national", "officer", "operations",
    "physical", "president", "principal", "professor",
    "regional", "representative", "research", "resident",
    "secretary", "senior", "sergeant", "solicitor",
    "special", "specialist", "strategic", "supervisor",
    "technical", "vice",
    # Document/structural terms
    "abstract", "appendix", "article", "chapter", "conclusion",
    "consent", "contents", "document", "edition", "exhibit",
    "figure", "footnote", "formula", "header", "index",
    "introduction", "notice", "paragraph", "policy", "provision",
    "schedule", "section", "standard", "statement", "subject",
    "summary", "table", "version",
    # Medical/clinical terms
    "assessment", "clinical", "diagnosis", "discharge",
    "hospital", "medical", "medication", "patient",
    "physician", "procedure", "prognosis", "surgery",
    "symptom", "therapy", "treatment",
    # Technology terms
    "account", "address", "application", "browser", "column",
    "command", "computer", "database", "desktop", "digital",
    "domain", "download", "email", "error", "file",
    "format", "function", "hardware", "install", "internet",
    "keyboard", "laptop", "mobile", "monitor", "network",
    "online", "output", "password", "platform", "printer",
    "process", "profile", "program", "protocol", "router",
    "screen", "server", "software", "storage", "system",
    "update", "upload", "virtual", "website",
    # Financial terms
    "account", "balance", "banking", "capital", "credit",
    "currency", "deposit", "exchange", "finance", "fiscal",
    "insurance", "interest", "invoice", "payment", "premium",
    "revenue", "savings", "transfer",
    # Common words unlikely to be standalone names
    "access", "active", "actual", "annual", "basic",
    "common", "complete", "complex", "critical", "current",
    "custom", "default", "direct", "effective", "entire",
    "essential", "existing", "external", "final", "formal",
    "future", "generic", "ideal", "impact", "initial",
    "limited", "local", "manual", "material", "maximum",
    "minimum", "minor", "model", "modern", "multiple",
    "natural", "negative", "normal", "option", "original",
    "overall", "perfect", "personal", "positive", "potential",
    "practical", "primary", "private", "proper", "public",
    "quality", "random", "regular", "relative", "remote",
    "required", "reserve", "response", "review", "sample",
    "secure", "separate", "service", "session", "simple",
    "single", "social", "source", "status", "target",
    "total", "typical", "unique", "universal", "valid",
    # Gretel PII FP analysis — more structural/domain words
    "avionics", "defendant", "plaintiff", "utilities",
    "aviation", "automotive", "logistics", "maritime",
    "industrial", "commercial", "residential", "municipal",
    "regulatory", "judicial", "legislative", "diplomatic",
    "wholesale", "retail", "consumer", "vendor", "supplier",
    "inventory", "warehouse", "shipping", "delivery",
    "revenue", "portfolio", "advisory", "brokerage",
    "diagnostic", "surgical", "pharmaceutical", "veterinary",
    "academic", "scholarly", "tutorial", "curriculum",
    "garrison", "sentinel", "outpost", "barracks",
})


def _load_name_file(filename: str) -> frozenset[str]:
    """Load a name dictionary from the package-bundled dictionaries dir."""
    from ..constants import DEFAULT_DICTIONARIES_DIR

    # Try configured dir first, fall back to package-bundled
    for d in (DEFAULT_DICTIONARIES_DIR, _PACKAGE_DICT_DIR):
        filepath = d / filename
        if filepath.exists():
            terms: set[str] = set()
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        terms.add(line.lower())
            return frozenset(terms)

    logger.warning("Name dictionary not found: %s", filename)
    return frozenset()


@register_detector
class DictionaryNameDetector(BaseDetector):
    """Detects first/last names via dictionary lookup.

    Tier: PATTERN (same as regex patterns).
    Confidence: 0.60 baseline for single-word matches.
    """

    name = "dictionary_names"
    tier = Tier.PATTERN

    def __init__(self) -> None:
        self._first_names = _load_name_file("first_names.txt")
        self._last_names = _load_name_file("last_names.txt")
        logger.debug(
            "DictionaryNameDetector loaded: %d first, %d last",
            len(self._first_names),
            len(self._last_names),
        )

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        seen: set[tuple[int, int]] = set()

        for match in _WORD_RE.finditer(text):
            word = match.group(1)
            start = match.start(1)
            end = match.end(1)

            # Must be title-case (not ALL-CAPS, not lowercase)
            if not word[0].isupper() or word.isupper():
                continue

            # Short words are too ambiguous for dictionary-only matching
            if len(word) < 4:
                continue

            lower = word.lower()

            # Absolute exclusions
            if lower in _NEVER_NAMES:
                continue

            # Suppress names preceded by city/place prefixes (e.g., "Fort Kamron")
            if start >= 2:
                before = text[max(0, start - 15):start].rstrip()
                before_lower = before.lower()
                if before_lower.endswith(('fort', 'lake', 'port', 'mount',
                                          'cape', 'new', 'old', 'saint', 'san',
                                          'santa', 'los', 'las', 'el')):
                    continue

            # Suppress names followed by address suffixes (e.g., "Turner Street")
            after = text[end:end + 20].lstrip()
            after_word = after.split()[0].lower().rstrip('.,;:') if after.split() else ''
            if after_word in _ADDRESS_SUFFIXES:
                continue

            # Suppress names preceded by street numbers (e.g., "123 Michael Ave")
            if start >= 2:
                before_text = text[max(0, start - 8):start].rstrip()
                if before_text and before_text[-1].isdigit():
                    # Check if followed by address suffix too
                    if after_word in _ADDRESS_SUFFIXES:
                        continue
                    # Or check if word after THIS word is an address suffix
                    remaining = text[end:end + 40]
                    remaining_words = remaining.split()
                    if len(remaining_words) >= 2:
                        second_word = remaining_words[1].lower().rstrip('.,;:')
                        if second_word in _ADDRESS_SUFFIXES:
                            continue

            key = (start, end)
            if key in seen:
                continue

            is_first = lower in self._first_names and lower not in _AMBIGUOUS_FIRST
            is_last = lower in self._last_names and lower not in _AMBIGUOUS_LAST

            if is_first:
                seen.add(key)
                spans.append(Span(
                    start=start,
                    end=end,
                    text=word,
                    entity_type="FIRSTNAME",
                    confidence=0.60,
                    detector=self.name,
                    tier=self.tier,
                ))
            elif is_last:
                seen.add(key)
                spans.append(Span(
                    start=start,
                    end=end,
                    text=word,
                    entity_type="LASTNAME",
                    confidence=0.55,
                    detector=self.name,
                    tier=self.tier,
                ))

        return spans

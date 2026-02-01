"""Gender inference for entity tracking.

Simple heuristic-based gender inference for names to support
pronoun resolution in the EntityGraph.

This is NOT for gender classification of people - it's purely
for linguistic pronoun resolution (he/she/they).

IMPORTANT: This module is intentionally conservative. If there's
any ambiguity about a name's typical pronoun usage, we return None
rather than guessing wrong. Wrong gender inference causes incorrect
pronoun resolution, which is worse than no resolution.
"""

import re
from typing import Optional, Set, Tuple

# Import centralized name type checking
from ..constants import is_name_entity_type  # noqa: F401 - re-exported


# Gender-neutral names that should NOT be assigned M or F
# These names are commonly used by people of all genders
# Sources: US SSA data, gender studies research
NEUTRAL_NAMES: Set[str] = {
    # Classic neutral names
    "alex", "alexis", "angel", "ariel", "ash", "aspen", "aubrey", "avery",
    "bailey", "blair", "blake", "bobbie", "brett", "brooke",
    "cameron", "carey", "carmen", "casey", "charlie", "chris", "corey",
    "courtney", "dakota", "dale", "dana", "darcy", "devin", "devon", "drew",
    "dylan", "eden", "eli", "elliot", "elliott", "emery", "emerson", "evan",
    "finley", "frankie", "gale", "gene", "gray", "grey", "hadley", "harley",
    "harper", "hayden", "hunter", "indigo",
    "jackie", "jaime", "jamie", "jay", "jayden", "jean", "jess", "jessie",
    "jo", "jocelyn", "jody", "jordan", "jules", "justice",
    "kai", "kameron", "keegan", "kelley", "kelly", "kendall", "kennedy",
    "kim", "kris", "lake", "lane", "lee", "leigh", "lennon", "leslie",
    "logan", "london", "loren", "lou", "lucian", "lynn",
    "mackenzie", "madison", "marley", "marlowe", "micah", "morgan",
    "murphy", "nicky", "noel", "oakley", "onyx", "parker", "pat", "payton",
    "peyton", "phoenix", "quinn", "raven", "ray", "reagan", "reese", "regan",
    "reilly", "remington", "remy", "riley", "river", "robbie", "robin", "rowan",
    "ryan", "rylan", "sage", "sam", "sandy", "sascha", "sasha", "sawyer",
    "scout", "shawn", "shelby", "shiloh", "sidney", "sky", "skylar", "skyler",
    "sloane", "spencer", "stevie", "storm", "sydney",
    "tanner", "taylor", "terry", "toni", "tony", "tracy", "tristan",
    "val", "winter", "wren", "zion",
    # International neutral names
    "andrea",  # Male in Italy, female in English
    "kim",  # Common in both genders across cultures
    "yuki", "sora", "akira", "haru", "ren",  # Japanese
    "sascha", "sasha",  # Slavic
    "nico", "nicky",  # Romance languages
}

# Common name → gender mappings (US Census + international)
# These are statistical associations for pronoun resolution only
# IMPORTANT: Do NOT add names that appear in NEUTRAL_NAMES
# The sets below are filtered to exclude NEUTRAL_NAMES entries
MALE_NAMES: Set[str] = {
    # Top US male names
    # NOTE: alex, chris, dylan, jordan, logan, ryan, sam, terry removed (in NEUTRAL_NAMES)
    "james", "john", "robert", "michael", "william", "david", "richard",
    "joseph", "thomas", "charles", "christopher", "daniel", "matthew",
    "anthony", "mark", "donald", "steven", "paul", "andrew", "joshua",
    "kenneth", "kevin", "brian", "george", "timothy", "ronald", "edward",
    "jason", "jeffrey", "jacob", "gary", "nicholas", "eric",
    "jonathan", "stephen", "larry", "justin", "scott", "brandon", "benjamin",
    "samuel", "raymond", "gregory", "frank", "alexander", "patrick", "jack",
    "dennis", "jerry", "tyler", "aaron", "jose", "adam", "nathan", "henry",
    "douglas", "zachary", "peter", "kyle", "noah", "ethan", "jeremy",
    "walter", "christian", "keith", "roger", "austin", "sean",
    "gerald", "carl", "harold", "arthur", "lawrence",
    "jesse", "bryan", "billy", "bruce", "gabriel", "joe", "albert",
    "willie", "alan", "eugene", "russell", "vincent", "philip", "bobby",
    "johnny", "bradley", "roy", "ralph", "randy", "wayne",
    "howard", "carlos", "victor", "martin", "louis", "harry", "fred",
    # Common international
    # NOTE: andrea, jean removed (in NEUTRAL_NAMES)
    "mohammed", "muhammad", "ahmed", "ali", "omar", "hassan", "hussein",
    "juan", "luis", "miguel", "jorge", "pedro", "francisco",
    "antonio", "manuel", "rafael", "sergio", "fernando", "ricardo",
    "hans", "klaus", "franz", "wolfgang", "heinrich", "fritz", "karl",
    "pierre", "michel", "jacques", "philippe", "francois",
    "giovanni", "marco", "giuseppe", "luigi", "francesco",
    "ivan", "dimitri", "vladimir", "sergei", "nikolai",
    "raj", "amit", "rahul", "vijay", "kumar", "anil", "suresh",
    "wei", "ming", "jian", "chen", "wang", "zhang", "li",
    "bob", "jim", "tom", "bill", "mike", "dave", "steve", "dan", "matt",
    "ben", "nick", "max", "jake", "luke", "zach",
}

FEMALE_NAMES: Set[str] = {
    # Top US female names
    # NOTE: alexis, andrea, carmen, jean, jess, kelly, kim, madison removed (in NEUTRAL_NAMES)
    "mary", "patricia", "jennifer", "linda", "barbara", "elizabeth",
    "susan", "jessica", "sarah", "karen", "lisa", "nancy", "betty",
    "margaret", "sandra", "ashley", "kimberly", "emily", "donna", "michelle",
    "dorothy", "carol", "amanda", "melissa", "deborah", "stephanie",
    "rebecca", "sharon", "laura", "cynthia", "kathleen", "amy", "angela",
    "shirley", "anna", "brenda", "pamela", "emma", "nicole", "helen",
    "samantha", "katherine", "christine", "debra", "rachel", "carolyn",
    "janet", "catherine", "maria", "heather", "diane", "ruth", "julie",
    "olivia", "joyce", "virginia", "victoria", "lauren", "christina",
    "joan", "evelyn", "judith", "megan", "cheryl", "hannah",
    "jacqueline", "martha", "gloria", "teresa", "ann", "sara",
    "frances", "kathryn", "janice", "abigail", "alice", "judy",
    "sophia", "grace", "denise", "amber", "doris", "marilyn", "danielle",
    "beverly", "isabella", "theresa", "diana", "natalie", "brittany",
    "charlotte", "marie", "kayla", "lori", "jane", "ella",
    # Common international
    # NOTE: carmen removed (in NEUTRAL_NAMES)
    "fatima", "aisha", "mariam", "zainab", "khadija", "amina",
    "maria", "ana", "rosa", "lucia", "elena", "isabel",
    "ingrid", "helga", "greta", "anna", "eva", "elisabeth",
    "sophie", "claire", "isabelle", "charlotte", "camille",
    "giulia", "francesca", "chiara", "valentina", "alessandra",
    "olga", "natasha", "tatiana", "svetlana", "irina",
    "priya", "neha", "pooja", "anjali", "sunita", "kavita",
    "mei", "ling", "xiao", "yan", "hong", "jing", "hui",
    "kate", "jenny", "meg", "sue", "beth", "jen",
    "emma", "sophie", "chloe", "mia", "ava", "lily", "zoe",
}

# Title/honorific patterns
MALE_TITLES = re.compile(r'^(mr\.?|sir|lord|master)\s+', re.I)
FEMALE_TITLES = re.compile(r'^(mrs\.?|ms\.?|miss|madam|lady|dame)\s+', re.I)

# Suffix patterns
MALE_SUFFIXES = re.compile(r',?\s+(jr\.?|sr\.?|ii|iii|iv|esq\.?)$', re.I)


def infer_gender(name: str) -> Optional[str]:
    """
    Infer likely gender from a name for pronoun resolution.

    This is a linguistic heuristic, not a gender classification.
    Used to resolve "he"/"she" pronouns in coreference.

    IMPORTANT: This function is conservative. It returns None for:
    - Names that are commonly gender-neutral (Alex, Jordan, etc.)
    - Names not in our database
    - Ambiguous cases

    Wrong gender inference causes worse coref errors than no inference.

    Args:
        name: Full name or partial name

    Returns:
        "M" for masculine, "F" for feminine, None if unknown/neutral
    """
    if not name:
        return None

    name_clean = name.strip()

    # Check titles first (most reliable)
    if MALE_TITLES.match(name_clean):
        return "M"
    if FEMALE_TITLES.match(name_clean):
        return "F"

    # Remove titles and suffixes for name lookup
    name_clean = MALE_TITLES.sub('', name_clean)
    name_clean = FEMALE_TITLES.sub('', name_clean)
    name_clean = MALE_SUFFIXES.sub('', name_clean)

    # Extract first name (most reliable for gender)
    parts = name_clean.split()
    if not parts:
        return None

    first_name = parts[0].lower().strip('.')

    # Check neutral names FIRST - these should not get M/F assignment
    # This prevents incorrect pronoun resolution for gender-neutral names
    if first_name in NEUTRAL_NAMES:
        return None

    # Check against gendered name lists
    if first_name in MALE_NAMES:
        return "M"
    if first_name in FEMALE_NAMES:
        return "F"

    # Handle hyphenated names like "Mary-Jane" - check first component
    if '-' in first_name:
        first_component = first_name.split('-')[0]
        if first_component in NEUTRAL_NAMES:
            return None
        if first_component in MALE_NAMES:
            return "M"
        if first_component in FEMALE_NAMES:
            return "F"

    # Unknown name - do NOT guess based on patterns
    # Pattern-based guessing (e.g., names ending in -a are female)
    # has too many exceptions and causes more harm than good
    return None


def infer_gender_with_confidence(name: str) -> Tuple[Optional[str], float]:
    """
    Infer gender with a confidence score.

    Args:
        name: Full name or partial name

    Returns:
        (gender, confidence) where:
        - gender is "M", "F", or None
        - confidence is 0.0-1.0

    Confidence levels:
    - 0.95: Title-based (Mr., Mrs., etc.)
    - 0.85: First name in gendered list
    - 0.0: Unknown or neutral name
    """
    if not name:
        return None, 0.0

    name_clean = name.strip()

    # Check titles first (most reliable)
    if MALE_TITLES.match(name_clean):
        return "M", 0.95
    if FEMALE_TITLES.match(name_clean):
        return "F", 0.95

    # Remove titles and suffixes for name lookup
    name_clean = MALE_TITLES.sub('', name_clean)
    name_clean = FEMALE_TITLES.sub('', name_clean)
    name_clean = MALE_SUFFIXES.sub('', name_clean)

    parts = name_clean.split()
    if not parts:
        return None, 0.0

    first_name = parts[0].lower().strip('.')

    # Neutral names - explicitly unknown
    if first_name in NEUTRAL_NAMES:
        return None, 0.0

    # Gendered names
    if first_name in MALE_NAMES:
        return "M", 0.85
    if first_name in FEMALE_NAMES:
        return "F", 0.85

    # Unknown
    return None, 0.0


def infer_gender_from_context(name: str, context: str) -> Optional[str]:
    """
    Infer gender from surrounding context.
    
    Looks for pronoun usage near the name that indicates gender.
    
    Args:
        name: The name to infer gender for
        context: Surrounding text (50-100 chars each side)
        
    Returns:
        "M", "F", or None
    """
    if not context:
        return infer_gender(name)
    
    context_lower = context.lower()
    name_lower = name.lower()
    
    # Find name position
    pos = context_lower.find(name_lower)
    if pos == -1:
        return infer_gender(name)
    
    # Get text after name (pronouns often follow)
    after = context_lower[pos + len(name):pos + len(name) + 50]
    
    # Look for pronoun patterns
    male_patterns = [
        r'\bhe\b', r'\bhis\b', r'\bhim\b', r'\bhimself\b',
        r'\bfather\b', r'\bson\b', r'\bbrother\b', r'\bhusband\b',
        r'\bmale\b', r'\bman\b', r'\bboy\b', r'\bgentleman\b',
    ]
    female_patterns = [
        r'\bshe\b', r'\bher\b', r'\bhers\b', r'\bherself\b',
        r'\bmother\b', r'\bdaughter\b', r'\bsister\b', r'\bwife\b',
        r'\bfemale\b', r'\bwoman\b', r'\bgirl\b', r'\blady\b',
    ]
    
    male_score = sum(1 for p in male_patterns if re.search(p, after))
    female_score = sum(1 for p in female_patterns if re.search(p, after))
    
    if male_score > female_score:
        return "M"
    if female_score > male_score:
        return "F"
    
    # Fall back to name-based inference
    return infer_gender(name)


# is_name_entity_type is imported from constants and re-exported
# for backwards compatibility with any code that imports it from this module

"""Context-aware allowlist for false positive filtering."""

import re
from typing import List

from ..types import Span


# Common English words that are never PHI
# (Stopwords that ML sometimes misclassifies as NAME entities)
COMMON_WORDS = frozenset([
    # Greetings (ML sometimes misclassifies as names)
    "hello", "hi", "hey", "greetings", "welcome", "goodbye", "bye",
    "good morning", "good afternoon", "good evening",
    "thanks", "thank you", "please", "sorry", "okay", "ok",
    # Articles/conjunctions/prepositions
    "if", "the", "a", "an", "and", "or", "but", "so", "as", "at", "by",
    "for", "in", "of", "on", "to", "with", "from", "into", "onto", "upon",
    "about", "above", "after", "before", "below", "between", "during",
    "through", "until", "while", "since", "because", "although", "though",
    # Pronouns (these should be handled by coref, not detected as names)
    "i", "me", "my", "mine", "myself",
    "you", "your", "yours", "yourself",
    "he", "him", "his", "himself",
    "she", "her", "hers", "herself",
    "it", "its", "itself",
    "we", "us", "our", "ours", "ourselves",
    "they", "them", "their", "theirs", "themselves",
    "one", "ones", "whoever", "whatever", "whichever",
    # Common verbs/auxiliaries
    "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did",
    "will", "would", "could", "should", "may", "might", "must",
    "can", "shall",
    # Verbs that appear after clinical roles (Provider/Dr./Mr./Mrs./Ms. + verb)
    # These get falsely detected as names after "Provider:", "Dr.", etc.
    "reports", "notes", "states", "says", "advises", "recommends",
    "suggests", "indicates", "documents", "records", "orders",
    "prescribes", "diagnoses", "confirms", "denies", "describes",
    "observes", "examines", "evaluates", "assesses", "determines",
    "concludes", "believes", "thinks", "feels", "considers",
    "called", "visited", "presented", "arrived", "returned",
    "requested", "referred", "consulted", "treated", "discharged",
    # Common adverbs
    "not", "no", "yes", "very", "also", "just", "only", "even",
    "still", "already", "always", "never", "often", "sometimes",
    "here", "there", "then", "now", "too",
    # Common nouns that appear in clinical phrases (prevents "recommends rest" etc.)
    "rest", "pain", "improvement", "stable", "labs", "tests", "medication",
    "follow", "up", "care", "treatment", "therapy", "bed", "home",
    "work", "activity", "diet", "fluids", "sleep", "exercise",
    # Question words
    "who", "what", "where", "when", "why", "how", "which",
    # Demonstratives
    "this", "that", "these", "those",
    # Other common words
    "all", "any", "some", "none", "each", "every", "both", "few", "many",
    "more", "most", "other", "another", "such", "same", "different",
    # Interjections
    "oh", "ah", "um", "uh", "hmm", "wow", "oops",
    # Common words that are also first names (suppress when standalone)
    # These should NOT be redacted when used as common words
    "will", "mark", "bill", "sue", "rob", "bob", "jack", "don",
    "gene", "art", "faith", "grace", "hope", "joy", "patience",
    "charity", "crystal", "ivy", "dawn", "iris", "pearl", "ruby",
    "sandy", "violet", "hazel", "rose", "cliff", "dale", "glen",
    "heath", "lane", "lee", "max", "ray", "wade", "ward",
    # Days of week (some are names)
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    # Months (some are names like April, May, June, August)
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
])

# Safe allowlist - always suppress (confidence = 0)
SAFE_ALLOWLIST = frozenset([
    # Relative dates
    "today", "yesterday", "tomorrow", "now",
    "recently", "soon", "later", "currently",
    "this week", "last week", "next week",
    "this month", "last month", "next month",
    "this year", "last year", "next year",
    # Brand names that look like names
    "dr. pepper", "dr pepper", "mr. clean", "mr clean",
    "mrs. butterworth", "mrs butterworth",
    # Template/placeholder text (common in redacted documents)
    "redacted", "removed", "deleted", "omitted", "withheld",
    "tbd", "tba", "n/a", "na", "none", "null", "blank",
    "unknown", "unspecified", "undetermined", "unavailable",
    "xxxxx", "xxxx", "xxx", "xx",
    "first name", "last name", "full name",
    "patient name", "provider name", "doctor name",
    # Generic status words
    "pending", "complete", "completed", "active", "inactive",
    "normal", "abnormal", "positive", "negative",
    "stable", "unstable", "critical", "guarded",
])

# Job titles and common phrases that look like names with credentials
# These trigger NAME_PROVIDER patterns but are never actual personal names
# Accumulated from precision testing false positives
FALSE_POSITIVE_PHRASES = frozenset([
    # Job titles with credentials (look like "Name, MD" but aren't)
    "lab director, md",
    "lab director md",
    "medical director, md",
    "medical director md", 
    "clinical director, md",
    "chief of staff, md",
    "attending physician, md",
    "resident physician, md",
    "staff physician, md",
    "consulting physician, md",
    "department chair, md",
    "section chief, md",
    "program director, md",
    "nurse manager, rn",
    "charge nurse, rn",
    "staff nurse, rn",
    "clinical coordinator, rn",
    "nurse practitioner, np",
    "physician assistant, pa",
    "physical therapist, pt",
    "occupational therapist, ot",
    "respiratory therapist, rt",
    "pharmacist, pharmd",
    "dietitian, rd",
    # Common instructional phrases (trigger "Primary Care:" pattern)
    "call to schedule",
    "call for appointment",
    "call to reschedule",
    "call if needed",
    "call if worse",
    "call if worsens",
    "call if symptoms worsen",
    "return if symptoms worsen",
    "return if worse",
    "follow up as needed",
    "follow up prn",
    "see as needed",
    "pending results",
    "to be determined",
    "to be scheduled",
    "not applicable",
    "none reported",
    "none noted",
    "not available",
    "see above",
    "see below",
    "as above",
    "as noted",
    "as discussed",
    "per protocol",
    "per routine",
    # Referral phrases
    "referring the above",
    "the above patient",
    "the above named",
    "above named patient",
])

# Clinical field labels - these are labels/headers, never PHI
# PHI-BERT sometimes misclassifies these as NAME entities
CLINICAL_LABELS = frozenset([
    # Identifier labels
    "ssn", "dob", "mrn", "npi", "dea", "phone", "fax", "email",
    "address", "zip", "dod", "dos", "admit", "discharge", "acct",
    # Role labels
    "patient", "provider", "physician", "doctor", "nurse", "md", "do",
    "rn", "np", "pa", "ma", "cna", "lpn", "lvn", "pt", "ot", "rt",
    # Demographic labels
    "name", "age", "sex", "gender", "race", "ethnicity", "dob",
    "marital", "language", "religion", "occupation",
    # Clinical section headers
    "dx", "hx", "rx", "tx", "sx", "pmh", "psh", "fhx", "shx",
    "cc", "hpi", "ros", "pe", "a/p", "plan", "assessment",
    "subjective", "objective", "allergies", "medications",
    "vitals", "labs", "imaging", "procedures", "diagnosis",
    # Common abbreviations
    "pt", "pts", "yo", "y/o", "m", "f", "h/o", "s/p", "w/", "c/o",
    "r/o", "f/u", "prn", "bid", "tid", "qid", "qd", "hs", "ac", "pc",
])

# Medication false positives - dosage forms and units that aren't drug names
# These get incorrectly detected as MEDICATION by ML models
MEDICATION_FALSE_POSITIVES = frozenset([
    # Dosage forms
    "tablet", "tablets", "capsule", "capsules", "pill", "pills",
    "injection", "injections", "solution", "suspension", "syrup",
    "cream", "ointment", "gel", "patch", "patches", "spray",
    "inhaler", "drops", "suppository", "suppositories",
    # Units
    "mg", "mcg", "ml", "cc", "unit", "units", "iu",
    # Instructions
    "daily", "twice", "once", "oral", "orally", "topical", "topically",
    "as needed", "with food", "before meals", "after meals",
    # Generic terms
    "medication", "medicine", "drug", "prescription", "rx",
    "refill", "refills", "supply", "dose", "doses", "dosage",
])

# Address false positives - clinical terms incorrectly detected as addresses
ADDRESS_FALSE_POSITIVES = frozenset([
    # Clinical monitoring terms (often after "home")
    "monitoring", "monitoring.", "care", "health", "visit",
    # Single words that aren't addresses
    "none", "unknown", "n/a", "na", "pending", "same",
])

# Facility false positives - generic facility type words that aren't specific facility names
# "HOSPITAL ADMISSION RECORD" -> "HOSPITAL" is not a specific facility
FACILITY_FALSE_POSITIVES = frozenset([
    "hospital", "clinic", "medical", "center", "centre", "health",
    "healthcare", "facility", "office", "practice", "department",
    "emergency", "urgent", "care", "services", "system", "network",
])

# Account number false positives - words incorrectly captured after "Account" or "Billing" labels
ACCOUNT_FALSE_POSITIVES = frozenset([
    "created", "statement", "status", "type", "balance", "due",
    "summary", "history", "activity", "information", "details",
])

# ID number false positive patterns - lab reference ranges, percentages
# These contain digits but aren't identifiers
ID_NUMBER_FALSE_POSITIVE_PATTERNS = [
    # Reference ranges: "70-100", "5.7-6.4"
    r'^\d+\.?\d*-\d+\.?\d*$',
    # Comparison values: "<200", ">50", "<=100"
    r'^[<>]=?\d+\.?\d*\)?$',
    # Percentages: "5.7%", "<5.7%)"
    r'^[<>]?\d+\.?\d*%\)?$',
]

# Device ID false positives - generic label words, not actual serial numbers
DEVICE_ID_FALSE_POSITIVES = frozenset([
    "number", "serial", "model", "lot", "udi", "device", "id",
    "none", "unknown", "n/a", "na", "pending",
])

# Top 500 FDA drugs (generic and brand names that could be confused with personal names)
# Source: FDA Orange Book, CMS Drug Spending Data, clinical frequency data
# Lowercase for case-insensitive matching
DRUG_NAMES = frozenset([
    # A
    "abilify", "acarbose", "accupril", "acebutolol", "acetaminophen", "acetazolamide",
    "aciphex", "actos", "adalat", "adalimumab", "adderall", "adefovir", "advair",
    "advil", "aggrenox", "albuterol", "alendronate", "aleve", "alfuzosin", "allegra",
    "allopurinol", "almotriptan", "alprazolam", "altace", "amaryl", "ambien",
    "amiodarone", "amitriptyline",
    "amlodipine", "amoxicillin", "amphetamine", "anastrozole", "androgel", "aricept",
    "aripiprazole", "armour", "aspirin", "atenolol", "ativan", "atorvastatin", "atripla",
    "atrovent", "augmentin", "avalide", "avandia", "avapro", "avelox", "azathioprine",
    "azithromycin", "azor",
    # B
    "baclofen", "bactrim", "benadryl", "benicar", "benzonatate", "betamethasone",
    "bicalutamide", "biaxin", "bisoprolol", "boniva", "brilinta", "budesonide", "bumex",
    "bumetanide", "buprenorphine", "bupropion", "buspar", "buspirone", "byetta", "bystolic",
    # C
    "cabergoline", "calan", "calcitriol", "campral", "candesartan", "capoten", "captopril",
    "carbamazepine", "cardizem", "cardura", "carisoprodol", "carvedilol", "casodex",
    "catapres", "cefdinir", "cefprozil", "ceftriaxone", "cefuroxime", "celebrex",
    "celecoxib", "celexa", "cephalexin", "chantix", "cialis", "cilostazol", "cimetidine",
    "cipro", "ciprofloxacin", "citalopram", "clarinex", "clarithromycin", "claritin",
    "clindamycin", "clobetasol", "clomiphene", "clonazepam", "clonidine", "clopidogrel",
    "clotrimazole", "clozapine", "colace", "colchicine", "colestid", "combivent",
    "concerta", "copaxone", "cordarone", "coreg", "corgard", "coumadin", "cozaar",
    "crestor", "cymbalta",
    # D
    "dabigatran", "darvocet", "depakote", "desloratadine", "desvenlafaxine", "detrol",
    "dexamethasone", "dexilant", "dexmethylphenidate", "diazepam", "diclofenac", "dicyclomine",
    "didanosine", "differin", "diflucan", "digoxin", "dilantin", "diltiazem", "diovan",
    "diphenhydramine", "ditropan", "divalproex", "docusate", "donepezil", "dorzolamide",
    "doxazosin", "doxepin", "doxycycline", "dulera", "duloxetine", "duragesic", "dutasteride",
    "dyazide",
    # E
    "effexor", "elavil", "eliquis", "emtricitabine", "enalapril", "enbrel", "entresto",
    "epinephrine", "epzicom", "ergotamine", "erythromycin", "escitalopram", "esomeprazole",
    "estrace", "estradiol", "eszopiclone", "etanercept", "etonogestrel", "evista",
    "exelon", "ezetimibe", "ezogabine",
    # F
    "famotidine", "farxiga", "felodipine", "fenofibrate", "fentanyl", "ferrous", "fexofenadine",
    "finasteride", "fioricet", "flagyl", "flexeril", "flomax", "flonase", "flovent",
    "fluconazole", "fludrocortisone", "flunisolide", "fluocinonide", "fluorouracil",
    "fluoxetine", "fluticasone", "fluvastatin", "focalin", "folic", "foradil",
    "formoterol", "fortamet", "fosamax", "fosinopril", "furosemide",
    # G
    "gabapentin", "galantamine", "ganciclovir", "gemfibrozil", "geodon", "gianvi",
    "glimepiride", "glipizide", "glucophage", "glucotrol", "glyburide", "granisetron",
    "guaifenesin", "guanfacine",
    # H
    "haloperidol", "harvoni", "humalog", "humira", "hydrochlorothiazide", "hydrocodone",
    "hydrocortisone", "hydromorphone", "hydroxychloroquine", "hydroxyzine", "hyoscyamine",
    "hytrin", "hyzaar",
    # I
    "ibandronate", "ibuprofen", "imbruvica", "imdur", "imiquimod", "imipramine", "imitrex",
    "incivek", "indapamide", "inderal", "indomethacin", "infliximab", "invokana",
    "ipratropium", "irbesartan", "isoniazid", "isosorbide", "isotretinoin", "itraconazole",
    # J
    "janumet", "januvia", "jardiance", "junel",
    # K
    "keflex", "kenalog", "keppra", "ketoconazole", "ketoprofen", "ketorolac", "klor-con",
    "klonopin", "kombiglyze",
    # L
    "labetalol", "lactulose", "lamictal", "lamivudine", "lamotrigine", "lanoxin", "lansoprazole",
    "lantus", "lasix", "latanoprost", "latuda", "lescol", "letrozole", "levemir",
    "levetiracetam", "levitra", "levocetirizine", "levodopa", "levofloxacin", "levonorgestrel",
    "levothyroxine", "lexapro", "lidocaine", "lidoderm", "linezolid", "liothyronine",
    "lipitor", "liraglutide", "lisinopril", "lithium", "livalo", "lodine", "loestrin",
    "loperamide", "lopid", "lopressor", "loratadine", "lorazepam", "lortab", "losartan",
    "lotemax", "lotrel", "lovenox", "lumigan", "lunesta", "lurasidone", "lyrica",
    # M
    "meclizine", "medroxyprogesterone", "meloxicam", "memantine", "mesalamine",
    "metaxalone", "metformin", "methadone", "methocarbamol", "methotrexate", "methylphenidate",
    "methylprednisolone", "metoclopramide", "metolazone", "metoprolol", "metronidazole",
    "mevacor", "micardis", "minocycline", "minoxidil", "mirtazapine", "misoprostol",
    "mobic", "modafinil", "mometasone", "montelukast", "morphine", "motrin", "moxifloxacin",
    "mucinex", "multaq", "mycophenolate",
    # N
    "nabumetone", "nadolol", "naloxone", "naltrexone", "namenda", "naprosyn", "naproxen",
    "nasonex", "nebivolol", "nelfinavir", "neoral", "neurontin", "nexium", "niacin",
    "niaspan", "nicotine", "nifedipine", "nitrofurantoin", "nitroglycerin", "nitroquick",
    "nizoral", "nolvadex", "norco", "norvasc", "nortriptyline", "novolog", "nuvigil",
    # O
    "olanzapine", "olmesartan", "olopatadine", "omeprazole", "ondansetron", "onglyza",
    "opana", "orlistat", "ortho", "oseltamivir", "oxaprozin", "oxcarbazepine", "oxybutynin",
    "oxycodone", "oxycontin", "oxytocin",
    # P
    "paliperidone", "palonosetron", "pancrelipase", "pantoprazole", "paroxetine", "patanol",
    "paxil", "penicillin", "pentasa", "percocet", "phenazopyridine", "phenobarbital",
    "phentermine", "phenytoin", "pioglitazone", "plavix", "pletal", "polyethylene",
    "potassium", "pradaxa", "pramipexole", "prandin", "prasugrel", "pravachol", "pravastatin",
    "prazosin", "prednisone", "pregabalin", "premarin", "prempro", "prevacid", "prilosec",
    "primidone", "prinivil", "pristiq", "proair", "procainamide", "prochlorperazine",
    "progestrone", "promethazine", "propecia", "propoxyphene", "propranolol", "proscar",
    "protonix", "proventil", "provera", "provigil", "prozac", "pulmicort",
    # Q
    "quetiapine", "quillivant", "quinapril", "qvar",
    # R
    "rabeprazole", "raloxifene", "ramelteon", "ramipril", "ranexa", "ranitidine",
    "razadyne", "reglan", "remeron", "remicade", "repaglinide", "requip", "restoril",
    "revatio", "rexulti", "rifampin", "risperdal", "risperidone", "ritalin", "rivaroxaban",
    "rizatriptan", "robaxin", "ropinirole", "rosuvastatin", "rozerem", "rythmol",
    # S
    "salmeterol", "sandostatin", "saphris", "saxagliptin", "seasonique", "selegiline",
    "sensipar", "septra", "serevent", "seroquel", "sertraline", "simvastatin", "sinemet",
    "singulair", "sitagliptin", "skelaxin", "sodium", "solaraze", "solifenacin", "soma",
    "sonata", "spiriva", "spironolactone", "sporanox", "sprintec", "sprix", "stalevo",
    "staxyn", "stelara", "stendra", "strattera", "stromectol", "suboxone", "sucralfate",
    "sulfamethoxazole", "sulfasalazine", "sulindac", "sumatriptan", "sustiva", "symbicort",
    "synthroid",
    # T
    "tacrolimus", "tadalafil", "tamoxifen", "tamsulosin", "tapentadol", "tegretol",
    "tekturna", "telmisartan", "temazepam", "tenofovir", "terazosin", "terbinafine",
    "testosterone", "theophylline", "timolol", "tizanidine", "tobramycin", "tobrex",
    "tolterodine", "topamax", "topiramate", "toprol", "toradol", "torsemide", "toviaz",
    "tradjenta", "tramadol", "trandolapril", "tranexamic", "trazodone", "treximet",
    "triamcinolone", "triamterene", "triazolam", "tricor", "trilipix", "trimethoprim",
    "trintellix", "triptan", "trokendi", "trospium", "trulicity", "truvada", "tylenol",
    # U
    "uloric", "ultracet", "ultram", "urecholine", "ursodiol",
    # V
    "valacyclovir", "valium", "valproic", "valsartan", "valtrex", "vancomycin", "vardenafil",
    "varenicline", "vasotec", "venlafaxine", "ventolin", "verapamil", "versed", "vesicare",
    "viagra", "vibramycin", "vicodin", "victoza", "videx", "vigamox", "viibryd", "vimpat",
    "viread", "voltaren", "vraylar", "vytorin", "vyvanse",
    # W
    "warfarin", "welchol", "wellbutrin",
    # X
    "xalatan", "xanax", "xarelto", "xeljanz", "xgeva", "xifaxan", "xopenex", "xyrem",
    # Y
    "yasmin", "yaz",
    # Z
    "zanaflex", "zantac", "zarontin", "zebeta", "zegerid", "zestoretic", "zestril",
    "zetia", "ziac", "ziprasidone", "zithromax", "zocor", "zofran", "zoloft", "zolpidem",
    "zomig", "zonegran", "zostavax", "zosyn", "zovirax", "zyloprim", "zyprexa", "zyrtec",
])

# Medication context indicators - expanded
MED_CONTEXT_PATTERNS = [
    # Dosages
    re.compile(r'\b\d+\s*mg\b', re.I),
    re.compile(r'\b\d+\s*ml\b', re.I),
    re.compile(r'\b\d+\s*mcg\b', re.I),
    re.compile(r'\b\d+\s*g\b', re.I),
    re.compile(r'\b\d+\s*iu\b', re.I),
    re.compile(r'\b\d+\s*units?\b', re.I),
    # Frequency
    re.compile(r'\bdaily\b', re.I),
    re.compile(r'\btwice\s+daily\b', re.I),
    re.compile(r'\bb\.?i\.?d\.?\b', re.I),
    re.compile(r'\bt\.?i\.?d\.?\b', re.I),
    re.compile(r'\bq\.?i\.?d\.?\b', re.I),
    re.compile(r'\bp\.?r\.?n\.?\b', re.I),
    re.compile(r'\bq\.?\d+h\b', re.I),
    re.compile(r'\bonce\s+daily\b', re.I),
    re.compile(r'\bat\s+bedtime\b', re.I),
    re.compile(r'\bhs\b', re.I),
    re.compile(r'\bqhs\b', re.I),
    # Routes
    re.compile(r'\boral(ly)?\b', re.I),
    re.compile(r'\biv\b', re.I),
    re.compile(r'\bim\b', re.I),
    re.compile(r'\bsubq?\b', re.I),
    re.compile(r'\btopical(ly)?\b', re.I),
    re.compile(r'\binhaled?\b', re.I),
    re.compile(r'\bpo\b', re.I),
    # Actions
    re.compile(r'\bprescribed\b', re.I),
    re.compile(r'\btakes?\b', re.I),
    re.compile(r'\btaking\b', re.I),
    re.compile(r'\badministered\b', re.I),
    re.compile(r'\brefill\b', re.I),
    re.compile(r'\bstarted?\b', re.I),
    re.compile(r'\bdiscontinued?\b', re.I),
    re.compile(r'\bhold\b', re.I),
    re.compile(r'\bon\b', re.I),
    # Forms
    re.compile(r'\btablets?\b', re.I),
    re.compile(r'\bcapsules?\b', re.I),
    re.compile(r'\bpills?\b', re.I),
    re.compile(r'\bsyrup\b', re.I),
    re.compile(r'\binjection\b', re.I),
    re.compile(r'\bdose\b', re.I),
    re.compile(r'\bmedication\b', re.I),
    re.compile(r'\bfor\s+(?:pain|anxiety|diabetes|hypertension|depression|insomnia|cholesterol)\b', re.I),
]

# Date context indicators (suppress dates after these)
DATE_CONTEXT = frozenset([
    "published", "version", "copyright",
    "fda approved", "guideline from", "effective",
    "revision", "updated", "released",
])

# Number context indicators (suppress numbers after these)
NUMBER_CONTEXT = frozenset([
    "room", "extension", "ext", "lab code",
    "reference", "ref", "lot", "batch",
    "invoice", "order", "case",
])

def _has_medication_context(text: str, span: Span, window: int = 50) -> bool:
    """Check if surrounding text has medication context."""
    start = max(0, span.start - window)
    end = min(len(text), span.end + window)
    context = text[start:end].lower()

    for pattern in MED_CONTEXT_PATTERNS:
        if pattern.search(context):
            return True

    return False


def _has_date_context(text: str, span: Span, window: int = 30) -> bool:
    """Check if date appears after context words."""
    start = max(0, span.start - window)
    prefix = text[start:span.start].lower()

    for ctx in DATE_CONTEXT:
        if ctx in prefix:
            return True

    return False


def _has_number_context(text: str, span: Span, window: int = 20) -> bool:
    """Check if number appears after context words."""
    start = max(0, span.start - window)
    prefix = text[start:span.start].lower()

    for ctx in NUMBER_CONTEXT:
        if ctx in prefix:
            return True

    return False


def apply_allowlist(text: str, spans: List[Span]) -> List[Span]:
    """
    Two-pass allowlist filtering.
    
    Pass 1: All potential PHI flagged (already done by detectors)
    Pass 2: Suppress based on context
    
    Rules:
    - Safe allowlist terms: fully suppress (skip)
    - False positive phrases: suppress if detected as NAME (job titles, instructions)
    - Clinical labels: suppress if detected as NAME (they're field headers)
    - Drug names WITH medication context: fully suppress (skip)
    - Drug names WITHOUT context: no change (could be a personal name)
    - Dates with publishing context: confidence *= 0.3
    - Numbers with reference context: confidence *= 0.3
    
    Returns only spans that should remain (those not suppressed).
    """
    result = []

    for span in spans:
        text_lower = span.text.lower().strip()
        # Strip leading/trailing punctuation for matching (e.g., "Hello," -> "hello")
        text_clean = text_lower.strip('.,;:!?"\'-()[]{}')

        # Safe allowlist - always suppress
        if text_clean in SAFE_ALLOWLIST:
            continue  # Don't add to result

        # Common words - suppress if detected as NAME type (single words only)
        # "treatment", "therapy", "care" etc. are generic terms, not personal names
        # NOTE: Don't filter MEDICATION type here - COMMON_WORDS contains drug names
        # and we WANT to detect those. DRUG_NAMES filter below handles name vs drug.
        if text_clean in COMMON_WORDS and span.entity_type.startswith("NAME"):
            continue  # Don't add to result - generic terms aren't names

        # Medication false positives - "tablet", "capsule", "mg" etc. aren't drug names
        if text_clean in MEDICATION_FALSE_POSITIVES and span.entity_type == "MEDICATION":
            continue  # Don't add to result - dosage forms aren't medications

        # Address false positives - "monitoring.", "care" etc. aren't addresses
        if text_clean in ADDRESS_FALSE_POSITIVES and span.entity_type == "ADDRESS":
            continue  # Don't add to result - clinical terms aren't addresses

        # Facility false positives - generic words like "HOSPITAL" from headers
        if text_clean in FACILITY_FALSE_POSITIVES and span.entity_type == "FACILITY":
            continue  # Don't add to result - generic facility type, not specific name

        # Account number false positives - "Created", "Statement" after Account/Billing labels
        if text_clean in ACCOUNT_FALSE_POSITIVES and span.entity_type == "ACCOUNT_NUMBER":
            continue  # Don't add to result - not an account number

        # ID number false positives - lab reference ranges like "70-100", "<5.7%)"
        if span.entity_type == "ID_NUMBER":
            is_reference_range = any(re.match(p, text_clean) for p in ID_NUMBER_FALSE_POSITIVE_PATTERNS)
            if is_reference_range:
                continue  # Don't add to result - lab reference range, not an ID

        # Device ID false positives - "Number" captured after "Serial Number:" label
        if text_clean in DEVICE_ID_FALSE_POSITIVES and span.entity_type == "DEVICE_ID":
            continue  # Don't add to result - label word, not a device ID

        # For multi-word NAME spans, only filter if ALL words are common words
        # This catches "recommends rest" but keeps "April Jones" (Jones is not common)
        if span.entity_type.startswith("NAME") and " " in text_clean:
            words = [w.strip('.,;:!?"\'-()[]{}') for w in text_clean.split()]
            if all(word in COMMON_WORDS for word in words):
                continue  # All words are common, not a name

        # False positive phrases - suppress if detected as NAME type
        # These are job titles ("Lab Director, MD") and instructions ("Call to schedule")
        if text_clean in FALSE_POSITIVE_PHRASES and span.entity_type.startswith("NAME"):
            continue  # Don't add to result - not a personal name

        # Clinical labels - suppress if detected as NAME type
        # These are field headers like "SSN", "DOB", "MRN", not actual PHI
        if text_clean in CLINICAL_LABELS and span.entity_type.startswith("NAME"):
            continue  # Don't add to result - "SSN" the label is not a name

        # Drug names detected as NAME - suppress if medication context present
        # This filters "Allegra" when clearly used as a drug, not a person's name
        # But keep MEDICATION type spans - those should be detected
        if text_clean in DRUG_NAMES and span.entity_type.startswith("NAME"):
            if _has_medication_context(text, span):
                continue  # Don't add to result - it's clearly a drug, not a name
            # Without context: keep it (could be a personal name like "Allegra")

        # Date context - downgrade confidence (immutable - create new span)
        if span.entity_type in ("DATE", "DATE_DOB", "DATE_RANGE"):
            if _has_date_context(text, span):
                span = Span(
                    start=span.start,
                    end=span.end,
                    text=span.text,
                    entity_type=span.entity_type,
                    confidence=span.confidence * 0.3,
                    detector=span.detector,
                    tier=span.tier,
                    safe_harbor_value=span.safe_harbor_value,
                    needs_review=span.needs_review,
                    review_reason=span.review_reason,
                    coref_anchor_value=span.coref_anchor_value,
                    token=span.token,
                )

        # Number context (for MRN-like numbers) - downgrade confidence (immutable)
        if span.entity_type in ("MRN", "ENCOUNTER_ID", "ACCESSION_ID"):
            if _has_number_context(text, span):
                span = Span(
                    start=span.start,
                    end=span.end,
                    text=span.text,
                    entity_type=span.entity_type,
                    confidence=span.confidence * 0.3,
                    detector=span.detector,
                    tier=span.tier,
                    safe_harbor_value=span.safe_harbor_value,
                    needs_review=span.needs_review,
                    review_reason=span.review_reason,
                    coref_anchor_value=span.coref_anchor_value,
                    token=span.token,
                )

        result.append(span)

    return result

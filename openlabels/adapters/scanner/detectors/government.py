"""Tier 2: Government and classification detectors (clearance markings, CAGE codes, contracts)."""

import logging
import re
from typing import List, Tuple

from ..types import Span, Tier
from .base import BasePatternDetector
from .constants import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_MEDIUM_LOW,
    CONFIDENCE_NEAR_CERTAIN,
    CONFIDENCE_PERFECT,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_VERY_HIGH,
)

logger = logging.getLogger(__name__)

from .pattern_registry import create_pattern_adder

GOVERNMENT_PATTERNS: List[Tuple[re.Pattern, str, float, int]] = []
_add = create_pattern_adder(GOVERNMENT_PATTERNS)


# --- CLASSIFICATION LEVELS ---
# Basic classification levels
_add(r'\b(TOP\s*SECRET)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(SECRET)\b(?!\s*(?:santa|garden|service|recipe|ingredient|weapon|sauce))', 
     'CLASSIFICATION_LEVEL', CONFIDENCE_LOW, 1, re.I)  # Avoid false positives
_add(r'\b(CONFIDENTIAL)\b(?=.*(?:classification|clearance|noforn|sci|//|caveat))', 
     'CLASSIFICATION_LEVEL', CONFIDENCE_MEDIUM, 1, re.I)  # Require context
_add(r'\b(UNCLASSIFIED)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_RELIABLE, 1, re.I)
_add(r'\b(UNCLASSIFIED//FOUO)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(CUI)\b(?=.*(?:controlled|unclassified|information|category))', 
     'CLASSIFICATION_LEVEL', CONFIDENCE_MEDIUM_LOW, 1, re.I)  # Controlled Unclassified Information
_add(r'\b(CONTROLLED\s+UNCLASSIFIED\s+INFORMATION)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)


# --- FULL CLASSIFICATION MARKINGS (with caveats) ---
# Classification with SCI: "TOP SECRET//SCI"
_add(r'\b((?:TOP\s*SECRET|SECRET)//SCI)\b', 'CLASSIFICATION_MARKING', CONFIDENCE_PERFECT, 1, re.I)

# Classification with compartments: "TOP SECRET//SI/TK//NOFORN"
_add(r'\b((?:TOP\s*SECRET|SECRET)(?://[A-Z]{2,})+(?://[A-Z\s]+)?)\b', 
     'CLASSIFICATION_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)

# Classification with NOFORN/REL TO
_add(r'\b((?:TOP\s*SECRET|SECRET|CONFIDENTIAL)//(?:NOFORN|NF))\b', 
     'CLASSIFICATION_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b((?:TOP\s*SECRET|SECRET|CONFIDENTIAL)//REL\s+TO\s+[A-Z,\s]+)\b', 
     'CLASSIFICATION_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)

# Portion markings: (TS), (S), (C), (U), (TS//SCI)
_add(r'\(([TCS]S?(?://[A-Z/]+)?)\)', 'CLASSIFICATION_MARKING', CONFIDENCE_RELIABLE, 1)
_add(r'\((TS//SCI(?:/[A-Z]+)*)\)', 'CLASSIFICATION_MARKING', CONFIDENCE_VERY_HIGH, 1)


# --- SCI (Sensitive Compartmented Information) MARKERS ---
# Common SCI compartments
_add(r'\b(//SI)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1)  # Special Intelligence
_add(r'\b(//TK)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1)  # TALENT KEYHOLE
_add(r'\b(//HCS)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1)  # HUMINT Control System
_add(r'\b(//G)\b(?=.*(?:gamma|//|sci|secret))', 'SCI_MARKING', CONFIDENCE_MEDIUM, 1, re.I)  # GAMMA
_add(r'\b(//COMINT)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(//SIGINT)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(//HUMINT)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(//IMINT)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(//GEOINT)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(//MASINT)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)

# SAP (Special Access Program) indicators
_add(r'\b(SAP)\b(?=.*(?:access|program|classified|//|waived))', 'SCI_MARKING', CONFIDENCE_MEDIUM_LOW, 1, re.I)
_add(r'\b(SPECIAL\s+ACCESS\s+(?:PROGRAM|REQUIRED))\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(WAIVED\s+SAP)\b', 'SCI_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)


# --- DISSEMINATION CONTROLS ---
# NOFORN: Not Releasable to Foreign Nationals
_add(r'\b(NOFORN|NF)\b(?=.*(?://|secret|classified|rel|dissem))', 
     'DISSEMINATION_CONTROL', CONFIDENCE_HIGH, 1, re.I)
_add(r'\b(//NOFORN)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_PERFECT, 1, re.I)

# REL TO: Releasable To
_add(r'\b(REL\s+(?:TO\s+)?(?:USA|FVEY|[A-Z]{3}(?:\s*,\s*[A-Z]{3})*))\b', 
     'DISSEMINATION_CONTROL', CONFIDENCE_HIGH, 1, re.I)
_add(r'\b(//REL\s+TO\s+[A-Z,\s]+)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_VERY_HIGH, 1, re.I)

# FVEY: Five Eyes
_add(r'\b(FVEY|FIVE\s+EYES)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_HIGH, 1, re.I)

# Other dissemination controls
_add(r'\b(ORCON)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_VERY_HIGH, 1)  # Originator Controlled
_add(r'\b(IMCON)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_VERY_HIGH, 1)  # Imagery Intelligence Control
_add(r'\b(PROPIN)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_VERY_HIGH, 1)  # Proprietary Information
_add(r'\b(RELIDO)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_VERY_HIGH, 1)  # Releasable by IDO
_add(r'\b(FOUO)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_HIGH, 1)  # For Official Use Only
_add(r'\b(LAW\s+ENFORCEMENT\s+SENSITIVE)\b', 'DISSEMINATION_CONTROL', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(LES)\b(?=.*(?:law|enforcement|sensitive|//|dissem))', 'DISSEMINATION_CONTROL', CONFIDENCE_LOW, 1)


# --- GOVERNMENT ENTITY CODES ---
# CAGE Code: 5 alphanumeric (Commercial and Government Entity)
_add(r'(?:CAGE|cage)[:\s#]+([A-Z0-9]{5})\b', 'CAGE_CODE', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(?:cage\s+code)[:\s]+([A-Z0-9]{5})\b', 'CAGE_CODE', CONFIDENCE_VERY_HIGH, 1, re.I)

# DUNS Number: 9 digits (deprecated but still in use)
_add(r'(?:DUNS|D-U-N-S)[:\s#]+(\d{9})\b', 'DUNS_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'(?:DUNS|D-U-N-S)[:\s#]+(\d{2}-\d{3}-\d{4})\b', 'DUNS_NUMBER', CONFIDENCE_VERY_HIGH, 1, re.I)

# UEI: Unique Entity Identifier (12 alphanumeric, replaced DUNS)
_add(r'(?:UEI|Unique\s+Entity\s+(?:ID|Identifier))[:\s#]+([A-Z0-9]{12})\b', 'UEI', CONFIDENCE_VERY_HIGH, 1, re.I)

# SAM.gov registration
_add(r'(?:SAM|SAM\.gov)[:\s]+(?:registration|ID|#)[:\s]*([A-Z0-9]{12})\b', 'UEI', CONFIDENCE_HIGH, 1, re.I)


# --- DOD CONTRACT NUMBERS ---
# DoD Contract Number Formats:
# FA####-##-C-#### (Air Force)
# W####-##-C-#### (Army)  
# N#####-##-C-#### (Navy)
# DAAB##-##-C-#### (older Army)
# H#####-##-C-#### (Defense Logistics)

# Generic DoD contract pattern
_DOD_PREFIX = r'(?:FA|W|N|HQ|DAAB|DAHC|DACA|DACW|DAHA|DAJA|DAKF|DAMX|DASA|DASW|DASG|DAST|DATC|DAEA|DAAD|DAAE|DAAG|DAAH|DAAJ|DAAL|DAAM|DAAK|DAAO|DAAP|DAAQ|H|HR|SP)'

# Standard format: PREFIX + 4-5 digits + YY + C/D/G/M + 4 digits
_add(rf'\b({_DOD_PREFIX}\d{{4,5}}-\d{{2}}-[CDGM]-\d{{4}})\b', 'DOD_CONTRACT', CONFIDENCE_VERY_HIGH, 1, re.I)

# With modification number: ... + P##### or M#####
_add(rf'\b({_DOD_PREFIX}\d{{4,5}}-\d{{2}}-[CDGM]-\d{{4}}-[PM]\d{{3,5}})\b', 'DOD_CONTRACT', CONFIDENCE_VERY_HIGH, 1, re.I)

# PIID format (newer)
_add(r'\b([A-Z]{1,6}\d{4,5}-\d{2}-[CDGM]-\d{4})\b', 'DOD_CONTRACT', CONFIDENCE_MEDIUM, 1)

# Labeled contract references (exclude GSA MAS format starting with 47)
_add(r'(?:Contract|Contract\s+(?:No|Number|#))[:\s]+(?!47[A-Z]{2})([A-Z0-9\-]{10,25})\b', 'DOD_CONTRACT', CONFIDENCE_LOW, 1, re.I)


# --- GSA CONTRACT NUMBERS ---
# GSA Schedule contract: GS-###-####
_add(r'\b(GS-\d{2}[A-Z]-\d{4}[A-Z]?)\b', 'GSA_CONTRACT', CONFIDENCE_VERY_HIGH, 1)
_add(r'\b(GS-\d{3}-\d{4}[A-Z]?)\b', 'GSA_CONTRACT', CONFIDENCE_VERY_HIGH, 1)

# GSA MAS (Multiple Award Schedule) - 47QTCA21D1234 format
# Must be before broad DOD labeled pattern to take precedence
_add(r'\b(47[A-Z]{2}[A-Z0-9]{2}\d{2}[A-Z]\d{4})\b', 'GSA_CONTRACT', CONFIDENCE_HIGH, 1)

# Labeled GSA MAS - "Contract 47QTCA21D1234" format
_add(r'(?:Contract|Contract\s+(?:No|Number|#))[:\s]+(47[A-Z]{2}[A-Z0-9]{2}\d{2}[A-Z]\d{4})\b',
     'GSA_CONTRACT', CONFIDENCE_NEAR_CERTAIN, 1, re.I)

# Labeled GSA
_add(r'(?:GSA\s+(?:Schedule|Contract)|Schedule\s+Contract)[:\s#]+([A-Z0-9\-]{8,20})\b',
     'GSA_CONTRACT', CONFIDENCE_RELIABLE, 1, re.I)


# --- SECURITY CLEARANCE ---
# Clearance level references
_add(r'\b(TS/SCI)\b', 'CLEARANCE_LEVEL', CONFIDENCE_VERY_HIGH, 1)
_add(r'\b(TOP\s*SECRET\s+(?:SCI\s+)?CLEARANCE)\b', 'CLEARANCE_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(SECRET\s+CLEARANCE)\b', 'CLEARANCE_LEVEL', CONFIDENCE_HIGH, 1, re.I)
_add(r'\b((?:ACTIVE\s+)?(?:TS|TOP\s*SECRET|SECRET|CONFIDENTIAL)\s+(?:SECURITY\s+)?CLEARANCE)\b', 
     'CLEARANCE_LEVEL', CONFIDENCE_HIGH, 1, re.I)
_add(r'\b(Q\s+CLEARANCE)\b', 'CLEARANCE_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)  # DOE
_add(r'\b(L\s+CLEARANCE)\b', 'CLEARANCE_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)  # DOE
_add(r'\b(YANKEE\s+WHITE)\b', 'CLEARANCE_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)  # Presidential access

# Polygraph requirements
_add(r'\b((?:FULL\s+SCOPE|CI|COUNTER[- ]?INTELLIGENCE|LIFESTYLE)\s+POLY(?:GRAPH)?)\b', 
     'CLEARANCE_LEVEL', CONFIDENCE_HIGH, 1, re.I)


# --- EXPORT CONTROL (ITAR/EAR) ---
# ITAR markings
_add(r'\b(ITAR\s+(?:CONTROLLED|RESTRICTED|DATA|INFORMATION))\b', 'ITAR_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b((?:THIS\s+)?(?:DOCUMENT|DATA|INFORMATION)\s+(?:IS\s+)?(?:SUBJECT\s+TO\s+)?ITAR)\b', 
     'ITAR_MARKING', CONFIDENCE_HIGH, 1, re.I)
_add(r'\b(USML\s+CATEGORY\s+[IVXLCDM]+)\b', 'ITAR_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)  # US Munitions List
_add(r'\b(22\s*CFR\s*1[2-9][0-9])\b', 'ITAR_MARKING', CONFIDENCE_HIGH, 1, re.I)  # ITAR regulations

# EAR markings  
_add(r'\b(EAR\s+(?:CONTROLLED|99|DATA))\b', 'EAR_MARKING', CONFIDENCE_HIGH, 1, re.I)
_add(r'\b(ECCN[:\s]+[0-9][A-Z][0-9]{3})\b', 'EAR_MARKING', CONFIDENCE_VERY_HIGH, 1, re.I)  # Export Control Classification
_add(r'\b(15\s*CFR\s*7[3-9][0-9])\b', 'EAR_MARKING', CONFIDENCE_HIGH, 1, re.I)  # EAR regulations
_add(r'\b(EXPORT\s+(?:CONTROLLED|RESTRICTED))\b', 'EAR_MARKING', CONFIDENCE_MEDIUM_LOW, 1, re.I)


# --- SENSITIVE BUT UNCLASSIFIED CATEGORIES ---
# SBU categories
_add(r'\b(SENSITIVE\s+BUT\s+UNCLASSIFIED)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(LIMITED\s+OFFICIAL\s+USE)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(OFFICIAL\s+USE\s+ONLY)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_HIGH, 1, re.I)
_add(r'\b(DEA\s+SENSITIVE)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)
_add(r'\b(DOD\s+UNCLASSIFIED\s+CONTROLLED)\b', 'CLASSIFICATION_LEVEL', CONFIDENCE_VERY_HIGH, 1, re.I)


# --- DETECTOR CLASS ---
class GovernmentDetector(BasePatternDetector):
    """
    Detects government classification markings and identifiers.

    Catches security classification levels, SCI compartments,
    dissemination controls, contract numbers, and CAGE codes.
    """

    name = "government"
    tier = Tier.PATTERN

    def get_patterns(self):
        """Return government patterns."""
        return GOVERNMENT_PATTERNS

    def detect(self, text: str) -> List[Span]:
        """Detect government markings in text with logging."""
        spans = super().detect(text)

        if spans:
            # Summarize by entity type
            type_counts = {}
            for span in spans:
                type_counts[span.entity_type] = type_counts.get(span.entity_type, 0) + 1
            logger.info(f"GovernmentDetector found {len(spans)} entities: {type_counts}")

            # Log classification markings at DEBUG (sensitive indicators)
            classification_types = ['CLASSIFICATION_LEVEL', 'CLASSIFICATION_MARKING', 'SCI_MARKING']
            for span in spans:
                if span.entity_type in classification_types:
                    logger.debug(f"Classification marking detected: {span.entity_type} at position {span.start}-{span.end}")

        return spans

    def _is_false_positive(self, entity_type: str, value: str,
                           text: str, start: int) -> bool:
        """Filter false positives for classification words."""
        if entity_type != 'CLASSIFICATION_LEVEL':
            return False

        value_lower = value.lower()

        # "SECRET" has many false positives
        if 'secret' in value_lower and 'top' not in value_lower:
            # Check surrounding context for classification indicators
            context_start = max(0, start - 50)
            context_end = min(len(text), start + len(value) + 50)
            context = text[context_start:context_end].lower()

            # Must have classification context
            classification_context = [
                '//', 'classified', 'clearance', 'noforn', 'sci', 'fouo',
                'dissem', 'caveat', 'portion', 'marking', 'unclassified',
                'secret//', '//secret'
            ]

            if not any(ctx in context for ctx in classification_context):
                logger.debug(f"Filtered false positive 'SECRET' - no classification context found")
                return True

        return False

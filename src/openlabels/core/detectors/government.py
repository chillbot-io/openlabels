"""
Government and classification detector.

Detects security classification markings, government identifiers,
and defense/intelligence related patterns.

Entity Types:
- CLASSIFICATION_LEVEL: Classification levels (TOP SECRET, SECRET, etc.)
- CLASSIFICATION_MARKING: Full classification lines with caveats
- SCI_MARKING: Sensitive Compartmented Information markers
- DISSEMINATION_CONTROL: NOFORN, REL TO, ORCON, etc.
- CAGE_CODE: Commercial and Government Entity Code (5 chars)
- DUNS_NUMBER: Data Universal Numbering System (9 digits)
- UEI: Unique Entity Identifier (12 chars)
- DOD_CONTRACT: DoD contract numbers
- GSA_CONTRACT: GSA schedule contract numbers
- CLEARANCE_LEVEL: Security clearance references
- ITAR_MARKING: International Traffic in Arms Regulations
- EAR_MARKING: Export Administration Regulations
"""

from __future__ import annotations

import re

from ..types import Span, Tier
from .base import BaseDetector
from .pattern_registry import PatternDefinition, _p
from .registry import register_detector

_DOD_PREFIX = (
    r'(?:FA|W|N|HQ|DAAB|DAHC|DACA|DACW|DAHA|DAJA|DAKF|DAMX|DASA|DASW'
    r'|DASG|DAST|DATC|DAEA|DAAD|DAAE|DAAG|DAAH|DAAJ|DAAL|DAAM|DAAK|DAAO|DAAP|DAAQ|H|HR|SP)'
)

GOVERNMENT_PATTERNS: tuple[PatternDefinition, ...] = (
    # --- CLASSIFICATION LEVELS ---
    _p(r'\b(TOP\s*SECRET)\b', 'CLASSIFICATION_LEVEL', 0.98, 1, flags=re.I),
    _p(r'\b(SECRET)\b(?!\s*(?:santa|garden|service|recipe|ingredient|weapon|sauce))',
       'CLASSIFICATION_LEVEL', 0.85, 1, flags=re.I),
    _p(r'\b(CONFIDENTIAL)\b(?=.*(?:classification|clearance|noforn|sci|//|caveat))',
       'CLASSIFICATION_LEVEL', 0.90, 1, flags=re.I),
    _p(r'\b(UNCLASSIFIED)\b', 'CLASSIFICATION_LEVEL', 0.92, 1, flags=re.I),
    _p(r'\b(UNCLASSIFIED//FOUO)\b', 'CLASSIFICATION_LEVEL', 0.98, 1, flags=re.I),
    _p(r'\b(CUI)\b(?=.*(?:controlled|unclassified|information|category))',
       'CLASSIFICATION_LEVEL', 0.88, 1, flags=re.I),
    _p(r'\b(CONTROLLED\s+UNCLASSIFIED\s+INFORMATION)\b', 'CLASSIFICATION_LEVEL', 0.98, 1, flags=re.I),

    # --- FULL CLASSIFICATION MARKINGS ---
    _p(r'\b((?:TOP\s*SECRET|SECRET)//SCI)\b', 'CLASSIFICATION_MARKING', 0.99, 1, flags=re.I),
    _p(r'\b((?:TOP\s*SECRET|SECRET)(?://[A-Z]{2,})+(?://[A-Z\s]+)?)\b',
       'CLASSIFICATION_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b((?:TOP\s*SECRET|SECRET|CONFIDENTIAL)//(?:NOFORN|NF))\b',
       'CLASSIFICATION_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b((?:TOP\s*SECRET|SECRET|CONFIDENTIAL)//REL\s+TO\s+[A-Z,\s]+)\b',
       'CLASSIFICATION_MARKING', 0.98, 1, flags=re.I),
    _p(r'\(([TCS]S?(?://[A-Z/]+)?)\)', 'CLASSIFICATION_MARKING', 0.92, 1),
    _p(r'\((TS//SCI(?:/[A-Z]+)*)\)', 'CLASSIFICATION_MARKING', 0.98, 1),

    # --- SCI MARKERS ---
    _p(r'\b(//SI)\b', 'SCI_MARKING', 0.98, 1),
    _p(r'\b(//TK)\b', 'SCI_MARKING', 0.98, 1),
    _p(r'\b(//HCS)\b', 'SCI_MARKING', 0.98, 1),
    _p(r'\b(//COMINT)\b', 'SCI_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(//SIGINT)\b', 'SCI_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(//HUMINT)\b', 'SCI_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(//IMINT)\b', 'SCI_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(//GEOINT)\b', 'SCI_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(//MASINT)\b', 'SCI_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(SPECIAL\s+ACCESS\s+(?:PROGRAM|REQUIRED))\b', 'SCI_MARKING', 0.98, 1, flags=re.I),

    # --- DISSEMINATION CONTROLS ---
    _p(r'\b(//NOFORN)\b', 'DISSEMINATION_CONTROL', 0.99, 1, flags=re.I),
    _p(r'\b(NOFORN|NF)\b(?=.*(?://|secret|classified|rel|dissem))',
       'DISSEMINATION_CONTROL', 0.95, 1, flags=re.I),
    _p(r'\b(REL\s+(?:TO\s+)?(?:USA|FVEY|[A-Z]{3}(?:\s*,\s*[A-Z]{3})*))\b',
       'DISSEMINATION_CONTROL', 0.95, 1, flags=re.I),
    _p(r'\b(//REL\s+TO\s+[A-Z,\s]+)\b', 'DISSEMINATION_CONTROL', 0.98, 1, flags=re.I),
    _p(r'\b(FVEY|FIVE\s+EYES)\b', 'DISSEMINATION_CONTROL', 0.95, 1, flags=re.I),
    _p(r'\b(ORCON)\b', 'DISSEMINATION_CONTROL', 0.98, 1),
    _p(r'\b(IMCON)\b', 'DISSEMINATION_CONTROL', 0.98, 1),
    _p(r'\b(PROPIN)\b', 'DISSEMINATION_CONTROL', 0.98, 1),
    _p(r'\b(FOUO)\b', 'DISSEMINATION_CONTROL', 0.95, 1),
    _p(r'\b(LAW\s+ENFORCEMENT\s+SENSITIVE)\b', 'DISSEMINATION_CONTROL', 0.98, 1, flags=re.I),

    # --- GOVERNMENT ENTITY CODES ---
    _p(r'(?:CAGE|cage)[:\s#]+([A-Z0-9]{5})\b', 'CAGE_CODE', 0.98, 1, flags=re.I),
    _p(r'(?:DUNS|D-U-N-S)[:\s#]+(\d{9})\b', 'DUNS_NUMBER', 0.98, 1, flags=re.I),
    _p(r'(?:DUNS|D-U-N-S)[:\s#]+(\d{2}-\d{3}-\d{4})\b', 'DUNS_NUMBER', 0.98, 1, flags=re.I),
    _p(r'(?:UEI|Unique\s+Entity\s+(?:ID|Identifier))[:\s#]+([A-Z0-9]{12})\b', 'UEI', 0.98, 1, flags=re.I),
    _p(r'(?:SAM|SAM\.gov)[:\s]+(?:registration|ID|#)[:\s]*([A-Z0-9]{12})\b', 'UEI', 0.95, 1, flags=re.I),

    # --- DOD CONTRACT NUMBERS ---
    _p(rf'\b({_DOD_PREFIX}\d{{4,5}}-\d{{2}}-[CDGM]-\d{{4}})\b', 'DOD_CONTRACT', 0.98, 1, flags=re.I),
    _p(rf'\b({_DOD_PREFIX}\d{{4,5}}-\d{{2}}-[CDGM]-\d{{4}}-[PM]\d{{3,5}})\b', 'DOD_CONTRACT', 0.98, 1, flags=re.I),
    _p(r'\b([A-Z]{1,6}\d{4,5}-\d{2}-[CDGM]-\d{4})\b', 'DOD_CONTRACT', 0.90, 1),
    _p(r'(?:Contract|Contract\s+(?:No|Number|#))[:\s]+(?!47[A-Z]{2})([A-Z0-9\-]{10,25})\b', 'DOD_CONTRACT', 0.85, 1, flags=re.I),

    # --- GSA CONTRACT NUMBERS ---
    _p(r'\b(GS-\d{2}[A-Z]-\d{4}[A-Z]?)\b', 'GSA_CONTRACT', 0.98, 1),
    _p(r'\b(GS-\d{3}-\d{4}[A-Z]?)\b', 'GSA_CONTRACT', 0.98, 1),
    _p(r'\b(47[A-Z]{2}[A-Z0-9]{2}\d{2}[A-Z]\d{4})\b', 'GSA_CONTRACT', 0.95, 1),
    _p(r'(?:GSA\s+(?:Schedule|Contract)|Schedule\s+Contract)[:\s#]+([A-Z0-9\-]{8,20})\b',
       'GSA_CONTRACT', 0.92, 1, flags=re.I),

    # --- SECURITY CLEARANCE ---
    _p(r'\b(TS/SCI)\b', 'CLEARANCE_LEVEL', 0.98, 1),
    _p(r'\b(TOP\s*SECRET\s+(?:SCI\s+)?CLEARANCE)\b', 'CLEARANCE_LEVEL', 0.98, 1, flags=re.I),
    _p(r'\b(SECRET\s+CLEARANCE)\b', 'CLEARANCE_LEVEL', 0.95, 1, flags=re.I),
    _p(r'\b((?:ACTIVE\s+)?(?:TS|TOP\s*SECRET|SECRET|CONFIDENTIAL)\s+(?:SECURITY\s+)?CLEARANCE)\b',
       'CLEARANCE_LEVEL', 0.95, 1, flags=re.I),
    _p(r'\b(Q\s+CLEARANCE)\b', 'CLEARANCE_LEVEL', 0.98, 1, flags=re.I),
    _p(r'\b(L\s+CLEARANCE)\b', 'CLEARANCE_LEVEL', 0.98, 1, flags=re.I),
    _p(r'\b(YANKEE\s+WHITE)\b', 'CLEARANCE_LEVEL', 0.98, 1, flags=re.I),

    # --- EXPORT CONTROL (ITAR/EAR) ---
    _p(r'\b(ITAR\s+(?:CONTROLLED|RESTRICTED|DATA|INFORMATION))\b', 'ITAR_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(USML\s+CATEGORY\s+[IVXLCDM]+)\b', 'ITAR_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(22\s*CFR\s*1[2-9][0-9])\b', 'ITAR_MARKING', 0.95, 1, flags=re.I),
    _p(r'\b(EAR\s+(?:CONTROLLED|99|DATA))\b', 'EAR_MARKING', 0.95, 1, flags=re.I),
    _p(r'\b(ECCN[:\s]+[0-9][A-Z][0-9]{3})\b', 'EAR_MARKING', 0.98, 1, flags=re.I),
    _p(r'\b(15\s*CFR\s*7[3-9][0-9])\b', 'EAR_MARKING', 0.95, 1, flags=re.I),
    _p(r'\b(EXPORT\s+(?:CONTROLLED|RESTRICTED))\b', 'EAR_MARKING', 0.88, 1, flags=re.I),

    # --- SENSITIVE BUT UNCLASSIFIED ---
    _p(r'\b(SENSITIVE\s+BUT\s+UNCLASSIFIED)\b', 'CLASSIFICATION_LEVEL', 0.98, 1, flags=re.I),
    _p(r'\b(LIMITED\s+OFFICIAL\s+USE)\b', 'CLASSIFICATION_LEVEL', 0.98, 1, flags=re.I),
    _p(r'\b(OFFICIAL\s+USE\s+ONLY)\b', 'CLASSIFICATION_LEVEL', 0.95, 1, flags=re.I),
)


@register_detector
class GovernmentDetector(BaseDetector):
    """
    Detects government classification markings and identifiers.

    Catches security classification levels, SCI compartments,
    dissemination controls, contract numbers, and CAGE codes.
    """

    name = "government"
    tier = Tier.PATTERN

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        seen: set[tuple[int, int]] = set()

        for pdef in GOVERNMENT_PATTERNS:
            for match in pdef.pattern.finditer(text):
                if pdef.group > 0 and match.lastindex and pdef.group <= match.lastindex:
                    value = match.group(pdef.group)
                    start = match.start(pdef.group)
                    end = match.end(pdef.group)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                if not value or not value.strip():
                    continue

                key = (start, end)
                if key in seen:
                    continue
                seen.add(key)

                if pdef.entity_type == 'CLASSIFICATION_LEVEL':
                    if self._is_false_positive_classification(value, text, start):
                        continue

                spans.append(Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=pdef.entity_type,
                    confidence=pdef.confidence,
                    detector=self.name,
                    tier=self.tier,
                ))

        return spans

    def _is_false_positive_classification(self, value: str, text: str, start: int) -> bool:
        """Filter false positives for classification words."""
        value_lower = value.lower()

        if 'secret' in value_lower and 'top' not in value_lower:
            context_start = max(0, start - 50)
            context_end = min(len(text), start + len(value) + 50)
            context = text[context_start:context_end].lower()

            classification_context = [
                '//', 'classified', 'clearance', 'noforn', 'sci', 'fouo',
                'dissem', 'caveat', 'portion', 'marking', 'unclassified',
                'secret//', '//secret'
            ]

            if not any(ctx in context for ctx in classification_context):
                return True

        return False

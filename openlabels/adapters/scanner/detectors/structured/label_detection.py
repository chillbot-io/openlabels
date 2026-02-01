"""
Label detection in structured documents.

Finds field labels (DOB:, NAME:, MRN:, etc.) in OCR text and maps them
to PHI types using the label taxonomy.
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from .label_taxonomy import LABEL_TO_PHI_TYPE, SORTED_LABELS, normalize_label

logger = logging.getLogger(__name__)


@dataclass
class DetectedLabel:
    """A field label found in text."""
    label: str  # Normalized label (uppercase, trimmed)
    label_start: int  # Position of label in text
    label_end: int  # Position after label (including colon/separator)
    phi_type: Optional[str]  # Mapped PHI type, or None if not PHI
    raw_label: str  # Original text of label


def detect_labels(text: str) -> List[DetectedLabel]:
    """
    Find field labels in text.

    Looks for patterns like:
    - LABEL: value (primary pattern)
    - 16 HGT: value (with numeric prefix from field codes)
    - LABEL value (only for longer, unambiguous labels)
    """
    labels = []

    # Pattern 1: Standard LABEL: format
    label_pattern = re.compile(
        r'\b([A-Z][A-Z0-9\s\'\-#]{0,30}?)\s*[:\-]\s*(?=\S)',
        re.IGNORECASE
    )

    for match in label_pattern.finditer(text):
        raw_label = match.group(1).strip()

        # Try to find the longest matching label in taxonomy
        best_label = None
        best_normalized = None

        words = raw_label.split()
        for i in range(len(words), 0, -1):
            candidate = ' '.join(words[-i:])  # Try last N words
            normalized = normalize_label(candidate)

            if normalized in LABEL_TO_PHI_TYPE:
                if best_label is None or len(normalized) > len(best_normalized):
                    best_label = candidate
                    best_normalized = normalized

        if best_normalized is None:
            continue

        # Skip document type labels and common false positives
        if best_normalized in (
            "DRIVER'S LICENSE", "DRIVER LICENSE", "LICENSE",
            "STREET", "USA", "STATE", "SAMPLE"
        ):
            continue

        phi_type = LABEL_TO_PHI_TYPE[best_normalized]

        # Calculate where this specific label starts
        if best_label == raw_label:
            label_start = match.start()
        else:
            idx = raw_label.upper().find(best_label.upper())
            if idx >= 0:
                label_start = match.start() + idx
            else:
                label_start = match.start()

        labels.append(DetectedLabel(
            label=best_normalized,
            label_start=label_start,
            label_end=match.end(),
            phi_type=phi_type,
            raw_label=best_label,
        ))

    # Pattern 2: Field code + LABEL: format (common on ID documents)
    field_code_pattern = re.compile(
        r'\b\d+[a-z]?\s+([A-Z]{2,})\s*[:\-]\s*(?=\S)',
        re.IGNORECASE
    )

    for match in field_code_pattern.finditer(text):
        raw_label = match.group(1).strip()
        normalized = normalize_label(raw_label)

        if normalized in LABEL_TO_PHI_TYPE:
            # Check we didn't already capture this
            already_found = any(
                abs(l.label_start - match.start()) < 5
                for l in labels
            )
            if already_found:
                continue

            phi_type = LABEL_TO_PHI_TYPE[normalized]
            labels.append(DetectedLabel(
                label=normalized,
                label_start=match.start(1),
                label_end=match.end(),
                phi_type=phi_type,
                raw_label=raw_label,
            ))

    # Pattern 3: Labels without colons (contextual)
    # Only for longer, unambiguous labels
    COLON_REQUIRED_LABELS = {
        "DL", "ID", "NO", "SS", "DD", "PH", "FN", "LN", "HT", "WT",
        "GRP", "BIN", "PCN", "NPI", "DEA", "DOC", "REF", "MRN", "RX",
        "HOSPITAL", "CLINIC", "MEDICAL", "CENTER", "HEALTH",
        "PATIENT", "DOCTOR", "DR", "PHYSICIAN", "PROVIDER", "NURSE",
        "MEMBER", "SUBSCRIBER", "EMPLOYER", "GUARDIAN", "PARENT", "SPOUSE",
    }

    for known_label in SORTED_LABELS:
        if len(known_label) < 3:
            continue

        if known_label in COLON_REQUIRED_LABELS:
            continue

        if known_label in ("DRIVER'S LICENSE", "DRIVER LICENSE", "LICENSE"):
            continue

        # Only match if followed by what looks like a value
        pattern = re.compile(
            rf'\b({re.escape(known_label)})\s+(?=[A-Z][a-z]|[0-9])',
            re.IGNORECASE
        )

        for match in pattern.finditer(text):
            # Check we didn't already capture this
            already_found = any(
                l.label_start <= match.start() < l.label_end
                for l in labels
            )
            if already_found:
                continue

            # Don't match if part of a longer phrase
            before_start = max(0, match.start() - 15)
            context_before = text[before_start:match.start()]
            if re.search(r"(DRIVER'?S?|DRIVING)\s*$", context_before, re.I):
                continue

            raw_label = match.group(1).strip()
            normalized = normalize_label(raw_label)
            phi_type = LABEL_TO_PHI_TYPE.get(normalized)

            labels.append(DetectedLabel(
                label=normalized,
                label_start=match.start(),
                label_end=match.end(),
                phi_type=phi_type,
                raw_label=raw_label,
            ))

    # Sort by position
    labels.sort(key=lambda l: l.label_start)

    # Deduplicate - keep first occurrence at each position
    seen_positions = set()
    unique_labels = []
    for label in labels:
        if label.label_start not in seen_positions:
            seen_positions.add(label.label_start)
            unique_labels.append(label)

    if unique_labels:
        phi_labels = [l for l in unique_labels if l.phi_type]
        logger.debug(f"Detected {len(unique_labels)} labels, {len(phi_labels)} mapped to PHI types")

    return unique_labels

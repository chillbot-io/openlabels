"""
OCR post-processing and position mapping.

Applies fixes for common OCR errors (concatenated text, missing spaces)
while maintaining character-level position mapping back to original text.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class OCRFix:
    """A regex-based OCR correction rule."""
    pattern: re.Pattern
    replacement: str
    description: str


# OCR fixes applied in order - ORDER MATTERS
# NOTE: "Collapse multiple spaces" was REMOVED because it changes text length
# and breaks position mapping when other detectors run on the processed text.
OCR_FIXES: List[OCRFix] = [
    # -------------------------------------------------------------------------
    # PRIORITY FIXES - Run these first to preserve specific patterns
    # -------------------------------------------------------------------------

    # Normalize driver's license number format (4dDLN:99 → DLN: 99)
    OCRFix(
        re.compile(r'\b\d+[a-z]?DLN[:\-]\s*(\S+)', re.I),
        r'DLN: \1',
        "Normalize driver's license number (4dDLN:99 → DLN: 99)"
    ),

    # -------------------------------------------------------------------------
    # Re-space concatenated addresses
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(
            r'(\d{1,5})([A-Z]{2,})(STREET|ST|AVENUE|AVE|ROAD|RD|DRIVE|DR|LANE|LN|'
            r'BLVD|BOULEVARD|WAY|COURT|CT|CIRCLE|CIR|PLACE|PL|TERRACE|TER|TRAIL|'
            r'TRL|PIKE|HWY|HIGHWAY)\b',
            re.I
        ),
        r'\1 \2 \3',
        "Split concatenated street addresses (8123MAINSTREET → 8123 MAIN STREET)"
    ),

    # -------------------------------------------------------------------------
    # Fix CITY,STZIP format
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b([A-Z][A-Za-z]{2,}),([A-Z]{2})(\d{5}(?:-?\d{4})?)\b'),
        r'\1, \2 \3',
        "Split CITY,STZIP (HARRISBURG,PA17101 → HARRISBURG, PA 17101)"
    ),

    # -------------------------------------------------------------------------
    # Split field codes like 4aISS: → 4a ISS:
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d+[a-z])((?:ISS|EXP|DOB|SEX|HGT|WGT|EYES|END|RESTR)):'),
        r'\1 \2:',
        "Split field codes (4aISS: → 4a ISS:)"
    ),

    # -------------------------------------------------------------------------
    # Split stuck numeric prefix + label (18EYES:BRO → 18 EYES: BRO)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d{1,2})(EYES|HGT|SEX|WGT|CLASS|RESTR|END):(\S+)'),
        r'\1 \2: \3',
        "Split numeric prefix from label (18EYES:BRO → 18 EYES: BRO)"
    ),

    # -------------------------------------------------------------------------
    # Split stuck label:value with no space (DOB:01/01/2000 → DOB: 01/01/2000)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(DOB|EXP|ISS|DLN|SSN|MRN|ID|DD):(\d)'),
        r'\1: \2',
        "Add space after label colon (DOB:01 → DOB: 01)"
    ),

    # -------------------------------------------------------------------------
    # Fix common OCR character substitutions
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\bD0B\b'),
        'DOB',
        "Fix zero-for-O in DOB"
    ),

    # -------------------------------------------------------------------------
    # Split stuck document discriminator (5DD:123 → 5 DD: 123)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d)DD:(\d+)'),
        r'\1 DD: \2',
        "Split document discriminator (5DD:123 → 5 DD: 123)"
    ),

    # -------------------------------------------------------------------------
    # Split single digit field code + ALL CAPS name (ID cards)
    # -------------------------------------------------------------------------
    OCRFix(
        re.compile(r'\b(\d)([A-Z]{2,})\b'),
        r'\1 \2',
        "Split field code from name (2ANDREW → 2 ANDREW)"
    ),
]


def post_process_ocr(text: str) -> Tuple[str, List[int]]:
    """
    Apply OCR post-processing fixes with position tracking.

    Returns:
        Tuple of (fixed_text, char_map) where char_map[i] gives the position
        in original text that corresponds to position i in fixed_text.
    """
    result = text

    # Apply all fixes
    for fix in OCR_FIXES:
        result = fix.pattern.sub(fix.replacement, result)

    # Build character-level mapping from processed -> original
    char_map = _build_char_map(text, result)

    return result, char_map


def _build_char_map(original: str, processed: str) -> List[int]:
    """
    Build a character-level map from processed positions to original positions.

    Uses a greedy alignment approach that handles insertions, deletions,
    and substitutions.

    Returns:
        List where char_map[processed_pos] = original_pos
    """
    if original == processed:
        return list(range(len(processed)))

    char_map = []
    orig_pos = 0
    proc_pos = 0

    while proc_pos < len(processed):
        if orig_pos < len(original) and processed[proc_pos] == original[orig_pos]:
            # Characters match - direct mapping
            char_map.append(orig_pos)
            orig_pos += 1
            proc_pos += 1
        elif orig_pos < len(original) and processed[proc_pos] == ' ':
            # Space in processed might be an insertion
            if (proc_pos + 1 < len(processed) and
                processed[proc_pos + 1] == original[orig_pos]):
                # This space was inserted - map it to current original position
                char_map.append(orig_pos)
                proc_pos += 1
            else:
                # Space exists in both or is a replacement
                char_map.append(orig_pos)
                orig_pos += 1
                proc_pos += 1
        elif orig_pos < len(original):
            # Characters don't match - try to find where they sync up
            lookahead = original[orig_pos:orig_pos+10]
            if processed[proc_pos] in lookahead:
                # Skip chars in original until we match
                skip = lookahead.index(processed[proc_pos])
                orig_pos += skip
                char_map.append(orig_pos)
                orig_pos += 1
                proc_pos += 1
            else:
                # No match found - this char was inserted in processed
                char_map.append(orig_pos)
                proc_pos += 1
        else:
            # Ran out of original text - map remaining to end
            char_map.append(len(original) - 1)
            proc_pos += 1

    return char_map


def map_processed_to_original(
    processed_pos: int,
    char_map: List[int],
    strict: bool = False
) -> int:
    """
    Map a position in processed text back to position in original text.

    Args:
        processed_pos: Position in processed (post-OCR-fix) text
        char_map: Character map from post_process_ocr
        strict: If True, raise ValueError for out-of-bounds positions

    Returns:
        Corresponding position in original text

    Raises:
        ValueError: If strict=True and position is out of bounds
    """
    if not char_map:
        return processed_pos

    if processed_pos < 0:
        if strict:
            raise ValueError(f"Position {processed_pos} is negative")
        return 0

    if processed_pos >= len(char_map):
        if strict:
            raise ValueError(
                f"Position {processed_pos} exceeds char_map length {len(char_map)}"
            )
        # Beyond end of map - return last mapped position + offset
        if char_map:
            return char_map[-1] + (processed_pos - len(char_map) + 1)
        return processed_pos

    return char_map[processed_pos]


def map_span_to_original(
    span_start: int,
    span_end: int,
    span_text: str,
    char_map: List[int],
    original_text: str
) -> Tuple[int, int]:
    """
    Map a span from processed text coordinates to original text coordinates.

    Args:
        span_start: Start position in processed text
        span_end: End position in processed text
        span_text: The text content of the span
        char_map: Character map from post_process_ocr
        original_text: The original (pre-OCR-fix) text

    Returns:
        Tuple of (original_start, original_end)

    Raises:
        ValueError: If span positions are out of bounds for the char_map
    """
    if not char_map:
        return span_start, span_end

    # Validate span positions are within char_map bounds
    if span_start < 0 or span_start >= len(char_map):
        raise ValueError(
            f"span_start {span_start} out of bounds for char_map "
            f"of length {len(char_map)}"
        )
    if span_end < 0 or span_end > len(char_map):
        raise ValueError(
            f"span_end {span_end} out of bounds for char_map "
            f"of length {len(char_map)}"
        )

    # Map start and end positions
    orig_start = map_processed_to_original(span_start, char_map)

    # For end position, we want the position AFTER the last character
    if span_end > 0:
        orig_end = map_processed_to_original(span_end - 1, char_map) + 1
    else:
        orig_end = orig_start

    # Ensure bounds are valid
    orig_start = max(0, min(orig_start, len(original_text)))
    orig_end = max(orig_start, min(orig_end, len(original_text)))

    # Verify the mapping by checking if original text matches span_text
    orig_text_at_pos = original_text[orig_start:orig_end]

    # If texts don't match well, try to find span_text in original nearby
    if not _texts_similar(orig_text_at_pos, span_text):
        search_start = max(0, orig_start - 20)
        search_end = min(len(original_text), orig_end + 20)

        # Try to find exact match first
        pos = original_text.find(span_text, search_start)
        if pos >= 0 and pos < search_end:
            return pos, pos + len(span_text)

        # Try to find compacted version (without spaces added by OCR fixes)
        compact = span_text.replace(' ', '')
        for i in range(search_start, min(search_end, len(original_text) - len(compact) + 1)):
            if original_text[i:].replace(' ', '').startswith(compact):
                # Found it - find the actual end position
                chars_needed = len(compact)
                end_pos = i
                while chars_needed > 0 and end_pos < len(original_text):
                    if original_text[end_pos] != ' ':
                        chars_needed -= 1
                    end_pos += 1
                return i, end_pos

    return orig_start, orig_end


def _texts_similar(text1: str, text2: str) -> bool:
    """Check if two texts are similar (ignoring spacing differences)."""
    return text1.replace(' ', '').upper() == text2.replace(' ', '').upper()

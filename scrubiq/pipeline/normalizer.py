"""Text normalization for consistent span positioning."""

import re
import unicodedata

# Zero-width and control characters to strip
ZERO_WIDTH = frozenset([
    '\x00',    # Null byte - can be used to evade detection
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u2060',  # Word joiner
    '\ufeff',  # Zero-width no-break space (BOM)
    '\u180e',  # Mongolian vowel separator
])

# E3: Bidirectional override characters - can be used for visual spoofing
# These change text direction without visible indication
BIDI_CONTROLS = frozenset([
    '\u200e',  # Left-to-right mark
    '\u200f',  # Right-to-left mark
    '\u202a',  # Left-to-right embedding
    '\u202b',  # Right-to-left embedding
    '\u202c',  # Pop directional formatting
    '\u202d',  # Left-to-right override
    '\u202e',  # Right-to-left override (DANGEROUS - reverses text visually)
    '\u2066',  # Left-to-right isolate
    '\u2067',  # Right-to-left isolate
    '\u2068',  # First strong isolate
    '\u2069',  # Pop directional isolate
])

# Other potentially dangerous control characters
CONTROL_CHARS = frozenset([
    '\u0000',  # Null (also in ZERO_WIDTH)
    '\u0008',  # Backspace
    '\u007f',  # Delete
    '\u0085',  # Next line
    '\u00ad',  # Soft hyphen (invisible)
    '\u2028',  # Line separator
    '\u2029',  # Paragraph separator
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
    '\ufff9',  # Interlinear annotation anchor
    '\ufffa',  # Interlinear annotation separator
    '\ufffb',  # Interlinear annotation terminator
])

# Combined set of all characters to strip
CHARS_TO_STRIP = ZERO_WIDTH | BIDI_CONTROLS | CONTROL_CHARS

# Common homoglyph mappings (Cyrillic/Greek → Latin)
# Only the most common lookalikes that could be used for evasion
HOMOGLYPHS = {
    # Cyrillic uppercase → Latin
    '\u0408': 'J',  # Ј (Cyrillic Je)
    '\u0406': 'I',  # І (Cyrillic Byelorussian-Ukrainian I)
    '\u0405': 'S',  # Ѕ (Cyrillic Dze)
    '\u0404': 'E',  # Є (Cyrillic Ukrainian Ie)
    # Cyrillic → Latin
    '\u0410': 'A',  # А
    '\u0412': 'B',  # В
    '\u0415': 'E',  # Е
    '\u041a': 'K',  # К
    '\u041c': 'M',  # М
    '\u041d': 'H',  # Н
    '\u041e': 'O',  # О
    '\u0420': 'P',  # Р
    '\u0421': 'C',  # С
    '\u0422': 'T',  # Т
    '\u0425': 'X',  # Х
    '\u0430': 'a',  # а
    '\u0435': 'e',  # е
    '\u0438': 'i',  # и (Cyrillic i)
    '\u0456': 'i',  # і (Ukrainian i)
    '\u043e': 'o',  # о
    '\u0440': 'p',  # р
    '\u0441': 'c',  # с
    '\u0443': 'y',  # у
    '\u0445': 'x',  # х
    '\u0455': 's',  # ѕ (Cyrillic s)
    '\u0458': 'j',  # ј (Cyrillic j)
    # Greek → Latin
    '\u0391': 'A',  # Α
    '\u0392': 'B',  # Β
    '\u0395': 'E',  # Ε
    '\u0396': 'Z',  # Ζ
    '\u0397': 'H',  # Η
    '\u0399': 'I',  # Ι
    '\u039a': 'K',  # Κ
    '\u039c': 'M',  # Μ
    '\u039d': 'N',  # Ν
    '\u039f': 'O',  # Ο
    '\u03a1': 'P',  # Ρ
    '\u03a4': 'T',  # Τ
    '\u03a5': 'Y',  # Υ
    '\u03a7': 'X',  # Χ
    '\u03b1': 'a',  # α (debatable)
    '\u03bf': 'o',  # ο
    '\u03b9': 'i',  # ι
    # Common substitutions
    '\u0131': 'i',  # Turkish dotless i
    '\u0251': 'a',  # Latin alpha
    '\u0261': 'g',  # Script g
    '\u01c3': '!',  # ǃ (click)
    # Fullwidth → ASCII
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},  # ！→! through ～→~
}

# Build homoglyph translation table
_HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS)


def strip_zero_width(text: str) -> str:
    """Remove zero-width characters."""
    return ''.join(c for c in text if c not in ZERO_WIDTH)


def strip_control_chars(text: str) -> str:
    """Remove zero-width, bidi overrides, and control characters."""
    return ''.join(c for c in text if c not in CHARS_TO_STRIP)


def normalize_homoglyphs(text: str) -> str:
    """Replace homoglyphs with ASCII equivalents."""
    return text.translate(_HOMOGLYPH_TABLE)


def normalize_text(
    text: str, 
    strip_zwc: bool = True, 
    fix_homoglyphs: bool = True,
    strip_bidi: bool = True,
    fix_ocr: bool = True,
) -> str:
    """
    Normalize text for consistent span positioning.
    
    Steps:
    1. Handle None/empty (E1 FIX: explicit None check)
    2. NFKC normalization (canonical decomposition + compatibility composition)
    3. Strip control characters including RTL overrides (E3 FIX)
    4. Normalize homoglyphs (optional)
    5. Fix OCR character substitutions in numeric contexts (optional)
    
    Args:
        text: Input text (None returns empty string)
        strip_zwc: Remove zero-width characters
        fix_homoglyphs: Replace lookalike characters with ASCII
        strip_bidi: Remove bidirectional override characters (security)
        fix_ocr: Normalize OCR errors in numeric patterns (SSN, phone, etc.)
    
    Returns:
        Normalized text
    """
    # Explicit None handling
    if text is None:
        return ""
    
    if not text:
        return text

    # NFKC normalization
    # - Decomposes characters, then recomposes with compatibility equivalents
    # - e.g., ﬁ → fi, ² → 2, ℃ → °C
    text = unicodedata.normalize('NFKC', text)

    # Strip control chars including RTL overrides (security-critical)
    # Do this BEFORE other processing to prevent evasion
    if strip_bidi:
        text = strip_control_chars(text)
    elif strip_zwc:
        # Legacy mode: only strip zero-width
        text = strip_zero_width(text)

    # Normalize homoglyphs
    if fix_homoglyphs:
        text = normalize_homoglyphs(text)
    
    # Fix OCR character substitutions in numeric contexts
    # e.g., "SSN: l23-45-67B9" → "SSN: 123-45-6789"
    if fix_ocr:
        text = normalize_ocr_numerics(text)

    return text


def is_binary(data: bytes, sample_size: int = 8192) -> bool:
    """
    Check if data appears to be binary (not text).
    
    Uses null byte detection and high-bit character ratio.
    """
    sample = data[:sample_size]
    
    if not sample:
        return False

    # Null bytes are strong indicator of binary
    if b'\x00' in sample:
        return True

    # High ratio of non-printable characters suggests binary
    try:
        text = sample.decode('utf-8', errors='ignore')
        
        # If most bytes were ignored (invalid UTF-8), it's likely binary
        # e.g., bytes([0x80, 0x81, ...]) are all invalid UTF-8
        if len(text) < len(sample) * 0.5:
            return True
        
        if len(text) > 0:
            non_printable = sum(1 for c in text if not c.isprintable() and c not in '\n\r\t')
            if non_printable / len(text) > 0.3:
                return True
    except (UnicodeDecodeError, TypeError):
        return True

    return False


def safe_decode(data: bytes) -> str:
    """
    Decode bytes to string, replacing invalid sequences with U+FFFD.
    """
    return data.decode('utf-8', errors='replace')


# OCR Character Normalization
# Common substitutions from scanned documents where characters are misread
# Applied ONLY in numeric/alphanumeric contexts to avoid false positives

# Pattern to find sequences that look like they should be numeric
# (e.g., SSN-like, phone-like, date-like patterns with OCR errors)
_OCR_NUMERIC_PATTERN = re.compile(
    r'''
    (?:
        # SSN-like: 3-2-4 digits with possible OCR errors
        [0-9lIOS]{3}[-.\s][0-9lIOS]{2}[-.\s][0-9lIOS]{4}
        |
        # Phone-like: area code + 3 + 4 digits
        \(?[0-9lIOSB]{3}\)?[-.\s]?[0-9lIOSB]{3}[-.\s]?[0-9lIOSB]{4}
        |
        # Date-like: MM/DD/YYYY or similar with OCR errors
        [0-9lIOSB]{1,2}[/.-][0-9lIOSB]{1,2}[/.-][0-9lIOSB]{2,4}
        |
        # MRN/ID-like: 6+ digit sequences
        [0-9lIOSB]{6,}
        |
        # ZIP-like: 5 or 9 digits
        [0-9lIOSB]{5}(?:[-][0-9lIOSB]{4})?
    )
    ''',
    re.VERBOSE
)

# OCR character mappings (visually similar chars → digits)
_OCR_CHAR_MAP = str.maketrans({
    'l': '1',  # lowercase L → 1
    'I': '1',  # uppercase I → 1
    'O': '0',  # uppercase O → 0
    'o': '0',  # lowercase o → 0 (in numeric context)
    'S': '5',  # uppercase S → 5
    's': '5',  # lowercase s → 5
    'B': '8',  # uppercase B → 8
    'G': '6',  # uppercase G → 6 (sometimes)
    'Z': '2',  # uppercase Z → 2 (sometimes)
    'z': '2',  # lowercase z → 2
})


def normalize_ocr_numerics(text: str) -> str:
    """
    Normalize common OCR character substitutions in numeric-looking sequences.
    
    Only applies substitutions within patterns that appear to be:
    - SSNs (###-##-####)
    - Phone numbers
    - Dates (MM/DD/YYYY)
    - MRNs/IDs (6+ digits)
    - ZIP codes
    
    This targeted approach avoids false positives from replacing letters
    in normal words (e.g., "slide" → "s1ide").
    
    Args:
        text: Input text, possibly with OCR errors
        
    Returns:
        Text with OCR errors corrected in numeric contexts
    """
    if not text:
        return text
    
    def fix_match(match: re.Match) -> str:
        """Replace OCR chars with digits in matched sequence."""
        return match.group(0).translate(_OCR_CHAR_MAP)
    
    return _OCR_NUMERIC_PATTERN.sub(fix_match, text)

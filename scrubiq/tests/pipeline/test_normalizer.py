"""Tests for text normalization in normalizer.py.

Tests zero-width character stripping, homoglyph normalization,
bidi override removal, OCR error correction, and binary detection.
"""

import pytest
from scrubiq.pipeline.normalizer import (
    strip_zero_width,
    strip_control_chars,
    normalize_homoglyphs,
    normalize_text,
    normalize_ocr_numerics,
    is_binary,
    safe_decode,
    ZERO_WIDTH,
    BIDI_CONTROLS,
    CONTROL_CHARS,
    CHARS_TO_STRIP,
    HOMOGLYPHS,
)


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Tests for normalizer constants."""

    def test_zero_width_contains_common_invisible(self):
        """ZERO_WIDTH contains common invisible characters."""
        assert '\u200b' in ZERO_WIDTH  # Zero-width space
        assert '\ufeff' in ZERO_WIDTH  # BOM
        assert '\u200d' in ZERO_WIDTH  # Zero-width joiner

    def test_bidi_controls_contains_overrides(self):
        """BIDI_CONTROLS contains direction override characters."""
        assert '\u202e' in BIDI_CONTROLS  # Right-to-left override
        assert '\u200e' in BIDI_CONTROLS  # Left-to-right mark
        assert '\u200f' in BIDI_CONTROLS  # Right-to-left mark

    def test_control_chars_contains_dangerous(self):
        """CONTROL_CHARS contains dangerous control characters."""
        assert '\x00' in CONTROL_CHARS  # Null
        assert '\x08' in CONTROL_CHARS  # Backspace
        assert '\x7f' in CONTROL_CHARS  # Delete

    def test_chars_to_strip_is_union(self):
        """CHARS_TO_STRIP is union of all character sets."""
        assert CHARS_TO_STRIP == ZERO_WIDTH | BIDI_CONTROLS | CONTROL_CHARS

    def test_homoglyphs_contains_cyrillic(self):
        """HOMOGLYPHS contains Cyrillic lookalikes."""
        assert '\u0410' in HOMOGLYPHS  # Cyrillic A → A
        assert '\u0430' in HOMOGLYPHS  # Cyrillic a → a
        assert '\u041e' in HOMOGLYPHS  # Cyrillic O → O

    def test_homoglyphs_contains_greek(self):
        """HOMOGLYPHS contains Greek lookalikes."""
        assert '\u0391' in HOMOGLYPHS  # Greek A → A
        assert '\u039f' in HOMOGLYPHS  # Greek O → O


# =============================================================================
# STRIP ZERO WIDTH TESTS
# =============================================================================

class TestStripZeroWidth:
    """Tests for strip_zero_width()."""

    def test_removes_zero_width_space(self):
        """Zero-width space is removed."""
        text = "John\u200bSmith"  # Zero-width space between words
        result = strip_zero_width(text)
        assert result == "JohnSmith"

    def test_removes_bom(self):
        """BOM character is removed."""
        text = "\ufeffHello"
        result = strip_zero_width(text)
        assert result == "Hello"

    def test_removes_zero_width_joiner(self):
        """Zero-width joiner is removed."""
        text = "test\u200dtext"
        result = strip_zero_width(text)
        assert result == "testtext"

    def test_preserves_normal_text(self):
        """Normal text is unchanged."""
        text = "John Smith"
        result = strip_zero_width(text)
        assert result == text

    def test_removes_multiple_zero_width(self):
        """Multiple zero-width characters are removed."""
        text = "\u200bJohn\u200c\u200dSmith\ufeff"
        result = strip_zero_width(text)
        assert result == "JohnSmith"


# =============================================================================
# STRIP CONTROL CHARS TESTS
# =============================================================================

class TestStripControlChars:
    """Tests for strip_control_chars()."""

    def test_removes_null_bytes(self):
        """Null bytes are removed."""
        text = "John\x00Smith"
        result = strip_control_chars(text)
        assert result == "JohnSmith"

    def test_removes_backspace(self):
        """Backspace characters are removed."""
        text = "test\x08text"
        result = strip_control_chars(text)
        assert result == "testtext"

    def test_removes_rtl_override(self):
        """Right-to-left override is removed (security)."""
        text = "SSN: \u202e9876-54-321"  # RTL override reverses display
        result = strip_control_chars(text)
        assert result == "SSN: 9876-54-321"
        assert '\u202e' not in result

    def test_removes_bidi_controls(self):
        """All bidi controls are removed."""
        text = "\u200eHello\u200f\u202aWorld\u202b"
        result = strip_control_chars(text)
        assert result == "HelloWorld"

    def test_preserves_newlines(self):
        """Newlines are preserved."""
        text = "Line1\nLine2\r\nLine3"
        result = strip_control_chars(text)
        assert result == text

    def test_preserves_tabs(self):
        """Tabs are preserved."""
        text = "Name:\tJohn Smith"
        result = strip_control_chars(text)
        assert result == text


# =============================================================================
# HOMOGLYPH NORMALIZATION TESTS
# =============================================================================

class TestNormalizeHomoglyphs:
    """Tests for normalize_homoglyphs()."""

    def test_normalizes_cyrillic_a(self):
        """Cyrillic A is normalized to Latin A."""
        text = "\u0410dam"  # Cyrillic А + dam
        result = normalize_homoglyphs(text)
        assert result == "Adam"

    def test_normalizes_cyrillic_lowercase(self):
        """Cyrillic lowercase is normalized."""
        text = "t\u0435st"  # Cyrillic е instead of e
        result = normalize_homoglyphs(text)
        assert result == "test"

    def test_normalizes_greek_o(self):
        """Greek O is normalized to Latin O."""
        text = "J\u039fhn"  # Greek Ο instead of O
        result = normalize_homoglyphs(text)
        assert result == "JOhn"

    def test_normalizes_mixed_homoglyphs(self):
        """Mixed homoglyphs are all normalized."""
        # Cyrillic А and е
        text = "\u0410l\u0435x"  # Cyrillic А + l + Cyrillic е + x
        result = normalize_homoglyphs(text)
        assert result == "Alex"

    def test_preserves_actual_latin(self):
        """Actual Latin characters are preserved."""
        text = "John Smith"
        result = normalize_homoglyphs(text)
        assert result == text

    def test_normalizes_fullwidth(self):
        """Fullwidth characters are normalized to ASCII."""
        text = "ＡＢＣ１２３"  # Fullwidth ABC123
        result = normalize_homoglyphs(text)
        assert result == "ABC123"


# =============================================================================
# NORMALIZE TEXT TESTS
# =============================================================================

class TestNormalizeText:
    """Tests for normalize_text() main function."""

    def test_handles_none(self):
        """None input returns empty string."""
        result = normalize_text(None)
        assert result == ""

    def test_handles_empty(self):
        """Empty string returns empty string."""
        result = normalize_text("")
        assert result == ""

    def test_nfkc_normalization(self):
        """NFKC normalization is applied."""
        text = "ﬁle"  # fi ligature
        result = normalize_text(text)
        assert result == "file"

    def test_combines_all_steps(self):
        """All normalization steps are combined."""
        # Zero-width + Cyrillic homoglyph + fullwidth
        text = "\u200bJ\u043ehn\ufeff Ｓmith"
        result = normalize_text(text)
        assert result == "John Smith"

    def test_strips_rtl_override_by_default(self):
        """RTL override is stripped by default (security)."""
        text = "\u202eevil\u202c"
        result = normalize_text(text)
        assert '\u202e' not in result
        assert '\u202c' not in result

    def test_can_disable_homoglyph_fix(self):
        """Homoglyph normalization can be disabled."""
        text = "\u0410dam"  # Cyrillic A
        result = normalize_text(text, fix_homoglyphs=False)
        assert result == "\u0410dam"  # Unchanged

    def test_can_disable_zwc_strip(self):
        """Zero-width stripping can be disabled."""
        # But bidi is still stripped by default
        text = "\u200btest"
        result = normalize_text(text, strip_zwc=False, strip_bidi=False)
        # NFKC doesn't remove zero-width space, but strip_bidi=True by default
        # With strip_bidi=False, only strip_zwc matters
        assert result == "\u200btest"

    def test_can_disable_bidi_strip(self):
        """Bidi stripping can be disabled (legacy mode)."""
        text = "\u200etest\u200f"
        result = normalize_text(text, strip_bidi=False)
        # With bidi disabled, only zero-width is stripped (if enabled)
        assert result == "\u200etest\u200f"

    def test_ocr_fix_enabled_by_default(self):
        """OCR normalization is enabled by default."""
        # Use characters from the SSN pattern class [0-9lIOS]
        text = "SSN: l23-4S-67O9"
        result = normalize_text(text)
        # l→1, S→5, O→0 in numeric context
        assert result == "SSN: 123-45-6709"

    def test_can_disable_ocr_fix(self):
        """OCR normalization can be disabled."""
        text = "SSN: l23-45-67B9"
        result = normalize_text(text, fix_ocr=False)
        assert result == "SSN: l23-45-67B9"


# =============================================================================
# OCR NUMERIC NORMALIZATION TESTS
# =============================================================================

class TestNormalizeOcrNumerics:
    """Tests for normalize_ocr_numerics()."""

    def test_handles_empty(self):
        """Empty string returns empty string."""
        result = normalize_ocr_numerics("")
        assert result == ""

    def test_handles_none_like(self):
        """Falsy input returns input."""
        result = normalize_ocr_numerics("")
        assert result == ""

    def test_fixes_ssn_with_l_as_1(self):
        """Lowercase L is corrected to 1 in SSN."""
        text = "SSN: l23-45-6789"
        result = normalize_ocr_numerics(text)
        assert result == "SSN: 123-45-6789"

    def test_fixes_ssn_with_O_as_0(self):
        """Uppercase O is corrected to 0 in SSN."""
        text = "SSN: 123-O5-6789"
        result = normalize_ocr_numerics(text)
        assert result == "SSN: 123-05-6789"

    def test_fixes_phone_number(self):
        """Phone number OCR errors are corrected."""
        text = "Phone: (5S5) 123-456B"
        result = normalize_ocr_numerics(text)
        assert result == "Phone: (555) 123-4568"

    def test_fixes_date(self):
        """Date OCR errors are corrected."""
        text = "DOB: Ol/l5/l990"
        result = normalize_ocr_numerics(text)
        assert result == "DOB: 01/15/1990"

    def test_fixes_mrn(self):
        """MRN OCR errors are corrected."""
        text = "MRN: l2345678"
        result = normalize_ocr_numerics(text)
        assert result == "MRN: 12345678"

    def test_fixes_zip_code(self):
        """ZIP code OCR errors are corrected."""
        text = "ZIP: l02O3"
        result = normalize_ocr_numerics(text)
        assert result == "ZIP: 10203"

    def test_preserves_normal_words(self):
        """Normal words are not modified."""
        text = "The patient said SLIDE was good"
        result = normalize_ocr_numerics(text)
        # "SLIDE" should not become "51IDE" because it's not in numeric context
        assert "SLIDE" in result

    def test_fixes_B_as_8(self):
        """B is corrected to 8 in numeric context."""
        text = "ID: 12345B78"
        result = normalize_ocr_numerics(text)
        assert result == "ID: 12345878"

    def test_fixes_S_as_5(self):
        """S is corrected to 5 in numeric context."""
        text = "Code: S12-34-S678"
        result = normalize_ocr_numerics(text)
        assert result == "Code: 512-34-5678"

    def test_multiple_corrections_in_text(self):
        """Multiple OCR errors in different patterns are all corrected."""
        text = "SSN: l23-45-6789, Phone: (555) l23-4567"
        result = normalize_ocr_numerics(text)
        assert result == "SSN: 123-45-6789, Phone: (555) 123-4567"


# =============================================================================
# BINARY DETECTION TESTS
# =============================================================================

class TestIsBinary:
    """Tests for is_binary()."""

    def test_detects_null_bytes(self):
        """Data with null bytes is detected as binary."""
        data = b"Hello\x00World"
        assert is_binary(data) is True

    def test_text_is_not_binary(self):
        """Normal text is not detected as binary."""
        data = b"Hello, World!"
        assert is_binary(data) is False

    def test_utf8_text_is_not_binary(self):
        """UTF-8 text with special chars is not binary."""
        data = "José García".encode('utf-8')
        assert is_binary(data) is False

    def test_empty_is_not_binary(self):
        """Empty data is not binary."""
        data = b""
        assert is_binary(data) is False

    def test_high_non_printable_ratio_is_binary(self):
        """High ratio of non-printable characters is binary."""
        # Create data that's mostly non-printable
        data = bytes(range(128, 200))  # High bytes
        assert is_binary(data) is True

    def test_invalid_utf8_is_binary(self):
        """Invalid UTF-8 sequences indicate binary."""
        # Invalid continuation byte
        data = b"\x80\x81\x82\x83" * 100
        assert is_binary(data) is True

    def test_uses_sample_size(self):
        """Only samples first N bytes."""
        # Null byte after sample size shouldn't be detected
        data = b"A" * 10000 + b"\x00"
        assert is_binary(data, sample_size=100) is False


# =============================================================================
# SAFE DECODE TESTS
# =============================================================================

class TestSafeDecode:
    """Tests for safe_decode()."""

    def test_decodes_valid_utf8(self):
        """Valid UTF-8 is decoded correctly."""
        data = "Hello, World!".encode('utf-8')
        result = safe_decode(data)
        assert result == "Hello, World!"

    def test_replaces_invalid_sequences(self):
        """Invalid UTF-8 sequences are replaced with U+FFFD."""
        data = b"Hello\x80World"  # 0x80 is invalid UTF-8 start
        result = safe_decode(data)
        assert "Hello" in result
        assert "World" in result
        assert '\ufffd' in result

    def test_handles_utf8_special_chars(self):
        """UTF-8 special characters are decoded correctly."""
        data = "Ñoño".encode('utf-8')
        result = safe_decode(data)
        assert result == "Ñoño"


# =============================================================================
# SECURITY TESTS
# =============================================================================

class TestSecurityNormalization:
    """Tests for security-critical normalization."""

    def test_rtl_override_attack_prevented(self):
        """RTL override attack is prevented.

        Attack: Display "123-45-6789" but actual bytes are reversed.
        """
        # "\u202e" reverses text direction - "9876-54-321" displays as "123-45-6789"
        malicious = "SSN: \u202e9876-54-321"
        result = normalize_text(malicious)
        # After stripping RTL override, we get actual order
        assert '\u202e' not in result
        assert "9876-54-321" in result

    def test_zero_width_evasion_prevented(self):
        """Zero-width character evasion is prevented.

        Attack: Insert invisible chars to evade pattern matching.
        """
        # "J\u200bohn" looks like "John" but doesn't match "John" regex
        evasion = "J\u200bohn S\u200cmith"
        result = normalize_text(evasion)
        assert result == "John Smith"

    def test_homoglyph_evasion_prevented(self):
        """Homoglyph evasion is prevented.

        Attack: Use Cyrillic 'а' instead of Latin 'a' to evade detection.
        """
        # Cyrillic characters look identical to Latin but have different codes
        evasion = "J\u043ehn"  # Cyrillic о instead of Latin o
        result = normalize_text(evasion)
        assert result == "John"

    def test_null_byte_evasion_prevented(self):
        """Null byte evasion is prevented."""
        evasion = "SSN\x00: 123-45-6789"
        result = normalize_text(evasion)
        assert '\x00' not in result


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge cases for normalization."""

    def test_unicode_combining_characters(self):
        """Combining characters are handled by NFKC."""
        # é as e + combining acute accent
        text = "e\u0301"  # e + combining acute
        result = normalize_text(text)
        # NFKC should compose to single character
        assert result == "é"

    def test_emoji_preserved(self):
        """Emoji are preserved (not stripped as control chars)."""
        text = "Hello 👋 World"
        result = normalize_text(text)
        assert "👋" in result

    def test_cjk_characters_preserved(self):
        """CJK characters are preserved."""
        text = "名前: 田中"
        result = normalize_text(text)
        assert result == text

    def test_arabic_text_preserved(self):
        """Arabic text is preserved (only bidi controls removed)."""
        text = "مرحبا"  # "Hello" in Arabic
        result = normalize_text(text)
        assert result == text

    def test_mixed_script_text(self):
        """Mixed script text is handled correctly."""
        text = "Hello 世界 Привет"
        result = normalize_text(text)
        # Only Cyrillic lookalikes are normalized, not all Cyrillic
        assert "Hello" in result
        assert "世界" in result

    def test_long_text_performance(self):
        """Long text is processed efficiently."""
        text = "John Smith " * 10000
        result = normalize_text(text)
        assert len(result) == len(text)

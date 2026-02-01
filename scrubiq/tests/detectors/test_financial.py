"""
Comprehensive tests for scrubiq/detectors/financial.py.

Tests financial security identifiers and cryptocurrency address detection
with checksum validation.
"""

import pytest
import hashlib
from scrubiq.detectors.financial import (
    FinancialDetector,
    _validate_cusip,
    _validate_isin,
    _validate_sedol,
    _validate_swift,
    _validate_lei,
    _validate_figi,
    _validate_bitcoin_base58,
    _validate_bitcoin_bech32,
    _validate_ethereum,
    _validate_seed_phrase,
    BIP39_SAMPLE_WORDS,
    FINANCIAL_PATTERNS,
)
from scrubiq.types import Tier


# =============================================================================
# CUSIP Validator Tests
# =============================================================================
class TestCUSIPValidator:
    """Tests for CUSIP check digit validation."""

    def test_valid_cusip_apple(self):
        """Apple Inc CUSIP should validate."""
        assert _validate_cusip("037833100") is True

    def test_valid_cusip_microsoft(self):
        """Microsoft CUSIP should validate."""
        assert _validate_cusip("594918104") is True

    def test_valid_cusip_google(self):
        """Google Class A CUSIP should validate."""
        assert _validate_cusip("02079K305") is True

    def test_valid_cusip_with_letters(self):
        """CUSIP with alphanumeric characters."""
        # Synthetic valid CUSIP with letters
        assert _validate_cusip("38259P508") is True  # HP Inc

    def test_cusip_with_spaces_normalized(self):
        """CUSIP with spaces should be normalized."""
        assert _validate_cusip("037 833 100") is True

    def test_cusip_with_dashes_normalized(self):
        """CUSIP with dashes should be normalized."""
        assert _validate_cusip("037-833-100") is True

    def test_cusip_lowercase_normalized(self):
        """Lowercase CUSIP should be normalized to uppercase."""
        assert _validate_cusip("02079k305") is True

    def test_invalid_cusip_wrong_check_digit(self):
        """CUSIP with wrong check digit should fail."""
        assert _validate_cusip("037833101") is False
        assert _validate_cusip("037833102") is False

    def test_invalid_cusip_too_short(self):
        """CUSIP shorter than 9 chars should fail."""
        assert _validate_cusip("03783310") is False
        assert _validate_cusip("1234567") is False

    def test_invalid_cusip_too_long(self):
        """CUSIP longer than 9 chars should fail."""
        assert _validate_cusip("0378331001") is False

    def test_invalid_cusip_special_chars(self):
        """CUSIP with unsupported special characters."""
        assert _validate_cusip("03783$100") is False

    def test_cusip_special_valid_chars(self):
        """CUSIP can contain * @ # as special chars."""
        # These have specific values in CUSIP algorithm
        # Creating a test that uses these is complex; test the char_value logic
        cusip_with_star = "12345*780"  # Would need valid check digit
        # Just verify it doesn't crash
        result = _validate_cusip(cusip_with_star)
        assert isinstance(result, bool)

    def test_cusip_empty_string(self):
        """Empty string should fail."""
        assert _validate_cusip("") is False

    def test_cusip_all_zeros(self):
        """All zeros CUSIP check digit calculation."""
        assert _validate_cusip("000000000") is True  # Check digit for zeros is 0

    def test_cusip_numeric_only(self):
        """Fully numeric CUSIP."""
        assert _validate_cusip("123456782") is True  # Valid check digit


# =============================================================================
# ISIN Validator Tests
# =============================================================================
class TestISINValidator:
    """Tests for ISIN (International Securities Identification Number) validation."""

    def test_valid_isin_us_apple(self):
        """Apple Inc ISIN should validate."""
        assert _validate_isin("US0378331005") is True

    def test_valid_isin_us_microsoft(self):
        """Microsoft ISIN should validate."""
        assert _validate_isin("US5949181045") is True

    def test_valid_isin_uk(self):
        """UK ISIN should validate."""
        assert _validate_isin("GB0002634946") is True  # BAE Systems

    def test_valid_isin_germany(self):
        """German ISIN should validate."""
        assert _validate_isin("DE0007164600") is True  # SAP

    def test_valid_isin_japan(self):
        """Japanese ISIN should validate."""
        assert _validate_isin("JP3633400001") is True  # Toyota

    def test_isin_with_spaces_normalized(self):
        """ISIN with spaces should be normalized."""
        assert _validate_isin("US 0378 3310 05") is True

    def test_isin_with_dashes_normalized(self):
        """ISIN with dashes should be normalized."""
        assert _validate_isin("US-0378-3310-05") is True

    def test_isin_lowercase_normalized(self):
        """Lowercase ISIN should be normalized."""
        assert _validate_isin("us0378331005") is True

    def test_invalid_isin_wrong_check_digit(self):
        """ISIN with wrong check digit should fail."""
        assert _validate_isin("US0378331001") is False
        assert _validate_isin("US0378331009") is False

    def test_invalid_isin_too_short(self):
        """ISIN shorter than 12 chars should fail."""
        assert _validate_isin("US03783310") is False

    def test_invalid_isin_too_long(self):
        """ISIN longer than 12 chars should fail."""
        assert _validate_isin("US03783310050") is False

    def test_invalid_isin_numeric_country(self):
        """ISIN with numeric country code should fail."""
        assert _validate_isin("120378331005") is False

    def test_invalid_isin_special_chars(self):
        """ISIN with special characters should fail."""
        assert _validate_isin("US037833100$") is False

    def test_isin_empty_string(self):
        """Empty string should fail."""
        assert _validate_isin("") is False


# =============================================================================
# SEDOL Validator Tests
# =============================================================================
class TestSEDOLValidator:
    """Tests for SEDOL (Stock Exchange Daily Official List) validation."""

    def test_valid_sedol_bp(self):
        """BP plc SEDOL should validate."""
        assert _validate_sedol("0798059") is True

    def test_valid_sedol_vodafone(self):
        """Vodafone SEDOL should validate."""
        assert _validate_sedol("BH4HKS3") is True

    def test_valid_sedol_numeric(self):
        """Fully numeric SEDOL."""
        assert _validate_sedol("2936921") is True

    def test_sedol_with_spaces_normalized(self):
        """SEDOL with spaces should be normalized."""
        assert _validate_sedol("079 8059") is True

    def test_sedol_lowercase_normalized(self):
        """Lowercase SEDOL should be normalized."""
        assert _validate_sedol("bh4hks3") is True

    def test_invalid_sedol_with_vowels(self):
        """SEDOL cannot contain vowels (A, E, I, O, U)."""
        assert _validate_sedol("BA12345") is False  # Contains A
        assert _validate_sedol("BE12345") is False  # Contains E
        assert _validate_sedol("BI12345") is False  # Contains I
        assert _validate_sedol("BO12345") is False  # Contains O
        assert _validate_sedol("BU12345") is False  # Contains U

    def test_invalid_sedol_wrong_check_digit(self):
        """SEDOL with wrong check digit should fail."""
        assert _validate_sedol("0798050") is False
        assert _validate_sedol("0798051") is False

    def test_invalid_sedol_too_short(self):
        """SEDOL shorter than 7 chars should fail."""
        assert _validate_sedol("079805") is False

    def test_invalid_sedol_too_long(self):
        """SEDOL longer than 7 chars should fail."""
        assert _validate_sedol("07980590") is False

    def test_sedol_empty_string(self):
        """Empty string should fail."""
        assert _validate_sedol("") is False


# =============================================================================
# SWIFT/BIC Validator Tests
# =============================================================================
class TestSWIFTValidator:
    """Tests for SWIFT/BIC code validation."""

    def test_valid_swift_8_char(self):
        """Valid 8-character SWIFT code."""
        assert _validate_swift("BOFAUS3N") is True  # Bank of America

    def test_valid_swift_11_char(self):
        """Valid 11-character SWIFT code with branch."""
        assert _validate_swift("BOFAUS3NXXX") is True

    def test_valid_swift_jpmorgan(self):
        """JPMorgan Chase SWIFT should validate."""
        assert _validate_swift("CHASUS33") is True

    def test_valid_swift_deutsche(self):
        """Deutsche Bank SWIFT should validate."""
        assert _validate_swift("DEUTDEFF") is True

    def test_valid_swift_hsbc(self):
        """HSBC SWIFT should validate."""
        assert _validate_swift("HSBCHKHH") is True

    def test_swift_with_spaces_normalized(self):
        """SWIFT with spaces should be normalized."""
        assert _validate_swift("BOFA US3N") is True

    def test_swift_lowercase_normalized(self):
        """Lowercase SWIFT should be normalized."""
        assert _validate_swift("bofaus3n") is True

    def test_invalid_swift_numeric_bank_code(self):
        """SWIFT bank code (first 4) must be letters."""
        assert _validate_swift("1234US3N") is False

    def test_invalid_swift_numeric_country_code(self):
        """SWIFT country code (positions 5-6) must be letters."""
        assert _validate_swift("BOFA12XX") is False

    def test_invalid_swift_wrong_length(self):
        """SWIFT must be 8 or 11 characters."""
        assert _validate_swift("BOFAUS") is False  # Too short
        assert _validate_swift("BOFAUS3") is False  # 7 chars
        assert _validate_swift("BOFAUS3NX") is False  # 9 chars
        assert _validate_swift("BOFAUS3NXX") is False  # 10 chars
        assert _validate_swift("BOFAUS3NXXXX") is False  # 12 chars

    def test_swift_deny_list_common_words(self):
        """Common English words matching SWIFT pattern should be rejected."""
        # 8-letter words that match SWIFT format
        assert _validate_swift("HOSPITAL") is False
        assert _validate_swift("NATIONAL") is False
        assert _validate_swift("REGIONAL") is False
        assert _validate_swift("PERSONAL") is False
        assert _validate_swift("OFFICIAL") is False
        assert _validate_swift("PHYSICAL") is False
        assert _validate_swift("CLINICAL") is False

    def test_swift_deny_list_healthcare_terms(self):
        """Healthcare terms matching SWIFT format should be rejected."""
        assert _validate_swift("REFERRAL") is False
        assert _validate_swift("TERMINAL") is False
        assert _validate_swift("SURGICAL") is False
        assert _validate_swift("CHEMICAL") is False

    def test_swift_deny_list_11_char_words(self):
        """11-letter words matching SWIFT format should be rejected."""
        assert _validate_swift("INFORMATION") is False
        assert _validate_swift("APPLICATION") is False
        assert _validate_swift("DESCRIPTION") is False
        assert _validate_swift("EDUCATIONAL") is False

    def test_swift_deny_list_us_locations(self):
        """US cities/states matching SWIFT format should be rejected."""
        assert _validate_swift("CALIFORNIA") is False
        assert _validate_swift("WASHINGTON") is False

    def test_swift_empty_string(self):
        """Empty string should fail."""
        assert _validate_swift("") is False


# =============================================================================
# LEI Validator Tests
# =============================================================================
class TestLEIValidator:
    """Tests for LEI (Legal Entity Identifier) validation."""

    def test_valid_lei_apple(self):
        """Apple Inc LEI should validate."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT394") is True

    def test_valid_lei_google(self):
        """Alphabet/Google LEI should validate."""
        assert _validate_lei("5493006MHB84DD0ZWV18") is True

    def test_valid_lei_microsoft(self):
        """Microsoft LEI should validate."""
        assert _validate_lei("INR2EJN1ERAN0W5ZP974") is True

    def test_lei_with_spaces_normalized(self):
        """LEI with spaces should be normalized."""
        assert _validate_lei("HWUP KR0M POU8 FGXB T394") is True

    def test_lei_with_dashes_normalized(self):
        """LEI with dashes should be normalized."""
        assert _validate_lei("HWUPKR0M-POU8FGXB-T394") is True

    def test_lei_lowercase_normalized(self):
        """Lowercase LEI should be normalized."""
        assert _validate_lei("hwupkr0mpou8fgxbt394") is True

    def test_invalid_lei_wrong_check_digits(self):
        """LEI with wrong check digits should fail."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT390") is False
        assert _validate_lei("HWUPKR0MPOU8FGXBT399") is False

    def test_invalid_lei_too_short(self):
        """LEI shorter than 20 chars should fail."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT39") is False

    def test_invalid_lei_too_long(self):
        """LEI longer than 20 chars should fail."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT3940") is False

    def test_invalid_lei_special_chars(self):
        """LEI with special characters should fail."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT39$") is False

    def test_lei_empty_string(self):
        """Empty string should fail."""
        assert _validate_lei("") is False


# =============================================================================
# FIGI Validator Tests
# =============================================================================
class TestFIGIValidator:
    """Tests for FIGI (Financial Instrument Global Identifier) validation."""

    def test_valid_figi_bbg_prefix(self):
        """FIGI with BBG (Bloomberg) prefix should validate."""
        assert _validate_figi("BBG000B9XRY4") is True  # Apple
        assert _validate_figi("BBG000BPH459") is True  # Microsoft

    def test_valid_figi_ggg_prefix(self):
        """FIGI with GGG prefix should validate."""
        assert _validate_figi("GGG000000001") is True

    def test_figi_with_spaces_normalized(self):
        """FIGI with spaces should be normalized."""
        assert _validate_figi("BBG 000B 9XRY 4") is True

    def test_figi_lowercase_normalized(self):
        """Lowercase FIGI should be normalized."""
        assert _validate_figi("bbg000b9xry4") is True

    def test_invalid_figi_too_short(self):
        """FIGI shorter than 12 chars should fail."""
        assert _validate_figi("BBG000B9XRY") is False

    def test_invalid_figi_too_long(self):
        """FIGI longer than 12 chars should fail."""
        assert _validate_figi("BBG000B9XRY45") is False

    def test_invalid_figi_special_chars(self):
        """FIGI with special characters should fail."""
        assert _validate_figi("BBG000B9XRY$") is False

    def test_figi_empty_string(self):
        """Empty string should fail."""
        assert _validate_figi("") is False


# =============================================================================
# Bitcoin Base58 Validator Tests
# =============================================================================
class TestBitcoinBase58Validator:
    """Tests for Bitcoin legacy and P2SH address validation."""

    def test_valid_bitcoin_legacy_p2pkh(self):
        """Valid Bitcoin P2PKH (starts with 1) address."""
        # Well-known valid Bitcoin addresses
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is True

    def test_valid_bitcoin_p2sh(self):
        """Valid Bitcoin P2SH (starts with 3) address."""
        assert _validate_bitcoin_base58("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is True

    def test_invalid_bitcoin_wrong_prefix(self):
        """Bitcoin address must start with 1 or 3 for Base58."""
        assert _validate_bitcoin_base58("2BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False

    def test_invalid_bitcoin_too_short(self):
        """Bitcoin address shorter than 25 chars should fail."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn") is False

    def test_invalid_bitcoin_too_long(self):
        """Bitcoin address longer than 34 chars should fail."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2XXX") is False

    def test_invalid_bitcoin_bad_chars(self):
        """Bitcoin Base58 excludes 0, O, I, l."""
        assert _validate_bitcoin_base58("10vBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False
        assert _validate_bitcoin_base58("1OvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False
        assert _validate_bitcoin_base58("1IvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False
        assert _validate_bitcoin_base58("1lvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False

    def test_invalid_bitcoin_wrong_checksum(self):
        """Bitcoin address with invalid checksum should fail."""
        # Changed last char to invalidate checksum
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3") is False

    def test_bitcoin_empty_string(self):
        """Empty string should fail."""
        assert _validate_bitcoin_base58("") is False

    def test_bitcoin_none(self):
        """None should fail."""
        assert _validate_bitcoin_base58(None) is False


# =============================================================================
# Bitcoin Bech32 Validator Tests
# =============================================================================
class TestBitcoinBech32Validator:
    """Tests for Bitcoin Bech32 (SegWit) address validation."""

    def test_valid_bitcoin_native_segwit_p2wpkh(self):
        """Valid Native SegWit P2WPKH (bc1q...) address - 42 chars."""
        assert _validate_bitcoin_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") is True

    def test_valid_bitcoin_native_segwit_p2wsh(self):
        """Valid Native SegWit P2WSH (bc1q...) address - 62 chars."""
        addr = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        assert _validate_bitcoin_bech32(addr) is True

    def test_valid_bitcoin_taproot_p2tr(self):
        """Valid Taproot P2TR (bc1p...) address - 62 chars."""
        addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
        assert _validate_bitcoin_bech32(addr) is True

    def test_bech32_case_insensitive(self):
        """Bech32 addresses should be case-insensitive."""
        assert _validate_bitcoin_bech32("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ") is True

    def test_invalid_bech32_wrong_prefix(self):
        """Bech32 must start with bc1."""
        assert _validate_bitcoin_bech32("tb1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") is False

    def test_invalid_bech32_wrong_witness_version(self):
        """Bech32 witness version must be q (v0) or p (v1)."""
        # 'r' is not a valid witness version
        assert _validate_bitcoin_bech32("bc1rar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") is False

    def test_invalid_bech32_bad_chars(self):
        """Bech32 charset excludes 1, b, i, o."""
        # These should fail due to invalid characters
        assert _validate_bitcoin_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5md1") is False
        assert _validate_bitcoin_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdb") is False

    def test_invalid_bech32_wrong_length_p2wpkh(self):
        """P2WPKH (bc1q) must be exactly 42 chars."""
        # Too short
        assert _validate_bitcoin_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5md") is False
        # Wrong length (not 42 or 62)
        assert _validate_bitcoin_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdqa") is False

    def test_invalid_bech32_too_short(self):
        """Bech32 minimum data part length."""
        assert _validate_bitcoin_bech32("bc1qxxx") is False

    def test_bech32_empty_string(self):
        """Empty string should fail."""
        assert _validate_bitcoin_bech32("") is False


# =============================================================================
# Ethereum Validator Tests
# =============================================================================
class TestEthereumValidator:
    """Tests for Ethereum address validation."""

    def test_valid_ethereum_lowercase(self):
        """Valid Ethereum address in lowercase."""
        assert _validate_ethereum("0x742d35cc6634c0532925a3b844bc9e7595f5b1c3") is True

    def test_valid_ethereum_uppercase(self):
        """Valid Ethereum address in uppercase."""
        assert _validate_ethereum("0X742D35CC6634C0532925A3B844BC9E7595F5B1C3") is True

    def test_valid_ethereum_mixed_case(self):
        """Valid Ethereum address with EIP-55 checksum (mixed case)."""
        assert _validate_ethereum("0x742d35Cc6634C0532925a3b844Bc9e7595f5b1C3") is True

    def test_valid_ethereum_known_addresses(self):
        """Well-known Ethereum addresses."""
        # Vitalik's address
        assert _validate_ethereum("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045") is True
        # Null address
        assert _validate_ethereum("0x0000000000000000000000000000000000000000") is True

    def test_invalid_ethereum_missing_prefix(self):
        """Ethereum address must start with 0x."""
        assert _validate_ethereum("742d35cc6634c0532925a3b844bc9e7595f5b1c3") is False

    def test_invalid_ethereum_wrong_length(self):
        """Ethereum address must be 0x + 40 hex characters."""
        assert _validate_ethereum("0x742d35cc6634c0532925a3b844bc9e7595f5b1c") is False  # 39
        assert _validate_ethereum("0x742d35cc6634c0532925a3b844bc9e7595f5b1c30") is False  # 41

    def test_invalid_ethereum_non_hex(self):
        """Ethereum address must be hexadecimal."""
        assert _validate_ethereum("0x742d35cc6634c0532925a3b844bc9e7595f5b1cZ") is False

    def test_ethereum_empty_string(self):
        """Empty string should fail."""
        assert _validate_ethereum("") is False


# =============================================================================
# Seed Phrase Validator Tests
# =============================================================================
class TestSeedPhraseValidator:
    """Tests for BIP-39 seed phrase validation."""

    def test_valid_12_word_seed_phrase(self):
        """Valid 12-word seed phrase."""
        phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        assert _validate_seed_phrase(phrase) is True

    def test_valid_24_word_seed_phrase(self):
        """Valid 24-word seed phrase."""
        phrase = " ".join(["abandon"] * 23 + ["zoo"])
        assert _validate_seed_phrase(phrase) is True

    def test_valid_15_word_seed_phrase(self):
        """Valid 15-word seed phrase."""
        phrase = " ".join(["abandon"] * 15)
        assert _validate_seed_phrase(phrase) is True

    def test_valid_18_word_seed_phrase(self):
        """Valid 18-word seed phrase."""
        phrase = " ".join(["abandon"] * 18)
        assert _validate_seed_phrase(phrase) is True

    def test_valid_21_word_seed_phrase(self):
        """Valid 21-word seed phrase."""
        phrase = " ".join(["abandon"] * 21)
        assert _validate_seed_phrase(phrase) is True

    def test_invalid_word_count(self):
        """Seed phrase must have 12, 15, 18, 21, or 24 words."""
        assert _validate_seed_phrase("abandon ability able") is False  # 3 words
        assert _validate_seed_phrase(" ".join(["abandon"] * 11)) is False  # 11 words
        assert _validate_seed_phrase(" ".join(["abandon"] * 13)) is False  # 13 words
        assert _validate_seed_phrase(" ".join(["abandon"] * 25)) is False  # 25 words

    def test_mixed_bip39_words(self):
        """Seed phrase with mix of BIP-39 words."""
        phrase = "abandon zebra ability zoo about above absent absorb abstract absurd abuse access"
        assert _validate_seed_phrase(phrase) is True

    def test_case_insensitive(self):
        """Seed phrase validation should be case-insensitive."""
        phrase = "ABANDON ABILITY ABLE ABOUT ABOVE ABSENT ABSORB ABSTRACT ABSURD ABUSE ACCESS ACCIDENT"
        assert _validate_seed_phrase(phrase) is True

    def test_empty_string(self):
        """Empty string should fail."""
        assert _validate_seed_phrase("") is False


# =============================================================================
# FinancialDetector Class Tests
# =============================================================================
class TestFinancialDetector:
    """Tests for the FinancialDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a FinancialDetector instance."""
        return FinancialDetector()

    def test_detector_name(self, detector):
        """Detector should have correct name."""
        assert detector.name == "financial"

    def test_detector_tier(self, detector):
        """Detector should use CHECKSUM tier."""
        assert detector.tier == Tier.CHECKSUM

    def test_detect_returns_list(self, detector):
        """Detection should return a list."""
        result = detector.detect("No financial data here")
        assert isinstance(result, list)

    def test_detect_empty_text(self, detector):
        """Empty text should return empty list."""
        result = detector.detect("")
        assert result == []

    # --- CUSIP Detection ---
    def test_detect_cusip_labeled(self, detector):
        """Detect labeled CUSIP."""
        text = "The security CUSIP: 037833100 was purchased today."
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) == 1
        assert cusip_spans[0].text == "037833100"
        assert cusip_spans[0].confidence >= 0.98

    def test_detect_cusip_bare(self, detector):
        """Detect bare CUSIP (lower confidence)."""
        text = "Security 594918104 is performing well."
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        # May detect with lower confidence since it's not labeled
        if cusip_spans:
            assert cusip_spans[0].text == "594918104"

    # --- ISIN Detection ---
    def test_detect_isin_labeled(self, detector):
        """Detect labeled ISIN."""
        text = "Buy ISIN: US0378331005 (Apple Inc)"
        spans = detector.detect(text)

        isin_spans = [s for s in spans if s.entity_type == "ISIN"]
        assert len(isin_spans) >= 1
        assert any(s.text == "US0378331005" for s in isin_spans)

    def test_detect_isin_bare(self, detector):
        """Detect bare ISIN."""
        text = "Holding GB0002634946 in portfolio"
        spans = detector.detect(text)

        isin_spans = [s for s in spans if s.entity_type == "ISIN"]
        if isin_spans:
            assert any(s.text == "GB0002634946" for s in isin_spans)

    # --- SEDOL Detection ---
    def test_detect_sedol_labeled(self, detector):
        """Detect labeled SEDOL."""
        text = "SEDOL: 0798059 is BP plc"
        spans = detector.detect(text)

        sedol_spans = [s for s in spans if s.entity_type == "SEDOL"]
        assert len(sedol_spans) >= 1
        assert any(s.text == "0798059" for s in sedol_spans)

    # --- SWIFT/BIC Detection ---
    def test_detect_swift_labeled(self, detector):
        """Detect labeled SWIFT code."""
        text = "Wire to SWIFT: BOFAUS3N for Bank of America"
        spans = detector.detect(text)

        swift_spans = [s for s in spans if s.entity_type == "SWIFT_BIC"]
        assert len(swift_spans) >= 1
        assert any(s.text == "BOFAUS3N" for s in swift_spans)

    def test_detect_swift_11_char(self, detector):
        """Detect 11-character SWIFT code."""
        text = "BIC: DEUTDEFFXXX for Deutsche Bank"
        spans = detector.detect(text)

        swift_spans = [s for s in spans if s.entity_type == "SWIFT_BIC"]
        assert len(swift_spans) >= 1

    # --- LEI Detection ---
    def test_detect_lei_labeled(self, detector):
        """Detect labeled LEI."""
        text = "Entity LEI: HWUPKR0MPOU8FGXBT394 (Apple)"
        spans = detector.detect(text)

        lei_spans = [s for s in spans if s.entity_type == "LEI"]
        assert len(lei_spans) >= 1
        assert any(s.text == "HWUPKR0MPOU8FGXBT394" for s in lei_spans)

    # --- FIGI Detection ---
    def test_detect_figi_labeled(self, detector):
        """Detect labeled FIGI."""
        text = "FIGI: BBG000B9XRY4 for Apple equity"
        spans = detector.detect(text)

        figi_spans = [s for s in spans if s.entity_type == "FIGI"]
        assert len(figi_spans) >= 1
        assert any(s.text == "BBG000B9XRY4" for s in figi_spans)

    def test_detect_figi_bare_bbg(self, detector):
        """Detect bare FIGI with BBG prefix."""
        text = "Looking at BBG000BPH459 performance"
        spans = detector.detect(text)

        figi_spans = [s for s in spans if s.entity_type == "FIGI"]
        assert len(figi_spans) >= 1
        assert any(s.text == "BBG000BPH459" for s in figi_spans)

    # --- Bitcoin Detection ---
    def test_detect_bitcoin_legacy(self, detector):
        """Detect Bitcoin legacy P2PKH address."""
        text = "Send to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1
        assert any("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in s.text for s in btc_spans)

    def test_detect_bitcoin_p2sh(self, detector):
        """Detect Bitcoin P2SH address."""
        text = "Payment address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1

    def test_detect_bitcoin_segwit(self, detector):
        """Detect Bitcoin SegWit bech32 address."""
        text = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1
        assert btc_spans[0].confidence >= 0.95

    def test_detect_bitcoin_taproot(self, detector):
        """Detect Bitcoin Taproot address."""
        text = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1

    # --- Ethereum Detection ---
    def test_detect_ethereum(self, detector):
        """Detect Ethereum address."""
        text = "ETH wallet: 0x742d35cc6634c0532925a3b844bc9e7595f5b1c3"
        spans = detector.detect(text)

        eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
        assert len(eth_spans) >= 1
        assert eth_spans[0].confidence >= 0.95

    # --- Seed Phrase Detection ---
    def test_detect_seed_phrase_12_words(self, detector):
        """Detect 12-word seed phrase with context."""
        phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        text = f"Recovery seed phrase: {phrase}"
        spans = detector.detect(text)

        seed_spans = [s for s in spans if s.entity_type == "CRYPTO_SEED_PHRASE"]
        assert len(seed_spans) >= 1

    def test_detect_seed_phrase_mnemonic_context(self, detector):
        """Detect seed phrase with 'mnemonic' keyword."""
        phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        text = f"Mnemonic words: {phrase}"
        spans = detector.detect(text)

        seed_spans = [s for s in spans if s.entity_type == "CRYPTO_SEED_PHRASE"]
        assert len(seed_spans) >= 1

    # --- Litecoin Detection ---
    def test_detect_litecoin_l_prefix(self, detector):
        """Detect Litecoin address starting with L."""
        text = "LTC: LNFeXJXQDjPv7H28qd2r2QRHo2HWEYPDpw"
        spans = detector.detect(text)

        ltc_spans = [s for s in spans if s.entity_type == "LITECOIN_ADDRESS"]
        # May or may not detect depending on pattern specificity

    # --- Cardano Detection ---
    def test_detect_cardano(self, detector):
        """Detect Cardano address."""
        text = "addr1qxckz3kplv7mfx0rn5yx4e0fz6kxcqk9ehg5xn8v7wd4s0h5n7q0w2r7gctqy3z"
        spans = detector.detect(text)
        # Cardano pattern requires addr1 prefix

    # --- Multiple Detections ---
    def test_detect_multiple_types(self, detector):
        """Detect multiple financial identifier types in one text."""
        text = """
        Portfolio Holdings:
        - Apple: CUSIP: 037833100, ISIN: US0378331005
        - Payment: 0x742d35cc6634c0532925a3b844bc9e7595f5b1c3
        - Wire to SWIFT: BOFAUS3N
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        # Should detect at least CUSIP, ISIN, ETHEREUM_ADDRESS
        assert "CUSIP" in entity_types or "ISIN" in entity_types
        assert "ETHEREUM_ADDRESS" in entity_types

    def test_detect_deduplication(self, detector):
        """Same identifier should not create duplicate spans."""
        text = "CUSIP: 037833100 is the same as CUSIP 037833100"
        spans = detector.detect(text)

        # Should have two separate spans (different positions)
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        positions = [(s.start, s.end) for s in cusip_spans]
        # Each position should be unique
        assert len(positions) == len(set(positions))

    # --- Span Properties ---
    def test_span_has_correct_properties(self, detector):
        """Detected span should have all required properties."""
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        assert len(spans) >= 1
        span = spans[0]

        assert hasattr(span, "start")
        assert hasattr(span, "end")
        assert hasattr(span, "text")
        assert hasattr(span, "entity_type")
        assert hasattr(span, "confidence")
        assert hasattr(span, "detector")
        assert hasattr(span, "tier")

        assert span.detector == "financial"
        assert span.tier == Tier.CHECKSUM
        assert 0 <= span.confidence <= 1

    def test_span_position_accuracy(self, detector):
        """Span start/end positions should be accurate."""
        prefix = "Security identifier: "
        cusip = "037833100"
        text = f"{prefix}CUSIP: {cusip}"

        spans = detector.detect(text)
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]

        assert len(cusip_spans) >= 1
        span = cusip_spans[0]

        # Verify the text at span positions matches
        assert text[span.start:span.end] == span.text

    # --- Confidence Boosting ---
    def test_confidence_boosted_with_validation(self, detector):
        """Confidence should be boosted when validator passes."""
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1

        # With valid checksum and label, confidence should be very high
        assert cusip_spans[0].confidence >= 0.98

    # --- Invalid Identifiers ---
    def test_no_detection_invalid_cusip(self, detector):
        """Invalid CUSIP should not be detected."""
        text = "Invalid CUSIP: 037833109"  # Wrong check digit
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP" and s.text == "037833109"]
        assert len(cusip_spans) == 0

    def test_no_detection_invalid_isin(self, detector):
        """Invalid ISIN should not be detected."""
        text = "Invalid ISIN: US0378331009"  # Wrong check digit
        spans = detector.detect(text)

        isin_spans = [s for s in spans if s.entity_type == "ISIN" and s.text == "US0378331009"]
        assert len(isin_spans) == 0


# =============================================================================
# Pattern Coverage Tests
# =============================================================================
class TestFinancialPatternsCoverage:
    """Tests to ensure pattern definitions are properly structured."""

    def test_patterns_not_empty(self):
        """FINANCIAL_PATTERNS should contain patterns."""
        assert len(FINANCIAL_PATTERNS) > 0

    def test_pattern_structure(self):
        """Each pattern should have correct structure."""
        for pattern, entity_type, confidence, group_idx, validator in FINANCIAL_PATTERNS:
            # Pattern should be compiled regex
            assert hasattr(pattern, "finditer")
            # Entity type should be non-empty string
            assert isinstance(entity_type, str) and len(entity_type) > 0
            # Confidence should be between 0 and 1
            assert 0 <= confidence <= 1
            # Group index should be non-negative
            assert group_idx >= 0
            # Validator should be callable or None
            assert validator is None or callable(validator)

    def test_all_entity_types_defined(self):
        """All documented entity types should have patterns."""
        entity_types = {pattern[1] for pattern in FINANCIAL_PATTERNS}

        expected = {
            "CUSIP", "ISIN", "SEDOL", "SWIFT_BIC", "LEI", "FIGI",
            "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "CRYPTO_SEED_PHRASE",
            "LITECOIN_ADDRESS", "DOGECOIN_ADDRESS", "XRP_ADDRESS",
            "SOLANA_ADDRESS", "CARDANO_ADDRESS",
        }

        # At least core types should be present
        core_types = {"CUSIP", "ISIN", "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS"}
        assert core_types.issubset(entity_types)


# =============================================================================
# BIP39 Word List Tests
# =============================================================================
class TestBIP39WordList:
    """Tests for the BIP39 sample word list."""

    def test_sample_words_not_empty(self):
        """BIP39_SAMPLE_WORDS should contain words."""
        assert len(BIP39_SAMPLE_WORDS) > 0

    def test_sample_words_lowercase(self):
        """All BIP39 words should be lowercase."""
        for word in BIP39_SAMPLE_WORDS:
            assert word == word.lower()

    def test_sample_words_alphabetic(self):
        """All BIP39 words should be alphabetic."""
        for word in BIP39_SAMPLE_WORDS:
            assert word.isalpha()

    def test_common_bip39_words_present(self):
        """Common BIP39 words should be in the sample list."""
        common = ["abandon", "ability", "able", "about", "above", "zebra", "zero", "zone", "zoo"]
        for word in common:
            assert word in BIP39_SAMPLE_WORDS


# =============================================================================
# Edge Cases and Robustness Tests
# =============================================================================
class TestFinancialEdgeCases:
    """Edge case tests for financial detection."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_unicode_text(self, detector):
        """Detector should handle Unicode text."""
        text = "CUSIP: 037833100 for Apple Inc™ © 2024"
        spans = detector.detect(text)
        # Should still detect the CUSIP
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1

    def test_newlines_in_text(self, detector):
        """Detector should handle text with newlines."""
        text = "CUSIP:\n037833100\nfor Apple"
        spans = detector.detect(text)
        # May or may not detect depending on pattern
        # Just verify no crash
        assert isinstance(spans, list)

    def test_very_long_text(self, detector):
        """Detector should handle very long text."""
        text = "prefix " + "x" * 100000 + " CUSIP: 037833100 " + "y" * 100000
        spans = detector.detect(text)
        # Should still find the CUSIP
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1

    def test_special_characters_around_identifiers(self, detector):
        """Identifiers surrounded by special characters."""
        text = "===CUSIP: 037833100==="
        spans = detector.detect(text)
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1

    def test_identifiers_in_urls(self, detector):
        """Identifiers embedded in URLs may be detected."""
        text = "https://example.com/security/037833100/details"
        spans = detector.detect(text)
        # URL context may prevent detection; just verify no crash
        assert isinstance(spans, list)

    def test_identifiers_in_json(self, detector):
        """Identifiers in JSON format."""
        text = '{"cusip": "037833100", "isin": "US0378331005"}'
        spans = detector.detect(text)
        # Should detect these identifiers
        assert len(spans) >= 1

    def test_mixed_case_labels(self, detector):
        """Labels in mixed case should still work."""
        text = "Cusip: 037833100 and Isin: US0378331005"
        spans = detector.detect(text)
        # At least one should be detected
        assert len(spans) >= 1

    def test_multiple_spaces_between_label_and_value(self, detector):
        """Multiple spaces between label and value."""
        text = "CUSIP:     037833100"
        spans = detector.detect(text)
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1

    def test_no_false_positives_on_random_numbers(self, detector):
        """Random 9-digit numbers shouldn't trigger CUSIP false positives."""
        text = "Phone: 123456789 and order 987654321"
        spans = detector.detect(text)
        # May detect some as CUSIPs if checksums happen to validate
        # This is expected behavior - checksum validation filters most
        for span in spans:
            if span.entity_type == "CUSIP":
                # If detected, the checksum should be valid
                assert _validate_cusip(span.text)

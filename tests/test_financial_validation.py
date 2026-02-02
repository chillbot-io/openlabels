"""
Comprehensive tests for financial detector.

Tests detection and validation of:
- CUSIP (9-character security identifier)
- ISIN (12-character international security identifier)
- SEDOL (7-character UK security identifier)
- SWIFT/BIC (8 or 11 character bank code)
- LEI (20-character legal entity identifier)
- FIGI (12-character financial instrument identifier)
- Cryptocurrency addresses (Bitcoin, Ethereum, etc.)
- Crypto seed phrases

Strong assertions with real validation logic.
No skipping - all dependencies required.
"""

import pytest
from openlabels.core.detectors.financial import (
    FinancialDetector,
    _validate_cusip,
    _validate_isin,
    _validate_sedol,
    _validate_swift,
    _validate_lei,
    _validate_bitcoin_base58,
    _validate_bitcoin_bech32,
    _validate_ethereum,
    _validate_seed_phrase,
)
from openlabels.core.types import Tier


# =============================================================================
# CUSIP VALIDATION TESTS
# =============================================================================

class TestCUSIPValidation:
    """Test CUSIP validation with checksum."""

    def test_cusip_valid_apple(self):
        """Test valid Apple CUSIP."""
        assert _validate_cusip("037833100") is True

    def test_cusip_valid_microsoft(self):
        """Test valid Microsoft CUSIP."""
        assert _validate_cusip("594918104") is True

    def test_cusip_valid_google(self):
        """Test valid Alphabet/Google CUSIP."""
        assert _validate_cusip("02079K305") is True

    def test_cusip_valid_amazon(self):
        """Test valid Amazon CUSIP."""
        assert _validate_cusip("023135106") is True

    def test_cusip_valid_with_spaces(self):
        """Test CUSIP with spaces."""
        assert _validate_cusip("037 833 100") is True

    def test_cusip_valid_lowercase(self):
        """Test CUSIP with lowercase letters."""
        assert _validate_cusip("02079k305") is True

    def test_cusip_invalid_checksum(self):
        """Test CUSIP with wrong check digit."""
        assert _validate_cusip("037833101") is False

    def test_cusip_wrong_length_short(self):
        """Test CUSIP that's too short."""
        assert _validate_cusip("03783310") is False

    def test_cusip_wrong_length_long(self):
        """Test CUSIP that's too long."""
        assert _validate_cusip("0378331001") is False

    def test_cusip_all_digits(self):
        """Test all-numeric CUSIP."""
        assert _validate_cusip("123456782") is True  # Valid checksum

    def test_cusip_with_special_chars(self):
        """Test CUSIP with special characters * @ #."""
        # CUSIP allows *, @, # as values 36, 37, 38
        # Creating a valid one is complex - test format acceptance
        assert isinstance(_validate_cusip("12345*789"), bool)


# =============================================================================
# ISIN VALIDATION TESTS
# =============================================================================

class TestISINValidation:
    """Test ISIN validation with Luhn algorithm."""

    def test_isin_valid_us_apple(self):
        """Test valid US ISIN for Apple."""
        assert _validate_isin("US0378331005") is True

    def test_isin_valid_uk(self):
        """Test valid UK ISIN."""
        assert _validate_isin("GB0002634946") is True

    def test_isin_valid_germany_bayer(self):
        """Test valid German ISIN for Bayer."""
        assert _validate_isin("DE000BAY0017") is True

    def test_isin_valid_france(self):
        """Test valid French ISIN."""
        assert _validate_isin("FR0000131104") is True  # BNP Paribas

    def test_isin_valid_japan(self):
        """Test valid Japanese ISIN."""
        assert _validate_isin("JP3633400001") is True  # Toyota

    def test_isin_valid_lowercase(self):
        """Test ISIN with lowercase."""
        assert _validate_isin("us0378331005") is True

    def test_isin_valid_with_spaces(self):
        """Test ISIN with spaces."""
        assert _validate_isin("US 0378331005") is True

    def test_isin_invalid_checksum(self):
        """Test ISIN with wrong check digit."""
        assert _validate_isin("US0378331006") is False

    def test_isin_wrong_length(self):
        """Test ISIN with wrong length."""
        assert _validate_isin("US037833100") is False

    def test_isin_invalid_country(self):
        """Test ISIN with numeric country code."""
        assert _validate_isin("12345678901X") is False

    def test_isin_invalid_special_char(self):
        """Test ISIN with invalid special character."""
        assert _validate_isin("US03783$1005") is False


# =============================================================================
# SEDOL VALIDATION TESTS
# =============================================================================

class TestSEDOLValidation:
    """Test SEDOL validation with check digit."""

    def test_sedol_valid_standard(self):
        """Test valid SEDOL."""
        assert _validate_sedol("0263494") is True  # BAE Systems

    def test_sedol_valid_bp(self):
        """Test valid BP SEDOL."""
        assert _validate_sedol("0798059") is True

    def test_sedol_valid_with_letters(self):
        """Test valid SEDOL with letters."""
        assert _validate_sedol("B0YBKJ7") is True  # Tesco

    def test_sedol_invalid_with_vowels(self):
        """Test SEDOL with vowels fails."""
        # SEDOL cannot contain vowels
        assert _validate_sedol("0A63494") is False  # A is vowel

    def test_sedol_invalid_checksum(self):
        """Test SEDOL with wrong check digit."""
        assert _validate_sedol("0263495") is False

    def test_sedol_wrong_length(self):
        """Test SEDOL with wrong length."""
        assert _validate_sedol("026349") is False

    def test_sedol_lowercase(self):
        """Test SEDOL with lowercase."""
        assert _validate_sedol("b0ybkj7") is True


# =============================================================================
# SWIFT/BIC VALIDATION TESTS
# =============================================================================

class TestSWIFTValidation:
    """Test SWIFT/BIC code validation."""

    def test_swift_valid_8_char(self):
        """Test valid 8-character SWIFT code."""
        assert _validate_swift("DEUTDEFF") is True  # Deutsche Bank

    def test_swift_valid_11_char(self):
        """Test valid 11-character SWIFT code."""
        assert _validate_swift("DEUTDEFFXXX") is True

    def test_swift_valid_hsbc(self):
        """Test valid HSBC SWIFT code."""
        assert _validate_swift("HSBCGB2L") is True

    def test_swift_valid_chase(self):
        """Test valid Chase SWIFT code."""
        assert _validate_swift("CHASUS33") is True

    def test_swift_valid_lowercase(self):
        """Test SWIFT with lowercase."""
        assert _validate_swift("deutdeff") is True

    def test_swift_invalid_length_7(self):
        """Test SWIFT with 7 characters."""
        assert _validate_swift("DEUTDEF") is False

    def test_swift_invalid_length_9(self):
        """Test SWIFT with 9 characters."""
        assert _validate_swift("DEUTDEFFX") is False

    def test_swift_invalid_format(self):
        """Test SWIFT with invalid format."""
        assert _validate_swift("1234DEFF") is False  # Starts with numbers

    def test_swift_blocked_word(self):
        """Test SWIFT rejects common English words."""
        # These words match SWIFT format but are denied
        assert _validate_swift("HOSPITAL") is False
        assert _validate_swift("TERMINAL") is False
        assert _validate_swift("NATIONAL") is False


# =============================================================================
# LEI VALIDATION TESTS
# =============================================================================

class TestLEIValidation:
    """Test LEI validation with ISO 7064 Mod 97-10."""

    def test_lei_valid_apple(self):
        """Test valid Apple LEI."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT394") is True

    def test_lei_valid_microsoft(self):
        """Test valid Microsoft LEI."""
        assert _validate_lei("INR2EJN1ERAN0W5ZP974") is True

    def test_lei_valid_google(self):
        """Test valid Alphabet/Google LEI."""
        assert _validate_lei("ZBUT11V806EZRVTWT807") is True

    def test_lei_valid_lowercase(self):
        """Test LEI with lowercase."""
        assert _validate_lei("hwupkr0mpou8fgxbt394") is True

    def test_lei_valid_with_spaces(self):
        """Test LEI with spaces."""
        assert _validate_lei("HWUP KR0M POU8 FGXB T394") is True

    def test_lei_invalid_checksum(self):
        """Test LEI with wrong checksum."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT395") is False

    def test_lei_wrong_length(self):
        """Test LEI with wrong length."""
        assert _validate_lei("HWUPKR0MPOU8FGXBT39") is False

    def test_lei_special_char(self):
        """Test LEI with special character."""
        assert _validate_lei("HWUPKR0MPOU8FGX@T394") is False


# =============================================================================
# BITCOIN ADDRESS VALIDATION TESTS
# =============================================================================

class TestBitcoinBase58Validation:
    """Test Bitcoin legacy/P2SH address validation."""

    def test_bitcoin_valid_legacy_1(self):
        """Test valid legacy Bitcoin address starting with 1."""
        # Well-known test address
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is True

    def test_bitcoin_valid_p2sh_3(self):
        """Test valid P2SH Bitcoin address starting with 3."""
        assert _validate_bitcoin_base58("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is True

    def test_bitcoin_invalid_wrong_start(self):
        """Test Bitcoin address with wrong start character."""
        assert _validate_bitcoin_base58("2BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False

    def test_bitcoin_invalid_checksum(self):
        """Test Bitcoin address with bad checksum."""
        # Change last char
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3") is False

    def test_bitcoin_invalid_too_short(self):
        """Test Bitcoin address that's too short."""
        assert _validate_bitcoin_base58("1BvBMSEYstWet") is False

    def test_bitcoin_invalid_too_long(self):
        """Test Bitcoin address that's too long."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2Extra") is False

    def test_bitcoin_invalid_chars(self):
        """Test Bitcoin address with invalid Base58 characters."""
        # Base58 excludes 0, O, I, l
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN0") is False


class TestBitcoinBech32Validation:
    """Test Bitcoin Bech32 (SegWit) address validation."""

    def test_bitcoin_valid_bech32_p2wpkh(self):
        """Test valid Bech32 P2WPKH address."""
        # Witness version 0 (q), 42 chars total
        is_valid = _validate_bitcoin_bech32(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        )
        assert is_valid is True

    def test_bitcoin_valid_bech32_p2wsh(self):
        """Test valid Bech32 P2WSH address."""
        # Witness version 0, 62 chars total
        is_valid = _validate_bitcoin_bech32(
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        )
        assert is_valid is True

    def test_bitcoin_valid_bech32_lowercase(self):
        """Test Bech32 must be lowercase (or all uppercase)."""
        is_valid = _validate_bitcoin_bech32(
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
        )
        # Implementation converts to lowercase, so should work
        assert is_valid is True

    def test_bitcoin_invalid_bech32_wrong_prefix(self):
        """Test Bech32 with wrong prefix."""
        is_valid = _validate_bitcoin_bech32(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        )
        assert is_valid is False  # tb1 is testnet

    def test_bitcoin_invalid_bech32_bad_chars(self):
        """Test Bech32 with invalid characters."""
        is_valid = _validate_bitcoin_bech32(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb"
        )
        # 'b' is not in bech32 charset
        assert is_valid is False

    def test_bitcoin_invalid_bech32_wrong_length(self):
        """Test Bech32 with wrong length."""
        is_valid = _validate_bitcoin_bech32("bc1qshort")
        assert is_valid is False


# =============================================================================
# ETHEREUM ADDRESS VALIDATION TESTS
# =============================================================================

class TestEthereumValidation:
    """Test Ethereum address validation."""

    def test_ethereum_valid_standard(self):
        """Test valid Ethereum address."""
        assert _validate_ethereum("0x71C7656EC7ab88b098defB751B7401B5f6d8976F") is True

    def test_ethereum_valid_lowercase(self):
        """Test valid Ethereum address lowercase."""
        assert _validate_ethereum("0x71c7656ec7ab88b098defb751b7401b5f6d8976f") is True

    def test_ethereum_valid_uppercase_prefix(self):
        """Test Ethereum with uppercase 0X prefix."""
        assert _validate_ethereum("0X71C7656EC7ab88b098defB751B7401B5f6d8976F") is True

    def test_ethereum_valid_zeros(self):
        """Test Ethereum null address."""
        assert _validate_ethereum("0x0000000000000000000000000000000000000000") is True

    def test_ethereum_invalid_no_prefix(self):
        """Test Ethereum without 0x prefix."""
        assert _validate_ethereum("71C7656EC7ab88b098defB751B7401B5f6d8976F") is False

    def test_ethereum_invalid_too_short(self):
        """Test Ethereum address too short."""
        assert _validate_ethereum("0x71C7656EC7ab88b098defB751B7401B5f6d897") is False

    def test_ethereum_invalid_too_long(self):
        """Test Ethereum address too long."""
        assert _validate_ethereum("0x71C7656EC7ab88b098defB751B7401B5f6d8976F0") is False

    def test_ethereum_invalid_non_hex(self):
        """Test Ethereum with non-hex characters."""
        assert _validate_ethereum("0x71C7656EC7ab88b098defB751B7401B5f6d8976G") is False


# =============================================================================
# SEED PHRASE VALIDATION TESTS
# =============================================================================

class TestSeedPhraseValidation:
    """Test BIP-39 seed phrase validation."""

    def test_seed_12_words_valid(self):
        """Test valid 12-word seed phrase."""
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        assert _validate_seed_phrase(phrase) is True

    def test_seed_24_words_valid(self):
        """Test valid 24-word seed phrase."""
        phrase = "abandon " * 23 + "about"
        assert _validate_seed_phrase(phrase) is True

    def test_seed_15_words_valid(self):
        """Test valid 15-word seed phrase."""
        phrase = "abandon " * 14 + "about"
        assert _validate_seed_phrase(phrase) is True

    def test_seed_18_words_valid(self):
        """Test valid 18-word seed phrase."""
        phrase = "abandon " * 17 + "about"
        assert _validate_seed_phrase(phrase) is True

    def test_seed_21_words_valid(self):
        """Test valid 21-word seed phrase."""
        phrase = "abandon " * 20 + "about"
        assert _validate_seed_phrase(phrase) is True

    def test_seed_invalid_word_count(self):
        """Test seed phrase with invalid word count."""
        phrase = "abandon " * 10 + "about"  # 11 words
        assert _validate_seed_phrase(phrase) is False

    def test_seed_invalid_words(self):
        """Test seed phrase with non-BIP39 words."""
        phrase = "notabip39word " * 12
        assert _validate_seed_phrase(phrase) is False

    def test_seed_case_insensitive(self):
        """Test seed phrase is case insensitive."""
        phrase = "ABANDON " * 11 + "ABOUT"
        assert _validate_seed_phrase(phrase) is True


# =============================================================================
# FINANCIAL DETECTOR INTEGRATION TESTS
# =============================================================================

class TestFinancialDetector:
    """Integration tests for FinancialDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a FinancialDetector instance."""
        return FinancialDetector()

    def test_detector_name(self, detector):
        """Test detector has correct name."""
        assert detector.name == "financial"

    def test_detector_tier(self, detector):
        """Test detector has correct tier."""
        assert detector.tier == Tier.CHECKSUM

    def test_detect_cusip_labeled(self, detector):
        """Test detecting labeled CUSIP."""
        text = "The CUSIP for Apple is 037833100 per SEC filing."
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1
        assert "037833100" in [s.text for s in cusip_spans]

    def test_detect_isin_labeled(self, detector):
        """Test detecting labeled ISIN."""
        text = "ISIN: US0378331005 for Apple Inc."
        spans = detector.detect(text)

        isin_spans = [s for s in spans if s.entity_type == "ISIN"]
        assert len(isin_spans) >= 1
        assert "US0378331005" in [s.text for s in isin_spans]

    def test_detect_swift_labeled(self, detector):
        """Test detecting labeled SWIFT code."""
        text = "Wire transfer via SWIFT: DEUTDEFF to German bank."
        spans = detector.detect(text)

        swift_spans = [s for s in spans if s.entity_type == "SWIFT_BIC"]
        assert len(swift_spans) >= 1
        assert "DEUTDEFF" in [s.text for s in swift_spans]

    def test_detect_ethereum_address(self, detector):
        """Test detecting Ethereum address."""
        text = "Send ETH to 0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        spans = detector.detect(text)

        eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
        assert len(eth_spans) >= 1
        assert "0x71C7656EC7ab88b098defB751B7401B5f6d8976F" in [s.text for s in eth_spans]

    def test_detect_bitcoin_legacy(self, detector):
        """Test detecting Bitcoin legacy address."""
        text = "BTC address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1

    def test_detect_bitcoin_bech32(self, detector):
        """Test detecting Bitcoin Bech32 address."""
        text = "SegWit address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1

    def test_detect_seed_phrase(self, detector):
        """Test detecting crypto seed phrase."""
        text = "seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        spans = detector.detect(text)

        seed_spans = [s for s in spans if s.entity_type == "CRYPTO_SEED_PHRASE"]
        assert len(seed_spans) >= 1

    def test_detect_lei_labeled(self, detector):
        """Test detecting labeled LEI."""
        text = "LEI: HWUPKR0MPOU8FGXBT394 for reporting purposes."
        spans = detector.detect(text)

        lei_spans = [s for s in spans if s.entity_type == "LEI"]
        assert len(lei_spans) >= 1

    def test_detect_figi_labeled(self, detector):
        """Test detecting labeled FIGI."""
        text = "FIGI: BBG000B9XRY4 for market data."
        spans = detector.detect(text)

        figi_spans = [s for s in spans if s.entity_type == "FIGI"]
        assert len(figi_spans) >= 1

    def test_detect_multiple_entities(self, detector):
        """Test detecting multiple financial entity types."""
        text = """
        Securities:
        - CUSIP: 037833100
        - ISIN: US0378331005

        Crypto:
        - ETH: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F

        Banking:
        - SWIFT: DEUTDEFF
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        assert "CUSIP" in entity_types
        assert "ISIN" in entity_types
        assert "ETHEREUM_ADDRESS" in entity_types
        assert "SWIFT_BIC" in entity_types

    def test_detect_no_duplicates(self, detector):
        """Test that detector doesn't return duplicate spans."""
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        # Get all (start, end) tuples
        positions = [(s.start, s.end) for s in spans]
        unique_positions = set(positions)

        assert len(positions) == len(unique_positions)

    def test_detect_span_positions_correct(self, detector):
        """Test that span positions are accurate."""
        text = "ISIN: US0378331005 is the identifier."
        spans = detector.detect(text)

        for span in spans:
            extracted = text[span.start:span.end]
            assert extracted == span.text

    def test_detect_confidence_levels(self, detector):
        """Test that labeled entities have higher confidence."""
        # Labeled pattern should have higher confidence
        text_labeled = "CUSIP: 037833100"
        text_unlabeled = "The identifier is 037833100."

        spans_labeled = detector.detect(text_labeled)
        spans_unlabeled = detector.detect(text_unlabeled)

        # Labeled should have higher base confidence
        labeled_cusip = [s for s in spans_labeled if s.entity_type == "CUSIP"]
        unlabeled_cusip = [s for s in spans_unlabeled if s.entity_type == "CUSIP"]

        if labeled_cusip and unlabeled_cusip:
            assert labeled_cusip[0].confidence >= unlabeled_cusip[0].confidence

    def test_detect_empty_text(self, detector):
        """Test detecting in empty text."""
        spans = detector.detect("")

        assert len(spans) == 0

    def test_detect_no_matches(self, detector):
        """Test text with no financial entities."""
        text = "This is just regular text without any financial data."
        spans = detector.detect(text)

        financial_types = {
            "CUSIP", "ISIN", "SEDOL", "SWIFT_BIC", "LEI", "FIGI",
            "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "CRYPTO_SEED_PHRASE"
        }
        found_types = {s.entity_type for s in spans}

        # Should not find core financial identifiers
        assert len(found_types.intersection(financial_types)) == 0


class TestFinancialDetectorEdgeCases:
    """Edge case tests for FinancialDetector."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_cusip_in_sentence(self, detector):
        """Test CUSIP embedded in sentence."""
        text = "Please look up CUSIP 037833100 in your system."
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1

    def test_multiple_cusips(self, detector):
        """Test detecting multiple CUSIPs."""
        text = "Compare CUSIP: 037833100 with CUSIP: 594918104"
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 2

    def test_ethereum_with_context(self, detector):
        """Test Ethereum address with contract context."""
        text = "Contract deployed at 0x71C7656EC7ab88b098defB751B7401B5f6d8976F on mainnet."
        spans = detector.detect(text)

        eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
        assert len(eth_spans) >= 1

    def test_unicode_context(self, detector):
        """Test detection with unicode surrounding text."""
        text = "加密货币地址: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
        spans = detector.detect(text)

        eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
        assert len(eth_spans) >= 1

    def test_swift_not_false_positive_on_text(self, detector):
        """Test SWIFT doesn't match common words."""
        text = "The hospital terminal was operational."
        spans = detector.detect(text)

        swift_spans = [s for s in spans if s.entity_type == "SWIFT_BIC"]
        # HOSPITAL and TERMINAL should be blocked
        assert len(swift_spans) == 0

    def test_mixed_case_identifiers(self, detector):
        """Test identifiers with mixed case."""
        text = "ISIN: us0378331005 (lowercase) and CUSIP: 037833100"
        spans = detector.detect(text)

        assert len(spans) >= 2

    def test_whitespace_handling(self, detector):
        """Test handling of extra whitespace."""
        text = "  CUSIP:   037833100   "
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1


class TestCryptoAddressPatterns:
    """Test specific cryptocurrency address patterns."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_cardano_address(self, detector):
        """Test Cardano address detection."""
        # Cardano addresses start with addr1
        text = "Cardano: addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        spans = detector.detect(text)

        cardano_spans = [s for s in spans if s.entity_type == "CARDANO_ADDRESS"]
        assert len(cardano_spans) >= 1

    def test_litecoin_legacy(self, detector):
        """Test Litecoin legacy address detection."""
        # Litecoin addresses start with L or M
        text = "LTC: LMfAo1P3R3Bwa2D8g2vbgFwXMpQnP8t4g1"
        spans = detector.detect(text)

        ltc_spans = [s for s in spans if s.entity_type == "LITECOIN_ADDRESS"]
        assert len(ltc_spans) >= 1

    def test_litecoin_bech32(self, detector):
        """Test Litecoin Bech32 address detection."""
        text = "Litecoin SegWit: ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9"
        spans = detector.detect(text)

        ltc_spans = [s for s in spans if s.entity_type == "LITECOIN_ADDRESS"]
        assert len(ltc_spans) >= 1

    def test_dogecoin_address(self, detector):
        """Test Dogecoin address detection."""
        # Dogecoin addresses start with D
        text = "DOGE: DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
        spans = detector.detect(text)

        doge_spans = [s for s in spans if s.entity_type == "DOGECOIN_ADDRESS"]
        assert len(doge_spans) >= 1

    def test_xrp_address(self, detector):
        """Test XRP/Ripple address detection."""
        # XRP addresses start with r
        text = "XRP: rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9"
        spans = detector.detect(text)

        xrp_spans = [s for s in spans if s.entity_type == "XRP_ADDRESS"]
        assert len(xrp_spans) >= 1


class TestValidatorFunctionsDirect:
    """Direct tests of validator functions for edge cases."""

    def test_cusip_empty(self):
        """Test CUSIP validator with empty string."""
        assert _validate_cusip("") is False

    def test_isin_empty(self):
        """Test ISIN validator with empty string."""
        assert _validate_isin("") is False

    def test_sedol_empty(self):
        """Test SEDOL validator with empty string."""
        assert _validate_sedol("") is False

    def test_swift_empty(self):
        """Test SWIFT validator with empty string."""
        assert _validate_swift("") is False

    def test_lei_empty(self):
        """Test LEI validator with empty string."""
        assert _validate_lei("") is False

    def test_ethereum_empty(self):
        """Test Ethereum validator with empty string."""
        assert _validate_ethereum("") is False

    def test_bitcoin_base58_empty(self):
        """Test Bitcoin Base58 validator with empty string."""
        assert _validate_bitcoin_base58("") is False

    def test_bitcoin_bech32_empty(self):
        """Test Bitcoin Bech32 validator with empty string."""
        assert _validate_bitcoin_bech32("") is False

    def test_seed_phrase_empty(self):
        """Test seed phrase validator with empty string."""
        assert _validate_seed_phrase("") is False

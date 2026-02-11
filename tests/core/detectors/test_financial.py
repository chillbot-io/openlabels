"""
Comprehensive tests for the Financial Detector.

Tests detection of financial security identifiers and cryptocurrency addresses,
with checksum validation where applicable.

Entity Types tested:
- CUSIP: Committee on Uniform Securities Identification (9 chars)
- ISIN: International Securities Identification Number (12 chars)
- SEDOL: Stock Exchange Daily Official List (7 chars, UK)
- SWIFT_BIC: Bank Identifier Code (8 or 11 chars)
- FIGI: Financial Instrument Global Identifier (12 chars)
- LEI: Legal Entity Identifier (20 chars)
- BITCOIN_ADDRESS: Bitcoin wallet addresses (all formats)
- ETHEREUM_ADDRESS: Ethereum wallet addresses (0x + 40 hex)
- CRYPTO_SEED_PHRASE: BIP-39 mnemonic seed phrases
- SOLANA_ADDRESS, CARDANO_ADDRESS, LITECOIN_ADDRESS, etc.
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
# DETECTOR INITIALIZATION TESTS
# =============================================================================

# =============================================================================
# CUSIP VALIDATION TESTS
# =============================================================================

class TestCUSIPValidation:
    """Test CUSIP checksum validation."""

    def test_valid_cusip_apple(self):
        """Test valid CUSIP for Apple Inc."""
        assert _validate_cusip("037833100") is True

    def test_valid_cusip_microsoft(self):
        """Test valid CUSIP for Microsoft."""
        assert _validate_cusip("594918104") is True

    def test_valid_cusip_amazon(self):
        """Test valid CUSIP for Amazon."""
        assert _validate_cusip("023135106") is True

    def test_valid_cusip_cisco(self):
        """Test valid CUSIP with letters (Cisco)."""
        assert _validate_cusip("17275R102") is True

    def test_valid_cusip_google(self):
        """Test valid CUSIP for Alphabet/Google."""
        assert _validate_cusip("02079K305") is True

    def test_invalid_cusip_wrong_checksum(self):
        """Test CUSIP with wrong check digit fails."""
        assert _validate_cusip("037833101") is False
        assert _validate_cusip("594918105") is False
        assert _validate_cusip("023135107") is False

    def test_invalid_cusip_wrong_length_short(self):
        """Test CUSIP with too few characters fails."""
        assert _validate_cusip("03783310") is False
        assert _validate_cusip("0378331") is False

    def test_invalid_cusip_wrong_length_long(self):
        """Test CUSIP with too many characters fails."""
        assert _validate_cusip("0378331000") is False
        assert _validate_cusip("03783310012") is False

    def test_cusip_with_spaces(self):
        """Test CUSIP validation handles spaces."""
        assert _validate_cusip("037 833 100") is True

    def test_cusip_with_dashes(self):
        """Test CUSIP validation handles dashes."""
        assert _validate_cusip("037-833-100") is True

    def test_cusip_lowercase(self):
        """Test CUSIP validation handles lowercase."""
        assert _validate_cusip("17275r102") is True

    def test_cusip_with_special_chars(self):
        """Test CUSIP with special characters (* @ #)."""
        # The validator strips non-alphanumeric characters, so * is removed.
        # "0378331*0" becomes "03783310" (8 chars) which is too short -> False
        assert _validate_cusip("0378331*0") is False
        # A fully alphanumeric CUSIP with correct checksum should pass
        assert _validate_cusip("037833100") is True


# =============================================================================
# ISIN VALIDATION TESTS
# =============================================================================

class TestISINValidation:
    """Test ISIN checksum validation using Luhn algorithm."""

    def test_valid_isin_apple_us(self):
        """Test valid ISIN for Apple (US)."""
        assert _validate_isin("US0378331005") is True

    def test_valid_isin_microsoft_us(self):
        """Test valid ISIN for Microsoft (US)."""
        assert _validate_isin("US5949181045") is True

    def test_valid_isin_bp_uk(self):
        """Test valid ISIN for BP (UK)."""
        assert _validate_isin("GB0007980591") is True

    def test_valid_isin_siemens_de(self):
        """Test valid ISIN for Siemens (Germany)."""
        assert _validate_isin("DE0007236101") is True

    def test_valid_isin_toyota_jp(self):
        """Test valid ISIN for Toyota (Japan)."""
        assert _validate_isin("JP3633400001") is True

    def test_invalid_isin_wrong_checksum(self):
        """Test ISIN with wrong check digit fails."""
        assert _validate_isin("US0378331006") is False
        assert _validate_isin("US0378331007") is False

    def test_invalid_isin_wrong_length_short(self):
        """Test ISIN with too few characters fails."""
        assert _validate_isin("US037833100") is False
        assert _validate_isin("US03783310") is False

    def test_invalid_isin_wrong_length_long(self):
        """Test ISIN with too many characters fails."""
        assert _validate_isin("US03783310050") is False
        assert _validate_isin("US037833100512") is False

    def test_invalid_isin_bad_country_code(self):
        """Test ISIN with numeric country code fails."""
        assert _validate_isin("123378331005") is False
        assert _validate_isin("11378331005X") is False

    def test_isin_with_spaces(self):
        """Test ISIN validation handles spaces."""
        assert _validate_isin("US 0378 3310 05") is True

    def test_isin_lowercase(self):
        """Test ISIN validation handles lowercase."""
        assert _validate_isin("us0378331005") is True


# =============================================================================
# SEDOL VALIDATION TESTS
# =============================================================================

class TestSEDOLValidation:
    """Test SEDOL checksum validation."""

    def test_valid_sedol_example1(self):
        """Test valid SEDOL number."""
        assert _validate_sedol("0263494") is True

    def test_valid_sedol_example2(self):
        """Test valid SEDOL with letters."""
        assert _validate_sedol("B0WNLY7") is True

    def test_valid_sedol_bp(self):
        """Test valid SEDOL for BP."""
        assert _validate_sedol("0263494") is True

    def test_invalid_sedol_wrong_checksum(self):
        """Test SEDOL with wrong check digit fails."""
        assert _validate_sedol("0263495") is False
        assert _validate_sedol("B0WNLY8") is False

    def test_invalid_sedol_wrong_length_short(self):
        """Test SEDOL with too few characters fails."""
        assert _validate_sedol("026349") is False
        assert _validate_sedol("02634") is False

    def test_invalid_sedol_wrong_length_long(self):
        """Test SEDOL with too many characters fails."""
        assert _validate_sedol("02634944") is False
        assert _validate_sedol("026349445") is False

    def test_sedol_with_vowels_rejected(self):
        """Test SEDOL with vowels is rejected (SEDOL doesn't use vowels)."""
        assert _validate_sedol("A263494") is False
        assert _validate_sedol("E263494") is False
        assert _validate_sedol("I263494") is False
        assert _validate_sedol("O263494") is False
        assert _validate_sedol("U263494") is False

    def test_sedol_uppercase(self):
        """Test SEDOL validation handles uppercase."""
        assert _validate_sedol("B0WNLY7") is True

    def test_sedol_lowercase(self):
        """Test SEDOL validation handles lowercase."""
        assert _validate_sedol("b0wnly7") is True


# =============================================================================
# SWIFT/BIC VALIDATION TESTS
# =============================================================================

class TestSWIFTValidation:
    """Test SWIFT/BIC code validation."""

    def test_valid_swift_8_chars(self):
        """Test valid 8-character SWIFT code."""
        assert _validate_swift("CHASUS33") is True  # Chase US

    def test_valid_swift_11_chars(self):
        """Test valid 11-character SWIFT code with branch."""
        assert _validate_swift("CHASUS33XXX") is True
        assert _validate_swift("BOFAUS3NXXX") is True

    def test_valid_swift_various_banks(self):
        """Test valid SWIFT codes for various banks."""
        assert _validate_swift("DEUTDEFF") is True  # Deutsche Bank
        assert _validate_swift("HSBCGB2L") is True  # HSBC UK
        assert _validate_swift("BNPAFRPP") is True  # BNP Paribas

    def test_invalid_swift_wrong_length(self):
        """Test SWIFT with wrong length fails."""
        assert _validate_swift("CHASUS3") is False  # 7 chars
        assert _validate_swift("CHASUS333") is False  # 9 chars
        assert _validate_swift("CHASUS3333") is False  # 10 chars

    def test_invalid_swift_numeric_bank_code(self):
        """Test SWIFT with numeric bank code fails."""
        assert _validate_swift("1234US33") is False

    def test_invalid_swift_numeric_country_code(self):
        """Test SWIFT with numeric country code fails."""
        assert _validate_swift("CHAS1233") is False

    def test_swift_false_positive_words(self):
        """Test common words that look like SWIFT codes are rejected."""
        assert _validate_swift("HOSPITAL") is False
        assert _validate_swift("NATIONAL") is False
        assert _validate_swift("REFERRAL") is False
        assert _validate_swift("TERMINAL") is False

    def test_swift_lowercase(self):
        """Test SWIFT validation handles lowercase."""
        assert _validate_swift("chasus33") is True


# =============================================================================
# LEI VALIDATION TESTS
# =============================================================================

class TestLEIValidation:
    """Test Legal Entity Identifier (LEI) validation."""

    def test_valid_lei(self):
        """Test valid LEI numbers."""
        # LEI uses ISO 7064 Mod 97-10 checksum
        # Valid LEI: The numeric representation mod 97 must equal 1
        # Using known valid format: 7ZW8QJWVPR4P1J1KQY45
        assert _validate_lei("7ZW8QJWVPR4P1J1KQY45") is True

    def test_invalid_lei_wrong_length(self):
        """Test LEI with wrong length fails."""
        assert _validate_lei("549300JQTO6B1RL9237") is False  # 19 chars
        assert _validate_lei("549300JQTO6B1RL923771") is False  # 21 chars

    def test_invalid_lei_wrong_checksum(self):
        """Test LEI with wrong checksum fails."""
        assert _validate_lei("549300JQTO6B1RL92376") is False
        assert _validate_lei("549300JQTO6B1RL92378") is False

    def test_invalid_lei_non_alphanumeric(self):
        """Test LEI with non-alphanumeric chars fails."""
        assert _validate_lei("549300JQTO6B1RL923-7") is False


# =============================================================================
# BITCOIN ADDRESS VALIDATION TESTS
# =============================================================================

class TestBitcoinAddressValidation:
    """Test Bitcoin address validation."""

    def test_valid_p2pkh_address_starting_with_1(self):
        """Test valid P2PKH (legacy) address starting with 1."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is True

    def test_valid_p2sh_address_starting_with_3(self):
        """Test valid P2SH address starting with 3."""
        assert _validate_bitcoin_base58("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is True

    def test_invalid_base58_wrong_checksum(self):
        """Test Base58 address with wrong checksum fails."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3") is False

    def test_invalid_base58_wrong_prefix(self):
        """Test Base58 address with wrong prefix fails."""
        assert _validate_bitcoin_base58("0BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False
        assert _validate_bitcoin_base58("2BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False

    def test_invalid_base58_too_short(self):
        """Test Base58 address that's too short fails."""
        assert _validate_bitcoin_base58("1BvBMSEY") is False

    def test_invalid_base58_too_long(self):
        """Test Base58 address that's too long fails."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2EXTRA") is False

    def test_invalid_base58_invalid_chars(self):
        """Test Base58 address with invalid characters fails."""
        # Base58 doesn't include 0, O, I, l
        assert _validate_bitcoin_base58("0BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False

    def test_valid_bech32_p2wpkh(self):
        """Test valid Bech32 SegWit P2WPKH address (bc1q...)."""
        assert _validate_bitcoin_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") is True

    def test_valid_bech32_p2wsh(self):
        """Test valid Bech32 SegWit P2WSH address."""
        # P2WSH addresses are 62 characters total
        addr = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        assert _validate_bitcoin_bech32(addr) is True

    def test_valid_bech32_taproot(self):
        """Test valid Bech32m Taproot address (bc1p...)."""
        # Taproot addresses start with bc1p and are 62 chars
        addr = "bc1p" + "q" * 58
        assert _validate_bitcoin_bech32(addr) is True

    def test_invalid_bech32_wrong_prefix(self):
        """Test Bech32 address with wrong prefix fails."""
        assert _validate_bitcoin_bech32("tb1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") is False

    def test_invalid_bech32_too_short(self):
        """Test Bech32 address that's too short fails."""
        assert _validate_bitcoin_bech32("bc1qar0srrr") is False

    def test_bech32_case_insensitive(self):
        """Test Bech32 validation is case insensitive."""
        assert _validate_bitcoin_bech32("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ") is True


# =============================================================================
# ETHEREUM ADDRESS VALIDATION TESTS
# =============================================================================

class TestEthereumAddressValidation:
    """Test Ethereum address validation."""

    def test_valid_ethereum_lowercase(self):
        """Test valid lowercase Ethereum address."""
        assert _validate_ethereum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae") is True

    def test_valid_ethereum_uppercase(self):
        """Test valid uppercase Ethereum address."""
        assert _validate_ethereum("0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE") is True

    def test_valid_ethereum_mixed_case_eip55(self):
        """Test valid mixed-case Ethereum address (EIP-55 checksum)."""
        assert _validate_ethereum("0xDe0B295669a9FD93d5F28D9Ec85E40f4cb697BAe") is True

    def test_invalid_ethereum_wrong_length_short(self):
        """Test Ethereum address that's too short fails."""
        assert _validate_ethereum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697ba") is False

    def test_invalid_ethereum_wrong_length_long(self):
        """Test Ethereum address that's too long fails."""
        assert _validate_ethereum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697baee") is False

    def test_invalid_ethereum_no_prefix(self):
        """Test Ethereum address without 0x prefix fails."""
        assert _validate_ethereum("de0b295669a9fd93d5f28d9ec85e40f4cb697bae") is False

    def test_invalid_ethereum_invalid_hex(self):
        """Test Ethereum address with invalid hex chars fails."""
        assert _validate_ethereum("0xge0b295669a9fd93d5f28d9ec85e40f4cb697bae") is False
        assert _validate_ethereum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697baz") is False


# =============================================================================
# SEED PHRASE VALIDATION TESTS
# =============================================================================

class TestSeedPhraseValidation:
    """Test BIP-39 seed phrase validation."""

    def test_valid_12_word_seed(self):
        """Test valid 12-word seed phrase."""
        phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        assert _validate_seed_phrase(phrase) is True

    def test_valid_24_word_seed(self):
        """Test valid 24-word seed phrase."""
        phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident abandon ability able about above absent absorb abstract absurd abuse access zoo"
        assert _validate_seed_phrase(phrase) is True

    def test_invalid_seed_wrong_word_count(self):
        """Test seed phrase with wrong word count fails."""
        # 10 words (invalid)
        phrase = "abandon ability able about above absent absorb abstract absurd abuse"
        assert _validate_seed_phrase(phrase) is False

        # 13 words (invalid)
        phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident zone"
        assert _validate_seed_phrase(phrase) is False

    def test_valid_seed_word_counts(self):
        """Test valid seed phrase word counts (12, 15, 18, 21, 24)."""
        base_words = ["abandon", "ability", "able", "about", "above", "absent",
                      "absorb", "abstract", "absurd", "abuse", "access", "accident"]

        # 12 words
        assert _validate_seed_phrase(" ".join(base_words[:12])) is True

        # 15 words
        assert _validate_seed_phrase(" ".join(base_words[:12] + ["zoo", "zero", "zone"])) is True


# =============================================================================
# FINANCIAL DETECTOR INTEGRATION TESTS
# =============================================================================

class TestFinancialDetectorDetection:
    """Test FinancialDetector detect() method."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_detect_cusip_labeled(self, detector):
        """Test CUSIP detection with label."""
        text = "Buy shares of Apple Inc (CUSIP: 037833100)"
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1
        assert any(s.text == "037833100" for s in cusip_spans)

    def test_detect_cusip_unlabeled(self, detector):
        """Test CUSIP detection without label."""
        text = "The security identifier is 037833100"
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1
        assert any(s.text == "037833100" for s in cusip_spans)

    def test_detect_isin_labeled(self, detector):
        """Test ISIN detection with label."""
        text = "The security has ISIN US0378331005"
        spans = detector.detect(text)

        isin_spans = [s for s in spans if s.entity_type == "ISIN"]
        assert len(isin_spans) >= 1
        assert any(s.text == "US0378331005" for s in isin_spans)

    def test_detect_isin_unlabeled(self, detector):
        """Test ISIN detection without label."""
        text = "Trade reference: US0378331005"
        spans = detector.detect(text)

        isin_spans = [s for s in spans if s.entity_type == "ISIN"]
        assert len(isin_spans) >= 1
        assert any(s.text == "US0378331005" for s in isin_spans)

    def test_detect_sedol_labeled(self, detector):
        """Test SEDOL detection with label."""
        text = "London listed security SEDOL: 0263494"
        spans = detector.detect(text)

        sedol_spans = [s for s in spans if s.entity_type == "SEDOL"]
        assert len(sedol_spans) >= 1
        assert any(s.text == "0263494" for s in sedol_spans)

    def test_detect_swift_labeled(self, detector):
        """Test SWIFT/BIC detection with label."""
        text = "Wire transfer to SWIFT: CHASUS33XXX"
        spans = detector.detect(text)

        swift_spans = [s for s in spans if s.entity_type == "SWIFT_BIC"]
        assert len(swift_spans) >= 1
        assert any(s.text == "CHASUS33XXX" for s in swift_spans)

    def test_detect_figi_labeled(self, detector):
        """Test FIGI detection with label."""
        text = "Bloomberg identifier FIGI: BBG000B9XRY4"
        spans = detector.detect(text)

        figi_spans = [s for s in spans if s.entity_type == "FIGI"]
        assert len(figi_spans) >= 1
        assert any(s.text == "BBG000B9XRY4" for s in figi_spans)

    def test_detect_figi_bbg_prefix(self, detector):
        """Test FIGI detection with BBG prefix."""
        text = "Security BBG000B9XRY4 is available"
        spans = detector.detect(text)

        figi_spans = [s for s in spans if s.entity_type == "FIGI"]
        assert len(figi_spans) >= 1
        assert any(s.text == "BBG000B9XRY4" for s in figi_spans)

    def test_detect_lei_labeled(self, detector):
        """Test LEI detection with label."""
        text = "Entity LEI: 7ZW8QJWVPR4P1J1KQY45"
        spans = detector.detect(text)

        lei_spans = [s for s in spans if s.entity_type == "LEI"]
        assert len(lei_spans) >= 1
        assert any(s.text == "7ZW8QJWVPR4P1J1KQY45" for s in lei_spans)

    def test_detect_bitcoin_legacy_address(self, detector):
        """Test Bitcoin legacy address detection."""
        text = "Send payment to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1
        assert any(s.text == "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" for s in btc_spans)

    def test_detect_bitcoin_p2sh_address(self, detector):
        """Test Bitcoin P2SH address detection."""
        text = "P2SH address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1
        assert any(s.text == "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" for s in btc_spans)

    def test_detect_bitcoin_bech32_address(self, detector):
        """Test Bitcoin SegWit Bech32 address detection."""
        text = "SegWit address: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1
        assert any(s.text == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" for s in btc_spans)

    def test_detect_ethereum_address(self, detector):
        """Test Ethereum address detection."""
        text = "ETH wallet: 0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
        spans = detector.detect(text)

        eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
        assert len(eth_spans) >= 1
        assert any(s.text == "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae" for s in eth_spans)

    def test_detect_cardano_address(self, detector):
        """Test Cardano address detection."""
        text = "ADA address: addr1qxqs59lphg8g6qndelq8xwqn60ag3aeyfcp33c2kdp46a09re5df3pzwwmyq946axfcejy5n4x0y99wqpgtp2gd0k09qsgy6pz5"
        spans = detector.detect(text)

        ada_spans = [s for s in spans if s.entity_type == "CARDANO_ADDRESS"]
        assert len(ada_spans) >= 1
        assert any(s.text.startswith("addr1") for s in ada_spans)

    def test_detect_litecoin_address_legacy(self, detector):
        """Test Litecoin legacy address detection."""
        text = "LTC address: LbTjAfJzh9fMCXBP5Q8bVNuT4XHuVw9eNi"
        spans = detector.detect(text)

        ltc_spans = [s for s in spans if s.entity_type == "LITECOIN_ADDRESS"]
        assert len(ltc_spans) >= 1
        assert any(s.text.startswith("L") for s in ltc_spans)

    def test_detect_litecoin_address_bech32(self, detector):
        """Test Litecoin Bech32 address detection."""
        text = "LTC SegWit: ltc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdqq"
        spans = detector.detect(text)

        ltc_spans = [s for s in spans if s.entity_type == "LITECOIN_ADDRESS"]
        assert len(ltc_spans) >= 1
        assert any(s.text.startswith("ltc1") for s in ltc_spans)


# =============================================================================
# FALSE POSITIVE TESTS
# =============================================================================

class TestFinancialFalsePositives:
    """Test false positive prevention."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_no_false_positive_normal_text(self, detector):
        """Test normal text is not flagged."""
        text = "The quick brown fox jumps over the lazy dog."
        spans = detector.detect(text)
        assert len(spans) == 0

    def test_no_false_positive_random_numbers(self, detector):
        """Test random number sequences aren't flagged as CUSIPs."""
        text = "Reference number: 123456789"
        spans = detector.detect(text)

        # Should not be flagged as CUSIP (wrong checksum)
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) == 0

    def test_no_false_positive_swift_like_words(self, detector):
        """Test common words aren't flagged as SWIFT codes."""
        text = "The hospital admission was referred by the terminal doctor."
        spans = detector.detect(text)

        swift_spans = [s for s in spans if s.entity_type == "SWIFT_BIC"]
        assert len(swift_spans) == 0

    def test_no_false_positive_invalid_bitcoin(self, detector):
        """Test invalid Bitcoin addresses aren't flagged."""
        # Invalid checksum
        text = "Invalid BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) == 0

    def test_no_false_positive_invalid_ethereum(self, detector):
        """Test invalid Ethereum addresses aren't flagged."""
        # Wrong length
        text = "Invalid ETH: 0xde0b295669a9fd93d5f28d9ec85e40f4cb697ba"
        spans = detector.detect(text)

        eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
        assert len(eth_spans) == 0


# =============================================================================
# EDGE CASES
# =============================================================================

class TestFinancialEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_empty_string(self, detector):
        """Test empty string input."""
        spans = detector.detect("")
        assert spans == []

    def test_whitespace_only(self, detector):
        """Test whitespace-only input."""
        spans = detector.detect("   \n\t  ")
        assert spans == []

    def test_multiple_identifiers_in_text(self, detector):
        """Test detecting multiple identifiers in one text."""
        text = """
        CUSIP: 037833100
        ISIN: US0378331005
        Bitcoin: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
        Ethereum: 0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        assert "CUSIP" in entity_types
        assert "ISIN" in entity_types
        assert "BITCOIN_ADDRESS" in entity_types
        assert "ETHEREUM_ADDRESS" in entity_types

    def test_identifier_in_json(self, detector):
        """Test identifier detection in JSON format."""
        text = '{"cusip": "037833100", "isin": "US0378331005"}'
        spans = detector.detect(text)

        # The unlabeled CUSIP pattern should match 037833100 (valid checksum)
        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1
        assert any(s.text == "037833100" for s in cusip_spans)

        # The unlabeled ISIN pattern should match US0378331005 (valid checksum)
        isin_spans = [s for s in spans if s.entity_type == "ISIN"]
        assert len(isin_spans) >= 1
        assert any(s.text == "US0378331005" for s in isin_spans)

    def test_span_positions_valid(self, detector):
        """Test that span positions are correct."""
        text = "Buy CUSIP 037833100 shares"
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)
            assert text[span.start:span.end] == span.text

    def test_validator_boosts_confidence(self, detector):
        """Test that validated identifiers get confidence boost."""
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1, "CUSIP should be detected"
        # Labeled CUSIP pattern has confidence 0.98, validator adds +0.02 (capped at 0.99)
        # So validated labeled CUSIP should have confidence >= 0.99
        assert all(s.confidence >= 0.99 for s in cusip_spans)


# =============================================================================
# SPAN VALIDATION TESTS
# =============================================================================

class TestFinancialSpanValidation:
    """Test span properties and validation."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_span_has_correct_detector_name(self, detector):
        """Test spans have correct detector name."""
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        for span in spans:
            assert span.detector == "financial"

    def test_span_has_correct_tier(self, detector):
        """Test spans have correct tier."""
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        for span in spans:
            assert span.tier == Tier.CHECKSUM

    def test_span_text_matches_position(self, detector):
        """Test span text matches extracted position."""
        text = "prefix CUSIP: 037833100 suffix"
        spans = detector.detect(text)

        for span in spans:
            extracted = text[span.start:span.end]
            assert extracted == span.text

    def test_no_duplicate_spans(self, detector):
        """Test no duplicate spans are returned."""
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        # Check for exact duplicates
        seen = set()
        for span in spans:
            key = (span.start, span.end, span.entity_type)
            assert key not in seen, f"Duplicate span found: {key}"
            seen.add(key)


# =============================================================================
# CRYPTOCURRENCY COMPREHENSIVE TESTS
# =============================================================================

class TestCryptocurrencyComprehensive:
    """Comprehensive tests for cryptocurrency address detection."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_bitcoin_in_various_contexts(self, detector):
        """Test Bitcoin detection in various text contexts."""
        contexts = [
            "Payment address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "Send BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 please",
            "wallet=1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        ]

        for context in contexts:
            spans = detector.detect(context)
            btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
            assert len(btc_spans) >= 1, f"Failed to detect Bitcoin in: {context}"

    def test_ethereum_mixed_case(self, detector):
        """Test Ethereum detection handles mixed case."""
        addresses = [
            "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",  # lowercase
            "0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE",  # uppercase
            "0xDe0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",  # mixed (EIP-55)
        ]

        for addr in addresses:
            spans = detector.detect(f"ETH: {addr}")
            eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
            assert len(eth_spans) >= 1, f"Failed to detect Ethereum: {addr}"

    def test_multiple_crypto_types(self, detector):
        """Test detecting multiple cryptocurrency types."""
        text = """
        Portfolio:
        BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
        ETH: 0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae
        """
        spans = detector.detect(text)

        btc_spans = [s for s in spans if "BITCOIN" in s.entity_type]
        eth_spans = [s for s in spans if "ETHEREUM" in s.entity_type]

        assert len(btc_spans) >= 1
        assert len(eth_spans) >= 1

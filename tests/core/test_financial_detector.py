"""
Tests for the Financial Detector.

Tests pattern matching, checksum validation, and cryptocurrency addresses.
Adapted from openrisk/tests/test_scanner/test_financial_detector.py
"""

import pytest
from openlabels.core.detectors.financial import (
    FinancialDetector,
    _validate_cusip,
    _validate_isin,
    _validate_sedol,
    _validate_bitcoin_base58,
    _validate_bitcoin_bech32,
    _validate_ethereum,
)


class TestCUSIPValidation:
    """Test CUSIP checksum validation."""

    def test_valid_cusip(self):
        """Test valid CUSIP numbers pass validation."""
        assert _validate_cusip("037833100") is True  # Apple
        assert _validate_cusip("594918104") is True  # Microsoft
        assert _validate_cusip("023135106") is True  # Amazon

    def test_invalid_cusip_wrong_checksum(self):
        """Test CUSIP with wrong check digit fails."""
        assert _validate_cusip("037833101") is False
        assert _validate_cusip("594918105") is False

    def test_invalid_cusip_wrong_length(self):
        """Test CUSIP with wrong length fails."""
        assert _validate_cusip("03783310") is False
        assert _validate_cusip("0378331000") is False

    def test_cusip_with_letters(self):
        """Test CUSIP with alphanumeric characters."""
        assert _validate_cusip("17275R102") is True  # Cisco


class TestISINValidation:
    """Test ISIN checksum validation."""

    def test_valid_isin(self):
        """Test valid ISIN numbers pass validation."""
        assert _validate_isin("US0378331005") is True  # Apple
        assert _validate_isin("US5949181045") is True  # Microsoft
        assert _validate_isin("GB0007980591") is True  # BP

    def test_invalid_isin_wrong_checksum(self):
        """Test ISIN with wrong check digit fails."""
        assert _validate_isin("US0378331006") is False

    def test_invalid_isin_wrong_length(self):
        """Test ISIN with wrong length fails."""
        assert _validate_isin("US037833100") is False
        assert _validate_isin("US03783310050") is False


class TestSEDOLValidation:
    """Test SEDOL checksum validation."""

    def test_valid_sedol(self):
        """Test valid SEDOL numbers pass validation."""
        assert _validate_sedol("0263494") is True
        assert _validate_sedol("B0WNLY7") is True

    def test_invalid_sedol_wrong_checksum(self):
        """Test SEDOL with wrong check digit fails."""
        assert _validate_sedol("0263495") is False

    def test_invalid_sedol_wrong_length(self):
        """Test SEDOL with wrong length fails."""
        assert _validate_sedol("026349") is False
        assert _validate_sedol("02634944") is False


class TestBitcoinAddressValidation:
    """Test Bitcoin address validation."""

    def test_valid_p2pkh_address(self):
        """Test valid P2PKH (legacy) addresses starting with 1."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is True

    def test_valid_p2sh_address(self):
        """Test valid P2SH addresses starting with 3."""
        assert _validate_bitcoin_base58("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is True

    def test_valid_bech32_address(self):
        """Test valid Bech32 (SegWit) addresses starting with bc1."""
        assert _validate_bitcoin_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") is True

    def test_invalid_bitcoin_base58_address(self):
        """Test invalid Base58 Bitcoin addresses fail."""
        assert _validate_bitcoin_base58("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3") is False
        assert _validate_bitcoin_base58("0BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is False


class TestEthereumAddressValidation:
    """Test Ethereum address validation."""

    def test_valid_ethereum_address_lowercase(self):
        """Test valid lowercase Ethereum address."""
        assert _validate_ethereum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae") is True

    def test_valid_ethereum_address_mixed_case(self):
        """Test valid mixed-case Ethereum address (EIP-55)."""
        assert _validate_ethereum("0xDe0B295669a9FD93d5F28D9Ec85E40f4cb697BAe") is True

    def test_invalid_ethereum_address_wrong_length(self):
        """Test Ethereum address with wrong length fails."""
        assert _validate_ethereum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697ba") is False
        assert _validate_ethereum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697baee") is False

    def test_invalid_ethereum_address_no_prefix(self):
        """Test Ethereum address without 0x prefix fails."""
        assert _validate_ethereum("de0b295669a9fd93d5f28d9ec85e40f4cb697bae") is False


class TestFinancialDetector:
    """Test the FinancialDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a FinancialDetector instance."""
        return FinancialDetector()

    def test_detector_name(self, detector):
        """Test detector has correct name."""
        assert detector.name == "financial"

    def test_detect_cusip(self, detector):
        """Test CUSIP detection in text."""
        text = "Buy shares of Apple Inc (CUSIP: 037833100)"
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) >= 1
        assert any(s.text == "037833100" for s in cusip_spans)

    def test_detect_isin(self, detector):
        """Test ISIN detection in text."""
        text = "The security has ISIN US0378331005"
        spans = detector.detect(text)

        isin_spans = [s for s in spans if s.entity_type == "ISIN"]
        assert len(isin_spans) >= 1
        assert any(s.text == "US0378331005" for s in isin_spans)

    def test_detect_bitcoin_address(self, detector):
        """Test Bitcoin address detection."""
        text = "Send payment to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        spans = detector.detect(text)

        btc_spans = [s for s in spans if s.entity_type == "BITCOIN_ADDRESS"]
        assert len(btc_spans) >= 1

    def test_detect_ethereum_address(self, detector):
        """Test Ethereum address detection."""
        text = "ETH wallet: 0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
        spans = detector.detect(text)

        eth_spans = [s for s in spans if s.entity_type == "ETHEREUM_ADDRESS"]
        assert len(eth_spans) >= 1

    def test_no_false_positives_on_normal_text(self, detector):
        """Test detector doesn't flag normal text."""
        text = "The quick brown fox jumps over the lazy dog."
        spans = detector.detect(text)
        assert len(spans) == 0

    def test_confidence_scores(self, detector):
        """Test that detected spans have valid confidence scores."""
        text = "CUSIP 037833100 and ISIN US0378331005"
        spans = detector.detect(text)

        for span in spans:
            assert 0.0 <= span.confidence <= 1.0

    def test_tier_is_pattern(self, detector):
        """Test detector uses PATTERN tier (Tier 2)."""
        from openlabels.core.types import Tier
        text = "CUSIP: 037833100"
        spans = detector.detect(text)

        if spans:
            # Financial identifiers are pattern-matched with validation
            assert spans[0].tier in (Tier.PATTERN, Tier.CHECKSUM)


class TestEdgeCases:
    """Edge case tests for financial detector."""

    @pytest.fixture
    def detector(self):
        return FinancialDetector()

    def test_empty_string(self, detector):
        """Test empty string input."""
        spans = detector.detect("")
        assert spans == []

    def test_multiple_crypto_addresses(self, detector):
        """Test detecting multiple crypto addresses."""
        text = """
        BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
        ETH: 0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae
        """
        spans = detector.detect(text)

        btc_spans = [s for s in spans if "BITCOIN" in s.entity_type]
        eth_spans = [s for s in spans if "ETHEREUM" in s.entity_type]

        assert len(btc_spans) >= 1
        assert len(eth_spans) >= 1

    def test_cusip_in_context(self, detector):
        """Test CUSIP detection with surrounding context."""
        text = "Please purchase 1000 shares of CUSIP 037833100 at market price."
        spans = detector.detect(text)

        cusip_spans = [s for s in spans if s.entity_type == "CUSIP"]
        assert len(cusip_spans) == 1
        assert cusip_spans[0].text == "037833100"

"""Tests for EU multilingual PII patterns and validators.

Tests cover:
- Validators: Dutch BSN, French NIR, German Steuer-ID, Greek AMKA/AFM,
  Brazilian CPF/CNPJ, Portuguese NIF, Slovenian EMSO
- Pattern matching: labeled and bare patterns for each country's IDs
- Phone number patterns for EU countries
- False positive rejection (invalid checksums, wrong formats)
"""

import re

import pytest

from openlabels.core.detectors.patterns import (
    _validate_br_cnpj,
    _validate_br_cpf,
    _validate_de_steuer_id,
    _validate_el_afm,
    _validate_el_amka,
    _validate_fr_nir,
    _validate_nl_bsn,
    _validate_pt_nif,
    _validate_si_emso,
    PatternDetector,
)


# ── Validator unit tests ──────────────────────────────────────────────


class TestDutchBSN:
    """Dutch BSN (Burgerservicenummer) validation."""

    def test_valid_bsn(self):
        # Well-known test BSNs
        assert _validate_nl_bsn("111222333") is True

    def test_valid_bsn_with_separators(self):
        assert _validate_nl_bsn("111 222 333") is True

    def test_invalid_bsn_wrong_checksum(self):
        assert _validate_nl_bsn("123456789") is False

    def test_invalid_bsn_wrong_length(self):
        assert _validate_nl_bsn("12345678") is False
        assert _validate_nl_bsn("1234567890") is False

    def test_all_zeros_invalid(self):
        assert _validate_nl_bsn("000000000") is False


class TestFrenchNIR:
    """French NIR (INSEE number) validation."""

    def test_valid_nir(self):
        # Synthetic: 1 85 05 78 006 084 36
        # number = 1850578006084, key = 97 - (1850578006084 % 97)
        number = 1850578006084
        key = 97 - (number % 97)
        nir = f"{number:013d}{key:02d}"
        assert _validate_fr_nir(nir) is True

    def test_invalid_nir_wrong_key(self):
        assert _validate_fr_nir("185057800608400") is False

    def test_invalid_nir_wrong_sex_digit(self):
        assert _validate_fr_nir("385057800608436") is False

    def test_invalid_nir_wrong_length(self):
        assert _validate_fr_nir("18505780060843") is False

    def test_invalid_nir_wrong_month(self):
        # Month 13 is invalid
        assert _validate_fr_nir("185137800608400") is False


class TestGermanSteuerID:
    """German Steuerliche Identifikationsnummer validation."""

    def test_valid_steuer_id(self):
        # Computed via ISO 7064 Mod 11,10 algorithm
        assert _validate_de_steuer_id("12345678903") is True

    def test_invalid_steuer_id_wrong_check(self):
        assert _validate_de_steuer_id("12345678904") is False

    def test_invalid_steuer_id_wrong_length(self):
        assert _validate_de_steuer_id("0247629135") is False
        assert _validate_de_steuer_id("024762913580") is False


class TestGreekAMKA:
    """Greek AMKA (social security number) validation."""

    def test_valid_amka(self):
        # Computed via Luhn: 01/01/70 + serial 00000 + check digit 9
        assert _validate_el_amka("01017000009") is True

    def test_invalid_amka_bad_date(self):
        assert _validate_el_amka("32017000009") is False  # Day 32
        assert _validate_el_amka("01137000009") is False  # Month 13

    def test_invalid_amka_wrong_length(self):
        assert _validate_el_amka("0101000002") is False


class TestGreekAFM:
    """Greek AFM (tax identification number) validation."""

    def test_valid_afm(self):
        # AFM: sum(d[i] * 2^(8-i) for i in 0..7) mod 11 mod 10 == d[8]
        # Test with: 090000045 → check computation
        assert _validate_el_afm("090000045") is True

    def test_invalid_afm_wrong_check(self):
        assert _validate_el_afm("090000046") is False

    def test_invalid_afm_wrong_length(self):
        assert _validate_el_afm("09000004") is False


class TestBrazilianCPF:
    """Brazilian CPF validation."""

    def test_valid_cpf(self):
        # Known valid: 529.982.247-25
        assert _validate_br_cpf("52998224725") is True

    def test_valid_cpf_formatted(self):
        assert _validate_br_cpf("529.982.247-25") is True

    def test_invalid_cpf_all_same(self):
        assert _validate_br_cpf("11111111111") is False
        assert _validate_br_cpf("00000000000") is False

    def test_invalid_cpf_wrong_check(self):
        assert _validate_br_cpf("52998224726") is False

    def test_invalid_cpf_wrong_length(self):
        assert _validate_br_cpf("5299822472") is False


class TestBrazilianCNPJ:
    """Brazilian CNPJ validation."""

    def test_valid_cnpj(self):
        # Known valid: 11.222.333/0001-81
        assert _validate_br_cnpj("11222333000181") is True

    def test_valid_cnpj_formatted(self):
        assert _validate_br_cnpj("11.222.333/0001-81") is True

    def test_invalid_cnpj_all_same(self):
        assert _validate_br_cnpj("11111111111111") is False

    def test_invalid_cnpj_wrong_check(self):
        assert _validate_br_cnpj("11222333000182") is False

    def test_invalid_cnpj_wrong_length(self):
        assert _validate_br_cnpj("1122233300018") is False


class TestPortugueseNIF:
    """Portuguese NIF validation."""

    def test_valid_nif(self):
        # Test NIF: 123456789 → compute check
        # sum(d[i] * (9-i) for i in 0..7) → 1*9+2*8+3*7+4*6+5*5+6*4+7*3+8*2 = 156
        # 156 % 11 = 2, check = 11-2 = 9 ✓
        assert _validate_pt_nif("123456789") is True

    def test_invalid_nif_wrong_check(self):
        assert _validate_pt_nif("123456780") is False

    def test_invalid_nif_wrong_first_digit(self):
        # First digit 0 or 4 is invalid
        assert _validate_pt_nif("023456789") is False
        assert _validate_pt_nif("423456789") is False

    def test_invalid_nif_wrong_length(self):
        assert _validate_pt_nif("12345678") is False


class TestSlovenianEMSO:
    """Slovenian EMSO validation."""

    def test_valid_emso(self):
        # EMSO: DDMMYYY RR SSS C (mod-11 weighted)
        # 0101006500006: 01/01/006 (year 2006), region 50, serial 000, check 6
        # Test with known valid: compute manually
        assert _validate_si_emso("0101006500006") is True

    def test_invalid_emso_bad_date(self):
        assert _validate_si_emso("3201006500006") is False  # Day 32

    def test_invalid_emso_wrong_length(self):
        assert _validate_si_emso("010100650000") is False


# ── Pattern detection integration tests ───────────────────────────────


class TestMultilingualPatternDetection:
    """Test that EU patterns are detected by PatternDetector."""

    @pytest.fixture()
    def detector(self):
        return PatternDetector()

    def test_detect_french_nir_labeled(self, detector):
        text = "Numéro de sécurité sociale: 185057800608436"
        # Compute valid key
        number = 1850578006084
        key = 97 - (number % 97)
        nir = f"{number:013d}{key:02d}"
        text = f"Numéro de sécurité sociale: {nir}"
        spans = detector.detect(text)
        nir_spans = [s for s in spans if s.entity_type == 'FR_NIR']
        assert len(nir_spans) >= 1

    def test_detect_dutch_bsn_labeled(self, detector):
        text = "BSN: 111222333"
        spans = detector.detect(text)
        bsn_spans = [s for s in spans if s.entity_type == 'NL_BSN']
        assert len(bsn_spans) >= 1

    def test_detect_brazilian_cpf_formatted(self, detector):
        text = "CPF: 529.982.247-25"
        spans = detector.detect(text)
        cpf_spans = [s for s in spans if s.entity_type == 'BR_CPF']
        assert len(cpf_spans) >= 1

    def test_detect_brazilian_cpf_bare_formatted(self, detector):
        """Bare CPF in XXX.XXX.XXX-XX format detected via pattern+validator."""
        text = "O número é 529.982.247-25 do contribuinte"
        spans = detector.detect(text)
        cpf_spans = [s for s in spans if s.entity_type == 'BR_CPF']
        assert len(cpf_spans) >= 1

    def test_detect_brazilian_cnpj_formatted(self, detector):
        text = "CNPJ: 11.222.333/0001-81"
        spans = detector.detect(text)
        cnpj_spans = [s for s in spans if s.entity_type == 'BR_CNPJ']
        assert len(cnpj_spans) >= 1

    def test_detect_greek_amka_labeled(self, detector):
        text = "AMKA: 01017000009"
        spans = detector.detect(text)
        amka_spans = [s for s in spans if s.entity_type == 'EL_AMKA']
        assert len(amka_spans) >= 1

    def test_detect_greek_afm_labeled(self, detector):
        text = "AFM: 090000045"
        spans = detector.detect(text)
        afm_spans = [s for s in spans if s.entity_type == 'EL_AFM']
        assert len(afm_spans) >= 1

    def test_detect_portuguese_nif_labeled(self, detector):
        text = "NIF: 123456789"
        spans = detector.detect(text)
        nif_spans = [s for s in spans if s.entity_type == 'PT_NIF']
        assert len(nif_spans) >= 1

    def test_detect_slovenian_emso_labeled(self, detector):
        text = "EMSO: 0101006500006"
        spans = detector.detect(text)
        emso_spans = [s for s in spans if s.entity_type == 'SI_EMSO']
        assert len(emso_spans) >= 1

    def test_detect_german_steuer_id_labeled(self, detector):
        text = "Steuer-ID: 12345678903"
        spans = detector.detect(text)
        steuer_spans = [s for s in spans if s.entity_type == 'DE_STEUER_ID']
        assert len(steuer_spans) >= 1

    def test_detect_spanish_nif_still_works(self, detector):
        """Verify existing Spanish patterns aren't broken."""
        text = "NIF: 12345678Z"
        spans = detector.detect(text)
        nif_spans = [s for s in spans if s.entity_type == 'ES_NIF']
        assert len(nif_spans) >= 1

    def test_detect_italian_codice_still_works(self, detector):
        """Verify existing Italian patterns aren't broken."""
        text = "Codice Fiscale: RSSMRA85T10A562S"
        spans = detector.detect(text)
        it_spans = [s for s in spans if s.entity_type == 'IT_FISCAL_CODE']
        assert len(it_spans) >= 1


class TestEUPhonePatterns:
    """Test EU country phone patterns."""

    @pytest.fixture()
    def detector(self):
        return PatternDetector()

    def test_french_phone_international(self, detector):
        text = "Appelez +33 1 23 45 67 89"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1

    def test_german_phone_international(self, detector):
        text = "Anruf: +49 30 123456"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1

    def test_dutch_phone_international(self, detector):
        text = "Bel +31 6 1234 5678"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1

    def test_italian_phone_international(self, detector):
        text = "Chiamare +39 06 1234 5678"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1

    def test_spanish_phone_international(self, detector):
        text = "Llamar +34 612 345 678"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1

    def test_portuguese_phone_international(self, detector):
        text = "Ligar +351 912 345 678"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1

    def test_greek_phone_international(self, detector):
        text = "Καλέστε +30 210 1234 567"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1

    def test_slovenian_phone_international(self, detector):
        text = "Pokličite +386 1 234 5678"
        spans = detector.detect(text)
        phone_spans = [s for s in spans if s.entity_type == 'PHONE']
        assert len(phone_spans) >= 1


class TestEntityTypesRegistered:
    """Verify new entity types are in KNOWN_ENTITY_TYPES."""

    def test_all_eu_types_registered(self):
        from openlabels.core.types import KNOWN_ENTITY_TYPES

        expected = [
            "FR_NIR", "FR_SIRET",
            "DE_STEUER_ID", "DE_PERSONALAUSWEIS",
            "NL_BSN",
            "PT_NIF", "PT_CC",
            "BR_CPF", "BR_CNPJ",
            "EL_AMKA", "EL_AFM",
            "SI_EMSO", "SI_DAVCNA",
        ]
        for etype in expected:
            assert etype in KNOWN_ENTITY_TYPES, f"{etype} not in KNOWN_ENTITY_TYPES"

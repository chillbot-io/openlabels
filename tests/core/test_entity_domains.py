"""Tests for the unified entity domain taxonomy."""

from __future__ import annotations

import pytest

from openlabels.core.entity_domains import (
    COMPLIANCE_COMPOSITIONS,
    ENTITY_DOMAIN_REGISTRY,
    ComplianceComposition,
    EntityDomain,
    evaluate_compositions,
    get_all_domains,
    get_compliance_frameworks,
    get_domains,
    get_max_score_multiplier,
)
from openlabels.core.policies.schema import PolicyCategory, RiskLevel
from openlabels.core.types import KNOWN_ENTITY_TYPES, normalize_entity_type


# -----------------------------------------------------------------------
# Registry coverage
# -----------------------------------------------------------------------

class TestRegistryCoverage:
    """Every canonical entity type in KNOWN_ENTITY_TYPES should have domains."""

    def _canonical_types(self) -> set[str]:
        """Resolve all KNOWN_ENTITY_TYPES to their canonical forms."""
        return {normalize_entity_type(t) for t in KNOWN_ENTITY_TYPES}

    def test_all_canonical_types_have_domains(self):
        """Every canonical (post-normalization) entity type has a registry entry."""
        canonical = self._canonical_types()
        missing = {t for t in canonical if t not in ENTITY_DOMAIN_REGISTRY}
        assert not missing, (
            f"Canonical entity types missing from ENTITY_DOMAIN_REGISTRY: {sorted(missing)}"
        )

    def test_registry_keys_are_uppercase(self):
        for key in ENTITY_DOMAIN_REGISTRY:
            assert key == key.upper(), f"Registry key not uppercase: {key}"

    def test_registry_values_are_nonempty_frozensets(self):
        for key, domains in ENTITY_DOMAIN_REGISTRY.items():
            assert isinstance(domains, frozenset), f"{key}: expected frozenset"
            assert len(domains) >= 1, f"{key}: has empty domain set"

    def test_no_registry_entry_has_more_than_3_domains(self):
        for key, domains in ENTITY_DOMAIN_REGISTRY.items():
            assert len(domains) <= 3, (
                f"{key}: has {len(domains)} domains ({domains}), max is 3"
            )


# -----------------------------------------------------------------------
# EntityDomain enum
# -----------------------------------------------------------------------

class TestEntityDomainEnum:
    def test_exactly_14_domains(self):
        assert len(EntityDomain) == 14

    def test_string_values(self):
        for domain in EntityDomain:
            assert domain.value == domain.value.lower()
            assert isinstance(domain, str)

    def test_known_domains(self):
        expected = {
            "identifier", "medical", "financial", "credential", "contact",
            "location", "temporal", "biometric", "government", "classification",
            "vehicle", "professional", "network", "demographic",
        }
        actual = {d.value for d in EntityDomain}
        assert actual == expected


# -----------------------------------------------------------------------
# get_domains()
# -----------------------------------------------------------------------

class TestGetDomains:
    def test_known_type(self):
        assert get_domains("SSN") == frozenset({
            EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT,
        })

    def test_multi_domain_type(self):
        assert get_domains("NHS_NUMBER") == frozenset({
            EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT, EntityDomain.MEDICAL,
        })

    def test_single_domain_type(self):
        assert get_domains("PASSWORD") == frozenset({EntityDomain.CREDENTIAL})

    def test_unknown_type_returns_empty(self):
        assert get_domains("TOTALLY_UNKNOWN_XYZ") == frozenset()

    def test_normalizes_aliases(self):
        # "DOB" normalizes to "DATE_DOB"
        assert get_domains("DOB") == get_domains("DATE_DOB")

    def test_case_insensitive(self):
        assert get_domains("ssn") == get_domains("SSN")

    def test_medical_context_types_have_medical_domain(self):
        for t in ["DIAGNOSIS", "MEDICATION", "LAB_TEST", "PROCEDURE", "DRUG"]:
            domains = get_domains(t)
            assert EntityDomain.MEDICAL in domains, f"{t} should have MEDICAL domain"

    def test_credential_types_have_credential_domain(self):
        cred_types = [
            "AWS_ACCESS_KEY", "GITHUB_TOKEN", "PASSWORD", "API_KEY",
            "JWT", "DATABASE_URL", "STRIPE_KEY",
        ]
        for t in cred_types:
            domains = get_domains(t)
            assert EntityDomain.CREDENTIAL in domains, f"{t} should have CREDENTIAL"


# -----------------------------------------------------------------------
# get_all_domains()
# -----------------------------------------------------------------------

class TestGetAllDomains:
    def test_dict_input(self):
        entities = {"MRN": 3, "NAME": 5, "PHONE": 2, "DIAGNOSIS": 4}
        domains = get_all_domains(entities)
        assert domains == {
            EntityDomain.MEDICAL, EntityDomain.IDENTIFIER, EntityDomain.CONTACT,
        }

    def test_iterable_input(self):
        domains = get_all_domains(["SSN", "CREDIT_CARD"])
        assert EntityDomain.GOVERNMENT in domains
        assert EntityDomain.FINANCIAL in domains
        assert EntityDomain.IDENTIFIER in domains

    def test_empty_input(self):
        assert get_all_domains({}) == set()
        assert get_all_domains([]) == set()

    def test_unknown_types_ignored(self):
        domains = get_all_domains(["UNKNOWN_TYPE"])
        assert domains == set()

    def test_mixed_known_unknown(self):
        domains = get_all_domains(["SSN", "UNKNOWN_TYPE"])
        assert domains == {EntityDomain.IDENTIFIER, EntityDomain.GOVERNMENT}


# -----------------------------------------------------------------------
# evaluate_compositions()
# -----------------------------------------------------------------------

class TestEvaluateCompositions:
    def test_blueprint_walkthrough_example(self):
        """Reproduce the exact example from Section 8 of the blueprint."""
        entities = {"MRN": 3, "NAME": 5, "PHONE": 2, "DIAGNOSIS": 4}
        compositions = evaluate_compositions(entities)
        names = [c.name for c in compositions]

        assert "hipaa_phi" in names
        assert "hipaa_phi_contact" in names
        assert "pii_contact" in names

    def test_hipaa_phi_fires_on_mrn_alone(self):
        """MRN is {IDENTIFIER, MEDICAL} — should trigger hipaa_phi by itself."""
        compositions = evaluate_compositions(["MRN"])
        names = [c.name for c in compositions]
        assert "hipaa_phi" in names

    def test_nhs_number_triggers_multiple(self):
        """NHS_NUMBER is {IDENTIFIER, GOVERNMENT, MEDICAL} — triggers several."""
        compositions = evaluate_compositions(["NHS_NUMBER"])
        names = [c.name for c in compositions]
        assert "hipaa_phi" in names
        assert "gdpr_health" in names
        # classified_data does NOT fire: requires CLASSIFICATION domain,
        # not GOVERNMENT (which is for government-issued IDs)

    def test_credential_only(self):
        compositions = evaluate_compositions(["AWS_ACCESS_KEY"])
        names = [c.name for c in compositions]
        assert "credential_exposure" in names
        assert len(compositions) == 1

    def test_empty_input_returns_nothing(self):
        assert evaluate_compositions({}) == []
        assert evaluate_compositions([]) == []

    def test_sorted_by_multiplier_descending(self):
        compositions = evaluate_compositions(
            {"SSN": 1, "CREDIT_CARD": 1, "NAME": 1}
        )
        multipliers = [c.score_multiplier for c in compositions]
        assert multipliers == sorted(multipliers, reverse=True)

    def test_full_identity_package(self):
        """SSN + CREDIT_CARD should fire full_identity (needs ID+GOV+FIN)."""
        compositions = evaluate_compositions(["SSN", "CREDIT_CARD"])
        names = [c.name for c in compositions]
        assert "full_identity" in names
        assert "identity_theft" in names
        assert "pci_dss" in names

    def test_classification_markings_only(self):
        """Classification entities have CLASSIFICATION domain."""
        compositions = evaluate_compositions(["CLASSIFICATION_LEVEL"])
        names = [c.name for c in compositions]
        assert "classified_data" in names
        # Should NOT fire identity_theft (no FINANCIAL)
        assert "identity_theft" not in names

    def test_financial_without_identifier(self):
        """SWIFT_BIC is {FINANCIAL} only — no IDENTIFIER, so no pci_dss."""
        compositions = evaluate_compositions(["SWIFT_BIC"])
        assert all(c.name != "pci_dss" for c in compositions)

    def test_crypto_seed_phrase_fires_credential_and_financial(self):
        """CRYPTO_SEED_PHRASE is {FINANCIAL, CREDENTIAL}."""
        compositions = evaluate_compositions(["CRYPTO_SEED_PHRASE"])
        names = [c.name for c in compositions]
        assert "credential_exposure" in names


# -----------------------------------------------------------------------
# get_compliance_frameworks()
# -----------------------------------------------------------------------

class TestGetComplianceFrameworks:
    def test_hipaa_detected(self):
        frameworks = get_compliance_frameworks(["MRN", "NAME"])
        assert PolicyCategory.HIPAA in frameworks

    def test_multiple_frameworks(self):
        # SSN + CREDIT_CARD → PII, PCI_DSS, GLBA (no classified_data: that needs CLASSIFICATION)
        frameworks = get_compliance_frameworks(["SSN", "CREDIT_CARD"])
        assert PolicyCategory.PCI_DSS in frameworks
        assert PolicyCategory.PII in frameworks
        assert PolicyCategory.GLBA in frameworks

    def test_empty_input(self):
        assert get_compliance_frameworks([]) == set()


# -----------------------------------------------------------------------
# get_max_score_multiplier()
# -----------------------------------------------------------------------

class TestGetMaxScoreMultiplier:
    def test_empty_input(self):
        mult, rules = get_max_score_multiplier({})
        assert mult == 1.0
        assert rules == []

    def test_hipaa_phi_multiplier(self):
        mult, rules = get_max_score_multiplier({"MRN": 1, "NAME": 1})
        assert mult == 2.0
        assert "hipaa_phi" in rules

    def test_classified_data_is_highest(self):
        mult, rules = get_max_score_multiplier(
            {"CLASSIFICATION_LEVEL": 1, "SSN": 1, "CREDIT_CARD": 1}
        )
        assert mult == 2.5
        assert "classified_data" in rules

    def test_credential_only_multiplier(self):
        mult, rules = get_max_score_multiplier({"PASSWORD": 1})
        assert mult == 1.5
        assert "credential_exposure" in rules

    def test_full_identity_multiplier(self):
        # SSN has {IDENTIFIER, GOVERNMENT}, CREDIT_CARD has {IDENTIFIER, FINANCIAL}
        # Together: full_identity (2.2) is the highest
        mult, rules = get_max_score_multiplier({"SSN": 1, "CREDIT_CARD": 1})
        assert mult == 2.2
        assert "full_identity" in rules

    def test_parity_with_current_scorer_rules(self):
        """Verify that the key multiplier values match the existing CO_OCCURRENCE_RULES."""
        # hipaa_phi = 2.0
        mult, _ = get_max_score_multiplier({"MRN": 1, "DIAGNOSIS": 1})
        assert mult == 2.0

        # SSN has {GOVERNMENT, IDENTIFIER}, SWIFT_BIC has {FINANCIAL}
        # Together all three → full_identity (2.2) wins over identity_theft (1.8)
        mult, rules = get_max_score_multiplier({"SSN": 1, "SWIFT_BIC": 1})
        assert mult == 2.2
        assert "full_identity" in rules

        # credential_exposure = 1.5
        mult, _ = get_max_score_multiplier({"JWT": 1})
        assert mult == 1.5

        # classified_data = 2.5
        mult, _ = get_max_score_multiplier({"SCI_MARKING": 1})
        assert mult == 2.5


# -----------------------------------------------------------------------
# ComplianceComposition invariants
# -----------------------------------------------------------------------

class TestComplianceCompositionInvariants:
    def test_all_compositions_have_required_fields(self):
        for comp in COMPLIANCE_COMPOSITIONS:
            assert comp.name
            assert len(comp.required_domains) >= 1
            assert isinstance(comp.implies_framework, PolicyCategory)
            assert isinstance(comp.risk_level, RiskLevel)
            assert comp.score_multiplier >= 1.0
            assert comp.description

    def test_unique_composition_names(self):
        names = [c.name for c in COMPLIANCE_COMPOSITIONS]
        assert len(names) == len(set(names)), "Duplicate composition names"

    def test_compositions_are_frozen(self):
        comp = COMPLIANCE_COMPOSITIONS[0]
        with pytest.raises(AttributeError):
            comp.name = "modified"  # type: ignore[misc]


# -----------------------------------------------------------------------
# Edge cases
# -----------------------------------------------------------------------

class TestEdgeCases:
    def test_alias_resolution_in_composition(self):
        """Aliased entity types should work in composition evaluation."""
        # "DOB" normalizes to "DATE_DOB" which has {TEMPORAL, IDENTIFIER}
        # Combined with a CONTACT type, should fire pii_contact
        compositions = evaluate_compositions(["DOB", "PHONE"])
        names = [c.name for c in compositions]
        assert "pii_contact" in names

    def test_single_entity_multi_composition(self):
        """A single multi-domain entity can trigger compositions."""
        # NHS_NUMBER is {IDENTIFIER, GOVERNMENT, MEDICAL}
        compositions = evaluate_compositions(["NHS_NUMBER"])
        assert len(compositions) >= 2  # hipaa_phi, gdpr_health, ...

    def test_duplicate_entity_types(self):
        """Duplicate entity types in iterable don't change domains."""
        d1 = get_all_domains(["SSN", "SSN", "SSN"])
        d2 = get_all_domains(["SSN"])
        assert d1 == d2

    def test_generator_input(self):
        """get_all_domains accepts generators."""
        def gen():
            yield "SSN"
            yield "EMAIL"
        domains = get_all_domains(gen())
        assert EntityDomain.GOVERNMENT in domains
        assert EntityDomain.CONTACT in domains

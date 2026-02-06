"""
Comprehensive tests for policy evaluation engine, built-in policies, and schema.

Complements test_engine.py by focusing on:
- Real built-in policy evaluation with realistic entity combinations
- Negative testing (ensuring policies do NOT fire on wrong entity types)
- Confidence threshold boundary conditions for each built-in policy
- Multi-policy risk aggregation with real policy stacks
- Retention, jurisdiction, and data subject rights merging
- Edge cases: empty inputs, unknown types, boundary confidence values
- Special category triggers (GDPR Article 9, CCPA sensitive)
- exclude_if_only and min_count trigger mechanics
- PolicyResult.to_dict() serialization
- PolicyTrigger.is_empty() behavior
- evaluate() min_confidence parameter vs. trigger min_confidence
- Value redaction in matched_values
- Priority ordering of policies
"""

import pytest

from openlabels.core.policies.schema import (
    DataSubjectRights,
    EntityMatch,
    HandlingRequirements,
    PolicyCategory,
    PolicyMatch,
    PolicyPack,
    PolicyResult,
    PolicyTrigger,
    RetentionPolicy,
    RiskLevel,
)
from openlabels.core.policies.engine import PolicyEngine, RISK_ORDER, EvaluationContext
from openlabels.core.policies.loader import (
    load_builtin_policies,
    load_policy_pack,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entity(
    entity_type: str,
    value: str = "REDACTED",
    confidence: float = 0.95,
    start: int = 0,
    source: str = "test",
) -> EntityMatch:
    """Shorthand to build an EntityMatch."""
    return EntityMatch(
        entity_type=entity_type,
        value=value,
        confidence=confidence,
        start=start,
        end=start + len(value),
        source=source,
    )


def _engine_with_builtins() -> PolicyEngine:
    """Fresh engine loaded with all 8 built-in policies."""
    engine = PolicyEngine()
    engine.add_policies(load_builtin_policies())
    return engine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    return PolicyEngine()


@pytest.fixture
def full_engine():
    """Engine pre-loaded with all built-in policies."""
    return _engine_with_builtins()


# ============================================================================
# 1. HIPAA PHI -- comprehensive triggering / non-triggering
# ============================================================================

class TestHIPAA:
    """HIPAA PHI policy must fire on healthcare-related entities and combos."""

    # -- direct any_of triggers --

    @pytest.mark.parametrize("etype", [
        "medical_record_number",
        "mrn",
        "health_insurance_id",
        "health_plan_beneficiary",
        "diagnosis_code",
        "icd_code",
        "prescription",
        "medication",
        "npi",
        "dea_number",
    ])
    def test_hipaa_fires_on_each_direct_trigger(self, full_engine, etype):
        """Each individual HIPAA any_of entity type should trigger the policy."""
        result = full_engine.evaluate([_entity(etype)])
        matched_names = result.policy_names
        assert "HIPAA PHI" in matched_names, (
            f"HIPAA PHI should fire on entity type '{etype}'"
        )
        assert result.has_phi
        assert result.risk_level == RiskLevel.CRITICAL

    # -- combination triggers --

    @pytest.mark.parametrize("combo", [
        ["person_name", "diagnosis"],
        ["person_name", "treatment"],
        ["person_name", "medical_provider"],
        ["ssn", "medical_provider"],
        ["ssn", "diagnosis"],
        ["email", "diagnosis"],
        ["phone", "diagnosis"],
        ["address", "diagnosis"],
        ["person_name", "date_of_birth", "medical_facility"],
    ])
    def test_hipaa_fires_on_combinations(self, full_engine, combo):
        """HIPAA should fire when a recognized entity combination is present."""
        entities = [_entity(t) for t in combo]
        result = full_engine.evaluate(entities)
        assert "HIPAA PHI" in result.policy_names, (
            f"HIPAA PHI should fire on combination {combo}"
        )

    # -- negative cases --

    def test_hipaa_does_not_fire_on_credit_card_alone(self, full_engine):
        """A credit card number without medical context is not PHI."""
        result = full_engine.evaluate([_entity("credit_card_number")])
        assert "HIPAA PHI" not in result.policy_names

    def test_hipaa_does_not_fire_on_person_name_alone(self, full_engine):
        """A person name alone is not PHI (no healthcare context)."""
        result = full_engine.evaluate([_entity("person_name")])
        assert "HIPAA PHI" not in result.policy_names

    def test_hipaa_does_not_fire_on_email_alone(self, full_engine):
        """An email address alone is not PHI."""
        result = full_engine.evaluate([_entity("email")])
        assert "HIPAA PHI" not in result.policy_names

    def test_hipaa_does_not_fire_on_student_id(self, full_engine):
        """Education entity types are not HIPAA triggers."""
        result = full_engine.evaluate([_entity("student_id")])
        assert "HIPAA PHI" not in result.policy_names

    # -- confidence boundary --

    def test_hipaa_below_min_confidence(self, full_engine):
        """HIPAA min_confidence is 0.7; entities at 0.69 should not trigger."""
        entity = _entity("medical_record_number", confidence=0.69)
        result = full_engine.evaluate([entity])
        assert "HIPAA PHI" not in result.policy_names

    def test_hipaa_at_exact_min_confidence(self, full_engine):
        """HIPAA min_confidence is 0.7; entities at exactly 0.7 should trigger."""
        entity = _entity("medical_record_number", confidence=0.7)
        result = full_engine.evaluate([entity])
        assert "HIPAA PHI" in result.policy_names

    # -- handling requirements --

    def test_hipaa_requires_full_encryption_and_audit(self, full_engine):
        """HIPAA mandates encryption at rest, in transit, and audit logging."""
        result = full_engine.evaluate([_entity("medical_record_number")])
        assert result.handling.encryption_required
        assert result.handling.encryption_at_rest
        assert result.handling.encryption_in_transit
        assert result.handling.audit_access
        assert result.handling.access_logging

    # -- retention --

    def test_hipaa_retention_minimum_six_years(self, full_engine):
        """HIPAA requires minimum 6-year retention (2190 days)."""
        result = full_engine.evaluate([_entity("medical_record_number")])
        assert result.retention.min_days == 2190

    # -- jurisdiction --

    def test_hipaa_jurisdiction_is_us(self, full_engine):
        """HIPAA applies to US jurisdiction."""
        result = full_engine.evaluate([_entity("medical_record_number")])
        assert "US" in result.jurisdictions


# ============================================================================
# 2. PCI-DSS
# ============================================================================

class TestPCIDSS:
    """PCI-DSS must fire on payment card / financial account entities."""

    @pytest.mark.parametrize("etype", [
        "credit_card",
        "credit_card_number",
        "pan",
        "card_cvv",
        "cvv",
        "card_expiry",
        "cardholder_name",
        "bank_routing",
        "bank_account",
        "iban",
    ])
    def test_pci_fires_on_each_direct_trigger(self, full_engine, etype):
        result = full_engine.evaluate([_entity(etype)])
        assert "PCI-DSS" in result.policy_names, (
            f"PCI-DSS should fire on entity type '{etype}'"
        )
        assert result.has_pci

    @pytest.mark.parametrize("combo", [
        ["credit_card_number", "card_expiry"],
        ["credit_card_number", "cvv"],
        ["bank_account", "routing_number"],
        ["iban", "bic"],
    ])
    def test_pci_fires_on_combinations(self, full_engine, combo):
        entities = [_entity(t) for t in combo]
        result = full_engine.evaluate(entities)
        assert "PCI-DSS" in result.policy_names, (
            f"PCI-DSS should fire on combination {combo}"
        )

    def test_pci_does_not_fire_on_medical_record(self, full_engine):
        result = full_engine.evaluate([_entity("medical_record_number")])
        assert "PCI-DSS" not in result.policy_names

    def test_pci_does_not_fire_on_student_id(self, full_engine):
        result = full_engine.evaluate([_entity("student_id")])
        assert "PCI-DSS" not in result.policy_names

    def test_pci_below_min_confidence(self, full_engine):
        """PCI min_confidence is 0.8."""
        entity = _entity("credit_card_number", confidence=0.79)
        result = full_engine.evaluate([entity])
        assert "PCI-DSS" not in result.policy_names

    def test_pci_at_exact_min_confidence(self, full_engine):
        entity = _entity("credit_card_number", confidence=0.8)
        result = full_engine.evaluate([entity])
        assert "PCI-DSS" in result.policy_names

    def test_pci_requires_tokenization_and_masking(self, full_engine):
        """PCI-DSS uniquely requires tokenization and masking."""
        result = full_engine.evaluate([_entity("credit_card_number")])
        assert result.handling.tokenization_required
        assert result.handling.masking_required

    def test_pci_max_retention_365_days(self, full_engine):
        """PCI limits retention to 365 days max."""
        result = full_engine.evaluate([_entity("credit_card_number")])
        assert result.retention.max_days == 365

    def test_pci_review_frequency_90_days(self, full_engine):
        """PCI requires review every 90 days."""
        result = full_engine.evaluate([_entity("credit_card_number")])
        assert result.retention.review_frequency_days == 90


# ============================================================================
# 3. GDPR Personal Data + Special Categories
# ============================================================================

class TestGDPR:
    """GDPR fires broadly on personal data, and flags special categories."""

    @pytest.mark.parametrize("etype", [
        "person_name",
        "email",
        "email_address",
        "phone",
        "phone_number",
        "ip_address",
        "device_id",
        "cookie_id",
        "location",
        "location_data",
        "gps_coordinates",
        "national_id",
        "passport",
        "uk_nino",
        "de_id",
    ])
    def test_gdpr_fires_on_each_personal_data_type(self, full_engine, etype):
        result = full_engine.evaluate([_entity(etype)])
        assert "GDPR Personal Data" in result.policy_names, (
            f"GDPR should fire on '{etype}'"
        )

    def test_gdpr_below_min_confidence(self, full_engine):
        """GDPR min_confidence is 0.6."""
        entity = _entity("person_name", confidence=0.59)
        result = full_engine.evaluate([entity])
        assert "GDPR Personal Data" not in result.policy_names

    def test_gdpr_at_exact_min_confidence(self, full_engine):
        entity = _entity("person_name", confidence=0.6)
        result = full_engine.evaluate([entity])
        assert "GDPR Personal Data" in result.policy_names

    def test_gdpr_does_not_fire_on_api_key(self, full_engine):
        """API keys are not personal data under GDPR."""
        result = full_engine.evaluate([_entity("api_key")])
        assert "GDPR Personal Data" not in result.policy_names

    # -- special category (Article 9) --

    @pytest.mark.parametrize("etype", [
        "racial_ethnic_origin",
        "political_opinion",
        "religious_belief",
        "trade_union_membership",
        "genetic_data",
        "biometric_data",
        "health_data",
        "diagnosis",
        "medical_condition",
        "sex_life",
        "sexual_orientation",
    ])
    def test_gdpr_special_category_fires(self, full_engine, etype):
        """GDPR Article 9 special categories should set has_gdpr_special."""
        result = full_engine.evaluate([_entity(etype)])
        assert result.has_gdpr_special, (
            f"GDPR special category should fire on '{etype}'"
        )

    def test_gdpr_non_special_entity_does_not_set_special_flag(self, full_engine):
        """Regular personal data (email) is NOT a special category."""
        result = full_engine.evaluate([_entity("email")])
        assert not result.has_gdpr_special

    # -- data subject rights --

    def test_gdpr_grants_all_data_subject_rights(self, full_engine):
        result = full_engine.evaluate([_entity("email")])
        dsr = result.data_subject_rights
        assert dsr.access
        assert dsr.rectification
        assert dsr.erasure
        assert dsr.portability
        assert dsr.restriction
        assert dsr.objection

    # -- jurisdictions --

    def test_gdpr_jurisdictions(self, full_engine):
        result = full_engine.evaluate([_entity("email")])
        assert "EU" in result.jurisdictions
        assert "EEA" in result.jurisdictions
        assert "UK" in result.jurisdictions


# ============================================================================
# 4. CCPA/CPRA
# ============================================================================

class TestCCPA:
    """CCPA/CPRA fires on California-relevant consumer data."""

    @pytest.mark.parametrize("etype", [
        "ssn",
        "drivers_license",
        "passport",
        "financial_account",
        "credit_card",
        "biometric_data",
    ])
    def test_ccpa_fires_on_direct_triggers(self, full_engine, etype):
        result = full_engine.evaluate([_entity(etype)])
        assert "CCPA/CPRA" in result.policy_names, (
            f"CCPA should fire on '{etype}'"
        )

    @pytest.mark.parametrize("combo", [
        ["person_name", "email"],
        ["person_name", "phone"],
        ["person_name", "address"],
        ["person_name", "ip_address"],
        ["email", "purchase_history"],
        ["device_id", "browsing_history"],
    ])
    def test_ccpa_fires_on_combinations(self, full_engine, combo):
        entities = [_entity(t) for t in combo]
        result = full_engine.evaluate(entities)
        assert "CCPA/CPRA" in result.policy_names, (
            f"CCPA should fire on combination {combo}"
        )

    def test_ccpa_does_not_fire_on_medical_record_alone(self, full_engine):
        result = full_engine.evaluate([_entity("medical_record_number")])
        assert "CCPA/CPRA" not in result.policy_names

    def test_ccpa_jurisdiction_is_california(self, full_engine):
        result = full_engine.evaluate([_entity("ssn")])
        assert "US-CA" in result.jurisdictions

    def test_ccpa_grants_access_erasure_portability_objection(self, full_engine):
        result = full_engine.evaluate([_entity("ssn")])
        dsr = result.data_subject_rights
        assert dsr.access
        assert dsr.erasure
        assert dsr.portability
        assert dsr.objection

    # -- special category triggers --

    @pytest.mark.parametrize("etype", [
        "ssn",
        "drivers_license",
        "passport",
        "financial_account",
        "precise_geolocation",
        "racial_ethnic_origin",
        "religious_belief",
        "genetic_data",
        "biometric_data",
        "health_data",
        "sex_life",
        "sexual_orientation",
    ])
    def test_ccpa_special_category_triggers(self, full_engine, etype):
        """CCPA sensitive personal information triggers should fire."""
        result = full_engine.evaluate([_entity(etype)])
        # CCPA should match (either via any_of or special_category)
        assert "CCPA/CPRA" in result.policy_names, (
            f"CCPA should fire on sensitive type '{etype}'"
        )


# ============================================================================
# 5. GLBA (Financial)
# ============================================================================

class TestGLBA:
    """GLBA fires on financial account / SSN / tax data."""

    @pytest.mark.parametrize("etype", [
        "ssn",
        "tax_id",
        "bank_account",
        "bank_routing",
        "credit_card",
        "financial_account",
    ])
    def test_glba_fires_on_direct_triggers(self, full_engine, etype):
        result = full_engine.evaluate([_entity(etype)])
        assert "GLBA" in result.policy_names, (
            f"GLBA should fire on '{etype}'"
        )

    @pytest.mark.parametrize("combo", [
        ["person_name", "account_number"],
        ["person_name", "financial_account"],
        ["ssn", "account_balance"],
        ["person_name", "credit_score"],
        ["person_name", "loan_amount"],
    ])
    def test_glba_fires_on_combinations(self, full_engine, combo):
        entities = [_entity(t) for t in combo]
        result = full_engine.evaluate(entities)
        assert "GLBA" in result.policy_names, (
            f"GLBA should fire on combination {combo}"
        )

    def test_glba_does_not_fire_on_email_alone(self, full_engine):
        result = full_engine.evaluate([_entity("email")])
        assert "GLBA" not in result.policy_names

    def test_glba_does_not_fire_on_medical_record(self, full_engine):
        result = full_engine.evaluate([_entity("medical_record_number")])
        assert "GLBA" not in result.policy_names

    def test_glba_below_min_confidence(self, full_engine):
        """GLBA min_confidence is 0.7."""
        entity = _entity("bank_account", confidence=0.69)
        result = full_engine.evaluate([entity])
        assert "GLBA" not in result.policy_names

    def test_glba_at_exact_min_confidence(self, full_engine):
        entity = _entity("bank_account", confidence=0.7)
        result = full_engine.evaluate([entity])
        assert "GLBA" in result.policy_names

    def test_glba_retention_seven_years(self, full_engine):
        """GLBA requires 7-year minimum retention (2555 days)."""
        result = full_engine.evaluate([_entity("bank_account")])
        assert result.retention.min_days == 2555

    def test_glba_jurisdiction_us(self, full_engine):
        result = full_engine.evaluate([_entity("bank_account")])
        assert "US" in result.jurisdictions


# ============================================================================
# 6. FERPA (Education)
# ============================================================================

class TestFERPA:
    """FERPA fires on education record entities."""

    @pytest.mark.parametrize("etype", [
        "student_id",
        "education_record",
        "transcript",
        "grade",
        "gpa",
    ])
    def test_ferpa_fires_on_direct_triggers(self, full_engine, etype):
        result = full_engine.evaluate([_entity(etype)])
        assert "FERPA" in result.policy_names, (
            f"FERPA should fire on '{etype}'"
        )

    @pytest.mark.parametrize("combo", [
        ["person_name", "student_id"],
        ["person_name", "grade"],
        ["person_name", "school", "date_of_birth"],
        ["person_name", "disciplinary_record"],
    ])
    def test_ferpa_fires_on_combinations(self, full_engine, combo):
        entities = [_entity(t) for t in combo]
        result = full_engine.evaluate(entities)
        assert "FERPA" in result.policy_names, (
            f"FERPA should fire on combination {combo}"
        )

    def test_ferpa_does_not_fire_on_credit_card(self, full_engine):
        result = full_engine.evaluate([_entity("credit_card_number")])
        assert "FERPA" not in result.policy_names

    def test_ferpa_does_not_fire_on_bank_account(self, full_engine):
        result = full_engine.evaluate([_entity("bank_account")])
        assert "FERPA" not in result.policy_names

    def test_ferpa_below_min_confidence(self, full_engine):
        """FERPA min_confidence is 0.7."""
        entity = _entity("student_id", confidence=0.69)
        result = full_engine.evaluate([entity])
        assert "FERPA" not in result.policy_names

    def test_ferpa_retention_five_years(self, full_engine):
        """FERPA requires 5-year minimum retention (1825 days)."""
        result = full_engine.evaluate([_entity("student_id")])
        assert result.retention.min_days == 1825

    def test_ferpa_grants_access_and_rectification(self, full_engine):
        result = full_engine.evaluate([_entity("student_id")])
        assert result.data_subject_rights.access
        assert result.data_subject_rights.rectification

    def test_ferpa_jurisdiction_us(self, full_engine):
        result = full_engine.evaluate([_entity("student_id")])
        assert "US" in result.jurisdictions


# ============================================================================
# 7. PII General
# ============================================================================

class TestPIIGeneral:
    """PII General policy covers government IDs and identity combos."""

    @pytest.mark.parametrize("etype", [
        "ssn",
        "social_security_number",
        "drivers_license",
        "passport",
        "national_id",
        "itin",
        "tax_id",
        "ein",
        "uk_nino",
        "ca_sin",
        "de_id",
    ])
    def test_pii_fires_on_direct_triggers(self, full_engine, etype):
        result = full_engine.evaluate([_entity(etype)])
        assert "PII General" in result.policy_names, (
            f"PII General should fire on '{etype}'"
        )
        assert result.has_pii

    @pytest.mark.parametrize("combo", [
        ["person_name", "date_of_birth"],
        ["person_name", "address"],
        ["person_name", "phone"],
        ["person_name", "email", "date_of_birth"],
    ])
    def test_pii_fires_on_combinations(self, full_engine, combo):
        entities = [_entity(t) for t in combo]
        result = full_engine.evaluate(entities)
        assert "PII General" in result.policy_names, (
            f"PII General should fire on combination {combo}"
        )

    def test_pii_does_not_fire_on_email_alone(self, full_engine):
        """Email alone is not enough for PII General (only GDPR catches it)."""
        result = full_engine.evaluate([_entity("email")])
        assert "PII General" not in result.policy_names

    def test_pii_does_not_fire_on_ip_address_alone(self, full_engine):
        """IP address alone is not in PII General triggers."""
        result = full_engine.evaluate([_entity("ip_address")])
        assert "PII General" not in result.policy_names

    def test_pii_below_min_confidence(self, full_engine):
        """PII General min_confidence is 0.6."""
        entity = _entity("ssn", confidence=0.59)
        result = full_engine.evaluate([entity])
        assert "PII General" not in result.policy_names

    def test_pii_at_exact_min_confidence(self, full_engine):
        entity = _entity("ssn", confidence=0.6)
        result = full_engine.evaluate([entity])
        assert "PII General" in result.policy_names


# ============================================================================
# 8. Credentials & Secrets
# ============================================================================

class TestCredentials:
    """Credentials policy fires on secret/key entity types."""

    @pytest.mark.parametrize("etype", [
        "aws_key",
        "aws_secret",
        "api_key",
        "password",
        "private_key",
        "ssh_key",
        "github_token",
        "azure_connection_string",
        "database_password",
        "jwt_secret",
        "encryption_key",
        "client_secret",
    ])
    def test_credentials_fires_on_each_type(self, full_engine, etype):
        result = full_engine.evaluate([_entity(etype)])
        assert "Credentials & Secrets" in result.policy_names, (
            f"Credentials should fire on '{etype}'"
        )
        assert result.risk_level == RiskLevel.CRITICAL

    def test_credentials_does_not_fire_on_email(self, full_engine):
        result = full_engine.evaluate([_entity("email")])
        assert "Credentials & Secrets" not in result.policy_names

    def test_credentials_does_not_fire_on_ssn(self, full_engine):
        result = full_engine.evaluate([_entity("ssn")])
        assert "Credentials & Secrets" not in result.policy_names

    def test_credentials_below_min_confidence(self, full_engine):
        """Credentials min_confidence is 0.8."""
        entity = _entity("api_key", confidence=0.79)
        result = full_engine.evaluate([entity])
        assert "Credentials & Secrets" not in result.policy_names

    def test_credentials_max_retention_90_days(self, full_engine):
        """Credentials should be rotated -- max retention 90 days."""
        result = full_engine.evaluate([_entity("api_key")])
        assert result.retention.max_days == 90


# ============================================================================
# 9. Edge Cases
# ============================================================================

class TestEdgeCases:
    """Boundary conditions and unusual inputs."""

    def test_empty_entity_list(self, full_engine):
        """Empty list yields non-sensitive result with MINIMAL risk."""
        result = full_engine.evaluate([])
        assert not result.is_sensitive
        assert result.risk_level == RiskLevel.MINIMAL
        assert len(result.matches) == 0
        assert len(result.categories) == 0

    def test_single_unknown_entity_type(self, full_engine):
        """Entity type not matching any policy should yield no matches."""
        result = full_engine.evaluate([_entity("completely_unknown_type_xyz")])
        assert not result.is_sensitive

    def test_all_entities_below_evaluate_min_confidence(self, full_engine):
        """evaluate(min_confidence=...) filters out entities before matching."""
        entities = [
            _entity("ssn", confidence=0.5),
            _entity("credit_card_number", confidence=0.5),
            _entity("medical_record_number", confidence=0.5),
        ]
        result = full_engine.evaluate(entities, min_confidence=0.6)
        assert not result.is_sensitive

    def test_evaluate_min_confidence_vs_trigger_min_confidence(self, full_engine):
        """
        evaluate(min_confidence) is a pre-filter on entities.
        Trigger min_confidence is checked afterward on the remaining entities.
        An entity passing evaluate's threshold can still fail the trigger threshold.
        """
        # PCI min_confidence = 0.8
        # Entity at 0.75 passes evaluate min_confidence=0.7, but fails PCI trigger
        entity = _entity("credit_card_number", confidence=0.75)
        result = full_engine.evaluate([entity], min_confidence=0.7)
        assert "PCI-DSS" not in result.policy_names

    def test_evaluate_min_confidence_zero_keeps_all(self, full_engine):
        """min_confidence=0.0 (default) retains all entities."""
        entity = _entity("ssn", confidence=0.01)
        result = full_engine.evaluate([entity], min_confidence=0.0)
        # SSN triggers both PII General (threshold 0.6) -- should fail
        # but CCPA (threshold 0.6) -- should fail
        # None should fire because 0.01 < all trigger thresholds
        assert "PII General" not in result.policy_names

    def test_multiple_entities_same_type_counts(self, full_engine):
        """Multiple entities of the same type increment counts correctly."""
        entities = [
            _entity("ssn", value="111-11-1111", confidence=0.9),
            _entity("ssn", value="222-22-2222", confidence=0.95),
        ]
        result = full_engine.evaluate(entities)
        assert result.is_sensitive
        assert result.has_pii

    def test_entity_type_case_normalization_mixed(self, full_engine):
        """Entity types with mixed case (e.g., 'SSN') still match policies."""
        entity = _entity("SSN", confidence=0.9)
        result = full_engine.evaluate([entity])
        assert result.has_pii

    def test_entity_type_case_normalization_uppercase(self, full_engine):
        """Fully uppercase entity type like 'CREDIT_CARD_NUMBER' still matches."""
        entity = _entity("CREDIT_CARD_NUMBER", confidence=0.9)
        result = full_engine.evaluate([entity])
        assert result.has_pci


# ============================================================================
# 10. Multi-Policy Risk Aggregation
# ============================================================================

class TestRiskAggregation:
    """When multiple policies fire, the highest risk level wins."""

    def test_ssn_triggers_multiple_policies(self, full_engine):
        """SSN should trigger PII General, GLBA, and CCPA (at minimum)."""
        result = full_engine.evaluate([_entity("ssn")])
        assert PolicyCategory.PII in result.categories
        assert PolicyCategory.GLBA in result.categories
        assert PolicyCategory.CCPA in result.categories

    def test_credit_card_triggers_pci_glba_ccpa(self, full_engine):
        """Credit card should trigger PCI-DSS, GLBA, and CCPA."""
        result = full_engine.evaluate([_entity("credit_card")])
        assert PolicyCategory.PCI_DSS in result.categories
        assert PolicyCategory.GLBA in result.categories
        assert PolicyCategory.CCPA in result.categories

    def test_highest_risk_level_wins_across_real_policies(self, full_engine):
        """
        Email triggers GDPR (HIGH). PCI fires CRITICAL.
        Combined result should be CRITICAL.
        """
        entities = [
            _entity("email"),
            _entity("credit_card_number"),
        ]
        result = full_engine.evaluate(entities)
        assert result.risk_level == RiskLevel.CRITICAL

    def test_risk_order_completeness(self):
        """RISK_ORDER dict covers every RiskLevel variant."""
        for level in RiskLevel:
            assert level in RISK_ORDER

    def test_risk_order_monotonic(self):
        """MINIMAL < LOW < MEDIUM < HIGH < CRITICAL in risk ordering."""
        assert RISK_ORDER[RiskLevel.MINIMAL] < RISK_ORDER[RiskLevel.LOW]
        assert RISK_ORDER[RiskLevel.LOW] < RISK_ORDER[RiskLevel.MEDIUM]
        assert RISK_ORDER[RiskLevel.MEDIUM] < RISK_ORDER[RiskLevel.HIGH]
        assert RISK_ORDER[RiskLevel.HIGH] < RISK_ORDER[RiskLevel.CRITICAL]


# ============================================================================
# 11. Handling Requirements Merging (real policies)
# ============================================================================

class TestHandlingMerge:
    """
    Merging handling requirements when multiple policies fire.
    Any True wins (OR semantics).
    """

    def test_pci_adds_tokenization_to_combined_result(self, full_engine):
        """
        HIPAA does not require tokenization. PCI does.
        When both fire, result should require tokenization.
        """
        entities = [
            _entity("medical_record_number"),  # HIPAA
            _entity("credit_card_number"),      # PCI
        ]
        result = full_engine.evaluate(entities)
        assert result.handling.tokenization_required
        assert result.handling.masking_required
        assert result.handling.encryption_at_rest
        assert result.handling.encryption_in_transit

    def test_geographic_restrictions_intersection(self, engine):
        """When two policies both specify geographic_restrictions, the intersection is used."""
        p1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(geographic_restrictions=["US", "EU", "UK"]),
        )
        p2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(geographic_restrictions=["EU", "UK", "JP"]),
        )
        engine.add_policies([p1, p2])
        result = engine.evaluate([_entity("test")])
        allowed = set(result.handling.geographic_restrictions)
        assert allowed == {"EU", "UK"}

    def test_prohibited_regions_union(self, engine):
        """Prohibited regions from multiple policies are unioned."""
        p1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(prohibited_regions=["CN", "RU"]),
        )
        p2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(prohibited_regions=["RU", "IR"]),
        )
        engine.add_policies([p1, p2])
        result = engine.evaluate([_entity("test")])
        prohibited = set(result.handling.prohibited_regions)
        assert prohibited == {"CN", "RU", "IR"}

    def test_mfa_requirement_or_merge(self, engine):
        """MFA required if any policy demands it."""
        p1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(mfa_required=False),
        )
        p2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(mfa_required=True),
        )
        engine.add_policies([p1, p2])
        result = engine.evaluate([_entity("test")])
        assert result.handling.mfa_required


# ============================================================================
# 12. Retention Policy Merging
# ============================================================================

class TestRetentionMerge:
    """Most restrictive retention wins when policies merge."""

    def test_longest_minimum_retention_wins(self, engine):
        """min_days: take the larger value."""
        p1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(min_days=365),
        )
        p2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(min_days=2555),
        )
        engine.add_policies([p1, p2])
        result = engine.evaluate([_entity("test")])
        assert result.retention.min_days == 2555

    def test_shortest_maximum_retention_wins(self, engine):
        """max_days: take the smaller value."""
        p1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(max_days=365),
        )
        p2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(max_days=90),
        )
        engine.add_policies([p1, p2])
        result = engine.evaluate([_entity("test")])
        assert result.retention.max_days == 90

    def test_most_frequent_review_wins(self, engine):
        """review_frequency_days: take the smaller (more frequent)."""
        p1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(review_frequency_days=365),
        )
        p2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(review_frequency_days=90),
        )
        engine.add_policies([p1, p2])
        result = engine.evaluate([_entity("test")])
        assert result.retention.review_frequency_days == 90

    def test_retention_none_vs_value(self, engine):
        """When one policy has None, the other's value is adopted."""
        p1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(min_days=None, max_days=None),
        )
        p2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            retention=RetentionPolicy(min_days=1000, max_days=2000),
        )
        engine.add_policies([p1, p2])
        result = engine.evaluate([_entity("test")])
        assert result.retention.min_days == 1000
        assert result.retention.max_days == 2000

    def test_hipaa_and_glba_retention_merge(self, full_engine):
        """
        SSN triggers both HIPAA (min 2190) and GLBA (min 2555).
        Merged min_days should be 2555 (the longer minimum).
        """
        entities = [
            _entity("ssn"),
            _entity("medical_provider"),
        ]
        result = full_engine.evaluate(entities)
        # HIPAA fires via combination ssn+medical_provider, GLBA fires via ssn any_of
        assert result.retention.min_days >= 2555

    def test_pci_and_hipaa_retention_merge(self, full_engine):
        """
        PCI max_days=365. HIPAA min_days=2190.
        Both fire together to illustrate that max and min are tracked independently.
        """
        entities = [
            _entity("credit_card_number"),      # PCI
            _entity("medical_record_number"),    # HIPAA
        ]
        result = full_engine.evaluate(entities)
        assert result.retention.max_days == 365
        assert result.retention.min_days == 2190


# ============================================================================
# 13. Data Subject Rights Merging
# ============================================================================

class TestDataSubjectRightsMerge:
    """Data subject rights are unioned across matched policies."""

    def test_gdpr_and_ccpa_rights_combined(self, full_engine):
        """
        GDPR grants all 6 rights. CCPA grants access, erasure, portability, objection.
        Union should yield all 6.
        """
        entities = [
            _entity("ssn"),           # CCPA, PII, GLBA
            _entity("person_name"),   # GDPR
        ]
        result = full_engine.evaluate(entities)
        dsr = result.data_subject_rights
        assert dsr.access
        assert dsr.rectification     # GDPR
        assert dsr.erasure
        assert dsr.portability
        assert dsr.restriction        # GDPR
        assert dsr.objection

    def test_ferpa_only_grants_access_and_rectification(self, full_engine):
        """FERPA alone: access and rectification, not erasure/portability."""
        result = full_engine.evaluate([_entity("student_id")])
        dsr = result.data_subject_rights
        assert dsr.access
        assert dsr.rectification
        assert not dsr.erasure
        assert not dsr.portability


# ============================================================================
# 14. Jurisdiction Merging
# ============================================================================

class TestJurisdictionMerge:
    """Jurisdictions from all matched policies are unioned."""

    def test_ssn_jurisdictions(self, full_engine):
        """SSN triggers US policies (PII General, GLBA, CCPA)."""
        result = full_engine.evaluate([_entity("ssn")])
        assert "US" in result.jurisdictions
        assert "US-CA" in result.jurisdictions

    def test_email_triggers_gdpr_and_ccpa_jurisdictions(self, full_engine):
        """
        'email' triggers GDPR (EU, EEA, UK).
        Combined with 'person_name' triggers CCPA combo [person_name, email] -> US-CA.
        """
        entities = [
            _entity("email"),
            _entity("person_name"),
        ]
        result = full_engine.evaluate(entities)
        assert "EU" in result.jurisdictions
        assert "US-CA" in result.jurisdictions


# ============================================================================
# 15. exclude_if_only Trigger
# ============================================================================

class TestExcludeIfOnly:
    """Test the exclude_if_only trigger modifier."""

    def test_exclude_if_only_suppresses_match(self, engine):
        """When ALL entities are in exclude_if_only, the policy does not fire."""
        policy = PolicyPack(
            name="Exclude Test",
            triggers=PolicyTrigger(
                any_of=["person_name", "email"],
                exclude_if_only=["person_name"],
            ),
        )
        engine.add_policy(policy)

        # Only person_name -> excluded
        result = engine.evaluate([_entity("person_name")])
        assert not result.is_sensitive

    def test_exclude_if_only_allows_when_others_present(self, engine):
        """If other entity types are present beyond the exclusion set, policy fires."""
        policy = PolicyPack(
            name="Exclude Test",
            triggers=PolicyTrigger(
                any_of=["person_name", "email"],
                exclude_if_only=["person_name"],
            ),
        )
        engine.add_policy(policy)

        entities = [
            _entity("person_name"),
            _entity("email"),
        ]
        result = engine.evaluate(entities)
        assert result.is_sensitive

    def test_exclude_if_only_with_multiple_excluded_types(self, engine):
        """Multiple excluded types: suppressed only if ALL present types are in the set."""
        policy = PolicyPack(
            name="Exclude Multi",
            triggers=PolicyTrigger(
                any_of=["person_name", "email", "phone"],
                exclude_if_only=["person_name", "email"],
            ),
        )
        engine.add_policy(policy)

        # Both excluded types only -> suppressed
        entities = [_entity("person_name"), _entity("email")]
        result = engine.evaluate(entities)
        assert not result.is_sensitive

        # Add phone -> not suppressed
        entities.append(_entity("phone"))
        result = engine.evaluate(entities)
        assert result.is_sensitive


# ============================================================================
# 16. min_count Trigger
# ============================================================================

class TestMinCount:
    """Test the min_count trigger modifier."""

    def test_min_count_not_reached(self, engine):
        """When min_count > number of entities of that type, trigger fails."""
        policy = PolicyPack(
            name="Min Count",
            triggers=PolicyTrigger(
                any_of=["ssn"],
                min_count=3,
            ),
        )
        engine.add_policy(policy)

        # Only 2 SSNs
        entities = [
            _entity("ssn", value="111-11-1111"),
            _entity("ssn", value="222-22-2222"),
        ]
        result = engine.evaluate(entities)
        assert not result.is_sensitive

    def test_min_count_reached(self, engine):
        """When count meets min_count, trigger fires."""
        policy = PolicyPack(
            name="Min Count",
            triggers=PolicyTrigger(
                any_of=["ssn"],
                min_count=3,
            ),
        )
        engine.add_policy(policy)

        entities = [
            _entity("ssn", value="111-11-1111"),
            _entity("ssn", value="222-22-2222"),
            _entity("ssn", value="333-33-3333"),
        ]
        result = engine.evaluate(entities)
        assert result.is_sensitive

    def test_min_count_default_is_one(self, engine):
        """Default min_count is 1, so single match suffices."""
        policy = PolicyPack(
            name="Default Count",
            triggers=PolicyTrigger(any_of=["ssn"]),
        )
        engine.add_policy(policy)

        result = engine.evaluate([_entity("ssn")])
        assert result.is_sensitive


# ============================================================================
# 17. PolicyResult properties and to_dict()
# ============================================================================

class TestPolicyResultSerialization:
    """Test PolicyResult properties and serialization."""

    def test_is_sensitive_false_when_no_matches(self):
        result = PolicyResult()
        assert not result.is_sensitive

    def test_is_sensitive_true_when_matches_exist(self):
        result = PolicyResult(
            matches=[PolicyMatch(
                policy_name="test",
                trigger_type="any_of",
                matched_entities=["ssn"],
                matched_values=["SSN:12***89"],
            )]
        )
        assert result.is_sensitive

    def test_requires_encryption_flag(self):
        result = PolicyResult(
            handling=HandlingRequirements(encryption_required=True),
        )
        assert result.requires_encryption

    def test_policy_names_property(self):
        result = PolicyResult(
            matches=[
                PolicyMatch("HIPAA PHI", "any_of", ["mrn"], []),
                PolicyMatch("PCI-DSS", "any_of", ["pan"], []),
            ]
        )
        assert result.policy_names == ["HIPAA PHI", "PCI-DSS"]

    def test_to_dict_complete(self, full_engine):
        """to_dict() should serialize all key fields."""
        entities = [
            _entity("credit_card_number"),
            _entity("email"),
        ]
        result = full_engine.evaluate(entities)
        d = result.to_dict()

        assert d["risk_level"] == "critical"
        assert isinstance(d["categories"], list)
        assert "pci_dss" in d["categories"]
        assert isinstance(d["policies"], list)
        assert "PCI-DSS" in d["policies"]
        assert isinstance(d["has_phi"], bool)
        assert isinstance(d["has_pii"], bool)
        assert isinstance(d["has_pci"], bool)
        assert d["has_pci"] is True
        assert isinstance(d["has_gdpr_special"], bool)
        assert isinstance(d["requires_encryption"], bool)
        assert d["requires_encryption"] is True
        assert isinstance(d["jurisdictions"], list)

    def test_to_dict_empty_result(self):
        result = PolicyResult()
        d = result.to_dict()
        assert d["risk_level"] == "minimal"
        assert d["categories"] == []
        assert d["policies"] == []
        assert d["has_phi"] is False
        assert d["has_pii"] is False
        assert d["has_pci"] is False
        assert d["has_gdpr_special"] is False
        assert d["requires_encryption"] is False
        assert d["jurisdictions"] == []


# ============================================================================
# 18. PolicyTrigger.is_empty()
# ============================================================================

class TestPolicyTriggerIsEmpty:
    """Test PolicyTrigger.is_empty() behavior."""

    def test_default_trigger_is_empty(self):
        t = PolicyTrigger()
        assert t.is_empty()

    def test_any_of_not_empty(self):
        t = PolicyTrigger(any_of=["ssn"])
        assert not t.is_empty()

    def test_all_of_not_empty(self):
        t = PolicyTrigger(all_of=["a", "b"])
        assert not t.is_empty()

    def test_combinations_not_empty(self):
        t = PolicyTrigger(combinations=[["a", "b"]])
        assert not t.is_empty()

    def test_only_thresholds_still_empty(self):
        """Setting min_confidence or min_count without trigger lists is still empty."""
        t = PolicyTrigger(min_confidence=0.9, min_count=5)
        assert t.is_empty()


# ============================================================================
# 19. Priority Ordering
# ============================================================================

class TestPriorityOrdering:
    """Policies are evaluated in priority order (highest first)."""

    def test_policies_sorted_by_priority_descending(self, engine):
        p_low = PolicyPack(name="Low", priority=10, triggers=PolicyTrigger(any_of=["x"]))
        p_high = PolicyPack(name="High", priority=100, triggers=PolicyTrigger(any_of=["x"]))
        p_mid = PolicyPack(name="Mid", priority=50, triggers=PolicyTrigger(any_of=["x"]))

        engine.add_policy(p_low)
        engine.add_policy(p_high)
        engine.add_policy(p_mid)

        # Internal list should be sorted high -> mid -> low
        assert engine._policies[0].name == "High"
        assert engine._policies[1].name == "Mid"
        assert engine._policies[2].name == "Low"

    def test_builtin_policies_priority_order(self, full_engine):
        """HIPAA, PCI, and Credentials should be at priority 100 (highest)."""
        top = full_engine._policies[0]
        assert top.priority == 100
        # All priority-100 policies should come before priority-90
        top_names = {p.name for p in full_engine._policies if p.priority == 100}
        assert "HIPAA PHI" in top_names
        assert "PCI-DSS" in top_names
        assert "Credentials & Secrets" in top_names


# ============================================================================
# 20. Value Redaction in matched_values
# ============================================================================

class TestValueRedaction:
    """The engine redacts matched values for audit logging."""

    def test_long_value_partially_redacted(self, engine):
        """Values longer than 4 chars show first 2 and last 2, middle is stars."""
        policy = PolicyPack(
            name="Redact Test",
            triggers=PolicyTrigger(any_of=["ssn"]),
        )
        engine.add_policy(policy)
        entity = _entity("ssn", value="123-45-6789", confidence=0.95)
        result = engine.evaluate([entity])
        # 123-45-6789 has length 11, so first 2 + 7 stars + last 2
        assert len(result.matches) == 1
        vals = result.matches[0].matched_values
        assert len(vals) == 1
        # Format: "ssn:12*******89"
        assert vals[0].startswith("ssn:")
        assert "***" in vals[0]

    def test_short_value_fully_redacted(self, engine):
        """Values 4 chars or fewer are fully redacted."""
        policy = PolicyPack(
            name="Short Val",
            triggers=PolicyTrigger(any_of=["pin"]),
        )
        engine.add_policy(policy)
        entity = _entity("pin", value="1234", confidence=0.95)
        result = engine.evaluate([entity])
        vals = result.matches[0].matched_values
        assert vals[0] == "pin:****"

    def test_matched_values_capped_at_ten(self, engine):
        """At most 10 redacted values per match."""
        policy = PolicyPack(
            name="Cap Test",
            triggers=PolicyTrigger(any_of=["ssn"]),
        )
        engine.add_policy(policy)
        entities = [_entity("ssn", value=f"SSN-{i:05d}", start=i * 20) for i in range(15)]
        result = engine.evaluate(entities)
        assert len(result.matches[0].matched_values) == 10


# ============================================================================
# 21. EvaluationContext building
# ============================================================================

class TestEvaluationContext:
    """Test the _build_context internal method."""

    def test_context_tracks_max_confidence(self, engine):
        entities = [
            _entity("ssn", confidence=0.7),
            _entity("ssn", confidence=0.95),
            _entity("ssn", confidence=0.8),
        ]
        ctx = engine._build_context(entities, min_confidence=0.0)
        assert ctx.type_max_confidence["ssn"] == 0.95

    def test_context_filters_by_min_confidence(self, engine):
        entities = [
            _entity("ssn", confidence=0.3),
            _entity("email", confidence=0.9),
        ]
        ctx = engine._build_context(entities, min_confidence=0.5)
        assert "ssn" not in ctx.entity_types
        assert "email" in ctx.entity_types

    def test_context_normalizes_entity_types_to_lowercase(self, engine):
        entities = [_entity("Person_Name")]
        ctx = engine._build_context(entities, min_confidence=0.0)
        assert "person_name" in ctx.entity_types

    def test_context_counts_entities(self, engine):
        entities = [
            _entity("ssn", value="a"),
            _entity("ssn", value="b"),
            _entity("ssn", value="c"),
            _entity("email", value="d"),
        ]
        ctx = engine._build_context(entities, min_confidence=0.0)
        assert ctx.type_counts["ssn"] == 3
        assert ctx.type_counts["email"] == 1


# ============================================================================
# 22. Summary Flags
# ============================================================================

class TestSummaryFlags:
    """Test has_phi, has_pii, has_pci, has_gdpr_special flags."""

    def test_has_phi_set_for_hipaa(self, full_engine):
        result = full_engine.evaluate([_entity("medical_record_number")])
        assert result.has_phi is True
        assert result.has_pii is False  # MRN does not trigger PII General

    def test_has_pii_set_for_ssn(self, full_engine):
        result = full_engine.evaluate([_entity("ssn")])
        assert result.has_pii is True

    def test_has_pci_set_for_credit_card(self, full_engine):
        result = full_engine.evaluate([_entity("credit_card_number")])
        assert result.has_pci is True

    def test_has_gdpr_special_on_biometric_data(self, full_engine):
        result = full_engine.evaluate([_entity("biometric_data")])
        assert result.has_gdpr_special is True

    def test_no_flags_on_unknown_type(self, full_engine):
        result = full_engine.evaluate([_entity("unknown_xyz")])
        assert result.has_phi is False
        assert result.has_pii is False
        assert result.has_pci is False
        assert result.has_gdpr_special is False


# ============================================================================
# 23. Engine Management API
# ============================================================================

class TestEngineManagement:
    """Test policy management methods not covered in test_engine.py."""

    def test_clear_policies(self, engine):
        policies = load_builtin_policies()
        engine.add_policies(policies)
        assert engine.policy_count > 0

        engine.clear_policies()
        assert engine.policy_count == 0
        assert engine.policy_names == []

    def test_remove_nonexistent_policy(self, engine):
        assert engine.remove_policy("does_not_exist") is False

    def test_get_policies_for_category(self, full_engine):
        hipaa_policies = full_engine.get_policies_for_category(PolicyCategory.HIPAA)
        assert len(hipaa_policies) == 1
        assert hipaa_policies[0].name == "HIPAA PHI"

    def test_get_enabled_categories(self, full_engine):
        cats = full_engine.get_enabled_categories()
        assert PolicyCategory.HIPAA in cats
        assert PolicyCategory.PCI_DSS in cats
        assert PolicyCategory.GDPR in cats
        assert PolicyCategory.CCPA in cats
        assert PolicyCategory.GLBA in cats
        assert PolicyCategory.FERPA in cats
        assert PolicyCategory.PII in cats
        assert PolicyCategory.CUSTOM in cats  # Credentials

    def test_get_policies_for_empty_category(self, full_engine):
        """A category with no loaded policies returns empty list."""
        result = full_engine.get_policies_for_category(PolicyCategory.SOX)
        assert result == []


# ============================================================================
# 24. YAML / Dict Loader Edge Cases
# ============================================================================

class TestLoaderEdgeCases:
    """Test loader for edge cases not covered in test_engine.py."""

    def test_missing_name_raises(self):
        with pytest.raises(ValueError, match="name"):
            load_policy_pack({"category": "pii"})

    def test_unknown_category_defaults_to_custom(self):
        policy = load_policy_pack({"name": "Test", "category": "nonexistent_regulation"})
        assert policy.category == PolicyCategory.CUSTOM

    def test_unknown_risk_level_defaults_to_high(self):
        policy = load_policy_pack({"name": "Test", "risk_level": "banana"})
        assert policy.risk_level == RiskLevel.HIGH

    def test_invalid_source_type_raises(self):
        with pytest.raises(ValueError, match="Invalid source type"):
            load_policy_pack(12345)

    def test_load_all_fields_from_dict(self):
        data = {
            "name": "Full Policy",
            "version": "3.0",
            "description": "All fields populated",
            "category": "gdpr",
            "risk_level": "critical",
            "triggers": {
                "any_of": ["email"],
                "all_of": ["a", "b"],
                "combinations": [["x", "y"]],
                "min_confidence": 0.8,
                "min_count": 2,
                "exclude_if_only": ["z"],
            },
            "special_category_triggers": {
                "any_of": ["health_data"],
            },
            "handling": {
                "encryption_required": True,
                "encryption_at_rest": True,
                "encryption_in_transit": True,
                "tokenization_required": True,
                "masking_required": True,
                "audit_access": True,
                "access_logging": True,
                "mfa_required": True,
                "geographic_restrictions": ["EU"],
                "prohibited_regions": ["CN"],
            },
            "retention": {
                "max_days": 365,
                "min_days": 30,
                "review_frequency_days": 90,
                "auto_delete": True,
            },
            "data_subject_rights": {
                "access": True,
                "rectification": True,
                "erasure": True,
                "portability": True,
                "restriction": True,
                "objection": True,
            },
            "jurisdictions": ["EU", "UK"],
            "enabled": True,
            "priority": 99,
            "tags": ["test", "full"],
            "metadata": {"author": "test"},
        }
        policy = load_policy_pack(data)
        assert policy.name == "Full Policy"
        assert policy.version == "3.0"
        assert policy.category == PolicyCategory.GDPR
        assert policy.risk_level == RiskLevel.CRITICAL
        assert policy.triggers.min_confidence == 0.8
        assert policy.triggers.min_count == 2
        assert policy.triggers.exclude_if_only == ["z"]
        assert "health_data" in policy.special_category_triggers.any_of
        assert policy.handling.mfa_required
        assert policy.handling.geographic_restrictions == ["EU"]
        assert policy.handling.prohibited_regions == ["CN"]
        assert policy.retention.auto_delete is True
        assert policy.retention.min_days == 30
        assert policy.data_subject_rights.restriction
        assert policy.jurisdictions == ["EU", "UK"]
        assert policy.priority == 99
        assert policy.tags == ["test", "full"]
        assert policy.metadata == {"author": "test"}

    def test_disabled_policy_from_dict(self):
        policy = load_policy_pack({"name": "Disabled", "enabled": False})
        assert policy.enabled is False

    def test_default_values_from_minimal_dict(self):
        policy = load_policy_pack({"name": "Minimal"})
        assert policy.version == "1.0"
        assert policy.description == ""
        assert policy.category == PolicyCategory.CUSTOM
        assert policy.risk_level == RiskLevel.HIGH
        assert policy.triggers.is_empty()
        assert policy.enabled is True
        assert policy.priority == 0
        assert policy.tags == []
        assert policy.metadata == {}

    def test_load_yaml_with_special_category_triggers(self):
        yaml_str = """
name: GDPR Test
category: gdpr
special_category_triggers:
  any_of:
    - health_data
    - biometric_data
"""
        policy = load_policy_pack(yaml_str)
        assert "health_data" in policy.special_category_triggers.any_of
        assert "biometric_data" in policy.special_category_triggers.any_of


# ============================================================================
# 25. Schema dataclass construction and __post_init__
# ============================================================================

class TestSchemaConstruction:
    """Test schema dataclass construction and coercion."""

    def test_policy_pack_string_category_coerced(self):
        """PolicyPack __post_init__ coerces string category to enum."""
        pp = PolicyPack(name="Test", category="hipaa")
        assert pp.category == PolicyCategory.HIPAA

    def test_policy_pack_string_risk_level_coerced(self):
        pp = PolicyPack(name="Test", risk_level="critical")
        assert pp.risk_level == RiskLevel.CRITICAL

    def test_entity_match_fields(self):
        em = EntityMatch(
            entity_type="ssn",
            value="123-45-6789",
            confidence=0.95,
            start=10,
            end=21,
            source="regex",
            metadata={"pattern": "ssn_pattern"},
        )
        assert em.entity_type == "ssn"
        assert em.start == 10
        assert em.end == 21
        assert em.source == "regex"
        assert em.metadata["pattern"] == "ssn_pattern"

    def test_entity_match_default_source(self):
        em = EntityMatch(entity_type="test", value="v", confidence=0.5, start=0, end=1)
        assert em.source == ""
        assert em.metadata == {}


# ============================================================================
# 26. Builtin Policy Count and Names
# ============================================================================

class TestBuiltinPolicyIntegrity:
    """Ensure the set of built-in policies is complete and named correctly."""

    def test_exactly_eight_builtin_policies(self):
        policies = load_builtin_policies()
        assert len(policies) == 8

    def test_all_expected_names_present(self):
        names = {p.name for p in load_builtin_policies()}
        expected = {
            "HIPAA PHI",
            "PII General",
            "PCI-DSS",
            "GDPR Personal Data",
            "CCPA/CPRA",
            "GLBA",
            "FERPA",
            "Credentials & Secrets",
        }
        assert names == expected

    def test_all_builtin_policies_are_enabled(self):
        for p in load_builtin_policies():
            assert p.enabled, f"{p.name} should be enabled"

    def test_all_builtin_policies_have_non_empty_triggers(self):
        for p in load_builtin_policies():
            assert not p.triggers.is_empty(), (
                f"{p.name} should have non-empty triggers"
            )

    def test_all_builtin_policies_have_risk_high_or_critical(self):
        """All built-in policies should be at least HIGH risk."""
        for p in load_builtin_policies():
            assert p.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL), (
                f"{p.name} has unexpected risk level {p.risk_level}"
            )


# ============================================================================
# 27. Cross-Policy Interaction Scenarios
# ============================================================================

class TestCrossPolicyScenarios:
    """Realistic multi-entity scenarios that trigger multiple regulations."""

    def test_healthcare_breach_scenario(self, full_engine):
        """
        A document with patient name, SSN, diagnosis, and credit card
        should trigger HIPAA, PII, PCI, GLBA, CCPA, and GDPR.
        """
        entities = [
            _entity("person_name", value="Jane Doe"),
            _entity("ssn", value="123-45-6789"),
            _entity("diagnosis", value="diabetes"),
            _entity("credit_card_number", value="4111111111111111"),
        ]
        result = full_engine.evaluate(entities)
        assert result.has_phi
        assert result.has_pii
        assert result.has_pci
        assert result.risk_level == RiskLevel.CRITICAL
        assert len(result.matches) >= 4

    def test_financial_document_scenario(self, full_engine):
        """
        A document with bank_account, routing number, SSN, person_name.
        Should trigger PCI, PII, GLBA, CCPA.
        """
        entities = [
            _entity("person_name", value="John Smith"),
            _entity("ssn", value="123-45-6789"),
            _entity("bank_account", value="1234567890"),
            _entity("bank_routing", value="021000021"),
        ]
        result = full_engine.evaluate(entities)
        assert PolicyCategory.PCI_DSS in result.categories
        assert PolicyCategory.GLBA in result.categories
        assert PolicyCategory.PII in result.categories
        assert result.requires_encryption

    def test_education_record_scenario(self, full_engine):
        """
        Student record with name, student_id, grade, and DOB.
        Should trigger FERPA and PII combo.
        """
        entities = [
            _entity("person_name", value="Alice Johnson"),
            _entity("student_id", value="STU12345"),
            _entity("grade", value="A+"),
            _entity("date_of_birth", value="2005-03-15"),
        ]
        result = full_engine.evaluate(entities)
        assert "FERPA" in result.policy_names
        assert "PII General" in result.policy_names  # person_name + date_of_birth
        assert result.data_subject_rights.access

    def test_secrets_in_config_file(self, full_engine):
        """
        Config file with multiple credential types.
        Should trigger Credentials policy with CRITICAL risk.
        """
        entities = [
            _entity("aws_key", value="AKIAIOSFODNN7EXAMPLE"),
            _entity("aws_secret", value="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            _entity("database_password", value="p@ssw0rd123"),
        ]
        result = full_engine.evaluate(entities)
        assert "Credentials & Secrets" in result.policy_names
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.retention.max_days == 90

    def test_gdpr_special_category_health_scenario(self, full_engine):
        """
        EU citizen with health data: triggers GDPR special category.
        """
        entities = [
            _entity("email", value="patient@eu.example"),
            _entity("health_data", value="blood_type_O_positive"),
        ]
        result = full_engine.evaluate(entities)
        assert result.has_gdpr_special
        assert PolicyCategory.GDPR in result.categories
        assert "EU" in result.jurisdictions

    def test_empty_after_confidence_filtering(self, full_engine):
        """
        Many entities but all below the evaluate min_confidence: no matches.
        """
        entities = [
            _entity("ssn", confidence=0.1),
            _entity("credit_card_number", confidence=0.2),
            _entity("medical_record_number", confidence=0.05),
            _entity("api_key", confidence=0.15),
        ]
        result = full_engine.evaluate(entities, min_confidence=0.5)
        assert not result.is_sensitive
        assert result.risk_level == RiskLevel.MINIMAL

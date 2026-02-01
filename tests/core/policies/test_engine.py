"""Tests for the policy evaluation engine."""

import pytest

from openlabels.core.policies.schema import (
    EntityMatch,
    PolicyCategory,
    PolicyPack,
    PolicyTrigger,
    RiskLevel,
    HandlingRequirements,
)
from openlabels.core.policies.engine import PolicyEngine
from openlabels.core.policies.loader import load_builtin_policies


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def engine() -> PolicyEngine:
    """Create a fresh policy engine."""
    return PolicyEngine()


@pytest.fixture
def engine_with_builtins() -> PolicyEngine:
    """Create an engine with built-in policies loaded."""
    engine = PolicyEngine()
    engine.add_policies(load_builtin_policies())
    return engine


def make_entity(entity_type: str, value: str = "test", confidence: float = 0.9) -> EntityMatch:
    """Helper to create an entity match."""
    return EntityMatch(
        entity_type=entity_type,
        value=value,
        confidence=confidence,
        start=0,
        end=len(value),
        source="test",
    )


# ============================================================================
# Basic Engine Tests
# ============================================================================

class TestPolicyEngine:
    """Basic policy engine tests."""

    def test_empty_engine_returns_empty_result(self, engine: PolicyEngine):
        """Engine with no policies returns empty result."""
        entities = [make_entity("person_name", "John Doe")]
        result = engine.evaluate(entities)

        assert not result.is_sensitive
        assert len(result.matches) == 0
        assert result.risk_level == RiskLevel.MINIMAL

    def test_add_policy(self, engine: PolicyEngine):
        """Can add policies to engine."""
        policy = PolicyPack(
            name="Test Policy",
            triggers=PolicyTrigger(any_of=["ssn"]),
        )
        engine.add_policy(policy)

        assert engine.policy_count == 1
        assert "Test Policy" in engine.policy_names

    def test_remove_policy(self, engine: PolicyEngine):
        """Can remove policies from engine."""
        policy = PolicyPack(name="Test Policy")
        engine.add_policy(policy)
        assert engine.policy_count == 1

        removed = engine.remove_policy("Test Policy")
        assert removed
        assert engine.policy_count == 0

    def test_disabled_policy_not_added(self, engine: PolicyEngine):
        """Disabled policies are not added."""
        policy = PolicyPack(name="Disabled", enabled=False)
        engine.add_policy(policy)

        assert engine.policy_count == 0


# ============================================================================
# Trigger Tests
# ============================================================================

class TestTriggers:
    """Test policy trigger evaluation."""

    def test_any_of_single_match(self, engine: PolicyEngine):
        """any_of triggers on single matching entity."""
        policy = PolicyPack(
            name="SSN Policy",
            triggers=PolicyTrigger(any_of=["ssn"]),
            risk_level=RiskLevel.HIGH,
        )
        engine.add_policy(policy)

        entities = [make_entity("ssn", "123-45-6789")]
        result = engine.evaluate(entities)

        assert result.is_sensitive
        assert len(result.matches) == 1
        assert result.matches[0].policy_name == "SSN Policy"
        assert result.matches[0].trigger_type == "any_of"
        assert result.risk_level == RiskLevel.HIGH

    def test_any_of_no_match(self, engine: PolicyEngine):
        """any_of does not trigger without matching entity."""
        policy = PolicyPack(
            name="SSN Policy",
            triggers=PolicyTrigger(any_of=["ssn"]),
        )
        engine.add_policy(policy)

        entities = [make_entity("email", "test@example.com")]
        result = engine.evaluate(entities)

        assert not result.is_sensitive
        assert len(result.matches) == 0

    def test_all_of_requires_all(self, engine: PolicyEngine):
        """all_of requires all entity types to be present."""
        policy = PolicyPack(
            name="PII Combo",
            triggers=PolicyTrigger(all_of=["person_name", "date_of_birth"]),
        )
        engine.add_policy(policy)

        # Only one entity - should not match
        entities = [make_entity("person_name", "John Doe")]
        result = engine.evaluate(entities)
        assert not result.is_sensitive

        # Both entities - should match
        entities = [
            make_entity("person_name", "John Doe"),
            make_entity("date_of_birth", "1990-01-01"),
        ]
        result = engine.evaluate(entities)
        assert result.is_sensitive
        assert result.matches[0].trigger_type == "all_of"

    def test_combinations_or_logic(self, engine: PolicyEngine):
        """combinations are OR'd together."""
        policy = PolicyPack(
            name="PHI Policy",
            triggers=PolicyTrigger(
                combinations=[
                    ["person_name", "diagnosis"],
                    ["person_name", "medical_provider"],
                ]
            ),
        )
        engine.add_policy(policy)

        # First combination
        entities = [
            make_entity("person_name", "John Doe"),
            make_entity("diagnosis", "Flu"),
        ]
        result = engine.evaluate(entities)
        assert result.is_sensitive

        # Second combination
        entities = [
            make_entity("person_name", "John Doe"),
            make_entity("medical_provider", "Dr. Smith"),
        ]
        result = engine.evaluate(entities)
        assert result.is_sensitive

        # Neither combination
        entities = [
            make_entity("person_name", "John Doe"),
            make_entity("email", "john@example.com"),
        ]
        result = engine.evaluate(entities)
        assert not result.is_sensitive

    def test_confidence_threshold(self, engine: PolicyEngine):
        """Entities below confidence threshold are ignored."""
        policy = PolicyPack(
            name="High Confidence",
            triggers=PolicyTrigger(
                any_of=["ssn"],
                min_confidence=0.8,
            ),
        )
        engine.add_policy(policy)

        # Low confidence - should not match
        entities = [make_entity("ssn", "123-45-6789", confidence=0.5)]
        result = engine.evaluate(entities)
        assert not result.is_sensitive

        # High confidence - should match
        entities = [make_entity("ssn", "123-45-6789", confidence=0.9)]
        result = engine.evaluate(entities)
        assert result.is_sensitive

    def test_case_insensitive_entity_types(self, engine: PolicyEngine):
        """Entity type matching is case-insensitive."""
        policy = PolicyPack(
            name="Case Test",
            triggers=PolicyTrigger(any_of=["SSN"]),
        )
        engine.add_policy(policy)

        # Lowercase entity
        entities = [make_entity("ssn", "123-45-6789")]
        result = engine.evaluate(entities)
        assert result.is_sensitive


# ============================================================================
# Multiple Policy Tests
# ============================================================================

class TestMultiplePolicies:
    """Test evaluation with multiple policies."""

    def test_multiple_policies_match(self, engine: PolicyEngine):
        """Multiple policies can match the same entities."""
        policy1 = PolicyPack(
            name="PII",
            triggers=PolicyTrigger(any_of=["ssn"]),
            category=PolicyCategory.PII,
            risk_level=RiskLevel.HIGH,
        )
        policy2 = PolicyPack(
            name="Financial",
            triggers=PolicyTrigger(any_of=["ssn", "bank_account"]),
            category=PolicyCategory.GLBA,
            risk_level=RiskLevel.HIGH,
        )
        engine.add_policy(policy1)
        engine.add_policy(policy2)

        entities = [make_entity("ssn", "123-45-6789")]
        result = engine.evaluate(entities)

        assert len(result.matches) == 2
        assert PolicyCategory.PII in result.categories
        assert PolicyCategory.GLBA in result.categories

    def test_highest_risk_wins(self, engine: PolicyEngine):
        """Result takes highest risk level from matched policies."""
        policy1 = PolicyPack(
            name="Low Risk",
            triggers=PolicyTrigger(any_of=["email"]),
            risk_level=RiskLevel.LOW,
        )
        policy2 = PolicyPack(
            name="Critical Risk",
            triggers=PolicyTrigger(any_of=["email"]),
            risk_level=RiskLevel.CRITICAL,
        )
        engine.add_policy(policy1)
        engine.add_policy(policy2)

        entities = [make_entity("email", "test@example.com")]
        result = engine.evaluate(entities)

        assert result.risk_level == RiskLevel.CRITICAL


# ============================================================================
# Built-in Policy Tests
# ============================================================================

class TestBuiltinPolicies:
    """Test built-in policy packs."""

    def test_builtin_policies_load(self, engine_with_builtins: PolicyEngine):
        """Built-in policies load successfully."""
        assert engine_with_builtins.policy_count >= 7

        names = engine_with_builtins.policy_names
        assert "HIPAA PHI" in names
        assert "PII General" in names
        assert "PCI-DSS" in names
        assert "GDPR Personal Data" in names
        assert "CCPA/CPRA" in names

    def test_ssn_triggers_pii(self, engine_with_builtins: PolicyEngine):
        """SSN triggers PII policy."""
        entities = [make_entity("ssn", "123-45-6789")]
        result = engine_with_builtins.evaluate(entities)

        assert result.is_sensitive
        assert result.has_pii

    def test_credit_card_triggers_pci(self, engine_with_builtins: PolicyEngine):
        """Credit card triggers PCI-DSS policy."""
        entities = [make_entity("credit_card_number", "4111111111111111")]
        result = engine_with_builtins.evaluate(entities)

        assert result.is_sensitive
        assert result.has_pci
        assert PolicyCategory.PCI_DSS in result.categories
        # PCI requires encryption
        assert result.requires_encryption

    def test_medical_record_triggers_hipaa(self, engine_with_builtins: PolicyEngine):
        """Medical record number triggers HIPAA."""
        entities = [make_entity("medical_record_number", "MRN12345")]
        result = engine_with_builtins.evaluate(entities)

        assert result.is_sensitive
        assert result.has_phi
        assert PolicyCategory.HIPAA in result.categories

    def test_email_triggers_gdpr(self, engine_with_builtins: PolicyEngine):
        """Email triggers GDPR personal data policy."""
        entities = [make_entity("email", "user@example.eu")]
        result = engine_with_builtins.evaluate(entities)

        assert result.is_sensitive
        assert PolicyCategory.GDPR in result.categories
        # GDPR grants data subject rights
        assert result.data_subject_rights.access
        assert result.data_subject_rights.erasure

    def test_api_key_triggers_credentials(self, engine_with_builtins: PolicyEngine):
        """API key triggers credentials policy."""
        entities = [make_entity("aws_key", "AKIAIOSFODNN7EXAMPLE")]
        result = engine_with_builtins.evaluate(entities)

        assert result.is_sensitive
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.requires_encryption


# ============================================================================
# Handling Requirements Tests
# ============================================================================

class TestHandlingRequirements:
    """Test handling requirements merging."""

    def test_handling_requirements_merged(self, engine: PolicyEngine):
        """Handling requirements are OR'd together."""
        policy1 = PolicyPack(
            name="P1",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(
                encryption_required=True,
                audit_access=False,
            ),
        )
        policy2 = PolicyPack(
            name="P2",
            triggers=PolicyTrigger(any_of=["test"]),
            handling=HandlingRequirements(
                encryption_required=False,
                audit_access=True,
            ),
        )
        engine.add_policy(policy1)
        engine.add_policy(policy2)

        entities = [make_entity("test", "value")]
        result = engine.evaluate(entities)

        # Both should be True (OR logic)
        assert result.handling.encryption_required
        assert result.handling.audit_access


# ============================================================================
# Policy Loader Tests
# ============================================================================

class TestPolicyLoader:
    """Test YAML policy loading."""

    def test_load_from_dict(self):
        """Load policy from dictionary."""
        from openlabels.core.policies.loader import load_policy_pack

        data = {
            "name": "Custom Policy",
            "version": "1.0",
            "category": "custom",
            "risk_level": "high",
            "triggers": {
                "any_of": ["custom_type"],
            },
        }

        policy = load_policy_pack(data)
        assert policy.name == "Custom Policy"
        assert policy.category == PolicyCategory.CUSTOM
        assert policy.risk_level == RiskLevel.HIGH
        assert "custom_type" in policy.triggers.any_of

    def test_load_from_yaml_string(self):
        """Load policy from YAML string."""
        from openlabels.core.policies.loader import load_policy_pack

        yaml_str = """
name: YAML Policy
version: "2.0"
category: pii
risk_level: medium

triggers:
  any_of:
    - person_name
    - email
  combinations:
    - [name, dob]
  min_confidence: 0.7

handling:
  encryption_required: true
"""

        policy = load_policy_pack(yaml_str)
        assert policy.name == "YAML Policy"
        assert policy.version == "2.0"
        assert policy.category == PolicyCategory.PII
        assert policy.risk_level == RiskLevel.MEDIUM
        assert policy.triggers.min_confidence == 0.7
        assert policy.handling.encryption_required

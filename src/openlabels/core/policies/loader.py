"""
Policy pack loader and built-in policies.

Supports loading policies from:
- Built-in Python definitions
- YAML files
- JSON files
- Directory scanning
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from openlabels.core.policies.schema import (
    DataSubjectRights,
    HandlingRequirements,
    PolicyCategory,
    PolicyPack,
    PolicyTrigger,
    RetentionPolicy,
    RiskLevel,
)

logger = logging.getLogger(__name__)


# Built-in Policy Packs
def _create_hipaa_phi() -> PolicyPack:
    """HIPAA Protected Health Information (PHI) policy."""
    return PolicyPack(
        name="HIPAA PHI",
        version="1.0",
        description="Protected Health Information under HIPAA Privacy Rule (45 CFR 164.514)",
        category=PolicyCategory.HIPAA,
        risk_level=RiskLevel.CRITICAL,
        triggers=PolicyTrigger(
            # Direct identifiers (single entity = PHI in healthcare context)
            any_of=[
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
            ],
            # Combination identifiers (need context)
            combinations=[
                ["person_name", "date_of_birth", "medical_facility"],
                ["person_name", "diagnosis"],
                ["person_name", "treatment"],
                ["person_name", "medical_provider"],
                ["ssn", "medical_provider"],
                ["ssn", "diagnosis"],
                ["email", "diagnosis"],
                ["phone", "diagnosis"],
                ["address", "diagnosis"],
            ],
            min_confidence=0.7,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            encryption_at_rest=True,
            encryption_in_transit=True,
            audit_access=True,
            access_logging=True,
        ),
        retention=RetentionPolicy(
            min_days=2190,  # 6 years from creation or last effective date
            review_frequency_days=365,
        ),
        jurisdictions=["US"],
        priority=100,
        tags=["healthcare", "phi", "hipaa", "regulated"],
    )


def _create_pii_general() -> PolicyPack:
    """General PII (Personally Identifiable Information) policy."""
    return PolicyPack(
        name="PII General",
        version="1.0",
        description="General Personally Identifiable Information",
        category=PolicyCategory.PII,
        risk_level=RiskLevel.HIGH,
        triggers=PolicyTrigger(
            any_of=[
                "ssn",
                "social_security_number",
                "drivers_license",
                "passport",
                "national_id",
                "itin",
                "tax_id",
                "ein",
                # International IDs
                "uk_nino",
                "ca_sin",
                "de_id",
            ],
            # PII combinations
            combinations=[
                ["person_name", "date_of_birth"],
                ["person_name", "address"],
                ["person_name", "phone"],
                ["person_name", "email", "date_of_birth"],
            ],
            min_confidence=0.6,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            encryption_at_rest=True,
            audit_access=True,
        ),
        retention=RetentionPolicy(
            review_frequency_days=365,
        ),
        priority=80,
        tags=["pii", "personal-data"],
    )


def _create_pci_dss() -> PolicyPack:
    """PCI-DSS Payment Card Industry Data Security Standard policy."""
    return PolicyPack(
        name="PCI-DSS",
        version="4.0",
        description="Payment Card Industry Data Security Standard",
        category=PolicyCategory.PCI_DSS,
        risk_level=RiskLevel.CRITICAL,
        triggers=PolicyTrigger(
            any_of=[
                "credit_card",
                "credit_card_number",
                "pan",  # Primary Account Number
                "card_cvv",
                "cvv",
                "card_expiry",
                "cardholder_name",
                "bank_routing",
                "bank_account",
                "iban",
            ],
            combinations=[
                ["credit_card_number", "card_expiry"],
                ["credit_card_number", "cvv"],
                ["bank_account", "routing_number"],
                ["iban", "bic"],
            ],
            min_confidence=0.8,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            encryption_at_rest=True,
            encryption_in_transit=True,
            tokenization_required=True,
            masking_required=True,
            audit_access=True,
            access_logging=True,
        ),
        retention=RetentionPolicy(
            max_days=365,  # Only retain as long as needed
            review_frequency_days=90,
        ),
        priority=100,
        tags=["financial", "pci", "payment-cards", "regulated"],
    )


def _create_gdpr_personal() -> PolicyPack:
    """GDPR Personal Data policy (Article 4)."""
    return PolicyPack(
        name="GDPR Personal Data",
        version="1.0",
        description="Personal Data under GDPR Article 4 - any information relating to an identified or identifiable natural person",
        category=PolicyCategory.GDPR,
        risk_level=RiskLevel.HIGH,
        triggers=PolicyTrigger(
            # GDPR has broad definition of personal data
            any_of=[
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
            ],
            min_confidence=0.6,
        ),
        # GDPR Article 9 - Special Categories (require explicit consent)
        special_category_triggers=PolicyTrigger(
            any_of=[
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
            ],
            min_confidence=0.7,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            encryption_in_transit=True,
            audit_access=True,
            access_logging=True,
        ),
        retention=RetentionPolicy(
            review_frequency_days=365,
            auto_delete=False,  # Subject to data subject requests
        ),
        data_subject_rights=DataSubjectRights(
            access=True,
            rectification=True,
            erasure=True,  # Right to be forgotten
            portability=True,
            restriction=True,
            objection=True,
        ),
        jurisdictions=["EU", "EEA", "UK"],
        priority=90,
        tags=["gdpr", "eu", "personal-data", "regulated"],
    )


def _create_ccpa_cpra() -> PolicyPack:
    """CCPA/CPRA California Consumer Privacy Act policy."""
    return PolicyPack(
        name="CCPA/CPRA",
        version="2.0",
        description="California Consumer Privacy Act and California Privacy Rights Act",
        category=PolicyCategory.CCPA,
        risk_level=RiskLevel.HIGH,
        triggers=PolicyTrigger(
            any_of=[
                "ssn",
                "drivers_license",
                "passport",
                "financial_account",
                "credit_card",
                "biometric_data",
            ],
            combinations=[
                # Personal information + consumer identifier
                ["person_name", "email"],
                ["person_name", "phone"],
                ["person_name", "address"],
                ["person_name", "ip_address"],
                ["email", "purchase_history"],
                ["device_id", "browsing_history"],
            ],
            min_confidence=0.6,
        ),
        # Sensitive personal information (requires opt-in)
        special_category_triggers=PolicyTrigger(
            any_of=[
                "ssn",
                "drivers_license",
                "passport",
                "financial_account",
                "precise_geolocation",
                "racial_ethnic_origin",
                "religious_belief",
                "union_membership",
                "genetic_data",
                "biometric_data",
                "health_data",
                "sex_life",
                "sexual_orientation",
            ],
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            audit_access=True,
        ),
        retention=RetentionPolicy(
            review_frequency_days=365,
        ),
        data_subject_rights=DataSubjectRights(
            access=True,
            erasure=True,  # Right to delete
            portability=True,
            objection=True,  # Right to opt-out of sale
        ),
        jurisdictions=["US-CA"],
        priority=85,
        tags=["ccpa", "cpra", "california", "regulated"],
    )


def _create_glba() -> PolicyPack:
    """GLBA Gramm-Leach-Bliley Act (financial privacy) policy."""
    return PolicyPack(
        name="GLBA",
        version="1.0",
        description="Gramm-Leach-Bliley Act - Financial Privacy",
        category=PolicyCategory.GLBA,
        risk_level=RiskLevel.HIGH,
        triggers=PolicyTrigger(
            any_of=[
                "ssn",
                "tax_id",
                "bank_account",
                "bank_routing",
                "credit_card",
                "financial_account",
            ],
            combinations=[
                ["person_name", "account_number"],
                ["person_name", "financial_account"],
                ["ssn", "account_balance"],
                ["person_name", "credit_score"],
                ["person_name", "loan_amount"],
            ],
            min_confidence=0.7,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            encryption_at_rest=True,
            encryption_in_transit=True,
            audit_access=True,
        ),
        retention=RetentionPolicy(
            min_days=2555,  # 7 years
        ),
        jurisdictions=["US"],
        priority=85,
        tags=["financial", "glba", "regulated"],
    )


def _create_ferpa() -> PolicyPack:
    """FERPA Family Educational Rights and Privacy Act policy."""
    return PolicyPack(
        name="FERPA",
        version="1.0",
        description="Family Educational Rights and Privacy Act - Education Records",
        category=PolicyCategory.FERPA,
        risk_level=RiskLevel.HIGH,
        triggers=PolicyTrigger(
            any_of=[
                "student_id",
                "education_record",
                "transcript",
                "grade",
                "gpa",
            ],
            combinations=[
                ["person_name", "student_id"],
                ["person_name", "grade"],
                ["person_name", "school", "date_of_birth"],
                ["person_name", "disciplinary_record"],
            ],
            min_confidence=0.7,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            audit_access=True,
        ),
        retention=RetentionPolicy(
            min_days=1825,  # 5 years after last attendance
        ),
        data_subject_rights=DataSubjectRights(
            access=True,
            rectification=True,
        ),
        jurisdictions=["US"],
        priority=80,
        tags=["education", "ferpa", "regulated"],
    )


def _create_credentials() -> PolicyPack:
    """Credentials and secrets policy."""
    return PolicyPack(
        name="Credentials & Secrets",
        version="1.0",
        description="API keys, passwords, tokens, and other credentials",
        category=PolicyCategory.CUSTOM,
        risk_level=RiskLevel.CRITICAL,
        triggers=PolicyTrigger(
            any_of=[
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
            ],
            min_confidence=0.8,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            encryption_at_rest=True,
            audit_access=True,
            access_logging=True,
        ),
        retention=RetentionPolicy(
            max_days=90,  # Rotate credentials regularly
        ),
        priority=100,  # Highest priority
        tags=["credentials", "secrets", "security"],
    )


def _create_soc2() -> PolicyPack:
    """SOC 2 Trust Services Criteria policy.

    Focuses on confidentiality, availability, and processing integrity
    controls relevant to service-organization data.  Triggers on PII,
    credentials, and financial identifiers that are commonly flagged
    during SOC 2 Type II audits.
    """
    return PolicyPack(
        name="SOC2 Trust Services",
        version="1.0",
        description=(
            "SOC 2 Trust Services Criteria — data confidentiality and "
            "processing integrity controls for service organizations"
        ),
        category=PolicyCategory.SOC2,
        risk_level=RiskLevel.HIGH,
        triggers=PolicyTrigger(
            any_of=[
                # Confidentiality criteria
                "ssn",
                "social_security_number",
                "credit_card",
                "bank_account",
                "iban",
                "api_key",
                "password",
                "private_key",
                "aws_key",
                "aws_secret",
                "client_secret",
                "database_password",
                "encryption_key",
            ],
            combinations=[
                # PII + financial identifiers
                ["person_name", "bank_account"],
                ["person_name", "credit_card"],
                ["email", "ssn"],
            ],
            min_confidence=0.7,
        ),
        handling=HandlingRequirements(
            encryption_required=True,
            encryption_at_rest=True,
            encryption_in_transit=True,
            audit_access=True,
            access_logging=True,
        ),
        retention=RetentionPolicy(
            min_days=365,   # Minimum 1 year for audit evidence
            review_frequency_days=90,  # Quarterly review
        ),
        jurisdictions=["US"],
        priority=60,
        tags=["soc2", "trust-services", "confidentiality"],
    )


# All built-in policies
BUILTIN_POLICIES = [
    _create_hipaa_phi,
    _create_pii_general,
    _create_pci_dss,
    _create_gdpr_personal,
    _create_ccpa_cpra,
    _create_glba,
    _create_ferpa,
    _create_credentials,
    _create_soc2,
]


def load_builtin_policies() -> list[PolicyPack]:
    """Load all built-in policy packs."""
    return [factory() for factory in BUILTIN_POLICIES]


# YAML/JSON Loader
def _parse_trigger(data: dict[str, Any]) -> PolicyTrigger:
    """Parse trigger configuration from dict."""
    return PolicyTrigger(
        any_of=data.get("any_of", []),
        all_of=data.get("all_of", []),
        combinations=data.get("combinations", []),
        min_confidence=data.get("min_confidence", 0.5),
        min_count=data.get("min_count", 1),
        exclude_if_only=data.get("exclude_if_only", []),
    )


def _parse_handling(data: dict[str, Any]) -> HandlingRequirements:
    """Parse handling requirements from dict."""
    return HandlingRequirements(
        encryption_required=data.get("encryption_required", False),
        encryption_at_rest=data.get("encryption_at_rest", False),
        encryption_in_transit=data.get("encryption_in_transit", False),
        tokenization_required=data.get("tokenization_required", False),
        masking_required=data.get("masking_required", False),
        audit_access=data.get("audit_access", False),
        access_logging=data.get("access_logging", False),
        mfa_required=data.get("mfa_required", False),
        geographic_restrictions=data.get("geographic_restrictions", []),
        prohibited_regions=data.get("prohibited_regions", []),
    )


def _parse_retention(data: dict[str, Any]) -> RetentionPolicy:
    """Parse retention policy from dict."""
    return RetentionPolicy(
        max_days=data.get("max_days"),
        min_days=data.get("min_days"),
        review_frequency_days=data.get("review_frequency_days"),
        auto_delete=data.get("auto_delete", False),
    )


def _parse_rights(data: dict[str, Any]) -> DataSubjectRights:
    """Parse data subject rights from dict."""
    return DataSubjectRights(
        access=data.get("access", False),
        rectification=data.get("rectification", False),
        erasure=data.get("erasure", False),
        portability=data.get("portability", False),
        restriction=data.get("restriction", False),
        objection=data.get("objection", False),
    )


def load_policy_pack(source: str | Path | dict) -> PolicyPack:
    """
    Load a policy pack from YAML, JSON, or dict.

    Args:
        source: File path, YAML string, or dict

    Returns:
        Parsed PolicyPack
    """
    if isinstance(source, dict):
        data = source
    elif isinstance(source, (str, Path)):
        path = Path(source)
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f)
        else:
            # Assume it's YAML content
            data = yaml.safe_load(source)
    else:
        raise ValueError(f"Invalid source type: {type(source)}")

    # Parse required fields
    name = data.get("name")
    if not name:
        raise ValueError("Policy pack must have a 'name' field")

    # Parse category
    category_str = data.get("category", "custom").lower()
    try:
        category = PolicyCategory(category_str)
    except ValueError:
        logger.warning(f"Unknown category '{category_str}', using CUSTOM")
        category = PolicyCategory.CUSTOM

    # Parse risk level
    risk_str = data.get("risk_level", "high").lower()
    try:
        risk_level = RiskLevel(risk_str)
    except ValueError:
        logger.warning(f"Unknown risk level '{risk_str}', using HIGH")
        risk_level = RiskLevel.HIGH

    # Parse triggers
    triggers_data = data.get("triggers", {})
    triggers = _parse_trigger(triggers_data)

    special_triggers_data = data.get("special_category_triggers", {})
    special_triggers = _parse_trigger(special_triggers_data) if special_triggers_data else PolicyTrigger()

    # Parse requirements
    handling = _parse_handling(data.get("handling", {}))
    retention = _parse_retention(data.get("retention", {}))
    rights = _parse_rights(data.get("data_subject_rights", {}))

    return PolicyPack(
        name=name,
        version=data.get("version", "1.0"),
        description=data.get("description", ""),
        category=category,
        risk_level=risk_level,
        triggers=triggers,
        special_category_triggers=special_triggers,
        handling=handling,
        retention=retention,
        data_subject_rights=rights,
        jurisdictions=data.get("jurisdictions", []),
        enabled=data.get("enabled", True),
        priority=data.get("priority", 0),
        tags=data.get("tags", []),
        metadata=data.get("metadata", {}),
    )


